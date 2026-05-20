"""Generic Rust AST extraction using tree-sitter.

Handles non-blockchain Rust code. For blockchain-specific Rust, see
anchor.py (Solana/Anchor) and substrate.py (Substrate/Polkadot).

Security patterns detected:
- Unsafe blocks and unsafe function calls (memory safety boundary)
- Panic/unwrap/expect sinks (DoS vectors in library/server code)
- Unchecked arithmetic (overflow/underflow in non-debug builds)
- Dangerous FFI patterns (raw pointer dereference, transmute)
- Error suppression (unwrap on Result in non-test code)
- Cryptographic misuse patterns
"""

import json
import re
import tree_sitter_rust
from tree_sitter import Language, Parser
from core.web3 import ExtractResult
from core.web3.base import BaseExtractor


# --- Rust Security Pattern Constants ---

# Panic/abort sinks — these crash the process (DoS vector)
PANIC_SINKS = {
    "unwrap", "expect", "panic", "unreachable", "unimplemented", "todo",
    "unwrap_or_else",  # only dangerous if closure panics, but worth flagging
}

# Unwrap variants that are safe (return default, don't panic)
SAFE_UNWRAP = {"unwrap_or", "unwrap_or_default"}

# Dangerous FFI/memory functions
UNSAFE_FFI_PATTERNS = {
    "transmute", "transmute_copy", "from_raw_parts", "from_raw_parts_mut",
    "offset", "read_unaligned", "write_unaligned",
    "copy_nonoverlapping", "copy", "write_bytes",
    "as_mut_ptr", "as_ptr",
}

# Cryptographic misuse patterns
CRYPTO_MISUSE_PATTERNS = {
    "from_seed",  # Deterministic key generation
    "new_unseeded",  # Unseeded RNG
    "thread_rng",  # Non-cryptographic RNG used for crypto
}

# Integer overflow-prone operations in Rust
# In release mode, Rust wraps on overflow instead of panicking
OVERFLOW_METHODS = {
    "wrapping_add", "wrapping_sub", "wrapping_mul",
    "overflowing_add", "overflowing_sub", "overflowing_mul",
}

# Safe arithmetic methods (checked_* returns Option, saturating_* clamps)
SAFE_ARITHMETIC = {
    "checked_add", "checked_sub", "checked_mul", "checked_div",
    "saturating_add", "saturating_sub", "saturating_mul",
}

# Test file/function patterns
RUST_TEST_PATTERNS = {"#[test]", "#[cfg(test)]", "tests::", "_test.rs"}

# Public API entry points worth flagging for validation
RUST_ENTRY_MARKERS = {"pub fn", "pub async fn", "pub unsafe fn"}


def _get_parser():
    lang = Language(tree_sitter_rust.language())
    parser = Parser(lang)
    return parser


def _child_by_type(node, type_name):
    """Get first child of a given type."""
    for c in node.children:
        if c.type == type_name:
            return c
    return None


def _children_by_type(node, type_name):
    """Get all children of a given type."""
    return [c for c in node.children if c.type == type_name]


def _text(node):
    """Decode node text."""
    return node.text.decode("utf-8") if node else ""


def _get_visibility(node):
    """Extract visibility from a node's visibility_modifier child."""
    vis = _child_by_type(node, "visibility_modifier")
    if vis:
        return _text(vis).strip()
    return "private"


def _collect_nodes_by_type(node, type_name):
    """Recursively collect all descendant nodes of the given type."""
    results = []
    if node is None:
        return results
    if node.type == type_name:
        results.append(node)
    for child in node.children:
        results.extend(_collect_nodes_by_type(child, type_name))
    return results


def _collect_field_expressions(node):
    """Recursively collect all field_expression nodes."""
    return _collect_nodes_by_type(node, "field_expression")


def _collect_call_expressions(node):
    """Recursively collect all call_expression nodes."""
    return _collect_nodes_by_type(node, "call_expression")


def _collect_assignments(node):
    """Recursively collect assignment_expression nodes."""
    return _collect_nodes_by_type(node, "assignment_expression")


def _get_call_name(call_node):
    """Extract the function/method name from a call_expression."""
    func_child = call_node.children[0] if call_node.children else None
    if func_child is None:
        return None
    if func_child.type == "identifier":
        return _text(func_child)
    if func_child.type == "field_expression":
        field = _child_by_type(func_child, "field_identifier")
        return _text(field) if field else None
    if func_child.type == "scoped_identifier":
        ids = _children_by_type(func_child, "identifier") + _children_by_type(func_child, "type_identifier")
        return _text(ids[-1]) if ids else None
    # Fallback: try to find deepest identifier
    ids = []

    def _dig(n):
        if n.type in ("identifier", "field_identifier"):
            ids.append(_text(n))
        for c in n.children:
            _dig(c)

    _dig(func_child)
    return ids[-1] if ids else None


def _is_self_field_access(field_expr):
    """Check if a field_expression is `self.something`."""
    if not field_expr.children:
        return False, None
    obj = field_expr.children[0]
    if _text(obj) == "self":
        field = _child_by_type(field_expr, "field_identifier")
        if field:
            return True, _text(field)
    return False, None


def _has_unsafe_modifier(node):
    """Check if a function_item has unsafe keyword."""
    for child in node.children:
        if child.type == "unsafe" or _text(child) == "unsafe":
            return True
    text = _text(node)
    return text.lstrip().startswith("pub unsafe fn") or text.lstrip().startswith("unsafe fn")


def _has_async_modifier(node):
    """Check if a function_item has async keyword (H3)."""
    for child in node.children:
        if _text(child) == "async":
            return True
    text = _text(node)
    return "async fn" in text.split("{")[0] if "{" in text else "async fn" in text


def _extract_generics(node):
    """Extract generic type parameters from a node (H1).

    Returns the generics string like '<T: Clone + Send>' or empty string.
    """
    tp = _child_by_type(node, "type_parameters")
    if tp:
        return _text(tp)
    return ""


def _extract_where_clause(node):
    """Extract where clause from a node (H1)."""
    wc = _child_by_type(node, "where_clause")
    if wc:
        return _text(wc)
    return ""


def _extract_lifetimes(node):
    """Extract lifetime parameters from a node (H2).

    Looks in type_parameters for lifetime nodes, and also scans the
    function signature text for lifetime patterns.
    """
    lifetimes = []
    tp = _child_by_type(node, "type_parameters")
    if tp:
        for child in tp.children:
            if child.type == "lifetime":
                lifetimes.append(_text(child))
    # Also scan parameters for lifetime annotations
    params = _child_by_type(node, "parameters")
    if params:
        for lt in _collect_nodes_by_type(params, "lifetime"):
            lt_text = _text(lt)
            if lt_text and lt_text not in lifetimes:
                lifetimes.append(lt_text)
    # Scan return type for lifetimes
    ret = _child_by_type(node, "return_type")
    if ret:
        for lt in _collect_nodes_by_type(ret, "lifetime"):
            lt_text = _text(lt)
            if lt_text and lt_text not in lifetimes:
                lifetimes.append(lt_text)
    return lifetimes


def _extract_receiver(node):
    """Extract receiver type from method parameters (H5).

    Returns "&self", "&mut self", "self", "mut self", or None.
    """
    params = _child_by_type(node, "parameters")
    if not params:
        return None
    for child in params.children:
        if child.type == "self_parameter":
            return _text(child).strip()
    return None


def _extract_fn_signature(node):
    """Build a human-readable function signature from a function_item."""
    parts = []
    vis = _child_by_type(node, "visibility_modifier")
    if vis:
        parts.append(_text(vis))
    if _has_async_modifier(node):
        parts.append("async")
    if _has_unsafe_modifier(node):
        parts.append("unsafe")
    parts.append("fn")
    name = _child_by_type(node, "identifier")
    if name:
        parts.append(_text(name))
    generics = _extract_generics(node)
    if generics:
        parts.append(generics)
    params = _child_by_type(node, "parameters")
    if params:
        parts.append(_text(params))
    ret = _child_by_type(node, "return_type")
    if ret:
        parts.append(_text(ret))
    where_clause = _extract_where_clause(node)
    if where_clause:
        parts.append(where_clause)
    return " ".join(parts)


class RustExtractor(BaseExtractor):

    def __init__(self):
        self.parser = _get_parser()

    def extract_from_source(self, source_code: bytes, file_path: str) -> ExtractResult:
        """Parse source and extract."""
        tree = self.parser.parse(source_code)
        return self.extract(tree, source_code, file_path)

    def extract(self, tree, source_code: bytes, file_path: str) -> ExtractResult:
        result = ExtractResult()
        root = tree.root_node

        # Collected type info for cross-referencing
        struct_fields: dict[str, list[str]] = {}  # struct_name -> [field_names]
        enum_variants: dict[str, list[str]] = {}  # enum_name -> [variant_names]
        trait_methods: dict[str, list[str]] = {}  # trait_name -> [method_names]
        func_ts_map: dict[int, str] = {}  # tree-sitter node.id -> our node_id

        # Extract everything from root with no prefix
        self._extract_items(root, file_path, "", result,
                            struct_fields, enum_variants, trait_methods, func_ts_map)

        return result

    def _extract_items(self, container_node, file_path, prefix, result,
                       struct_fields, enum_variants, trait_methods, func_ts_map):
        """Extract all items from a container node (root or module body).

        This is the main recursive dispatcher. The `prefix` parameter is used
        to build module-qualified node IDs like 'file::modname::StructName'.
        """
        # First pass: types (structs, enums, traits, modules, uses, macros)
        for child in container_node.children:
            if child.type == "struct_item":
                self._extract_struct(child, file_path, prefix, result, struct_fields)
            elif child.type == "enum_item":
                self._extract_enum(child, file_path, prefix, result, enum_variants)
            elif child.type == "trait_item":
                self._extract_trait(child, file_path, prefix, result, trait_methods)
            elif child.type == "mod_item":
                self._extract_module(child, file_path, prefix, result,
                                     struct_fields, enum_variants, trait_methods, func_ts_map)
            elif child.type == "use_declaration":
                self._extract_use(child, file_path, prefix, result)
            elif child.type == "macro_definition":
                self._extract_macro(child, file_path, prefix, result)

        # Second pass: impl blocks
        for child in container_node.children:
            if child.type == "impl_item":
                self._extract_impl(child, file_path, prefix, result, func_ts_map,
                                   struct_fields, enum_variants)

        # Third pass: free functions
        for child in container_node.children:
            if child.type == "function_item":
                self._extract_free_function(child, file_path, prefix, result, func_ts_map,
                                            struct_fields, enum_variants)

    def _prefixed(self, prefix, name):
        """Build a qualified name with module prefix."""
        if prefix:
            return f"{prefix}::{name}"
        return name

    def _extract_struct(self, node, file_path, prefix, result, struct_fields):
        """Extract struct definition and its fields."""
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return
        struct_name = _text(name_node)
        qualified = self._prefixed(prefix, struct_name)
        struct_id = self._make_node_id(file_path, qualified)
        vis = _get_visibility(node)

        # H1: generics and where clause
        generics = _extract_generics(node)
        where_clause = _extract_where_clause(node)

        meta: dict = {"kind": "struct"}
        if generics:
            meta["generics"] = generics
        if where_clause:
            meta["where_clause"] = where_clause

        sig = f"struct {struct_name}"
        if generics:
            sig += generics

        result.nodes.append({
            "id": struct_id,
            "label": struct_name,
            "type": "struct",
            "visibility": vis,
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": sig,
            "metadata": json.dumps(meta),
        })

        # Extract fields
        field_list = _child_by_type(node, "field_declaration_list")
        if not field_list:
            struct_fields[struct_name] = []
            return

        field_names = []
        for field in _children_by_type(field_list, "field_declaration"):
            fname_node = _child_by_type(field, "field_identifier")
            if not fname_node:
                continue
            fname = _text(fname_node)
            field_names.append(fname)
            field_vis = _get_visibility(field)
            field_type = _child_by_type(field, "type_identifier")
            type_text = ""
            for c in field.children:
                if c.type not in ("field_identifier", "visibility_modifier", ":"):
                    if c.type != "identifier":
                        type_text = _text(c)
                        break
            if not type_text and field_type:
                type_text = _text(field_type)

            field_id = self._make_node_id(file_path, f"{qualified}.{fname}")
            result.nodes.append({
                "id": field_id,
                "label": fname,
                "type": "state_var",
                "visibility": field_vis,
                "file": file_path,
                "line_start": field.start_point[0] + 1,
                "line_end": field.end_point[0] + 1,
                "signature": type_text,
                "metadata": json.dumps({"struct": struct_name, "type_text": type_text}),
            })
            result.edges.append({
                "source": struct_id,
                "target": field_id,
                "relation": "contains",
                "attributes": "{}",
            })

        struct_fields[struct_name] = field_names

    def _extract_enum(self, node, file_path, prefix, result, enum_variants):
        """Extract enum definition and its variants."""
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return
        enum_name = _text(name_node)
        qualified = self._prefixed(prefix, enum_name)
        enum_id = self._make_node_id(file_path, qualified)
        vis = _get_visibility(node)

        # H1: generics
        generics = _extract_generics(node)

        variants = []
        variant_list = _child_by_type(node, "enum_variant_list")
        if variant_list:
            for variant in _children_by_type(variant_list, "enum_variant"):
                vname_node = _child_by_type(variant, "identifier")
                if vname_node:
                    vname = _text(vname_node)
                    variants.append(vname)

                    variant_id = self._make_node_id(file_path, f"{qualified}.{vname}")
                    result.nodes.append({
                        "id": variant_id,
                        "label": vname,
                        "type": "enum_variant",
                        "visibility": vis,
                        "file": file_path,
                        "line_start": variant.start_point[0] + 1,
                        "line_end": variant.end_point[0] + 1,
                        "signature": "",
                        "metadata": json.dumps({"enum": enum_name}),
                    })
                    result.edges.append({
                        "source": enum_id,
                        "target": variant_id,
                        "relation": "contains",
                        "attributes": "{}",
                    })

        enum_variants[enum_name] = variants

        meta: dict = {"kind": "enum", "variants": variants}
        if generics:
            meta["generics"] = generics

        result.nodes.append({
            "id": enum_id,
            "label": enum_name,
            "type": "enum",
            "visibility": vis,
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"enum {enum_name}",
            "metadata": json.dumps(meta),
        })

    def _extract_trait(self, node, file_path, prefix, result, trait_methods):
        """Extract trait definition."""
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return
        trait_name = _text(name_node)
        qualified = self._prefixed(prefix, trait_name)
        trait_id = self._make_node_id(file_path, qualified)
        vis = _get_visibility(node)

        # H1: generics
        generics = _extract_generics(node)

        methods = []
        decl_list = _child_by_type(node, "declaration_list")
        if decl_list:
            for child in decl_list.children:
                if child.type in ("function_signature_item", "function_item"):
                    mname = _child_by_type(child, "identifier")
                    if mname:
                        methods.append(_text(mname))

        trait_methods[trait_name] = methods

        meta: dict = {"kind": "trait", "methods": methods}
        if generics:
            meta["generics"] = generics

        result.nodes.append({
            "id": trait_id,
            "label": trait_name,
            "type": "trait",
            "visibility": vis,
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"trait {trait_name}",
            "metadata": json.dumps(meta),
        })

    def _extract_module(self, node, file_path, prefix, result,
                        struct_fields, enum_variants, trait_methods, func_ts_map):
        """Extract module declaration and recurse into its body (C1)."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        mod_name = _text(name_node)
        qualified = self._prefixed(prefix, mod_name)
        mod_id = self._make_node_id(file_path, qualified)
        vis = _get_visibility(node)

        result.nodes.append({
            "id": mod_id,
            "label": mod_name,
            "type": "module",
            "visibility": vis,
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"mod {mod_name}",
            "metadata": json.dumps({"kind": "module"}),
        })

        # C1: Recurse into module body (declaration_list)
        decl_list = _child_by_type(node, "declaration_list")
        if decl_list:
            self._extract_items(decl_list, file_path, qualified, result,
                                struct_fields, enum_variants, trait_methods, func_ts_map)

    def _extract_use(self, node, file_path, prefix, result):
        """Extract use declaration (C2)."""
        use_text = _text(node).strip()
        # Extract the path from "use path::to::thing;"
        # Remove "use " prefix and ";" suffix
        path = use_text
        if path.startswith("use "):
            path = path[4:]
        if path.endswith(";"):
            path = path[:-1]
        path = path.strip()

        qualified = self._prefixed(prefix, f"use::{path}")
        use_id = self._make_node_id(file_path, qualified)
        vis = _get_visibility(node)

        result.nodes.append({
            "id": use_id,
            "label": path,
            "type": "use",
            "visibility": vis,
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": use_text,
            "metadata": json.dumps({"path": path}),
        })

    def _extract_macro(self, node, file_path, prefix, result):
        """Extract macro_rules! definition (H4)."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        macro_name = _text(name_node)
        qualified = self._prefixed(prefix, macro_name)
        macro_id = self._make_node_id(file_path, qualified)

        result.nodes.append({
            "id": macro_id,
            "label": macro_name,
            "type": "macro",
            "visibility": "private",
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"macro_rules! {macro_name}",
            "metadata": json.dumps({"kind": "macro"}),
        })

    def _extract_impl(self, node, file_path, prefix, result, func_ts_map,
                      struct_fields, enum_variants):
        """Extract impl block: methods and trait implementation edges."""
        type_name = None
        trait_name = None

        type_node = _child_by_type(node, "type_identifier")
        if type_node:
            type_name = _text(type_node)

        # Check for trait impl: look for "for" keyword in children
        has_for = False
        for child in node.children:
            if _text(child) == "for":
                has_for = True
                break

        if has_for:
            type_ids = []
            for child in node.children:
                if child.type == "type_identifier":
                    type_ids.append(_text(child))
                elif child.type == "generic_type":
                    gname = _child_by_type(child, "type_identifier")
                    if gname:
                        type_ids.append(_text(gname))
                elif child.type == "scoped_type_identifier":
                    type_ids.append(_text(child))

            if len(type_ids) >= 2:
                trait_name = type_ids[0]
                type_name = type_ids[1]
            elif len(type_ids) == 1:
                trait_name = type_ids[0]
                found_for = False
                for child in node.children:
                    if _text(child) == "for":
                        found_for = True
                        continue
                    if found_for and child.type == "type_identifier":
                        type_name = _text(child)
                        break

            # Emit inherits edge
            if trait_name and type_name:
                type_qualified = self._prefixed(prefix, type_name)
                trait_qualified = self._prefixed(prefix, trait_name)
                type_id = self._make_node_id(file_path, type_qualified)
                trait_id = self._make_node_id(file_path, trait_qualified)
                result.edges.append({
                    "source": type_id,
                    "target": trait_id,
                    "relation": "inherits",
                    "attributes": "{}",
                })

        if not type_name:
            return

        # Get field names for this type (for state read/write detection)
        fields = struct_fields.get(type_name, [])

        # Extract methods from declaration_list
        decl_list = _child_by_type(node, "declaration_list")
        if not decl_list:
            return

        for item in decl_list.children:
            if item.type == "function_item":
                self._extract_method(item, file_path, prefix, type_name, trait_name,
                                     result, func_ts_map, fields, enum_variants)

    def _extract_method(self, node, file_path, prefix, type_name, trait_name,
                        result, func_ts_map, fields, enum_variants):
        """Extract a method from an impl block."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        method_name = _text(name_node)

        # C3: Fix trait impl vs inherent impl method ID collision
        if trait_name:
            qualified = self._prefixed(prefix, f"{type_name}::{trait_name}::{method_name}")
        else:
            qualified = self._prefixed(prefix, f"{type_name}::{method_name}")
        method_id = self._make_node_id(file_path, qualified)
        func_ts_map[node.id] = method_id

        vis = _get_visibility(node)
        sig = _extract_fn_signature(node)
        is_unsafe = _has_unsafe_modifier(node)
        is_async = _has_async_modifier(node)
        receiver = _extract_receiver(node)
        generics = _extract_generics(node)
        where_clause = _extract_where_clause(node)
        lifetimes = _extract_lifetimes(node)

        meta: dict = {"impl_type": type_name}
        if trait_name:
            meta["trait"] = trait_name
        if is_unsafe:
            meta["unsafe"] = True
        if is_async:
            meta["async"] = True
        if receiver:
            meta["receiver"] = receiver
        if generics:
            meta["generics"] = generics
        if where_clause:
            meta["where_clause"] = where_clause
        if lifetimes:
            meta["lifetimes"] = lifetimes

        # Extract body edges + security patterns (mutates meta before node append)
        body = _child_by_type(node, "block")
        if body:
            self._extract_body_edges(body, node, method_id, file_path, prefix,
                                     type_name, fields, enum_variants, meta, result)

        result.nodes.append({
            "id": method_id,
            "label": method_name,
            "type": "function",
            "visibility": vis,
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": sig,
            "metadata": json.dumps(meta),
        })

    def _extract_free_function(self, node, file_path, prefix, result, func_ts_map,
                               struct_fields, enum_variants):
        """Extract a free (non-impl) function."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        func_name = _text(name_node)
        qualified = self._prefixed(prefix, func_name)
        func_id = self._make_node_id(file_path, qualified)
        func_ts_map[node.id] = func_id

        vis = _get_visibility(node)
        sig = _extract_fn_signature(node)
        is_unsafe = _has_unsafe_modifier(node)
        is_async = _has_async_modifier(node)
        generics = _extract_generics(node)
        where_clause = _extract_where_clause(node)
        lifetimes = _extract_lifetimes(node)

        meta: dict = {}
        if is_unsafe:
            meta["unsafe"] = True
        if is_async:
            meta["async"] = True
        if generics:
            meta["generics"] = generics
        if where_clause:
            meta["where_clause"] = where_clause
        if lifetimes:
            meta["lifetimes"] = lifetimes

        # Extract body edges + security patterns (mutates meta before node append)
        body = _child_by_type(node, "block")
        if body:
            self._extract_body_edges(body, node, func_id, file_path, prefix,
                                     None, [], enum_variants, meta, result)

        result.nodes.append({
            "id": func_id,
            "label": func_name,
            "type": "function",
            "visibility": vis,
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": sig,
            "metadata": json.dumps(meta),
        })

    def _extract_body_edges(self, body_node, func_node, func_id, file_path, prefix,
                            type_name, fields, enum_variants, meta, result):
        """Walk function body to extract call, state read/write, transition, and security edges.

        H6: Compute write-only fields first, then exclude them from reads_state.
        Security: detect unsafe blocks, panic sinks, unchecked arithmetic, FFI patterns.
        """
        # Collect assignments for write detection and state transitions
        assignments = _collect_assignments(body_node)

        # Track which fields are written (LHS of assignment with self.field)
        written_fields: set[str] = set()
        # Track which fields appear in write-only contexts (LHS only in assignments)
        write_only_lhs_fields: set[str] = set()

        for assign in assignments:
            if len(assign.children) < 2:
                continue
            lhs = assign.children[0]
            rhs = assign.children[-1]

            lhs_field_exprs = _collect_field_expressions(lhs)
            if lhs.type == "field_expression":
                lhs_field_exprs = [lhs] + lhs_field_exprs
            for fe in lhs_field_exprs:
                is_self, field_name = _is_self_field_access(fe)
                if is_self and field_name in fields:
                    written_fields.add(field_name)
                    write_only_lhs_fields.add(field_name)
                    qualified = self._prefixed(prefix, f"{type_name}.{field_name}") if prefix else f"{type_name}.{field_name}"
                    var_id = self._make_node_id(file_path, qualified)
                    result.edges.append({
                        "source": func_id,
                        "target": var_id,
                        "relation": "writes_state",
                        "attributes": "{}",
                    })

            # State transition detection
            self._detect_state_transitions(assign, func_id, file_path, prefix, type_name,
                                           fields, enum_variants, result)

        # Collect all self.field accesses in the body
        all_field_exprs = _collect_field_expressions(body_node)

        # H6: Determine which written fields are also read in non-LHS contexts
        # A field is read if it appears outside of assignment LHS positions
        # Collect assignment LHS node IDs for exclusion
        assignment_lhs_ids: set[int] = set()
        for assign in assignments:
            if assign.children:
                lhs = assign.children[0]
                # Collect all field_expression node ids in LHS
                for fe in _collect_field_expressions(lhs):
                    assignment_lhs_ids.add(fe.id)
                if lhs.type == "field_expression":
                    assignment_lhs_ids.add(lhs.id)

        read_fields: set[str] = set()
        for fe in all_field_exprs:
            is_self, field_name = _is_self_field_access(fe)
            if is_self and field_name in fields and field_name not in read_fields:
                # H6: Skip if this field_expression is in an assignment LHS
                if fe.id in assignment_lhs_ids:
                    # Check if this field is ONLY in LHS contexts
                    # We need at least one non-LHS access for reads_state
                    continue
                read_fields.add(field_name)
                qualified = self._prefixed(prefix, f"{type_name}.{field_name}") if prefix else f"{type_name}.{field_name}"
                var_id = self._make_node_id(file_path, qualified)
                result.edges.append({
                    "source": func_id,
                    "target": var_id,
                    "relation": "reads_state",
                    "attributes": "{}",
                })

        # Call expressions -> calls edges
        for call in _collect_call_expressions(body_node):
            call_name = _get_call_name(call)
            if not call_name:
                continue

            callee = call.children[0] if call.children else None
            is_unresolved = False
            if callee and callee.type == "field_expression":
                obj = callee.children[0] if callee.children else None
                if obj and _text(obj) == "self" and type_name:
                    target_qualified = self._prefixed(prefix, f"{type_name}::{call_name}") if prefix else f"{type_name}::{call_name}"
                    target_id = self._make_node_id(file_path, target_qualified)
                else:
                    target_id = self._make_node_id(file_path, f"_unresolved::{call_name}")
                    is_unresolved = True
            elif callee and callee.type == "scoped_identifier":
                target_id = self._make_node_id(file_path, f"_unresolved::{call_name}")
                is_unresolved = True
            else:
                if type_name:
                    target_qualified = self._prefixed(prefix, f"{type_name}::{call_name}") if prefix else f"{type_name}::{call_name}"
                    target_id = self._make_node_id(file_path, target_qualified)
                else:
                    target_qualified = self._prefixed(prefix, call_name) if prefix else call_name
                    target_id = self._make_node_id(file_path, target_qualified)

            attrs = {}
            if is_unresolved:
                attrs = {"unresolved": True, "call_name": call_name}
            result.edges.append({
                "source": func_id,
                "target": target_id,
                "relation": "calls",
                "attributes": json.dumps(attrs) if attrs else "{}",
            })

        # Security pattern detection (must run after call edges are built)
        self._detect_security_patterns(
            body_node, func_node, func_id, file_path, type_name, meta, result)

    def _detect_state_transitions(self, assign_node, func_id, file_path, prefix,
                                  type_name, fields, enum_variants, result):
        """Detect enum state transitions from assignments like self.state = Enum::Variant."""
        if len(assign_node.children) < 2:
            return
        lhs = assign_node.children[0]
        rhs = assign_node.children[-1]

        lhs_field = None
        if lhs.type == "field_expression":
            is_self, field_name = _is_self_field_access(lhs)
            if is_self:
                lhs_field = field_name

        if not lhs_field:
            return

        scoped_ids = _collect_nodes_by_type(rhs, "scoped_identifier")
        for sid in scoped_ids:
            sid_text = _text(sid)
            if "::" in sid_text:
                parts = sid_text.split("::")
                enum_name = parts[0]
                variant = parts[1] if len(parts) > 1 else ""
                if enum_name in enum_variants:
                    result.transitions.append({
                        "entity": enum_name,
                        "from_state": "*",
                        "to_state": variant,
                        "function_id": func_id,
                        "guard": "",
                    })
        if rhs.type == "scoped_identifier":
            sid_text = _text(rhs)
            if "::" in sid_text:
                parts = sid_text.split("::")
                enum_name = parts[0]
                variant = parts[1] if len(parts) > 1 else ""
                if enum_name in enum_variants:
                    result.transitions.append({
                        "entity": enum_name,
                        "from_state": "*",
                        "to_state": variant,
                        "function_id": func_id,
                        "guard": "",
                    })

    # --- Security Pattern Detection ---

    def _detect_security_patterns(self, body_node, func_node, func_id,
                                   file_path, type_name, meta, result):
        """Detect Rust security patterns in a function body.

        Mutates `meta` dict to add security flags. Creates sink nodes
        for dangerous operations.
        """
        body_text = _text(body_node)
        is_test = self._is_test_context(file_path, func_node)

        # 1. Unsafe blocks
        unsafe_blocks = _collect_nodes_by_type(body_node, "unsafe_block")
        if unsafe_blocks:
            meta["unsafe_blocks"] = len(unsafe_blocks)
            # Check for specific dangerous patterns inside unsafe
            for ub in unsafe_blocks:
                ub_text = _text(ub)
                for pattern in UNSAFE_FFI_PATTERNS:
                    if pattern in ub_text:
                        meta.setdefault("unsafe_operations", [])
                        if pattern not in meta["unsafe_operations"]:
                            meta["unsafe_operations"].append(pattern)
                        # Create sink node for dangerous unsafe ops
                        self._create_sink_node(
                            pattern, "unsafe_ffi", func_id, file_path,
                            type_name, ub.start_point[0] + 1,
                            f"unsafe {{ {pattern}() }}", result)

        # 2. Panic/unwrap sinks (DoS vectors)
        # Only create sink nodes for pub functions (attack surface).
        # Still tag metadata for all non-test functions.
        is_pub = _get_visibility(func_node) == "pub"
        if not is_test:
            panic_calls_seen = set()
            for call in _collect_call_expressions(body_node):
                call_name = _get_call_name(call)
                if call_name in PANIC_SINKS and call_name not in panic_calls_seen:
                    panic_calls_seen.add(call_name)
                    meta.setdefault("panic_paths", [])
                    if call_name not in meta["panic_paths"]:
                        meta["panic_paths"].append(call_name)
                    # Only create sink nodes for pub functions to reduce noise
                    if is_pub:
                        self._create_sink_node(
                            call_name, "panic", func_id, file_path,
                            type_name, call.start_point[0] + 1,
                            _text(call)[:80], result)

            # Also detect .unwrap() / .expect() as method chains
            if ".unwrap()" in body_text or ".expect(" in body_text:
                if "panic_paths" not in meta:
                    meta["panic_paths"] = []
                if ".unwrap()" in body_text and "unwrap" not in meta["panic_paths"]:
                    meta["panic_paths"].append("unwrap")
                    if is_pub and "unwrap" not in panic_calls_seen:
                        self._create_sink_node(
                            "unwrap", "panic", func_id, file_path,
                            type_name, func_node.start_point[0] + 1,
                            "_.unwrap()", result)
                if ".expect(" in body_text and "expect" not in meta["panic_paths"]:
                    meta["panic_paths"].append("expect")
                    if is_pub and "expect" not in panic_calls_seen:
                        self._create_sink_node(
                            "expect", "panic", func_id, file_path,
                            type_name, func_node.start_point[0] + 1,
                            '_.expect("...")', result)

        # 3. Unchecked arithmetic detection
        # In release builds, Rust wraps on overflow. Flag explicit wrapping ops
        # and raw arithmetic on user-controlled values
        for pattern in OVERFLOW_METHODS:
            if pattern in body_text:
                meta.setdefault("wrapping_arithmetic", [])
                if pattern not in meta["wrapping_arithmetic"]:
                    meta["wrapping_arithmetic"].append(pattern)

        # 4. Unsafe function (the function itself is unsafe)
        if _has_unsafe_modifier(func_node):
            meta["is_unsafe_fn"] = True

        # 5. Raw pointer operations outside unsafe blocks
        if "*const " in body_text or "*mut " in body_text:
            meta["raw_pointers"] = True

        # 6. Crypto misuse
        for pattern in CRYPTO_MISUSE_PATTERNS:
            if pattern in body_text:
                meta.setdefault("crypto_concerns", [])
                if pattern not in meta["crypto_concerns"]:
                    meta["crypto_concerns"].append(pattern)

        # 7. Input validation: pub functions with parameters but no Result return
        #    and no assert/ensure/require checks
        if not is_test and _get_visibility(func_node) == "pub":
            has_params = self._has_meaningful_params(func_node)
            has_result_return = "Result" in body_text or "-> Result" in _text(func_node)
            has_validation = ("assert" in body_text or "ensure" in body_text
                              or "require" in body_text or "bail!" in body_text
                              or "anyhow!" in body_text or "return Err" in body_text)
            if has_params and not has_result_return and not has_validation:
                meta["no_input_validation"] = True

    def _is_test_context(self, file_path, func_node):
        """Check if we're in a test context."""
        if "_test.rs" in file_path or "/tests/" in file_path or "/test/" in file_path:
            return True
        # Check for #[test] or #[cfg(test)] attributes
        func_text = _text(func_node)
        if "#[test]" in func_text or "#[cfg(test)]" in func_text:
            return True
        return False

    def _has_meaningful_params(self, func_node):
        """Check if function has non-self parameters."""
        params = _child_by_type(func_node, "parameters")
        if not params:
            return False
        param_decls = [c for c in params.children
                       if c.type == "parameter" and _text(c).strip() not in
                       ("self", "&self", "&mut self", "mut self")]
        return len(param_decls) > 0

    def _create_sink_node(self, call_name, sink_type, func_id, file_path,
                           type_name, line, signature, result):
        """Create a sink node and edge for a dangerous operation."""
        container = type_name or "_module"
        sink_id = self._make_node_id(
            file_path, f"{container}._sink_{call_name}_{line}")
        result.nodes.append({
            "id": sink_id,
            "label": call_name,
            "type": "function",
            "visibility": "",
            "file": file_path,
            "line_start": line,
            "line_end": line,
            "signature": signature[:120],
            "metadata": json.dumps({
                "is_sink": True,
                "sink_type": sink_type,
                "struct": type_name or "",
            }),
        })
        result.edges.append({
            "source": func_id,
            "target": sink_id,
            "relation": "calls",
            "attributes": json.dumps({"sink": True}),
        })
