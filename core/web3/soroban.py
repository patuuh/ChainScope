"""Soroban/Stellar AST extraction using tree-sitter-rust."""

import json
import re
import tree_sitter_rust
from tree_sitter import Language, Parser
from core.web3 import ExtractResult
from core.web3.base import BaseExtractor


def _get_parser():
    lang = Language(tree_sitter_rust.language())
    parser = Parser(lang)
    return parser


def _child_by_type(node, type_name):
    for c in node.children:
        if c.type == type_name:
            return c
    return None


def _children_by_type(node, type_name):
    return [c for c in node.children if c.type == type_name]


def _text(node):
    return node.text.decode("utf-8") if node else ""


def _has_attribute(node, attr_name):
    """Check if any preceding attribute_item sibling contains attr_name.

    Walks backwards through ALL consecutive attribute_items before this node,
    since Rust attributes like #[contracterror] can be separated from the item
    by other attributes like #[derive(...)] and #[repr(u32)].
    """
    if node.parent is None:
        return False
    children = list(node.parent.children)
    idx = None
    for i, c in enumerate(children):
        if c.id == node.id:
            idx = i
            break
    if idx is None:
        return False
    for i in range(idx - 1, -1, -1):
        child = children[i]
        if child.type == "attribute_item":
            if attr_name in _text(child):
                return True
            # Continue checking more attributes
        else:
            break
    return False


def _get_preceding_attributes(node):
    """Get all attribute_item nodes immediately before this node."""
    attrs = []
    if node.parent is None:
        return attrs
    children = list(node.parent.children)
    idx = None
    for i, c in enumerate(children):
        if c.id == node.id:
            idx = i
            break
    if idx is None:
        return attrs
    for i in range(idx - 1, -1, -1):
        if children[i].type == "attribute_item":
            attrs.append(children[i])
        else:
            break
    return attrs


def _collect_calls(node):
    """Recursively collect call_expression nodes."""
    calls = []
    if node is None:
        return calls
    if node.type == "call_expression":
        calls.append(node)
    for child in node.children:
        calls.extend(_collect_calls(child))
    return calls


def _collect_macro_invocations(node):
    """Recursively collect macro_invocation nodes."""
    macros = []
    if node is None:
        return macros
    if node.type == "macro_invocation":
        macros.append(node)
    for child in node.children:
        macros.extend(_collect_macro_invocations(child))
    return macros


def _collect_assignments(node):
    """Recursively collect assignment_expression nodes."""
    assigns = []
    if node is None:
        return assigns
    if node.type == "assignment_expression":
        assigns.append(node)
    if node.type == "compound_assignment_expr":
        assigns.append(node)
    for child in node.children:
        assigns.extend(_collect_assignments(child))
    return assigns


def _collect_unsafe_blocks(node):
    """Recursively collect unsafe_block nodes."""
    blocks = []
    if node is None:
        return blocks
    if node.type == "unsafe_block":
        blocks.append(node)
    for child in node.children:
        blocks.extend(_collect_unsafe_blocks(child))
    return blocks


def _collect_for_loops(node):
    """Recursively collect for_expression nodes."""
    loops = []
    if node is None:
        return loops
    if node.type == "for_expression":
        loops.append(node)
    for child in node.children:
        loops.extend(_collect_for_loops(child))
    return loops


def _get_call_name(call_node):
    """Extract function name from call_expression."""
    func = _child_by_type(call_node, "field_expression")
    if func:
        field = _child_by_type(func, "field_identifier")
        return _text(field) if field else None
    # Handle generic_function: env.invoke_contract::<T>(...)
    generic = _child_by_type(call_node, "generic_function")
    if generic:
        field_expr = _child_by_type(generic, "field_expression")
        if field_expr:
            field = _child_by_type(field_expr, "field_identifier")
            return _text(field) if field else None
        scoped = _child_by_type(generic, "scoped_identifier")
        if scoped:
            ids = _children_by_type(scoped, "identifier")
            return _text(ids[-1]) if ids else None
        ident = _child_by_type(generic, "identifier")
        if ident:
            return _text(ident)
    scoped = _child_by_type(call_node, "scoped_identifier")
    if scoped:
        ids = _children_by_type(scoped, "identifier")
        return _text(ids[-1]) if ids else None
    ident = _child_by_type(call_node, "identifier")
    if ident:
        return _text(ident)
    return None


def _get_full_call_text(call_node):
    """Get full text of a call expression."""
    return _text(call_node)


# --- Soroban-specific patterns ---

# Admin/privileged function name patterns (A2)
ADMIN_FUNCTION_PATTERNS = re.compile(
    r"^(set_admin|upgrade|pause|unpause|mint|clawback|"
    r"set_fee|set_oracle|set_config|emergency|freeze|"
    r"update_current_contract_wasm|initialize)$",
    re.IGNORECASE,
)

# Panic/error patterns (E1-E4)
PANIC_SINKS = {
    "unwrap", "expect", "panic", "unreachable",
    "unimplemented", "todo",
}

PANIC_MACROS = {
    "panic", "assert", "assert_eq", "assert_ne",
    "unreachable", "unimplemented", "todo",
}

# Storage method patterns
STORAGE_READ_METHODS = {"get", "has", "contains_key"}
STORAGE_WRITE_METHODS = {"set", "remove", "update"}
STORAGE_TTL_METHODS = {"extend_ttl"}

# Storage tier names
STORAGE_TIERS = {"instance", "persistent", "temporary"}

# Token-related method patterns for SEP-41 detection
TOKEN_TRANSFER_METHODS = {
    "transfer", "transfer_from", "approve", "burn",
    "burn_from", "mint",
}

# Cross-contract call patterns
CROSS_CONTRACT_METHODS = {"invoke_contract", "try_invoke_contract"}


class SorobanExtractor(BaseExtractor):

    def __init__(self):
        self.parser = _get_parser()

    def extract_from_source(self, source_code: bytes, file_path: str) -> ExtractResult:
        tree = self.parser.parse(source_code)
        return self.extract(tree, source_code, file_path)

    def extract(self, tree, source_code: bytes, file_path: str) -> ExtractResult:
        result = ExtractResult()
        root = tree.root_node
        enum_map: dict[str, list[str]] = {}
        contract_name = None

        # First pass: collect enums, structs, errors (may appear before/after contractimpl)
        for child in root.children:
            if child.type == "enum_item":
                if _has_attribute(child, "contracterror"):
                    self._extract_error_enum(child, file_path, result)
                elif _has_attribute(child, "contracttype"):
                    self._extract_contracttype_enum(child, file_path, result, enum_map)
                else:
                    # Plain enum — still collect for state machine detection
                    self._collect_enum_variants(child, enum_map)
            elif child.type == "struct_item":
                if _has_attribute(child, "contract"):
                    contract_name = self._extract_contract_struct(child, file_path, result)
                elif _has_attribute(child, "contracttype"):
                    self._extract_contracttype_struct(child, file_path, result)

        # Second pass: extract contractimpl blocks
        func_ts_map: dict[int, str] = {}
        all_functions: list[dict] = []

        for child in root.children:
            if child.type == "impl_item":
                if _has_attribute(child, "contractimpl"):
                    self._extract_contractimpl(
                        child, file_path, contract_name or "Contract",
                        result, func_ts_map, enum_map, all_functions,
                    )

        # Post-pass: security analysis
        self._analyze_security(result, file_path, all_functions, source_code)

        return result

    # --- Contract struct extraction ---

    def _extract_contract_struct(self, node, file_path, result) -> str:
        """Extract #[contract] struct as the main contract node."""
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return "Contract"
        struct_name = _text(name_node)
        struct_id = self._make_node_id(file_path, struct_name)

        result.nodes.append({
            "id": struct_id,
            "label": struct_name,
            "type": "contract",
            "visibility": "public",
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"struct {struct_name}",
            "metadata": json.dumps({"is_contract": True}),
        })
        return struct_name

    # --- ContractType structs ---

    def _extract_contracttype_struct(self, node, file_path, result):
        """Extract #[contracttype] struct."""
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return
        struct_name = _text(name_node)
        struct_id = self._make_node_id(file_path, struct_name)

        fields = []
        field_list = _child_by_type(node, "field_declaration_list")
        if field_list:
            for fd in _children_by_type(field_list, "field_declaration"):
                fname = _child_by_type(fd, "field_identifier")
                if fname:
                    fields.append(_text(fname))

        result.nodes.append({
            "id": struct_id,
            "label": struct_name,
            "type": "struct",
            "visibility": "public",
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"struct {struct_name}",
            "metadata": json.dumps({
                "contracttype": True,
                "fields": fields,
            }),
        })

        # Create state_var nodes for fields
        for field_name in fields:
            field_id = self._make_node_id(file_path, f"{struct_name}.{field_name}")
            result.nodes.append({
                "id": field_id,
                "label": field_name,
                "type": "state_var",
                "visibility": "public",
                "file": file_path,
                "line_start": node.start_point[0] + 1,
                "line_end": node.end_point[0] + 1,
                "signature": field_name,
                "metadata": json.dumps({"parent_struct": struct_name}),
            })
            result.edges.append({
                "source": struct_id,
                "target": field_id,
                "relation": "contains",
                "attributes": "{}",
            })

    # --- ContractType enums ---

    def _extract_contracttype_enum(self, node, file_path, result, enum_map):
        """Extract #[contracttype] enum."""
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return
        enum_name = _text(name_node)
        enum_id = self._make_node_id(file_path, enum_name)

        variants = self._get_enum_variants(node)
        enum_map[enum_name] = variants

        result.nodes.append({
            "id": enum_id,
            "label": enum_name,
            "type": "enum",
            "visibility": "public",
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"enum {enum_name}",
            "metadata": json.dumps({
                "contracttype": True,
                "variants": variants,
            }),
        })

        # Create variant nodes
        for variant_name in variants:
            variant_id = self._make_node_id(file_path, variant_name)
            result.nodes.append({
                "id": variant_id,
                "label": variant_name,
                "type": "enum_variant",
                "visibility": "public",
                "file": file_path,
                "line_start": node.start_point[0] + 1,
                "line_end": node.end_point[0] + 1,
                "signature": f"{enum_name}::{variant_name}",
                "metadata": json.dumps({"parent_enum": enum_name}),
            })
            result.edges.append({
                "source": enum_id,
                "target": variant_id,
                "relation": "contains",
                "attributes": "{}",
            })

    # --- ContractError enums ---

    def _extract_error_enum(self, node, file_path, result):
        """Extract #[contracterror] enum."""
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return
        enum_name = _text(name_node)
        enum_id = self._make_node_id(file_path, enum_name)

        variants = self._get_enum_variants(node)
        # Extract error codes from #[repr(u32)]
        error_codes = {}
        # Parse the enum body for variant = value patterns
        variant_list = _child_by_type(node, "enum_variant_list")
        if variant_list:
            for v in _children_by_type(variant_list, "enum_variant"):
                vid = _child_by_type(v, "identifier")
                # Look for = value
                v_text = _text(v)
                eq_match = re.search(r"=\s*(\d+)", v_text)
                if vid and eq_match:
                    error_codes[_text(vid)] = int(eq_match.group(1))

        result.nodes.append({
            "id": enum_id,
            "label": enum_name,
            "type": "error",
            "visibility": "public",
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"enum {enum_name}",
            "metadata": json.dumps({
                "contracterror": True,
                "variants": variants,
                "error_codes": error_codes,
            }),
        })

    # --- Enum helper ---

    def _get_enum_variants(self, node) -> list[str]:
        variant_list = _child_by_type(node, "enum_variant_list")
        variants = []
        if variant_list:
            for v in _children_by_type(variant_list, "enum_variant"):
                vid = _child_by_type(v, "identifier")
                if vid:
                    variants.append(_text(vid))
        return variants

    def _collect_enum_variants(self, node, enum_map):
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return
        enum_name = _text(name_node)
        enum_map[enum_name] = self._get_enum_variants(node)

    # --- ContractImpl extraction ---

    def _extract_contractimpl(self, impl_node, file_path, contract_name,
                               result, func_ts_map, enum_map, all_functions):
        """Extract all functions from a #[contractimpl] block."""
        decl_list = _child_by_type(impl_node, "declaration_list")
        if not decl_list:
            return

        for item in decl_list.children:
            if item.type == "function_item":
                self._extract_function(
                    item, file_path, contract_name,
                    result, func_ts_map, enum_map, all_functions,
                )

    def _extract_function(self, node, file_path, contract_name,
                           result, func_ts_map, enum_map, all_functions):
        """Extract a single function from #[contractimpl]."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        func_name = _text(name_node)
        func_id = self._make_node_id(file_path, func_name)
        func_ts_map[node.id] = func_id

        # Visibility
        vis_node = _child_by_type(node, "visibility_modifier")
        visibility = "public" if vis_node else "private"

        # Parameters
        params = []
        param_list = _child_by_type(node, "parameters")
        has_env_param = False
        if param_list:
            for p in _children_by_type(param_list, "parameter"):
                ptext = _text(p)
                params.append(ptext)
                if "Env" in ptext:
                    has_env_param = True

        # Self parameter (non-entry-point internal methods)
        has_self = False
        if param_list:
            for p in param_list.children:
                if p.type == "self_parameter":
                    has_self = True

        sig = f"fn {func_name}({', '.join(params)})"

        # Return type
        ret_type = None
        for child in node.children:
            if child.type == "type_identifier" and child.prev_sibling and _text(child.prev_sibling) == "->":
                ret_type = _text(child)

        meta = {
            "contract": contract_name,
            "is_entry_point": visibility == "public" and has_env_param and not has_self,
        }
        if ret_type:
            meta["return_type"] = ret_type

        # Parse body for detailed analysis
        body = _child_by_type(node, "block")
        body_text = _text(body) if body else ""

        # Auth detection — strip comments to avoid false positives
        has_auth = False
        has_custom_auth = False
        code_text = re.sub(r'//[^\n]*', '', body_text)  # strip line comments
        code_text = re.sub(r'/\*.*?\*/', '', code_text, flags=re.DOTALL)  # strip block comments
        if "require_auth()" in code_text or ".require_auth()" in code_text:
            has_auth = True
        if "require_auth_for_args" in code_text:
            has_auth = True
            has_custom_auth = True
        meta["has_auth"] = has_auth
        if has_custom_auth:
            meta["custom_auth_args"] = True

        # Storage operation detection
        storage_ops = self._detect_storage_ops(body_text)
        if storage_ops:
            meta["storage_ops"] = storage_ops

        # Upgrade detection
        if "update_current_contract_wasm" in body_text:
            meta["is_upgrade"] = True

        # PRNG detection (H1)
        if "env.prng()" in body_text or ".prng()" in body_text:
            meta["insecure_randomness"] = True

        # Ledger timestamp/sequence usage (H2)
        if "ledger().timestamp()" in body_text or "ledger().sequence()" in body_text:
            meta["time_dependent"] = True

        # Unsafe block detection (E6)
        if body:
            unsafe_blocks = _collect_unsafe_blocks(body)
            if unsafe_blocks:
                meta["unsafe"] = True

        result.nodes.append({
            "id": func_id,
            "label": func_name,
            "type": "function",
            "visibility": visibility,
            "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": sig,
            "metadata": json.dumps(meta),
        })

        # Track for post-pass security analysis
        all_functions.append({
            "id": func_id,
            "name": func_name,
            "visibility": visibility,
            "has_auth": has_auth,
            "has_custom_auth": has_custom_auth,
            "body_text": body_text,
            "meta": meta,
            "node": node,
            "body": body,
        })

        # Extract body edges
        if body:
            self._extract_body_edges(
                body, func_id, file_path, contract_name,
                enum_map, result, body_text,
            )

    def _detect_storage_ops(self, body_text: str) -> dict:
        """Detect storage read/write/ttl operations by tier."""
        ops = {}
        for tier in STORAGE_TIERS:
            tier_ops = {}
            # Pattern: .storage().tier().method(
            for method in STORAGE_READ_METHODS:
                pattern = rf"\.{tier}\(\)\s*\.\s*{method}\s*\("
                if re.search(pattern, body_text):
                    tier_ops.setdefault("reads", []).append(method)
            for method in STORAGE_WRITE_METHODS:
                pattern = rf"\.{tier}\(\)\s*\.\s*{method}\s*\("
                if re.search(pattern, body_text):
                    tier_ops.setdefault("writes", []).append(method)
            for method in STORAGE_TTL_METHODS:
                pattern = rf"\.{tier}\(\)\s*\.\s*{method}\s*\("
                if re.search(pattern, body_text):
                    tier_ops.setdefault("ttl", []).append(method)
            if tier_ops:
                ops[tier] = tier_ops
        return ops

    def _extract_body_edges(self, body, func_id, file_path, contract_name,
                             enum_map, result, body_text):
        """Extract edges from function body."""

        # --- Storage read/write edges ---
        self._extract_storage_edges(body_text, func_id, file_path, result)

        # --- Call edges ---
        for call in _collect_calls(body):
            call_name = _get_call_name(call)
            if not call_name:
                continue
            call_text = _get_full_call_text(call)

            # Cross-contract call detection
            is_cross_contract = False
            if call_name in CROSS_CONTRACT_METHODS:
                is_cross_contract = True
            # Client pattern: token_client.transfer(...)
            if "Client::new" in call_text or "_client." in call_text.lower():
                is_cross_contract = True

            if is_cross_contract:
                sink_id = self._make_node_id(
                    file_path,
                    f"_cross_{call_name}_{call.start_point[0]}",
                )
                is_token = any(t in call_text for t in ("TokenClient", "StellarAssetClient", "token_client"))
                sink_type = "token_transfer" if is_token else "cross_contract"

                result.nodes.append({
                    "id": sink_id,
                    "label": call_name,
                    "type": "function",
                    "visibility": "",
                    "file": file_path,
                    "line_start": call.start_point[0] + 1,
                    "line_end": call.end_point[0] + 1,
                    "signature": call_text[:120],
                    "metadata": json.dumps({
                        "contract": contract_name,
                        "is_sink": True,
                        "sink_type": sink_type,
                        "cross_contract": True,
                    }),
                })
                result.edges.append({
                    "source": func_id,
                    "target": sink_id,
                    "relation": "calls",
                    "attributes": json.dumps({
                        "sink": True,
                        "cross_contract": True,
                        "order": call.start_point[0],
                    }),
                })
            else:
                # Regular call
                target_id = self._make_node_id(file_path, call_name)
                attrs = {}
                if call_name in PANIC_SINKS:
                    attrs["panic_sink"] = True
                result.edges.append({
                    "source": func_id,
                    "target": target_id,
                    "relation": "calls",
                    "attributes": json.dumps(attrs) if attrs else "{}",
                })

        # --- Event emission edges ---
        # Pattern: env.events().publish((...), ...)
        # The symbol_short! macro may be inside nested parens
        event_blocks = re.finditer(
            r'events\(\)\s*\.\s*publish\s*\(',
            body_text,
        )
        for event_block in event_blocks:
            # Search for symbol_short! in the surrounding context (next ~200 chars)
            context = body_text[event_block.start():event_block.start() + 300]
            topic_match = re.search(r'symbol_short!\("(\w+)"\)', context)
            event_name = topic_match.group(1) if topic_match else "unknown_event"
            event_id = self._make_node_id(file_path, f"_event_{event_name}")
            result.nodes.append({
                "id": event_id,
                "label": f"event:{event_name}",
                "type": "event",
                "visibility": "public",
                "file": file_path,
                "line_start": body.start_point[0] + 1,
                "line_end": body.end_point[0] + 1,
                "signature": f"event::{event_name}",
                "metadata": json.dumps({"contract": contract_name}),
            })
            result.edges.append({
                "source": func_id,
                "target": event_id,
                "relation": "emits_event",
                "attributes": json.dumps({"event": event_name}),
            })

        # --- Auth guard edges ---
        if "require_auth" in body_text:
            guard_id = self._make_node_id(file_path, "_guard_require_auth")
            result.edges.append({
                "source": guard_id,
                "target": func_id,
                "relation": "guards",
                "attributes": json.dumps({"auth_type": "require_auth"}),
            })

        # --- Macro invocations (panic_with_error!, assert!, etc.) ---
        for macro in _collect_macro_invocations(body):
            macro_name_node = _child_by_type(macro, "identifier")
            if not macro_name_node:
                continue
            macro_name = _text(macro_name_node)
            if macro_name in PANIC_MACROS:
                panic_id = self._make_node_id(
                    file_path,
                    f"_panic_{macro_name}_{macro.start_point[0]}",
                )
                result.edges.append({
                    "source": func_id,
                    "target": panic_id,
                    "relation": "calls",
                    "attributes": json.dumps({"panic_sink": True, "macro": macro_name}),
                })

        # --- State transitions ---
        # Check both direct assignments and storage.set() calls for enum variants
        for enum_name, variants in enum_map.items():
            for variant in variants:
                pattern = f"{enum_name}::{variant}"
                # Check in assignments
                for assign in _collect_assignments(body):
                    if pattern in _text(assign):
                        from_state = self._find_require_state(body, enum_name, body_text)
                        conditions = self._collect_conditions(body)
                        result.transitions.append({
                            "entity": enum_name,
                            "from_state": from_state,
                            "to_state": variant,
                            "function_id": func_id,
                            "conditions": json.dumps(conditions),
                        })
                        break
                else:
                    # Also check in storage.set() calls with enum values
                    if pattern in body_text and ".set(" in body_text:
                        from_state = self._find_require_state(body, enum_name, body_text)
                        conditions = self._collect_conditions(body)
                        result.transitions.append({
                            "entity": enum_name,
                            "from_state": from_state,
                            "to_state": variant,
                            "function_id": func_id,
                            "conditions": json.dumps(conditions),
                        })

        # --- Unchecked arithmetic (B4) ---
        self._detect_unchecked_arithmetic(body, func_id, file_path, result, body_text)

        # --- Division before multiplication (B2) ---
        self._detect_div_before_mul(body_text, func_id, file_path, result)

        # --- XOR as exponentiation (B3) ---
        self._detect_xor_exponentiation(body_text, func_id, file_path, result)

    def _extract_storage_edges(self, body_text, func_id, file_path, result):
        """Extract storage read/write edges with tier information."""
        for tier in STORAGE_TIERS:
            # Read patterns
            for method in STORAGE_READ_METHODS:
                pattern = rf"\.{tier}\(\)\s*\.\s*{method}\s*\("
                for m in re.finditer(pattern, body_text):
                    # Try to extract the key
                    key_match = re.search(
                        rf"\.{tier}\(\)\s*\.\s*{method}\s*\(\s*&?(\w+(?:::\w+(?:\([^)]*\))?)?)",
                        body_text[m.start():m.start() + 200],
                    )
                    key_name = key_match.group(1) if key_match else "unknown"
                    storage_id = self._make_node_id(
                        file_path, f"_storage_{tier}_{key_name}",
                    )
                    result.edges.append({
                        "source": func_id,
                        "target": storage_id,
                        "relation": "reads_state",
                        "attributes": json.dumps({
                            "storage_tier": tier,
                            "key": key_name,
                        }),
                    })

            # Write patterns
            for method in STORAGE_WRITE_METHODS:
                pattern = rf"\.{tier}\(\)\s*\.\s*{method}\s*\("
                for m in re.finditer(pattern, body_text):
                    key_match = re.search(
                        rf"\.{tier}\(\)\s*\.\s*{method}\s*\(\s*&?(\w+(?:::\w+(?:\([^)]*\))?)?)",
                        body_text[m.start():m.start() + 200],
                    )
                    key_name = key_match.group(1) if key_match else "unknown"
                    storage_id = self._make_node_id(
                        file_path, f"_storage_{tier}_{key_name}",
                    )
                    result.edges.append({
                        "source": func_id,
                        "target": storage_id,
                        "relation": "writes_state",
                        "attributes": json.dumps({
                            "storage_tier": tier,
                            "key": key_name,
                            "order": m.start(),
                        }),
                    })

    def _find_require_state(self, body, enum_name, body_text) -> str:
        """Find from_state from conditionals like: state != VaultState::Active."""
        pattern = rf"{enum_name}::(\w+)"
        # Look for comparison patterns
        for check_pat in [r"==\s*", r"!=\s*"]:
            match = re.search(check_pat + pattern, body_text)
            if match:
                return match.group(1)
        return "*"

    def _collect_conditions(self, body) -> list[str]:
        """Collect all guard conditions from function body."""
        conditions = []
        for macro in _collect_macro_invocations(body):
            macro_name_node = _child_by_type(macro, "identifier")
            if not macro_name_node:
                continue
            name = _text(macro_name_node)
            if name in ("panic_with_error", "assert", "assert_eq"):
                token_tree = _child_by_type(macro, "token_tree")
                if token_tree:
                    conditions.append(_text(token_tree).strip("()"))
        # Also collect if-panic patterns
        body_text = _text(body)
        for m in re.finditer(r'if\s+(.+?)\s*\{[^}]*panic', body_text):
            conditions.append(m.group(1).strip())
        return conditions

    def _detect_unchecked_arithmetic(self, body, func_id, file_path, result, body_text):
        """B4: Detect unchecked arithmetic on i128/u128 values."""
        has_checked = any(x in body_text for x in (
            "checked_add", "checked_sub", "checked_mul", "checked_div",
            "saturating_add", "saturating_sub", "saturating_mul",
        ))
        if has_checked:
            return

        # Compound assignments
        compound_pattern = re.compile(r'(\w+)\s*(\+=|-=|\*=)')
        # Binary arithmetic in expressions
        binary_pattern = re.compile(r'(\w+)\s*(\+|-|\*)\s*(\w+)')

        for pattern in [compound_pattern, binary_pattern]:
            for match in pattern.finditer(body_text):
                op = match.group(2)
                checked_ops = {
                    "+": "checked_add", "+=": "checked_add",
                    "-": "checked_sub", "-=": "checked_sub",
                    "*": "checked_mul", "*=": "checked_mul",
                }
                arith_id = self._make_node_id(
                    file_path,
                    f"_arith_{func_id.split('::')[-1]}_{match.start()}",
                )
                result.edges.append({
                    "source": func_id,
                    "target": arith_id,
                    "relation": "unchecked_math",
                    "attributes": json.dumps({
                        "unchecked_arithmetic": True,
                        "operation": match.group(0).strip()[:80],
                    }),
                })
                break  # One flag per function is sufficient

    def _detect_div_before_mul(self, body_text, func_id, file_path, result):
        """B2: Detect division before multiplication patterns."""
        # Pattern: (a / b) * c
        if re.search(r'\w+\s*/\s*\w+\s*\)\s*\*\s*\w+', body_text):
            result.edges.append({
                "source": func_id,
                "target": self._make_node_id(file_path, "_precision_loss"),
                "relation": "unchecked_math",
                "attributes": json.dumps({
                    "precision_loss": True,
                    "pattern": "division_before_multiplication",
                }),
            })

    def _detect_xor_exponentiation(self, body_text, func_id, file_path, result):
        """B3: Detect ^ used as exponentiation (it's XOR in Rust)."""
        # Strip comments first
        code_only = re.sub(r'//[^\n]*', '', body_text)
        # Pattern: value ^ value (the caret operator on non-boolean expressions)
        if re.search(r'[)\w]\s*\^\s*\w+', code_only):
            # Check it's not a boolean context and .pow() isn't used instead
            if ".pow(" not in code_only:
                result.edges.append({
                    "source": func_id,
                    "target": self._make_node_id(file_path, "_xor_as_pow"),
                    "relation": "unchecked_math",
                    "attributes": json.dumps({
                        "xor_as_exponentiation": True,
                        "pattern": "caret_not_power",
                    }),
                })

    # --- Post-pass security analysis ---

    def _analyze_security(self, result, file_path, all_functions, source_code):
        """Run all security detectors on extracted data."""
        source_text = source_code.decode("utf-8") if isinstance(source_code, bytes) else source_code

        for func in all_functions:
            warnings = []
            meta = func["meta"]
            func_name = func["name"]
            body_text = func["body_text"]
            is_entry = meta.get("is_entry_point", False)

            # A1: Missing require_auth on state-modifying public functions
            if is_entry and not func["has_auth"]:
                storage_ops = meta.get("storage_ops", {})
                has_writes = any(
                    "writes" in ops for ops in storage_ops.values()
                )
                if has_writes:
                    warnings.append({
                        "type": "missing_auth",
                        "severity": "critical",
                        "detail": f"Public function '{func_name}' writes state without require_auth()",
                    })

            # A2: Missing auth on admin functions
            if is_entry and not func["has_auth"]:
                if ADMIN_FUNCTION_PATTERNS.match(func_name):
                    warnings.append({
                        "type": "missing_admin_auth",
                        "severity": "critical",
                        "detail": f"Admin function '{func_name}' has no auth check",
                    })

            # A3: Unprotected upgrade
            if meta.get("is_upgrade") and not func["has_auth"]:
                warnings.append({
                    "type": "unprotected_upgrade",
                    "severity": "critical",
                    "detail": "update_current_contract_wasm() called without require_auth()",
                })

            # A4: Storage writes with user-supplied keys
            if is_entry and body_text:
                # Check if any fn parameter is used as a storage key
                param_names = re.findall(r'(\w+)\s*:', func["meta"].get("signature", ""))
                for pname in param_names:
                    if pname in ("env", "self"):
                        continue
                    # Check if param appears in storage set key
                    if re.search(rf'\.set\s*\(\s*&?.*{pname}', body_text):
                        if not func["has_auth"]:
                            warnings.append({
                                "type": "unprotected_storage_key",
                                "severity": "high",
                                "detail": f"User parameter '{pname}' used as storage key without auth",
                            })

            # C1: Unbounded instance storage
            if "instance" in meta.get("storage_ops", {}):
                if "Vec" in body_text and ".push_back(" in body_text:
                    if "instance().set" in body_text or "instance()\n" in body_text:
                        warnings.append({
                            "type": "unbounded_instance_storage",
                            "severity": "high",
                            "detail": "Growing Vec in instance storage — loads all data per call",
                        })

            # C7: Missing extend_ttl on persistent writes
            storage_ops = meta.get("storage_ops", {})
            persistent_ops = storage_ops.get("persistent", {})
            if "writes" in persistent_ops and "ttl" not in persistent_ops:
                warnings.append({
                    "type": "missing_extend_ttl",
                    "severity": "medium",
                    "detail": "Persistent storage write without extend_ttl()",
                })

            # C3/C8: Security-critical data in temporary storage
            temp_ops = storage_ops.get("temporary", {})
            if "writes" in temp_ops:
                if any(w in func_name.lower() for w in ("nonce", "auth", "lock")):
                    warnings.append({
                        "type": "security_in_temporary",
                        "severity": "high",
                        "detail": f"Security-critical data in temporary storage (function: {func_name}) — can expire and allow replay",
                    })

            # E1: panic! instead of panic_with_error!
            if "panic!(" in body_text and "panic_with_error!" not in body_text:
                warnings.append({
                    "type": "unstructured_panic",
                    "severity": "medium",
                    "detail": "Using panic!() instead of panic_with_error!() — callers cannot distinguish error types",
                })

            # E2/E3: unwrap/expect in contract code
            unwrap_count = body_text.count(".unwrap()")
            expect_count = body_text.count(".expect(")
            if unwrap_count > 0:
                warnings.append({
                    "type": "unsafe_unwrap",
                    "severity": "medium",
                    "detail": f"{unwrap_count} .unwrap() call(s) — can cause unstructured panics",
                })
            if expect_count > 0:
                warnings.append({
                    "type": "unsafe_expect",
                    "severity": "medium",
                    "detail": f"{expect_count} .expect() call(s) — can cause unstructured panics",
                })

            # E6: Unsafe blocks
            if meta.get("unsafe"):
                warnings.append({
                    "type": "unsafe_block",
                    "severity": "critical",
                    "detail": "Unsafe block in contract code — memory safety not guaranteed",
                })

            # F2: State write after cross-contract call (reentrancy)
            if func["body"]:
                self._detect_state_after_external_call(
                    func["body"], body_text, func["id"], warnings,
                )

            # G2: Missing events for token operations
            if func_name in TOKEN_TRANSFER_METHODS:
                if "events().publish" not in body_text:
                    warnings.append({
                        "type": "missing_token_event",
                        "severity": "medium",
                        "detail": f"Token function '{func_name}' does not emit an event — SEP-41 non-compliance",
                    })

            # G4: Missing amount validation for token ops
            if func_name in ("mint", "transfer", "burn", "approve"):
                # Strip comments to avoid false positives
                code_only = re.sub(r'//[^\n]*', '', body_text)
                code_only = re.sub(r'/\*.*?\*/', '', code_only, flags=re.DOTALL)
                if "amount" in code_only and "amount <= 0" not in code_only and "amount > 0" not in code_only:
                    if "InvalidAmount" not in code_only:
                        warnings.append({
                            "type": "missing_amount_validation",
                            "severity": "medium",
                            "detail": f"Token function '{func_name}' may not validate amount > 0",
                        })

            # H1: PRNG for security decisions
            if meta.get("insecure_randomness"):
                warnings.append({
                    "type": "insecure_prng",
                    "severity": "critical",
                    "detail": "env.prng() is deterministic — not suitable for security-critical randomness",
                })

            # H2: Ledger attributes as randomness
            if meta.get("time_dependent"):
                # Check if it's used for selection/randomness
                if any(w in func_name.lower() for w in ("random", "select", "winner", "lottery")):
                    warnings.append({
                        "type": "timestamp_randomness",
                        "severity": "critical",
                        "detail": "Ledger timestamp/sequence used for randomness — predictable by validators",
                    })

            # J1: Unbounded loops
            if func["body"]:
                for loop_node in _collect_for_loops(func["body"]):
                    loop_text = _text(loop_node)
                    # Check if loop bound comes from dynamic source
                    if ".len()" in loop_text and "recipients" in loop_text:
                        warnings.append({
                            "type": "unbounded_loop",
                            "severity": "high",
                            "detail": "Loop over dynamic-length data without bounds check — DoS risk",
                        })

            # Attach warnings to the function node
            if warnings:
                for n in result.nodes:
                    if n["id"] == func["id"]:
                        existing_meta = json.loads(n.get("metadata", "{}"))
                        existing_meta["soroban_risks"] = warnings
                        n["metadata"] = json.dumps(existing_meta)
                        break

        # I2: Check if contract has upgrade function
        has_upgrade = any(
            f["meta"].get("is_upgrade") for f in all_functions
        )
        if not has_upgrade and all_functions:
            # Informational: no upgrade path
            for n in result.nodes:
                if n["type"] == "contract":
                    meta = json.loads(n.get("metadata", "{}"))
                    meta["no_upgrade_function"] = True
                    n["metadata"] = json.dumps(meta)

        # I3: Upgrade without event
        for func in all_functions:
            if func["meta"].get("is_upgrade"):
                if "events().publish" not in func["body_text"]:
                    for n in result.nodes:
                        if n["id"] == func["id"]:
                            meta = json.loads(n.get("metadata", "{}"))
                            risks = meta.get("soroban_risks", [])
                            risks.append({
                                "type": "upgrade_no_event",
                                "severity": "medium",
                                "detail": "Contract upgrade without event emission — poor transparency",
                            })
                            meta["soroban_risks"] = risks
                            n["metadata"] = json.dumps(meta)
                            break

    def _detect_state_after_external_call(self, body, body_text, func_id, warnings):
        """F2: Detect storage writes that occur after cross-contract calls."""
        # Find positions of cross-contract calls
        cross_positions = []
        for call in _collect_calls(body):
            call_text = _get_full_call_text(call)
            is_cross = (
                "invoke_contract" in call_text
                or "try_invoke_contract" in call_text
                or "Client::new" in call_text
                or "_client." in call_text.lower()
                or "token_client" in call_text.lower()
            )
            if is_cross:
                cross_positions.append(call.start_point[0])

        if not cross_positions:
            return

        min_cross_line = min(cross_positions)

        # Find storage writes after the cross-contract call
        for tier in STORAGE_TIERS:
            for method in STORAGE_WRITE_METHODS:
                pattern = rf"\.{tier}\(\)\s*\.\s*{method}\s*\("
                for m in re.finditer(pattern, body_text):
                    # Estimate line from character position
                    write_line = body_text[:m.start()].count("\n")
                    if write_line > min_cross_line - body.start_point[0]:
                        warnings.append({
                            "type": "state_after_external_call",
                            "severity": "high",
                            "detail": f"Storage write ({tier}.{method}) after cross-contract call — potential reentrancy",
                        })
                        return  # One warning is enough
