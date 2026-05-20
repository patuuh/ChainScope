"""Substrate/Polkadot pallet AST extraction using tree-sitter-rust."""

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


def _has_preceding_attribute(node, attr_name):
    """Check if node has a preceding attribute_item containing attr_name."""
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
        if children[i].type == "attribute_item":
            if attr_name in _text(children[i]):
                return True
        else:
            break
    return False


def _get_preceding_attribute_text(node, attr_name):
    """Get the full text of a preceding attribute_item containing attr_name, or None."""
    if node.parent is None:
        return None
    children = list(node.parent.children)
    idx = None
    for i, c in enumerate(children):
        if c.id == node.id:
            idx = i
            break
    if idx is None:
        return None
    for i in range(idx - 1, -1, -1):
        if children[i].type == "attribute_item":
            text = _text(children[i])
            if attr_name in text:
                return text
        else:
            break
    return None


def _collect_calls(node):
    calls = []
    if node is None:
        return calls
    if node.type == "call_expression":
        calls.append(node)
    for child in node.children:
        calls.extend(_collect_calls(child))
    return calls


def _collect_macro_invocations(node):
    macros = []
    if node is None:
        return macros
    if node.type == "macro_invocation":
        macros.append(node)
    for child in node.children:
        macros.extend(_collect_macro_invocations(child))
    return macros


# Patterns for currency-related sink methods
_CURRENCY_SINK_PATTERNS = re.compile(
    r"transfer|deposit|withdraw|slash|reserve|unreserve|burn|mint",
    re.IGNORECASE,
)

# Hook types with specific metadata
_HOOK_TYPES = {
    "on_initialize": "on_initialize",
    "on_finalize": "on_finalize",
    "on_idle": "on_idle",
    "offchain_worker": "offchain_worker",
    "integrity_test": "integrity_test",
    "on_runtime_upgrade": "on_runtime_upgrade",
    "pre_upgrade": "pre_upgrade",
    "post_upgrade": "post_upgrade",
}

# Migration hooks
_MIGRATION_HOOKS = {"on_runtime_upgrade", "pre_upgrade", "post_upgrade"}


class SubstrateExtractor(BaseExtractor):

    def __init__(self):
        self.parser = _get_parser()

    def extract_from_source(self, source_code: bytes, file_path: str) -> ExtractResult:
        tree = self.parser.parse(source_code)
        return self.extract(tree, source_code, file_path)

    def extract(self, tree, source_code: bytes, file_path: str) -> ExtractResult:
        result = ExtractResult()
        root = tree.root_node
        enum_map: dict[str, list[str]] = {}
        pallet_name = None

        # Find the pallet mod
        for child in root.children:
            if child.type == "mod_item":
                name_node = _child_by_type(child, "identifier")
                if name_node:
                    pallet_name = _text(name_node)
                self._extract_pallet_mod(child, file_path, pallet_name or "pallet", result, enum_map)

        return result

    def _extract_pallet_mod(self, mod_node, file_path, pallet_name, result, enum_map):
        """Extract all pallet components from the mod."""
        decl = _child_by_type(mod_node, "declaration_list")
        if not decl:
            return

        # First pass: collect enums
        for item in decl.children:
            if item.type == "enum_item":
                self._extract_enum(item, file_path, pallet_name, result, enum_map)

        # Second pass: extract storage, impl blocks, hooks, inherents
        for item in decl.children:
            if item.type == "type_item" and _has_preceding_attribute(item, "pallet::storage"):
                self._extract_storage(item, file_path, pallet_name, result)
            elif item.type == "impl_item":
                if _has_preceding_attribute(item, "pallet::call"):
                    self._extract_call_impl(item, file_path, pallet_name, result, enum_map)
                elif _has_preceding_attribute(item, "pallet::hooks"):
                    self._extract_hooks_impl(item, file_path, pallet_name, result, enum_map)
                elif _has_preceding_attribute(item, "pallet::inherent"):
                    self._extract_inherent_impl(item, file_path, pallet_name, result)

    def _extract_enum(self, node, file_path, pallet_name, result, enum_map):
        """Extract enum declarations."""
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return
        enum_name = _text(name_node)

        variant_list = _child_by_type(node, "enum_variant_list")
        variants = []
        if variant_list:
            for v in _children_by_type(variant_list, "enum_variant"):
                vid = _child_by_type(v, "identifier")
                if vid:
                    variants.append(_text(vid))

        # Detect if this is an event enum
        is_event = _has_preceding_attribute(node, "pallet::event")
        is_error = _has_preceding_attribute(node, "pallet::error")

        if is_event:
            # Extract event variants as event nodes
            for variant_name in variants:
                event_id = self._make_node_id(file_path, variant_name)
                result.nodes.append({
                    "id": event_id, "label": variant_name, "type": "event",
                    "visibility": "public", "file": file_path,
                    "line_start": node.start_point[0] + 1,
                    "line_end": node.end_point[0] + 1,
                    "signature": f"Event::{variant_name}",
                    "metadata": json.dumps({"pallet": pallet_name}),
                })
        elif not is_error:
            # State enum - track for state machine detection
            enum_map[enum_name] = variants

    def _extract_storage(self, node, file_path, pallet_name, result):
        """Extract #[pallet::storage] type items."""
        type_text = _text(node)

        # Extract name from type_identifier
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return
        storage_name = _text(name_node)
        storage_id = self._make_node_id(file_path, storage_name)

        # C1/C2: Detect storage type - most specific first
        storage_type = "unknown"
        if "StorageDoubleMap" in type_text:
            storage_type = "StorageDoubleMap"
        elif "CountedStorageMap" in type_text:
            storage_type = "CountedStorageMap"
        elif "StorageMap" in type_text:
            storage_type = "StorageMap"
        elif "StorageValue" in type_text:
            storage_type = "StorageValue"

        meta = {
            "pallet": pallet_name,
            "storage_type": storage_type,
        }

        # H4: Detect unbounded types in storage value (expanded)
        unbounded_patterns = [
            r"(?<!Bounded)Vec<",
            r"(?<!Bounded)BTreeMap<",
            r"(?<!Bounded)BTreeSet<",
            r"(?<!Bounded)String(?:\s*[,>]|$)",
            r"(?<!Bounded)HashMap<",
            r"(?<!Bounded)HashSet<",
        ]
        is_unbounded = False
        for pat in unbounded_patterns:
            if re.search(pat, type_text):
                is_unbounded = True
                break
        if is_unbounded:
            meta["unbounded"] = True

        node_entry = {
            "id": storage_id, "label": storage_name, "type": "state_var",
            "visibility": "public", "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": type_text.split("=")[0].strip() if "=" in type_text else type_text[:80],
            "metadata": json.dumps(meta),
        }
        result.nodes.append(node_entry)

        # Add warning for unbounded storage
        if is_unbounded:
            result.warnings = getattr(result, "warnings", [])
            result.warnings.append({
                "type": "unbounded_storage",
                "storage": storage_name,
                "message": f"Storage item '{storage_name}' contains unbounded collection type. Consider using Bounded variants.",
            })

    def _extract_call_impl(self, impl_node, file_path, pallet_name, result, enum_map):
        """Extract functions from #[pallet::call] impl block."""
        decl_list = _child_by_type(impl_node, "declaration_list")
        if not decl_list:
            return

        for item in decl_list.children:
            if item.type == "function_item":
                self._extract_dispatchable(item, file_path, pallet_name, result, enum_map)

    def _extract_dispatchable(self, node, file_path, pallet_name, result, enum_map):
        """Extract a dispatchable call function."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        func_name = _text(name_node)
        func_id = self._make_node_id(file_path, func_name)

        vis_node = _child_by_type(node, "visibility_modifier")
        visibility = "public" if vis_node else "private"

        # Parameters
        params = []
        param_list = _child_by_type(node, "parameters")
        if param_list:
            for p in _children_by_type(param_list, "parameter"):
                params.append(_text(p))

        sig = f"fn {func_name}({', '.join(params)})"

        meta = {"pallet": pallet_name}

        # GAP #1: Weight extraction
        weight_attr_text = _get_preceding_attribute_text(node, "pallet::weight")
        if weight_attr_text:
            # Extract the weight value from #[pallet::weight(VALUE)]
            weight_match = re.search(r"pallet::weight\((.+?)\)\s*\]", weight_attr_text, re.DOTALL)
            if weight_match:
                meta["weight"] = weight_match.group(1).strip()

        # H2: Extract call_index
        call_index_attr = _get_preceding_attribute_text(node, "pallet::call_index")
        if call_index_attr:
            idx_match = re.search(r"call_index\((\d+)\)", call_index_attr)
            if idx_match:
                meta["call_index"] = int(idx_match.group(1))

        # GAP #2: Transactional detection
        is_transactional = _has_preceding_attribute(node, "transactional")
        meta["transactional"] = is_transactional

        # Check for origin type
        body = _child_by_type(node, "block")
        body_text = _text(body) if body else ""

        # GAP #7: ensure_none and custom origin detection
        if "ensure_signed" in body_text:
            meta["origin"] = "signed"
        elif "ensure_root" in body_text:
            meta["origin"] = "root"
        elif "ensure_none" in body_text:
            meta["origin"] = "none"

        # Detect custom origin pattern: T::SomeOrigin::ensure_origin(origin)
        custom_origin_match = re.search(r"T::(\w+)::ensure_origin\s*\(", body_text)
        if custom_origin_match:
            meta["origin"] = f"custom:{custom_origin_match.group(1)}"

        result.nodes.append({
            "id": func_id, "label": func_name, "type": "function",
            "visibility": visibility, "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": sig,
            "metadata": json.dumps(meta),
        })

        # Extract body edges
        if body:
            self._extract_body_edges(body, func_id, file_path, pallet_name, enum_map, result)

    def _extract_hooks_impl(self, impl_node, file_path, pallet_name, result, enum_map=None):
        """Extract hook functions (on_initialize, on_finalize, etc.)."""
        decl_list = _child_by_type(impl_node, "declaration_list")
        if not decl_list:
            return

        for item in decl_list.children:
            if item.type == "function_item":
                name_node = _child_by_type(item, "identifier")
                if not name_node:
                    continue
                func_name = _text(name_node)
                func_id = self._make_node_id(file_path, func_name)

                hook_meta = {
                    "pallet": pallet_name,
                    "is_hook": True,
                }

                # H1: Add specific hook_type metadata
                if func_name in _HOOK_TYPES:
                    hook_meta["hook_type"] = _HOOK_TYPES[func_name]

                # C3: Flag migration hooks
                if func_name in _MIGRATION_HOOKS:
                    hook_meta["is_migration"] = True

                result.nodes.append({
                    "id": func_id, "label": func_name, "type": "function",
                    "visibility": "internal", "file": file_path,
                    "line_start": item.start_point[0] + 1,
                    "line_end": item.end_point[0] + 1,
                    "signature": f"fn {func_name}()",
                    "metadata": json.dumps(hook_meta),
                })

                # GAP #6: Extract body edges for hooks
                body = _child_by_type(item, "block")
                if body and enum_map is not None:
                    self._extract_body_edges(body, func_id, file_path, pallet_name, enum_map, result)

    def _extract_inherent_impl(self, impl_node, file_path, pallet_name, result):
        """GAP #5: Extract inherent call functions from #[pallet::inherent] impl blocks."""
        decl_list = _child_by_type(impl_node, "declaration_list")
        if not decl_list:
            return

        for item in decl_list.children:
            if item.type == "function_item":
                name_node = _child_by_type(item, "identifier")
                if not name_node:
                    continue
                func_name = _text(name_node)
                func_id = self._make_node_id(file_path, func_name)

                result.nodes.append({
                    "id": func_id, "label": func_name, "type": "function",
                    "visibility": "internal", "file": file_path,
                    "line_start": item.start_point[0] + 1,
                    "line_end": item.end_point[0] + 1,
                    "signature": f"fn {func_name}()",
                    "metadata": json.dumps({
                        "pallet": pallet_name,
                        "is_inherent": True,
                    }),
                })

                # Extract body edges for inherent functions
                body = _child_by_type(item, "block")
                if body:
                    self._extract_body_edges(body, func_id, file_path, pallet_name, {}, result)

    def _extract_body_edges(self, body, func_id, file_path, pallet_name, enum_map, result):
        """Extract edges from function body."""
        body_text = _text(body)

        # H3: Storage reads/writes - handle multiple syntax patterns
        # Pattern 1: StorageName::<T>::get() (turbofish)
        # Pattern 2: <StorageName<T>>::get() (angle bracket)
        # Pattern 3: StorageName::get() (bare, no generics)
        storage_read_patterns = [
            r"(\w+)::<[^>]*>::(?:get|contains_key)",
            r"<(\w+)<[^>]*>>::(?:get|contains_key)",
            r"(\w+)::(?:get|contains_key)\b",
        ]
        storage_write_patterns = [
            r"(\w+)::<[^>]*>::(?:put|insert|mutate|try_mutate|remove|kill)",
            r"<(\w+)<[^>]*>>::(?:put|insert|mutate|try_mutate|remove|kill)",
            r"(\w+)::(?:put|insert|mutate|try_mutate|remove|kill)\b",
        ]

        storage_reads = set()
        for pat in storage_read_patterns:
            storage_reads.update(re.findall(pat, body_text))

        storage_writes = set()
        for pat in storage_write_patterns:
            storage_writes.update(re.findall(pat, body_text))

        # Filter out common false positives (non-storage identifiers)
        _false_positives = {"Error", "Self", "Option", "Result", "Ok", "Err", "Some", "None", "Call"}

        for storage_name in storage_reads - _false_positives:
            storage_id = self._make_node_id(file_path, storage_name)
            result.edges.append({
                "source": func_id, "target": storage_id,
                "relation": "reads_state", "attributes": "{}",
            })

        for storage_name in storage_writes - _false_positives:
            storage_id = self._make_node_id(file_path, storage_name)
            result.edges.append({
                "source": func_id, "target": storage_id,
                "relation": "writes_state", "attributes": "{}",
            })

        # Event emissions: Self::deposit_event(Event::EventName { ... })
        event_matches = re.findall(r"Event::(\w+)", body_text)
        for event_name in set(event_matches):
            event_id = self._make_node_id(file_path, event_name)
            result.edges.append({
                "source": func_id, "target": event_id,
                "relation": "emits_event", "attributes": "{}",
            })

        # State transitions: detect pattern of proposal.state = ProposalState::Active
        for enum_name, variants in enum_map.items():
            for variant in variants:
                pattern = f"{enum_name}::{variant}"
                if pattern in body_text and (".state" in body_text or "state =" in body_text):
                    # Check if this is an assignment (not just a comparison)
                    assign_pattern = rf"\.state\s*=\s*{enum_name}::{variant}"
                    if re.search(assign_pattern, body_text):
                        from_state = self._find_ensure_state(body_text, enum_name)
                        conditions = self._collect_ensure_conditions(body)
                        result.transitions.append({
                            "entity": enum_name,
                            "from_state": from_state,
                            "to_state": variant,
                            "function_id": func_id,
                            "conditions": json.dumps(conditions),
                        })

        # GAP #4: Cross-pallet calls - generalized T::Trait::method detection
        cross_pallet_matches = re.findall(r"T::(\w+)::(\w+)", body_text)
        for trait_name, method_name in set(cross_pallet_matches):
            # Skip ensure_origin calls - those are origin checks, not cross-pallet calls
            if method_name == "ensure_origin":
                continue
            call_label = f"{trait_name}::{method_name}"
            sink_id = self._make_node_id(file_path, f"_cross_{trait_name}_{method_name}")

            # Determine if this is a currency-related sink
            is_sink = bool(_CURRENCY_SINK_PATTERNS.search(method_name))

            node_meta = {
                "pallet": pallet_name,
                "cross_pallet": True,
                "trait": trait_name,
                "method": method_name,
            }
            if is_sink:
                node_meta["is_sink"] = True
                node_meta["sink_type"] = "currency_transfer"

            result.nodes.append({
                "id": sink_id, "label": call_label, "type": "function",
                "visibility": "", "file": file_path,
                "line_start": body.start_point[0] + 1,
                "line_end": body.end_point[0] + 1,
                "signature": call_label,
                "metadata": json.dumps(node_meta),
            })
            result.edges.append({
                "source": func_id, "target": sink_id,
                "relation": "calls",
                "attributes": json.dumps({"cross_pallet": True, "sink": is_sink, "unresolved": True, "call_name": method_name}),
            })

    def _find_ensure_state(self, body_text: str, enum_name: str) -> str:
        """Find from_state from ensure!(proposal.state == EnumName::X, ...) patterns."""
        pattern = rf"(?:ensure!|assert!)\s*\([^,]*{enum_name}::(\w+)"
        match = re.search(pattern, body_text)
        if match:
            return match.group(1)
        return "*"

    def _collect_ensure_conditions(self, body) -> list[str]:
        """Collect all ensure!/assert! macro texts as conditions."""
        conditions = []
        for macro in _collect_macro_invocations(body):
            macro_name_node = _child_by_type(macro, "identifier")
            if not macro_name_node:
                continue
            name = _text(macro_name_node)
            if name in ("ensure", "ensure!", "assert"):
                token_tree = _child_by_type(macro, "token_tree")
                if token_tree:
                    conditions.append(_text(token_tree).strip("()"))
        return conditions
