"""Anchor/Solana AST extraction using tree-sitter-rust."""

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
    """Check if the preceding sibling is an attribute_item with the given name."""
    # Walk backwards through parent's children to find attribute_item before this node
    if node.parent is None:
        return False
    found_self = False
    for child in reversed(node.parent.children):
        if child.id == node.id:
            found_self = True
            continue
        if found_self and child.type == "attribute_item":
            attr_text = _text(child)
            if attr_name in attr_text:
                return True
            break
        if found_self and child.type != "attribute_item":
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


def _get_call_name(call_node):
    """Extract function name from call_expression."""
    func = _child_by_type(call_node, "field_expression")
    if func:
        field = _child_by_type(func, "field_identifier")
        return _text(field) if field else None
    # Scoped identifier: anchor_lang::system_program::transfer
    scoped = _child_by_type(call_node, "scoped_identifier")
    if scoped:
        ids = _children_by_type(scoped, "identifier")
        return _text(ids[-1]) if ids else None
    ident = _child_by_type(call_node, "identifier")
    if ident:
        return _text(ident)
    return None


# CPI patterns that indicate fund transfers
CPI_TRANSFER_PATTERNS = {
    "transfer", "transfer_checked", "invoke", "invoke_signed",
    "mint_to", "burn", "approve", "revoke",
    "freeze_account", "thaw_account", "close_account",
    "mint_to_checked", "burn_checked",
}

# Sink type classification for CPI patterns
CPI_SINK_TYPES = {
    "transfer": "fund_transfer",
    "transfer_checked": "fund_transfer",
    "mint_to": "fund_creation",
    "mint_to_checked": "fund_creation",
    "burn": "fund_destruction",
    "burn_checked": "fund_destruction",
    "close_account": "fund_destruction",
    "approve": "token_authority",
    "revoke": "token_authority",
    "freeze_account": "token_authority",
    "thaw_account": "token_authority",
}

# Require macro variants (tree-sitter gives "require" not "require!")
REQUIRE_MACROS = {
    "require", "require_keys_eq", "require_gt", "require_gte",
    "require_eq", "require_neq", "require_keys_neq",
}


class AnchorExtractor(BaseExtractor):

    def __init__(self):
        self.parser = _get_parser()

    def extract_from_source(self, source_code: bytes, file_path: str) -> ExtractResult:
        tree = self.parser.parse(source_code)
        return self.extract(tree, source_code, file_path)

    def extract(self, tree, source_code: bytes, file_path: str) -> ExtractResult:
        result = ExtractResult()
        root = tree.root_node
        enum_map: dict[str, list[str]] = {}
        program_name = None

        # First pass: collect enums (they may appear after the program mod)
        for child in root.children:
            if child.type == "enum_item":
                self._extract_enum(child, file_path, enum_map)

        # Second pass: extract program mod, structs
        for child in root.children:
            if child.type == "mod_item" and _has_attribute(child, "program"):
                name_node = _child_by_type(child, "identifier")
                program_name = _text(name_node) if name_node else "program"
                self._extract_program_mod(child, file_path, program_name, result, enum_map)

            elif child.type == "struct_item":
                if _has_attribute(child, "derive(Accounts)"):
                    self._extract_account_struct(child, file_path, program_name or "", result)
                elif _has_attribute(child, "account"):
                    self._extract_state_struct(child, file_path, program_name or "", result)

        # Post-pass: link account structs to functions via guards/close edges
        self._link_structs_to_functions(result, file_path, program_name or "")

        return result

    def _extract_enum(self, node, file_path, enum_map):
        """Extract enum for state machine detection."""
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
        enum_map[enum_name] = variants

    def _extract_state_struct(self, node, file_path, program_name, result):
        """Extract #[account] struct as state container."""
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
            "id": struct_id, "label": struct_name, "type": "struct",
            "visibility": "public", "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"struct {struct_name}",
            "metadata": json.dumps({
                "program": program_name,
                "fields": fields,
                "is_account": True,
            }),
        })

    def _extract_account_struct(self, node, file_path, program_name, result):
        """Extract #[derive(Accounts)] context struct."""
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return
        struct_name = _text(name_node)
        struct_id = self._make_node_id(file_path, struct_name)

        # Extract fields and their constraints
        fields = []
        field_metadata = {}  # field_name -> per-field metadata dict
        constraints = []
        access_controls = []
        pda_fields = {}  # field_name -> {"pda_seeds": [...], "has_bump": bool}
        close_targets = {}  # field_name -> target
        constraint_exprs = []  # H2: arbitrary constraint = <expr> clauses
        warnings = []  # C1: security warnings
        init_if_needed_fields = []  # C1: fields using init_if_needed
        field_list = _child_by_type(node, "field_declaration_list")
        if field_list:
            children = list(field_list.children)
            pending_attrs = []
            for child in children:
                if child.type == "attribute_item":
                    pending_attrs.append(_text(child))
                elif child.type == "field_declaration":
                    fname = _child_by_type(child, "field_identifier")
                    if fname:
                        field_name = _text(fname)
                        fields.append(field_name)
                        fmeta = {}  # per-field metadata

                        # Determine field type for C2/C3 detection
                        ftype = _text(child).split(":")[-1].strip().rstrip(",")

                        # C2/C3: Detect unchecked account types
                        if "AccountInfo<" in ftype and "Account<" not in ftype.replace("AccountInfo<", ""):
                            fmeta["unchecked_account"] = True
                            fmeta["type_cosplay_risk"] = True
                        elif "UncheckedAccount<" in ftype:
                            fmeta["unchecked_account"] = True
                            fmeta["type_cosplay_risk"] = True
                        elif "Signer<" in ftype:
                            fmeta["account_type"] = "Signer"
                        elif "Account<" in ftype:
                            fmeta["account_type"] = "Account"

                        # Check if any pending attribute is an account constraint
                        for attr in pending_attrs:
                            if "account(" in attr:
                                constraints.append(f"{field_name}: {attr}")

                                # C1: Detect init_if_needed
                                if "init_if_needed" in attr:
                                    fmeta["init_if_needed"] = True
                                    init_if_needed_fields.append(field_name)
                                    warnings.append(
                                        f"init_if_needed on '{field_name}': "
                                        f"reinitialization attack risk"
                                    )

                                # H3: Detect mut constraint
                                if re.search(r'\bmut\b', attr):
                                    fmeta["mutable"] = True

                                # C2: Parse owner check
                                owner_match = re.search(r'owner\s*=\s*(\w+)', attr)
                                if owner_match:
                                    fmeta["owner_check"] = owner_match.group(1)

                                # H2: Parse constraint = <expr> clauses
                                for cexpr_match in re.finditer(
                                    r'constraint\s*=\s*([^,\]]+)',
                                    attr,
                                ):
                                    expr = cexpr_match.group(1).strip().rstrip(")")
                                    constraint_exprs.append(expr)

                                # Parse PDA seeds
                                seeds_match = re.search(r'seeds\s*=\s*\[([^\]]+)\]', attr)
                                if seeds_match:
                                    seeds_raw = seeds_match.group(1)
                                    seeds = [s.strip() for s in seeds_raw.split(",") if s.strip()]
                                    bump_match = re.search(r'\bbump\b', attr)
                                    has_bump = bump_match is not None
                                    pda_fields[field_name] = {
                                        "pda_seeds": seeds,
                                        "has_bump": has_bump,
                                    }
                                # Parse has_one constraints
                                for has_one_match in re.finditer(r'has_one\s*=\s*(\w+)', attr):
                                    ac = f"has_one:{has_one_match.group(1)}"
                                    access_controls.append(ac)
                                # Parse close constraints
                                close_match = re.search(r'close\s*=\s*(\w+)', attr)
                                if close_match:
                                    close_targets[field_name] = close_match.group(1)

                        if "Signer" in ftype:
                            constraints.append(f"{field_name}: Signer")

                        if fmeta:
                            field_metadata[field_name] = fmeta
                    pending_attrs = []
                else:
                    pending_attrs = []

        meta = {
            "program": program_name,
            "fields": fields,
            "constraints": constraints,
            "is_accounts_context": True,
        }
        if access_controls:
            meta["access_controls"] = access_controls
        if pda_fields:
            meta["pda_fields"] = pda_fields
        if close_targets:
            meta["close_targets"] = close_targets
        if field_metadata:
            meta["field_metadata"] = field_metadata
        if constraint_exprs:
            meta["constraint_exprs"] = constraint_exprs
        if init_if_needed_fields:
            meta["init_if_needed"] = True
        if warnings:
            meta["warnings"] = warnings

        result.nodes.append({
            "id": struct_id, "label": struct_name, "type": "struct",
            "visibility": "public", "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"struct {struct_name}",
            "metadata": json.dumps(meta),
        })

    def _extract_program_mod(self, mod_node, file_path, program_name, result, enum_map):
        """Extract functions from #[program] mod."""
        decl_list = _child_by_type(mod_node, "declaration_list")
        if not decl_list:
            return

        func_ts_map: dict[int, str] = {}

        for item in decl_list.children:
            if item.type == "function_item":
                self._extract_function(item, file_path, program_name, result, func_ts_map, enum_map)

    def _extract_function(self, node, file_path, program_name, result, func_ts_map, enum_map):
        """Extract a function from the #[program] module."""
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
        if param_list:
            for p in _children_by_type(param_list, "parameter"):
                ptext = _text(p)
                params.append(ptext)

        sig = f"fn {func_name}({', '.join(params)})"

        # Determine Context type for signer detection
        context_type = None
        for p in params:
            if "Context<" in p:
                start = p.index("Context<") + 8
                end = p.index(">", start)
                context_type = p[start:end]

        meta = {"program": program_name}
        if context_type:
            meta["context_type"] = context_type

        result.nodes.append({
            "id": func_id, "label": func_name, "type": "function",
            "visibility": visibility, "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": sig,
            "metadata": json.dumps(meta),
        })

        # Extract body edges
        body = _child_by_type(node, "block")
        if body:
            self._extract_body_edges(body, func_id, file_path, program_name, enum_map, result)

    def _extract_body_edges(self, body, func_id, file_path, program_name, enum_map, result):
        """Extract call edges, CPI detection, state transitions from function body."""
        body_text = _text(body)

        # Call expressions
        for call in _collect_calls(body):
            call_name = _get_call_name(call)
            if call_name:
                call_full = _text(call)
                attrs = {}

                # CPI detection
                is_cpi = False
                if call_name in CPI_TRANSFER_PATTERNS:
                    is_cpi = True
                if "CpiContext" in call_full:
                    is_cpi = True

                if is_cpi:
                    sink_type = CPI_SINK_TYPES.get(call_name, "cpi_transfer")
                    sink_id = self._make_node_id(file_path, f"_sink_{call_name}_{call.start_point[0]}")
                    result.nodes.append({
                        "id": sink_id, "label": call_name, "type": "function",
                        "visibility": "", "file": file_path,
                        "line_start": call.start_point[0] + 1,
                        "line_end": call.end_point[0] + 1,
                        "signature": _text(call)[:120],
                        "metadata": json.dumps({
                            "program": program_name,
                            "is_sink": True,
                            "sink_type": sink_type,
                        }),
                    })
                    result.edges.append({
                        "source": func_id, "target": sink_id,
                        "relation": "calls",
                        "attributes": json.dumps({"sink": True, "cpi": True}),
                    })
                else:
                    # Detect cross-module calls (field_expression or scoped_identifier)
                    callee = _child_by_type(call, "field_expression") or _child_by_type(call, "scoped_identifier")
                    if callee:
                        attrs["unresolved"] = True
                        attrs["call_name"] = call_name
                    target_id = self._make_node_id(file_path, call_name)
                    result.edges.append({
                        "source": func_id, "target": target_id,
                        "relation": "calls", "attributes": json.dumps(attrs) if attrs else "{}",
                    })

        # require! macros → guard conditions (collected for state transitions below)
        # emit! macros → event emission edges
        for macro in _collect_macro_invocations(body):
            macro_name_node = _child_by_type(macro, "identifier")
            if not macro_name_node:
                continue
            macro_name = _text(macro_name_node)
            if macro_name in REQUIRE_MACROS:
                # Collected for state transition detection below
                pass
            elif macro_name == "emit":
                # Detect emit!(EventName { ... })
                token_tree = _child_by_type(macro, "token_tree")
                if token_tree:
                    tt_text = _text(token_tree).strip("()")
                    # Extract event name (first identifier before '{')
                    event_match = re.match(r'\s*(\w+)\s*\{', tt_text)
                    if event_match:
                        event_name = event_match.group(1)
                        event_id = self._make_node_id(file_path, event_name)
                        result.edges.append({
                            "source": func_id, "target": event_id,
                            "relation": "emits_event",
                            "attributes": json.dumps({"event": event_name}),
                        })

        # H1: Detect unchecked arithmetic on state fields
        self._detect_unchecked_arithmetic(body, func_id, file_path, result)

        # State transition detection from assignments like: vault.state = VaultState::Active
        for assign in _collect_assignments(body):
            assign_text = _text(assign)
            # Check for state enum assignments
            for enum_name, variants in enum_map.items():
                for variant in variants:
                    pattern = f"{enum_name}::{variant}"
                    if pattern in assign_text and ".state" in assign_text:
                        from_state = self._find_require_state(body, enum_name)
                        result.transitions.append({
                            "entity": enum_name,
                            "from_state": from_state,
                            "to_state": variant,
                            "function_id": func_id,
                            "conditions": json.dumps(self._collect_require_conditions(body)),
                        })

    def _find_require_state(self, body, enum_name) -> str:
        """Find from_state from require!(... == EnumName::X) in the function body."""
        for macro in _collect_macro_invocations(body):
            macro_text = _text(macro)
            macro_name_node = _child_by_type(macro, "identifier")
            if not macro_name_node:
                continue
            name = _text(macro_name_node)
            if name not in REQUIRE_MACROS:
                continue
            if enum_name in macro_text and "==" in macro_text:
                match = re.search(rf"{enum_name}::(\w+)", macro_text)
                if match:
                    return match.group(1)
        return "*"

    def _collect_require_conditions(self, body) -> list[str]:
        """Collect all require! macro texts as conditions."""
        conditions = []
        for macro in _collect_macro_invocations(body):
            macro_name_node = _child_by_type(macro, "identifier")
            if not macro_name_node:
                continue
            name = _text(macro_name_node)
            if name in REQUIRE_MACROS:
                token_tree = _child_by_type(macro, "token_tree")
                if token_tree:
                    conditions.append(_text(token_tree).strip("()"))
        return conditions

    def _detect_unchecked_arithmetic(self, body, func_id, file_path, result):
        """H1: Detect unchecked arithmetic operations on state fields."""
        body_text = _text(body)
        has_checked_block = "checked {" in body_text

        # Patterns: compound assignments like vault.total_deposits += amount
        compound_pattern = re.compile(
            r'(\w+\.\w+)\s*(\+=|-=|\*=)'
        )
        # Patterns: binary arithmetic like config.base_fee + new_fee
        binary_pattern = re.compile(
            r'(\w+\.\w+)\s*(\+|-|\*)\s*\w+'
        )

        for pattern in [compound_pattern, binary_pattern]:
            for match in pattern.finditer(body_text):
                field_ref = match.group(0)
                op = match.group(2)
                # Check if a checked_* variant exists nearby
                checked_ops = {
                    "+": "checked_add", "+=": "checked_add",
                    "-": "checked_sub", "-=": "checked_sub",
                    "*": "checked_mul", "*=": "checked_mul",
                }
                checked_name = checked_ops.get(op, "")
                if checked_name in body_text or has_checked_block:
                    continue

                # Flag as unchecked arithmetic edge
                arith_id = self._make_node_id(
                    file_path,
                    f"_arith_{func_id.split('::')[-1]}_{match.start()}"
                )
                result.edges.append({
                    "source": func_id, "target": arith_id,
                    "relation": "unchecked_math",
                    "attributes": json.dumps({
                        "unchecked_arithmetic": True,
                        "operation": field_ref.strip(),
                    }),
                })

    def _link_structs_to_functions(self, result, file_path, program_name):
        """Create guards and sink edges linking account structs to their functions."""
        # Build lookup: struct_name -> struct node
        struct_map = {}
        for n in result.nodes:
            if n["type"] == "struct":
                meta = json.loads(n.get("metadata", "{}"))
                if meta.get("is_accounts_context"):
                    struct_map[n["label"]] = (n, meta)

        # Build lookup: function context_type -> func node
        func_map = {}
        for n in result.nodes:
            if n["type"] == "function":
                meta = json.loads(n.get("metadata", "{}"))
                ct = meta.get("context_type")
                if ct:
                    func_map[ct] = n

        for struct_name, (struct_node, meta) in struct_map.items():
            struct_id = struct_node["id"]
            func_node = func_map.get(struct_name)

            # Guards edge: if struct has access_controls, link to function
            if meta.get("access_controls") and func_node:
                result.edges.append({
                    "source": struct_id, "target": func_node["id"],
                    "relation": "guards",
                    "attributes": json.dumps({
                        "access_controls": meta["access_controls"],
                    }),
                })

            # Close/sink edge: if struct has close_targets, link function to sink
            if meta.get("close_targets") and func_node:
                for field_name, target in meta["close_targets"].items():
                    sink_id = self._make_node_id(
                        file_path, f"_sink_close_{struct_name}_{field_name}"
                    )
                    result.nodes.append({
                        "id": sink_id, "label": f"close({field_name})",
                        "type": "function",
                        "visibility": "", "file": file_path,
                        "line_start": struct_node["line_start"],
                        "line_end": struct_node["line_end"],
                        "signature": f"close = {target}",
                        "metadata": json.dumps({
                            "program": program_name,
                            "is_sink": True,
                            "sink_type": "fund_destruction",
                            "close_target": target,
                        }),
                    })
                    result.edges.append({
                        "source": func_node["id"], "target": sink_id,
                        "relation": "calls",
                        "attributes": json.dumps({"sink": True, "close": True}),
                    })

            # --- Anchor security analysis on account context ---
            if not func_node:
                continue
            func_meta = json.loads(func_node.get("metadata", "{}"))
            field_metadata = meta.get("field_metadata", {})
            anchor_warnings = []

            # S1: Missing signer check — mutable accounts without a Signer in context
            has_signer = any(
                fm.get("account_type") == "Signer"
                for fm in field_metadata.values()
            )
            mutable_fields = [
                fname for fname, fm in field_metadata.items()
                if fm.get("mutable")
            ]
            if mutable_fields and not has_signer and not meta.get("access_controls"):
                anchor_warnings.append({
                    "type": "missing_signer",
                    "detail": f"Mutable accounts ({', '.join(mutable_fields)}) without Signer in context",
                })

            # S2: PDA seed quality — all-constant seeds (collision/frontrun risk)
            pda_fields = meta.get("pda_fields", {})
            for pda_name, pda_info in pda_fields.items():
                seeds = pda_info.get("pda_seeds", [])
                if seeds:
                    # Check if ALL seeds are byte-string constants (b"...")
                    all_constant = all(
                        s.startswith('b"') or s.startswith("b'")
                        for s in seeds
                    )
                    if all_constant:
                        anchor_warnings.append({
                            "type": "weak_pda_seeds",
                            "field": pda_name,
                            "detail": f"All PDA seeds are constants: {seeds}. "
                                      "Include user/account key to prevent collisions.",
                        })
                    if not pda_info.get("has_bump"):
                        anchor_warnings.append({
                            "type": "missing_bump",
                            "field": pda_name,
                            "detail": "PDA without bump seed — canonical bump not enforced",
                        })

            # S3: Unchecked accounts without owner constraint
            for fname, fm in field_metadata.items():
                if fm.get("unchecked_account") and not fm.get("owner_check"):
                    anchor_warnings.append({
                        "type": "unchecked_no_owner",
                        "field": fname,
                        "detail": f"UncheckedAccount/AccountInfo '{fname}' without owner constraint — type cosplay risk",
                    })

            if anchor_warnings:
                func_meta["anchor_risks"] = anchor_warnings
                func_node["metadata"] = json.dumps(func_meta)

        # S4: CPI reentrancy — state writes after CPI calls in function bodies
        for n in result.nodes:
            if n["type"] != "function":
                continue
            func_id = n["id"]
            cpi_edges = []
            write_edges = []
            for e in result.edges:
                if e.get("source") != func_id:
                    continue
                attrs = json.loads(e.get("attributes", "{}"))
                if attrs.get("cpi"):
                    cpi_edges.append(e)
                if e["relation"] == "writes_state":
                    write_edges.append(e)
            # If function has both CPI calls and state writes, flag as potential reentrancy
            if cpi_edges and write_edges:
                fmeta = json.loads(n.get("metadata", "{}"))
                fmeta["cpi_reentrancy_risk"] = True
                n["metadata"] = json.dumps(fmeta)
