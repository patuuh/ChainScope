"""Go AST extraction using tree-sitter.

Extracts packages, structs, interfaces, functions, methods, type declarations,
and edges (calls, state reads/writes, interface implementations) from Go source.

Cosmos SDK-aware: detects bank module fund transfers, KVStore state writes,
MsgServer entry points, and Keeper method exposure as security-relevant patterns.
"""

import json
import tree_sitter_go
from tree_sitter import Language, Parser
from core.web3 import ExtractResult
from core.web3.base import BaseExtractor


# --- Cosmos SDK Security Patterns ---

# Bank module fund transfer sinks (loss-of-funds vectors)
COSMOS_FUND_TRANSFER_SINKS = {
    "SendCoins", "SendCoinsFromModuleToAccount", "SendCoinsFromModuleToModule",
    "SendCoinsFromAccountToModule", "DelegateCoins", "UndelegateCoins",
    "BurnCoins", "MintCoins",
    # IBC transfer
    "Transfer", "SendTransfer",
    # Distribution
    "FundCommunityPool", "WithdrawDelegationRewards", "WithdrawValidatorCommission",
}

# KVStore state write operations
COSMOS_STATE_WRITE_SINKS = {
    "Set", "Delete", "SetParams", "SetValidator", "SetDelegation",
    "SetBalance", "SetAccount", "SetSequence",
}

# Qualifier patterns that indicate bank keeper calls
COSMOS_BANK_QUALIFIERS = {
    "bankKeeper", "k.bankKeeper", "k.BankKeeper",
    "keeper.bankKeeper", "keeper.BankKeeper",
    "bk",  # common alias
}

# MsgServer interface method patterns (entry points)
COSMOS_MSGSERVER_INTERFACES = {
    "MsgServer", "QueryServer",
}

# Keeper struct name patterns
COSMOS_KEEPER_PATTERNS = {
    "Keeper", "MsgServer", "QueryServer",
    "msgServer", "queryServer",
}

# Cosmos SDK validation patterns — if a MsgServer method body contains
# any of these, we consider it to have input validation
COSMOS_VALIDATION_PATTERNS = {
    "ValidateBasic", "GetAuthority", "AccAddressFromBech32",
    "VerifyAddressFormat", "MustAccAddressFromBech32",
    "BlockedAddr", "IsSendEnabledCoins",
}

# Cosmos SDK state-writing method calls (via keeper fields)
# These produce writes_state edges when called on keeper fields
COSMOS_STATE_WRITE_METHODS = {
    "Set", "Delete", "SetParams", "SetValidator", "SetDelegation",
    "SetBalance", "SetAccount", "SetSequence",
    "SendCoins", "SendCoinsFromModuleToAccount", "SendCoinsFromModuleToModule",
    "SendCoinsFromAccountToModule", "MintCoins", "BurnCoins",
    "DelegateCoins", "UndelegateCoins",
    "OverwritePlatformPercentage", "OverwritePlatformMinimum",
}

# KVStore operations that mutate state — used for lifecycle tracking
COSMOS_STORE_WRITE_OPS = {"Set", "Delete"}
COSMOS_STORE_READ_OPS = {"Get", "Has"}

import re
# Pattern to extract entity name from key prefix constants
# e.g., types.AudienceClaimKeyPrefix → AudienceClaim
# e.g., types.AudienceKey(...) → Audience
_KEY_PREFIX_RE = re.compile(r'types\.(\w+?)(?:KeyPrefix|Key)\b')


def _get_parser():
    lang = Language(tree_sitter_go.language())
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


def _is_exported(name: str) -> bool:
    """In Go, exported identifiers start with an uppercase letter."""
    return bool(name) and name[0].isupper()


def _visibility(name: str) -> str:
    """Return 'public' for exported, 'private' for unexported."""
    return "public" if _is_exported(name) else "private"


def _extract_type_text(node):
    """Extract type annotation text from a type node."""
    if node is None:
        return ""
    return _text(node)


def _get_receiver_info(node):
    """Extract receiver from a method declaration.

    For `func (s *MyStruct) DoThing()`, returns ("s", "MyStruct", True).
    For `func (s MyStruct) DoThing()`, returns ("s", "MyStruct", False).
    Returns (None, None, False) if no receiver.
    """
    param_list = _child_by_type(node, "parameter_list")
    if param_list is None:
        return None, None, False

    # The receiver is the first parameter_list before the function name.
    # In tree-sitter-go, method_declaration has a dedicated structure:
    #   method_declaration -> parameter_list (receiver) name parameter_list (params) ...
    # But we also handle function_declaration which has no receiver.
    params = _children_by_type(param_list, "parameter_declaration")
    if not params:
        return None, None, False

    param = params[0]
    # Get receiver variable name
    recv_name_node = _child_by_type(param, "identifier")
    recv_name = _text(recv_name_node) if recv_name_node else ""

    # Get the type — could be pointer_type or type_identifier
    pointer_type = _child_by_type(param, "pointer_type")
    is_pointer = pointer_type is not None
    if is_pointer:
        type_node = _child_by_type(pointer_type, "type_identifier")
        struct_name = _text(type_node) if type_node else ""
    else:
        type_node = _child_by_type(param, "type_identifier")
        struct_name = _text(type_node) if type_node else ""

    return recv_name, struct_name, is_pointer


def _build_func_signature(node, func_name: str, recv_str: str = "") -> str:
    """Build a human-readable function signature."""
    parts = ["func"]
    if recv_str:
        parts.append(f"({recv_str})")
    parts.append(func_name)

    # Find parameter list(s) — methods have two (receiver + params),
    # functions have one.
    param_lists = _children_by_type(node, "parameter_list")
    if node.type == "method_declaration" and len(param_lists) >= 2:
        parts.append(_text(param_lists[1]))
    elif node.type == "function_declaration" and param_lists:
        parts.append(_text(param_lists[0]))
    elif param_lists:
        parts.append(_text(param_lists[-1]))

    # Return type
    result = _child_by_type(node, "result")
    if result is None:
        # Try parameter_list as return (Go uses parameter_list for multi-return)
        # or type_identifier directly
        for child in node.children:
            if child.type in ("type_identifier", "qualified_type", "pointer_type",
                              "slice_type", "map_type", "channel_type", "interface_type"):
                parts.append(_text(child))
                break
    else:
        parts.append(_text(result))

    return " ".join(parts)


def _collect_call_expressions(node):
    """Recursively collect all call_expression nodes."""
    return _collect_nodes_by_type(node, "call_expression")


def _collect_selector_expressions(node):
    """Recursively collect all selector_expression nodes (field access)."""
    return _collect_nodes_by_type(node, "selector_expression")


def _collect_go_statements(node):
    """Recursively collect all go_statement nodes (goroutine launches)."""
    return _collect_nodes_by_type(node, "go_statement")


def _collect_defer_statements(node):
    """Recursively collect all defer_statement nodes."""
    return _collect_nodes_by_type(node, "defer_statement")


def _collect_send_statements(node):
    """Recursively collect all send_statement nodes (channel sends)."""
    return _collect_nodes_by_type(node, "send_statement")


def _collect_receive_expressions(node):
    """Recursively collect unary_expression with <- operator (channel receives)."""
    results = []
    for n in _collect_nodes_by_type(node, "unary_expression"):
        if _text(n).startswith("<-"):
            results.append(n)
    return results


def _collect_assignment_statements(node):
    """Recursively collect assignment_statement nodes."""
    results = _collect_nodes_by_type(node, "assignment_statement")
    results.extend(_collect_nodes_by_type(node, "short_var_declaration"))
    return results


def _get_call_name(call_node):
    """Extract function/method name from a call_expression.

    Returns (name, qualifier_or_none).
    For `pkg.Func()` -> ("Func", "pkg")
    For `s.Method()` -> ("Method", "s")
    For `Func()` -> ("Func", None)
    """
    func_child = call_node.children[0] if call_node.children else None
    if func_child is None:
        return None, None
    if func_child.type == "identifier":
        return _text(func_child), None
    if func_child.type == "selector_expression":
        operand = func_child.children[0] if func_child.children else None
        field = _child_by_type(func_child, "field_identifier")
        qualifier = _text(operand) if operand else None
        name = _text(field) if field else None
        return name, qualifier
    if func_child.type == "parenthesized_expression":
        # Type assertion call: (Type)(args)
        return _text(func_child), None
    return _text(func_child), None


def _is_receiver_field_access(sel_expr, recv_name: str):
    """Check if a selector_expression is receiver.field access.

    Returns (is_access, field_name).
    """
    if not sel_expr.children:
        return False, None
    operand = sel_expr.children[0]
    if _text(operand) == recv_name:
        field = _child_by_type(sel_expr, "field_identifier")
        if field:
            return True, _text(field)
    return False, None


def _detect_unchecked_errors(node):
    """Detect if function calls returning error are not checked.

    Looks for patterns like:
      result, _ := SomeFunc()   (blank identifier for error)
      SomeFunc()                (return value discarded entirely)
    """
    unchecked = []
    # Look for short_var_declaration / assignment with blank identifier
    for assign in _collect_nodes_by_type(node, "short_var_declaration"):
        lhs = _child_by_type(assign, "expression_list")
        if lhs is None:
            continue
        ids = _children_by_type(lhs, "identifier")
        blanks = [i for i in ids if _text(i) == "_"]
        if blanks:
            rhs = assign.children[-1] if assign.children else None
            if rhs:
                calls = _collect_nodes_by_type(rhs, "call_expression")
                for call in calls:
                    name, _ = _get_call_name(call)
                    if name:
                        unchecked.append(name)

    for assign in _collect_nodes_by_type(node, "assignment_statement"):
        lhs_nodes = []
        for child in assign.children:
            if child.type == "expression_list":
                lhs_nodes = _children_by_type(child, "identifier")
                break
            if child.type == "identifier":
                lhs_nodes.append(child)
            if _text(child) in ("=", ":="):
                break
        blanks = [i for i in lhs_nodes if _text(i) == "_"]
        if blanks:
            rhs = assign.children[-1] if assign.children else None
            if rhs:
                calls = _collect_nodes_by_type(rhs, "call_expression")
                for call in calls:
                    name, _ = _get_call_name(call)
                    if name:
                        unchecked.append(name)

    # Expression statements (call as statement, return value ignored)
    for expr_stmt in _collect_nodes_by_type(node, "expression_statement"):
        for child in expr_stmt.children:
            if child.type == "call_expression":
                name, _ = _get_call_name(child)
                if name:
                    unchecked.append(name)

    return unchecked


def _has_cosmos_validation(body_node):
    """Check if a function body contains Cosmos SDK validation patterns.

    Looks for: error checks (if err != nil), authority checks,
    address validation, ValidateBasic calls, and explicit comparisons
    on msg fields.
    """
    body_text = _text(body_node)

    # Check for known validation function calls
    for pat in COSMOS_VALIDATION_PATTERNS:
        if pat in body_text:
            return True

    # Check for error return pattern: if err != nil { return
    if "err != nil" in body_text:
        return True

    # Check for authority/signer comparison
    if "Authority" in body_text and ("!=" in body_text or "==" in body_text):
        return True

    return False


def _has_go_validation(body_node):
    """Check if a Go function body contains any input validation.

    More general than Cosmos-specific checks. Looks for:
    - error checks (if err != nil)
    - nil checks (if x == nil)
    - length checks (if len(x) ...)
    - bounds checks (if x < 0, if x > max)
    - panic calls (validate-or-die)
    - errors.New / fmt.Errorf (creating error returns)
    """
    body_text = _text(body_node)

    if "err != nil" in body_text:
        return True
    if "== nil" in body_text or "!= nil" in body_text:
        return True
    if "len(" in body_text and ("==" in body_text or ">" in body_text or "<" in body_text):
        return True
    if "panic(" in body_text:
        return True
    if "errors.New" in body_text or "fmt.Errorf" in body_text:
        return True
    for pat in COSMOS_VALIDATION_PATTERNS:
        if pat in body_text:
            return True

    return False


def _collect_type_assertions(node):
    """Collect unsafe type assertions: x.(Type) without ok-check.

    Safe: val, ok := x.(Type)
    Unsafe: val := x.(Type)   — panics if assertion fails

    Returns list of (assertion_text, line) tuples.
    """
    unsafe = []
    if node is None:
        return unsafe

    for ta in _collect_nodes_by_type(node, "type_assertion_expression"):
        # Check if used in a 2-value assignment (val, ok := ...)
        parent = ta.parent
        is_ok_checked = False

        # Walk up to find assignment
        cur = ta
        while cur and cur.type not in ("block", "function_declaration",
                                        "method_declaration"):
            if cur.type in ("short_var_declaration", "assignment_statement"):
                # Check if LHS has 2+ identifiers (val, ok pattern)
                lhs = cur.children[0] if cur.children else None
                if lhs and lhs.type == "expression_list":
                    ids = _children_by_type(lhs, "identifier")
                    if len(ids) >= 2:
                        is_ok_checked = True
                break
            cur = cur.parent

        if not is_ok_checked:
            unsafe.append({
                "assertion": _text(ta).strip()[:60],
                "line": ta.start_point[0] + 1,
            })

    return unsafe


# SQL injection patterns
GO_SQL_SINKS = {
    "Query", "QueryRow", "QueryContext", "QueryRowContext",
    "Exec", "ExecContext", "Prepare", "PrepareContext",
}

GO_SQL_QUALIFIERS = {"db", "tx", "conn", "pool", "sqlDB", "pgx"}


def _has_parameters(node):
    """Check if a function/method has non-context, non-receiver parameters.

    In Cosmos SDK MsgServer methods, the signature is typically:
      func (m msgServer) Send(ctx context.Context, msg *MsgSend) (...)
    We want to detect if there are meaningful params beyond ctx.
    """
    param_lists = _children_by_type(node, "parameter_list")
    if not param_lists:
        return False

    # For methods: first param_list is receiver, second is params
    # For functions: first param_list is params
    if node.type == "method_declaration" and len(param_lists) >= 2:
        params_node = param_lists[1]
    elif param_lists:
        params_node = param_lists[0]
    else:
        return False

    param_decls = _children_by_type(params_node, "parameter_declaration")
    # Filter out context.Context params
    meaningful = 0
    for pd in param_decls:
        type_text = ""
        for c in pd.children:
            if c.type in ("type_identifier", "qualified_type", "pointer_type",
                          "selector_expression"):
                type_text = _text(c)
        if "Context" not in type_text:
            meaningful += 1
    return meaningful > 0


class GoExtractor(BaseExtractor):

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
        struct_fields: dict[str, list[str]] = {}   # struct_name -> [field_names]
        interface_methods: dict[str, list[str]] = {}  # iface_name -> [method_names]
        struct_methods: dict[str, list[str]] = {}   # struct_name -> [method_names]
        func_ts_map: dict[int, str] = {}            # tree-sitter node.id -> our node_id

        # Extract package declaration
        self._extract_package(root, file_path, result)

        # Extract type declarations (structs, interfaces, type aliases)
        for child in root.children:
            if child.type == "type_declaration":
                self._extract_type_declaration(child, file_path, result,
                                               struct_fields, interface_methods)

        # Extract function and method declarations
        for child in root.children:
            if child.type == "function_declaration":
                self._extract_function(child, file_path, result, func_ts_map,
                                       struct_fields)
            elif child.type == "method_declaration":
                self._extract_method(child, file_path, result, func_ts_map,
                                     struct_fields, struct_methods,
                                     interface_methods)

        # Infer interface implementations: if a struct has all methods of an interface
        self._infer_interface_impls(file_path, result, interface_methods, struct_methods)

        return result

    def _extract_package(self, root, file_path, result):
        """Extract package declaration as a module node."""
        pkg_clause = _child_by_type(root, "package_clause")
        if pkg_clause is None:
            return
        pkg_name_node = _child_by_type(pkg_clause, "package_identifier")
        if pkg_name_node is None:
            return
        pkg_name = _text(pkg_name_node)
        pkg_id = self._make_node_id(file_path, pkg_name)

        result.nodes.append({
            "id": pkg_id,
            "label": pkg_name,
            "type": "module",
            "visibility": "public",
            "file": file_path,
            "line_start": pkg_clause.start_point[0] + 1,
            "line_end": pkg_clause.end_point[0] + 1,
            "signature": f"package {pkg_name}",
            "metadata": json.dumps({"kind": "package"}),
        })

    def _extract_type_declaration(self, node, file_path, result,
                                  struct_fields, interface_methods):
        """Extract type declarations: structs, interfaces, type aliases."""
        for child in node.children:
            if child.type == "type_spec":
                self._extract_type_spec(child, file_path, result,
                                        struct_fields, interface_methods)

    def _extract_type_spec(self, node, file_path, result,
                           struct_fields, interface_methods):
        """Extract a single type_spec node."""
        name_node = _child_by_type(node, "type_identifier")
        if name_node is None:
            return
        type_name = _text(name_node)
        vis = _visibility(type_name)

        # Determine the underlying type
        struct_type = _child_by_type(node, "struct_type")
        iface_type = _child_by_type(node, "interface_type")

        if struct_type:
            self._extract_struct(node, struct_type, type_name, vis,
                                 file_path, result, struct_fields)
        elif iface_type:
            self._extract_interface(node, iface_type, type_name, vis,
                                    file_path, result, interface_methods)
        else:
            # Type alias or other type declaration
            self._extract_type_alias(node, type_name, vis, file_path, result)

    def _extract_struct(self, spec_node, struct_type, struct_name, vis,
                        file_path, result, struct_fields):
        """Extract struct definition and its fields."""
        struct_id = self._make_node_id(file_path, struct_name)

        result.nodes.append({
            "id": struct_id,
            "label": struct_name,
            "type": "struct",
            "visibility": vis,
            "file": file_path,
            "line_start": spec_node.start_point[0] + 1,
            "line_end": spec_node.end_point[0] + 1,
            "signature": f"type {struct_name} struct",
            "metadata": json.dumps({"kind": "struct"}),
        })

        # Extract fields from field_declaration_list
        field_list = _child_by_type(struct_type, "field_declaration_list")
        if not field_list:
            struct_fields[struct_name] = []
            return

        field_names = []
        for field_decl in _children_by_type(field_list, "field_declaration"):
            # Field can have multiple names: `x, y int`
            fname_nodes = _children_by_type(field_decl, "field_identifier")
            if not fname_nodes:
                # Embedded type (anonymous field)
                type_id = _child_by_type(field_decl, "type_identifier")
                if type_id:
                    fname = _text(type_id)
                    fname_nodes = [type_id]
                else:
                    continue

            # Get type text (skip the field names)
            type_text = ""
            for c in field_decl.children:
                if c.type not in ("field_identifier", "tag"):
                    if c.type != "comment":
                        type_text = _text(c)

            for fname_node in fname_nodes:
                fname = _text(fname_node)
                field_names.append(fname)
                field_vis = _visibility(fname)

                field_id = self._make_node_id(file_path, f"{struct_name}.{fname}")
                result.nodes.append({
                    "id": field_id,
                    "label": fname,
                    "type": "state_var",
                    "visibility": field_vis,
                    "file": file_path,
                    "line_start": field_decl.start_point[0] + 1,
                    "line_end": field_decl.end_point[0] + 1,
                    "signature": type_text,
                    "metadata": json.dumps({
                        "struct": struct_name,
                        "type_text": type_text,
                    }),
                })
                result.edges.append({
                    "source": struct_id,
                    "target": field_id,
                    "relation": "contains",
                    "attributes": "{}",
                })

        struct_fields[struct_name] = field_names

    def _extract_interface(self, spec_node, iface_type, iface_name, vis,
                           file_path, result, interface_methods):
        """Extract interface definition with method signatures."""
        iface_id = self._make_node_id(file_path, iface_name)

        methods = []
        # Interface body contains method_spec nodes
        for child in iface_type.children:
            if child.type == "method_spec":
                mname_node = _child_by_type(child, "field_identifier")
                if mname_node:
                    mname = _text(mname_node)
                    methods.append(mname)
            elif child.type == "method_elem":
                # Alternative grammar node for interface methods
                mname_node = _child_by_type(child, "field_identifier")
                if mname_node:
                    mname = _text(mname_node)
                    methods.append(mname)

        interface_methods[iface_name] = methods

        result.nodes.append({
            "id": iface_id,
            "label": iface_name,
            "type": "trait",
            "visibility": vis,
            "file": file_path,
            "line_start": spec_node.start_point[0] + 1,
            "line_end": spec_node.end_point[0] + 1,
            "signature": f"type {iface_name} interface",
            "metadata": json.dumps({
                "kind": "interface",
                "methods": methods,
            }),
        })

    def _extract_type_alias(self, spec_node, type_name, vis, file_path, result):
        """Extract type alias / named type declaration."""
        # Get the underlying type text
        underlying = ""
        for c in spec_node.children:
            if c.type != "type_identifier":
                underlying = _text(c)

        alias_id = self._make_node_id(file_path, type_name)
        result.nodes.append({
            "id": alias_id,
            "label": type_name,
            "type": "type",
            "visibility": vis,
            "file": file_path,
            "line_start": spec_node.start_point[0] + 1,
            "line_end": spec_node.end_point[0] + 1,
            "signature": f"type {type_name} {underlying}".strip(),
            "metadata": json.dumps({
                "kind": "type_alias",
                "underlying": underlying,
            }),
        })

    def _extract_function(self, node, file_path, result, func_ts_map,
                          struct_fields):
        """Extract a package-level function declaration."""
        name_node = _child_by_type(node, "identifier")
        if name_node is None:
            return
        func_name = _text(name_node)
        func_id = self._make_node_id(file_path, func_name)
        func_ts_map[node.id] = func_id

        vis = _visibility(func_name)
        sig = _build_func_signature(node, func_name)

        meta: dict = {}

        # Detect unchecked errors in body
        body = _child_by_type(node, "block")
        if body:
            unchecked = _detect_unchecked_errors(body)
            if unchecked:
                meta["unchecked_errors"] = unchecked

            # Input validation: exported functions with params but no validation
            is_test = ("_test.go" in file_path or func_name.startswith("Test")
                       or func_name.startswith("Benchmark"))
            is_getter = (func_name.startswith("Get") or func_name.startswith("List")
                         or func_name.startswith("Has") or func_name.startswith("New")
                         or func_name.startswith("String") or func_name == "Error"
                         or func_name == "String")
            is_generated_file = any(pat in file_path for pat in (
                "_gen.go", "_generated.go", ".pb.go", ".abigen.go",
                "_string.go", "bindings/",
            ))
            if (vis == "public" and not is_test and not is_getter
                    and not is_generated_file
                    and _has_parameters(node)
                    and not _has_go_validation(body)):
                meta["no_input_validation"] = True

            # Unsafe type assertions
            unsafe_ta = _collect_type_assertions(body)
            if unsafe_ta:
                meta["unsafe_type_assertions"] = unsafe_ta

            # SQL injection: string concatenation in SQL query calls
            self._detect_sql_injection(body, meta)

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

        # Extract body edges (no receiver for free functions)
        if body:
            self._extract_body_edges(body, func_id, file_path, None, None,
                                     [], result)

    def _extract_method(self, node, file_path, result, func_ts_map,
                        struct_fields, struct_methods, interface_methods=None):
        """Extract a method declaration (function with receiver)."""
        name_node = _child_by_type(node, "field_identifier")
        if name_node is None:
            return
        method_name = _text(name_node)

        # Get receiver info
        recv_name, struct_name, is_pointer = _get_receiver_info(node)
        if not struct_name:
            return

        qualified = f"{struct_name}::{method_name}"
        method_id = self._make_node_id(file_path, qualified)
        func_ts_map[node.id] = method_id

        vis = _visibility(method_name)
        recv_str = f"{recv_name} *{struct_name}" if is_pointer else f"{recv_name} {struct_name}"
        sig = _build_func_signature(node, method_name, recv_str)

        meta: dict = {
            "receiver": recv_str,
            "struct": struct_name,
        }
        if is_pointer:
            meta["pointer_receiver"] = True

        # Cosmos SDK: tag MsgServer/Keeper entry points
        self._tag_cosmos_entry_point(
            method_name, struct_name, method_id, meta,
            interface_methods or {})

        # Track methods per struct for interface inference
        if struct_name not in struct_methods:
            struct_methods[struct_name] = []
        struct_methods[struct_name].append(method_name)

        # Get fields for this struct
        fields = struct_fields.get(struct_name, [])

        # Detect unchecked errors in body
        body = _child_by_type(node, "block")
        if body:
            unchecked = _detect_unchecked_errors(body)
            if unchecked:
                meta["unchecked_errors"] = unchecked

            # Input validation check — applies to Cosmos entry points AND all exported methods
            is_getter = (method_name.startswith("Get") or
                         method_name.startswith("List") or
                         method_name.startswith("Has") or
                         method_name.startswith("Iterate") or
                         method_name.startswith("String") or
                         method_name == "Params" or
                         method_name == "Logger" or
                         method_name == "Error" or
                         method_name == "String")
            is_query_file = ("query" in file_path.lower() or
                             "grpc_query" in file_path.lower())
            is_test = ("_test.go" in file_path or
                       method_name.startswith("Test") or
                       method_name.startswith("Benchmark"))
            if (meta.get("cosmos_entry_point") or meta.get("keeper_method")):
                if (not is_getter and not is_query_file
                        and _has_parameters(node)
                        and not _has_cosmos_validation(body)):
                    meta["no_input_validation"] = True
            # Skip generated binding types and files for validation check
            is_generated_binding = any(struct_name.endswith(sfx) for sfx in (
                "Session", "TransactorSession", "CallerSession",
                "CallerRaw", "TransactorRaw", "Transactor", "Caller",
                "Filterer", "Iterator",
            ))
            is_generated_file = any(pat in file_path for pat in (
                "_gen.go", "_generated.go", ".pb.go", ".abigen.go",
                "_string.go", "bindings/",
            ))
            if (not meta.get("no_input_validation")
                    and vis == "public" and not is_getter and not is_test
                    and not is_query_file
                    and not is_generated_binding and not is_generated_file
                    and _has_parameters(node)
                    and not _has_go_validation(body)):
                meta["no_input_validation"] = True

            # Unsafe type assertions (panic if assertion fails)
            unsafe_ta = _collect_type_assertions(body)
            if unsafe_ta:
                meta["unsafe_type_assertions"] = unsafe_ta

            # SQL injection detection
            self._detect_sql_injection(body, meta)

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

        # Extract body edges
        if body:
            self._extract_body_edges(body, method_id, file_path,
                                     recv_name, struct_name, fields, result)

    def _extract_body_edges(self, body_node, func_id, file_path,
                            recv_name, struct_name, fields, result):
        """Walk function body to extract call, state read/write, goroutine,
        defer, and channel edges.
        """
        # --- State writes: detect assignments to receiver.field ---
        written_fields: set[str] = set()
        assignment_lhs_ids: set[int] = set()

        if recv_name and struct_name:
            for assign in _collect_assignment_statements(body_node):
                if len(assign.children) < 2:
                    continue
                lhs = assign.children[0]

                # Collect selector expressions on LHS
                lhs_sels = _collect_selector_expressions(lhs)
                if lhs.type == "selector_expression":
                    lhs_sels = [lhs] + lhs_sels

                for sel in lhs_sels:
                    is_recv, field_name = _is_receiver_field_access(sel, recv_name)
                    if is_recv and field_name in fields:
                        written_fields.add(field_name)
                        assignment_lhs_ids.add(sel.id)
                        var_id = self._make_node_id(
                            file_path, f"{struct_name}.{field_name}")
                        result.edges.append({
                            "source": func_id,
                            "target": var_id,
                            "relation": "writes_state",
                            "attributes": "{}",
                        })

        # --- State reads: receiver.field in non-LHS positions ---
        if recv_name and struct_name:
            read_fields: set[str] = set()
            for sel in _collect_selector_expressions(body_node):
                if sel.id in assignment_lhs_ids:
                    continue
                is_recv, field_name = _is_receiver_field_access(sel, recv_name)
                if is_recv and field_name in fields and field_name not in read_fields:
                    read_fields.add(field_name)
                    var_id = self._make_node_id(
                        file_path, f"{struct_name}.{field_name}")
                    result.edges.append({
                        "source": func_id,
                        "target": var_id,
                        "relation": "reads_state",
                        "attributes": "{}",
                    })

        # --- Call expressions -> calls edges ---
        for call in _collect_call_expressions(body_node):
            call_name, qualifier = _get_call_name(call)
            if not call_name:
                continue

            is_unresolved = False
            if qualifier:
                if qualifier == recv_name and struct_name:
                    # self-call: s.Method() -> same struct
                    target_id = self._make_node_id(
                        file_path, f"{struct_name}::{call_name}")
                else:
                    # Cross-package or other object call
                    target_id = self._make_node_id(
                        file_path, f"_unresolved::{call_name}")
                    is_unresolved = True
            else:
                # Local function call
                if struct_name:
                    # From a method — try same-package function
                    target_id = self._make_node_id(file_path, call_name)
                else:
                    target_id = self._make_node_id(file_path, call_name)

            attrs: dict = {}
            if is_unresolved:
                attrs = {"unresolved": True, "call_name": call_name,
                         "qualifier": qualifier}

            result.edges.append({
                "source": func_id,
                "target": target_id,
                "relation": "calls",
                "attributes": json.dumps(attrs) if attrs else "{}",
            })

            # Cosmos SDK: detect fund transfer and state write sinks
            self._detect_cosmos_sink(
                call_name, qualifier, func_id, file_path, struct_name,
                call.start_point[0] + 1, result)

            # Cosmos SDK: state-writing method calls -> writes_state edges
            # e.g., k.bankKeeper.SendCoins(), store.Set(), k.OverwritePlatformPercentage()
            if call_name in COSMOS_STATE_WRITE_METHODS:
                # Create a state_var node for the written state if needed
                state_label = f"_state:{call_name}"
                state_id = self._make_node_id(file_path,
                    f"{struct_name or '_module'}.{state_label}")
                # Check if we already emitted this state var
                if not any(n["id"] == state_id for n in result.nodes):
                    result.nodes.append({
                        "id": state_id,
                        "label": state_label,
                        "type": "state_var",
                        "visibility": "private",
                        "file": file_path,
                        "line_start": call.start_point[0] + 1,
                        "line_end": call.end_point[0] + 1,
                        "signature": f"{qualifier}.{call_name}()" if qualifier else call_name,
                        "metadata": json.dumps({
                            "cosmos_state_write": True,
                            "method": call_name,
                        }),
                    })
                result.edges.append({
                    "source": func_id,
                    "target": state_id,
                    "relation": "writes_state",
                    "attributes": json.dumps({"cosmos_sdk": True}),
                })

        # --- Goroutine detection ---
        for go_stmt in _collect_go_statements(body_node):
            # The go_statement wraps a call expression
            go_call = _child_by_type(go_stmt, "call_expression")
            if go_call:
                call_name, qualifier = _get_call_name(go_call)
                if call_name:
                    if qualifier and qualifier != recv_name:
                        target_id = self._make_node_id(
                            file_path, f"_unresolved::{call_name}")
                        is_unresolved = True
                    elif qualifier == recv_name and struct_name:
                        target_id = self._make_node_id(
                            file_path, f"{struct_name}::{call_name}")
                        is_unresolved = False
                    else:
                        target_id = self._make_node_id(file_path, call_name)
                        is_unresolved = False

                    attrs = {"goroutine": True}
                    if is_unresolved:
                        attrs["unresolved"] = True
                        attrs["call_name"] = call_name
                    result.edges.append({
                        "source": func_id,
                        "target": target_id,
                        "relation": "calls",
                        "attributes": json.dumps(attrs),
                    })
            else:
                # go func() { ... }() — anonymous goroutine
                func_lit = _child_by_type(go_stmt, "func_literal")
                if func_lit is None:
                    # Could be wrapping a call_expression inside func literal
                    pass

        # --- Defer detection ---
        for defer_stmt in _collect_defer_statements(body_node):
            defer_call = _child_by_type(defer_stmt, "call_expression")
            if defer_call:
                call_name, qualifier = _get_call_name(defer_call)
                if call_name:
                    if qualifier and qualifier != recv_name:
                        target_id = self._make_node_id(
                            file_path, f"_unresolved::{call_name}")
                    elif qualifier == recv_name and struct_name:
                        target_id = self._make_node_id(
                            file_path, f"{struct_name}::{call_name}")
                    else:
                        target_id = self._make_node_id(file_path, call_name)

                    result.edges.append({
                        "source": func_id,
                        "target": target_id,
                        "relation": "calls",
                        "attributes": json.dumps({"defer": True}),
                    })

        # --- Cosmos SDK KVStore lifecycle transitions ---
        # Detect store.Set(types.XxxKey(...), ...) and store.Delete(types.XxxKey(...))
        # to generate state_transitions for KV store entities
        body_text = _text(body_node)
        for match in _KEY_PREFIX_RE.finditer(body_text):
            entity_name = match.group(1)
            # Determine operation by looking at context before the key reference
            # Find the call context: store.Set(...types.XxxKey...) or store.Delete(...)
            prefix_text = body_text[max(0, match.start() - 40):match.start()]
            if ".Set(" in prefix_text or ".Set (" in prefix_text:
                result.transitions.append({
                    "entity": entity_name,
                    "from_state": "*",
                    "to_state": "exists",
                    "function_id": func_id,
                    "conditions": json.dumps(
                        ["has_validation"] if "err != nil" in body_text else ["no_validation"]),
                })
            elif ".Delete(" in prefix_text or ".Delete (" in prefix_text:
                result.transitions.append({
                    "entity": entity_name,
                    "from_state": "exists",
                    "to_state": "deleted",
                    "function_id": func_id,
                    "conditions": json.dumps(
                        ["has_validation"] if "err != nil" in body_text else ["no_validation"]),
                })
            elif ".Get(" in prefix_text or ".Get (" in prefix_text:
                # Track reads too — useful for understanding entity lifecycle
                result.transitions.append({
                    "entity": entity_name,
                    "from_state": "exists",
                    "to_state": "exists",
                    "function_id": func_id,
                    "conditions": json.dumps(["read"]),
                })

        # --- Goroutine race condition detection ---
        # If a goroutine body accesses receiver fields that the parent also
        # reads/writes, flag as potential data race
        if recv_name and struct_name:
            go_stmts = _collect_go_statements(body_node)
            for go_stmt in go_stmts:
                # func_literal is inside call_expression: go func(){...}()
                go_body = _child_by_type(go_stmt, "func_literal")
                if not go_body:
                    go_call = _child_by_type(go_stmt, "call_expression")
                    if go_call:
                        go_body = _child_by_type(go_call, "func_literal")
                if not go_body:
                    continue
                go_text = _text(go_body)
                # Check if goroutine accesses receiver fields
                shared_fields = []
                for field in fields:
                    if f"{recv_name}.{field}" in go_text:
                        shared_fields.append(field)
                if shared_fields:
                    # Check if there's a mutex Lock before the goroutine
                    pre_go_text = body_text[:body_text.find("go ")]
                    has_mutex = ("Lock()" in pre_go_text or "RLock()" in pre_go_text
                                 or "sync.Mutex" in body_text or "sync.RWMutex" in body_text)
                    if not has_mutex:
                        for n in result.nodes:
                            if n["id"] == func_id:
                                meta = json.loads(n["metadata"])
                                meta["potential_race"] = {
                                    "shared_fields": shared_fields,
                                    "goroutine_line": go_stmt.start_point[0] + 1,
                                }
                                n["metadata"] = json.dumps(meta)
                                break

        # --- Channel operations ---
        sends = _collect_send_statements(body_node)
        receives = _collect_receive_expressions(body_node)
        if sends or receives:
            # Add metadata to the function node about channel usage
            # We update the last-added node's metadata
            for n in result.nodes:
                if n["id"] == func_id:
                    meta = json.loads(n["metadata"])
                    if sends:
                        meta["channel_sends"] = len(sends)
                    if receives:
                        meta["channel_receives"] = len(receives)
                    n["metadata"] = json.dumps(meta)
                    break

    def _infer_interface_impls(self, file_path, result,
                               interface_methods, struct_methods):
        """Infer which structs implement which interfaces based on method sets.

        If a struct implements all methods defined in an interface,
        emit an `inherits` edge.
        """
        for iface_name, iface_meths in interface_methods.items():
            if not iface_meths:
                continue
            iface_set = set(iface_meths)
            iface_id = self._make_node_id(file_path, iface_name)

            for struct_name, struct_meths in struct_methods.items():
                struct_set = set(struct_meths)
                if iface_set.issubset(struct_set):
                    struct_id = self._make_node_id(file_path, struct_name)
                    result.edges.append({
                        "source": struct_id,
                        "target": iface_id,
                        "relation": "inherits",
                        "attributes": json.dumps({
                            "kind": "implements",
                            "interface": iface_name,
                        }),
                    })

    # --- Cosmos SDK Security Detection ---

    def _detect_cosmos_sink(self, call_name, qualifier, func_id, file_path,
                            struct_name, line, result):
        """Detect Cosmos SDK dangerous sinks: bank transfers, burns, mints.

        Creates sink nodes with is_sink/sink_type metadata so cs_sinks
        and cs_centralization queries find them.
        """
        sink_type = None

        # Bank module fund transfer calls
        if call_name in COSMOS_FUND_TRANSFER_SINKS:
            # Check qualifier hints at bank keeper
            if qualifier and any(q in qualifier for q in ("bank", "Bank", "bk")):
                sink_type = "fund_transfer"
            elif qualifier and qualifier.startswith("k."):
                # k.bankKeeper.SendCoins — qualifier is "k" for keeper self-calls
                # but the call_name itself is definitive
                sink_type = "fund_transfer"
            else:
                # call_name alone is strong enough (SendCoins is unambiguous)
                sink_type = "fund_transfer"

        # KVStore state writes
        if not sink_type and call_name in COSMOS_STATE_WRITE_SINKS:
            if qualifier and any(q in qualifier for q in
                                 ("store", "Store", "kvStore", "KVStore")):
                sink_type = "state_write"

        if not sink_type:
            return

        container = struct_name or "_module"
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
            "signature": f"{qualifier}.{call_name}()" if qualifier else f"{call_name}()",
            "metadata": json.dumps({
                "is_sink": True,
                "sink_type": sink_type,
                "cosmos_sdk": True,
                "struct": struct_name or "",
            }),
        })
        result.edges.append({
            "source": func_id,
            "target": sink_id,
            "relation": "calls",
            "attributes": json.dumps({"sink": True}),
        })

    def _tag_cosmos_entry_point(self, method_name, struct_name, method_id,
                                meta, interface_methods):
        """Tag MsgServer/QueryServer methods as entry points.

        MsgServer methods are the attack surface for Cosmos SDK modules —
        they handle user-submitted transactions.
        """
        # Direct: struct is named msgServer/MsgServer
        is_msg_server = struct_name in COSMOS_KEEPER_PATTERNS

        # Indirect: struct implements MsgServer interface
        if not is_msg_server:
            for iface_name in COSMOS_MSGSERVER_INTERFACES:
                if iface_name in interface_methods:
                    # Will be fully resolved in _infer_interface_impls,
                    # but we can tag early if method name matches
                    if method_name in interface_methods.get(iface_name, []):
                        is_msg_server = True
                        break

        if is_msg_server and method_name[0:1].isupper():
            meta["cosmos_entry_point"] = True
            meta["msg_server"] = True

        # Keeper exported methods are also attack surface
        if struct_name in ("Keeper",) and method_name[0:1].isupper():
            meta["keeper_method"] = True

    def _detect_sql_injection(self, body_node, meta):
        """Detect potential SQL injection: string concatenation in SQL calls.

        Flags db.Query("SELECT ... " + userInput) patterns.
        Safe: db.Query("SELECT ... WHERE id = ?", id)
        """
        body_text = _text(body_node)
        sql_risks = []

        for call in _collect_call_expressions(body_node):
            call_name, qualifier = _get_call_name(call)
            if not call_name or call_name not in GO_SQL_SINKS:
                continue
            # Check if the first argument uses string concatenation
            call_text = _text(call)
            # Look for "string" + var or fmt.Sprintf patterns in query arg
            if ("+" in call_text and ('"' in call_text or "'" in call_text)):
                sql_risks.append({
                    "call": f"{qualifier}.{call_name}" if qualifier else call_name,
                    "line": call.start_point[0] + 1,
                    "type": "string_concat",
                })
            elif "Sprintf" in call_text and call_name in GO_SQL_SINKS:
                sql_risks.append({
                    "call": f"{qualifier}.{call_name}" if qualifier else call_name,
                    "line": call.start_point[0] + 1,
                    "type": "fmt_sprintf",
                })

        if sql_risks:
            meta["sql_injection_risk"] = sql_risks
