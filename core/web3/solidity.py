"""Solidity/EVM AST extraction using tree-sitter."""

import json
import re
import tree_sitter_solidity
from tree_sitter import Language, Parser
from core.web3 import ExtractResult
from core.web3.base import BaseExtractor


def _get_parser():
    lang = Language(tree_sitter_solidity.language())
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


def _collect_identifiers(node):
    """Recursively collect all identifier names from an expression."""
    ids = set()
    if node is None:
        return ids
    if node.type == "identifier":
        ids.add(_text(node))
    for child in node.children:
        ids.update(_collect_identifiers(child))
    return ids


def _collect_calls(node):
    """Recursively collect all call_expression nodes."""
    calls = []
    if node is None:
        return calls
    if node.type == "call_expression":
        calls.append(node)
    for child in node.children:
        calls.extend(_collect_calls(child))
    return calls


def _collect_assignments(node):
    """Recursively collect assignment and augmented_assignment nodes."""
    assigns = []
    if node is None:
        return assigns
    if node.type in ("assignment_expression", "augmented_assignment_expression"):
        assigns.append(node)
    for child in node.children:
        assigns.extend(_collect_assignments(child))
    return assigns


def _collect_emit_stmts(node):
    """Recursively collect emit_statement nodes."""
    emits = []
    if node is None:
        return emits
    if node.type == "emit_statement":
        emits.append(node)
    for child in node.children:
        emits.extend(_collect_emit_stmts(child))
    return emits


def _collect_member_expressions(node):
    """Recursively find member_expression nodes (e.g. VaultState.Active)."""
    results = []
    if node is None:
        return results
    if node.type == "member_expression":
        results.append(node)
    for child in node.children:
        results.extend(_collect_member_expressions(child))
    return results


def _get_call_name(call_node):
    """Extract the function/method name from a call_expression."""
    expr_nodes = _children_by_type(call_node, "expression")
    if not expr_nodes:
        return None
    expr = expr_nodes[0]
    # Unwrap struct_expression (e.g., addr.call{value: x}) to get inner member_expression
    if expr.type == "struct_expression":
        inner = _children_by_type(expr, "expression")
        if inner:
            expr = inner[0]
    if expr.type == "identifier":
        return _text(expr)
    if expr.type == "member_expression":
        ids = _children_by_type(expr, "identifier")
        return _text(ids[-1]) if ids else None
    # Nested: look for deepest identifier in non-struct children
    ids = []
    def _dig(n):
        if n.type == "identifier":
            ids.append(_text(n))
        for c in n.children:
            if c.type != "struct_field_assignment":
                _dig(c)
    _dig(expr)
    return ids[-1] if ids else None


def _extract_call_target_full(call_node):
    """Extract full call target text for sink detection."""
    expr_nodes = _children_by_type(call_node, "expression")
    if not expr_nodes:
        return ""
    return _text(expr_nodes[0])


def _extract_param_types(node):
    """Extract parameter type names from a function/constructor definition.

    Returns a comma-separated string of type names, e.g. "uint256,address".
    """
    types = []
    for p in _children_by_type(node, "parameter"):
        type_n = _child_by_type(p, "type_name")
        if type_n:
            types.append(_text(type_n))
        else:
            types.append("")
    return ",".join(types)


def _extract_param_locations(node):
    """Extract data location qualifiers for parameters.

    Returns a list of dicts with 'type' and 'location' keys.
    Data locations: storage, memory, calldata.
    """
    locations = []
    for p in _children_by_type(node, "parameter"):
        type_n = _child_by_type(p, "type_name")
        ptype = _text(type_n) if type_n else ""
        # Look for data location keyword in the parameter text
        p_text = _text(p)
        location = ""
        for loc in ("storage", "memory", "calldata"):
            if loc in p_text:
                location = loc
                break
        locations.append({"type": ptype, "location": location})
    return locations


def _node_is_inside(inner, outer):
    """Check if inner node is a descendant of outer node by byte range."""
    return (inner.start_byte >= outer.start_byte and
            inner.end_byte <= outer.end_byte)


def _collect_nodes_by_types(node, type_names):
    """Recursively collect all nodes matching any of the given type names."""
    results = []
    if node is None:
        return results
    if node.type in type_names:
        results.append(node)
    for child in node.children:
        results.extend(_collect_nodes_by_types(child, type_names))
    return results


def _find_unchecked_blocks(node):
    """Find unchecked block nodes in the AST.

    In tree-sitter-solidity, unchecked blocks are block_statement nodes
    that have an 'unchecked' keyword child.
    """
    results = []
    if node is None:
        return results
    ntype = node.type
    if "unchecked" in ntype:
        results.append(node)
    elif ntype == "block_statement":
        # Check if this block_statement has an 'unchecked' keyword child
        for child in node.children:
            if child.type == "unchecked":
                results.append(node)
                break
    for child in node.children:
        results.extend(_find_unchecked_blocks(child))
    return results


def _find_assembly_blocks(node):
    """Find assembly/yul block nodes in the AST."""
    results = []
    if node is None:
        return results
    ntype = node.type
    if "assembly" in ntype or "yul" in ntype:
        results.append(node)
        return results  # Don't recurse into assembly
    for child in node.children:
        results.extend(_find_assembly_blocks(child))
    return results


def _contains_tx_origin(node):
    """Check if any node text contains tx.origin."""
    if node is None:
        return False
    text = _text(node)
    return "tx.origin" in text


def _collect_statements_ordered(body_node):
    """Walk function body and assign monotonically increasing order to statements.

    Returns list of (order, statement_node) tuples for direct children that are
    statements (not just punctuation/braces).
    """
    stmts = []
    order = 0
    for child in body_node.children:
        # Skip punctuation like { } and whitespace
        if child.type in ("{", "}", ";", "comment"):
            continue
        stmts.append((order, child))
        order += 1
    return stmts


def _find_stmt_order(node, ordered_stmts):
    """Find the order index of the statement that contains this node."""
    for order, stmt in ordered_stmts:
        if _node_is_inside(node, stmt):
            return order
    return -1


# Sink patterns for Solidity
FUND_TRANSFER_PATTERNS = {"transfer", "send"}
DELEGATE_PATTERNS = {"delegatecall"}
SELF_DESTRUCT_PATTERNS = {"selfdestruct"}
LOW_LEVEL_CALL_PATTERNS = {"call", "staticcall"}

# Known library/built-in method names that should NOT be marked as unresolved
KNOWN_LIBRARY_METHODS = {
    # SafeMath / Math
    "add", "sub", "mul", "div", "mod",
    "min", "max", "average", "ceilDiv", "mulDiv",
    # SafeERC20
    "safeTransfer", "safeTransferFrom", "safeApprove",
    "safeIncreaseAllowance", "safeDecreaseAllowance", "forceApprove",
    # ABI encoding (built-in)
    "encode", "decode", "encodePacked", "encodeWithSignature", "encodeWithSelector",
    "encodeCall", "encodeWithSelector",
    # Array built-ins
    "push", "pop", "length",
    # SafeCast
    "toUint256", "toUint128", "toUint64", "toUint32", "toUint16", "toUint8",
    "toInt256", "toInt128", "toInt64", "toInt32", "toInt16", "toInt8",
    # Address utils
    "isContract", "sendValue", "functionCall", "functionCallWithValue",
    "functionStaticCall", "functionDelegateCall",
    # ECDSA / Signature
    "recover", "toEthSignedMessageHash", "toTypedDataHash",
    # Aragon storage helpers (assembly-based, not external calls)
    "getStorageUint256", "setStorageUint256",
    "getStorageBool", "setStorageBool",
    "getStorageBytes32", "setStorageBytes32",
    "getStorageAddress", "setStorageAddress",
    # Packing / unpacking (bit manipulation, pure)
    "pack", "unpack",
    # Counters
    "current", "increment", "decrement", "reset",
}

# Calls that are safe for reentrancy — pure/view library functions
# (using-for pattern makes these look like external calls)
SAFE_REENTRANCY_CALLS = KNOWN_LIBRARY_METHODS | {
    # EnumerableSet / EnumerableMap
    "remove", "contains", "at", "values", "get", "set", "tryGet",
    # String / bytes utils
    "concat", "toString", "toHexString", "isEmpty",
    # Structs (type constructors / named getters)
    "Props",
    # Aragon / unstructured storage — assembly-level storage ops
    "getStorageUint256", "setStorageUint256",
    "getStorageBool", "setStorageBool",
    "getStorageBytes32", "setStorageBytes32",
    "getStorageAddress", "setStorageAddress",
    "COUNTING_BASE_POSITION", "POSITION",
    # OpenZeppelin utilities (pure/view)
    "tryRecover", "toTypedDataHash",
    "checkUpkeep", "performUpkeep",
    # Bit packing / position helpers
    "pack", "unpack", "position",
    # Commonly safe view calls on self/inherited state
    "owner", "paused", "balanceOf", "totalSupply", "allowance",
    "name", "symbol", "decimals",
    "supportsInterface",
    # Type conversion / hashing (pure)
    "keccak256", "sha256", "ripemd160",
    "wrap", "unwrap",
    # Optimism UDT / library pure helpers (using-for on custom types)
    "raw", "move", "eq", "gt", "lt", "gte", "lte",
    "hashWithdrawal", "hashL2toL2CrossDomainMessage",
    "decodeVersionedNonce", "encodeVersionedNonce",
    "localizeIdent", "claimedSize", "countered", "partOffset",
    "getAnchorRoot", "l2SequenceNumber",
    "isGameFinalized", "isAllowedProposer", "isAllowedChallenger", "isGameProper",
    "cloneDeterministic", "deploy",
    "absorb", "pad", "squeeze",
    # General pure/view helpers commonly used via using-for
    "hash", "verify", "clamp", "bound",
    "encode", "decode", "compress", "decompress",
    "gameAtIndex", "superchainConfig", "ethLockbox",
    "getSchema", "getOwners", "isOwner",
    "execTransactionFromModuleReturnData",
    "shouldDeductFee", "getLatestPrimaryPrice",
    "getSwapPathMarkets", "buybackGmxFactorKey",
    "sumReturnUint256", "getUint", "setUint",
    "newRepoWithVersion", "setOwner",
    "getPooledEthByShares", "tokenAddresses",
}

ROLE_KEYWORDS = (
    "owner", "admin", "govern", "guardian", "pauser", "operator",
    "manager", "timelock", "multisig", "auth",
)

PRIVILEGED_NAME_PATTERNS = (
    ("upgrade", "upgrade"),
    ("implementation", "implementation_change"),
    ("migrate", "migration"),
    ("delegate", "delegate_execution"),
    ("owner", "ownership_change"),
    ("admin", "admin_change"),
    ("pause", "pause_control"),
    ("unpause", "pause_control"),
    ("sweep", "fund_sweep"),
    ("rescue", "fund_sweep"),
    ("emergency", "emergency_action"),
    ("destroy", "shutdown"),
    ("kill", "shutdown"),
)


def _infer_role_guards(modifier_names, body_text):
    roles = set()
    normalized_body = body_text.lower().replace(" ", "")
    for mod in modifier_names or []:
        lower = mod.lower()
        for keyword in ROLE_KEYWORDS:
            if keyword in lower:
                roles.add(keyword)
    if "msg.sender==owner" in normalized_body:
        roles.add("owner")
    if "msg.sender==admin" in normalized_body:
        roles.add("admin")
    if any(token in normalized_body for token in ("hasrole", "has_role", "onlyrole", "only_role", "_checkrole")):
        roles.add("role")
    if "requireauth" in normalized_body:
        roles.add("auth")
    return sorted(roles)


def _infer_privileged_operations(func_label, body_text, modifier_names):
    ops = set()
    label_lower = func_label.lower()
    body_lower = body_text.lower()
    normalized_body = body_lower.replace(" ", "")
    mod_lower = " ".join(modifier_names or []).lower()
    for needle, op in PRIVILEGED_NAME_PATTERNS:
        if needle in label_lower:
            ops.add(op)
    if "delegatecall" in body_lower:
        ops.add("delegate_execution")
    if "selfdestruct" in body_lower or "selfdestruct" in label_lower:
        ops.add("shutdown")
    if any(term in normalized_body for term in ("upgradeto(", "setimplementation(", "_upgradeTo(".lower())):
        ops.add("upgrade")
    if any(term in normalized_body for term in ("transferownership(", "_transferownership(", "changeadmin(")):
        ops.add("ownership_change")
    if any(term in normalized_body for term in ("_pause(", "_unpause(", "pause(", "unpause(")):
        ops.add("pause_control")
    if any(term in body_lower for term in ("target.call", ".call(", "functioncall(")):
        ops.add("arbitrary_call")
    if ops and any(term in mod_lower for term in ("onlyowner", "onlyadmin", "govern", "timelock", "guardian")):
        ops.add("privileged_entry")
    return sorted(ops)

def _collect_for_loops(node):
    """Recursively collect for_statement nodes."""
    results = []
    if node is None:
        return results
    if node.type == "for_statement":
        results.append(node)
    for child in node.children:
        results.extend(_collect_for_loops(child))
    return results


def _collect_while_loops(node):
    """Recursively collect while_statement nodes."""
    results = []
    if node is None:
        return results
    if node.type == "while_statement":
        results.append(node)
    for child in node.children:
        results.extend(_collect_while_loops(child))
    return results


def _has_division_before_multiply(node):
    """Detect division-before-multiplication in binary expressions (AST-based).

    Walks binary expressions to find patterns like: (a / b) * c
    where the left operand of a multiplication contains a division.
    """
    results = []
    if node is None:
        return results
    if node.type == "binary_expression":
        children = [c for c in node.children if c.type not in ("{", "}", ";", ",")]
        # Look for: left OP right where OP is * and left contains /
        if len(children) >= 3:
            op = children[1]
            if _text(op) == "*":
                left = children[0]
                if _contains_division(left):
                    results.append({
                        "type": "division_before_multiplication",
                        "expression": _text(node).strip()[:80],
                        "line": node.start_point[0] + 1,
                    })
    for child in node.children:
        results.extend(_has_division_before_multiply(child))
    return results


def _contains_division(node):
    """Check if a node contains a division operator."""
    if node is None:
        return False
    if node.type == "binary_expression":
        children = [c for c in node.children if c.type not in ("{", "}", ";", ",")]
        if len(children) >= 3 and _text(children[1]) == "/":
            return True
    for child in node.children:
        if _contains_division(child):
            return True
    return False


# Test file path patterns — suppress security findings from test code
TEST_PATH_PATTERNS = {"test/", "tests/", "test_", "forge-test/", "mock/", "mocks/",
                      "fixture/", "fixtures/", "scripts/", "script/"}


class SolidityExtractor(BaseExtractor):

    def __init__(self):
        self.parser = _get_parser()

    def extract_from_source(self, source_code: bytes, file_path: str) -> ExtractResult:
        """Parse source and extract."""
        tree = self.parser.parse(source_code)
        return self.extract(tree, source_code, file_path)

    def extract(self, tree, source_code: bytes, file_path: str) -> ExtractResult:
        result = ExtractResult()
        root = tree.root_node

        # Track state vars and enums at file level for cross-contract reference
        all_state_vars: set[str] = set()
        all_enums: dict[str, list[str]] = {}  # enum_name -> [variants]

        for child in root.children:
            if child.type == "contract_declaration":
                self._extract_contract(child, file_path, result, all_state_vars, all_enums)
            elif child.type == "interface_declaration":
                self._extract_interface(child, file_path, result)
            elif child.type == "struct_declaration":
                self._extract_struct(child, file_path, "", result)
            elif child.type == "library_declaration":
                self._extract_library(child, file_path, result, all_state_vars, all_enums)

        return result

    def _extract_interface(self, node, file_path, result):
        """Extract interface declarations as nodes."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        iface_name = _text(name_node)
        iface_id = self._make_node_id(file_path, iface_name)
        result.nodes.append({
            "id": iface_id, "label": iface_name, "type": "interface",
            "visibility": "public", "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"interface {iface_name}",
            "metadata": json.dumps({"contract": iface_name, "is_interface": True}),
        })

    def _extract_struct(self, node, file_path, contract_name, result):
        """Extract struct declarations as nodes."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        struct_name = _text(name_node)
        if contract_name:
            qualified = f"{contract_name}.{struct_name}"
        else:
            qualified = struct_name
        struct_id = self._make_node_id(file_path, qualified)

        # Extract fields
        fields = []
        body = _child_by_type(node, "struct_body")
        if not body:
            # Try contract_body or just iterate children for member declarations
            for child in node.children:
                if child.type == "struct_member":
                    type_n = _child_by_type(child, "type_name")
                    name_n = _child_by_type(child, "identifier")
                    fields.append({
                        "type": _text(type_n) if type_n else "",
                        "name": _text(name_n) if name_n else "",
                    })
        else:
            for child in body.children:
                if child.type == "struct_member":
                    type_n = _child_by_type(child, "type_name")
                    name_n = _child_by_type(child, "identifier")
                    fields.append({
                        "type": _text(type_n) if type_n else "",
                        "name": _text(name_n) if name_n else "",
                    })

        meta = {"contract": contract_name} if contract_name else {}
        meta["fields"] = fields

        result.nodes.append({
            "id": struct_id, "label": struct_name, "type": "struct",
            "visibility": "public", "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"struct {struct_name}",
            "metadata": json.dumps(meta),
        })

    def _extract_library(self, node, file_path, result, all_state_vars, all_enums):
        """Extract library declarations."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        lib_name = _text(name_node)
        lib_id = self._make_node_id(file_path, lib_name)
        result.nodes.append({
            "id": lib_id, "label": lib_name, "type": "library",
            "visibility": "public", "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"library {lib_name}",
            "metadata": json.dumps({"is_library": True}),
        })

        # Extract functions inside the library
        body = _child_by_type(node, "contract_body")
        if not body:
            return
        func_ts_map: dict[int, str] = {}
        for item in body.children:
            if item.type == "function_definition":
                self._extract_function(item, file_path, lib_name, result, func_ts_map)

        # Second pass: walk function bodies for call/state edges
        for item in body.children:
            if item.type == "function_definition":
                func_name_node = _child_by_type(item, "identifier")
                if not func_name_node:
                    continue
                func_name = _text(func_name_node)
                param_types = _extract_param_types(item)
                func_id = self._make_node_id(file_path, f"{lib_name}.{func_name}", param_types)
                func_body = _child_by_type(item, "function_body")
                if not func_body:
                    continue
                self._extract_body_edges(
                    func_body, func_id, file_path, lib_name,
                    all_state_vars, all_enums, result
                )

    def _extract_contract(self, node, file_path, result, all_state_vars, all_enums):
        """Extract everything from a contract declaration."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        contract_name = _text(name_node)

        # Detect abstract
        is_abstract = any(c.type == "abstract" for c in node.children)
        contract_type = "abstract" if is_abstract else "contract"

        # Create contract-level node
        contract_id = self._make_node_id(file_path, contract_name)
        result.nodes.append({
            "id": contract_id, "label": contract_name, "type": contract_type,
            "visibility": "public", "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"{'abstract ' if is_abstract else ''}contract {contract_name}",
            "metadata": json.dumps({"is_abstract": is_abstract}),
        })

        # Extract inheritance
        for spec in _children_by_type(node, "inheritance_specifier"):
            base_ids = _children_by_type(spec, "identifier")
            if not base_ids:
                # Try user_defined_type or type_name
                base_text = _text(spec).strip()
                if base_text:
                    result.edges.append({
                        "source": self._make_node_id(file_path, contract_name),
                        "target": f"_::{base_text}",
                        "relation": "inherits",
                        "attributes": "{}",
                    })
            else:
                for bid in base_ids:
                    result.edges.append({
                        "source": self._make_node_id(file_path, contract_name),
                        "target": f"_::{_text(bid)}",
                        "relation": "inherits",
                        "attributes": "{}",
                    })

        body = _child_by_type(node, "contract_body")
        if not body:
            return

        # Maps ts node.id -> our node_id for enclosing function lookup
        func_ts_map: dict[int, str] = {}
        state_var_names: set[str] = set()
        enum_map: dict[str, list[str]] = {}  # enum_name -> [variants]

        # First pass: extract enums, state vars, modifiers, events, functions,
        # constructors, fallback/receive, structs
        for item in body.children:
            if item.type == "enum_declaration":
                self._extract_enum(item, file_path, contract_name, enum_map, all_enums)

            elif item.type == "state_variable_declaration":
                self._extract_state_var(item, file_path, contract_name, result, state_var_names, all_state_vars)

            elif item.type == "modifier_definition":
                self._extract_modifier(item, file_path, contract_name, result)

            elif item.type == "event_definition":
                self._extract_event(item, file_path, contract_name, result)

            elif item.type == "function_definition":
                self._extract_function(item, file_path, contract_name, result, func_ts_map)

            elif item.type == "constructor_definition":
                self._extract_constructor(item, file_path, contract_name, result, func_ts_map)

            elif item.type == "fallback_receive_definition":
                self._extract_fallback_receive(item, file_path, contract_name, result, func_ts_map)

            elif item.type == "struct_declaration":
                self._extract_struct(item, file_path, contract_name, result)

        # Second pass: walk function bodies for edges
        for item in body.children:
            if item.type == "function_definition":
                func_name_node = _child_by_type(item, "identifier")
                if not func_name_node:
                    continue
                func_name = _text(func_name_node)
                param_types = _extract_param_types(item)
                func_id = self._make_node_id(file_path, f"{contract_name}.{func_name}", param_types)
                func_body = _child_by_type(item, "function_body")
                if not func_body:
                    continue
                # Extract modifier names for reentrancy guard detection
                func_modifiers = []
                for mod_inv in _children_by_type(item, "modifier_invocation"):
                    mn = _child_by_type(mod_inv, "identifier")
                    if mn:
                        func_modifiers.append(_text(mn))
                self._extract_body_edges(
                    func_body, func_id, file_path, contract_name,
                    state_var_names | all_state_vars, enum_map, result,
                    modifier_names=func_modifiers
                )

            elif item.type == "constructor_definition":
                func_id = self._make_node_id(file_path, f"{contract_name}.constructor")
                func_body = _child_by_type(item, "function_body")
                if not func_body:
                    continue
                self._extract_body_edges(
                    func_body, func_id, file_path, contract_name,
                    state_var_names | all_state_vars, enum_map, result
                )

            elif item.type == "fallback_receive_definition":
                node_text = _text(item)
                if node_text.strip().startswith("receive"):
                    label = "receive"
                else:
                    label = "fallback"
                func_id = self._make_node_id(file_path, f"{contract_name}.{label}")
                func_body = _child_by_type(item, "function_body")
                if not func_body:
                    continue
                self._extract_body_edges(
                    func_body, func_id, file_path, contract_name,
                    state_var_names | all_state_vars, enum_map, result
                )

            # H3: Walk modifier bodies for edges
            elif item.type == "modifier_definition":
                mod_name_node = _child_by_type(item, "identifier")
                if not mod_name_node:
                    continue
                mod_name = _text(mod_name_node)
                mod_id = self._make_node_id(file_path, f"{contract_name}.{mod_name}")
                # Modifier body: try function_body first, then look for block
                mod_body = _child_by_type(item, "function_body")
                if not mod_body:
                    mod_body = _child_by_type(item, "block")
                if not mod_body:
                    continue
                self._extract_body_edges(
                    mod_body, mod_id, file_path, contract_name,
                    state_var_names | all_state_vars, enum_map, result
                )

    def _extract_enum(self, node, file_path, contract_name, enum_map, all_enums):
        """Extract enum declarations for state machine detection."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        enum_name = _text(name_node)
        body = _child_by_type(node, "enum_body")
        variants = []
        if body:
            for v in _children_by_type(body, "identifier"):
                variants.append(_text(v))
            # Also check enum_value nodes
            for v in _children_by_type(body, "enum_value"):
                vid = _child_by_type(v, "identifier")
                if vid:
                    variants.append(_text(vid))
        enum_map[enum_name] = variants
        all_enums[enum_name] = variants

    def _extract_state_var(self, node, file_path, contract_name, result, state_var_names, all_state_vars):
        """Extract state variable declarations."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        var_name = _text(name_node)
        state_var_names.add(var_name)
        all_state_vars.add(var_name)

        vis_node = _child_by_type(node, "visibility")
        visibility = _text(vis_node) if vis_node else "internal"

        type_node = _child_by_type(node, "type_name")
        type_text = _text(type_node) if type_node else ""

        var_id = self._make_node_id(file_path, f"{contract_name}.{var_name}")
        result.nodes.append({
            "id": var_id, "label": var_name, "type": "state_var",
            "visibility": visibility, "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": type_text,
            "metadata": json.dumps({"contract": contract_name, "type_text": type_text}),
        })

    def _extract_modifier(self, node, file_path, contract_name, result):
        """Extract modifier definitions."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        mod_name = _text(name_node)
        mod_id = self._make_node_id(file_path, f"{contract_name}.{mod_name}")
        result.nodes.append({
            "id": mod_id, "label": mod_name, "type": "modifier",
            "visibility": "", "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"modifier {mod_name}",
            "metadata": json.dumps({"contract": contract_name}),
        })

    def _extract_event(self, node, file_path, contract_name, result):
        """Extract event definitions."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        event_name = _text(name_node)
        event_id = self._make_node_id(file_path, f"{contract_name}.{event_name}")
        result.nodes.append({
            "id": event_id, "label": event_name, "type": "event",
            "visibility": "", "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": _text(node).split("{")[0].strip().rstrip(";"),
            "metadata": json.dumps({"contract": contract_name}),
        })

    def _extract_constructor(self, node, file_path, contract_name, result, func_ts_map):
        """Extract constructor definitions."""
        func_id = self._make_node_id(file_path, f"{contract_name}.constructor")

        # Register in ts_node map
        func_ts_map[node.id] = func_id

        # Visibility - constructors are implicitly public
        visibility = "public"

        # Parameters
        params = []
        for p in _children_by_type(node, "parameter"):
            type_n = _child_by_type(p, "type_name")
            param_name = _child_by_type(p, "identifier")
            ptype = _text(type_n) if type_n else ""
            pname = _text(param_name) if param_name else ""
            params.append(f"{ptype} {pname}".strip())

        sig = f"constructor({', '.join(params)})"

        meta = {"contract": contract_name}
        full_text = _text(node)
        for kw in ("payable",):
            if kw in full_text.split("{")[0]:
                meta[kw] = True

        result.nodes.append({
            "id": func_id, "label": "constructor", "type": "function",
            "visibility": visibility, "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": sig,
            "metadata": json.dumps(meta),
        })

    def _extract_fallback_receive(self, node, file_path, contract_name, result, func_ts_map):
        """Extract fallback() and receive() definitions."""
        node_text = _text(node)
        if node_text.strip().startswith("receive"):
            label = "receive"
        else:
            label = "fallback"

        func_id = self._make_node_id(file_path, f"{contract_name}.{label}")

        # Register in ts_node map
        func_ts_map[node.id] = func_id

        # These are always external
        visibility = "external"

        sig = f"{label}()"

        meta = {"contract": contract_name}
        full_text = _text(node)
        for kw in ("payable",):
            if kw in full_text.split("{")[0]:
                meta[kw] = True

        result.nodes.append({
            "id": func_id, "label": label, "type": "function",
            "visibility": visibility, "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": sig,
            "metadata": json.dumps(meta),
        })

    def _extract_function(self, node, file_path, contract_name, result, func_ts_map):
        """Extract function definitions and modifier (guard) edges."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        func_name = _text(name_node)

        # Extract parameter types for overloading disambiguation
        param_types = _extract_param_types(node)
        func_id = self._make_node_id(file_path, f"{contract_name}.{func_name}", param_types)

        # Register in ts_node map for enclosing function lookup
        func_ts_map[node.id] = func_id

        # Visibility
        vis_node = _child_by_type(node, "visibility")
        visibility = _text(vis_node).strip() if vis_node else "public"

        # Parameters
        params = []
        for p in _children_by_type(node, "parameter"):
            type_n = _child_by_type(p, "type_name")
            param_name = _child_by_type(p, "identifier")
            ptype = _text(type_n) if type_n else ""
            pname = _text(param_name) if param_name else ""
            params.append(f"{ptype} {pname}".strip())

        sig = f"function {func_name}({', '.join(params)}) {visibility}"

        # Check for payable/view/pure state mutability
        meta = {"contract": contract_name}
        full_text = _text(node)
        for kw in ("payable", "view", "pure"):
            if kw in full_text.split("{")[0]:
                meta[kw] = True

        # Extract modifier names for reentrancy guard detection
        modifier_names = []
        for mod_inv in _children_by_type(node, "modifier_invocation"):
            mod_name_node = _child_by_type(mod_inv, "identifier")
            if mod_name_node:
                modifier_names.append(_text(mod_name_node))
        if modifier_names:
            meta["modifiers"] = modifier_names

        # H2: Capture param data locations
        param_locations = _extract_param_locations(node)
        if any(pl["location"] for pl in param_locations):
            meta["param_locations"] = param_locations

        # C3: Check for tx.origin in function body
        func_body = _child_by_type(node, "function_body")
        if func_body and _contains_tx_origin(func_body):
            meta["uses_tx_origin"] = True

        # H1: Check for unchecked blocks
        if func_body and _find_unchecked_blocks(func_body):
            meta["has_unchecked"] = True

        # MEDIUM: Check for assembly blocks
        if func_body and _find_assembly_blocks(func_body):
            meta["has_assembly"] = True

        result.nodes.append({
            "id": func_id, "label": func_name, "type": "function",
            "visibility": visibility, "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": sig,
            "metadata": json.dumps(meta),
        })

        # Modifier invocations -> guards edges
        for mod_inv in _children_by_type(node, "modifier_invocation"):
            mod_name_node = _child_by_type(mod_inv, "identifier")
            if mod_name_node:
                mod_name = _text(mod_name_node)
                mod_id = self._make_node_id(file_path, f"{contract_name}.{mod_name}")
                result.edges.append({
                    "source": mod_id,
                    "target": func_id,
                    "relation": "guards",
                    "attributes": "{}",
                })

    def _extract_body_edges(self, body_node, func_id, file_path, contract_name,
                            state_var_names, enum_map, result, modifier_names=None):
        """Walk function body to extract call, state, emit, and sink edges."""
        # C1: Build ordered statement list for reentrancy detection
        ordered_stmts = _collect_statements_ordered(body_node)

        # Find unchecked blocks for H1
        unchecked_blocks = _find_unchecked_blocks(body_node)

        # Collect all identifiers read in expressions (for reads_state)
        all_ids = _collect_identifiers(body_node)
        for var_name in all_ids & state_var_names:
            var_id = self._make_node_id(file_path, f"{contract_name}.{var_name}")
            # C1: find order for the first occurrence
            order = self._find_first_id_order(body_node, var_name, ordered_stmts)
            attrs = {"order": order} if order >= 0 else {}
            result.edges.append({
                "source": func_id, "target": var_id,
                "relation": "reads_state",
                "attributes": json.dumps(attrs) if attrs else "{}",
            })

        # Assignments -> writes_state
        for assign in _collect_assignments(body_node):
            lhs_ids = set()
            # Get the left-hand side (first expression child)
            expr_children = _children_by_type(assign, "expression")
            if expr_children:
                lhs_ids = _collect_identifiers(expr_children[0])
            written_vars = lhs_ids & state_var_names

            # C1: statement order
            order = _find_stmt_order(assign, ordered_stmts)
            # H1: check if inside unchecked block
            in_unchecked = any(_node_is_inside(assign, ub) for ub in unchecked_blocks)

            for var_name in written_vars:
                var_id = self._make_node_id(file_path, f"{contract_name}.{var_name}")
                attrs = {}
                if order >= 0:
                    attrs["order"] = order
                if in_unchecked:
                    attrs["unchecked"] = True
                result.edges.append({
                    "source": func_id, "target": var_id,
                    "relation": "writes_state",
                    "attributes": json.dumps(attrs) if attrs else "{}",
                })

            # State machine detection: assignment to state var of enum type
            self._detect_state_transition(
                assign, func_id, file_path, written_vars, enum_map, body_node, result
            )

        # Call expressions -> calls edges + sink detection
        for call in _collect_calls(body_node):
            call_name = _get_call_name(call)
            full_target = _extract_call_target_full(call)

            # C1: statement order for calls
            order = _find_stmt_order(call, ordered_stmts)
            # H1: check if inside unchecked block
            in_unchecked = any(_node_is_inside(call, ub) for ub in unchecked_blocks)

            if call_name and call_name not in ("require", "assert", "revert"):
                # Determine if this is an interface/external call
                attrs = {}
                if order >= 0:
                    attrs["order"] = order
                if in_unchecked:
                    attrs["unchecked"] = True
                if "." in full_target:
                    parts = full_target.split(".")
                    receiver = parts[0]
                    # Mark as unresolved cross-contract call unless it's a
                    # built-in namespace or known library method.
                    # State-variable receivers (dataStore.method()) ARE cross-contract.
                    if (receiver not in ("msg", "block", "tx", "abi", "super", "this")
                            and call_name not in KNOWN_LIBRARY_METHODS):
                        attrs["unresolved"] = True
                        attrs["call_name"] = call_name
                        attrs["interface"] = receiver

                target_id = self._make_node_id(file_path, f"{contract_name}.{call_name}")
                result.edges.append({
                    "source": func_id, "target": target_id,
                    "relation": "calls",
                    "attributes": json.dumps(attrs) if attrs else "{}",
                })

            # Sink detection
            self._detect_sink(call, full_target, call_name, func_id, file_path, contract_name, result)

        # Emit statements -> emits_event edges
        for emit in _collect_emit_stmts(body_node):
            event_ids = _children_by_type(emit, "expression")
            if event_ids:
                event_name_node = _child_by_type(event_ids[0], "identifier") if event_ids[0].type != "identifier" else event_ids[0]
                if event_name_node is None:
                    event_name_node = event_ids[0]
                event_name = _text(event_name_node)
                event_id = self._make_node_id(file_path, f"{contract_name}.{event_name}")
                result.edges.append({
                    "source": func_id, "target": event_id,
                    "relation": "emits_event", "attributes": "{}",
                })

        # Reentrancy detection: external call before state write
        # Skip test files entirely — test setUp() functions are not production code
        is_test_file = any(pat in file_path for pat in TEST_PATH_PATTERNS)
        if modifier_names is None:
            modifier_names = []
        reentrancy_guards = {"nonReentrant", "ReentrancyGuard", "noReentrant",
                              "globalNonReentrant", "nonReentrant_", "lock_"}
        has_guard = bool(set(modifier_names) & reentrancy_guards)

        # Build set of library/interface names for filtering
        # Libraries are inlined (no external call), interfaces are type-only
        library_names = set()
        interface_names = set()
        for n in result.nodes:
            if n.get("type") == "library":
                library_names.add(n["label"])
            elif n.get("type") == "interface":
                interface_names.add(n["label"])

        if not has_guard and not is_test_file:
            # Collect external call orders (skip library calls — they're inlined)
            ext_call_orders = []
            for e in result.edges:
                if e["source"] != func_id or e["relation"] != "calls":
                    continue
                attrs = json.loads(e["attributes"]) if e["attributes"] != "{}" else {}
                if attrs.get("unresolved") and "order" in attrs:
                    interface = attrs.get("interface", "")
                    call_name_r = attrs.get("call_name", "?")
                    # Skip library calls and known safe utility calls
                    if interface in library_names:
                        continue
                    if call_name_r in SAFE_REENTRANCY_CALLS:
                        continue
                    ext_call_orders.append((attrs["order"], call_name_r))
                elif attrs.get("sink") and "order" not in attrs:
                    # Sink calls: check the sink node for low-level call types
                    pass

            # Also check sink edges (fund_transfer, low_level_call, delegate)
            for e in result.edges:
                if e["source"] != func_id or e["relation"] != "calls":
                    continue
                attrs = json.loads(e["attributes"]) if e["attributes"] != "{}" else {}
                if attrs.get("sink"):
                    # Find the sink node to get its type and the call order
                    target_id = e["target"]
                    for n in result.nodes:
                        if n["id"] == target_id:
                            n_meta = json.loads(n.get("metadata", "{}"))
                            if n_meta.get("sink_type") in ("fund_transfer", "low_level_call", "delegate"):
                                # Find order from the original call edge (non-sink) or from line
                                call_order = self._find_call_order_for_line(
                                    n.get("line_start", 0), ordered_stmts, body_node
                                )
                                if call_order >= 0:
                                    ext_call_orders.append((call_order, n["label"]))

            # Collect state write orders
            write_orders = []
            for e in result.edges:
                if e["source"] != func_id or e["relation"] != "writes_state":
                    continue
                attrs = json.loads(e["attributes"]) if e["attributes"] != "{}" else {}
                if "order" in attrs:
                    target_label = e["target"].split("::")[-1] if "::" in e["target"] else e["target"]
                    write_orders.append((attrs["order"], target_label))

            # Check if any external call order < any state write order
            if ext_call_orders and write_orders:
                for call_order, call_name in ext_call_orders:
                    for write_order, write_var in write_orders:
                        if call_order < write_order:
                            # Flag reentrancy risk on the function node
                            for n in result.nodes:
                                if n["id"] == func_id:
                                    meta = json.loads(n.get("metadata", "{}"))
                                    meta["reentrancy_risk"] = True
                                    meta["reentrancy_details"] = (
                                        f"external call '{call_name}' at order {call_order} "
                                        f"before state write '{write_var}' at order {write_order}"
                                    )
                                    n["metadata"] = json.dumps(meta)
                                    break
                            break  # One finding is enough
                    else:
                        continue
                    break

        # Unchecked low-level call detection
        for call in _collect_calls(body_node):
            call_name = _get_call_name(call)
            if call_name not in ("call", "send", "delegatecall"):
                continue
            # Check if the call result is assigned or used in require/if
            parent = call.parent
            is_checked = False
            # Walk up to find assignment or require context
            current = call
            while current:
                if current.type in ("assignment_expression", "variable_declaration_statement",
                                    "variable_declaration"):
                    is_checked = True
                    break
                if current.type == "call_expression":
                    pname = _get_call_name(current)
                    if pname in ("require", "assert", "if"):
                        is_checked = True
                        break
                if current.type in ("if_statement",):
                    is_checked = True
                    break
                current = current.parent
            if not is_checked:
                # Mark unchecked call in function metadata
                for n in result.nodes:
                    if n["id"] == func_id:
                        meta = json.loads(n.get("metadata", "{}"))
                        if "unchecked_calls" not in meta:
                            meta["unchecked_calls"] = []
                        meta["unchecked_calls"].append({
                            "call_name": call_name,
                            "line": call.start_point[0] + 1,
                        })
                        n["metadata"] = json.dumps(meta)
                        break

        # C3: tx.origin detection - add edge
        if _contains_tx_origin(body_node):
            result.edges.append({
                "source": func_id,
                "target": "_::tx.origin",
                "relation": "reads_state",
                "attributes": json.dumps({"tx_origin": True}),
            })

        # --- SC10: Proxy & Upgradeability risk detection ---
        # Look up function metadata from the already-created node
        func_node = None
        for n in result.nodes:
            if n["id"] == func_id:
                func_node = n
                break

        if func_node:
            func_meta = json.loads(func_node.get("metadata", "{}"))
            func_label = func_node.get("label", "")
            func_vis = func_node.get("visibility", "")
            func_mods = func_meta.get("modifiers", [])

            # SC10: Proxy risk — unprotected initialize / delegatecall / selfdestruct
            proxy_risks = []
            if func_label in ("initialize", "__init__"):
                if "initializer" not in func_mods and "onlyInitializing" not in func_mods:
                    proxy_risks.append("initialize_without_initializer_modifier")
            body_text = _text(body_node)
            if "delegatecall" in body_text:
                proxy_risks.append("contains_delegatecall")
            if "selfdestruct" in body_text or "selfDestruct" in body_text:
                proxy_risks.append("contains_selfdestruct")
            if proxy_risks:
                func_meta["proxy_risk"] = proxy_risks
                func_node["metadata"] = json.dumps(func_meta)

            role_guards = _infer_role_guards(func_mods, body_text)
            if role_guards:
                func_meta["role_guards"] = role_guards
                func_node["metadata"] = json.dumps(func_meta)

            privileged_ops = _infer_privileged_operations(func_label, body_text, func_mods)
            if privileged_ops:
                func_meta["privileged_operations"] = privileged_ops
                if any(op in privileged_ops for op in ("upgrade", "implementation_change", "delegate_execution", "shutdown")):
                    func_meta["upgrade_surface"] = True
                if func_vis in ("external", "public") and not role_guards and not any(
                    mod.startswith(("only", "when", "check")) for mod in func_mods
                ):
                    func_meta["unguarded_privileged_operation"] = True
                func_node["metadata"] = json.dumps(func_meta)

            # --- ERC token callback reentrancy detection ---
            # onERC721Received, onERC1155Received, tokensReceived are reentrancy entry points
            ERC_CALLBACKS = {"onERC721Received", "onERC1155Received",
                             "onERC1155BatchReceived", "tokensReceived",
                             "tokensToSend"}
            if func_label in ERC_CALLBACKS:
                callback_risks = []
                has_writes = any(
                    e["relation"] == "writes_state"
                    for e in result.edges
                    if e.get("source") == func_id
                )
                has_ext_calls = any(
                    e["relation"] == "calls"
                    and e.get("target", "").startswith("UNRESOLVED::")
                    for e in result.edges
                    if e.get("source") == func_id
                )
                if has_writes:
                    callback_risks.append("state_write_in_callback")
                if has_ext_calls:
                    callback_risks.append("external_call_in_callback")
                if not any(mod in (modifier_names or [])
                           for mod in ("nonReentrant", "noReentrant", "lock_")):
                    callback_risks.append("no_reentrancy_guard")
                if callback_risks:
                    func_meta["erc_callback_risk"] = callback_risks
                    func_node["metadata"] = json.dumps(func_meta)

            # --- SC05: Input validation detection ---
            # Flag external/public state-changing functions with params but no validation
            # Skip: view/pure, functions with access-control modifiers (they validate via modifier),
            #        test files, standard ERC20/ERC721 functions (intentionally permissionless)
            # Exact-match modifiers that indicate access control or protection
            ACCESS_MODIFIERS = {"requiresAuth", "auth", "governance",
                                "nonReentrant", "noReentrant", "lock_",
                                "globalNonReentrant",
                                "initializer", "reinitializer",
                                "notTradingPausedOrFrozen",
                                "ifAdmin", "privileged", "restricted",
                                "proxyCallIfNotOwner", "proxyCallIfNotAdmin"}
            ERC_STANDARD_FUNCS = {"transfer", "approve", "transferFrom",
                                  "increaseAllowance", "decreaseAllowance",
                                  "safeTransfer", "safeTransferFrom",
                                  "setApprovalForAll", "permit",
                                  "transferShares", "transferSharesFrom"}
            # Prefix-based: any modifier starting with "only" or "when" is access control
            has_access_modifier = False
            for mod in (modifier_names or []):
                if mod in ACCESS_MODIFIERS or mod.startswith("only") or mod.startswith("when") or mod.startswith("check"):
                    has_access_modifier = True
                    break
            if func_meta.get("role_guards"):
                has_access_modifier = True
            is_erc_standard = func_label in ERC_STANDARD_FUNCS
            if (func_vis in ("external", "public")
                    and not func_meta.get("view") and not func_meta.get("pure")
                    and not has_access_modifier
                    and not is_erc_standard
                    and not is_test_file):
                # Check if the function has parameters
                sig = func_node.get("signature", "")
                paren_open = sig.find("(")
                paren_close = sig.find(")")
                has_params = (paren_open >= 0 and paren_close > paren_open + 1)
                if has_params:
                    # Check if body has ANY require/revert/assert/if statement
                    has_validation = False
                    for kw in ("require", "revert", "assert"):
                        if kw in body_text:
                            has_validation = True
                            break
                    if not has_validation:
                        if_nodes = _collect_nodes_by_types(body_node, {"if_statement"})
                        if if_nodes:
                            has_validation = True
                    if not has_validation:
                        func_meta["no_input_validation"] = True
                        func_node["metadata"] = json.dumps(func_meta)

            # --- SC09: Integer overflow/underflow detection ---
            unchecked_arith = []
            # Detect unchecked blocks with arithmetic
            # Skip the common gas-optimization pattern: unchecked { ++i; } or { i++; }
            for ub in unchecked_blocks:
                ub_text = _text(ub).strip()
                # Filter out loop counter increments: "unchecked { ++i; }" or "{ i++; }" etc.
                inner = ub_text
                if inner.startswith("unchecked"):
                    inner = inner[len("unchecked"):].strip()
                if inner.startswith("{"):
                    inner = inner[1:]
                if inner.endswith("}"):
                    inner = inner[:-1]
                inner = inner.strip().rstrip(";").strip()
                # Skip if it's just a single increment/decrement: ++var, var++, --var, var--
                if re.match(r'^(\+\+\w+|\w+\+\+|--\w+|\w+--)$', inner):
                    continue
                if any(op in ub_text for op in ("+", "-", "*", "/")):
                    unchecked_arith.append({
                        "type": "unchecked_block",
                        "line": ub.start_point[0] + 1,
                    })
            # Detect pre-0.8.0 pragma without SafeMath
            if not unchecked_arith:
                # Check source for old pragma
                source_text = body_node.text.decode("utf-8") if body_node else ""
                # Walk up to root to find pragma from the source
                root = body_node
                while root.parent:
                    root = root.parent
                root_text = _text(root)
                pragma_match = re.search(
                    r'pragma\s+solidity\s+[\^~>=<]*\s*(0\.\d+)', root_text
                )
                if pragma_match:
                    version_minor = int(pragma_match.group(1).split(".")[1])
                    if version_minor < 8:
                        # Pre-0.8.0: check if function does arithmetic without SafeMath
                        if any(op in body_text for op in ("+", "-", "*", "/")):
                            if "SafeMath" not in root_text:
                                unchecked_arith.append({
                                    "type": "pre_0.8_no_safemath",
                                })
            if unchecked_arith:
                func_meta["unchecked_arithmetic"] = unchecked_arith
                func_node["metadata"] = json.dumps(func_meta)

            # --- SC07: Arithmetic precision risk detection ---
            # Detect division-before-multiplication patterns: a / b * c
            precision_risks = []
            # Pattern: identifier/expression / identifier/expression * identifier/expression
            # Simple heuristic: look for "/ ... *" pattern in body text
            div_then_mul = re.findall(
                r'(\w+\s*/\s*\w+\s*\*\s*\w+)', body_text
            )
            for match in div_then_mul:
                precision_risks.append({
                    "type": "division_before_multiplication",
                    "expression": match.strip(),
                })
            if precision_risks:
                func_meta["precision_risk"] = precision_risks
                func_node["metadata"] = json.dumps(func_meta)

            # --- Timestamp dependence detection ---
            # block.timestamp / block.number in comparisons or arithmetic
            # = deadline bypass, auction manipulation, randomness abuse
            timestamp_risks = []
            if "block.timestamp" in body_text or "block.number" in body_text:
                ts_comparisons = re.findall(
                    r'(block\.(?:timestamp|number)\s*(?:>=|<=|!=|==|>(?!=)|<(?!=))\s*\w+|'
                    r'\w+\s*(?:>=|<=|!=|==|>(?!=)|<(?!=))\s*block\.(?:timestamp|number))',
                    body_text
                )
                for match in ts_comparisons:
                    timestamp_risks.append({
                        "type": "timestamp_comparison",
                        "expression": match.strip(),
                    })
                ts_arithmetic = re.findall(
                    r'(block\.(?:timestamp|number)\s*[+\-*/]\s*\w+|'
                    r'\w+\s*[+\-*/]\s*block\.(?:timestamp|number))',
                    body_text
                )
                for match in ts_arithmetic:
                    timestamp_risks.append({
                        "type": "timestamp_arithmetic",
                        "expression": match.strip(),
                    })
            if timestamp_risks:
                func_meta["timestamp_dependence"] = timestamp_risks
                func_node["metadata"] = json.dumps(func_meta)

            # --- Unchecked ERC20 return value detection ---
            # IERC20.transfer()/transferFrom() return bool but often ignored
            # -> silent token loss. SafeERC20 wrappers are the fix.
            unchecked_erc20 = []
            for call_node_erc in _collect_calls(body_node):
                cn_erc = _get_call_name(call_node_erc)
                if cn_erc not in ("transfer", "transferFrom"):
                    continue
                ft_erc = _extract_call_target_full(call_node_erc)
                # Must be on external receiver (bare transfer = ETH, already a sink)
                if "." not in ft_erc:
                    continue
                # Check if return value is captured
                erc_checked = False
                cur = call_node_erc
                while cur:
                    if cur.type in ("assignment_expression",
                                    "variable_declaration_statement",
                                    "variable_declaration"):
                        erc_checked = True
                        break
                    if cur.type == "call_expression":
                        pn = _get_call_name(cur)
                        if pn in ("require", "assert"):
                            erc_checked = True
                            break
                    if cur.type == "if_statement":
                        erc_checked = True
                        break
                    cur = cur.parent
                if not erc_checked:
                    unchecked_erc20.append({
                        "target": ft_erc,
                        "line": call_node_erc.start_point[0] + 1,
                    })
            if unchecked_erc20:
                func_meta["unchecked_erc20"] = unchecked_erc20
                func_node["metadata"] = json.dumps(func_meta)

            # --- Oracle / price manipulation detection ---
            # Spot price reads without TWAP or multi-block averaging
            ORACLE_READ_FNS = {"getReserves", "latestAnswer",
                               "latestRoundData", "getRoundData"}
            SPOT_PRICE_FNS = {"balanceOf", "getAmountsOut",
                              "getAmountsIn", "quote"}
            oracle_risks = []
            for call_node_or in _collect_calls(body_node):
                cn_or = _get_call_name(call_node_or)
                if cn_or in ORACLE_READ_FNS:
                    oracle_risks.append({
                        "type": "oracle_read",
                        "call": cn_or,
                        "line": call_node_or.start_point[0] + 1,
                    })
                elif cn_or in SPOT_PRICE_FNS:
                    ft_or = _extract_call_target_full(call_node_or)
                    if "." in ft_or:  # external call
                        oracle_risks.append({
                            "type": "spot_price_read",
                            "call": ft_or,
                            "line": call_node_or.start_point[0] + 1,
                        })
            if oracle_risks:
                func_meta["oracle_risk"] = oracle_risks
                func_node["metadata"] = json.dumps(func_meta)

            # --- Signature replay detection ---
            # ecrecover without nonce or chainId/domain separator
            if "ecrecover" in body_text:
                sig_risks = []
                has_nonce = any(n in body_text
                                for n in ("nonce", "nonces", "_nonces"))
                has_chain = ("chainid" in body_text.lower()
                             or "block.chainid" in body_text)
                has_domain = ("DOMAIN_SEPARATOR" in body_text
                              or "domainSeparator" in body_text
                              or "_domainSeparatorV4" in body_text)
                if not has_nonce:
                    sig_risks.append("missing_nonce")
                if not has_chain and not has_domain:
                    sig_risks.append("missing_chain_id_or_domain")
                if sig_risks:
                    func_meta["signature_risk"] = sig_risks
                    func_node["metadata"] = json.dumps(func_meta)

            # --- DoS: unbounded loops + external calls in loops ---
            dos_risks = []
            all_loops = _collect_for_loops(body_node) + _collect_while_loops(body_node)
            for loop_node in all_loops:
                loop_text = _text(loop_node)
                line = loop_node.start_point[0] + 1

                # Check if loop bound uses .length on a state variable
                # (dynamic array that can grow unboundedly)
                has_dynamic_bound = False
                for sv in state_var_names:
                    if f"{sv}.length" in loop_text.split("{")[0]:
                        has_dynamic_bound = True
                        dos_risks.append({
                            "type": "unbounded_loop",
                            "bound": f"{sv}.length",
                            "line": line,
                        })
                        break

                # Check for external calls inside the loop body
                loop_calls = _collect_calls(loop_node)
                for lc in loop_calls:
                    lc_name = _get_call_name(lc)
                    lc_full = _extract_call_target_full(lc)
                    if not lc_name:
                        continue
                    if "." in lc_full:
                        receiver = lc_full.split(".")[0]
                        if (receiver not in ("msg", "block", "tx", "abi",
                                             "super", "this")
                                and lc_name not in KNOWN_LIBRARY_METHODS):
                            dos_risks.append({
                                "type": "external_call_in_loop",
                                "call": lc_full,
                                "line": lc.start_point[0] + 1,
                            })
                            break  # One per loop is enough

            if dos_risks:
                func_meta["dos_risk"] = dos_risks
                func_node["metadata"] = json.dumps(func_meta)

            # --- Improved precision loss (AST-based) ---
            # Replace the simple regex with proper AST traversal
            ast_precision = _has_division_before_multiply(body_node)
            if ast_precision:
                # Merge with any existing regex-based findings, deduplicate
                existing = func_meta.get("precision_risk", [])
                seen_lines = {p.get("line") for p in existing}
                for ap in ast_precision:
                    if ap["line"] not in seen_lines:
                        existing.append(ap)
                if existing:
                    func_meta["precision_risk"] = existing
                    func_node["metadata"] = json.dumps(func_meta)

            # --- Frontrunning surface detection ---
            # 1. approve() without zero-set (ERC20 approve race)
            # 2. Functions reading price then executing swap (sandwich)
            frontrun_risks = []
            for call_fr in _collect_calls(body_node):
                cn_fr = _get_call_name(call_fr)
                ft_fr = _extract_call_target_full(call_fr)
                if cn_fr == "approve" and "." in ft_fr:
                    # Check if there's a prior approve(0) or forceApprove
                    if "approve(" in body_text:
                        # Look for approve(spender, 0) pattern before this one
                        call_line = call_fr.start_point[0] + 1
                        has_zero_set = ("approve(0)" in body_text
                                        or "forceApprove" in body_text
                                        or "safeApprove" in body_text)
                        if not has_zero_set:
                            frontrun_risks.append({
                                "type": "approve_race",
                                "target": ft_fr,
                                "line": call_line,
                            })

            if frontrun_risks:
                func_meta["frontrun_risk"] = frontrun_risks
                func_node["metadata"] = json.dumps(func_meta)

            # --- Unsafe type casting detection ---
            # uint256 -> smaller types without SafeCast (overflow risk)
            UINT_SIZES = {"uint8", "uint16", "uint32", "uint64", "uint96",
                          "uint128", "uint160", "uint192", "uint224"}
            INT_SIZES = {"int8", "int16", "int32", "int64", "int128"}
            unsafe_casts = []
            cast_nodes = _collect_nodes_by_types(body_node, {"type_cast_expression"})
            for cast_node in cast_nodes:
                cast_text = _text(cast_node)
                # Look for narrowing casts: uint128(someUint256Var)
                for small_type in UINT_SIZES | INT_SIZES:
                    if cast_text.startswith(small_type + "("):
                        # Check if SafeCast is used anywhere in the file
                        if "SafeCast" not in body_text and "safeCast" not in body_text:
                            unsafe_casts.append({
                                "type": small_type,
                                "line": cast_node.start_point[0] + 1,
                            })
                        break
            if unsafe_casts:
                func_meta["unsafe_downcast"] = unsafe_casts
                func_node["metadata"] = json.dumps(func_meta)

            # --- Flash loan callback detection ---
            # Functions named onFlashLoan / executeOperation / uniswapV3FlashCallback
            # that perform state writes or external calls are high-risk
            FLASH_CALLBACKS = {"onFlashLoan", "executeOperation",
                               "uniswapV3FlashCallback", "uniswapV2Call",
                               "pancakeCall", "onFlashLoanReceived",
                               "receiveFlashLoan"}
            if func_label in FLASH_CALLBACKS:
                flash_risks = []
                # Check for state writes in callback
                has_writes = any(
                    e["relation"] == "writes_state"
                    for e in result.edges
                    if e.get("source") == func_id
                )
                # Check for external calls in callback
                has_ext_calls = any(
                    e["relation"] == "calls" and e.get("target", "").startswith("UNRESOLVED::")
                    for e in result.edges
                    if e.get("source") == func_id
                )
                if has_writes:
                    flash_risks.append("state_write_in_callback")
                if has_ext_calls:
                    flash_risks.append("external_call_in_callback")
                if not any(mod in (modifier_names or [])
                           for mod in ("nonReentrant", "noReentrant", "lock_")):
                    flash_risks.append("no_reentrancy_guard")
                if flash_risks:
                    func_meta["flash_loan_risk"] = flash_risks
                    func_node["metadata"] = json.dumps(func_meta)

            # --- Missing slippage / deadline protection ---
            # Swap/deposit functions without minAmount/deadline params
            SWAP_NAMES = {"swap", "swapExactTokensForTokens",
                          "swapTokensForExactTokens", "swapExactETHForTokens",
                          "swapExactTokensForETH", "addLiquidity",
                          "removeLiquidity", "removeLiquidityETH"}
            if func_label in SWAP_NAMES or "swap" in func_label.lower():
                sig_lower = func_node.get("signature", "").lower()
                has_slippage = any(kw in sig_lower for kw in
                                   ("minamount", "amountmin", "amountoutmin",
                                    "minreturn", "slippage", "minout"))
                has_deadline = any(kw in sig_lower for kw in
                                   ("deadline", "expiry", "validuntil",
                                    "timestamp"))
                slippage_risks = []
                if not has_slippage:
                    slippage_risks.append("no_slippage_param")
                if not has_deadline:
                    slippage_risks.append("no_deadline_param")
                if slippage_risks:
                    func_meta["slippage_risk"] = slippage_risks
                    func_node["metadata"] = json.dumps(func_meta)

            # --- Dead parameter detection ---
            # Function params not referenced in body (business logic bugs)
            func_def_node = body_node.parent if body_node else None
            if func_def_node and func_vis in ("external", "public"):
                body_identifiers = _collect_identifiers(body_node)
                param_nodes = _children_by_type(func_def_node, "parameter")
                dead_params = []
                for p in param_nodes:
                    pname_node = _child_by_type(p, "identifier")
                    if pname_node:
                        pname = _text(pname_node)
                        if pname and pname not in body_identifiers and not pname.startswith("_"):
                            dead_params.append(pname)
                if dead_params:
                    func_meta["dead_params"] = dead_params
                    func_node["metadata"] = json.dumps(func_meta)

    def _find_call_order_for_line(self, line_num, ordered_stmts, body_node):
        """Find the statement order for a call at a given source line."""
        for order, stmt in ordered_stmts:
            if stmt.start_point[0] + 1 <= line_num <= stmt.end_point[0] + 1:
                return order
        return -1

    def _find_first_id_order(self, body_node, var_name, ordered_stmts):
        """Find the order of the first statement that references this identifier."""
        for order, stmt in ordered_stmts:
            ids = _collect_identifiers(stmt)
            if var_name in ids:
                return order
        return -1

    def _detect_sink(self, call_node, full_target, call_name, func_id, file_path, contract_name, result):
        """Detect dangerous call patterns and tag as sinks."""
        if not call_name:
            return

        sink_type = None
        # Fund transfer: .transfer(), .send(), .call{value:}
        if call_name in FUND_TRANSFER_PATTERNS:
            sink_type = "fund_transfer"
        elif call_name == "call" and "value" in _text(call_node):
            sink_type = "fund_transfer"
        # C2: Bare .call() without value -> low_level_call
        elif call_name == "call":
            sink_type = "low_level_call"
        # C2: .staticcall() detection
        elif call_name == "staticcall":
            sink_type = "static_call"
        # Delegatecall
        elif call_name in DELEGATE_PATTERNS:
            sink_type = "delegate"
        # Selfdestruct
        elif call_name in SELF_DESTRUCT_PATTERNS:
            sink_type = "self_destruct"

        if sink_type:
            sink_id = self._make_node_id(file_path, f"{contract_name}._sink_{call_name}_{call_node.start_point[0]}")
            result.nodes.append({
                "id": sink_id, "label": call_name, "type": "function",
                "visibility": "", "file": file_path,
                "line_start": call_node.start_point[0] + 1,
                "line_end": call_node.end_point[0] + 1,
                "signature": full_target,
                "metadata": json.dumps({
                    "contract": contract_name,
                    "is_sink": True,
                    "sink_type": sink_type,
                }),
            })
            result.edges.append({
                "source": func_id, "target": sink_id,
                "relation": "calls",
                "attributes": json.dumps({"sink": True}),
            })

    def _detect_state_transition(self, assign_node, func_id, file_path,
                                 written_vars, enum_map, func_body, result):
        """Detect state machine transitions from enum assignments."""
        # Look for: state = EnumName.Variant
        for var_name in written_vars:
            # Check if RHS is an enum member access
            expr_children = _children_by_type(assign_node, "expression")
            if len(expr_children) < 2:
                continue
            rhs = expr_children[1]
            rhs_members = _collect_member_expressions(rhs)
            for mem in rhs_members:
                ids = _children_by_type(mem, "identifier")
                if len(ids) >= 2:
                    enum_name = _text(ids[0])
                    to_state = _text(ids[1])
                    if enum_name in enum_map:
                        # Found a state transition! Now find from_state from require() calls
                        from_state = self._find_require_state(func_body, var_name, enum_name)
                        conditions = self._collect_require_conditions(func_body)
                        result.transitions.append({
                            "entity": enum_name,
                            "from_state": from_state,
                            "to_state": to_state,
                            "function_id": func_id,
                            "conditions": json.dumps(conditions),
                        })

    def _find_require_state(self, func_body, var_name, enum_name) -> str:
        """Find the from_state by looking for require(var == Enum.State) in the function."""
        # Walk all call expressions looking for require(state == EnumName.X)
        for call in _collect_calls(func_body):
            call_name = _get_call_name(call)
            if call_name != "require":
                continue
            # Look in arguments for binary_expression with == and our var_name
            call_text = _text(call)
            if var_name in call_text and enum_name in call_text:
                # Extract the variant from the member expression
                members = _collect_member_expressions(call)
                for mem in members:
                    ids = _children_by_type(mem, "identifier")
                    if len(ids) >= 2 and _text(ids[0]) == enum_name:
                        return _text(ids[1])
        return "*"  # No specific from_state found (unguarded transition)

    def _collect_require_conditions(self, func_body) -> list[str]:
        """Collect all require() call texts as conditions."""
        conditions = []
        for call in _collect_calls(func_body):
            call_name = _get_call_name(call)
            if call_name in ("require", "assert"):
                # Get first argument text
                args = _children_by_type(call, "call_argument")
                if args:
                    cond_text = _text(args[0]).strip()
                    if cond_text:
                        conditions.append(cond_text)
        return conditions
