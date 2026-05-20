"""C++ AST extraction using tree-sitter for knowledge graph construction."""

import json
import tree_sitter_cpp
from tree_sitter import Language, Parser
from core.web3 import ExtractResult
from core.web3.base import BaseExtractor


# H5: Dangerous C/C++ API patterns
DANGEROUS_APIS = {
    # Memory
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "sprintf", "gets", "scanf",
    # Allocation
    "malloc", "calloc", "realloc", "free",
    # Casts (these appear as keywords, detected separately)
    "reinterpret_cast", "const_cast", "dynamic_cast",
    # Other
    "system", "exec", "popen",
}

# Dangerous cast keywords that appear in tree-sitter as specific node types
DANGEROUS_CAST_KEYWORDS = {"reinterpret_cast", "const_cast", "dynamic_cast"}

# C security: API pattern sets for vulnerability detection
BUFFER_OVERFLOW_APIS = {"strcpy", "strncpy", "sprintf", "gets", "scanf", "memcpy", "memmove"}
FORMAT_STRING_APIS = {"printf", "fprintf", "sprintf", "snprintf", "syslog", "vprintf", "vfprintf"}
COMMAND_INJECTION_APIS = {"system", "exec", "execl", "execv", "execvp", "popen"}
ALLOC_APIS = {"malloc", "calloc", "realloc"}
TOCTOU_CHECK_APIS = {"access", "stat", "lstat", "fstat"}
TOCTOU_USE_APIS = {"open", "fopen", "freopen", "creat"}
PATH_APIS = {"fopen", "freopen", "open", "creat"}


def _get_parser():
    lang = Language(tree_sitter_cpp.language())
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
    if node.type in ("identifier", "field_identifier"):
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
    """Recursively collect assignment_expression nodes."""
    assigns = []
    if node is None:
        return assigns
    if node.type in ("assignment_expression", "augmented_assignment_expression"):
        assigns.append(node)
    for child in node.children:
        assigns.extend(_collect_assignments(child))
    return assigns


def _extract_param_names(func_node):
    """Extract parameter names from a function definition."""
    names = []
    params = _child_by_type(func_node, "parameter_list")
    if not params:
        # parameter_list may be inside function_declarator
        func_decl = _child_by_type(func_node, "function_declarator")
        if not func_decl:
            # For pointer return types, function_declarator is inside pointer_declarator
            ptr_decl = _child_by_type(func_node, "pointer_declarator")
            if ptr_decl:
                func_decl = _child_by_type(ptr_decl, "function_declarator")
        if func_decl:
            params = _child_by_type(func_decl, "parameter_list")
    if not params:
        return names
    for child in params.children:
        if child.type == "parameter_declaration":
            ident = None
            for sub in child.children:
                if sub.type == "identifier":
                    ident = _text(sub)
                elif sub.type == "pointer_declarator":
                    inner = _child_by_type(sub, "identifier")
                    if inner:
                        ident = _text(inner)
            if ident:
                names.append(ident)
    return names


def _collect_dangerous_calls(body_node):
    """Collect dangerous API calls from a function body.

    Returns a set of dangerous function/cast names found.
    """
    dangerous = set()
    if body_node is None:
        return dangerous

    # Check regular call expressions
    for call in _collect_calls(body_node):
        call_name = _get_call_name(call)
        if call_name and call_name in DANGEROUS_APIS:
            dangerous.add(call_name)

    # Check for dangerous casts (reinterpret_cast, const_cast, dynamic_cast)
    # These appear as specific expression types in tree-sitter
    _collect_cast_expressions(body_node, dangerous)

    # Also check for new/delete expressions
    _collect_new_delete(body_node, dangerous)

    return dangerous


def _collect_cast_expressions(node, dangerous):
    """Recursively find dangerous cast expressions."""
    if node is None:
        return
    # tree-sitter-cpp uses nodes like "cast_expression" but also has
    # specific types for C++ casts
    text = _text(node)
    for cast_kw in DANGEROUS_CAST_KEYWORDS:
        if cast_kw in text and node.type in (
            "cast_expression", "template_function",
            "call_expression", "expression_statement",
        ):
            # Only count once per cast keyword per body
            dangerous.add(cast_kw)
    # For more specific detection, check node text starting with cast keyword
    if node.type == "identifier" and _text(node) in DANGEROUS_CAST_KEYWORDS:
        dangerous.add(_text(node))
    for child in node.children:
        _collect_cast_expressions(child, dangerous)


def _collect_new_delete(node, dangerous):
    """Recursively find new/delete expressions."""
    if node is None:
        return
    if node.type == "new_expression":
        dangerous.add("new")
    elif node.type == "delete_expression":
        dangerous.add("delete")
    for child in node.children:
        _collect_new_delete(child, dangerous)


def _get_call_name(call_node):
    """Extract the function/method name from a call_expression."""
    func = _child_by_type(call_node, "identifier")
    if func:
        return _text(func)
    # Check for field_expression (obj.method()) or qualified_identifier
    field_expr = _child_by_type(call_node, "field_expression")
    if field_expr:
        field_id = _child_by_type(field_expr, "field_identifier")
        if field_id:
            return _text(field_id)
    # Check for qualified_identifier (namespace::func)
    qual = _child_by_type(call_node, "qualified_identifier")
    if qual:
        # Get the last identifier
        name = _child_by_type(qual, "identifier")
        if name:
            return _text(name)
    # Check template_function
    tmpl = _child_by_type(call_node, "template_function")
    if tmpl:
        name = _child_by_type(tmpl, "identifier")
        if name:
            return _text(name)
    return None


def _extract_declarator_name(declarator):
    """Extract the function/method name from a declarator chain.

    Handles: function_declarator -> identifier
             function_declarator -> field_identifier
             function_declarator -> destructor_name
             function_declarator -> qualified_identifier -> identifier
             function_declarator -> operator_name (C2: operator overloading)
             reference_declarator -> function_declarator -> ...
             pointer_declarator -> function_declarator -> ...
    """
    if declarator is None:
        return None, False

    is_destructor = False

    # Unwrap reference/pointer declarators
    while declarator.type in ("reference_declarator", "pointer_declarator"):
        inner = _child_by_type(declarator, "function_declarator")
        if inner:
            declarator = inner
            break
        inner = _child_by_type(declarator, "identifier")
        if inner:
            return _text(inner), False
        break

    if declarator.type == "function_declarator":
        # Check for destructor_name
        dtor = _child_by_type(declarator, "destructor_name")
        if dtor:
            ident = _child_by_type(dtor, "identifier")
            return ("~" + _text(ident)) if ident else _text(dtor), True

        # C2: Check for operator_name (operator+, operator==, etc.)
        op_name = _child_by_type(declarator, "operator_name")
        if op_name:
            return _text(op_name), False

        # C2: Check for operator_cast (conversion operators like operator int())
        op_cast = _child_by_type(declarator, "operator_cast")
        if op_cast:
            return _text(op_cast).split("(")[0].strip(), False

        # Check for qualified_identifier (e.g., ClassName::method)
        qual = _child_by_type(declarator, "qualified_identifier")
        if qual:
            # C2: Check for operator_name inside qualified_identifier
            op_name = _child_by_type(qual, "operator_name")
            if op_name:
                return _text(op_name), False
            ident = _child_by_type(qual, "identifier")
            if ident:
                return _text(ident), False

        # Direct identifier
        ident = _child_by_type(declarator, "identifier")
        if ident:
            return _text(ident), False

        field_id = _child_by_type(declarator, "field_identifier")
        if field_id:
            return _text(field_id), False

    if declarator.type == "identifier":
        return _text(declarator), False

    return None, False


def _extract_param_types(func_node):
    """Extract parameter type names from a function_definition.

    Returns a comma-separated string of type names.
    """
    declarator = _child_by_type(func_node, "function_declarator")
    if not declarator:
        declarator = _child_by_type(func_node, "declarator")
        if declarator:
            declarator = _child_by_type(declarator, "function_declarator")
    if not declarator:
        return ""
    param_list = _child_by_type(declarator, "parameter_list")
    if not param_list:
        return ""
    types = []
    for p in param_list.children:
        if p.type == "parameter_declaration":
            type_node = _child_by_type(p, "type_identifier")
            if type_node:
                types.append(_text(type_node))
            else:
                # Try primitive type or qualified_identifier
                prim = _child_by_type(p, "primitive_type")
                if prim:
                    types.append(_text(prim))
                else:
                    # Fallback: use the full text minus the declarator
                    decl = _child_by_type(p, "identifier") or _child_by_type(p, "reference_declarator")
                    full = _text(p)
                    if decl:
                        type_text = full[:full.rfind(_text(decl))].strip()
                        types.append(type_text if type_text else full)
                    else:
                        types.append(full.strip())
        elif p.type == "optional_parameter_declaration":
            type_node = _child_by_type(p, "type_identifier")
            if type_node:
                types.append(_text(type_node))
            else:
                prim = _child_by_type(p, "primitive_type")
                types.append(_text(prim) if prim else "")
    return ",".join(types)


def _has_specifier(func_node, specifier_text):
    """Check if a function_definition has a given specifier (virtual, static, etc.)."""
    for child in func_node.children:
        if child.type == "virtual" or (child.type == "virtual_specifier" and _text(child) == specifier_text):
            return True
        if child.type in ("type_qualifier", "storage_class_specifier") and _text(child) == specifier_text:
            return True
        # Check in the text before the body
        if _text(child).strip() == specifier_text:
            return True
    return False


def _is_virtual(func_node):
    """Check if a function_definition has the 'virtual' keyword."""
    full_text = _text(func_node)
    # virtual appears before the return type
    prefix = full_text.split("{")[0] if "{" in full_text else full_text.split(";")[0]
    tokens = prefix.split()
    return "virtual" in tokens


def _is_override(func_node):
    """Check if a function_definition has the 'override' keyword."""
    # override appears after the parameter list, before the body
    full_text = _text(func_node)
    prefix = full_text.split("{")[0] if "{" in full_text else full_text.split(";")[0]
    return "override" in prefix.split()


def _is_const_method(func_node):
    """H1: Check if a method has the 'const' qualifier after the parameter list."""
    full_text = _text(func_node)
    # const appears after closing paren and before opening brace or semicolon
    prefix = full_text.split("{")[0] if "{" in full_text else full_text.split(";")[0]
    # Find the last ')' and check if 'const' follows
    last_paren = prefix.rfind(")")
    if last_paren >= 0:
        after_paren = prefix[last_paren + 1:]
        return "const" in after_paren.split()
    return False


def _is_static_member(node):
    """C5: Check if a node (field_declaration or function_definition) has 'static' storage class."""
    for child in node.children:
        if child.type == "storage_class_specifier" and _text(child) == "static":
            return True
    return False


def _is_scoped_enum(node):
    """C4: Check if an enum_specifier uses 'enum class' (scoped) or plain 'enum'."""
    # In tree-sitter-cpp, 'enum class' has a 'class' child token
    full_text = _text(node)
    # Check for 'enum class' or 'enum struct'
    prefix = full_text.split("{")[0] if "{" in full_text else full_text.split(";")[0]
    tokens = prefix.split()
    if "class" in tokens or "struct" in tokens:
        return True
    return False


def _extract_template_params(template_node):
    """H3: Extract template parameter list text from a template_declaration."""
    param_list = _child_by_type(template_node, "template_parameter_list")
    if param_list:
        return _text(param_list)
    return None


def _build_qualified_name(*parts):
    """Build a qualified name from parts, skipping empty ones."""
    return "::".join(p for p in parts if p)


class CppExtractor(BaseExtractor):

    def __init__(self):
        self.parser = _get_parser()

    def extract_from_source(self, source_code: bytes, file_path: str) -> ExtractResult:
        """Parse source and extract."""
        tree = self.parser.parse(source_code)
        return self.extract(tree, source_code, file_path)

    def extract(self, tree, source_code: bytes, file_path: str) -> ExtractResult:
        result = ExtractResult()
        root = tree.root_node

        # Global context
        ctx = _ExtractContext(file_path)

        self._walk_children(root.children, file_path, result, ctx, namespace="", class_name="",
                            template_params=None)

        # Second pass: build call, read, write edges
        self._build_body_edges(result, ctx)

        return result

    def _walk_children(self, children, file_path, result, ctx, namespace, class_name,
                       template_params=None):
        """Walk a list of AST children, extracting nodes and edges."""
        current_access = "private" if class_name else "public"

        for child in children:
            if child.type == "access_specifier":
                # Update access level: text is like "public:"
                access_text = _text(child).rstrip(":").strip()
                if access_text in ("public", "protected", "private"):
                    current_access = access_text

            elif child.type == "namespace_definition":
                self._extract_namespace(child, file_path, result, ctx, namespace)

            elif child.type == "class_specifier":
                self._extract_class_or_struct(
                    child, file_path, result, ctx, namespace, "class", current_access,
                    template_params=template_params,
                )

            elif child.type == "struct_specifier":
                self._extract_class_or_struct(
                    child, file_path, result, ctx, namespace, "struct", current_access,
                    template_params=template_params,
                )

            elif child.type == "enum_specifier":
                self._extract_enum(child, file_path, result, ctx, namespace, class_name)

            elif child.type == "function_definition":
                self._extract_function(
                    child, file_path, result, ctx, namespace, class_name, current_access,
                    template_params=template_params,
                )

            elif child.type == "field_declaration":
                self._extract_field(
                    child, file_path, result, ctx, namespace, class_name, current_access
                )

            elif child.type == "declaration":
                # Could contain class/struct/enum specifiers or variable declarations
                self._extract_declaration(child, file_path, result, ctx, namespace, class_name,
                                          current_access)

            elif child.type == "template_declaration":
                # H3: Extract template params and pass them to inner definitions
                tpl_params = _extract_template_params(child)
                self._walk_children(child.children, file_path, result, ctx, namespace, class_name,
                                    template_params=tpl_params)

            # C1: alias_declaration (using X = Y)
            elif child.type in ("type_alias_declaration", "alias_declaration"):
                self._extract_type_alias(child, file_path, result, ctx, namespace, class_name)

            # C3: friend_declaration
            elif child.type == "friend_declaration":
                self._extract_friend(child, file_path, result, ctx, namespace, class_name)

    def _extract_declaration(self, node, file_path, result, ctx, namespace, class_name,
                             current_access):
        """Extract a declaration node which may contain nested types or typedefs."""
        for sub in node.children:
            if sub.type in ("class_specifier", "struct_specifier"):
                kind = "class" if sub.type == "class_specifier" else "struct"
                self._extract_class_or_struct(
                    sub, file_path, result, ctx, namespace, kind, current_access
                )
            elif sub.type == "enum_specifier":
                self._extract_enum(sub, file_path, result, ctx, namespace, class_name)

        # C1: Check if this is a typedef (type_definition)
        # tree-sitter-cpp: typedef int MyInt; -> type_definition node
        # But it can also appear as a declaration with "typedef" storage_class_specifier
        if node.type == "type_definition":
            self._extract_typedef(node, file_path, result, ctx, namespace, class_name)

    def _extract_namespace(self, node, file_path, result, ctx, parent_ns):
        """Extract a namespace_definition node."""
        name_node = _child_by_type(node, "namespace_identifier") or _child_by_type(node, "identifier")
        ns_name = _text(name_node) if name_node else ""
        qualified = _build_qualified_name(parent_ns, ns_name) if ns_name else parent_ns

        if ns_name:
            ns_id = self._make_node_id(file_path, qualified)
            result.nodes.append({
                "id": ns_id, "label": ns_name, "type": "namespace",
                "file": file_path, "visibility": "public",
                "line_start": node.start_point[0] + 1,
                "line_end": node.end_point[0] + 1,
                "signature": f"namespace {qualified}",
                "metadata": json.dumps({"namespace": parent_ns}),
            })

        body = _child_by_type(node, "declaration_list")
        if body:
            self._walk_children(body.children, file_path, result, ctx, qualified, class_name="")

    def _extract_class_or_struct(self, node, file_path, result, ctx, namespace, kind, outer_access,
                                 template_params=None):
        """Extract a class_specifier or struct_specifier."""
        name_node = _child_by_type(node, "name") or _child_by_type(node, "type_identifier")
        if not name_node:
            return
        class_name = _text(name_node)
        qualified = _build_qualified_name(namespace, class_name)
        class_id = self._make_node_id(file_path, qualified)

        meta = {"namespace": namespace}
        # H3: template params
        if template_params:
            meta["template_params"] = template_params

        result.nodes.append({
            "id": class_id, "label": class_name, "type": kind,
            "file": file_path, "visibility": outer_access,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"{kind} {qualified}",
            "metadata": json.dumps(meta),
        })

        # Namespace contains class
        if namespace:
            ns_id = self._make_node_id(file_path, namespace)
            result.edges.append({
                "source": ns_id, "target": class_id,
                "relation": "contains", "attributes": "{}",
            })

        # H4: Inheritance with access specifier and virtual
        base_clause = _child_by_type(node, "base_class_clause")
        if base_clause:
            self._extract_inheritance(base_clause, class_id, namespace, file_path, result)

        # Walk body
        body = _child_by_type(node, "field_declaration_list")
        if body:
            # Default access: private for class, public for struct
            default_access = "private" if kind == "class" else "public"
            ctx.class_member_fields[qualified] = set()
            self._walk_class_body(body, file_path, result, ctx, namespace, qualified, class_name, default_access)

    def _extract_inheritance(self, base_clause, class_id, namespace, file_path, result):
        """H4: Extract base classes with access specifier and virtual keyword."""
        # Walk children to find base class specifiers
        # Structure: base_class_clause -> [virtual] [access_specifier] type_identifier
        # We need to track the current access and virtual for each base class
        current_access = None
        current_virtual = False

        for bc_child in base_clause.children:
            if bc_child.type == "access_specifier" or _text(bc_child) in ("public", "protected", "private"):
                current_access = _text(bc_child).rstrip(":").strip()
            elif _text(bc_child) == "virtual":
                current_virtual = True
            elif bc_child.type == "type_identifier":
                base_name = _text(bc_child)
                base_qualified = _build_qualified_name(namespace, base_name)
                base_id = self._make_node_id(file_path, base_qualified)
                attrs = {
                    "base_class": base_name,
                    "access": current_access or "private",
                    "virtual": current_virtual,
                }
                result.edges.append({
                    "source": class_id, "target": base_id,
                    "relation": "inherits",
                    "attributes": json.dumps(attrs),
                })
                # Reset for next base class
                current_access = None
                current_virtual = False

    def _walk_class_body(self, body, file_path, result, ctx, namespace, qualified_class, class_name, default_access):
        """Walk the field_declaration_list of a class/struct."""
        current_access = default_access

        for child in body.children:
            if child.type == "access_specifier":
                access_text = _text(child).rstrip(":").strip()
                if access_text in ("public", "protected", "private"):
                    current_access = access_text

            elif child.type == "function_definition":
                self._extract_function(
                    child, file_path, result, ctx, namespace, qualified_class, current_access
                )

            elif child.type == "field_declaration":
                self._extract_field(
                    child, file_path, result, ctx, namespace, qualified_class, current_access
                )

            elif child.type == "declaration":
                # Nested types
                self._extract_declaration(child, file_path, result, ctx, namespace,
                                          qualified_class, current_access)

            elif child.type == "template_declaration":
                # H3: Template members - extract params and pass through
                tpl_params = _extract_template_params(child)
                for sub in child.children:
                    if sub.type == "function_definition":
                        self._extract_function(
                            sub, file_path, result, ctx, namespace, qualified_class, current_access,
                            template_params=tpl_params,
                        )
                    elif sub.type in ("class_specifier", "struct_specifier"):
                        kind = "class" if sub.type == "class_specifier" else "struct"
                        self._extract_class_or_struct(
                            sub, file_path, result, ctx, qualified_class, kind, current_access,
                            template_params=tpl_params,
                        )

            # C1: alias_declaration (using X = Y) inside class
            elif child.type in ("type_alias_declaration", "alias_declaration"):
                self._extract_type_alias(child, file_path, result, ctx, namespace, qualified_class)

            # C3: friend_declaration inside class
            elif child.type == "friend_declaration":
                self._extract_friend(child, file_path, result, ctx, namespace, qualified_class)

            # C1: typedef inside class body
            elif child.type == "type_definition":
                self._extract_typedef(child, file_path, result, ctx, namespace, qualified_class)

    def _detect_c_security_patterns(self, body_node, meta, params):
        """Detect C/C++ security vulnerability patterns in a function body.

        Populates meta dict with risk fields: buffer_overflow_risk,
        format_string_risk, command_injection_risk, use_after_free_risk,
        double_free_risk, null_deref_risk, integer_overflow_risk,
        toctou_risk, path_traversal_risk, uninitialized_use.

        Each field is a list of {"line": int, "detail": str}.
        """
        if body_node is None:
            return

        # Collect all calls with positions
        calls = _collect_calls(body_node)
        call_infos = []
        for c in calls:
            name = _get_call_name(c)
            if name:
                line = c.start_point[0] + 1
                arg_list = _child_by_type(c, "argument_list")
                args = []
                if arg_list:
                    args = [ch for ch in arg_list.children
                            if ch.type not in ("(", ")", ",", "comment")]
                call_infos.append({"name": name, "line": line, "node": c, "args": args})

        param_names = set(params) if params else set()

        # --- 1. Buffer overflow ---
        buf_risks = []
        for ci in call_infos:
            if ci["name"] in BUFFER_OVERFLOW_APIS:
                if ci["name"] == "gets":
                    buf_risks.append({"line": ci["line"], "detail": "gets() always unsafe"})
                elif ci["name"] == "strcpy":
                    buf_risks.append({"line": ci["line"], "detail": "strcpy() no bounds check"})
                elif ci["name"] == "sprintf":
                    buf_risks.append({"line": ci["line"], "detail": "sprintf() no bounds check"})
                elif ci["name"] == "strncpy":
                    buf_risks.append({"line": ci["line"], "detail": "strncpy() no guaranteed null termination"})
                elif ci["name"] in ("memcpy", "memmove") and len(ci["args"]) >= 3:
                    size_arg = ci["args"][2]
                    if size_arg.type != "number_literal":
                        buf_risks.append({"line": ci["line"],
                                          "detail": f"{ci['name']}() variable size"})
                elif ci["name"] == "scanf" and ci["args"]:
                    fmt_text = _text(ci["args"][0])
                    if "%s" in fmt_text and "%*s" not in fmt_text:
                        buf_risks.append({"line": ci["line"],
                                          "detail": "scanf() unbounded %s"})
        if buf_risks:
            meta["buffer_overflow_risk"] = buf_risks

        # --- 2. Format string ---
        fmt_risks = []
        for ci in call_infos:
            if ci["name"] in FORMAT_STRING_APIS and ci["args"]:
                fmt_idx = 0
                if ci["name"] in ("fprintf", "vfprintf", "sprintf", "snprintf") and len(ci["args"]) > 1:
                    fmt_idx = 1
                if ci["name"] == "snprintf" and len(ci["args"]) > 2:
                    fmt_idx = 2
                if fmt_idx < len(ci["args"]):
                    fmt_arg = ci["args"][fmt_idx]
                    if fmt_arg.type != "string_literal":
                        fmt_risks.append({"line": ci["line"],
                                          "detail": f"{ci['name']}() variable format"})
        if fmt_risks:
            meta["format_string_risk"] = fmt_risks

        # --- 3. Command injection ---
        cmd_risks = []
        for ci in call_infos:
            if ci["name"] in COMMAND_INJECTION_APIS and ci["args"]:
                first_arg = ci["args"][0]
                if first_arg.type != "string_literal":
                    cmd_risks.append({"line": ci["line"],
                                      "detail": f"{ci['name']}() variable command"})
        if cmd_risks:
            meta["command_injection_risk"] = cmd_risks

        # --- 4/5. Use-after-free and double-free ---
        uaf_risks = []
        df_risks = []
        freed_ptrs = {}
        self._walk_for_uaf(body_node, freed_ptrs, uaf_risks, df_risks)
        if uaf_risks:
            meta["use_after_free_risk"] = uaf_risks
        if df_risks:
            meta["double_free_risk"] = df_risks

        # --- 6. Null deref ---
        null_risks = []
        self._walk_for_null_deref(body_node, null_risks)
        if null_risks:
            meta["null_deref_risk"] = null_risks

        # --- 7. TOCTOU ---
        toctou_risks = []
        check_args = {}
        for ci in call_infos:
            if ci["name"] in TOCTOU_CHECK_APIS and ci["args"]:
                arg_text = _text(ci["args"][0])
                check_args[arg_text] = ci["line"]
            elif ci["name"] in TOCTOU_USE_APIS and ci["args"]:
                arg_text = _text(ci["args"][0])
                if arg_text in check_args:
                    toctou_risks.append({"line": ci["line"],
                                         "detail": f"check({check_args[arg_text]})->use({ci['line']}) on {arg_text}"})
        if toctou_risks:
            meta["toctou_risk"] = toctou_risks

        # --- 8. Path traversal ---
        path_risks = []
        for ci in call_infos:
            if ci["name"] in PATH_APIS and ci["args"]:
                path_arg = ci["args"][0]
                if path_arg.type != "string_literal":
                    path_ids = _collect_identifiers(path_arg)
                    if path_ids & param_names:
                        path_risks.append({"line": ci["line"],
                                           "detail": f"{ci['name']}() param-derived path"})
        if path_risks:
            meta["path_traversal_risk"] = path_risks

        # --- 9. Integer overflow in alloc ---
        int_risks = []
        for ci in call_infos:
            if ci["name"] in ALLOC_APIS and ci["args"]:
                size_idx = 0
                if ci["name"] == "calloc" and len(ci["args"]) >= 2:
                    size_idx = 0
                size_arg = ci["args"][size_idx]
                if size_arg.type == "binary_expression":
                    arg_ids = _collect_identifiers(size_arg)
                    if arg_ids & param_names:
                        int_risks.append({"line": ci["line"],
                                          "detail": f"{ci['name']}() arithmetic on param in size"})
        if int_risks:
            meta["integer_overflow_risk"] = int_risks

        # --- 10. Uninitialized use ---
        uninit_risks = []
        self._walk_for_uninit(body_node, uninit_risks)
        if uninit_risks:
            meta["uninitialized_use"] = uninit_risks

    def _walk_for_uaf(self, node, freed_ptrs, uaf_risks, df_risks):
        """Walk AST linearly tracking free/use/reassign for UAF and double-free."""
        if node is None:
            return
        for child in node.children:
            if child.type == "expression_statement":
                expr = child.children[0] if child.children else None
                if expr and expr.type == "call_expression":
                    call_name = _get_call_name(expr)
                    if call_name == "free":
                        arg_list = _child_by_type(expr, "argument_list")
                        if arg_list:
                            args = [c for c in arg_list.children
                                    if c.type not in ("(", ")", ",")]
                            if args:
                                ptr_name = _text(args[0])
                                line = child.start_point[0] + 1
                                if ptr_name in freed_ptrs:
                                    df_risks.append({"line": line,
                                                     "detail": f"double free of {ptr_name}"})
                                else:
                                    freed_ptrs[ptr_name] = line
                        continue

                if expr and expr.type == "assignment_expression" and expr.children:
                    lhs = _text(expr.children[0])
                    if lhs in freed_ptrs:
                        del freed_ptrs[lhs]
                    continue

            if child.type == "declaration":
                init_decl = _child_by_type(child, "init_declarator")
                if init_decl:
                    init_ids = _collect_identifiers(init_decl)
                    var_node = _child_by_type(init_decl, "identifier")
                    if not var_node:
                        ptr_decl = _child_by_type(init_decl, "pointer_declarator")
                        if ptr_decl:
                            var_node = _child_by_type(ptr_decl, "identifier")
                    declared_name = _text(var_node) if var_node else None
                    for uid in init_ids:
                        if uid != declared_name and uid in freed_ptrs:
                            uaf_risks.append({"line": child.start_point[0] + 1,
                                              "detail": f"use of {uid} after free at line {freed_ptrs[uid]}"})
                    if declared_name and declared_name in freed_ptrs:
                        del freed_ptrs[declared_name]
                continue

            if freed_ptrs and child.type not in ("compound_statement",):
                used_ids = _collect_identifiers(child)
                for uid in used_ids:
                    if uid in freed_ptrs:
                        uaf_risks.append({"line": child.start_point[0] + 1,
                                          "detail": f"use of {uid} after free at line {freed_ptrs[uid]}"})

            if child.type == "compound_statement":
                self._walk_for_uaf(child, freed_ptrs, uaf_risks, df_risks)

    def _walk_for_null_deref(self, body_node, null_risks):
        """Detect malloc/calloc/realloc without NULL check before use."""
        for child in body_node.children:
            if child.type != "declaration":
                continue
            init_decl = _child_by_type(child, "init_declarator")
            if not init_decl:
                continue
            rhs_calls = _collect_calls(init_decl)
            is_alloc = False
            for rc in rhs_calls:
                if _get_call_name(rc) in ALLOC_APIS:
                    is_alloc = True
                    break
            if not is_alloc:
                continue

            var_node = _child_by_type(init_decl, "identifier")
            if not var_node:
                ptr_decl = _child_by_type(init_decl, "pointer_declarator")
                if ptr_decl:
                    var_node = _child_by_type(ptr_decl, "identifier")
            if not var_node:
                continue
            var_name = _text(var_node)

            line = child.start_point[0] + 1
            siblings = list(body_node.children)
            idx = siblings.index(child)
            has_null_check = False
            has_use_before_check = False

            for sib in siblings[idx + 1:]:
                sib_text = _text(sib)
                if sib.type == "if_statement":
                    cond_text = sib_text.split("{")[0] if "{" in sib_text else sib_text
                    if var_name in cond_text and ("NULL" in cond_text or "nullptr" in cond_text
                                                   or f"!{var_name}" in cond_text
                                                   or f"! {var_name}" in cond_text):
                        has_null_check = True
                        break
                if var_name in sib_text and sib.type != "if_statement":
                    has_use_before_check = True
                    break

            if has_use_before_check and not has_null_check:
                null_risks.append({"line": line,
                                   "detail": f"{var_name} from alloc used without NULL check"})

    def _walk_for_uninit(self, body_node, uninit_risks):
        """Best-effort detection of uninitialized local variable use."""
        if body_node is None:
            return
        uninit_vars = {}
        children = list(body_node.children)
        for i, child in enumerate(children):
            if child.type == "declaration":
                init_decl = _child_by_type(child, "init_declarator")
                if init_decl:
                    continue
                ident = _child_by_type(child, "identifier")
                if ident:
                    uninit_vars[_text(ident)] = child.start_point[0] + 1
                continue

            if not uninit_vars:
                continue

            if child.type == "expression_statement":
                expr = child.children[0] if child.children else None
                if expr and expr.type == "assignment_expression" and expr.children:
                    lhs = _text(expr.children[0])
                    if lhs in uninit_vars:
                        del uninit_vars[lhs]
                        continue
            used_ids = _collect_identifiers(child)
            for uid in used_ids:
                if uid in uninit_vars:
                    uninit_risks.append({"line": child.start_point[0] + 1,
                                         "detail": f"{uid} used before assignment (declared line {uninit_vars[uid]})"})
                    del uninit_vars[uid]

    def _extract_function(self, node, file_path, result, ctx, namespace, class_name, access,
                          template_params=None):
        """Extract a function_definition node (method or free function)."""
        declarator = _child_by_type(node, "function_declarator")
        if not declarator:
            # May be wrapped in another declarator type
            for child in node.children:
                if child.type in ("function_declarator", "reference_declarator", "pointer_declarator"):
                    declarator = child
                    break
        if not declarator:
            return

        func_name, is_destructor = _extract_declarator_name(declarator)
        if not func_name:
            return

        # Determine if this is a constructor
        is_constructor = False
        if class_name:
            bare_class = class_name.split("::")[-1]
            if func_name == bare_class:
                is_constructor = True

        virtual = _is_virtual(node)
        override = _is_override(node)
        # H1: const method detection
        const_method = _is_const_method(node) if class_name else False
        # C5: static member detection
        static = _is_static_member(node)

        # Build qualified name
        if class_name:
            qualified = _build_qualified_name(class_name, func_name)
        else:
            qualified = _build_qualified_name(namespace, func_name)

        param_types = _extract_param_types(node)
        func_id = self._make_node_id(file_path, qualified, param_types)

        node_type = "constructor" if is_constructor else "function"
        visibility = access if class_name else "public"

        # Build signature
        full_text = _text(node)
        sig_text = full_text.split("{")[0].strip() if "{" in full_text else full_text.split(";")[0].strip()
        # Truncate overly long signatures
        if len(sig_text) > 200:
            sig_text = sig_text[:200] + "..."

        meta = {}
        if namespace:
            meta["namespace"] = namespace
        if class_name:
            meta["class"] = class_name
        if virtual:
            meta["virtual"] = True
        if override:
            meta["override"] = True
        if is_destructor:
            meta["destructor"] = True
        if const_method:
            meta["const"] = True
        if static:
            meta["static"] = True
        if template_params:
            meta["template_params"] = template_params

        # H5: Dangerous API detection (computed now, stored in meta)
        body = _child_by_type(node, "compound_statement")
        dangerous = _collect_dangerous_calls(body)
        if dangerous:
            meta["dangerous_calls"] = sorted(dangerous)

        # C security pattern detection
        if body:
            param_names = _extract_param_names(node)
            self._detect_c_security_patterns(body, meta, param_names)

        result.nodes.append({
            "id": func_id, "label": func_name, "type": node_type,
            "file": file_path, "visibility": visibility,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": sig_text,
            "metadata": json.dumps(meta),
        })

        # contains edge from class
        if class_name:
            class_id = self._make_node_id(file_path, class_name)
            result.edges.append({
                "source": class_id, "target": func_id,
                "relation": "contains", "attributes": "{}",
            })
        elif namespace:
            ns_id = self._make_node_id(file_path, namespace)
            result.edges.append({
                "source": ns_id, "target": func_id,
                "relation": "contains", "attributes": "{}",
            })

        # Register for body-edge pass
        ctx.func_registry[func_id] = {
            "name": func_name,
            "class": class_name,
            "namespace": namespace,
            "ts_node": node,
            "body_node": body,
        }
        ctx.func_ts_map[node.id] = func_id
        # Also register by short name for call resolution
        ctx.func_by_name.setdefault(func_name, []).append(func_id)

    def _extract_field(self, node, file_path, result, ctx, namespace, class_name, access):
        """Extract a field_declaration (member variable)."""
        if not class_name:
            return

        # Skip if this looks like a function declaration (has parameter_list descendant
        # but no compound_statement - i.e., a declaration not a definition)
        text = _text(node)

        # Find the field name - it's typically in a field_identifier or the last identifier
        field_id_node = _child_by_type(node, "field_identifier")
        name = None

        if field_id_node:
            name = _text(field_id_node)
        else:
            # Look for identifier in declarator patterns
            for child in node.children:
                if child.type == "field_identifier":
                    name = _text(child)
                    break
                if child.type == "identifier":
                    name = _text(child)
                    # Don't break - might find field_identifier later

        if not name:
            # Try to find from init_declarator or other patterns
            init_decl = _child_by_type(node, "init_declarator")
            if init_decl:
                ident = _child_by_type(init_decl, "identifier")
                if ident:
                    name = _text(ident)

        if not name:
            return

        # Skip if this is actually a function declaration (method prototype)
        if "(" in text and ")" in text:
            # Heuristic: if there's a parameter_list but no compound_statement, skip
            # unless it's a function pointer type member like std::function<...>
            if "std::function" not in text and "function" not in text.split("(")[0]:
                # Check if this looks like a method declaration
                for child in node.children:
                    if child.type == "function_declarator":
                        return

        qualified = _build_qualified_name(class_name, name)
        var_id = self._make_node_id(file_path, qualified)

        # Get type text
        type_text = ""
        for child in node.children:
            if child.type in ("type_identifier", "primitive_type", "sized_type_specifier",
                              "template_type", "qualified_identifier"):
                type_text = _text(child)
                break

        # C5: static member detection
        static = _is_static_member(node)

        meta = {"class": class_name, "type_text": type_text}
        if static:
            meta["static"] = True

        result.nodes.append({
            "id": var_id, "label": name, "type": "state_var",
            "file": file_path, "visibility": access,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": type_text,
            "metadata": json.dumps(meta),
        })

        # contains edge from class
        class_id = self._make_node_id(file_path, class_name)
        result.edges.append({
            "source": class_id, "target": var_id,
            "relation": "contains", "attributes": "{}",
        })

        # Register field name for read/write detection
        ctx.class_member_fields.setdefault(class_name, set()).add(name)

    def _extract_enum(self, node, file_path, result, ctx, namespace, class_name):
        """Extract an enum_specifier."""
        name_node = _child_by_type(node, "name") or _child_by_type(node, "type_identifier")
        if not name_node:
            return
        enum_name = _text(name_node)

        container = class_name or namespace
        qualified = _build_qualified_name(container, enum_name) if container else enum_name
        enum_id = self._make_node_id(file_path, qualified)

        # C4: Determine if scoped enum
        scoped = _is_scoped_enum(node)

        meta = {"namespace": namespace, "scoped": scoped}

        result.nodes.append({
            "id": enum_id, "label": enum_name, "type": "enum",
            "file": file_path, "visibility": "public",
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"enum {qualified}",
            "metadata": json.dumps(meta),
        })

        # contains edge from container
        if container:
            container_id = self._make_node_id(file_path, container)
            result.edges.append({
                "source": container_id, "target": enum_id,
                "relation": "contains", "attributes": "{}",
            })

        # Extract enumerator values
        body = _child_by_type(node, "enumerator_list")
        if body:
            variants = []
            for child in body.children:
                if child.type == "enumerator":
                    ename_node = _child_by_type(child, "identifier")
                    if ename_node:
                        ename = _text(ename_node)
                        variants.append(ename)
                        eval_qualified = _build_qualified_name(qualified, ename)
                        eval_id = self._make_node_id(file_path, eval_qualified)
                        result.nodes.append({
                            "id": eval_id, "label": ename, "type": "enumerator",
                            "file": file_path, "visibility": "public",
                            "line_start": child.start_point[0] + 1,
                            "line_end": child.end_point[0] + 1,
                            "signature": ename,
                            "metadata": json.dumps({"enum": qualified}),
                        })
                        result.edges.append({
                            "source": enum_id, "target": eval_id,
                            "relation": "contains", "attributes": "{}",
                        })
            ctx.enum_variants[qualified] = variants

    def _extract_type_alias(self, node, file_path, result, ctx, namespace, class_name):
        """C1: Extract a type_alias_declaration (using X = Y)."""
        # type_alias_declaration: using <type_identifier> = <type>
        name_node = _child_by_type(node, "type_identifier")
        if not name_node:
            return
        alias_name = _text(name_node)

        # Get the aliased type - everything after '='
        full_text = _text(node)
        eq_pos = full_text.find("=")
        aliased_type = full_text[eq_pos + 1:].rstrip(";").strip() if eq_pos >= 0 else ""

        container = class_name or namespace
        qualified = _build_qualified_name(container, alias_name) if container else alias_name
        alias_id = self._make_node_id(file_path, qualified)

        meta = {"aliased_type": aliased_type}
        if namespace:
            meta["namespace"] = namespace
        if class_name:
            meta["class"] = class_name

        result.nodes.append({
            "id": alias_id, "label": alias_name, "type": "type_alias",
            "file": file_path, "visibility": "public",
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": full_text.rstrip(";").strip(),
            "metadata": json.dumps(meta),
        })

        # contains edge from container
        if container:
            container_id = self._make_node_id(file_path, container)
            result.edges.append({
                "source": container_id, "target": alias_id,
                "relation": "contains", "attributes": "{}",
            })

    def _extract_typedef(self, node, file_path, result, ctx, namespace, class_name):
        """C1: Extract a type_definition (typedef)."""
        # typedef <type> <declarator>;
        # The declarator name is typically the last identifier or type_identifier
        full_text = _text(node)

        # Find the typedef name - it's typically the last type_identifier or identifier
        name = None
        for child in reversed(node.children):
            if child.type == "type_identifier":
                name = _text(child)
                break
            if child.type == "identifier":
                name = _text(child)
                break

        if not name:
            return

        # Get the aliased type text (everything between 'typedef' and the name)
        aliased_type = full_text.replace("typedef", "", 1).rstrip(";").strip()
        # Remove the name from the end
        if aliased_type.endswith(name):
            aliased_type = aliased_type[:-len(name)].strip()

        container = class_name or namespace
        qualified = _build_qualified_name(container, name) if container else name
        alias_id = self._make_node_id(file_path, qualified)

        meta = {"aliased_type": aliased_type}
        if namespace:
            meta["namespace"] = namespace
        if class_name:
            meta["class"] = class_name

        result.nodes.append({
            "id": alias_id, "label": name, "type": "type_alias",
            "file": file_path, "visibility": "public",
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": full_text.rstrip(";").strip(),
            "metadata": json.dumps(meta),
        })

        if container:
            container_id = self._make_node_id(file_path, container)
            result.edges.append({
                "source": container_id, "target": alias_id,
                "relation": "contains", "attributes": "{}",
            })

    def _extract_friend(self, node, file_path, result, ctx, namespace, class_name):
        """C3: Extract a friend_declaration and create a friend edge."""
        if not class_name:
            return

        class_id = self._make_node_id(file_path, class_name)

        # friend class Foo; -> has a type_identifier child
        # friend void foo(); -> has a function_declarator child
        friend_type = _child_by_type(node, "type_identifier")
        if friend_type:
            friend_name = _text(friend_type)
            friend_qualified = _build_qualified_name(namespace, friend_name)
            friend_id = self._make_node_id(file_path, friend_qualified)
            result.edges.append({
                "source": class_id, "target": friend_id,
                "relation": "friend",
                "attributes": json.dumps({"friend": friend_name}),
            })
            return

        # friend function: look for function declarator
        func_decl = _child_by_type(node, "function_declarator")
        if func_decl:
            fname, _ = _extract_declarator_name(func_decl)
            if fname:
                friend_qualified = _build_qualified_name(namespace, fname)
                friend_id = self._make_node_id(file_path, friend_qualified)
                result.edges.append({
                    "source": class_id, "target": friend_id,
                    "relation": "friend",
                    "attributes": json.dumps({"friend": fname}),
                })
            return

        # Fallback: extract name from text
        full_text = _text(node)
        # Try to find "friend class X" or "friend struct X" pattern
        for keyword in ("class", "struct"):
            if f"friend {keyword}" in full_text:
                parts = full_text.split(keyword, 1)
                if len(parts) > 1:
                    friend_name = parts[1].strip().rstrip(";").strip()
                    if friend_name:
                        friend_qualified = _build_qualified_name(namespace, friend_name)
                        friend_id = self._make_node_id(file_path, friend_qualified)
                        result.edges.append({
                            "source": class_id, "target": friend_id,
                            "relation": "friend",
                            "attributes": json.dumps({"friend": friend_name}),
                        })
                return

    def _build_body_edges(self, result, ctx):
        """Second pass: walk function bodies to build call/read/write edges.

        H2: Fixed reads_state over-reporting by computing write set first.
        """
        for func_id, info in ctx.func_registry.items():
            body = info["body_node"]
            if not body:
                continue

            class_name = info["class"]
            member_fields = ctx.class_member_fields.get(class_name, set()) if class_name else set()

            # H2: Compute write set first
            write_only_fields = set()
            all_written_fields = set()
            for assign in _collect_assignments(body):
                lhs_ids = set()
                if assign.children:
                    lhs_ids = _collect_identifiers(assign.children[0])
                written = lhs_ids & member_fields
                all_written_fields |= written

            # Collect all identifiers
            all_ids = _collect_identifiers(body)
            read_fields = all_ids & member_fields

            # H2: Determine write-only fields: fields that appear ONLY in
            # assignment LHS (not read in any other context)
            # A field is write-only if it appears in assignments but all its
            # appearances in the body are on the LHS of assignments
            for field_name in all_written_fields:
                # Check if this field is ever read (appears outside of assignment LHS)
                # Simple heuristic: count total appearances vs LHS appearances
                # If a field is in both all_ids and all_written_fields, it could
                # be read AND written. We only suppress reads_state for fields
                # that appear exclusively as assignment targets.
                is_read_anywhere = self._field_is_read(body, field_name, member_fields)
                if not is_read_anywhere:
                    write_only_fields.add(field_name)

            # reads_state edges (excluding write-only fields)
            for field_name in read_fields - write_only_fields:
                field_id = self._make_node_id(
                    ctx.file_path, _build_qualified_name(class_name, field_name)
                )
                result.edges.append({
                    "source": func_id, "target": field_id,
                    "relation": "reads_state", "attributes": "{}",
                })

            # writes_state edges
            for field_name in all_written_fields:
                field_id = self._make_node_id(
                    ctx.file_path, _build_qualified_name(class_name, field_name)
                )
                result.edges.append({
                    "source": func_id, "target": field_id,
                    "relation": "writes_state", "attributes": "{}",
                })

            # Call expressions -> calls edges
            for call in _collect_calls(body):
                call_name = _get_call_name(call)
                if not call_name:
                    continue

                # Try to resolve the call to a known function
                candidates = ctx.func_by_name.get(call_name, [])
                if candidates:
                    # Prefer same-class candidate
                    target = candidates[0]
                    for c in candidates:
                        if class_name and class_name in c:
                            target = c
                            break
                    result.edges.append({
                        "source": func_id, "target": target,
                        "relation": "calls", "attributes": "{}",
                    })
                else:
                    # Emit unresolved call edge — critical for cross-file path tracing
                    # Use a placeholder ID that can be matched during indexing
                    unresolved_id = self._make_node_id(ctx.file_path, f"_unresolved::{call_name}")
                    result.edges.append({
                        "source": func_id, "target": unresolved_id,
                        "relation": "calls",
                        "attributes": json.dumps({"unresolved": True, "call_name": call_name}),
                    })

    def _field_is_read(self, body, field_name, member_fields):
        """Check if a field is read (not just written) in a function body.

        Returns True if the field appears in a non-LHS context.
        """
        # Walk through all non-assignment contexts to see if the field appears
        return self._field_read_in_node(body, field_name, is_assignment_lhs=False)

    def _field_read_in_node(self, node, field_name, is_assignment_lhs):
        """Recursively check if field_name appears in a read context."""
        if node is None:
            return False

        if node.type in ("assignment_expression", "augmented_assignment_expression"):
            # LHS is write, RHS is read
            children = list(node.children)
            if len(children) >= 3:
                # children[0] = LHS, children[1] = operator, children[2] = RHS
                # Check if field appears in RHS (that's a read)
                if self._field_read_in_node(children[2], field_name, is_assignment_lhs=False):
                    return True
                # For augmented assignment (+=, etc.), LHS is also read
                if node.type == "augmented_assignment_expression":
                    if self._node_contains_field(children[0], field_name):
                        return True
                # LHS of plain assignment is NOT a read
                return False
            return False

        # For non-assignment nodes, any identifier match is a read
        if node.type in ("identifier", "field_identifier"):
            if _text(node) == field_name and not is_assignment_lhs:
                return True

        for child in node.children:
            if self._field_read_in_node(child, field_name, is_assignment_lhs=False):
                return True

        return False

    def _node_contains_field(self, node, field_name):
        """Check if a node contains a reference to field_name."""
        if node is None:
            return False
        if node.type in ("identifier", "field_identifier") and _text(node) == field_name:
            return True
        for child in node.children:
            if self._node_contains_field(child, field_name):
                return True
        return False


class _ExtractContext:
    """Mutable context passed through extraction."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        # func_id -> {name, class, namespace, ts_node, body_node}
        self.func_registry: dict[str, dict] = {}
        # ts_node.id -> func_id
        self.func_ts_map: dict[int, str] = {}
        # short function name -> [func_ids]
        self.func_by_name: dict[str, list[str]] = {}
        # qualified class name -> set of member field names
        self.class_member_fields: dict[str, set[str]] = {}
        # qualified enum name -> [variant names]
        self.enum_variants: dict[str, list[str]] = {}
