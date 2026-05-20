"""Java extractor — classes, interfaces, enums, methods, fields, security patterns."""

import json
import re
import tree_sitter
import tree_sitter_java

from core.web3.base import BaseExtractor
from core.web3 import ExtractResult

# ── Security pattern constants ──────────────────────────────────────────────

# Deserialization sinks (RCE vectors)
DESER_SINKS = {
    "readObject", "readUnshared", "readResolve", "readExternal",
    "readObjectNoData", "fromXML",  # XStream
    "unmarshal",  # JAXB/XML
    "fromJson", "deserialize",  # Gson/Jackson
}
DESER_CLASSES = {
    "ObjectInputStream", "XMLDecoder", "XStream",
    "ObjectMapper", "Gson", "Kryo",
}

# Reflection sinks (bypass access control)
REFLECTION_SINKS = {
    "forName", "getMethod", "getDeclaredMethod",
    "invoke", "setAccessible", "newInstance",
    "getDeclaredField", "getField",
}

# Command/code injection sinks
INJECTION_SINKS = {
    "exec", "getRuntime",  # Runtime.exec
    "ProcessBuilder",
    "executeQuery", "executeUpdate", "prepareStatement",  # SQL
    "eval",  # Script engines
    "compileClass", "loadClass",  # Dynamic class loading
}
# Injection sinks that need qualifier context (too generic alone)
QUALIFIED_INJECTION_SINKS = {
    ("Runtime", "exec"), ("Runtime", "getRuntime"),
    ("Statement", "execute"), ("Connection", "prepareStatement"),
    ("ScriptEngine", "eval"),
}

# Crypto operations (potential misuse)
CRYPTO_SINKS = {
    "getInstance",  # MessageDigest/Cipher — check arguments
    "generateKey", "generateKeyPair",
    "init",  # Cipher.init
    "doFinal", "update",  # Cipher operations
}
WEAK_CRYPTO = {
    "MD5", "SHA1", "SHA-1", "DES", "DESede", "RC4", "RC2",
    "ECB",  # ECB mode
    "NoPadding",  # No padding on block ciphers
}

# Unsafe memory operations
UNSAFE_PATTERNS = {
    "sun.misc.Unsafe", "Unsafe.getUnsafe",
    "allocateMemory", "freeMemory", "putLong", "putInt",
    "compareAndSwapInt", "compareAndSwapLong", "compareAndSwapObject",
}

# Thread safety sinks
THREAD_SINKS = {
    "Thread", "Runnable", "Callable",
    "ExecutorService", "ThreadPoolExecutor",
    "CompletableFuture", "ForkJoinPool",
}

# Resource leak patterns (should use try-with-resources)
CLOSEABLE_TYPES = {
    "InputStream", "OutputStream", "Reader", "Writer",
    "Connection", "Statement", "ResultSet", "PreparedStatement",
    "Socket", "ServerSocket", "Channel",
    "ObjectInputStream", "ObjectOutputStream",
    "FileInputStream", "FileOutputStream",
    "BufferedReader", "BufferedWriter",
}

# Validation patterns (input checking)
VALIDATION_METHODS = {
    "requireNonNull", "checkNotNull", "checkArgument", "checkState",
    "requireNotFrozen", "validate", "validateBasic",
    "assertNotNull", "assertTrue", "assertFalse",
    "Preconditions",
}

# JNI/native method indicators
NATIVE_INDICATORS = {"native"}

# Common annotations that indicate access control or special handling
SECURITY_ANNOTATIONS = {
    "Deprecated", "Override", "SuppressWarnings",
    "VisibleForTesting", "Nullable", "NonNull", "Nonnull",
}

# ── AST helpers ─────────────────────────────────────────────────────────────

def _text(node) -> str:
    return node.text.decode("utf-8") if node and node.text else ""


def _child_by_type(node, type_name):
    if node is None:
        return None
    for c in node.children:
        if c.type == type_name:
            return c
    return None


def _children_by_type(node, type_name) -> list:
    if node is None:
        return []
    return [c for c in node.children if c.type == type_name]


def _collect_nodes_by_types(node, type_names: set) -> list:
    results = []
    if node is None:
        return results
    if node.type in type_names:
        results.append(node)
    for child in node.children:
        results.extend(_collect_nodes_by_types(child, type_names))
    return results


def _get_modifiers(node) -> dict:
    """Extract modifiers and annotations from a modifiers node."""
    mods_node = _child_by_type(node, "modifiers")
    if mods_node is None:
        return {"visibility": "", "static": False, "final": False,
                "abstract": False, "synchronized": False, "volatile": False,
                "native": False, "annotations": []}

    vis = ""
    static = False
    final = False
    abstract = False
    synchronized = False
    volatile = False
    native = False
    annotations = []

    for c in mods_node.children:
        if c.type == "public":
            vis = "public"
        elif c.type == "private":
            vis = "private"
        elif c.type == "protected":
            vis = "protected"
        elif c.type == "static":
            static = True
        elif c.type == "final":
            final = True
        elif c.type == "abstract":
            abstract = True
        elif c.type == "synchronized":
            synchronized = True
        elif c.type == "volatile":
            volatile = True
        elif c.type == "native":
            native = True
        elif c.type in ("marker_annotation", "annotation"):
            ann_name = ""
            name_node = _child_by_type(c, "identifier")
            if name_node:
                ann_name = _text(name_node)
            else:
                # scoped identifier for fully qualified annotations
                si = _child_by_type(c, "scoped_identifier")
                if si:
                    ann_name = _text(si)
            if ann_name:
                annotations.append(ann_name)

    return {"visibility": vis, "static": static, "final": final,
            "abstract": abstract, "synchronized": synchronized,
            "volatile": volatile, "native": native,
            "annotations": annotations}


def _get_type_text(node) -> str:
    """Extract the type text from a type node."""
    if node is None:
        return ""
    # Skip modifiers to find the type
    for c in node.children:
        if c.type in ("type_identifier", "scoped_type_identifier",
                       "generic_type", "array_type", "void_type",
                       "boolean_type", "integral_type", "floating_point_type"):
            return _text(c)
    return ""


def _get_params(formal_params_node) -> list[tuple[str, str]]:
    """Extract (type, name) pairs from formal_parameters."""
    params = []
    if formal_params_node is None:
        return params
    for p in _children_by_type(formal_params_node, "formal_parameter"):
        ptype = _get_type_text(p)
        name_node = _child_by_type(p, "identifier")
        pname = _text(name_node) if name_node else ""
        if not ptype:
            # Try direct children for primitive types
            for c in p.children:
                if c.type in ("type_identifier", "scoped_type_identifier",
                               "generic_type", "array_type",
                               "boolean_type", "integral_type", "floating_point_type"):
                    ptype = _text(c)
                    break
        params.append((ptype, pname))
    # Also handle spread parameters
    for p in _children_by_type(formal_params_node, "spread_parameter"):
        ptype = _get_type_text(p)
        name_node = _child_by_type(p, "identifier")
        pname = _text(name_node) if name_node else ""
        params.append((ptype + "...", pname))
    return params


def _get_superclass(node) -> str | None:
    """Extract superclass name from class_declaration."""
    sc = _child_by_type(node, "superclass")
    if sc is None:
        return None
    for c in sc.children:
        if c.type in ("type_identifier", "generic_type", "scoped_type_identifier"):
            # Strip generics for the name
            text = _text(c)
            bracket = text.find("<")
            return text[:bracket] if bracket > 0 else text
    return None


def _get_interfaces(node) -> list[str]:
    """Extract implemented interface names."""
    si = _child_by_type(node, "super_interfaces")
    if si is None:
        return []
    tl = _child_by_type(si, "type_list")
    if tl is None:
        return []
    interfaces = []
    for c in tl.children:
        if c.type in ("type_identifier", "generic_type", "scoped_type_identifier"):
            text = _text(c)
            bracket = text.find("<")
            interfaces.append(text[:bracket] if bracket > 0 else text)
    return interfaces


def _get_extends_interfaces(node) -> list[str]:
    """Extract extended interface names (for interface declarations)."""
    ei = _child_by_type(node, "extends_interfaces")
    if ei is None:
        return []
    tl = _child_by_type(ei, "type_list")
    if tl is None:
        return []
    interfaces = []
    for c in tl.children:
        if c.type in ("type_identifier", "generic_type", "scoped_type_identifier"):
            text = _text(c)
            bracket = text.find("<")
            interfaces.append(text[:bracket] if bracket > 0 else text)
    return interfaces


def _get_type_parameters(node) -> str:
    """Extract generic type parameters text."""
    tp = _child_by_type(node, "type_parameters")
    return _text(tp) if tp else ""


def _get_throws(node) -> list[str]:
    """Extract thrown exception types from method declaration."""
    throws = _child_by_type(node, "throws")
    if throws is None:
        return []
    result = []
    for c in throws.children:
        if c.type in ("type_identifier", "scoped_type_identifier"):
            result.append(_text(c))
    return result


def _is_test_context(file_path: str) -> bool:
    """Check if file is in a test directory."""
    lower = file_path.lower()
    return ("/test/" in lower or "/tests/" in lower or
            "/testfixtures/" in lower or "/test-clients/" in lower or
            "/testutil/" in lower or "/testing/" in lower or
            "/jmh/" in lower or  # JMH benchmarks
            "test.java" in lower or lower.endswith("tests.java"))

# Annotations that indicate framework/DI methods (not user API surface)
FRAMEWORK_ANNOTATIONS = {
    "Provides", "Singleton", "IntoSet", "IntoMap", "Binds",
    "BindsOptionalOf", "Module", "Component", "Inject",
    "Bean", "Autowired", "PostConstruct", "PreDestroy",
    "BeforeAll", "BeforeEach", "AfterAll", "AfterEach",
    "Test", "ParameterizedTest", "RepeatedTest",
    "JSONRPC2Method",
}


# ── Extractor ───────────────────────────────────────────────────────────────

class JavaExtractor(BaseExtractor):
    """Extracts a knowledge graph from Java source files."""

    def __init__(self):
        self.lang = tree_sitter.Language(tree_sitter_java.language())
        self.parser = tree_sitter.Parser(self.lang)

    def extract_from_source(self, source_code: bytes, file_path: str) -> ExtractResult:
        tree = self.parser.parse(source_code)
        return self.extract(tree, source_code, file_path)

    def extract(self, tree, source_code: bytes, file_path: str) -> ExtractResult:
        result = ExtractResult()
        root = tree.root_node
        is_test = _is_test_context(file_path)

        # Tracking structures
        class_fields: dict[str, list[str]] = {}    # class_name -> [field_names]
        class_methods: dict[str, list[str]] = {}    # class_name -> [method_names]
        interface_methods: dict[str, list[str]] = {}  # iface_name -> [method_names]
        func_ts_map: dict[int, str] = {}             # ts node.id -> our node_id

        # Pass 1: Package declaration
        pkg = ""
        pkg_node = _child_by_type(root, "package_declaration")
        if pkg_node:
            for c in pkg_node.children:
                if c.type in ("scoped_identifier", "identifier"):
                    pkg = _text(c)
                    break

        # Pass 2: Import declarations
        for imp in _children_by_type(root, "import_declaration"):
            imp_path = ""
            for c in imp.children:
                if c.type in ("scoped_identifier", "identifier"):
                    imp_path = _text(c)
                    break
            if imp_path:
                node_id = self._make_node_id(file_path, f"import::{imp_path}")
                result.nodes.append({
                    "id": node_id, "label": imp_path, "type": "use",
                    "visibility": "", "file": file_path,
                    "line_start": imp.start_point[0] + 1,
                    "line_end": imp.end_point[0] + 1,
                    "signature": f"import {imp_path}",
                    "metadata": json.dumps({"path": imp_path}),
                })

        # Pass 3: Top-level declarations
        for child in root.children:
            if child.type == "class_declaration":
                self._extract_class(child, file_path, "", class_fields,
                                    class_methods, interface_methods,
                                    func_ts_map, is_test, result)
            elif child.type == "interface_declaration":
                self._extract_interface(child, file_path, "", class_fields,
                                        class_methods, interface_methods,
                                        func_ts_map, is_test, result)
            elif child.type == "enum_declaration":
                self._extract_enum(child, file_path, "", class_fields,
                                   class_methods, func_ts_map, is_test, result)

        return result

    # ── Class extraction ────────────────────────────────────────────────────

    def _extract_class(self, node, file_path: str, prefix: str,
                       class_fields: dict, class_methods: dict,
                       interface_methods: dict, func_ts_map: dict,
                       is_test: bool, result: ExtractResult):
        mods = _get_modifiers(node)
        name_node = _child_by_type(node, "identifier")
        if name_node is None:
            return
        class_name = _text(name_node)
        qualified = f"{prefix}::{class_name}" if prefix else class_name
        node_id = self._make_node_id(file_path, qualified)

        generics = _get_type_parameters(node)
        superclass = _get_superclass(node)
        interfaces = _get_interfaces(node)

        meta = {"kind": "class"}
        if mods["abstract"]:
            meta["abstract"] = True
        if generics:
            meta["generics"] = generics
        if mods["annotations"]:
            meta["annotations"] = mods["annotations"]

        node_type = "struct"
        if mods["abstract"]:
            node_type = "struct"  # still struct, but with abstract metadata

        sig_parts = []
        if mods["visibility"]:
            sig_parts.append(mods["visibility"])
        if mods["abstract"]:
            sig_parts.append("abstract")
        if mods["static"]:
            sig_parts.append("static")
        sig_parts.append("class")
        sig_parts.append(class_name)
        if generics:
            sig_parts.append(generics)
        if superclass:
            sig_parts.append(f"extends {superclass}")
        if interfaces:
            sig_parts.append(f"implements {', '.join(interfaces)}")

        result.nodes.append({
            "id": node_id, "label": class_name, "type": node_type,
            "visibility": mods["visibility"], "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": " ".join(sig_parts),
            "metadata": json.dumps(meta),
        })

        # Inheritance edges
        if superclass:
            result.edges.append({
                "source": node_id, "target": f"_::{superclass}",
                "relation": "inherits",
                "attributes": json.dumps({"kind": "extends"}),
            })
        for iface in interfaces:
            result.edges.append({
                "source": node_id, "target": f"_::{iface}",
                "relation": "inherits",
                "attributes": json.dumps({"kind": "implements", "interface": iface}),
            })

        # Extract body
        body = _child_by_type(node, "class_body")
        if body is None:
            return

        fields = []
        class_fields[class_name] = fields

        for child in body.children:
            if child.type == "field_declaration":
                self._extract_field(child, file_path, qualified, class_name,
                                    node_id, fields, result)
            elif child.type == "method_declaration":
                self._extract_method(child, file_path, qualified, class_name,
                                     fields, func_ts_map, is_test, result)
            elif child.type == "constructor_declaration":
                self._extract_constructor(child, file_path, qualified,
                                          class_name, fields, func_ts_map,
                                          is_test, result)
            elif child.type == "class_declaration":
                self._extract_class(child, file_path, qualified, class_fields,
                                    class_methods, interface_methods,
                                    func_ts_map, is_test, result)
            elif child.type == "interface_declaration":
                self._extract_interface(child, file_path, qualified,
                                        class_fields, class_methods,
                                        interface_methods, func_ts_map,
                                        is_test, result)
            elif child.type == "enum_declaration":
                self._extract_enum(child, file_path, qualified, class_fields,
                                   class_methods, func_ts_map, is_test, result)

    # ── Interface extraction ────────────────────────────────────────────────

    def _extract_interface(self, node, file_path: str, prefix: str,
                           class_fields: dict, class_methods: dict,
                           interface_methods: dict, func_ts_map: dict,
                           is_test: bool, result: ExtractResult):
        mods = _get_modifiers(node)
        name_node = _child_by_type(node, "identifier")
        if name_node is None:
            return
        iface_name = _text(name_node)
        qualified = f"{prefix}::{iface_name}" if prefix else iface_name
        node_id = self._make_node_id(file_path, qualified)

        generics = _get_type_parameters(node)
        extends = _get_extends_interfaces(node)

        meta = {"kind": "interface"}
        if generics:
            meta["generics"] = generics
        if mods["annotations"]:
            meta["annotations"] = mods["annotations"]

        result.nodes.append({
            "id": node_id, "label": iface_name, "type": "trait",
            "visibility": mods["visibility"], "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"interface {iface_name}" + (f" {generics}" if generics else ""),
            "metadata": json.dumps(meta),
        })

        for ext in extends:
            result.edges.append({
                "source": node_id, "target": f"_::{ext}",
                "relation": "inherits",
                "attributes": json.dumps({"kind": "extends"}),
            })

        # Extract interface body methods
        body = _child_by_type(node, "interface_body")
        if body is None:
            return

        method_names = []
        interface_methods[iface_name] = method_names

        for child in body.children:
            if child.type == "method_declaration":
                m_name = _child_by_type(child, "identifier")
                if m_name:
                    method_names.append(_text(m_name))
                self._extract_method(child, file_path, qualified, iface_name,
                                     [], func_ts_map, is_test, result)
            elif child.type == "constant_declaration":
                self._extract_field(child, file_path, qualified, iface_name,
                                    node_id, [], result)

    # ── Enum extraction ─────────────────────────────────────────────────────

    def _extract_enum(self, node, file_path: str, prefix: str,
                      class_fields: dict, class_methods: dict,
                      func_ts_map: dict, is_test: bool,
                      result: ExtractResult):
        mods = _get_modifiers(node)
        name_node = _child_by_type(node, "identifier")
        if name_node is None:
            return
        enum_name = _text(name_node)
        qualified = f"{prefix}::{enum_name}" if prefix else enum_name
        node_id = self._make_node_id(file_path, qualified)

        interfaces = _get_interfaces(node)
        variants = []

        body = _child_by_type(node, "enum_body")
        if body:
            for c in body.children:
                if c.type == "enum_constant":
                    v_name_node = _child_by_type(c, "identifier")
                    if v_name_node:
                        v_name = _text(v_name_node)
                        variants.append(v_name)
                        v_id = self._make_node_id(file_path, f"{qualified}::{v_name}")
                        result.nodes.append({
                            "id": v_id, "label": v_name, "type": "enum_variant",
                            "visibility": "public", "file": file_path,
                            "line_start": c.start_point[0] + 1,
                            "line_end": c.end_point[0] + 1,
                            "signature": v_name,
                            "metadata": json.dumps({"enum": enum_name}),
                        })
                        result.edges.append({
                            "source": node_id, "target": v_id,
                            "relation": "contains",
                            "attributes": "{}",
                        })

        meta = {"kind": "enum", "variants": variants}
        if mods["annotations"]:
            meta["annotations"] = mods["annotations"]

        result.nodes.append({
            "id": node_id, "label": enum_name, "type": "enum",
            "visibility": mods["visibility"], "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"enum {enum_name}",
            "metadata": json.dumps(meta),
        })

        for iface in interfaces:
            result.edges.append({
                "source": node_id, "target": f"_::{iface}",
                "relation": "inherits",
                "attributes": json.dumps({"kind": "implements", "interface": iface}),
            })

        # Extract enum body declarations (fields and methods)
        if body:
            ebd = _child_by_type(body, "enum_body_declarations")
            if ebd:
                fields = []
                class_fields[enum_name] = fields
                for child in ebd.children:
                    if child.type == "field_declaration":
                        self._extract_field(child, file_path, qualified,
                                            enum_name, node_id, fields, result)
                    elif child.type == "method_declaration":
                        self._extract_method(child, file_path, qualified,
                                             enum_name, fields, func_ts_map,
                                             is_test, result)
                    elif child.type == "constructor_declaration":
                        self._extract_constructor(child, file_path, qualified,
                                                  enum_name, fields, func_ts_map,
                                                  is_test, result)

        # State transitions for enums with meaningful variants
        if len(variants) >= 2 and not is_test:
            for v in variants:
                result.transitions.append({
                    "entity": enum_name, "from_state": "*",
                    "to_state": v,
                    "function_id": node_id,
                    "conditions": json.dumps(["enum_value"]),
                })

    # ── Field extraction ────────────────────────────────────────────────────

    def _extract_field(self, node, file_path: str, prefix: str,
                       class_name: str, class_node_id: str,
                       fields: list, result: ExtractResult):
        mods = _get_modifiers(node)
        type_text = _get_type_text(node)

        for decl in _children_by_type(node, "variable_declarator"):
            name_node = _child_by_type(decl, "identifier")
            if name_node is None:
                continue
            field_name = _text(name_node)
            fields.append(field_name)

            field_id = self._make_node_id(file_path, f"{prefix}::{field_name}")
            meta = {"struct": class_name, "type_text": type_text}
            if mods["static"]:
                meta["static"] = True
            if mods["final"]:
                meta["final"] = True
            if mods["volatile"]:
                meta["volatile"] = True
            if mods["annotations"]:
                meta["annotations"] = mods["annotations"]

            result.nodes.append({
                "id": field_id, "label": field_name, "type": "state_var",
                "visibility": mods["visibility"], "file": file_path,
                "line_start": node.start_point[0] + 1,
                "line_end": node.end_point[0] + 1,
                "signature": f"{type_text} {field_name}",
                "metadata": json.dumps(meta),
            })
            result.edges.append({
                "source": class_node_id, "target": field_id,
                "relation": "contains",
                "attributes": "{}",
            })

    # ── Constructor extraction ──────────────────────────────────────────────

    def _extract_constructor(self, node, file_path: str, prefix: str,
                             class_name: str, fields: list,
                             func_ts_map: dict, is_test: bool,
                             result: ExtractResult):
        mods = _get_modifiers(node)
        params_node = _child_by_type(node, "formal_parameters")
        params = _get_params(params_node)
        param_sig = ", ".join(f"{t} {n}" for t, n in params)
        param_types = ", ".join(t for t, _ in params)

        func_id = self._make_node_id(file_path, f"{prefix}::constructor", param_types)

        sig_parts = []
        if mods["visibility"]:
            sig_parts.append(mods["visibility"])
        sig_parts.append(f"{class_name}({param_sig})")

        meta = {"struct": class_name, "constructor": True}
        if mods["annotations"]:
            meta["annotations"] = mods["annotations"]

        body = _child_by_type(node, "constructor_body")
        if body:
            func_ts_map[node.id] = func_id
            self._extract_body_edges(body, node, func_id, file_path,
                                     class_name, fields, meta, is_test, result)

        result.nodes.append({
            "id": func_id, "label": "constructor", "type": "function",
            "visibility": mods["visibility"], "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": " ".join(sig_parts),
            "metadata": json.dumps(meta),
        })

    # ── Method extraction ───────────────────────────────────────────────────

    def _extract_method(self, node, file_path: str, prefix: str,
                        class_name: str, fields: list,
                        func_ts_map: dict, is_test: bool,
                        result: ExtractResult):
        mods = _get_modifiers(node)
        name_node = _child_by_type(node, "identifier")
        if name_node is None:
            return
        method_name = _text(name_node)

        return_type = _get_type_text(node)
        params_node = _child_by_type(node, "formal_parameters")
        params = _get_params(params_node)
        param_sig = ", ".join(f"{t} {n}" for t, n in params)
        param_types = ", ".join(t for t, _ in params)
        throws = _get_throws(node)

        func_id = self._make_node_id(file_path, f"{prefix}::{method_name}", param_types)

        sig_parts = []
        if mods["visibility"]:
            sig_parts.append(mods["visibility"])
        if mods["static"]:
            sig_parts.append("static")
        if mods["abstract"]:
            sig_parts.append("abstract")
        if mods["synchronized"]:
            sig_parts.append("synchronized")
        if mods["native"]:
            sig_parts.append("native")
        sig_parts.append(f"{return_type} {method_name}({param_sig})")
        if throws:
            sig_parts.append(f"throws {', '.join(throws)}")

        meta: dict = {"struct": class_name}
        if return_type:
            meta["return_type"] = return_type
        if mods["static"]:
            meta["static"] = True
        if mods["abstract"]:
            meta["abstract"] = True
        if mods["synchronized"]:
            meta["synchronized"] = True
        if mods["native"]:
            meta["native"] = True
            meta["is_sink"] = True
            meta["sink_type"] = "native"
        if mods["annotations"]:
            meta["annotations"] = mods["annotations"]
        if throws:
            meta["throws"] = throws

        # Body extraction (modifies meta with security patterns)
        body = _child_by_type(node, "block")
        if body:
            func_ts_map[node.id] = func_id
            self._extract_body_edges(body, node, func_id, file_path,
                                     class_name, fields, meta, is_test, result)

        # Validation detection (after body extraction so we have all info)
        if not is_test and not meta.get("_has_validation"):
            has_params = len(params) > 0
            is_public = mods["visibility"] in ("public", "")
            is_getter = (method_name.startswith("get") or
                         method_name.startswith("is") or
                         method_name.startswith("has") or
                         method_name.startswith("to") or
                         method_name.startswith("from"))
            is_override = "Override" in mods["annotations"]
            is_framework = bool(set(mods["annotations"]) & FRAMEWORK_ANNOTATIONS)
            is_simple_setter = (method_name.startswith("set") and len(params) == 1)

            if (is_public and has_params and not mods["abstract"]
                    and not mods["native"] and not is_getter
                    and not is_override and not is_framework
                    and not is_simple_setter
                    and body is not None):
                meta["no_input_validation"] = True

        # Clean up internal tracking key
        meta.pop("_has_validation", None)

        result.nodes.append({
            "id": func_id, "label": method_name, "type": "function",
            "visibility": mods["visibility"], "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": " ".join(sig_parts),
            "metadata": json.dumps(meta),
        })

    # ── Body edge extraction (security patterns) ───────────────────────────

    def _extract_body_edges(self, body_node, func_node, func_id: str,
                            file_path: str, class_name: str,
                            fields: list, meta: dict,
                            is_test: bool, result: ExtractResult):
        """Walk method body for calls, state access, and security patterns."""

        body_text = _text(body_node)

        # ── 1. State reads/writes ───────────────────────────────────────
        # Track this.field assignments
        assignments = _collect_nodes_by_types(body_node, {"assignment_expression"})
        written_fields = set()

        for assign in assignments:
            lhs = assign.children[0] if assign.children else None
            if lhs is None:
                continue
            # Check for this.field = ... pattern
            if lhs.type == "field_access":
                obj = _child_by_type(lhs, "this")
                if obj:
                    fname_node = _child_by_type(lhs, "identifier")
                    if fname_node:
                        fname = _text(fname_node)
                        if fname in fields:
                            written_fields.add(fname)
                            field_id = self._make_node_id(
                                file_path, f"{class_name}::{fname}" if "::" not in class_name
                                else f"{class_name}::{fname}")
                            # Fix: use the class prefix from func_id
                            parts = func_id.split("::")
                            if len(parts) >= 3:
                                field_id = self._make_node_id(
                                    file_path, f"{'::'.join(parts[1:-1])}::{fname}")
                            result.edges.append({
                                "source": func_id, "target": field_id,
                                "relation": "writes_state",
                                "attributes": "{}",
                            })

        # State reads: this.field in non-assignment contexts
        field_accesses = _collect_nodes_by_types(body_node, {"field_access"})
        read_fields = set()
        assign_ids = {a.children[0].id for a in assignments
                      if a.children and a.children[0].type == "field_access"}

        for fa in field_accesses:
            if fa.id in assign_ids:
                continue
            obj = _child_by_type(fa, "this")
            if obj:
                fname_node = _child_by_type(fa, "identifier")
                if fname_node:
                    fname = _text(fname_node)
                    if fname in fields and fname not in read_fields:
                        read_fields.add(fname)
                        parts = func_id.split("::")
                        if len(parts) >= 3:
                            field_id = self._make_node_id(
                                file_path, f"{'::'.join(parts[1:-1])}::{fname}")
                        else:
                            field_id = self._make_node_id(
                                file_path, f"{class_name}::{fname}")
                        result.edges.append({
                            "source": func_id, "target": field_id,
                            "relation": "reads_state",
                            "attributes": "{}",
                        })

        # ── 2. Method calls ─────────────────────────────────────────────
        call_nodes = _collect_nodes_by_types(body_node, {"method_invocation"})
        obj_creations = _collect_nodes_by_types(body_node, {"object_creation_expression"})

        for call in call_nodes:
            call_name, qualifier = self._get_call_info(call)
            if not call_name:
                continue

            # Determine target
            if qualifier and qualifier != "this":
                target_id = f"_::{qualifier}.{call_name}"
            elif class_name:
                target_id = self._make_node_id(
                    file_path, f"{class_name}::{call_name}" if "::" not in class_name
                    else f"{class_name}::{call_name}")
            else:
                target_id = f"_::{call_name}"

            attrs: dict = {}
            if qualifier and qualifier != "this":
                attrs["unresolved"] = True
                attrs["call_name"] = call_name
                attrs["qualifier"] = qualifier

            result.edges.append({
                "source": func_id, "target": target_id,
                "relation": "calls",
                "attributes": json.dumps(attrs) if attrs else "{}",
            })

        # ── 3. Security pattern detection ───────────────────────────────

        # Validation detection
        has_validation = False
        for kw in VALIDATION_METHODS:
            if kw in body_text:
                has_validation = True
                break
        if not has_validation:
            # Check for if-statements, throw, assert
            if_nodes = _collect_nodes_by_types(body_node, {"if_statement"})
            throw_nodes = _collect_nodes_by_types(body_node, {"throw_statement"})
            assert_nodes = _collect_nodes_by_types(body_node, {"assert_statement"})
            if if_nodes or throw_nodes or assert_nodes:
                has_validation = True
        if has_validation:
            meta["_has_validation"] = True

        # Deserialization sinks
        deser_calls = []
        for call in call_nodes:
            call_name, qualifier = self._get_call_info(call)
            if call_name in DESER_SINKS:
                deser_calls.append(call_name)
            if qualifier in DESER_CLASSES:
                deser_calls.append(f"{qualifier}.{call_name}")
        for oc in obj_creations:
            type_node = _child_by_type(oc, "type_identifier")
            if type_node and _text(type_node) in DESER_CLASSES:
                deser_calls.append(_text(type_node))

        if deser_calls and not is_test:
            meta["deserialization_sinks"] = list(set(deser_calls))
            self._create_sink_node(func_id, file_path, func_node,
                                   "deserialization", deser_calls[0], result)

        # Reflection usage
        reflection_calls = []
        for call in call_nodes:
            call_name, qualifier = self._get_call_info(call)
            if call_name in REFLECTION_SINKS:
                reflection_calls.append(call_name)

        if reflection_calls and not is_test:
            meta["reflection_usage"] = list(set(reflection_calls))
            if "invoke" in reflection_calls or "setAccessible" in reflection_calls:
                self._create_sink_node(func_id, file_path, func_node,
                                       "reflection", reflection_calls[0], result)

        # Injection sinks (command exec, SQL)
        injection_calls = []
        for call in call_nodes:
            call_name, qualifier = self._get_call_info(call)
            if call_name in INJECTION_SINKS:
                injection_calls.append(f"{qualifier}.{call_name}" if qualifier else call_name)
            # Qualified sinks need matching qualifier
            for q, m in QUALIFIED_INJECTION_SINKS:
                if call_name == m and qualifier and q.lower() in qualifier.lower():
                    injection_calls.append(f"{qualifier}.{call_name}")
        if injection_calls and not is_test:
            meta["injection_sinks"] = list(set(injection_calls))
            self._create_sink_node(func_id, file_path, func_node,
                                   "injection", injection_calls[0], result)

        # Weak crypto detection (require quotes or word boundaries for short patterns)
        weak_crypto_found = []
        for pattern in WEAK_CRYPTO:
            # Short patterns like "DES" need to appear in string literals to avoid FP
            if len(pattern) <= 4:
                if f'"{pattern}"' in body_text or f'"{pattern}/' in body_text:
                    weak_crypto_found.append(pattern)
            else:
                if pattern in body_text:
                    weak_crypto_found.append(pattern)
        if weak_crypto_found and not is_test:
            meta["weak_crypto"] = weak_crypto_found

        # Synchronized method / blocks
        sync_blocks = _collect_nodes_by_types(body_node, {"synchronized_statement"})
        if sync_blocks:
            meta["synchronized_blocks"] = len(sync_blocks)

        # Thread creation (potential race conditions)
        thread_creations = []
        for oc in obj_creations:
            type_node = _child_by_type(oc, "type_identifier")
            if type_node and _text(type_node) in THREAD_SINKS:
                thread_creations.append(_text(type_node))
        # Lambda + executor patterns
        for call in call_nodes:
            call_name, qualifier = self._get_call_info(call)
            if call_name in ("submit", "execute", "supplyAsync", "runAsync",
                             "thenApply", "thenAccept", "thenRun"):
                thread_creations.append(f"{qualifier}.{call_name}" if qualifier else call_name)

        if thread_creations and not is_test:
            meta["async_operations"] = list(set(thread_creations))
            # Check for field access without synchronization in async context
            if written_fields and not sync_blocks:
                meta["potential_race"] = {
                    "shared_fields": list(written_fields),
                    "async_patterns": list(set(thread_creations))[:3],
                }

        # Resource leak detection (non-try-with-resources Closeable usage)
        resource_leaks = []
        for oc in obj_creations:
            type_node = _child_by_type(oc, "type_identifier")
            if type_node and _text(type_node) in CLOSEABLE_TYPES:
                # Check if this is inside a try-with-resources
                parent = oc.parent
                in_twr = False
                while parent and parent != body_node:
                    if parent.type == "resource_specification":
                        in_twr = True
                        break
                    if parent.type == "try_with_resources_statement":
                        in_twr = True
                        break
                    parent = parent.parent
                if not in_twr:
                    resource_leaks.append(_text(type_node))

        if resource_leaks and not is_test:
            meta["resource_leaks"] = list(set(resource_leaks))

        # Exception swallowing (empty catch blocks)
        catch_clauses = _collect_nodes_by_types(body_node, {"catch_clause"})
        swallowed = 0
        for catch in catch_clauses:
            catch_body = _child_by_type(catch, "block")
            if catch_body:
                # Count non-whitespace, non-brace children
                meaningful = [c for c in catch_body.children
                              if c.type not in ("{", "}", "comment", "line_comment")]
                if len(meaningful) == 0:
                    swallowed += 1
        if swallowed > 0 and not is_test:
            meta["swallowed_exceptions"] = swallowed

        # Unsafe memory access
        if any(p in body_text for p in ("Unsafe", "allocateMemory",
                                         "compareAndSwap")):
            unsafe_ops = [p for p in UNSAFE_PATTERNS if p in body_text]
            if unsafe_ops:
                meta["unsafe_memory"] = unsafe_ops

        # Native method calls
        if "System.loadLibrary" in body_text or "System.load(" in body_text:
            meta["native_library_load"] = True

    # ── Helper: get call info ───────────────────────────────────────────

    def _get_call_info(self, call_node) -> tuple[str, str]:
        """Extract (method_name, qualifier) from a method_invocation node."""
        name_node = _child_by_type(call_node, "identifier")
        method_name = _text(name_node) if name_node else ""

        qualifier = ""
        # Check for obj.method() pattern
        obj_node = call_node.children[0] if call_node.children else None
        if obj_node and obj_node.type == "field_access":
            # qualifier.method
            q_ident = _child_by_type(obj_node, "identifier")
            if q_ident:
                qualifier = _text(q_ident)
            method_name = ""
            # The actual method name is the last identifier
            for c in reversed(obj_node.children):
                if c.type == "identifier":
                    method_name = _text(c)
                    break
        elif obj_node and obj_node.type == "identifier" and obj_node != name_node:
            qualifier = _text(obj_node)

        return method_name, qualifier

    # ── Helper: create sink node ────────────────────────────────────────

    def _create_sink_node(self, func_id: str, file_path: str,
                          func_node, sink_type: str, sink_name: str,
                          result: ExtractResult):
        """Create a sink node and link it to the calling function."""
        line = func_node.start_point[0] + 1 if func_node else 0
        sink_id = self._make_node_id(
            file_path,
            f"{func_id.split('::')[-1]}._sink_{sink_name}_{line}"
        )
        result.nodes.append({
            "id": sink_id, "label": sink_name, "type": "function",
            "visibility": "", "file": file_path,
            "line_start": line, "line_end": line,
            "signature": f"sink::{sink_type}::{sink_name}",
            "metadata": json.dumps({
                "is_sink": True,
                "sink_type": sink_type,
            }),
        })
        result.edges.append({
            "source": func_id, "target": sink_id,
            "relation": "calls",
            "attributes": json.dumps({"sink": True}),
        })
