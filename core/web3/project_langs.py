"""Lightweight extractors for blockchain project-specific languages.

These parsers intentionally avoid new tree-sitter dependencies. They extract
coarse but useful graph structure from languages that appear in the local
blockchain workspace: Move, Clarity, Vyper, Cairo, Sway, TON, protobuf,
Stellar XDR, TypeScript/JavaScript, and Python.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from core.web3 import ExtractResult
from core.web3.base import BaseExtractor


CONTROL_CALLS = {
    "if", "for", "while", "switch", "catch", "return", "require", "assert",
    "let", "const", "var", "function", "new", "typeof", "sizeof", "match",
    "else", "try", "begin", "ok", "err", "some", "none", "and", "or", "not",
}

VALIDATION_HINTS = (
    "assert", "require", "ensure", "abort", "raise", "throw", "revert",
    "try!", "unwrap!", "asserts!", "Validate", "validate", "check",
)

ACCESS_HINTS = (
    "onlyowner", "only_owner", "owner", "admin", "authority", "auth",
    "permission", "role", "has_role", "msg.sender", "tx-sender",
    "contract-caller", "ctx.sender", "signer", "require_auth",
)

TIMESTAMP_HINTS = (
    "block.timestamp", "block.number", "block-height", "burn-block-height",
    "get_block_timestamp", "timestamp", "Clock", "SYSVAR_CLOCK",
)

TRANSFER_HINTS = (
    "transfer", "public_transfer", "stx-transfer?", "ft-transfer?",
    "nft-transfer?", "raw_call", "sendTransaction", "sendAndConfirmTransaction",
    "signAndSendTransaction", "createTransfer", "mint", "burn",
)

BOUNDARY_CALL_NAMES = {
    "raw_call", "send", "transfer", "public_transfer", "stx-transfer?",
    "ft-transfer?", "nft-transfer?", "sendTransaction",
    "sendAndConfirmTransaction", "signAndSendTransaction",
    "call_contract_syscall", "library_call_syscall",
}


@dataclass
class FunctionSpan:
    name: str
    visibility: str
    start_line: int
    end_line: int
    signature: str
    body: str
    scope: str = ""
    decorators: list[str] = field(default_factory=list)


def _decode(source_code: bytes) -> str:
    return source_code.decode("utf-8", errors="ignore")


def _strip_comments(text: str) -> str:
    """Best-effort comment stripping for lightweight regex extraction."""
    text = re.sub(r"(?m)//.*$", "", text)
    text = re.sub(r"(?m);;.*$", "", text)
    text = re.sub(r"(?m)#.*$", "", text)
    return text


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _line_end(text: str, offset: int) -> int:
    newline = text.find("\n", offset)
    return len(text) if newline == -1 else newline


def _sanitize_name(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip()).replace(" ", "_")


def _find_matching(text: str, open_idx: int, opener: str, closer: str) -> int:
    depth = 0
    quote = ""
    escape = False
    i = open_idx
    while i < len(text):
        ch = text[i]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


def _brace_body(text: str, start: int) -> tuple[str, int]:
    open_idx = text.find("{", start)
    if open_idx == -1:
        end = _line_end(text, start)
        return text[start:end], end
    end = _find_matching(text, open_idx, "{", "}")
    return text[open_idx:end], end


def _paren_body(text: str, open_idx: int) -> tuple[str, int]:
    end = _find_matching(text, open_idx, "(", ")")
    return text[open_idx:end], end


def _line_indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _decorators_before(text: str, offset: int, prefix: str = "@") -> list[str]:
    decorators = []
    before = text[:offset].splitlines()
    for line in reversed(before):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(prefix):
            decorators.insert(0, stripped)
            continue
        break
    return decorators


def _call_names(body: str, extra_skip: Iterable[str] = ()) -> list[str]:
    skip = CONTROL_CALLS | set(extra_skip)
    names: list[str] = []
    for match in re.finditer(r"([A-Za-z_$][\w$]*(?:(?:::|\.)[A-Za-z_$][\w$]*)*)\s*\(", body):
        raw = match.group(1)
        name = raw.split("::")[-1].split(".")[-1]
        if not name or name in skip or name[0].isdigit():
            continue
        if name not in names:
            names.append(name)
    return names


def _is_boundary_call(call_name: str) -> bool:
    lower = call_name.lower()
    return (
        call_name in BOUNDARY_CALL_NAMES
        or "transfer" in lower
        or lower in {"send", "sendtransaction", "sendandconfirmtransaction", "signandsendtransaction"}
        or lower.endswith("call")
    )


class TextProjectExtractor(BaseExtractor):
    """Base class for line/regex based project-language extractors."""

    language = "text"
    entry_visibilities = {"external", "public"}

    def extract_from_source(self, source_code: bytes, file_path: str) -> ExtractResult:
        return self._extract_text(_decode(source_code), file_path)

    def extract(self, tree, source_code: bytes, file_path: str) -> ExtractResult:
        return self.extract_from_source(source_code, file_path)

    def _containers(self, text: str, file_path: str) -> list[dict]:
        return []

    def _state_declarations(self, text: str, scope: str) -> list[str]:
        return []

    def _functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        return []

    def _calls(self, span: FunctionSpan) -> list[str]:
        return _call_names(_strip_comments(span.body), extra_skip={span.name})

    def _state_writes(self, span: FunctionSpan) -> list[str]:
        return []

    def _state_reads(self, span: FunctionSpan) -> list[str]:
        return []

    def _default_scope(self, file_path: str, containers: list[dict]) -> str:
        return containers[0]["label"] if containers else Path(file_path).stem

    def _metadata(self, span: FunctionSpan) -> dict:
        body = _strip_comments(span.body)
        lower = body.lower()
        meta: dict = {"language": self.language}
        if span.decorators:
            meta["decorators"] = span.decorators
        if any(h.lower() in lower for h in TIMESTAMP_HINTS):
            meta["timestamp_dependence"] = ["time_or_height_reference"]
        if span.visibility in self.entry_visibilities and not any(h in body for h in VALIDATION_HINTS):
            meta["no_input_validation"] = True
        transfer_sinks = [h for h in TRANSFER_HINTS if h in body]
        if transfer_sinks:
            meta["transfer_sinks"] = sorted(set(transfer_sinks))
        if any(h.lower() in lower for h in ACCESS_HINTS):
            meta["access_check_hints"] = True
        return meta

    def _guards(self, span: FunctionSpan) -> list[str]:
        body_lower = _strip_comments(span.body).lower()
        guards = []
        for hint in ACCESS_HINTS:
            if hint.lower() in body_lower:
                guards.append(hint)
        return sorted(set(guards))

    def _scope_for_offset(self, offset: int, containers: list[dict]) -> str:
        scoped = []
        for c in containers:
            end = c.get("end")
            if c["start"] <= offset and (end is None or offset <= end):
                scoped.append(c)
        return scoped[-1]["label"] if scoped else ""

    def _node_symbol(self, scope: str, name: str) -> str:
        if scope:
            return f"{scope}.{name}"
        return name

    def _state_symbol(self, scope: str, name: str) -> str:
        clean = _sanitize_name(name)
        if scope:
            return f"{scope}.{clean}"
        return clean

    def _add_state_node(self, result: ExtractResult, seen: set[str],
                        file_path: str, scope: str, name: str):
        state_id = self._make_node_id(file_path, self._state_symbol(scope, name))
        if state_id in seen:
            return state_id
        seen.add(state_id)
        result.nodes.append({
            "id": state_id, "label": _sanitize_name(name), "type": "state_var",
            "visibility": "", "file": file_path, "line_start": 0, "line_end": 0,
            "signature": "", "metadata": json.dumps({"language": self.language}),
        })
        return state_id

    def _extract_text(self, text: str, file_path: str) -> ExtractResult:
        result = ExtractResult()
        state_nodes: set[str] = set()

        containers = self._containers(text, file_path)
        for c in containers:
            c_id = self._make_node_id(file_path, c["label"])
            c["id"] = c_id
            result.nodes.append({
                "id": c_id, "label": c["label"], "type": c.get("type", "module"),
                "visibility": "public", "file": file_path,
                "line_start": c["line"], "line_end": c.get("end_line", c["line"]),
                "signature": c.get("signature", c["label"]),
                "metadata": json.dumps({"language": self.language}),
            })

        default_scope = self._default_scope(file_path, containers)
        for name in self._state_declarations(text, default_scope):
            self._add_state_node(result, state_nodes, file_path, default_scope, name)

        for span in self._functions(text, file_path, containers):
            scope = span.scope or default_scope
            func_id = self._make_node_id(file_path, self._node_symbol(scope, span.name))
            meta = self._metadata(span)
            result.nodes.append({
                "id": func_id, "label": span.name, "type": "function",
                "visibility": span.visibility, "file": file_path,
                "line_start": span.start_line, "line_end": span.end_line,
                "signature": span.signature, "metadata": json.dumps(meta),
            })

            container_id = next((c["id"] for c in containers if c["label"] == scope), "")
            if container_id:
                result.edges.append({
                    "source": container_id, "target": func_id,
                    "relation": "contains", "attributes": "{}",
                })

            for guard in self._guards(span):
                guard_id = self._make_node_id(file_path, f"_guard_{_sanitize_name(guard)}")
                result.nodes.append({
                    "id": guard_id, "label": guard, "type": "guard",
                    "visibility": "", "file": file_path,
                    "line_start": span.start_line, "line_end": span.start_line,
                    "signature": guard, "metadata": json.dumps({"language": self.language}),
                })
                result.edges.append({
                    "source": guard_id, "target": func_id,
                    "relation": "guards", "attributes": json.dumps({"hint": guard}),
                })

            for call_name in self._calls(span):
                attrs = {
                    "unresolved": True,
                    "call_name": call_name,
                    "language": self.language,
                }
                if _is_boundary_call(call_name):
                    attrs["cross_boundary"] = True
                else:
                    attrs["internal_candidate"] = True
                result.edges.append({
                    "source": func_id, "target": f"_::{call_name}",
                    "relation": "calls",
                    "attributes": json.dumps(attrs),
                })

            for name in self._state_writes(span):
                state_id = self._add_state_node(result, state_nodes, file_path, scope, name)
                result.edges.append({
                    "source": func_id, "target": state_id,
                    "relation": "writes_state",
                    "attributes": json.dumps({"language": self.language}),
                })

            for name in self._state_reads(span):
                state_id = self._add_state_node(result, state_nodes, file_path, scope, name)
                result.edges.append({
                    "source": func_id, "target": state_id,
                    "relation": "reads_state",
                    "attributes": json.dumps({"language": self.language}),
                })

        return result


class MoveExtractor(TextProjectExtractor):
    language = "move"

    def _containers(self, text: str, file_path: str) -> list[dict]:
        out = []
        for m in re.finditer(r"(?m)^\s*(?:public\s+)?module\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)?)\s*[;{]", text):
            out.append({
                "label": m.group(1), "type": "module",
                "line": _line_for_offset(text, m.start()),
                "start": m.start(), "signature": m.group(0).strip(),
            })
        return out

    def _state_declarations(self, text: str, scope: str) -> list[str]:
        return re.findall(r"(?m)^\s*(?:public\s+)?struct\s+([A-Za-z_]\w*)\b", text)

    def _functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        spans = []
        pattern = re.compile(
            r"(?m)^\s*((?:public(?:\([^)]*\))?\s+)?(?:entry\s+)?(?:public\s+entry\s+)?)fun\s+([A-Za-z_]\w*)\s*(?:<[^>{}]*>)?\s*\("
        )
        for m in pattern.finditer(text):
            prefix = m.group(1) or ""
            body, end = _brace_body(text, m.end())
            if "entry" in prefix:
                vis = "external"
            elif "public" in prefix:
                vis = "public"
            else:
                vis = "private"
            spans.append(FunctionSpan(
                name=m.group(2), visibility=vis,
                start_line=_line_for_offset(text, m.start()),
                end_line=_line_for_offset(text, end),
                signature=text[m.start():_line_end(text, m.end())].strip(),
                body=body,
                scope=self._scope_for_offset(m.start(), containers),
            ))
        return spans

    def _state_writes(self, span: FunctionSpan) -> list[str]:
        names = re.findall(r"\b(?:move_to|move_from|borrow_global_mut)\s*<\s*([^>]+)>", span.body)
        if "transfer::" in span.body or "public_transfer" in span.body:
            names.append("asset_transfer")
        return names

    def _state_reads(self, span: FunctionSpan) -> list[str]:
        return re.findall(r"\b(?:borrow_global|exists)\s*<\s*([^>]+)>", span.body)

    def _metadata(self, span: FunctionSpan) -> dict:
        meta = super()._metadata(span)
        if re.search(r"\b(entry\s+fun|public\s+entry\s+fun)", span.signature):
            meta["move_entry"] = True
        if "transfer::" in span.body or "public_transfer" in span.body:
            meta["cross_contract_calls"] = ["transfer_module"]
        return meta


class ClarityExtractor(TextProjectExtractor):
    language = "clarity"

    CLARITY_SKIP = {
        "define-public", "define-private", "define-read-only", "define-map",
        "define-data-var", "define-constant", "let", "begin", "if", "ok", "err",
        "some", "none", "match", "and", "or", "not", "try!", "unwrap!",
        "asserts!",
    }

    def _state_declarations(self, text: str, scope: str) -> list[str]:
        names = []
        for pat in (
            r"\(define-data-var\s+([A-Za-z_][\w\-?!]*)",
            r"\(define-map\s+([A-Za-z_][\w\-?!]*)",
            r"\(define-fungible-token\s+([A-Za-z_][\w\-?!]*)",
            r"\(define-non-fungible-token\s+([A-Za-z_][\w\-?!]*)",
        ):
            names.extend(re.findall(pat, text))
        return names

    def _functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        spans = []
        pattern = re.compile(r"\(define-(public|private|read-only)\s+\(([A-Za-z_][\w\-?!]*)")
        for m in pattern.finditer(text):
            body, end = _paren_body(text, m.start())
            kind = m.group(1)
            vis = "private" if kind == "private" else "public"
            meta_decorators = [kind]
            spans.append(FunctionSpan(
                name=m.group(2), visibility=vis,
                start_line=_line_for_offset(text, m.start()),
                end_line=_line_for_offset(text, end),
                signature=text[m.start():_line_end(text, m.start())].strip(),
                body=body,
                scope=Path(file_path).stem,
                decorators=meta_decorators,
            ))
        return spans

    def _calls(self, span: FunctionSpan) -> list[str]:
        names = []
        for m in re.finditer(r"\(([A-Za-z_+\-*/<>=][\w+\-*/<>=?!]*)", span.body):
            name = m.group(1)
            if name not in self.CLARITY_SKIP and name != span.name and name not in names:
                names.append(name)
        return names

    def _state_writes(self, span: FunctionSpan) -> list[str]:
        names = []
        for pat in (r"\(var-set\s+([A-Za-z_][\w\-?!]*)", r"\(map-set\s+([A-Za-z_][\w\-?!]*)",
                    r"\(map-delete\s+([A-Za-z_][\w\-?!]*)"):
            names.extend(re.findall(pat, span.body))
        if any(s in span.body for s in ("stx-transfer?", "ft-transfer?", "nft-transfer?")):
            names.append("asset_transfer")
        return names

    def _state_reads(self, span: FunctionSpan) -> list[str]:
        names = []
        for pat in (r"\(var-get\s+([A-Za-z_][\w\-?!]*)", r"\(map-get\?\s+([A-Za-z_][\w\-?!]*)"):
            names.extend(re.findall(pat, span.body))
        return names

    def _metadata(self, span: FunctionSpan) -> dict:
        meta = super()._metadata(span)
        if "read-only" in span.decorators:
            meta["view"] = True
        sinks = [s for s in ("contract-call?", "stx-transfer?", "ft-transfer?", "nft-transfer?") if s in span.body]
        if sinks:
            meta["cross_contract_calls"] = sinks
        return meta


class VyperExtractor(TextProjectExtractor):
    language = "vyper"

    def _state_declarations(self, text: str, scope: str) -> list[str]:
        names = []
        for m in re.finditer(r"(?m)^([A-Za-z_]\w*)\s*:\s*(?!constant|immutable|event\b|interface\b)", text):
            names.append(m.group(1))
        return names

    def _functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        spans = []
        lines = text.splitlines(keepends=True)
        offsets = []
        pos = 0
        for line in lines:
            offsets.append(pos)
            pos += len(line)
        for idx, line in enumerate(lines):
            m = re.match(r"^(\s*)def\s+([A-Za-z_]\w*)\s*\(", line)
            if not m:
                continue
            indent = len(m.group(1))
            end_idx = idx + 1
            while end_idx < len(lines):
                stripped = lines[end_idx].strip()
                if stripped and not stripped.startswith("#") and _line_indent(lines[end_idx]) <= indent:
                    break
                end_idx += 1
            start_off = offsets[idx]
            end_off = offsets[end_idx] if end_idx < len(offsets) else len(text)
            decorators = _decorators_before(text, start_off)
            deco_text = " ".join(decorators)
            if "@external" in deco_text or "@public" in deco_text:
                vis = "external"
            else:
                vis = "private"
            spans.append(FunctionSpan(
                name=m.group(2), visibility=vis,
                start_line=idx + 1, end_line=end_idx,
                signature=line.strip(), body=text[start_off:end_off],
                scope=Path(file_path).stem, decorators=decorators,
            ))
        return spans

    def _state_writes(self, span: FunctionSpan) -> list[str]:
        names = re.findall(r"\bself\.([A-Za-z_]\w*)\s*(?:[+\-*/]?=)", span.body)
        if "raw_call" in span.body or re.search(r"\b(send|transfer)\s*\(", span.body):
            names.append("external_value_transfer")
        return names

    def _state_reads(self, span: FunctionSpan) -> list[str]:
        return re.findall(r"\bself\.([A-Za-z_]\w*)\b", span.body)

    def _metadata(self, span: FunctionSpan) -> dict:
        meta = super()._metadata(span)
        deco_text = " ".join(span.decorators)
        if "@view" in deco_text or "@pure" in deco_text:
            meta["view"] = True
        if "raw_call" in span.body:
            meta["cross_contract_calls"] = ["raw_call"]
            if "revert_on_failure=False" in span.body.replace(" ", ""):
                meta["unchecked_calls"] = [{"call": "raw_call", "detail": "revert_on_failure=False"}]
        if "ecrecover" in span.body and "chain.id" not in span.body and "domain" not in span.body.lower():
            meta["signature_risk"] = "vyper_ecrecover_without_domain"
        return meta


class CairoExtractor(TextProjectExtractor):
    language = "cairo"

    def _containers(self, text: str, file_path: str) -> list[dict]:
        out = []
        for m in re.finditer(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_]\w*)\b", text):
            out.append({
                "label": m.group(1), "type": "module", "start": m.start(),
                "line": _line_for_offset(text, m.start()), "signature": m.group(0).strip(),
            })
        return out

    def _functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        spans = []
        for m in re.finditer(r"(?m)^\s*(pub\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>{}]*>)?\s*\(", text):
            body, end = _brace_body(text, m.end())
            decorators = _decorators_before(text, m.start(), prefix="#[")
            deco_text = " ".join(decorators)
            vis = "external" if "external" in deco_text or "constructor" in deco_text else ("public" if m.group(1) else "private")
            spans.append(FunctionSpan(
                name=m.group(2), visibility=vis,
                start_line=_line_for_offset(text, m.start()),
                end_line=_line_for_offset(text, end),
                signature=text[m.start():_line_end(text, m.end())].strip(),
                body=body, scope=self._scope_for_offset(m.start(), containers),
                decorators=decorators,
            ))
        return spans

    def _state_writes(self, span: FunctionSpan) -> list[str]:
        return re.findall(r"\bself\.([A-Za-z_]\w*)\.write\s*\(", span.body)

    def _state_reads(self, span: FunctionSpan) -> list[str]:
        return re.findall(r"\bself\.([A-Za-z_]\w*)\.read\s*\(", span.body)

    def _metadata(self, span: FunctionSpan) -> dict:
        meta = super()._metadata(span)
        if "call_contract_syscall" in span.body or "library_call_syscall" in span.body:
            meta["cross_contract_calls"] = ["starknet_syscall"]
        return meta


class SwayExtractor(TextProjectExtractor):
    language = "sway"

    def _containers(self, text: str, file_path: str) -> list[dict]:
        kind = "contract" if re.search(r"(?m)^\s*contract\s*;", text) else "module"
        return [{
            "label": Path(file_path).stem, "type": kind, "start": 0,
            "line": 1, "signature": kind,
        }]

    def _functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        spans = []
        for m in re.finditer(r"(?m)^\s*(?:pub\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>{}]*>)?\s*\(", text):
            body, end = _brace_body(text, m.end())
            decorators = _decorators_before(text, m.start(), prefix="#[")
            vis = "external" if "storage" in " ".join(decorators) else "public"
            spans.append(FunctionSpan(
                name=m.group(1), visibility=vis,
                start_line=_line_for_offset(text, m.start()),
                end_line=_line_for_offset(text, end),
                signature=text[m.start():_line_end(text, m.end())].strip(),
                body=body, scope=self._scope_for_offset(m.start(), containers),
                decorators=decorators,
            ))
        return spans

    def _state_writes(self, span: FunctionSpan) -> list[str]:
        names = re.findall(r"\bstorage\.([A-Za-z_]\w*)\.write\s*\(", span.body)
        names.extend(re.findall(r"\bstorage\.([A-Za-z_]\w*)\s*=", span.body))
        return names

    def _state_reads(self, span: FunctionSpan) -> list[str]:
        return re.findall(r"\bstorage\.([A-Za-z_]\w*)\.read\s*\(", span.body)


class TonExtractor(TextProjectExtractor):
    """Extractor for TON FunC/Fift-like sources and Tact contracts."""

    language = "ton"

    FUNC_ENTRY_NAMES = {"recv_internal", "recv_external", "run_ticktock", "split_prepare", "split_install"}
    TON_SENDS = {
        "send_raw_message", "send_message", "send_message_with_state_init_and_body",
        "send", "nativeReserve", "raw_reserve",
    }

    def _containers(self, text: str, file_path: str) -> list[dict]:
        out = []
        for m in re.finditer(r"(?m)^\s*(?:abstract\s+)?contract\s+([A-Za-z_]\w*)\b", text):
            body, end = _brace_body(text, m.end())
            out.append({
                "label": m.group(1), "type": "contract",
                "start": m.start(), "line": _line_for_offset(text, m.start()),
                "end": end,
                "end_line": _line_for_offset(text, end),
                "signature": m.group(0).strip(), "body": body,
            })
        return out

    def _state_declarations(self, text: str, scope: str) -> list[str]:
        names = []
        # Tact fields: `nonceStatus: map<Int, Int>;`
        for m in re.finditer(r"(?m)^\s*([A-Za-z_]\w*)\s*:\s*(?!Int\s*=|String\s*=|Bool\s*=)[^;{}]+\s*;", text):
            name = m.group(1)
            if name not in {"import", "message", "contract", "const"}:
                names.append(name)
        if "set_data(" in text or "get_data()" in text:
            names.append("contract_storage")
        return names

    def _functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        if file_path.endswith(".tact"):
            return self._tact_functions(text, file_path, containers)
        return self._func_functions(text, file_path, containers)

    def _func_functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        spans = []
        pattern = re.compile(
            r"(?m)^\s*(?!if\b|elseif\b|else\b|do\b|until\b|while\b|return\b)"
            r"(?P<sig>[^#/\n;{}][^\n;{}]*?\s+(?P<name>~?[A-Za-z_][\w$?]*)\s*\([^;\n{}]*\)\s*(?:impure|inline|method_id|asm|forall|[<>\w\s,.$?~]*)*)\{"
        )
        for m in pattern.finditer(text):
            name = m.group("name").lstrip("~")
            if name in CONTROL_CALLS:
                continue
            body, end = _brace_body(text, m.end() - 1)
            sig = m.group("sig").strip()
            vis = "external" if name in self.FUNC_ENTRY_NAMES else ("public" if name.startswith("get_") else "private")
            spans.append(FunctionSpan(
                name=name, visibility=vis,
                start_line=_line_for_offset(text, m.start()),
                end_line=_line_for_offset(text, end),
                signature=sig, body=body, scope=Path(file_path).stem,
            ))
        return spans

    def _tact_functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        spans = []
        patterns = [
            (re.compile(r"(?m)^\s*init\s*\("), "init", "external"),
            (re.compile(r"(?m)^\s*receive\s*\(\s*msg\s*:\s*([A-Za-z_]\w*)\s*\)"), "receive", "external"),
            (re.compile(r"(?m)^\s*bounced\s*\("), "bounced", "external"),
            (re.compile(r"(?m)^\s*get\s+fun\s+([A-Za-z_]\w*)\s*\("), "get", "public"),
            (re.compile(r"(?m)^\s*fun\s+([A-Za-z_]\w*)\s*\("), "fun", "private"),
        ]
        for pat, kind, vis in patterns:
            for m in pat.finditer(text):
                body, end = _brace_body(text, m.end())
                if kind == "receive":
                    name = f"receive_{m.group(1)}"
                elif kind in ("get", "fun"):
                    name = m.group(1)
                else:
                    name = kind
                spans.append(FunctionSpan(
                    name=name, visibility=vis,
                    start_line=_line_for_offset(text, m.start()),
                    end_line=_line_for_offset(text, end),
                    signature=text[m.start():_line_end(text, m.end())].strip(),
                    body=body, scope=self._scope_for_offset(m.start(), containers),
                ))
        return spans

    def _calls(self, span: FunctionSpan) -> list[str]:
        body = _strip_comments(span.body)
        names = super()._calls(span)
        for m in re.finditer(r"([A-Za-z_][\w$?]*)\s*~\s*([A-Za-z_][\w$?]*)\s*\(", body):
            name = m.group(2)
            if name not in names:
                names.append(name)
        return names

    def _state_writes(self, span: FunctionSpan) -> list[str]:
        body = _strip_comments(span.body)
        names = []
        if "set_data(" in body:
            names.append("contract_storage")
        names.extend(re.findall(r"\bself\.([A-Za-z_]\w*)\s*(?:[+\-*/]?=|\.set\s*\()", body))
        if any(re.search(rf"\b{re.escape(send)}\s*\(", body) for send in self.TON_SENDS):
            names.append("ton_message_flow")
        return names

    def _state_reads(self, span: FunctionSpan) -> list[str]:
        body = _strip_comments(span.body)
        names = []
        if "get_data()" in body:
            names.append("contract_storage")
        names.extend(re.findall(r"\bself\.([A-Za-z_]\w*)\b", body))
        return names

    def _metadata(self, span: FunctionSpan) -> dict:
        meta = super()._metadata(span)
        body = _strip_comments(span.body)
        sends = [s for s in self.TON_SENDS if re.search(rf"\b{re.escape(s)}\s*\(", body)]
        if sends:
            meta["transfer_sinks"] = sorted(set(meta.get("transfer_sinks", []) + sends))
            meta["cross_contract_calls"] = sorted(set(sends))
        if "accept_message" in body:
            meta["ton_accept_message"] = True
        if "throw_unless" in body or "throw_if" in body or "require(" in body:
            meta["ton_validation"] = True
        if "now()" in body or "cur_lt()" in body:
            meta["timestamp_dependence"] = ["ton_time_reference"]
        if "bounced" in span.name and body.strip() in {"{}", "{ }"}:
            meta["ignored_bounce"] = True
        return meta


class ProtoExtractor(TextProjectExtractor):
    """Extractor for protobuf schemas that define protocol/API boundaries."""

    language = "proto"

    def _containers(self, text: str, file_path: str) -> list[dict]:
        out = []
        pkg = re.search(r"(?m)^\s*package\s+([A-Za-z_][\w.]*)\s*;", text)
        if pkg:
            out.append({
                "label": pkg.group(1), "type": "package", "start": pkg.start(),
                "line": _line_for_offset(text, pkg.start()), "signature": pkg.group(0).strip(),
            })
        for m in re.finditer(r"(?m)^\s*service\s+([A-Za-z_]\w*)\s*\{", text):
            body, end = _brace_body(text, m.end() - 1)
            out.append({
                "label": m.group(1), "type": "service", "start": m.start(),
                "line": _line_for_offset(text, m.start()),
                "end": end,
                "end_line": _line_for_offset(text, end),
                "signature": m.group(0).strip(), "body": body,
            })
        return out

    def _state_declarations(self, text: str, scope: str) -> list[str]:
        return re.findall(r"(?m)^\s*message\s+([A-Za-z_]\w*)\s*\{", text)

    def _functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        spans = []
        services = [c for c in containers if c.get("type") == "service"]
        for svc in services:
            body = svc.get("body", "")
            body_start = text.find(body, svc["start"]) if body else svc["start"]
            for m in re.finditer(
                r"\brpc\s+([A-Za-z_]\w*)\s*\(\s*(stream\s+)?([A-Za-z_.]\w*)\s*\)\s*returns\s*\(\s*(stream\s+)?([A-Za-z_.]\w*)\s*\)",
                body,
            ):
                abs_start = body_start + m.start()
                abs_end = body_start + m.end()
                spans.append(FunctionSpan(
                    name=m.group(1), visibility="external",
                    start_line=_line_for_offset(text, abs_start),
                    end_line=_line_for_offset(text, abs_end),
                    signature=m.group(0), body=m.group(0), scope=svc["label"],
                    decorators=["streaming"] if m.group(2) or m.group(4) else [],
                ))
        return spans

    def _metadata(self, span: FunctionSpan) -> dict:
        meta = super()._metadata(span)
        if "stream" in span.signature:
            meta["streaming_rpc"] = True
        if re.search(r"auth|signature|challenge|proof", span.signature, re.I):
            meta["auth_boundary"] = True
        return meta


class XdrExtractor(TextProjectExtractor):
    """Extractor for Stellar/RPC XDR schema files (`.x`)."""

    language = "xdr"

    def _containers(self, text: str, file_path: str) -> list[dict]:
        out = []
        for m in re.finditer(r"(?m)^\s*namespace\s+([A-Za-z_]\w*)\s*\{", text):
            body, end = _brace_body(text, m.end() - 1)
            out.append({
                "label": m.group(1), "type": "namespace",
                "start": m.start(), "line": _line_for_offset(text, m.start()),
                "end": end,
                "end_line": _line_for_offset(text, end),
                "signature": m.group(0).strip(), "body": body,
            })
        return out

    def _state_declarations(self, text: str, scope: str) -> list[str]:
        names = []
        for pat in (
            r"(?m)^\s*struct\s+([A-Za-z_]\w*)\s*\{",
            r"(?m)^\s*enum\s+([A-Za-z_]\w*)\s*\{",
            r"(?m)^\s*union\s+([A-Za-z_]\w*)\b",
            r"(?m)^\s*typedef\s+[^;]*\s+([A-Za-z_]\w*)\s*;",
        ):
            names.extend(re.findall(pat, text))
        return names

    def _functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        spans = []
        patterns = [
            ("struct", re.compile(r"(?m)^\s*struct\s+([A-Za-z_]\w*)\s*\{")),
            ("enum", re.compile(r"(?m)^\s*enum\s+([A-Za-z_]\w*)\s*\{")),
            ("union", re.compile(r"(?m)^\s*union\s+([A-Za-z_]\w*)\b[^{;]*\{")),
        ]
        for kind, pat in patterns:
            for m in pat.finditer(text):
                body, end = _brace_body(text, m.end() - 1)
                spans.append(FunctionSpan(
                    name=m.group(1), visibility="public",
                    start_line=_line_for_offset(text, m.start()),
                    end_line=_line_for_offset(text, end),
                    signature=m.group(0).strip(),
                    body=body,
                    scope=self._scope_for_offset(m.start(), containers),
                    decorators=[kind],
                ))
        return spans

    def _calls(self, span: FunctionSpan) -> list[str]:
        # XDR schemas are type declarations, not executable call graphs.
        return []

    def _state_reads(self, span: FunctionSpan) -> list[str]:
        fields = []
        for line in _strip_comments(span.body).splitlines():
            line = line.strip().rstrip(";")
            if not line or line.startswith(("case ", "default:", "void")):
                continue
            m = re.search(r"\b([A-Za-z_]\w*)\s*(?:<[^>]*>|\[[^\]]*\])?\s*$", line)
            if m:
                fields.append(m.group(1))
        return fields[:50]

    def _metadata(self, span: FunctionSpan) -> dict:
        meta = super()._metadata(span)
        kind = span.decorators[0] if span.decorators else "type"
        meta["schema_kind"] = kind
        body_lower = span.body.lower()
        name_lower = span.name.lower()
        if any(token in body_lower or token in name_lower for token in ("auth", "signature", "signer", "credential", "verifier")):
            meta["auth_boundary"] = True
        if any(token in body_lower or token in name_lower for token in ("ledger", "transaction", "operation", "account", "contract")):
            meta["protocol_state_schema"] = True
        if kind == "union" and ("switch" in body_lower or "switch" in span.signature.lower()):
            meta["variant_switch"] = True
        return meta


class TypeScriptExtractor(TextProjectExtractor):
    language = "typescript"

    def _default_scope(self, file_path: str, containers: list[dict]) -> str:
        return ""

    def _containers(self, text: str, file_path: str) -> list[dict]:
        out = []
        for m in re.finditer(r"(?m)^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)\b", text):
            body, end = _brace_body(text, m.end())
            out.append({
                "label": m.group(1), "type": "class", "start": m.start(),
                "line": _line_for_offset(text, m.start()),
                "end": end,
                "end_line": _line_for_offset(text, end),
                "signature": m.group(0).strip(),
                "body": body,
            })
        return out

    def _functions(self, text: str, file_path: str, containers: list[dict]) -> list[FunctionSpan]:
        spans = []
        seen: set[int] = set()
        patterns = [
            re.compile(r"(?m)^\s*(export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("),
            re.compile(r"(?m)^\s*(export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"),
            re.compile(r"(?m)^\s*(?:(public|private|protected)\s+)?(?:static\s+)?(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?::[^={]+)?\s*\{"),
        ]
        for pat in patterns:
            for m in pat.finditer(text):
                if m.start() in seen:
                    continue
                name = m.group(2)
                if name in CONTROL_CALLS or name in {"constructor", "if", "for", "while", "switch"}:
                    continue
                seen.add(m.start())
                body, end = _brace_body(text, m.end())
                prefix = m.group(1) or ""
                vis = "private" if prefix == "private" or name.startswith("_") else "public"
                spans.append(FunctionSpan(
                    name=name, visibility=vis,
                    start_line=_line_for_offset(text, m.start()),
                    end_line=_line_for_offset(text, end),
                    signature=text[m.start():_line_end(text, m.end())].strip(),
                    body=body, scope=self._scope_for_offset(m.start(), containers),
                ))
        return spans

    def _state_writes(self, span: FunctionSpan) -> list[str]:
        names = []
        if re.search(r"\b(sendTransaction|sendAndConfirmTransaction|signAndSendTransaction)\s*\(", span.body):
            names.append("chain_transaction")
        if re.search(r"\bcreate[A-Za-z0-9_]*Instruction\s*\(", span.body):
            names.append("program_instruction")
        return names

    def _state_reads(self, span: FunctionSpan) -> list[str]:
        names = []
        if re.search(r"\b(getAccountInfo|getBalance|getProgramAccounts|getStorageAt|callStatic)\s*\(", span.body):
            names.append("chain_state")
        return names

    def _metadata(self, span: FunctionSpan) -> dict:
        meta = super()._metadata(span)
        if re.search(r"\b(PRIVATE_KEY|secretKey|fromSecretKey|mnemonic|Keypair\.generate)\b", span.body):
            meta["private_key_material"] = True
        if re.search(r"\b(sendTransaction|sendAndConfirmTransaction|signAndSendTransaction)\s*\(", span.body):
            meta["cross_contract_calls"] = ["client_transaction_submit"]
        if "JSON.parse" in span.body:
            meta["deserialization_sinks"] = ["JSON.parse"]
        return meta


class PythonExtractor(BaseExtractor):
    language = "python"

    def extract_from_source(self, source_code: bytes, file_path: str) -> ExtractResult:
        text = _decode(source_code)
        try:
            tree = ast.parse(text, filename=file_path)
        except SyntaxError:
            return ExtractResult()
        result = ExtractResult()
        lines = text.splitlines()
        self._extract_body(tree.body, file_path, result, lines, scope="")
        return result

    def extract(self, tree, source_code: bytes, file_path: str) -> ExtractResult:
        return self.extract_from_source(source_code, file_path)

    def _extract_body(self, body, file_path: str, result: ExtractResult,
                      lines: list[str], scope: str):
        for node in body:
            if isinstance(node, ast.ClassDef):
                class_id = self._make_node_id(file_path, node.name)
                result.nodes.append({
                    "id": class_id, "label": node.name, "type": "class",
                    "visibility": "public", "file": file_path,
                    "line_start": node.lineno, "line_end": getattr(node, "end_lineno", node.lineno),
                    "signature": f"class {node.name}",
                    "metadata": json.dumps({"language": self.language}),
                })
                self._extract_body(node.body, file_path, result, lines, scope=node.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._extract_function(node, file_path, result, lines, scope)

    def _extract_function(self, node, file_path: str, result: ExtractResult,
                          lines: list[str], scope: str):
        symbol = f"{scope}.{node.name}" if scope else node.name
        func_id = self._make_node_id(file_path, symbol)
        vis = "private" if node.name.startswith("_") else "public"
        start = node.lineno
        end = getattr(node, "end_lineno", node.lineno)
        body_text = "\n".join(lines[start - 1:end])
        meta = self._metadata_for_python(node, body_text)
        result.nodes.append({
            "id": func_id, "label": node.name, "type": "function",
            "visibility": vis, "file": file_path,
            "line_start": start, "line_end": end,
            "signature": self._signature(node), "metadata": json.dumps(meta),
        })
        if scope:
            result.edges.append({
                "source": self._make_node_id(file_path, scope), "target": func_id,
                "relation": "contains", "attributes": "{}",
            })

        for call_name in self._python_calls(node):
            result.edges.append({
                "source": func_id, "target": f"_::{call_name}",
                "relation": "calls",
                "attributes": json.dumps({
                    "unresolved": True,
                    "call_name": call_name,
                    "language": self.language,
                    "internal_candidate": True,
                }),
            })

        for state_name in self._python_state_writes(node):
            state_id = self._make_node_id(file_path, f"{scope}.{state_name}" if scope else state_name)
            result.nodes.append({
                "id": state_id, "label": state_name, "type": "state_var",
                "visibility": "", "file": file_path,
                "line_start": 0, "line_end": 0, "signature": "",
                "metadata": json.dumps({"language": self.language}),
            })
            result.edges.append({
                "source": func_id, "target": state_id,
                "relation": "writes_state",
                "attributes": json.dumps({"language": self.language}),
            })

    def _signature(self, node) -> str:
        args = [a.arg for a in node.args.args]
        prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
        return f"{prefix} {node.name}({', '.join(args)})"

    def _call_name(self, func) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return ""

    def _python_calls(self, node) -> list[str]:
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._call_name(child.func)
                if name and name not in CONTROL_CALLS and name not in calls:
                    calls.append(name)
        return calls

    def _python_state_writes(self, node) -> list[str]:
        names = []
        for child in ast.walk(node):
            if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                for target in targets:
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                        names.append(target.attr)
            elif isinstance(child, ast.Call):
                name = self._call_name(child.func)
                if name in {"commit", "save", "write", "execute", "add"}:
                    names.append("persistent_state")
        return sorted(set(names))

    def _metadata_for_python(self, node, body_text: str) -> dict:
        meta: dict = {"language": self.language}
        if isinstance(node, ast.AsyncFunctionDef):
            meta["async"] = True
        if node.args.args and not any(isinstance(n, (ast.Assert, ast.Raise, ast.If)) for n in ast.walk(node)):
            meta["no_input_validation"] = True

        command_risks = []
        deser = []
        sql = []
        crypto = []
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            full = self._python_full_call_name(child.func)
            if full in {"os.system", "subprocess.call", "subprocess.run", "subprocess.Popen"}:
                shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in child.keywords)
                command_risks.append({"call": full, "shell": shell_true})
            if full in {"pickle.load", "pickle.loads", "yaml.load", "marshal.loads"}:
                deser.append(full)
            if self._call_name(child.func) in {"execute", "executemany"}:
                if child.args and isinstance(child.args[0], (ast.JoinedStr, ast.BinOp)):
                    sql.append("dynamic_sql")
            if full in {"hashlib.md5", "hashlib.sha1", "random.random", "random.randrange"}:
                crypto.append(full)

        if command_risks:
            meta["command_injection_risk"] = command_risks
        if deser:
            meta["deserialization_sinks"] = sorted(set(deser))
        if sql:
            meta["sql_injection_risk"] = sorted(set(sql))
        if crypto:
            meta["weak_crypto"] = sorted(set(crypto))
        if re.search(r"\b(private_key|secret_key|mnemonic|seed_phrase)\b", body_text, re.I):
            meta["private_key_material"] = True
        return meta

    def _python_full_call_name(self, func) -> str:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            base = self._python_full_call_name(func.value)
            return f"{base}.{func.attr}" if base else func.attr
        return ""
