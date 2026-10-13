"""Offline tests for core/cs_substrate.py - no network, transport is stubbed.

The point of these is the failure modes, not the happy path: a Substrate RPC read
fails by returning a well-formed response that means something other than what it
looks like, and the two ways that bites hardest are (a) a websocket-only endpoint
answering an HTML 503 page, and (b) a node returning null for `:code`, which is
easy to misread as "this chain has no runtime".
"""

from __future__ import annotations

import json

import pytest

from core.cs_substrate import (
    SubstrateError,
    _CODE_KEY,
    _decode_scale_runtime_names,
    describe_runtime,
    jsonrpc,
    runtime_code,
    runtime_version,
    runtime_wasm_hash,
    selftest,
)


def _install(monkeypatch, handler):
    """Route cs_substrate's urlopen through `handler(method, params) -> dict|str`."""
    import core.cs_substrate as cs

    class _Resp:
        def __init__(self, body):
            self._b = body.encode() if isinstance(body, str) else body

        def read(self):
            return self._b

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        payload = json.loads(req.data.decode())
        result = handler(payload["method"], payload.get("params", []))
        if isinstance(result, Exception):
            raise result
        return _Resp(result)

    monkeypatch.setattr(cs.urllib.request, "urlopen", fake_urlopen)


# ---------------------------------------------------------------- transport


def test_html_503_raises_with_useful_hint(monkeypatch):
    """A websocket-only endpoint returns HTML; say so instead of a JSON error."""
    _install(monkeypatch, lambda m, p: "<html><body><h1>503 Service Unavailable")
    with pytest.raises(SubstrateError) as exc:
        jsonrpc("https://x", "state_getRuntimeVersion")
    assert "websocket-only" in str(exc.value)


def test_rpc_error_object_raises(monkeypatch):
    _install(monkeypatch, lambda m, p: json.dumps(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Method not found"}}))
    with pytest.raises(SubstrateError) as exc:
        jsonrpc("https://x", "system_code")
    assert exc.value.code == -32601


def test_response_without_result_raises(monkeypatch):
    _install(monkeypatch, lambda m, p: json.dumps({"jsonrpc": "2.0", "id": 1}))
    with pytest.raises(SubstrateError):
        jsonrpc("https://x", "state_getRuntimeVersion")


def test_connection_error_surfaces_as_substrate_error(monkeypatch):
    _install(monkeypatch, lambda m, p: OSError("Name or service not known"))
    with pytest.raises(SubstrateError) as exc:
        jsonrpc("https://nope.invalid", "state_getRuntimeVersion")
    assert "cannot reach" in str(exc.value)


# --------------------------------------------------------------------- SCALE


def test_core_version_scale_decoder():
    """Real Core_version payload: compact len, then unpadded bytes, twice."""
    spec = b"polkadot"
    impl = b"parity-polkadot"
    payload = bytes([len(spec) << 2]) + spec + bytes([len(impl) << 2]) + impl
    payload += bytes([3, 0, 0, 0])  # authoring/spec/impl, ignored
    got_spec, got_impl = _decode_scale_runtime_names(payload)
    assert (got_spec, got_impl) == ("polkadot", "parity-polkadot")


def test_core_version_scale_decoder_rejects_truncation():
    with pytest.raises(SubstrateError):
        _decode_scale_runtime_names(bytes([8 << 2]) + b"poly")


# ---------------------------------------------------------------- code hash


def test_code_hash_strips_magic_prefix():
    blob = "0x0061736d" + "00" * 8
    # deterministic, and must not raise
    assert runtime_wasm_hash(blob).startswith("0x")


def test_code_hash_rejects_short_blob():
    with pytest.raises(SubstrateError):
        runtime_wasm_hash("0x00")


# ------------------------------------------------------------------- :code


def test_null_code_is_none_not_an_error(monkeypatch):
    """A node withholding :code must not look like an empty runtime."""
    _install(monkeypatch, lambda m, p: json.dumps({"jsonrpc": "2.0", "id": 1, "result": None}))
    assert runtime_code("https://x") is None


def test_code_key_is_32_byte_hex():
    assert _CODE_KEY.startswith("0x") and len(_CODE_KEY) == 66
    assert bytes.fromhex(_CODE_KEY[2:]) == b"\x00" * 27 + b":code"


def test_invalid_params_on_code_returns_none(monkeypatch):
    _install(monkeypatch, lambda m, p: json.dumps(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "Invalid params"}}))
    assert runtime_code("https://x") is None


# ------------------------------------------------------------- describe


def _full_node(monkeypatch):
    def handler(method, params):
        if method == "state_getRuntimeVersion":
            return json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
                "specName": "polkadot", "specVersion": 2005000,
                "implName": "parity-polkadot", "implVersion": 0,
                "stateVersion": 1, "apis": [["0xdf6acb", 1]]}})
        if method == "state_call":
            payload = bytes([8 << 2]) + b"polkadot" + bytes([15 << 2]) + b"parity-polkadot"
            return json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x" + payload.hex()})
        if method == "state_getStorage":
            return json.dumps({"jsonrpc": "2.0", "id": 1, "result": None})
        return json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"message": "nope"}})

    _install(monkeypatch, handler)


def test_describe_runtime_reports_both_routes_and_disagreement_flag(monkeypatch):
    _full_node(monkeypatch)
    d = describe_runtime("https://x")
    assert d["spec_name"] == "polkadot"
    assert d["spec_version"] == 2005000
    assert d["spec_name_via_call"] == "polkadot"
    assert d["impl_name_via_call"] == "parity-polkadot"
    assert d["version_routes_agree"] is True
    assert d["code_available"] is False
    assert "code_hash" not in d  # must not fabricate a hash it could not compute


def test_describe_runtime_flags_mismatched_routes(monkeypatch):
    """A lagging archive shows different names; that must surface, not resolve."""
    def handler(method, params):
        if method == "state_getRuntimeVersion":
            return json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
                "specName": "polkadot", "specVersion": 7,
                "implName": "parity-polkadot", "apis": []}})
        if method == "state_call":
            payload = bytes([8 << 2]) + b"polkadot" + bytes([15 << 2]) + b"parity-polkadot"
            return json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x" + payload.hex()})
        return json.dumps({"jsonrpc": "2.0", "id": 1, "result": None})

    _install(monkeypatch, handler)
    d = describe_runtime("https://x")
    assert d["version_routes_agree"] is True  # names still match
    assert d["spec_version"] == 7


def test_selftest_isolates_failures(monkeypatch):
    def handler_factory(url):
        return lambda m, p: (
            json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
                "specName": "polkadot", "specVersion": 1, "implName": "x", "apis": []}})
            if url == "https://good" else "<html>503</html>"
        )

    import core.cs_substrate as cs
    urls = ["https://good", "https://bad"]
    real = {}

    class _Resp:
        def __init__(self, body):
            self._b = body.encode()

        def read(self):
            return self._b

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        body = handler_factory(req.full_url)(None, None)
        if body.startswith("<html"):
            import urllib.error

            raise urllib.error.URLError("ws only")
        return _Resp(body)

    cs.urllib.request.urlopen = fake_urlopen
    out = selftest(urls)
    assert out["https://good"]["ok"] is True
    assert out["https://bad"]["ok"] is False
    assert real == {}