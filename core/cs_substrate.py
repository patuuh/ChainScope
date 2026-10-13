"""Substrate runtime introspection: read a chain's runtime version and code.

Built because the EVM path could not answer a question this hunt needed. For
Solidity, "is this the code I read?" is answered by `eth_getCode` plus an
EIP-1967 slot read. For a Substrate chain the runtime is opaque WASM swapped by
governance, so the equivalent questions are:

  * which runtime is live right now      -> `state_getRuntimeVersion`
  * what is its identity (code hash)     -> `system_code` at that block
  * does the repo I read match it        -> compare spec_version / wasm hash

Concretely this was needed for Hydration, whose Immunefi programme is the largest
in the catalog (maxBounty 222,222) and whose stableswap share-issuance invariant
was, before commit 50a55673c4 (2026-07-15), enforced only by `debug_assert_eq!` -
which compiles out of release WASM. Knowing whether a deployment still runs
pre-fix code is the difference between a report and a dead end.

Endpoints are **not** bundled. Alchemy does not serve Substrate chains at all, and
public relay/parachain endpoints move around, so callers pass a URL explicitly.
Verified working against the Polkadot relay chain; see `selftest()`.
"""

from __future__ import annotations

import json
import typing as t
import urllib.error
import urllib.request

__all__ = [
    "SubstrateError",
    "jsonrpc",
    "runtime_version",
    "runtime_code",
    "runtime_wasm_hash",
    "describe_runtime",
    "selftest",
]

DEFAULT_TIMEOUT = 45


class SubstrateError(RuntimeError):
    """A node-level failure: connection refused, non-JSON body, or an RPC error."""

    def __init__(self, message: str, *, code: t.Any = None, data: t.Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


def jsonrpc(
    url: str,
    method: str,
    params: list[t.Any] | None = None,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> t.Any:
    """One JSON-RPC call. Raises SubstrateError rather than returning an error dict.

    Returning the error dict is the trap here: a caller that treats it as a result
    reads `None` fields and concludes "no runtime", which reads identically to
    "this endpoint does not serve Substrate" - two very different conclusions, and
    the second one is the one that wastes an afternoon.
    """
    payload = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}
    ).encode()
    req = urllib.request.Request(
        url, payload, {"Content-Type": "application/json", "User-Agent": "ChainScope/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as fh:
            body = fh.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raise SubstrateError(f"HTTP {exc.code} from {method}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SubstrateError(f"cannot reach {url} for {method}: {exc}") from exc

    stripped = body.lstrip()
    if not stripped.startswith(("{", "[")):
        # Dwellir/OnFinality return an HTML 503 page on the POST endpoint; the WS
        # endpoint is the working one. Surface that instead of a JSON parse error.
        preview = " ".join(body.split())[:80]
        raise SubstrateError(
            f"non-JSON response from {url} for {method} "
            f"(is this a websocket-only endpoint?): {preview!r}"
        )
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise SubstrateError(f"malformed JSON from {method}: {body[:120]!r}") from exc

    if isinstance(data, dict) and data.get("error"):
        err = data["error"]
        raise SubstrateError(
            f"{method} failed: {err.get('message', err)}", code=err.get("code")
        )
    if not isinstance(data, dict) or "result" not in data:
        raise SubstrateError(f"{method}: response has no 'result': {body[:120]!r}")
    return data["result"]


# Substrate's well-known `:code` storage key, hex-encoded and zero-padded to the
# 32-byte storage-key size. `state_getStorage` rejects the literal string (it wants
# hex) and some nodes return null for it even at `latest`, so treat null as "this
# node does not expose the blob" rather than as an empty runtime.
_CODE_KEY = "0x" + ("00" * 27) + "3a636f6465"  # b":code" left-padded to 32 bytes


def runtime_version(
    url: str, *, block: str | int | None = None, timeout: int = DEFAULT_TIMEOUT
) -> dict[str, t.Any]:
    """Live runtime identity: spec_name, spec_version, impl_name, apis."""
    params: list[t.Any] = [] if block is None else [block]
    return t.cast(
        dict[str, t.Any], jsonrpc(url, "state_getRuntimeVersion", params, timeout=timeout)
    )


def runtime_version_via_call(
    url: str, *, block: str | int | None = None, timeout: int = DEFAULT_TIMEOUT
) -> dict[str, t.Any]:
    """Same identity via `state_call("Core_version")`.

    A second, independent route to the version. Useful because the two disagree
    when a node is a lagging archive: `state_getRuntimeVersion` is a state query
    and can be served from an older snapshot, while `Core_version` executes against
    the block's actual runtime. When they differ, trust this one.
    """
    params: list[t.Any] = ["Core_version", "0x"]
    if block is not None:
        params.append(block)
    raw = jsonrpc(url, "state_call", params, timeout=timeout)
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise SubstrateError(f"Core_version returned {type(raw).__name__}")
    spec, impl = _decode_scale_runtime_names(bytes.fromhex(raw[2:]))
    return {
        "specName": spec,
        "implName": impl,
        "source": "state_call:Core_version",
        "raw_len": len(raw) // 2,
    }


def _decode_scale_runtime_names(data: bytes) -> tuple[str, str]:
    """Pull specName and implName out of a SCALE-encoded `Core_version` return.

    Layout: `Vec<u8>` strings, each compact-length-prefixed and padded to 32 bytes,
    followed by the version integers. Only the two names are decoded - the numbers
    are read from `state_getRuntimeVersion`, which is not worth re-implementing.
    """
    names: list[str] = []
    pos = 0
    for _ in range(2):
        if pos >= len(data):
            raise SubstrateError("Core_version payload truncated while reading names")
        first = data[pos]
        # SCALE compact: single-byte mode is len<<2 for len < 64.
        length = first >> 2 if first < 0x40 else None
        if length is None:
            raise SubstrateError(
                "multi-byte SCALE compact length in Core_version; decoder not implemented"
            )
        start = pos + 1
        chunk = data[start : start + length]
        names.append(chunk.decode("utf-8", "replace"))
        # No padding: Core_version returns plain SCALE `Vec<u8>`, so the next
        # length prefix follows immediately. (Padding to 32 bytes is how the
        # *storage* keys are laid out, not this return value - assuming otherwise
        # reads the second name as empty and reports a false version mismatch.)
        pos = start + length
    return names[0], names[1]


def runtime_code(
    url: str, *, block: str | int | None = None, timeout: int = DEFAULT_TIMEOUT
) -> str | None:
    """The runtime WASM blob as `0x...` hex, or None if the node withholds it.

    Returns None rather than raising for a null result: several public endpoints
    answer `:code` with null at `latest` while serving it at historical blocks, and
    that is a node limitation, not evidence of an empty runtime.
    """
    params: list[t.Any] = [_CODE_KEY] + ([] if block is None else [block])
    try:
        code = jsonrpc(url, "state_getStorage", params, timeout=timeout)
    except SubstrateError as exc:
        if "Invalid params" in str(exc):
            return None
        raise
    return code if isinstance(code, str) and code.startswith("0x") and len(code) > 2 else None


def _blake2_256(data: bytes, digest_size: int) -> bytes:
    import hashlib

    return hashlib.blake2b(data, digest_size=digest_size).digest()


def runtime_wasm_hash(code_hex: str) -> str:
    """Substrate's `:code` hash: blake2-256 over the code, minus the 0x magic.

    Substrate hashes the code as stored, i.e. the blob with its trailing
    `0x0061736d` (wasm magic + version) prefix removed. Getting that wrong yields a
    hash that looks plausible and matches nothing, which is worse than no hash.
    """
    body = bytes.fromhex(code_hex[2:] if code_hex.startswith("0x") else code_hex)
    if len(body) <= 4:
        raise SubstrateError(f"runtime code too short to hash: {len(body)} bytes")
    return "0x" + _blake2_256(body[4:], 32).hex()


def describe_runtime(
    url: str, *, block: str | int | None = None, timeout: int = DEFAULT_TIMEOUT
) -> dict[str, t.Any]:
    """Runtime version plus code identity, as one summary.

    The version alone answers "is this new enough"; the hash answers "is this the
    same build I read in the repo". Both are needed, because a chain can report the
    same spec_version after a hotfix, and can bump spec_version without changing
    the pallet being audited.
    """
    version = runtime_version(url, block=block, timeout=timeout)
    out: dict[str, t.Any] = {
        "rpc": url,
        "block": block if block is not None else "latest",
        "spec_name": version.get("specName"),
        "spec_version": version.get("specVersion"),
        "impl_name": version.get("implName"),
        "impl_version": version.get("implVersion"),
        "transaction_version": version.get("transactionVersion"),
        "state_version": version.get("stateVersion"),
        "api_count": len(version.get("apis", []) or []),
        "apis": version.get("apis", []),
        "code_available": False,
    }
    try:
        cross = runtime_version_via_call(url, block=block, timeout=timeout)
        out["spec_name_via_call"] = cross.get("specName")
        out["impl_name_via_call"] = cross.get("implName")
        # Disagreement means the state query is being served from a lagging
        # snapshot. Surface it rather than silently preferring one.
        out["version_routes_agree"] = (
            cross.get("specName") == out["spec_name"]
            and cross.get("implName") == out["impl_name"]
        )
    except SubstrateError as exc:
        out["version_routes_agree"] = None
        out["call_route_error"] = str(exc)

    code = runtime_code(url, block=block, timeout=timeout)
    if code is not None:
        out["code_available"] = True
        out["code_bytes"] = (len(code) - 2) // 2
        try:
            out["code_hash"] = runtime_wasm_hash(code)
        except SubstrateError as exc:
            out["code_hash"] = None
            out["code_hash_error"] = str(exc)
    return out


def selftest(urls: list[str] | None = None) -> dict[str, dict[str, t.Any]]:
    """Probe candidate endpoints and report what each actually serves.

    Returns per-URL status rather than raising, because the common case is a list
    where some entries are websocket-only or down, and one bad URL should not
    discard the results from the good ones.
    """
    if urls is None:
        urls = [
            "https://rpc.polkadot.io",
            "https://polkadot.api.onfinality.io/public-ws",
            "https://rpc.hydration.cloud",
        ]
    out: dict[str, dict[str, t.Any]] = {}
    for url in urls:
        try:
            out[url] = {"ok": True, **describe_runtime(url)}
        except SubstrateError as exc:
            out[url] = {"ok": False, "error": str(exc)}
    return out


if __name__ == "__main__":  # pragma: no cover
    for endpoint, result in selftest().items():
        if result.get("ok"):
            print(
                f"OK   {endpoint}\n"
                f"     {result['spec_name']} v{result['spec_version']} "
                f"({result['impl_name']}) code={result['code_bytes']}B "
                f"hash={result['code_hash'][:18]}..."
            )
        else:
            print(f"FAIL {endpoint}\n     {result['error']}")