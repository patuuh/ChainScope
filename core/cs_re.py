"""Bytecode reverse engineering for target triage.

Most of the interesting surface is not published as source. Gamma, MetaLend and
Arcadia's live versions all served bytecode with no verifiable source, and that
is where triage stalled repeatedly: we could not tell whether a program was
reviewable at all, and burned real time finding out. Sourcify coverage exists but
is patchy, and a Sourcify entry is not proof the entry matches what is live -
Arcadia's AccountV4 verified on Sourcify while the deployed bytecode differed from
the repository.

So this module reconstructs *structure* from deployed bytecode:

  * function selector extraction and 4byte resolution
  * interface inference (ERC20/721/1155/4626/7579/Ownable/AccessControl/Proxy)
  * proxy resolution: EIP-1967, EIP-1167 minimal, EIP-1822 UUPS, beacon, clones
  * EIP-2535 diamond facets - the case that byte-for-byte selector matching
    cannot see through, because the logic lives in facet contracts registered in
    storage and appears in no reachable bytecode
  * dangerous opcode usage (DELEGATECALL, SELFDESTRUCT, CREATE2, CALLCODE)
  * storage slot inventory, constructor immutables, opcode histograms
  * differential comparison of two contracts' bytecode

The honest limit, stated once here because it governs every result: this recovers
structure, not meaning. It can tell you a contract exposes an unguarded sweep; it
cannot tell you whether the sweep is safe. Every function here is a filter for
what a human then reads.

Nothing in this module infers a verdict. It reports what is present and what is
absent, and marks UNKNOWN where the bytecode cannot decide.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import typing as t
from pathlib import Path

# --------------------------------------------------------------------------- #
# known interfaces
# --------------------------------------------------------------------------- #

# Required signature sets used for inference. A signature must be matched exactly
# after 4byte resolution; a name-only match is not evidence, because thousands of
# contracts share `owner()` while plenty of unverified contracts also expose a
# `name()` and nothing else.
INTERFACES: dict[str, dict[str, t.Any]] = {
    "ERC4626": {
        "required": [
            "totalAssets()", "convertToShares(uint256)", "convertToAssets(uint256)",
            "maxDeposit(address)", "previewDeposit(uint256)", "maxMint(address)",
            "previewMint(uint256)", "maxWithdraw(address)", "previewWithdraw(uint256)",
            "maxRedeem(address)", "previewRedeem(uint256)",
        ],
        "threshold": 0.8,
    },
    "ERC20": {
        "required": [
            "totalSupply()", "balanceOf(address)", "transfer(address,uint256)",
            "transferFrom(address,address,uint256)", "approve(address,uint256)",
            "allowance(address,address)",
        ],
        "threshold": 0.85,
    },
    "ERC721": {
        "required": [
            "balanceOf(address)", "ownerOf(uint256)", "approve(address,uint256)",
            "getApproved(uint256)", "setApprovalForAll(address,bool)",
            "isApprovedForAll(address,address)",
        ],
        "threshold": 0.85,
    },
    "ERC1155": {
        "required": [
            "balanceOf(address,uint256)", "balanceOfBatch(address[],uint256[])",
            "setApprovalForAll(address,bool)", "isApprovedForAll(address,address)",
            "safeTransferFrom(address,address,uint256,uint256,bytes)",
        ],
        "threshold": 0.8,
    },
    "Ownable": {
        "required": ["owner()", "renounceOwnership()", "transferOwnership(address)"],
        "threshold": 0.99,
    },
    "AccessControl": {
        "required": [
            "hasRole(bytes32,address)", "getRoleAdmin(bytes32)",
            "grantRole(bytes32,address)", "revokeRole(bytes32,address)",
            "renounceRole(bytes32,address)",
        ],
        "threshold": 0.8,
    },
    "Pausable": {
        "required": ["paused()", "pause()", "unpause()"],
        "threshold": 0.99,
    },
    "UUPSProxy": {
        "required": ["upgradeTo(address)", "upgradeToAndCall(address,bytes)"],
        "threshold": 0.99,
    },
    "ERC7579": {
        "required": [
            "execute(address,uint256,bytes)", "executeFromExecutor(bytes32,bytes)",
        ],
        "threshold": 0.99,
    },
    "Permit2": {
        "required": ["permit(address,address,address,uint256,uint256,bytes)",
                     "transferFrom(address,address,uint160,address)"],
        "threshold": 0.5,
    },
}

# Selectors, not names, are what we can trust from a bare function list.
DANGEROUS_OPS = {
    "DELEGATECALL": 0xF4,
    "CALLCODE": 0xF2,
    "SELFDESTRUCT": 0xFF,
    "CREATE2": 0xF5,
    "CREATE": 0xF0,
    "SSTORE": 0x55,
    "CALL": 0xF1,
}
DANGEROUS_REASONS = {
    "DELEGATECALL": "runs external code in this contract's storage",
    "CALLCODE": "deprecated, executes foreign code in caller storage",
    "SELFDESTRUCT": "can destroy the contract and force-send its balance",
    "CREATE2": "deterministic deployment; relevant to clone/factory front-running",
    "CREATE": "deploys a child contract",
    "SSTORE": "state write",
    "CALL": "value or control transfer",
}

# EIP-1967 / EIP-1822 / beacon slots
SLOT_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
# EIP-1167 minimal proxy runtime: 363d3d373d3d3d363d73<impl>5af43d82803e903d91602b57fd5bf3
# EIP-1167 minimal proxy runtime is a fixed 45-byte shape:
#   363d3d373d3d3d363d73 <20-byte impl> 5af43d82803e903d91602b57fd5bf3
# Some clones (OpenZeppelin/0age variants) differ only by an extra PUSH prefix,
# so a second shape is accepted.
_HEX40 = r"[0-9a-fA-F]{40}"
# Anchored at BOTH ends on purpose. An EIP-1167 runtime is exactly 45 bytes;
# a longer contract merely starting with that prefix is something else, and
# calling it an immutable proxy would understate an upgradeable one.
_MP_TAIL = r"5af43d82803e903d91602b57fd5bf3"
MINIMAL_PROXY_RE = re.compile(rf"^363d3d373d3d3d363d73({_HEX40}){_MP_TAIL}$", re.I)
CLONE_RE = re.compile(rf"^(?:3d3d3d3d)?363d3d37363d73({_HEX40}){_MP_TAIL}$", re.I)


class REError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# bytecode parsing
# --------------------------------------------------------------------------- #

# `cast call` does NOT return raw hex by default. It renders values human-readably:
#   139264475815180962450438490 [1.392e26]
# An earlier revision assumed `0x` + 64 hex and matched on that, so EVERY numeric
# comparison silently failed: the value filter reported live vaults as empty, and
# the uninit corroboration check could never reject. Parse properly instead.
_CAST_ANNOT = re.compile(r"\s*\[[0-9.eE+-]+\]\s*$")


def to_int(out: str) -> int | None:
    """Parse a `cast call` result into an int, whatever form cast rendered it."""
    if out is None:
        return None
    val = _CAST_ANNOT.sub("", out.strip()).strip()
    if not val:
        return None
    if val.startswith("0x") or val.startswith("0X"):
        body = val[2:]
        return int(body, 16) if body else 0
    try:
        return int(val, 10)
    except ValueError:
        return None


def to_addr(out: str) -> str | None:
    """Extract an address from a `cast call` result."""
    if not out:
        return None
    val = _CAST_ANNOT.sub("", out.strip()).strip()
    m = re.search(r"0x[a-fA-F0-9]{40}", val)
    return m.group(0) if m else None


def _strip_hex(h: str) -> str:
    h = (h or "").strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return re.sub(r"[^0-9a-fA-F]", "", h)


def iter_opcodes(code_hex: str) -> t.Iterator[tuple[int, str]]:
    """Yield exactly one (opcode, push_data) pair per instruction.

    Skipping PUSH payload is the whole game: a naive scan of hex pairs reports
    payload bytes as opcodes, which is how selector extraction ends up with
    nonsense.

    One yield per instruction, not two. Yielding PUSH twice (once bare, once with
    its data) makes any consumer that tallies opcodes count every PUSH twice, which
    quietly inflates opcode histograms and distorts the differential deltas.
    """
    h = _strip_hex(code_hex)
    i = 0
    n = len(h)
    while i + 2 <= n:
        op = int(h[i:i + 2], 16)
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            size = op - 0x5F
            data = h[i + 2:i + 2 + size * 2]
            yield op, data
            i += 2 + size * 2
        else:
            yield op, ""
            i += 2


def _selector(sig: str) -> str:
    """4-byte selector for a signature, via `cast sig` (keeps keccak out of deps)."""
    ok, out = _cast(["sig", sig])
    s = out.strip()
    if not ok or not s.startswith("0x") or len(s) != 10:
        raise ValueError(f"could not compute selector for {sig!r}: {out!r}")
    return s


def extract_selectors(code_hex: str, dispatcher_fraction: float = 0.5) -> dict[str, t.Any]:
    """Pull PUSH4 constants, split into dispatcher-region candidates and other constants.

    .. warning::
       **This is a constant scan, not a function list.** Do not treat
       ``dispatcher`` as the contract's ABI, and do not report a deployed-vs-source
       divergence on the strength of this function alone.

       A legacy dispatcher compares the calldata selector directly and stores each
       selector as a ``PUSH4`` immediate. Modern solc instead builds a **binary
       search over range comparisons** (``GT``/``LE`` chains), so the ``PUSH4``
       values sitting in the dispatcher region are comparison *bounds*. A selector
       being dispatched correctly frequently has no literal in the code at all,
       and a bound can coincidentally equal some unrelated known selector.

       Verified against IPOR's deployed PowerToken implementation
       (`0x78DBF1EA..`, Sourcify ``runtimeMatch: match``): this scan reported 42
       "selectors", all of which resolved to plausible signatures via 4byte. On-chain
       probing shows the real surface is very different - ``transfer``,
       ``transferFrom``, ``allowance``, ``nonces``, ``delegate`` and ``approve`` all
       **revert**, because ``PowerToken`` does not inherit ERC20 and is a
       non-transferable staking receipt. Several of the "resolved" entries were
       bounds that merely happened to match a well-known selector.

    PUSH4 values past the dispatcher region are still separated into
    ``other_constants``, since those are usually coincidental 4-byte windows of
    unrelated data.

    For ground truth on which functions actually exist, use :func:`probe_selectors`
    (behavioural, via ``eth_call``) or Sourcify.
    """
    h = _strip_hex(code_hex)
    total = len(h) // 2
    cutoff = max(64, int(total * dispatcher_fraction))
    dispatcher: list[str] = []
    elsewhere: list[str] = []
    seen: set[str] = set()
    offset = 0
    for op, data in iter_opcodes(code_hex):
        # `offset` is a byte position; comparing it against a byte-length cutoff is
        # what the dispatcher-region split is meant to do. (An earlier version
        # compared the *opcode index* against a byte count, which silently
        # misclassified constants whenever the two units drifted apart.)
        if op == 0x63 and data and len(data) == 8:  # PUSH4
            sel = "0x" + data.lower()
            if sel not in seen:
                seen.add(sel)
                (dispatcher if offset <= cutoff else elsewhere).append(sel)
        offset += 1 + len(data) // 2 if data else 1
    return {
        "dispatcher": sorted(dispatcher),
        "other_constants": sorted(elsewhere),
        "code_bytes": total,
        # explicit so callers cannot mistake this for a verified interface
        "is_function_list": False,
    }


def classify_reachable(
    address: str,
    signature: str,
    rpc_call: t.Callable[[str, str], str],
    *,
    control_signature: str | None = None,
) -> str:
    """Classify one function's reachability by *differential* revert comparison.

    Revert data alone is not a reachability signal. An absent selector on a contract
    with no fallback reverts with ``0x``; a present function that hits a ``require``
    reverts with ``Error(string)``; but a contract with a **custom-error fallback**
    answers *every* unknown selector with its own error, which looks exactly like a
    function that was found and rejected.

    Verified on IPOR/mETH: an unknown selector on the deployed Staking contract
    reverted ``0x34352c73``, identical to what ``approve(address,uint256)``
    returned. Reading that naively as "approve exists" inverts the finding's
    severity-limiting claim; the truth is the reverse, Staking exposes no ERC-20
    allowance at all.

    So the test is differential: probe a selector that cannot exist, then compare.
    Identical revert data means "absent"; different data means "present".

    .. warning::
       ``present`` is trustworthy with selector-only probing. ``absent`` is **not**,
       for any function that takes arguments. Probing sends the 4-byte selector
       with no argument words, so the dispatcher matches the function and then
       fails while decoding calldata - often with the same empty revert as an
       unknown selector. Observed live: ``mETH.allowance(address,address)`` probes
       as ``absent`` here yet answers ``0`` when given real arguments.

       To get a trustworthy ``absent``, pass full pre-encoded calldata via
       ``signature`` (any string containing ``0x`` is treated as data, not a
       signature), e.g. selector + 64 zero bytes per argument.

    Returns ``"present"``, ``"absent"``, ``"present-ok"`` (call succeeded),
    ``"ambiguous"`` (control unavailable or identical behaviour with no fallback
    distinction available), or ``"error"``.
    """

    def _revert(sig: str) -> tuple[str, str | None]:
        try:
            data = _selector(sig) if "0x" not in sig else sig
        except Exception:
            return "error", None
        try:
            res = rpc_call(address, data)
            return "present-ok", (res or "0x")
        except Exception as e:
            return "revert", str(e)

    ctrl_kind, ctrl_detail = _revert(control_signature or "___thisCannotExist___()")

    kind, detail = _revert(signature)
    if kind == "present-ok":
        return "present-ok"
    if kind == "error":
        return "error"
    if ctrl_kind == "error":
        return "ambiguous"
    if ctrl_kind == "present-ok":
        # control answered, so it does exist - bad control, cannot discriminate
        return "ambiguous"
    if detail == ctrl_detail:
        return "absent"
    return "present"


def probe_selectors(
    address: str,
    signatures: list[str],
    rpc_call: t.Callable[[str, str], str],
) -> dict[str, bool]:
    """Behavioural ground truth for which functions an address actually exposes.

    Unlike :func:`extract_selectors`, this does not look at code at all: it sends a
    real ``eth_call`` for each signature and records whether the node accepted it.

    .. warning::
       A revert is **not** proof of absence - see :func:`classify_reachable` for the
       differential form, which is what you want when the target may have a
       fallback. This convenience wrapper only answers "did it respond", which is
       still the right question for a contract with no fallback.

    ``rpc_call(to, data) -> result_hex`` must raise on revert.

    Returns ``{signature: responded}``.
    """
    out: dict[str, bool] = {}
    for sig in signatures:
        try:
            data = _selector(sig) if "0x" not in sig else sig
        except Exception:
            out[sig] = False
            continue
        try:
            res = rpc_call(address, data)
            out[sig] = bool(res) and res not in ("0x", "0x0")
        except Exception:
            out[sig] = False
    return out


def opcode_histogram(code_hex: str) -> dict[str, int]:
    hist: dict[str, int] = {}
    for op, _ in iter_opcodes(code_hex):
        hist[f"0x{op:02x}"] = hist.get(f"0x{op:02x}", 0) + 1
    return hist


def dangerous_ops(code_hex: str) -> list[dict[str, t.Any]]:
    hist = opcode_histogram(code_hex)
    out = []
    for name, opc in DANGEROUS_OPS.items():
        n = hist.get(f"0x{opc:02x}", 0)
        if n:
            out.append({"op": name, "count": n, "why": DANGEROUS_REASONS[name]})
    out.sort(key=lambda d: d["count"], reverse=True)
    return out


def storage_slots(code_hex: str) -> list[dict[str, t.Any]]:
    """Slots written by PUSHn immediately preceding an SLOAD/SSTORE.

    A map or array access compiles to a hash/plus of a base slot, so the pushed
    constant is the storage base, which is what a storage-collision review needs.
    """
    h = _strip_hex(code_hex)
    out: list[dict[str, t.Any]] = []
    pending: str | None = None
    for op, data in iter_opcodes(code_hex):
        if 0x60 <= op <= 0x7F and data:
            pending = data
            continue
        if op in (0x54, 0x55) and pending:  # SLOAD / SSTORE
            trimmed = pending.lower().lstrip("0")
            out.append({
                # 0x00 must render as 0x0, not the empty string after stripping
                "slot": ("0x" + trimmed) if trimmed else "0x0",
                "op": "SLOAD" if op == 0x54 else "SSTORE",
            })
        pending = None
    return out


def is_minimal_proxy(code_hex: str) -> str | None:
    h = _strip_hex(code_hex).lower()
    m = MINIMAL_PROXY_RE.match(h) or CLONE_RE.match(h)
    return "0x" + m.group(1) if m else None


def trailing_immutables(code_hex: str, assume: int = 32) -> list[str]:
    """Constructor-set immutables appended to the end of runtime code."""
    h = _strip_hex(code_hex)
    n = len(h)
    if assume <= 0 or n < assume * 2:
        return []
    tail = h[-assume * 2:]
    return ["0x" + tail.lower()]


# --------------------------------------------------------------------------- #
# chain interaction
# --------------------------------------------------------------------------- #

def _env() -> dict[str, str]:
    foundry = Path.home() / ".foundry" / "bin"
    return {**os.environ, "PATH": f"{foundry}:{os.environ.get('PATH', '')}"}


def _cast(args: list[str], timeout: int = 90) -> tuple[bool, str]:
    try:
        p = subprocess.run(["cast", *args], capture_output=True, text=True,
                           timeout=timeout, env=_env())
        return p.returncode == 0, (p.stdout or p.stderr).strip()
    except Exception:  # noqa: BLE001
        return False, ""


def rpc_for(chain: str) -> str | None:
    from .cs_rpc import rpc_for as _r

    return _r(str(chain))


def runtime_code(chain: str, address: str) -> str:
    url = rpc_for(chain)
    if not url:
        raise REError(f"no rpc for chain {chain}")
    ok, code = _cast(["code", address, "--rpc-url", url], timeout=120)
    if not ok:
        raise REError(f"cast code failed for {address}: {code[:80]}")
    return code if code.startswith("0x") else "0x" + code


def _storage(chain: str, address: str, slot: str) -> str | None:
    url = rpc_for(chain)
    if not url:
        return None
    ok, val = _cast(["storage", address, slot, "--rpc-url", url], timeout=90)
    if not ok or not val or val == "0x":
        return None
    val = val.strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", val):
        return None
    addr = "0x" + val[-40:]
    return None if int(addr, 16) == 0 else addr


def _call(chain: str, address: str, sig: str, args: str = "",
          timeout: int = 90) -> tuple[bool, str]:
    url = rpc_for(chain)
    if not url:
        return False, ""
    a = [f"{address}", sig]
    if args:
        a += args.split()
    return _cast(["call", *a, "--rpc-url", url], timeout=timeout)


def resolve_proxy(chain: str, address: str) -> dict[str, t.Any]:
    """Classify how an address reaches its logic, following every chain we know.

    Order matters: a minimal proxy's implementation is in its runtime code, a
    diamond's logic is in facets that appear in NO reachable bytecode, and a
    beacon's implementation moves without the address changing. All three look
    like "a contract" from the outside, and each was a dead end in practice.
    """
    out: dict[str, t.Any] = {
        "address": address,
        "chain": str(chain),
        "kind": "DIRECT",
        "implementations": [],
        "beacon": None,
        "facets": [],
        "notes": [],
    }
    try:
        code = runtime_code(chain, address)
    except REError as exc:
        out["kind"] = "UNREACHABLE"
        out["notes"].append(str(exc))
        return out

    out["code_bytes"] = len(_strip_hex(code)) // 2

    minimal = is_minimal_proxy(code)
    if minimal:
        out["kind"] = "EIP1167_MINIMAL_PROXY"
        out["implementations"].append(minimal)
        out["notes"].append(
            "EIP-1167 minimal proxy: the implementation is hardcoded in the "
            "runtime code, so it can never be upgraded."
        )
        return out

    impl = _storage(chain, address, SLOT_IMPL)
    if impl:
        out["kind"] = "EIP1967_PROXY"
        out["implementations"].append(impl)

    beacon = _storage(chain, address, SLOT_BEACON)
    if beacon:
        out["kind"] = "BEACON"
        out["beacon"] = beacon
        ok, bimpl = _call(chain, beacon, "implementation()(address)")
        got = to_addr(bimpl) if ok else None
        if got:
            out["implementations"].append(got)
        out["notes"].append(
            "beacon proxy: the implementation can change without this address "
            "changing, so a review of today's implementation may not hold tomorrow"
        )

    # EIP-2535 diamond: loupe() reports facets; facet logic is in facet
    # contracts, NOT in this contract's bytecode.
    ok_loupe, loupe = _call(chain, address, "facets()(address[])")
    if ok_loupe:
        facets = re.findall(r"0x[0-9a-fA-F]{40}", loupe)
        if facets:
            out["kind"] = "EIP2535_DIAMOND" if not impl else out["kind"]
            out["facets"] = sorted(set(facets))
            out["notes"].append(
                "EIP-2535 diamond: logic lives in facet contracts registered in "
                "storage, so selectors and dangerous opcodes in THIS bytecode "
                "understate the real surface. Read the facets, not this."
            )

    if not impl and not out["facets"] and not beacon and not minimal:
        out["notes"].append(
            "no proxy slot, no facets, no minimal-proxy runtime: logic is "
            "directly in this address's bytecode"
        )
    return out


# --------------------------------------------------------------------------- #
# selector resolution and interface inference
# --------------------------------------------------------------------------- #

_4BYTE_CACHE: dict[str, list[str]] = {}


def resolve_selectors(selectors: list[str]) -> dict[str, list[str]]:
    """Reverse-resolve 4-byte selectors to candidate signatures via openchain.

    A selector can map to several signatures, so every result is a list. Treating
    it as a single answer is how a detector ends up confidently wrong: plenty of
    selectors collide.
    """
    out: dict[str, list[str]] = {}
    todo = [s for s in selectors if s not in _4BYTE_CACHE]
    for sel in todo:
        ok, txt = _cast(["4byte", sel], timeout=60)
        sigs = []
        if ok:
            for line in txt.splitlines():
                line = line.strip()
                if "(" in line and ")" in line:
                    sigs.append(line.split(" ")[0])
        _4BYTE_CACHE[sel] = sigs
    for sel in selectors:
        out[sel] = _4BYTE_CACHE.get(sel, [])
    return out


def infer_interfaces(resolved: dict[str, list[str]]) -> dict[str, t.Any]:
    """Name the standards a contract implements, with the evidence for each.

    A match requires most of an interface's required signatures, compared exactly.
    `owner()` alone proves nothing - thousands of contracts expose it.
    """
    present: set[str] = set()
    for sigs in resolved.values():
        for s in sigs:
            present.add(s.replace(" ", ""))
    found: dict[str, t.Any] = {}
    for name, spec in INTERFACES.items():
        req = [r.replace(" ", "") for r in spec["required"]]
        have = [r for r in req if r in present]
        ratio = len(have) / len(req)
        if ratio >= spec["threshold"]:
            found[name] = {
                "confidence": round(ratio, 2),
                "matched": have,
                "missing": [r for r in req if r not in present],
            }
    return {
        "interfaces": found,
        "unresolved_selectors": [s for s, v in resolved.items() if not v],
    }


# --------------------------------------------------------------------------- #
# differential analysis
# --------------------------------------------------------------------------- #

def diff_bytecode(code_a: str, code_b: str) -> dict[str, t.Any]:
    """Structural difference between two contracts' runtime bytecode.

    This exists because most exploited contracts are a one-line change from a
    known-good sibling, and because a Sourcify entry is not proof that what is
    deployed matches what is published. Arcadia's AccountV4 verified on Sourcify
    while its live bytecode differed from the repository - 12 hunks, all comment
    removals and a pragma bump, adjudicated by hand. That adjudication is the part
    worth automating.

    Reports a selector-level diff (added/removed functions) and an opcode-level
    diff, and separately whether the runtime differs only in metadata - which is
    the common benign case (different IPFS hash, same logic).
    """
    ha, hb = _strip_hex(code_a).lower(), _strip_hex(code_b).lower()
    sa = extract_selectors(code_a)
    sb = extract_selectors(code_b)

    only_a = sorted(set(sa["dispatcher"]) - set(sb["dispatcher"]))
    only_b = sorted(set(sb["dispatcher"]) - set(sa["dispatcher"]))
    common = sorted(set(sa["dispatcher"]) & set(sb["dispatcher"]))

    hist_a = opcode_histogram(code_a)
    hist_b = opcode_histogram(code_b)

    # strip the CBOR metadata blob: it ends with a2 64 69 70 66 73 58 22 <34 bytes>
    def without_metadata(h: str) -> str:
        marker = "a264697066735822"
        i = h.rfind(marker)
        return h[:i] if i > 0 else h

    logic_a, logic_b = without_metadata(ha), without_metadata(hb)

    return {
        "same_length": len(ha) == len(hb),
        "identical": ha == hb,
        "logic_identical": logic_a == logic_b,
        "metadata_only_difference": logic_a == logic_b and ha != hb,
        "selectors_only_in_a": only_a,
        "selectors_only_in_b": only_b,
        "selectors_shared": len(common),
        "opcode_delta": {
            k: hist_a.get(k, 0) - hist_b.get(k, 0)
            for k in set(hist_a) | set(hist_b)
            if hist_a.get(k, 0) != hist_b.get(k, 0)
        },
        "dangerous_delta": {
            d["op"]: dangerous_ops(code_b)[i]["count"] - d["count"]
            for i, d in enumerate(dangerous_ops(code_a))
            if i < len(dangerous_ops(code_b))
            and dangerous_ops(code_b)[i]["count"] != d["count"]
        },
    }


def summarize(addr_info: dict[str, t.Any]) -> str:
    """One-screen summary of an address, for a human deciding whether to read it."""
    L: list[str] = []
    code = addr_info.get("code_hex")
    L.append(f"address     : {addr_info.get('address')}")
    L.append(f"chain       : {addr_info.get('chain')}")
    L.append(f"kind        : {addr_info.get('proxy', {}).get('kind')}")
    if addr_info.get("proxy", {}).get("implementations"):
        L.append(f"impls       : {', '.join(addr_info['proxy']['implementations'])}")
    if addr_info.get("proxy", {}).get("facets"):
        L.append(f"facets      : {len(addr_info['proxy']['facets'])} (diamond - read the facets)")
    for n in addr_info.get("proxy", {}).get("notes", []):
        L.append(f"note        : {n}")
    if code:
        sel = addr_info.get("selectors", {})
        L.append(f"code bytes  : {sel.get('code_bytes')}")
        L.append(f"selectors   : {len(sel.get('dispatcher', []))} in dispatcher")
        ifs = addr_info.get("inference", {}).get("interfaces", {})
        if ifs:
            L.append("interfaces  : " + ", ".join(
                f"{k} ({v['confidence']})" for k, v in ifs.items()))
        unresolved = addr_info.get("inference", {}).get("unresolved_selectors", [])
        if unresolved:
            L.append(f"unresolved  : {len(unresolved)} selectors (custom or unindexed)")
        ops = addr_info.get("dangerous_ops", [])
        if ops:
            L.append("opcodes     : " + ", ".join(f"{d['op']}x{d['count']}" for d in ops[:6]))
        acc = addr_info.get("access") or {}
        if acc:
            L.append(f"access      : {acc.get('verdict')} ({acc.get('confidence')})")
        ev = addr_info.get("events") or {}
        if ev:
            named = [e["signatures"][0] for e in ev.get("events", []) if e.get("signatures")]
            if named:
                L.append(f"events      : {len(named)} named, e.g. " + "; ".join(named[:3]))
        dorm = addr_info.get("dormant") or {}
        if dorm:
            L.append(f"dormant     : {dorm.get('dormant_count')} unnamed selectors, risk={dorm.get('risk')}")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #

def analyze(chain: str, address: str, *, resolve_4byte: bool = True,
            max_selectors: int = 200) -> dict[str, t.Any]:
    """Full structural analysis of one deployed address.

    Always answers: is this reachable, is it a proxy (and of what kind), what
    interfaces does the bytecode support, and what dangerous opcodes does it use.
    Returns UNKNOWN rather than guessing wherever the bytecode cannot decide, so
    a caller cannot mistake absence of evidence for absence of a surface.
    """
    info: dict[str, t.Any] = {"address": address, "chain": str(chain)}
    proxy = resolve_proxy(chain, address)
    info["proxy"] = proxy

    targets = list(proxy["implementations"])
    if proxy["beacon"]:
        targets.append(proxy["beacon"])

    analyses: list[dict[str, t.Any]] = []
    for tgt in targets or [address]:
        try:
            code = runtime_code(chain, tgt)
        except REError as exc:
            analyses.append({"address": tgt, "error": str(exc)})
            continue
        sel = extract_selectors(code)
        resolved = resolve_selectors(sel["dispatcher"][:max_selectors]) if resolve_4byte else {}
        entry: dict[str, t.Any] = {
            "address": tgt,
            "code_hex": code,
            "selectors": sel,
            "opcode_histogram": opcode_histogram(code),
            "dangerous_ops": dangerous_ops(code),
            "storage_slots": storage_slots(code)[:64],
            "minimal_proxy_impl": is_minimal_proxy(code),
        }
        if resolved:
            entry["resolved"] = resolved
            entry["inference"] = infer_interfaces(resolved)
            entry["events"] = resolve_events(event_topics(code)[:40])
            entry["dormant"] = dormant_paths(code, resolved, entry["inference"].get("interfaces"))
        entry["access"] = access_control_hints(code)
        analyses.append(entry)

    info["implementations"] = analyses
    primary = analyses[0] if analyses else {}
    if primary:
        info["code_hex"] = primary.get("code_hex")
        info["selectors"] = primary.get("selectors", {})
        info["dangerous_ops"] = primary.get("dangerous_ops", [])
        info["inference"] = primary.get("inference", {})
        info["storage_slots"] = primary.get("storage_slots", [])
        info["events"] = primary.get("events", {})
        info["dormant"] = primary.get("dormant", {})
        info["access"] = primary.get("access", {})

    # Diamonds hide their surface: say so rather than let a thin selector list
    # imply the contract is small.
    if proxy["facets"]:
        info["surface_caveat"] = (
            f"EIP-2535 diamond with {len(proxy['facets'])} facet(s). The selector "
            "and opcode findings above describe the proxy shell only; the real "
            "logic is in the facets and must be analysed separately."
        )
    if proxy["beacon"]:
        info["surface_caveat"] = (
            "beacon proxy: the implementation can be swapped without this address "
            "changing, so any conclusion is tied to the implementation hash, not "
            "the address."
        )
    return info


def analyze_many(chain: str, addresses: list[str], **kw: t.Any) -> list[dict[str, t.Any]]:
    """Analyse several addresses, keeping per-address failures isolated."""
    out = []
    for a in addresses:
        try:
            out.append(analyze(chain, a, **kw))
        except Exception as exc:  # noqa: BLE001
            out.append({"address": a, "chain": chain, "error": f"{type(exc).__name__}: {exc}"})
    return out


# --------------------------------------------------------------------------- #
# source <-> bytecode differential
# --------------------------------------------------------------------------- #

_FUNC_DECL = re.compile(r"\bfunction\s+(\w+)\s*\(([^)]*)\)", re.S)


def selectors_from_source(root: Path) -> dict[str, list[str]]:
    """Map file -> the 4-byte selectors its function declarations would produce.

    This is the missing half of deployed-source verification. Sourcify tells you
    whether source was published; it does not tell you whether the published
    source is what is deployed. Arcadia's AccountV4 verified on Sourcify while the
    live bytecode differed from the repository, and sDAI taught the same lesson
    from the other direction - I inferred a diamond by searching SOURCE TEXT for
    selector hex, which of course it cannot contain.

    Comparing declared selectors against the deployed dispatcher is cheap, needs
    no compiler, and catches the exact failure those two cases share: a repo that
    is newer than, older than, or simply different from the deployment.
    """
    from . import cs_re as _self  # noqa: F401  (self-reference keeps imports explicit)

    out: dict[str, list[str]] = {}
    for sol in Path(root).rglob("*.sol"):
        if any(part in {"node_modules", "lib", "out", "cache", ".git"} for part in sol.parts):
            continue
        try:
            text = _strip_comments(sol.read_text(errors="replace"))
        except OSError:
            continue
        sels: list[str] = []
        for m in _FUNC_DECL.finditer(text):
            name, args = m.group(1), m.group(2)
            # normalise: strip names, keep types, collapse whitespace
            types = [re.sub(r"\s+", "", a.split()[0]) if a.split() else ""
                     for a in args.split(",") if a.strip()]
            sig = f"{name}({','.join(types)})"
            ok, sel = _cast(["sig", sig], timeout=45)
            if ok and sel.startswith("0x") and len(sel) == 10:
                sels.append(sel.lower())
        if sels:
            out[str(sol.relative_to(root))] = sorted(set(sels))
    return out


def compare_source_to_deployed(chain: str, address: str, source_root: Path,
                               resolve_4byte: bool = True) -> dict[str, t.Any]:
    """Diff a source tree's declared selectors against a deployed contract.

    KNOWN LIMITATION - this cannot verify a contract with inheritance, and its
    verdict should not be trusted on one. The deployed bytecode of an inherited
    contract carries every inherited public function (hasRole, grantRole,
    getRoleAdmin, proxiableUUID, ...), which no single source file declares, so
    the comparison always reports "deployed exposes selectors the source does not
    declare". Scoping to one file does not fix it - it just inverts the
    asymmetry.

    This was misread twice on mETH: first as "deployed diverges from the repo"
    (it was comparing one contract against the whole src/ tree), then as a scoped
    check that also said DIVERGES. Both were artefacts of the comparison, not of
    the code.

    For real verification use the direct route, which needs no inference:
    fetch the deployed implementation's Sourcify source and compare bytes with the
    repository file. For mETH that is exact_match with md5 7ca18fb0... on both
    sides - an exact match is evidence; a selector ratio is not.
    """
    code = runtime_code(chain, address)
    deployed = extract_selectors(code)
    dep = set(deployed["dispatcher"])
    per_file = selectors_from_source(Path(source_root))
    src_all: set[str] = set()
    for sels in per_file.values():
        src_all.update(sels)

    only_src = sorted(src_all - dep)
    only_dep = sorted(dep - src_all)
    shared = sorted(dep & src_all)

    resolved: dict[str, list[str]] = {}
    if resolve_4byte and (only_src or only_dep):
        resolved = resolve_selectors(only_dep[:60])

    return {
        "address": address,
        "source_root": str(source_root),
        "deployed_selector_count": len(dep),
        "source_selector_count": len(src_all),
        "shared": len(shared),
        "only_in_source": only_src,
        "only_in_deployed": only_dep,
        "only_in_deployed_resolved": resolved,
        "per_file_source_selectors": {k: len(v) for k, v in list(per_file.items())[:20]},
        "verdict": (
            "SOURCE MATCHES DEPLOYED"
            if not only_src and not only_dep
            else "DIVERGES - deployed exposes selectors the source does not declare"
            if only_dep else "DIVERGES - source declares selectors the deployment does not expose"
        ),
    }


def _file_selectors(path: Path) -> list[str]:
    """Selectors declared by a single source file."""
    try:
        text = _strip_comments(path.read_text(errors="replace"))
    except OSError:
        return []
    out: list[str] = []
    for m in _FUNC_DECL.finditer(text):
        name, args = m.group(1), m.group(2)
        types = [re.sub(r"\s+", "", a.split()[0]) if a.split() else ""
                 for a in args.split(",") if a.strip()]
        sig = f"{name}({','.join(types)})"
        ok, sel = _cast(["sig", sig], timeout=45)
        if ok and sel.startswith("0x") and len(sel) == 10:
            out.append(sel.lower())
    return sorted(set(out))


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


# --------------------------------------------------------------------------- #
# 4. uninitialised-proxy / uninitialised-implementation detection
# --------------------------------------------------------------------------- #

# Initializer names, matched narrowly.
#
# The first version matched anything starting with "init", which swept up
# `initVersion()` - a pure view returning a version number. Calling it always
# succeeds, so six LIVE production protocols were reported as UNINITIALIZED. A
# name pattern alone cannot decide this; see uninitialized_probe for the
# corroboration requirement.
_INIT_NAME = re.compile(
    r"^(initialize|init|setUp|__init|reinitialize)[A-Z]?[0-9]*$"
    r"|^initialize[0-9]*$"
    r"|^setUp$|^__init$|^reinitializer$",
    re.I,
)

# Signatures whose successful call proves nothing: they are getters or version
# readouts that cannot revert and cannot take ownership.
_INIT_LOOKALIKE = re.compile(r"^(init|initialize)?(Version|Address|Nonce|Type|Owner|Status)$", re.I)

# Getters that corroborate "already initialised" when non-zero.
_STATE_PROBES = ("owner()", "admin()", "governance()", "getOwner()", "adminAddress()")
# Revert payloads that prove an Initializable guard already fired. Matching the
# rendered STRING is not enough: a contract declaring `error InvalidInitialization()`
# makes `cast call` print the raw 4-byte selector, never the name. Both forms are
# checked, because "the call reverted for an unrelated reason" must not be
# reported as "safe" - that is precisely how a probe would cry wolf.
_INIT_ERRORS = (
    "already initialized", "invalid initialization", "not initializing",
    "initialization", "initialized",
)
# OpenZeppelin Initializable guard errors. The selectors are DERIVED at runtime
# via `cast sig` rather than hardcoded: an earlier revision hardcoded
# f1c221079 for InvalidInitialization() when the real value is f92ee8a9, and a
# wrong constant silently turns every initialized contract into UNKNOWN. Deriving
# them removes the possibility of being wrong from memory.
_INIT_ERROR_SIGS = ("InvalidInitialization()", "NotInitializing()")
_INIT_ERROR_SELECTORS_CACHE: dict[str, str] | None = None


def _init_error_selectors() -> dict[str, str]:
    global _INIT_ERROR_SELECTORS_CACHE
    if _INIT_ERROR_SELECTORS_CACHE is None:
        out: dict[str, str] = {}
        for sig in _INIT_ERROR_SIGS:
            ok, sel = _cast(["sig", sig], timeout=45)
            if ok and sel.startswith("0x") and len(sel) == 10:
                out[sel[2:].lower()] = sig
        _INIT_ERROR_SELECTORS_CACHE = out
    return _INIT_ERROR_SELECTORS_CACHE


def initializer_selectors(code_hex: str, resolve: bool = True) -> list[dict[str, t.Any]]:
    """Selectors that look like initializer entrypoints.

    `initialize*` is the OpenZeppelin convention but the name is not the point -
    what matters is whether the CALL succeeds, which is probed separately. Any
    selector whose resolved name matches is a candidate worth trying.
    """
    sel = extract_selectors(code_hex)
    out: list[dict[str, t.Any]] = []
    if resolve and sel["dispatcher"]:
        res = resolve_selectors(sel["dispatcher"])
        for s, names in res.items():
            for n in names:
                # match the function NAME, not the full signature: an anchored
                # pattern applied to "initialize(address)" never matches
                name_only = n.split("(")[0]
                if _INIT_NAME.match(name_only) and not _INIT_LOOKALIKE.match(name_only):
                    out.append({"selector": s, "signature": n})
    return out


def uninitialized_probe(chain: str, address: str, *, max_args: int = 10) -> dict[str, t.Any]:
    """Is this address's initializer still callable?

    An uninitialised proxy or implementation can be taken over by anyone:
    calling `initialize(yourself)` makes you owner/admin. This is a Critical when
    it works and undetectable from source that is not the deployed code, so it is
    worth probing rather than assuming.

    Method: call each initializer-looking selector with dummy address arguments
    and read WHY it failed. OZ's guard reverts with "Initializable: contract is
    already initialized" - that specific revert is proof the guard fired and the
    target is safe. A call that SUCCEEDS is proof the other way and is reported
    loudly. Anything else is UNKNOWN, because guessing "safe" from an unrelated
    revert is exactly the error this whole module keeps correcting.

    Note this is an `eth_call`, so it never sends a transaction.
    """
    try:
        code = runtime_code(chain, address)
    except REError as exc:
        return {"address": address, "verdict": "UNREACHABLE", "reason": str(exc)}

    impls = resolve_proxy(chain, address).get("implementations") or []
    targets = [address] + list(impls)

    results: list[dict[str, t.Any]] = []
    overall = "NO_INITIALIZER_FOUND"

    for tgt in targets:
        try:
            tcode = runtime_code(chain, tgt)
        except REError:
            continue
        for cand in initializer_selectors(tcode, resolve=True):
            sig, sel = cand["signature"], cand["selector"]
            nargs = _count_args(sig)
            if nargs is None or nargs > max_args:
                continue
            dummy = "0x1111111111111111111111111111111111111111 " * nargs
            ok, out = _call(chain, tgt, sig, dummy.strip())
            verdict = _classify_init_call(ok, out)

            # CORROBORATION. A successful call alone is not evidence: getters
            # always succeed, and so does any unguarded helper. Before claiming a
            # takeover, require the target to actually look uninitialised - every
            # ownership getter zero. Otherwise this is a candidate, not a verdict.
            if verdict == "UNINITIALIZED" and not _INIT_LOOKALIKE.match(
                sig.split("(")[0]
            ):
                if not _looks_uninitialized(chain, tgt):
                    verdict = "INITIALIZED"
            results.append({
                "address": tgt, "selector": sel, "signature": sig,
                "args": nargs, "call_succeeded": ok, "verdict": verdict,
                "output": out[:120] if out else None,
            })
            if verdict == "UNINITIALIZED":
                overall = "UNINITIALIZED"
            elif verdict == "INITIALIZED" and overall != "UNINITIALIZED":
                overall = "INITIALIZED"
            elif overall == "NO_INITIALIZER_FOUND":
                overall = "UNKNOWN"

    if not results:
        overall = "NO_INITIALIZER_FOUND"
    return {
        "address": address,
        "verdict": overall,
        "probes": results,
        "caveat": (
            "eth_call only; nothing is submitted. A successful call proves an "
            "uninitialised target. An unrelated revert is UNKNOWN, not safe."
        ),
    }


def _count_args(sig: str) -> int | None:
    """Count top-level parameters, respecting nesting.

    Naive comma counting breaks on tuple/array arguments - `initialize(address,
    (uint256,bytes))` counts 3 instead of 2, which would build wrong calldata and
    make the probe answer something unrelated.
    """
    m = re.match(r"^[^(]+\((.*)\)$", sig)
    if not m:
        return None
    inner = m.group(1).strip()
    if not inner:
        return 0
    depth = 0
    count = 1
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            count += 1
    return count


def _looks_uninitialized(chain: str, address: str) -> bool:
    """True only when every ownership getter is zero.

    A proxy whose `owner()`/`admin()` is already set IS initialised, whatever a
    successful call to some `init*` function suggests. Six live production
    protocols were reported as UNINITIALIZED before this check existed.
    """
    saw_any = False
    for fn in _STATE_PROBES:
        ok, out = _call(chain, address, fn, timeout=30)
        if not ok:
            continue
        saw_any = True
        n = to_int(out)
        if n is None or n == 0:
            continue
        return False
    return saw_any


def _classify_init_call(ok: bool, out: str) -> str:
    """Decide what a failed initializer call actually proved."""
    if ok:
        return "UNINITIALIZED"
    low = (out or "").lower()
    # a custom error renders as raw revert data, e.g. "data: 0xf1c221079"
    m = re.search(r"0x([0-9a-f]{8})", low)
    if m and m.group(1) in _init_error_selectors():
        return "INITIALIZED"
    # Error(string) renders with the string visible in cast output
    if any(e in low for e in _INIT_ERRORS):
        return "INITIALIZED"
    return "UNKNOWN"


# --------------------------------------------------------------------------- #
# 1. access-control inference from control flow
# --------------------------------------------------------------------------- #
# Reading `onlyOwner` by hand across kelp's ~19,000 lines is exactly the work this
# is meant to remove. The signal is the SHAPE of a caller-identity check, not its
# source-level name, because no name survives compilation.
#
# Recognised shapes:
#   CALLER near an equality/branch -> a msg.sender check exists
#   PUSH20 immutables compared against CALLER -> an immutable owner
#   PUSH32 role hashes near CALLER comparisons -> AccessControl-style roles
#   CALLER present but never branched on -> caller is read but not gated (weaker)
#
# This is a HEURISTIC and is reported as such: it says a guard looks present, not
# that it is correct or complete. A missed guard is the dangerous direction, so
# "no guard detected" is stated as absence of evidence, never as "unprotected".

OP_CALLER = 0x33
OP_JUMPI = 0x57
OP_EQ = 0x14
OP_SUB = 0x03
OP_REVERT = 0xFD
ERR_SELECTOR = 0x08C379A0  # Error(string)


def _is_push(op: int) -> bool:
    return 0x60 <= op <= 0x7F


def access_control_hints(code_hex: str, *, context: int = 10) -> dict[str, t.Any]:
    """Infer caller-identity guards from bytecode shape.

    Returns evidence, not a verdict: which opcodes appeared, where, and which
    candidate owners/roles were seen near a CALLER comparison.
    """
    ops = [(op, data) for op, data in iter_opcodes(code_hex)]
    callers = [i for i, (op, _) in enumerate(ops) if op == OP_CALLER]
    if not callers:
        return {
            "caller_checks": 0,
            "branches": 0,
            "immutable_owners": [],
            "role_hashes": [],
            "verdict": "NO_CALLER_CHECK_DETECTED",
            "confidence": "none",
            "note": "absence of evidence, not evidence of an unguarded contract",
        }

    branched = 0
    immutable_owners: list[str] = []
    role_hashes: list[str] = []

    for i in callers:
        window = ops[i + 1:i + context]
        # A real guard is `CALLER` compared against a value it was stored with,
        # then conditionally jumping:
        #     CALLER ; SLOAD ownerSlot (or PUSH20 immutable) ; EQ ; PUSH2 revert ; JUMPI
        #
        # Merely reading the caller (`lastSender = msg.sender`) is CALLER then
        # SSTORE with no comparison, and must NOT be counted. An earlier version
        # accepted "any JUMPI nearby", which matched the function dispatcher
        # instead and reported that unguarded contract as guarded - the dangerous
        # direction, because it manufactures false assurance.
        has_cmp = any(op in (OP_EQ, OP_SUB) for op, _ in window)
        has_source = any(op == 0x54 or op == 0x73 for op, _ in window)  # SLOAD / PUSH20
        has_branch = any(op == OP_JUMPI for op, _ in window)
        stored_directly = bool(window) and window[0][0] == 0x55        # CALLER ; SSTORE
        if has_cmp and (has_branch or has_source) and not stored_directly:
            branched += 1
        for op, data in window:
            if op == 0x73 and len(data) == 40:      # PUSH20 -> immutable address
                immutable_owners.append("0x" + data.lower())
            elif op == 0x7F and len(data) == 64:    # PUSH32 -> role hash / storage key
                role_hashes.append("0x" + data.lower())

    immutable_owners = sorted(set(immutable_owners))
    role_hashes = sorted(set(role_hashes))

    if branched:
        verdict, confidence = "CALLER_GUARD_PRESENT", "heuristic"
    else:
        verdict, confidence = "CALLER_READ_NOT_GATED", "low"

    return {
        "caller_checks": len(callers),
        "branches": branched,
        "immutable_owners": immutable_owners[:8],
        "role_hashes": role_hashes[:8],
        "error_selector_present": ERR_SELECTOR in opcode_histogram(code_hex),
        "verdict": verdict,
        "confidence": confidence,
        "note": "shape-based heuristic; it cannot tell a correct guard from an incomplete one",
    }


def guard_coverage(code_hex: str, signatures: list[str]) -> dict[str, t.Any]:
    """Annotate a function list with whether a caller guard appears near it.

    Function boundaries cannot be recovered exactly from bytecode alone, so this
    attributes guards to the WHOLE contract and to each selector's vicinity, and
    reports the result as an upper bound on which functions are gated. Reporting a
    per-function verdict here would be a fabricated precision.
    """
    overall = access_control_hints(code_hex)
    sel = extract_selectors(code_hex)
    return {
        "contract": overall,
        "selector_count": len(sel["dispatcher"]),
        "gated_selectors": len(sel["dispatcher"]) if overall["branches"] else 0,
        "unguarded_or_unknown": 0 if overall["branches"] else len(sel["dispatcher"]),
        "explanation": (
            "Attributed per contract, not per function: bytecode does not carry "
            "reliable function boundaries. A non-zero `gated_selectors` means a "
            "caller guard exists SOMEWHERE, not that any particular selector is safe."
        ),
    }


# --------------------------------------------------------------------------- #
# 3. event signature recovery
# --------------------------------------------------------------------------- #
# EVM logs carry only hashed topics, but compilers place a PUSH32 of the topic
# hash immediately before the LOG, so the hash is recoverable. `cast 4byte-event`
# then resolves it - and event names are often the clearest statement of what a
# contract actually does: a `WithdrawalRequested` or `DebtIncreased` tells you the
# protocol's function far faster than its function names do.

LOG_OPS = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4}


def event_topics(code_hex: str, *, context: int = 12) -> list[dict[str, t.Any]]:
    """PUSH32 constants that sit next to a LOG, as topic0 candidates.

    The proximity requirement matters: a PUSH32 anywhere in the code is mostly
    storage keys and masks, and reporting those as event signatures would be
    nonsense.
    """
    ops = [(op, data) for op, data in iter_opcodes(code_hex)]
    out: list[dict[str, t.Any]] = []
    seen: set[str] = set()
    for i, (op, data) in enumerate(ops):
        if op not in LOG_OPS:
            continue
        for j in range(max(0, i - context), i):
            jop, jdata = ops[j]
            if jop == 0x7F and len(jdata) == 64:
                topic = "0x" + jdata.lower()
                if topic not in seen:
                    seen.add(topic)
                    out.append({
                        "topic": topic,
                        # derived from the LOG opcode, not from the distance
                        # between opcodes: LOG0..LOG4 carry 0..4 topics, and for a
                        # non-anonymous event topic0 IS the signature hash
                        "topics": op - 0xA0,
                    })
                break
    return out


_EVENT_CACHE: dict[str, list[str]] = {}


def resolve_events(topics: list[dict[str, t.Any]]) -> dict[str, t.Any]:
    """Resolve topic0 candidates to event signatures."""
    todo = [t["topic"] for t in topics if t["topic"] not in _EVENT_CACHE]
    for topic in todo:
        ok, txt = _cast(["4byte-event", topic], timeout=60)
        names = []
        if ok:
            for line in txt.splitlines():
                line = line.strip()
                if "(" in line and ")" in line:
                    names.append(line.split(" ")[0])
        _EVENT_CACHE[topic] = names
    resolved = [{**t, "signatures": _EVENT_CACHE.get(t["topic"], [])} for t in topics]
    return {
        "events": resolved,
        "resolved_count": sum(1 for e in resolved if e["signatures"]),
        "unresolved_count": sum(1 for e in resolved if not e["signatures"]),
    }


# --------------------------------------------------------------------------- #
# 5. dormant paths
# --------------------------------------------------------------------------- #
# Selectors the contract can execute but that no ABI, and no signature database,
# can name. These are where backdoors hide: a `sweep(address)` or a
# `setOwner(address)` behind an unadvertised selector is invisible to any review
# driven by the interface, and is exactly the shape that survives audits.
#
# This reports candidates and context. It does NOT attribute a selector to a code
# region: bytecode carries no reliable function boundaries, so claiming "this
# selector reaches a delegatecall" would be fabricated precision. What it can say
# honestly is how many unnameable entrypoints exist and whether the contract
# contains the opcodes a backdoor would need.

def dormant_paths(code_hex: str, resolved: dict[str, list[str]],
                   interfaces: dict[str, t.Any] | None = None) -> dict[str, t.Any]:
    """Selectors with no resolvable signature, ranked by what surrounds them."""
    sel = extract_selectors(code_hex)
    unresolved = [s for s in sel["dispatcher"] if not resolved.get(s)]

    ops = dangerous_ops(code_hex)
    has_delegate = any(o["op"] == "DELEGATECALL" for o in ops)
    has_selfdestruct = any(o["op"] == "SELFDESTRUCT" for o in ops)

    # a selector only counts as "standard" if it was matched, not merely present
    matched = sum(len(v["matched"]) for v in (interfaces or {}).values())
    explained = len(set())  # no offline standard map available; stay conservative

    # RISK IS A SCREENING SIGNAL ONLY, and it has been falsified three ways:
    #   1. rate-limited 4byte lookups were counted as "unnamed", so a cold cache
    #      reported Velvet Capital at 30/59 when all 59 resolve;
    #   2. a contract whose only `init*` is a view satisfies any init probe;
    #   3. LIBRARIES. A deployed library uses DELEGATECALL by design and its
    #      helpers are unindexed by nature, so a library is flagged REVIEW while
    #      being completely normal. Bytecode cannot reliably tell a library from
    #      a contract, so this cannot be filtered here - it must be checked
    #      against the source before REVIEW means anything.
    risk = "LOW"
    if unresolved and (has_delegate or has_selfdestruct):
        risk = "REVIEW"
    elif unresolved:
        risk = "NOTE"

    return {
        "dormant_count": len(unresolved),
        "selectors": unresolved[:64],
        "interfaces_matched_signatures": matched,
        "excluded_as_known": explained,
        "contract_has_delegatecall": has_delegate,
        "contract_has_selfdestruct": has_selfdestruct,
        "risk": risk,
        "explanation": (
            "Selectors that neither 4byte nor any detected interface accounts for. "
            "Risk is raised only when the contract also contains DELEGATECALL or "
            "SELFDESTRUCT, which is the machinery a hidden capability would use. "
            "No per-selector code attribution is claimed: bytecode has no reliable "
            "function boundaries, so which opcodes a given selector reaches is not "
            "recoverable here."
        ),
        "caveat": (
            "An empty list is not proof the contract is safe; it reflects only what "
            "4byte can name. And REVIEW is expected for a deployed LIBRARY, which "
            "delegates by design and keeps unindexed helpers - check the source before "
            "treating REVIEW as a hidden capability."
        ),
    }


# --------------------------------------------------------------------------- #
# 7. metadata / IPFS hash -> published source
# --------------------------------------------------------------------------- #
# Solidity appends a CBOR metadata blob to runtime bytecode whose `ipfs` field is
# a 34-byte multihash. That hash is how the compiler recorded the exact source it
# built - which means for a contract with no Sourcify entry, the metadata may
# still point at the published sources.
#
# Caveat that must travel with any result: the hash proves WHICH source produced
# the bytecode. It does not prove that source is what is deployed in the sense
# that matters for a bug report - an upgraded proxy serves code the hash describes
# correctly but that the user never chose. Always resolve the implementation first.

_CBOR_MARKER = "a264697066735822"   # a2 64 "ipfs" 58 22
_META_LEN = 53                         # map(1) + key + 0x22 + 34-byte multihash


def extract_metadata(code_hex: str) -> dict[str, t.Any]:
    """Pull the Swarm/IPFS metadata hash off the end of runtime bytecode."""
    h = _strip_hex(code_hex).lower()
    out: dict[str, t.Any] = {"found": False, "reason": None, "ipfs": None, "swarm": None}
    if len(h) < _META_LEN * 2:
        out["reason"] = "code too short to carry a metadata blob"
        return out
    i = h.rfind(_CBOR_MARKER)
    if i < 0:
        out["reason"] = "no CBOR ipfs marker found (unverified build, or stripped)"
        return out
    tail = h[i + len(_CBOR_MARKER):]
    digest = tail[:68]
    if len(digest) < 68:
        out["reason"] = "metadata marker present but digest truncated"
        return out
    # multihash: 0x12 0x20 (sha2-256, 32 bytes)
    out["found"] = True
    if digest.startswith("1220"):
        digest_hex = digest[4:]
        out["ipfs"] = digest_hex
        out["cid"] = _to_cid_v0(digest_hex)
        out["reason"] = "sha2-256 multihash"
    else:
        out["swarm"] = digest
        out["reason"] = "non-sha2 multihash (swarm-style); not resolvable as IPFS"
    out["metadata_offset_bytes"] = i // 2
    return out


def _to_cid_v0(digest_hex: str) -> str:
    """0x-prefixed multihash digest -> base58 CIDv0, without a b58 dependency."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    raw = bytes.fromhex("1220" + digest_hex)

    def b58(data: bytes) -> str:
        num = int.from_bytes(data, "big")
        out = ""
        while num:
            num, rem = divmod(num, 58)
            out = alphabet[rem] + out
        for byte in data:
            if byte:
                break
            out = alphabet[0] + out
        return out

    return b58(raw)


def fetch_published_source(cid: str, timeout: int = 90) -> dict[str, t.Any]:
    """Try to retrieve the published source for a CID, over several gateways.

    Reported as a FETCH result only. Content at a CID is not necessarily the
    audited source, and is not necessarily present at all; a gateway returning
    something proves nothing about whether the program intended to publish it.
    """
    # cloudflare-ipfs.com is retired (NXDOMAIN) and public gateways rate-limit
    # aggressively from shared IPs - a 429 here is a transport condition, not
    # evidence the CID is unresolvable, and is reported as such.
    urls = [
        f"https://ipfs.io/ipfs/{cid}",
        f"https://gateway.pinata.cloud/ipfs/{cid}",
        f"https://w3s.link/ipfs/{cid}",
        f"https://nftstorage.link/ipfs/{cid}",
    ]
    attempts: list[dict[str, t.Any]] = []
    import urllib.error
    import urllib.request

    for u in urls:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "chainscope-re"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
            attempts.append({"gateway": u, "ok": True, "bytes": len(body),
                             "content_type": resp.headers.get("Content-Type")})
            return {"fetched": True, "cid": cid, "bytes": len(body),
                    "source": body.decode("utf-8", "replace"), "attempts": attempts}
        except Exception as exc:  # noqa: BLE001
            attempts.append({"gateway": u, "ok": False, "error": f"{type(exc).__name__}: {exc}"[:100]})
    return {"fetched": False, "cid": cid, "attempts": attempts}


# --------------------------------------------------------------------------- #
# 2. cross-contract inference: who does this contract talk to, and how
# --------------------------------------------------------------------------- #
# Reading one contract at a time hides the protocol. This recovers the shape of a
# contract's OUTBOUND relationships from bytecode alone:
#
#   * immutable and PUSH20 address constants -> counterparties it can reach
#     without any storage read
#   * CALL-family sites -> how it moves value, and whether it can execute foreign
#     code in its own storage (DELEGATECALL) or only query others (STATICCALL)
#   * selector constants used as arguments to those calls -> which functions it
#     calls on those counterparties
#
# What this deliberately does NOT claim: bytecode has no reliable function
# boundaries, so every finding here is contract-level. "It can delegatecall" is
# stated; "function 0x1234 delegates" is not, because that attribution cannot be
# recovered here. Overstating it would be the same class of error this module has
# already made twice today.

STATICCALL = 0xFA
CALLCODE_OPS = {0xF1, 0xF2, 0xF4, 0xFA}


# PUSH20 immediates that are conventional sentinels rather than counterparties:
# the zero address, max-uint160, the "dead"/"eee" markers and the EIP-7702-style
# native placeholder. Reporting them as relationships makes the output look busy
# while adding no information.
_SENTINELS = {
    "0x" + "00" * 20,
    "0x" + "ff" * 20,
    "0x" + "dd" * 20,
    "0x" + "ee" * 20,
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
}


def _address_constants(code_hex: str) -> list[str]:
    """PUSH20 immediates that look like real embedded addresses (immutables)."""
    out: set[str] = set()
    for op, data in iter_opcodes(code_hex):
        if op == 0x73 and len(data) == 40:
            a = "0x" + data.lower()
            if a not in _SENTINELS:
                out.add(a)
    return sorted(out)


def call_sites(code_hex: str, *, context: int = 16) -> dict[str, t.Any]:
    """Enumerate CALL-family sites and the selector pushed before each.

    A PUSH4 within a short window before a CALL is very likely the function
    selector being invoked. Reported as a candidate, never as certainty.
    """
    ops = [(op, data) for op, data in iter_opcodes(code_hex)]
    sites: list[dict[str, t.Any]] = []
    for i, (op, _) in enumerate(ops):
        if op not in CALLCODE_OPS:
            continue
        name = {0xF1: "CALL", 0xF2: "CALLCODE", 0xF4: "DELEGATECALL", 0xFA: "STATICCALL"}[op]
        sel = None
        for j in range(max(0, i - context), i):
            jop, jdata = ops[j]
            if jop == 0x63 and len(jdata) == 8:
                sel = "0x" + jdata.lower()
                break
        sites.append({"index": i, "op": name, "selector_candidate": sel})
    by_op: dict[str, int] = {}
    for s in sites:
        by_op[s["op"]] = by_op.get(s["op"], 0) + 1
    return {
        "sites": sites,
        "count": len(sites),
        "by_op": by_op,
        "can_execute_foreign_code_in_own_storage": any(
            s["op"] in ("DELEGATECALL", "CALLCODE") for s in sites),
        "note": (
            "Contract-level. The selector preceding a call is a candidate, not a "
            "proven pairing: without function boundaries a selector cannot be "
            "attributed to a specific call site with confidence."
        ),
    }


def infer_relationships(chain: str, address: str, code_hex: str | None = None,
                        max_probe: int = 12) -> dict[str, t.Any]:
    """Counterparties this contract can reach, with cheap liveness probes.

    Constants are the reliable part - they are addresses baked into the code.
    Probing is best-effort and reported per-address, because an address that does
    not answer may simply have no view function matching what we tried.
    """
    code = code_hex if code_hex is not None else runtime_code(chain, address)
    consts = _address_constants(code)
    calls = call_sites(code)

    probes: list[dict[str, t.Any]] = []
    for a in consts[:max_probe]:
        try:
            ok, _ = _call(chain, a, "implementation()(address)", timeout=25)
            is_proxy = ok
            code_size = 0
            ok_code, raw = _cast(["codesize", a, "--rpc-url", rpc_for(chain) or ""], timeout=25)
            if ok_code and raw.strip().isdigit():
                code_size = int(raw.strip())
            probes.append({
                "address": a,
                "has_code": code_size > 0,
                "code_size": code_size,
                "looks_like_proxy": is_proxy,
            })
        except Exception:  # noqa: BLE001
            probes.append({"address": a, "has_code": None, "code_size": 0, "looks_like_proxy": False})

    live = [p for p in probes if p.get("has_code")]
    sentinels = sorted({
        "0x" + d.lower() for op, d in iter_opcodes(code)
        if op == 0x73 and len(d) == 40 and ("0x" + d.lower()) in _SENTINELS
    })
    return {
        "address": address,
        "immutable_addresses": consts,
        "immutable_count": len(consts),
        "with_code": [p["address"] for p in live],
        "without_code": [p["address"] for p in probes if not p.get("has_code")],
        "proxy_like": [p["address"] for p in probes if p.get("looks_like_proxy")],
        "sentinels_ignored": sentinels,
        "calls": {k: v for k, v in calls.items() if k != "sites"},
        "call_selector_candidates": sorted({
            s["selector_candidate"] for s in calls["sites"] if s["selector_candidate"]
        })[:64],
        "explanation": (
            "Addresses recovered from PUSH20 constants in the bytecode. This is a "
            "lower bound on counterparties: anything loaded from storage, or built "
            "at runtime, is invisible here."
        ),
    }


# --------------------------------------------------------------------------- #
# 6. runtime identification and routing (NOT a non-EVM disassembler)
# --------------------------------------------------------------------------- #
# This is deliberately not a Solana/CosmWasm/Cairo/Move reverse engineer. Those
# are separate disciplines with their own instruction sets, and pretending
# otherwise would produce confident nonsense - the exact failure this module has
# already made several times today. What is genuinely useful is knowing WHAT a
# contract is before applying EVM logic to it, because every other function here
# assumes EVM opcodes.
#
# ChainScope's supported RE is EVM. For other runtimes this reports the identity
# and the correct next step, and stops.

RUNTIME_SIGNATURES: list[tuple[str, str, str, str]] = [
    # (magic/regex, label, chain hint, guidance)
    (r"^7f454c46", "ELF", "solana", "SBF/ELF program - use an SBF disassembler; EVM opcode logic does not apply"),
    (r"^0061736d", "WASM", "cosmos", "CosmWasm module - decode the wasm and read the Rust/Go source if published"),
    (r"^5345", "CASM", "starknet", "Cairo compiled output - read Sierra/Cairo source"),
    (r"^a2646970667358", "EVM_CBOR_METADATA", "evm", "Solidity/EVM runtime"),
    (r"^a17364657269616e", "SOLIDITY_BYTECODE", "evm", "old solc runtime"),
    (r"^7f", "RAW", "unknown", "unrecognised runtime"),
]


def identify_runtime(code_hex: str) -> dict[str, t.Any]:
    """Identify the execution runtime behind a blob of code.

    Never guesses 'EVM' for an unrecognised blob: on Solana, Cosmos, Starknet and
    Move, every EVM heuristic in this module would produce confident nonsense.
    Unknown is reported as unknown, with the consequence spelled out.
    """
    h = _strip_hex(code_hex)
    if not h:
        return {"runtime": "EMPTY", "is_evm": False, "supported": False,
                "guidance": "no code at this address"}
    # the metadata CBOR marker at the tail is the strongest positive EVM signal
    if "a2646970667358" in h[:200]:
        return {"runtime": "EVM_SOLIDITY", "is_evm": True, "supported": True,
                "guidance": "Solidity runtime; this module's analysis applies"}
    head = h[:16].lower()
    if head.startswith("7f454c46"):
        return {"runtime": "SOLANA_SBF", "is_evm": False, "supported": False,
                "guidance": "SBF/ELF program. EVM opcode logic does not apply; "
                            "use an SBF disassembler and read the Rust program"}
    if head.startswith("0061736d"):
        return {"runtime": "COSMWASM", "is_evm": False, "supported": False,
                "guidance": "CosmWasm module. Decode the wasm; read the Rust/Go source "
                            "if published"}
    if head.startswith("5345") or head.startswith("0043"):
        return {"runtime": "CAIRO", "is_evm": False, "supported": False,
                "guidance": "Cairo/Sierra. Read the Cairo source; Starknet contracts are "
                            "often verified and readable directly"}
    # EVM heuristics: solidity/evm prelude, or a plausible dispatcher
    if head.startswith("608060405") or head.startswith("60806"):
        return {"runtime": "EVM", "is_evm": True, "supported": True,
                "guidance": "EVM runtime with the standard solidity prelude"}
    if head.startswith("6080") or head.startswith("80"):
        return {"runtime": "EVM_LIKELY", "is_evm": True, "supported": True,
                "guidance": "looks like EVM but without the standard prelude; verify before trusting"}
    return {"runtime": "UNKNOWN", "is_evm": None, "supported": False,
            "guidance": "Unrecognised runtime. NOT assumed to be EVM - Solana, CosmWasm, "
                        "Cairo and Move are all non-EVM and every EVM heuristic here would "
                        "be wrong on them"}


CHAIN_RUNTIME_HINT = {
    "1": "evm", "42161": "evm", "10": "evm", "137": "evm", "8453": "evm",
    "56": "evm", "43114": "evm", "250": "evm",
    "534352": "evm", "560048": "evm",
    "solana": "solana", "cairo-1": "starknet", "starknet": "starknet",
    "cosmoshub-4": "cosmos", "osmo-1": "cosmos", "juno-1": "cosmos",
    "sui": "move", "aptos-mainnet": "move", "polygon": "evm", "arbitrum": "evm",
}


def identify_target(chain: str, address: str) -> dict[str, t.Any]:
    """Chain hint plus runtime identity, with an explicit supported/unsupported flag."""
    expected = CHAIN_RUNTIME_HINT.get(str(chain).lower())
    try:
        code = runtime_code(chain, address)
    except REError as exc:
        return {"chain": chain, "address": address, "expected_runtime": expected,
                "runtime": "UNREACHABLE", "supported": False, "reason": str(exc)}
    ident = identify_runtime(code)
    supported = bool(ident.get("is_evm"))
    if expected and expected != "evm" and ident.get("is_evm"):
        return {
            **ident, "chain": chain, "address": address,
            "expected_runtime": expected, "supported": False,
            "guidance": f"chain {chain} is expected to be {expected}, but this looks like "
                        "EVM. Verify before drawing conclusions.",
        }
    return {**ident, "chain": chain, "address": address,
            "expected_runtime": expected, "supported": ident.get("supported", False),
            "code_bytes": len(_strip_hex(code)) // 2}


# --------------------------------------------------------------------------- #
# value / liveness filter
# --------------------------------------------------------------------------- #
# A contract can implement ERC4626 perfectly and still be worth nothing: an
# unconfigured base implementation, an already-exited strategy, a migrated pool.
# The sweep flagged Yearn's TokenizedStrategy base (0xD377919F) purely because it
# implements the interface - and that instance has totalSupply 0, totalAssets 0 and
# reverts on balance(), want() and shutdown(). There is no user to harm and
# nothing to freeze.
#
# Reading an empty contract is the single largest waste available in triage, so
# value is checked before any source is read.

VALUE_PROBES = (
    "totalSupply()(uint256)",
    "totalAssets()(uint256)",
    "balance()(uint256)",
    "totalDebt()(uint256)",
    "totalValueLocked()(uint256)",
    "getVirtualPrice()(uint256)",
    "shares()(uint256)",
    "stakedToken()(address)",
)


def has_value(chain: str, address: str, *, tolerance: int = 0) -> dict[str, t.Any]:
    """Whether a contract appears to hold anything at all.

    Reports WHAT answered and WHY it concluded empty, rather than a bare boolean:
    "no probe answered" is a different fact from "every probe read zero", and
    conflating them hides live contracts whose accessors are non-standard.
    """
    readings: dict[str, str] = {}
    answered = 0
    nonzero = 0
    for fn in VALUE_PROBES:
        ok, out = _call(chain, address, fn, timeout=40)
        if not ok:
            continue
        answered += 1
        val = out.strip()
        readings[fn] = val
        n = to_int(val)
        if n is not None and n > tolerance:
            nonzero += 1

    if answered == 0:
        return {"status": "UNKNOWN", "reason": "no value accessor answered",
                "readings": readings, "live": None}
    if nonzero == 0:
        return {"status": "EMPTY", "reason": f"all {answered} value accessors read zero",
                "readings": readings, "live": False}
    return {"status": "HOLDS_VALUE", "reason": f"{nonzero}/{answered} accessors non-zero",
            "readings": readings, "live": True}
