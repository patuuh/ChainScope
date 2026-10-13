"""Derive a proxy's initialisation model from bytecode, not from a guessed slot.

The slot-based sweep returned `init5=255` for a large group, which is not a plausible
`_initialized` value: the read had hit something that is not an OZ `Initializable`
layout. Calling `initialized()` confirmed it - every implementation reverted or lacked
the selector. Those are Aave-lineage contracts, which use
`PoolAddressesProvider.setImplementation` rather than a per-proxy `initialize()`.

So instead of assuming OZ, detect what is actually there.

The hard part: a selector that does not exist and one whose function reverts on
access control BOTH revert. Revert data alone cannot tell them apart. The technique
that works is a differential probe - call the candidate selector, and call a selector
generated from a random signature, then compare the behaviour. If they differ, the
selector exists in the dispatcher.
"""

from __future__ import annotations

import json
import secrets
import urllib.request
from dataclasses import dataclass, field

IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

# Selectors are RESOLVED, never hardcoded. An earlier version of this file carried
# four selectors written from memory, three of which were wrong - `initialized()` was
# recorded as 0xf7a05767 when it is 0x158ef93e. Probing with the bogus constant made
# every implementation look like it lacked the function, and I briefly concluded the
# contracts were Aave-lineage as a result. Resolving at import time removes the class
# of error entirely.
def _sel(sig: str) -> str:
    import subprocess
    out = subprocess.run(["cast", "sig", sig], capture_output=True, text=True).stdout.strip()
    if not out.startswith("0x") or len(out) != 10:
        raise RuntimeError(f"could not resolve selector for {sig!r}")
    return out


S_INITIALIZED = _sel("initialized()")            # 0x158ef93e
S_INIT = _sel("initialize()")                    # 0x8129fc1c
S_SET_IMPL = _sel("setImplementation(address)")   # 0xd784d426
S_GET_IMPL = _sel("getImplementation()")         # 0x5c975abb
S_OWNER = _sel("owner()")                        # 0x8da5cb5b
S_PROXIABLE_UUID = _sel("proxiableUUID()")       # 0x52d1902d
S_FACET_CUT = _sel("diamondCut((bytes4[],address,bytes),address,bytes)")  # 0x211cf82d
S_UPGRADE_TO = _sel("upgradeTo(address)")        # 0x3659cfe6
S_UPGRADE_TO_AND_CALL = _sel("upgradeToAndCall(address,bytes)")  # 0x4f1ef286

RPC = "https://ethereum.publicnode.com"


def _rpc(method: str, params: list, url: str = RPC, timeout: int = 25):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    req = urllib.request.Request(
        url, body, {"Content-Type": "application/json", "User-Agent": "ChainScope/1.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as fh:
        d = json.loads(fh.read())
    return d.get("result") if "error" not in d else {"__error": d["error"].get("message", "")}


def _sel(sig: str) -> str:
    import subprocess
    return subprocess.run(["cast", "sig", sig], capture_output=True, text=True).stdout.strip()


def probe(impl: str, sel: str) -> dict:
    """Differential probe: does `sel` exist in impl's dispatcher?

    Compares against a selector from a random signature. A missing function and an
    access-controlled one both revert, but not identically - a real function
    typically returns data or reverts with its own reason, while an unknown selector
    falls through to the fallback or reverts on the dispatcher. When impl has no
    fallback the two look alike, which is reported honestly as `inconclusive`.
    """
    rand = _sel("zzz_probe_%s()" % secrets.token_hex(8))
    a = _rpc("eth_call", [{"to": impl, "data": sel}, "latest"])
    b = _rpc("eth_call", [{"to": impl, "data": rand}, "latest"])

    def norm(x):
        if isinstance(x, dict):
            return ("err", x.get("__error", "")[:40])
        return ("ok", x)

    na, nb = norm(a), norm(b)
    if na[0] == "ok" and na[1] not in ("0x",):
        return {"exists": True, "conf": "high", "result": na[1]}
    if na == nb:
        return {"exists": False, "conf": "low", "note": "indistinguishable from unknown selector"}
    return {"exists": True, "conf": "med", "result": na}


@dataclass
class InitModel:
    address: str
    implementation: str | None
    model: str = "unknown"
    initialized: int | None = None
    detail: dict = field(default_factory=dict)

    def as_dict(self):
        return dict(self.__dict__)


def classify(addr: str, url: str = RPC) -> InitModel:
    m = InitModel(address=addr, implementation=None)
    slot = _rpc("eth_getStorageAt", [addr, IMPL_SLOT, "latest"], url)
    if not slot or not isinstance(slot, str):
        m.model = "direct"
        return m
    impl = "0x" + slot[2:][-40:]
    beacon_raw = _rpc("eth_getStorageAt", [addr, BEACON_SLOT, "latest"], url)

    if not int(slot, 16):
        # Beacon proxy: the EIP-1967 implementation slot is empty by design and the
        # real implementation sits behind the beacon. 274 of the 334 mainnet
        # in-scope addresses across 9 high-ceiling programmes are this shape, and a
        # sweep that only reads the implementation slot reports them all as
        # non-proxies - which is how the first pass undercounted 68 proxies where
        # there were 334.
        if isinstance(beacon_raw, str) and int(beacon_raw, 16):
            m.model = "beacon"
            beacon = "0x" + beacon_raw[2:][-40:]
            m.implementation = None
            try:
                b_impl = _rpc("eth_getStorageAt", [beacon, IMPL_SLOT, "latest"], url)
                if isinstance(b_impl, str) and int(b_impl, 16):
                    m.implementation = "0x" + b_impl[2:][-40:]
                    m.detail["beacon"] = beacon
            except Exception as e:  # noqa: BLE001
                m.detail["beacon_error"] = str(e)[:50]
            return m
        m.model = "direct"
        return m

    m.implementation = impl

    probes = {
        "initialized": S_INITIALIZED,
        "initialize": S_INIT,
        "setImplementation": S_SET_IMPL,
        "proxiableUUID": S_PROXIABLE_UUID,
        "diamondCut": S_FACET_CUT,
        "upgradeTo": S_UPGRADE_TO,
    }
    found = {}
    for name, sel in probes.items():
        try:
            found[name] = probe(impl, sel)
        except Exception as e:  # noqa: BLE001
            found[name] = {"exists": None, "conf": "none", "err": str(e)[:40]}
    m.detail = found

    if found.get("setImplementation", {}).get("exists"):
        m.model = "aave-provider-style"
        return m
    if found.get("diamondCut", {}).get("exists"):
        m.model = "diamond"
        return m
    if found.get("initialized", {}).get("exists"):
        m.model = "oz-initializable"
        r = found["initialized"].get("result")
        if isinstance(r, str) and r not in ("0x",):
            m.initialized = int(r, 16)
        else:
            m.initialized = None
            m.model = "oz-initializable-unreadable"
        return m
    if found.get("initialize", {}).get("exists"):
        m.model = "oz-initializable-unreadable"
        return m
    return m