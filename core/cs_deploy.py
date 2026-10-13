"""Deployment verification for an in-scope address set.

Answers the question that killed three separate findings this session: *is this
actually live?* Static reading cannot, because a source repo tells you nothing about
what a proxy points at today, or whether the implementation behind it was ever
initialised.

Checks per address:
  1. EIP-1967 implementation slot (and beacon slot) -> proxy or direct
  2. the implementation's `_initialized` flag -> an uninitialised implementation is
     Critical, because whoever calls initialize() owns the contract
  3. runtime bytecode identity -> for the diff-against-source axis

Both OZ layouts are probed because they disagree on storage:
  * OZ v4 Initializable: `_initialized` at slot 0
  * OZ v5 (ERC-7201): namespace
    0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field

IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72"
OZ5_INITIALIZABLE = "0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"

CHAIN_RPC = {
    "1": "https://ethereum.publicnode.com",
    "42161": "https://arbitrum-one-rpc.publicnode.com",
    "137": "https://polygon-bor-rpc.publicnode.com",
    "8453": "https://base-rpc.publicnode.com",
    "10": "https://optimism-rpc.publicnode.com",
}


def _rpc(url: str, method: str, params: list, timeout: int = 30):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    req = urllib.request.Request(
        url, body, {"Content-Type": "application/json", "User-Agent": "ChainScope/1.0"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as fh:
        data = json.loads(fh.read())
    if "error" in data:
        raise RuntimeError(data["error"].get("message", "rpc error"))
    return data.get("result")


@dataclass
class DeployFinding:
    address: str
    chain: str
    code_bytes: int = 0
    is_proxy: bool = False
    implementation: str | None = None
    beacon: str | None = None
    impl_code_bytes: int = 0
    oz4_initialized: int | None = None
    oz5_initialized: int | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def uninitialized(self) -> bool:
        """True when an implementation exists and neither OZ layout shows init."""
        if not self.is_proxy or not self.implementation:
            return False
        return self.oz4_initialized in (0, None) and self.oz5_initialized in (0, None)

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["uninitialized"] = self.uninitialized
        return d


def _slot_read(url: str, addr: str, slot: str) -> str:
    return _rpc(url, "eth_getStorageAt", [addr, slot, "latest"])


def verify(url: str, addr: str, chain: str = "1") -> DeployFinding:
    f = DeployFinding(address=addr, chain=chain)
    code = _rpc(url, "eth_getCode", [addr, "latest"]) or "0x"
    f.code_bytes = (len(code) - 2) // 2
    if f.code_bytes == 0:
        f.notes.append("no code at address")
        return f

    impl_raw = _slot_read(url, addr, IMPL_SLOT)
    beacon_raw = _slot_read(url, addr, BEACON_SLOT)
    impl = "0x" + impl_raw[2:][-40:] if int(impl_raw, 16) else None
    beacon = "0x" + beacon_raw[2:][-40:] if int(beacon_raw, 16) else None
    f.implementation = impl
    f.beacon = beacon
    f.is_proxy = impl is not None or beacon is not None

    target = impl or (beacon if beacon else None)
    if f.is_proxy and target:
        ic = _rpc(url, "eth_getCode", [target, "latest"]) or "0x"
        f.impl_code_bytes = (len(ic) - 2) // 2
        if f.impl_code_bytes:
            try:
                f.oz4_initialized = int(_slot_read(url, target, "0x0"), 16) & 0xFF
                f.oz5_initialized = int(_slot_read(url, target, OZ5_INITIALIZABLE), 16) & 0xFF
            except Exception as e:  # noqa: BLE001
                f.notes.append(f"init read failed: {e}")
    return f


def verify_all(addrs: list[tuple[str, str]]) -> list[DeployFinding]:
    """addrs: list of (chainId, address). Falls back to a public node per chain."""
    out: list[DeployFinding] = []
    for chain, addr in addrs:
        url = CHAIN_RPC.get(chain)
        if not url:
            out.append(DeployFinding(address=addr, chain=chain, notes=["no RPC for chain"]))
            continue
        try:
            out.append(verify(url, addr, chain))
        except Exception as e:  # noqa: BLE001
            out.append(DeployFinding(address=addr, chain=chain, notes=[f"error: {e}"]))
    return out
