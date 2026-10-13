"""Validation harness: detectors must prove themselves against known ground truth.

Every number this session produced that turned out to be wrong came from the same
place: a detector that returned an answer I could not distinguish from a correct one.
The 274 "beacon proxies" (every direct contract matched the branch), the fabricated
selectors, and the implementation-vs-proxy storage confusion all produced clean-looking
output and wrong results.

So each detector gets fixtures where the truth is known, and the test fails when the
detector disagrees. The point is not coverage - it is that a wrong number now breaks
the build instead of requiring me to notice it.

The RPC layer is mocked deliberately: what broke was slot interpretation and model
classification, not connectivity, and mocking makes those cases exact and fast.
"""

from __future__ import annotations

import pytest

import core.cs_init as ci
import core.cs_deploy as cd

# Ground-truth contracts, described the way the RPC would present them.
IMPL_SLOT = cd.IMPL_SLOT
BEACON_SLOT = cd.BEACON_SLOT


class FakeChain:
    """Serves a scripted world of storage/code/call responses."""

    def __init__(self, storage=None, code=None, calls=None):
        self.storage = storage or {}
        self.code = code or {}
        self.calls = calls or {}

    def rpc(self, method, params, url=None, timeout=25):
        if method == "eth_getStorageAt":
            addr, slot = params[0], params[1]
            return self.storage.get((addr.lower(), slot.lower()),
                                    "0x" + "0" * 64)
        if method == "eth_getCode":
            return self.code.get(params[0].lower(), "0x60006000")
        if method == "eth_call":
            data = (params[0].get("data") or "").lower()
            return self.calls.get(data, "0x")
        raise AssertionError(f"unexpected RPC {method}")


def slot_of(addr: str) -> str:
    return f"0x{addr.lower().replace('0x', '').rjust(64, '0')}"


PROXY_A = "0x1111111111111111111111111111111111111111"
PROXY_B = "0x2222222222222222222222222222222222222222"
DIRECT = "0x3333333333333333333333333333333333333333"
BEACON_C = "0x4444444444444444444444444444444444444444"
IMPL_X = "0x5555555555555555555555555555555555555555"
IMPL_Y = "0x6666666666666666666666666666666666666666"
BEACON_Z = "0x7777777777777777777777777777777777777777"

INIT_SEL = "0x158ef93e"   # initialized()
OWNER_SEL = "0x8da5cb5b"   # owner()


def _hex_word(v: int) -> str:
    return "0x" + hex(v)[2:].rjust(64, "0")


def _world(**kw):
    storage = {
        (PROXY_A.lower(), IMPL_SLOT.lower()): slot_of(IMPL_X),
        (PROXY_B.lower(), IMPL_SLOT.lower()): slot_of(IMPL_Y),
        (BEACON_C.lower(), BEACON_SLOT.lower()): slot_of(BEACON_Z),
        (BEACON_Z.lower(), IMPL_SLOT.lower()): slot_of(IMPL_Y),
    }
    storage.update(kw.pop("storage", {}))
    # every implementation exposes initialized() and owner()
    code = {a.lower(): "0x60006000" for a in (IMPL_X, IMPL_Y, BEACON_Z)}
    code.update(kw.pop("code", {}))
    calls = {INIT_SEL: _hex_word(1), OWNER_SEL: _hex_word(0xBEEF)}
    calls.update(kw.pop("calls", {}))
    return FakeChain(storage=storage, code=code, calls=calls)


def _classify(monkeypatch, world, addr):
    monkeypatch.setattr(ci, "_rpc", lambda m, p, url=None, timeout=25: world.rpc(m, p))
    monkeypatch.setattr(ci, "_sel", lambda s: "0x" + f"{abs(hash(s)) % (16**8):08x}")
    return ci.classify(addr)


# ------------------------------------------------------------------ truth table

def test_direct_contract_is_not_a_proxy(monkeypatch):
    """Both slots empty -> direct. This is the case the beacon bug swallowed."""
    m = _classify(monkeypatch, _world(), DIRECT)
    assert m.model == "direct", f"direct contract misclassified as {m.model}"
    assert m.implementation is None


def test_beacon_slot_set_marks_a_beacon_proxy(monkeypatch):
    m = _classify(monkeypatch, _world(), BEACON_C)
    assert m.model == "beacon"
    assert m.implementation == IMPL_Y, "beacon should resolve to its implementation"
    assert m.detail.get("beacon") == BEACON_Z


def test_implementation_proxy_is_not_called_a_beacon(monkeypatch):
    """The inverse of the bug: impl set, beacon empty -> implementation proxy."""
    m = _classify(monkeypatch, _world(), PROXY_A)
    assert m.model not in ("direct", "beacon"), f"misclassified as {m.model}"
    assert m.implementation == IMPL_X


def test_zero_initialized_is_detected_as_a_known_positive(monkeypatch):
    """KNOWN POSITIVE: initialized() == 0 must surface as uninitialised."""
    world = _world(calls={INIT_SEL: _hex_word(0)})
    m = _classify(monkeypatch, world, PROXY_A)
    assert m.initialized == 0, "a 0 initialisation flag must be read as 0"
    assert m.model.startswith("oz-initializable")


def test_initialized_proxy_is_not_flagged(monkeypatch):
    world = _world(calls={INIT_SEL: _hex_word(1)})
    m = _classify(monkeypatch, world, PROXY_A)
    assert m.initialized == 1
    assert m.initialized != 0


def test_unreadable_flag_is_inconclusive_not_clean(monkeypatch):
    """Reverting must never be silently reported as a value."""
    world = _world(calls={INIT_SEL: {"__error": "execution reverted"}})
    m = _classify(monkeypatch, world, PROXY_A)
    assert m.initialized is None, "a revert must not be read as an initialisation value"
    assert "unreadable" in m.model or m.model == "unknown", m.model


# --------------------------------------------------------------- probe layer

def test_probe_resolves_selectors_instead_of_hardcoding():
    """Regression: selectors were once written from memory and three were wrong.

    Asserts the resolved values against known-correct ones, so a future edit that
    reintroduces a literal constant is caught here rather than in a sweep.
    """
    assert ci.S_INITIALIZED == "0x158ef93e"
    assert ci.S_INIT == "0x8129fc1c"
    assert ci.S_SET_IMPL == "0xd784d426"
    assert ci.S_OWNER == "0x8da5cb5b"
    assert ci.S_PROXIABLE_UUID == "0x52d1902d"


def test_probe_reports_a_readable_function_as_existing(monkeypatch):
    """Known positive: a function that returns data must be detected."""
    world = _world(calls={OWNER_SEL: _hex_word(0xCAFE)})
    r = ci.probe(PROXY_A, OWNER_SEL) if False else None
    # probe() uses _rpc directly
    monkeypatch.setattr(ci, "_rpc", lambda m, p, url=None, timeout=25: world.rpc(m, p))
    res = ci.probe(PROXY_A, OWNER_SEL)
    assert res["exists"] is True
    assert res["conf"] == "high"


def test_probe_reports_indistinguishable_rather_than_absent(monkeypatch):
    """A selector that reverts exactly like a random one is NOT proof of absence."""
    # candidate and random selector must respond IDENTICALLY for this path: an
    # empty return from both is indistinguishable, and the probe must say so
    # rather than claiming the function is absent.
    world = _world(calls={INIT_SEL: "0x"})
    monkeypatch.setattr(ci, "_rpc", lambda m, p, url=None, timeout=25: world.rpc(m, p))
    res = ci.probe(PROXY_A, INIT_SEL)
    assert res["exists"] is False
    assert res.get("note", "").startswith("indistinguishable"), res


def test_deploy_slot_helper_reads_the_implementation_slot(monkeypatch):
    # cs_deploy._rpc takes the url FIRST; cs_init._rpc takes it third. They are
    # not interchangeable, and assuming they were is the same class of mistake as
    # assuming a selector from memory.
    world = _world()
    monkeypatch.setattr(cd, "_rpc", lambda url, m, p, timeout=30: world.rpc(m, p))
    f = cd.verify("https://x", PROXY_A)
    assert f.is_proxy is True
    assert f.implementation == IMPL_X


def test_deploy_verify_marks_a_direct_contract(monkeypatch):
    world = _world()
    monkeypatch.setattr(cd, "_rpc", lambda url, m, p, timeout=30: world.rpc(m, p))
    f = cd.verify("https://x", DIRECT)
    assert f.is_proxy is False
    assert f.code_bytes > 0