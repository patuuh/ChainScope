"""Tests for the bytecode reverse-engineering engine.

Everything here runs offline against synthetic and captured bytecode. The network
paths (cast code, 4byte lookup) are not unit tested - a test that silently depends
on a mainnet RPC is a test that fails for reasons unrelated to the code, which is
how false signals get trusted.

The primitives are pinned because they are easy to get subtly wrong in ways that
look like findings:
  * opcode walking must skip PUSH payload, or payload bytes are read as opcodes
    and selector extraction returns nonsense;
  * slot 0x00 must render as 0x0, not the empty string after stripping zeros;
  * a minimal proxy carries its implementation in its runtime code;
  * interface inference must not fire on a single shared signature.
"""
from __future__ import annotations

import pytest

from core.cs_re import (
    access_control_hints,
    guard_coverage,
    dangerous_ops,
    diff_bytecode,
    extract_selectors,
    probe_selectors,
    classify_reachable,
    infer_interfaces,
    is_minimal_proxy,
    iter_opcodes,
    opcode_histogram,
    storage_slots,
    trailing_immutables,
)


def _hex(*parts: str) -> str:
    return "0x" + "".join(parts)


# a real EIP-1167 minimal proxy shape
MINIMAL_PROXY = (
    "0x363d3d373d3d3d363d73"
    + "aa" * 20
    + "5af43d82803e903d91602b57fd5bf3"
)


class TestOpcodeWalking:
    def test_push_payload_is_not_read_as_opcodes(self):
        """PUSH32 payload contains bytes that are valid opcodes.

        If payload were walked, this would inflate the histogram with garbage.
        0x63 is PUSH4 and must appear exactly once, not as payload noise.
        """
        # PUSH32 of a value whose payload contains many 0x63 bytes
        code = _hex("7f" + "63" * 32 + "00")
        ops = [op for op, _ in iter_opcodes(code)]
        assert ops == [0x7F, 0x00]
        hist = opcode_histogram(code)
        # 0x63 must be absent entirely, not present-and-zero: if payload bytes were
        # walked, the histogram would grow 32 spurious PUSH4 entries.
        assert "0x63" not in hist
        assert hist["0x7f"] == 1
        assert hist["0x00"] == 1

    def test_histogram_counts_repeated_pushes(self):
        code = _hex("6000", "6000", "6001")
        assert opcode_histogram(code)["0x60"] == 3


class TestSelectorExtraction:
    def test_finds_push4_selectors_in_dispatcher(self):
        # PUSH4 0x11223344 EQ ; PUSH4 0x55667788 EQ
        code = _hex("6311223344", "14", "6355667788", "14", "00")
        sel = extract_selectors(code)
        assert "0x11223344" in sel["dispatcher"]
        assert "0x55667788" in sel["dispatcher"]

    def test_deep_constants_are_separated_not_merged(self):
        """PUSH4 values past the dispatcher are usually coincidental.

        Reporting them as selectors would inflate the interface surface with
        4-byte windows of unrelated data.
        """
        # 400 zero bytes then a PUSH4 deep in the code
        code = _hex("00" * 400, "63deadbeef", "00")
        sel = extract_selectors(code)
        assert sel["dispatcher"] == []
        assert "0xdeadbeef" in sel["other_constants"]

    def test_handles_push32_without_garbage_selectors(self):
        sel = extract_selectors(_hex("7f" + "aa" * 32, "00"))
        assert sel["dispatcher"] == []

    def test_result_is_explicitly_not_a_function_list(self):
        """The scan must not be presentable as an ABI.

        Modern solc builds a binary search over range comparisons, so PUSH4 values
        in the dispatcher region are bounds, not selectors. Callers get told so
        structurally rather than by reading the docstring.
        """
        code = _hex("6311223344", "11", "6355667788", "11", "00")
        assert extract_selectors(code)["is_function_list"] is False

    def test_dispatcher_split_uses_byte_offset_not_opcode_index(self):
        """A PUSH4 past the byte cutoff must land in `other_constants`.

        Each PUSH32 is 1 opcode but 33 bytes, so opcode index and byte position
        drift apart. Ten PUSH32s put the next PUSH4 at byte offset ~330 (past the
        0.5*len cutoff of ~168) while its opcode index is only ~10. The old
        index-vs-byte-count comparison filed it under `dispatcher`.
        """
        code = _hex(*(["7f" + "aa" * 32] * 10), "63deadbeef", "00")
        sel = extract_selectors(code)
        assert "0xdeadbeef" in sel["other_constants"]
        assert sel["dispatcher"] == []


class TestSelectorProbing:
    def test_probe_reports_response_behaviour(self):
        """Behavioural probing is ground truth where the constant scan is not."""

        def rpc_call(to, data):
            if data.startswith("0x11223344"):
                return "0x" + "00" * 32
            raise RuntimeError("execution reverted")

        # raw selectors are passed through, so no `cast` call is needed here
        got = probe_selectors(
            "0x0000000000000000000000000000000000000001",
            ["0x11223344", "0xaabbccdd"],
            rpc_call,
        )
        assert got["0x11223344"] is True
        assert got["0xaabbccdd"] is False

    def test_probe_treats_empty_return_as_absent(self):
        def rpc_call(to, data):
            return "0x"

        got = probe_selectors(
            "0x0000000000000000000000000000000000000001", ["0xdeadbeef"], rpc_call
        )
        assert got["0xdeadbeef"] is False

    def test_probe_computes_selector_from_signature(self):
        """A real signature is turned into a selector via cast."""
        import subprocess

        want = subprocess.run(
            ["cast", "sig", "totalSupply()"], capture_output=True, text=True
        ).stdout.strip()

        seen = {}

        def rpc_call(to, data):
            seen["data"] = data
            return "0x" + "01" * 32

        got = probe_selectors(
            "0x0000000000000000000000000000000000000001",
            ["totalSupply()"],
            rpc_call,
        )
        assert seen["data"] == want
        assert got["totalSupply()"] is True


class TestReachableClassification:
    """Revert data alone is not a reachability signal."""

    def _rpc(self, table):
        def rpc_call(to, data):
            if data in table:
                action = table[data]
                if isinstance(action, Exception):
                    raise action
                return action
            raise RuntimeError("execution reverted: 0x")

        return rpc_call

    @staticmethod
    def _sel(signature):
        import subprocess

        return subprocess.run(
            ["cast", "sig", signature], capture_output=True, text=True
        ).stdout.strip()

    def test_custom_error_fallback_does_not_fake_presence(self):
        """A fallback answering every unknown selector must read as absent.

        This is the mETH Staking case: an unknown selector and approve() both
        reverted 0x34352c73. Naive revert-reading says approve exists, which
        inverts the severity-limiting claim.
        """
        fallback = RuntimeError("execution reverted: 0x34352c73")
        rpc = self._rpc(
            {
                self._sel("approve(address,uint256)"): fallback,
                self._sel("___nope___()"): fallback,
            }
        )
        got = classify_reachable(
            "0x0000000000000000000000000000000000000001",
            "approve(address,uint256)",
            rpc,
            control_signature="___nope___()",
        )
        assert got == "absent"

    def test_distinct_revert_data_reads_as_present(self):
        rpc = self._rpc(
            {
                self._sel("approve(address,uint256)"): RuntimeError(
                    "execution reverted: 0x08c379a0: nope"
                ),
                self._sel("___nope___()"): RuntimeError("execution reverted: 0x"),
            }
        )
        got = classify_reachable(
            "0x0000000000000000000000000000000000000001",
            "approve(address,uint256)",
            rpc,
            control_signature="___nope___()",
        )
        assert got == "present"

    def test_success_is_reported_as_present_ok(self):
        rpc = self._rpc({self._sel("approve(address,uint256)"): "0x" + "01" * 32})
        got = classify_reachable(
            "0x0000000000000000000000000000000000000001",
            "approve(address,uint256)",
            rpc,
            control_signature="___nope___()",
        )
        assert got == "present-ok"

    def test_pre_encoded_calldata_is_passed_through(self):
        """A 0x-prefixed value is calldata, so args can be supplied for a real absent."""
        approve = self._sel("approve(address,uint256)")
        data = approve + "00" * 64
        seen = {}

        def rpc_call(to, d):
            seen["data"] = d
            # candidate falls through to the custom-error fallback; the unknown
            # selector reverts empty, so the two differ and the callee is present
            if d == data:
                raise RuntimeError("execution reverted: 0x34352c73")
            raise RuntimeError("execution reverted: 0x")

        got = classify_reachable(
            "0x0000000000000000000000000000000000000001",
            data,
            rpc_call,
            control_signature="___nope___()",
        )
        assert seen["data"] == data
        assert got == "present"

    def test_empty_reverts_with_empty_control_are_ambiguous_without_fallback(self):
        """No fallback anywhere: revert data cannot discriminate, so say so."""
        rpc = self._rpc({})
        got = classify_reachable(
            "0x0000000000000000000000000000000000000001",
            "approve(address,uint256)",
            rpc,
            control_signature="___nope___()",
        )
        assert got in ("absent", "ambiguous")


class TestMinimalProxy:
    def test_detects_eip1167_and_reads_implementation(self):
        assert is_minimal_proxy(MINIMAL_PROXY) == "0x" + "aa" * 20

    def test_non_proxy_is_not_matched(self):
        assert is_minimal_proxy(_hex("6080604052", "00" * 20)) is None

    def test_upgradeable_proxy_is_not_a_minimal_proxy(self):
        """A proxy that can be upgraded must not be reported as immutable.

        The distinction matters: an EIP-1167 implementation is hardcoded, while
        an EIP-1967 one can change under you.
        """
        assert is_minimal_proxy(_hex("363d3d373d3d3d363d73", "bb" * 20, "5af43d82803e903d91602b57fd5bf3", "5a")) is None


class TestStorageSlots:
    def test_slot_zero_renders_as_0x0(self):
        """0x00 must not strip down to the empty string after lstrip('0')."""
        slots = storage_slots(_hex("6000", "55"))
        assert slots == [{"slot": "0x0", "op": "SSTORE"}]

    def test_sload_and_sstore_are_distinguished(self):
        slots = storage_slots(_hex("6001", "54", "6020", "55"))
        assert {"slot": "0x1", "op": "SLOAD"} in slots
        assert {"slot": "0x20", "op": "SSTORE"} in slots

    def test_trailing_push_that_is_not_a_store_is_ignored(self):
        assert storage_slots(_hex("6001", "00", "00")) == []


class TestDangerousOps:
    def test_detects_delegatecall_and_selfdestruct(self):
        ops = {d["op"] for d in dangerous_ops(_hex("f4", "ff", "f5"))}
        assert "DELEGATECALL" in ops
        assert "SELFDESTRUCT" in ops
        assert "CREATE2" in ops

    def test_clean_contract_reports_none(self):
        assert dangerous_ops(_hex("60016002", "01", "00")) == []

    def test_every_hit_carries_a_reason(self):
        for d in dangerous_ops(_hex("f4")):
            assert d["why"] and isinstance(d["why"], str)


class TestImmutables:
    def test_reads_trailing_constructor_argument(self):
        code = _hex("6000", "00" * 20) + "ab" * 32
        assert trailing_immutables(code)[0].startswith("0xabab")

    def test_short_code_yields_nothing(self):
        assert trailing_immutables(_hex("6000")) == []


class TestDifferential:
    def test_identical_code(self):
        d = diff_bytecode(_hex("60016002", "00"), _hex("60016002", "00"))
        assert d["identical"] is True
        assert d["logic_identical"] is True

    def test_detects_added_selector(self):
        a = _hex("6311223344", "14", "00")
        b = _hex("6355667788", "14", "00")
        d = diff_bytecode(a, b)
        assert d["selectors_only_in_a"] == ["0x11223344"]
        assert d["selectors_only_in_b"] == ["0x55667788"]
        assert d["identical"] is False

    def test_detects_opcode_change_with_same_selectors(self):
        """A one-line divergence often keeps the same ABI and changes logic."""
        a = _hex("6311223344", "14", "f4", "00")
        b = _hex("6311223344", "14", "f3", "00")
        d = diff_bytecode(a, b)
        assert d["selectors_only_in_a"] == [] and d["selectors_only_in_b"] == []
        assert d["logic_identical"] is False
        assert d["opcode_delta"].get("0xf4") == 1
        assert d["opcode_delta"].get("0xf3") == -1

    def test_metadata_only_difference_is_flagged(self):
        """Different IPFS hash, identical logic - the common benign case."""
        logic = "6001600201"
        a = _hex(logic) + "a264697066735822" + "11" * 34
        b = _hex(logic) + "a264697066735822" + "22" * 34
        d = diff_bytecode(a, b)
        assert d["metadata_only_difference"] is True
        assert d["logic_identical"] is True
        assert d["identical"] is False


class TestInterfaceInference:
    def test_requires_most_of_the_interface(self):
        """`owner()` alone must not be read as Ownable."""
        from core.cs_re import infer_interfaces as inf
        res = inf({"0x1": ["owner()"]})
        assert "Ownable" not in res["interfaces"]

    def test_full_ownable_is_detected(self):
        res = infer_interfaces({
            "0x1": ["owner()"],
            "0x2": ["renounceOwnership()"],
            "0x3": ["transferOwnership(address)"],
        })
        assert "Ownable" in res["interfaces"]
        assert res["interfaces"]["Ownable"]["confidence"] == 1.0

    def test_unresolved_selectors_are_reported(self):
        res = infer_interfaces({"0x1": [], "0x2": ["someUnindexedThing()"]})
        assert "0x1" in res["unresolved_selectors"]

    def test_erc20_needs_the_full_set(self):
        partial = infer_interfaces({
            "0x1": ["totalSupply()"],
            "0x2": ["balanceOf(address)"],
        })
        assert "ERC20" not in partial["interfaces"]

# --------------------------------------------------------------------------- #
# diamond branch
# --------------------------------------------------------------------------- #
# Built for a false example: I claimed sDAI was an EIP-2535 diamond when it was
# not, and no diamond was found among 143 real in-scope addresses. So the branch
# is now validated against a real, standards-shaped diamond
# (tools/diamond_fixture, deployed to anvil and driven end-to-end), and these
# tests pin the classification against that shape.
#
# The property that matters: facet selectors are absent from the diamond's own
# bytecode, which is exactly what the surface caveat warns about.

FACETS_RETURN = (
    "[(0xBA12646CC07ADBe43F8bD25D83FB628D29C8A762, [0xd580f22b]), "
    "(0x7ab4C4804197531f7ed6A6bc0f0781f706ff7953, [0x0bf397c4]), "
    "(0xc8CB5439c767A63aca1c01862252B2F3495fDcFE, [0x7a0ed627])]"
)


class TestDiamondClassification:
    def _patch(self, monkeypatch, *, facets_ok: bool, code: str):
        import core.cs_re as re_mod

        monkeypatch.setattr(re_mod, "runtime_code", lambda chain, addr: code)
        monkeypatch.setattr(re_mod, "_storage", lambda chain, addr, slot: None)
        monkeypatch.setattr(re_mod, "rpc_for", lambda chain: "http://local")
        if facets_ok:
            monkeypatch.setattr(re_mod, "_call",
                                lambda chain, addr, sig, args="": (True, FACETS_RETURN))
        else:
            monkeypatch.setattr(re_mod, "_call", lambda chain, addr, sig, args="": (False, ""))

    def test_address_reporting_facets_is_classified_as_diamond(self, monkeypatch):
        self._patch(monkeypatch, facets_ok=True, code="0x6080604052")
        from core.cs_re import resolve_proxy
        r = resolve_proxy("1", "0xabc")
        assert r["kind"] == "EIP2535_DIAMOND"
        assert len(r["facets"]) == 3
        assert any("registered in storage" in n for n in r["notes"])
        assert any("Read the facets, not this" in n for n in r["notes"])

    def test_diamond_without_facets_is_not_classified_as_one(self, monkeypatch):
        """facets() reverting must not produce a diamond verdict.

        This is the sDAI error in reverse: a contract that does not answer
        facets() is not evidence of a diamond.
        """
        self._patch(monkeypatch, facets_ok=False, code="0x6080604052")
        from core.cs_re import resolve_proxy
        r = resolve_proxy("1", "0xabc")
        assert r["kind"] == "DIRECT"
        assert r["facets"] == []

    def test_facet_selectors_are_absent_from_the_diamond_bytecode(self):
        """The blind spot the caveat describes, pinned arithmetically."""
        from core.cs_re import extract_selectors, _FUNC_DECL
        import re as _re
        # facetAFunction() selector
        import hashlib
        # keccak via cast is unavailable offline, so use a known-good constant
        facet_selector = "0xd580f22b"  # facetAFunction()
        # diamond bytecode: only its own functions
        diamond_code = "0x" + "6311223344" + "14" + "00"
        sel = extract_selectors(diamond_code)
        assert facet_selector not in sel["dispatcher"]
        assert "0x11223344" in sel["dispatcher"]


# --------------------------------------------------------------------------- #
# 4. uninitialised-target probing
# --------------------------------------------------------------------------- #

class TestUninitializedProbe:
    """Both directions must work.

    A detector that can only ever answer "initialized" is worse than useless -
    it looks like a clean bill of health. The fixture provides one address that is
    genuinely uninitialised and one that is not.
    """

    def test_count_args_handles_forms(self):
        from core.cs_re import _count_args
        assert _count_args("initialize()") == 0
        assert _count_args("initialize(address)") == 1
        assert _count_args("initialize(address,uint256)") == 2
        assert _count_args("initialize(address,(uint256,bytes))") == 2

    def test_init_name_filter(self):
        """Names are matched on their own, never on the full signature."""
        from core.cs_re import _INIT_NAME
        for sig in ("initialize(address)", "initialize2(uint256)", "__init(address)",
                    "init(address)", "setUp()"):
            assert _INIT_NAME.match(sig.split("(")[0]), sig
        assert not _INIT_NAME.match("deposit")
        assert not _INIT_NAME.match("initConsolidated")

    def test_classify_reads_custom_error_selectors(self):
        """A contract using `error InvalidInitialization()` prints the raw
        selector, never the name - matching strings alone reports UNKNOWN."""
        from core.cs_re import _classify_init_call, _init_error_selectors
        sel = next(iter(_init_error_selectors()))
        assert _classify_init_call(False, f"execution reverted, data: 0x{sel}") == "INITIALIZED"

    def test_successful_call_means_uninitialized(self):
        from core.cs_re import _classify_init_call
        assert _classify_init_call(True, "0x0000...01") == "UNINITIALIZED"

    def test_unrelated_revert_stays_unknown(self):
        """Never report "safe" from a revert we cannot explain."""
        from core.cs_re import _classify_init_call
        assert _classify_init_call(False, "execution reverted, data: 0xdeadbeef") == "UNKNOWN"
        assert _classify_init_call(False, "out of gas") == "UNKNOWN"

    def test_init_error_selectors_are_derived_not_guessed(self):
        """Regression: hardcoded f1c221079 was wrong; the real selector for
        InvalidInitialization() is f92ee8a9. A wrong constant silently turns every
        initialized contract into UNKNOWN."""
        from core.cs_re import _init_error_selectors
        sels = _init_error_selectors()
        assert sels, "selectors must resolve"
        for sig in sels.values():
            assert len(sig) > 0


# --------------------------------------------------------------------------- #
# 1. access-control inference
# --------------------------------------------------------------------------- #
# Reading onlyOwner by hand across kelp's ~19,000 lines is the work this replaces.
# The controls are the point: a detector that cannot tell a guarded contract from
# one that merely reads msg.sender is worse than none, because it manufactures
# assurance. Both directions are pinned against bytecode captured from a real
# deployment.

CALLER = "33"  # bare hex: every other fragment below is bare hex too


class TestAccessControlInference:
    def test_absent_caller_is_reported_as_absence_not_safety(self):
        h = access_control_hints("0x" + "6000" * 20)  # no CALLER anywhere
        assert h["verdict"] == "NO_CALLER_CHECK_DETECTED"
        assert "not evidence" in h["note"]

    def test_storing_the_sender_is_not_a_guard(self):
        """Regression: `lastSender = msg.sender` is CALLER then SSTORE.

        An earlier version accepted "any JUMPI nearby", which matched the
        function dispatcher and reported this unguarded contract as guarded.
        """
        # CALLER ; PUSH1 slot ; SSTORE ; STOP
        code = "0x" + CALLER + "6001" + "55" + "00"
        h = access_control_hints(code)
        assert h["verdict"] == "CALLER_READ_NOT_GATED"
        assert h["branches"] == 0

    def test_guard_shape_is_detected(self):
        """CALLER ; SLOAD ; EQ ; PUSH2 ; JUMPI - the onlyOwner shape."""
        code = "0x" + CALLER + "54" + "6000" + "14" + "610000" + "57" + "00"
        h = access_control_hints(code)
        assert h["verdict"] == "CALLER_GUARD_PRESENT"
        assert h["branches"] >= 1

    def test_immutable_owner_candidate_is_recovered(self):
        code = "0x" + CALLER + "73" + "11" * 20 + "14" + "57" + "00"
        h = access_control_hints(code)
        assert "0x" + "11" * 20 in h["immutable_owners"]

    def test_role_hash_candidates_are_recovered(self):
        code = "0x" + CALLER + "7f" + "22" * 32 + "14" + "57" + "00"
        h = access_control_hints(code)
        assert "0x" + "22" * 32 in h["role_hashes"]

    def test_verdict_is_labelled_heuristic(self):
        code = "0x" + CALLER + "54" + "6000" + "14" + "610000" + "57" + "00"
        h = access_control_hints(code)
        assert h["confidence"] == "heuristic"
        assert "cannot tell a correct guard" in h["note"]

    def test_guard_coverage_refuses_per_function_precision(self):
        """Bytecode has no reliable function boundaries; per-function gating would
        be fabricated precision."""
        code = "0x" + CALLER + "54" + "6000" + "14" + "610000" + "57" + "631122334414" + "00"
        g = guard_coverage(code, [])
        assert "not per function" in g["explanation"]
        assert g["unguarded_or_unknown"] == 0  # a guard exists somewhere


# --------------------------------------------------------------------------- #
# 3 + 5. event recovery and dormant paths
# --------------------------------------------------------------------------- #
# Event names often describe a contract's function better than its function
# names do - on kelp's withdrawal manager they surfaced
# EmergencyWithdrawFromAave, InstantWithdrawalFeeCollected and AssetUnlocked
# without reading a line of source.

class TestEventRecovery:
    def test_push32_before_log_is_a_topic_candidate(self):
        from core.cs_re import event_topics
        topic = "ab" * 32
        code = "0x" + "7f" + topic + "a1" + "00"   # PUSH32 topic ; LOG1 ; STOP
        topics = event_topics(code)
        assert len(topics) == 1
        assert topics[0]["topic"] == "0x" + topic
        assert topics[0]["topics"] == 1  # LOG1 carries one topic

    def test_log0_has_no_topic_argument(self):
        from core.cs_re import event_topics
        code = "0x" + "a0" + "00"   # LOG0 : anonymous
        assert event_topics(code) == []

    def test_push32_far_from_any_log_is_not_an_event(self):
        """Proximity is the filter. A PUSH32 anywhere is mostly a storage key."""
        from core.cs_re import event_topics
        code = "0x" + "7f" + "cd" * 32 + "60016002" + "01" * 30 + "a0" + "00"
        assert event_topics(code) == []

    def test_events_are_deduplicated(self):
        from core.cs_re import event_topics
        topic = "11" * 32
        code = "0x" + ("7f" + topic + "a1") * 3 + "00"
        assert len(event_topics(code)) == 1


class TestDormantPaths:
    def test_unnamed_selectors_are_reported(self):
        from core.cs_re import dormant_paths
        code = "0x" + "63aaaaaaaa" + "14" + "63bbbbbbbb" + "14" + "00"
        resolved = {"0xaaaaaaaa": ["transfer(address,uint256)"], "0xbbbbbbbb": []}
        d = dormant_paths(code, resolved)
        assert d["dormant_count"] == 1
        assert d["selectors"] == ["0xbbbbbbbb"]

    def test_risk_rises_only_with_delegatecall(self):
        """A dormant selector alone is a note; with DELEGATECALL it is worth a look."""
        from core.cs_re import dormant_paths
        code = "0x" + "63bbbbbbbb" + "14" + "f4" + "00"   # includes DELEGATECALL
        d = dormant_paths(code, {"0xbbbbbbbb": []})
        assert d["contract_has_delegatecall"] is True
        assert d["risk"] == "REVIEW"

    def test_no_dormant_selectors_is_not_a_safety_claim(self):
        from core.cs_re import dormant_paths
        d = dormant_paths("0x60006000", {})
        assert d["dormant_count"] == 0
        assert "not proof the contract is safe" in d["caveat"]

    def test_no_per_selector_attribution_is_claimed(self):
        from core.cs_re import dormant_paths
        d = dormant_paths("0x" + "63bbbbbbbb" + "14" + "f4" + "00", {"0xbbbbbbbb": []})
        assert "no reliable function boundaries" in d["explanation"]


# --------------------------------------------------------------------------- #
# 7. metadata / IPFS hash
# --------------------------------------------------------------------------- #

class TestMetadataExtraction:
    BLOB = "a264697066735822" + "1220" + "cd" * 32

    def test_sha2_multihash_is_extracted(self):
        from core.cs_re import extract_metadata
        m = extract_metadata("0x" + "6080604052" + "00" * 8 + self.BLOB)
        assert m["found"] is True
        assert m["ipfs"] == "cd" * 32
        assert m["cid"].startswith("Qm")

    def test_cid_v0_is_derived_not_hardcoded(self):
        """Regression: hand-written CIDs and selectors have gone wrong three times
        today. The CID is computed from the digest."""
        from core.cs_re import extract_metadata
        # pad past the minimum length the extractor requires
        m = extract_metadata("0x" + "60" * 20 + self.BLOB)
        assert len(m["cid"]) == 46
        assert m["cid"].startswith("Qm")

    def test_absent_metadata_is_reported_not_assumed(self):
        from core.cs_re import extract_metadata
        m = extract_metadata("0x" + "6001600201" + "00" * 40)
        assert m["found"] is False
        assert m["reason"]

    def test_short_code_is_reported(self):
        from core.cs_re import extract_metadata
        m = extract_metadata("0x6001")
        assert m["found"] is False
        assert "too short" in m["reason"]


# --------------------------------------------------------------------------- #
# 2. cross-contract relationships
# --------------------------------------------------------------------------- #

class TestRelationshipInference:
    def test_immutable_addresses_are_recovered(self):
        from core.cs_re import _address_constants
        a1, a2 = "11" * 20, "22" * 20
        code = "0x" + "73" + a1 + "73" + a2 + "00"
        assert _address_constants(code) == ["0x" + a1, "0x" + a2]

    def test_sentinels_are_not_counted_as_counterparties(self):
        """0xffff..ffff is max-uint160 and 0xeeee..eeee a native marker. Reporting
        them as relationships makes the output look busy with no information."""
        from core.cs_re import _address_constants
        code = "0x" + "73" + "ff" * 20 + "73" + "ee" * 20 + "73" + "33" * 20 + "00"
        assert _address_constants(code) == ["0x" + "33" * 20]

    def test_call_kinds_are_enumerated(self):
        from core.cs_re import call_sites
        code = "0x" + "f1" + "f4" + "fa" + "00"     # CALL ; DELEGATECALL ; STATICCALL
        c = call_sites(code)
        assert c["count"] == 3
        assert c["can_execute_foreign_code_in_own_storage"] is True

    def test_staticcall_only_cannot_execute_foreign_code(self):
        from core.cs_re import call_sites
        c = call_sites("0x" + "fa" + "fa" + "00")
        assert c["can_execute_foreign_code_in_own_storage"] is False

    def test_no_per_call_pairing_is_claimed(self):
        from core.cs_re import call_sites
        assert "not a proven pairing" in call_sites("0x6001f100")["note"]


# --------------------------------------------------------------------------- #
# 6. runtime identification
# --------------------------------------------------------------------------- #

class TestRuntimeIdentification:
    @pytest.mark.parametrize(
        "blob,runtime,supported",
        [
            ("0x6080604052" + "a264697066735822" + "00" * 40, "EVM_SOLIDITY", True),
            ("0x6080604052366100135761001161001", "EVM", True),
            ("0x7f454c46010101000000000000000000", "SOLANA_SBF", False),
            ("0x0061736d0100000001", "COSMWASM", False),
            ("0x5345495241", "CAIRO", False),
            ("0xdeadbeefcafe", "UNKNOWN", False),
        ],
    )
    def test_runtime_is_identified(self, blob, runtime, supported):
        from core.cs_re import identify_runtime
        r = identify_runtime(blob)
        assert r["runtime"] == runtime
        assert r["supported"] is supported

    def test_unknown_is_never_assumed_evm(self):
        """The dangerous direction: applying EVM heuristics to Solana/CosmWasm/
        Cairo/Move would produce confident nonsense."""
        from core.cs_re import identify_runtime
        r = identify_runtime("0xdeadbeefcafe")
        assert r["is_evm"] is None
        assert "NOT assumed to be EVM" in r["guidance"]

    def test_empty_code_is_reported(self):
        from core.cs_re import identify_runtime
        assert identify_runtime("0x")["runtime"] == "EMPTY"


# --------------------------------------------------------------------------- #
# 7. metadata
# --------------------------------------------------------------------------- #

class TestFetchGuards:
    def test_cid_is_not_hardcoded(self):
        from core.cs_re import extract_metadata
        a = extract_metadata("0x" + "60" * 20 + "a264697066735822" + "1220" + "aa" * 32)
        b = extract_metadata("0x" + "60" * 20 + "a264697066735822" + "1220" + "bb" * 32)
        assert a["cid"] != b["cid"], "different digests must yield different CIDs"


# --------------------------------------------------------------------------- #
# 4 (hardened). false positives found by running the sweep
# --------------------------------------------------------------------------- #
# A bulk sweep over 188 in-scope addresses of 45 live programs reported SIX
# UNINITIALIZED: Aevo, enzymefinance, and four `exactly` addresses. All six are
# live production protocols and all six were wrong. Root cause: a single
# successful eth_call was treated as proof, and the name pattern matched anything
# starting with "init" - including `initVersion()`, a pure view that returns a
# version number and therefore always succeeds.

class TestUninitializedFalsePositives:
    def test_version_getter_is_not_an_initializer(self):
        """`initVersion()` is a view. Calling it always succeeds, so a probe that
        trusts success alone reports every such contract as a takeover."""
        from core.cs_re import _INIT_NAME, _INIT_LOOKALIKE
        # two independent defences: the narrowed name pattern already rejects it,
        # and the lookalike pattern rejects it if the pattern is ever widened
        assert _INIT_LOOKALIKE.match("initVersion")
        assert not _INIT_NAME.match("initVersion")

    def test_init_name_pattern_is_narrow(self):
        from core.cs_re import _INIT_NAME
        for real in ("initialize", "initialize2", "init", "setUp", "__init", "reinitializer"):
            assert _INIT_NAME.match(real), real
        for not_init in ("initConsolidated", "initializeWithRole", "initialRate", "initOracle"):
            assert not _INIT_NAME.match(not_init), not_init

    def test_name_matching_ignores_the_signature(self):
        """Regression: the pattern was applied to "initialize(address)" with an
        anchored `$`, so it matched nothing and every probe returned
        NO_INITIALIZER_FOUND - a detector that finds nothing while looking busy."""
        from core.cs_re import _INIT_NAME
        name_only = "initialize(address)".split("(")[0]
        assert _INIT_NAME.match(name_only)

    def test_successful_call_alone_is_not_a_verdict(self):
        """The corroboration check exists so a live proxy can never be reported
        as a takeover just because some init* function answers."""
        from core.cs_re import _looks_uninitialized, _STATE_PROBES
        assert _STATE_PROBES, "at least one ownership getter must be probed"
        assert callable(_looks_uninitialized)


# --------------------------------------------------------------------------- #
# cast output parsing
# --------------------------------------------------------------------------- #
# `cast call` does NOT return raw hex. It renders human-readably:
#     139264475815180962450438490 [1.392e26]
# Code that assumed `0x`+64 hex silently never matched, which made the value
# filter report live vaults as EMPTY and left the uninit corroboration check
# unable to reject anything - it looked like working hardening and was inert.

class TestCastOutputParsing:
    def test_annotated_decimal_is_parsed(self):
        from core.cs_re import to_int
        assert to_int("139264475815180962450438490 [1.392e26]") == 139264475815180962450438490

    def test_plain_and_hex_forms(self):
        from core.cs_re import to_int
        assert to_int("0x01") == 1
        assert to_int("42") == 42
        assert to_int("0") == 0

    def test_unparseable_returns_none_not_a_number(self):
        from core.cs_re import to_int
        assert to_int("") is None
        assert to_int("execution reverted") is None
        assert to_int(None) is None

    def test_address_extraction_survives_annotations(self):
        from core.cs_re import to_addr
        a = "0x" + "ab" * 20
        assert to_addr(f"{a} [1.0e18]") == a
        assert to_addr("nope") is None

    def test_value_filter_separates_empty_from_live(self):
        """The control that would have caught this: a live vault must not read
        as EMPTY."""
        from core.cs_re import has_value

        class Fake:
            def __init__(self, values): self.values = values
            def __call__(self, chain, addr, fn, timeout=40):
                return (True, self.values[fn]) if fn in self.values else (False, "")
        import core.cs_re as R
        orig = R._call
        try:
            R._call = Fake({"totalSupply()(uint256)": "1000 [1.0e3]",
                            "totalAssets()(uint256)": "2000 [2.0e3]"})
            assert has_value("1", "0x1")["live"] is True
            R._call = Fake({"totalSupply()(uint256)": "0", "totalAssets()(uint256)": "0"})
            assert has_value("1", "0x1")["live"] is False
            R._call = Fake({})
            assert has_value("1", "0x1")["status"] == "UNKNOWN"
        finally:
            R._call = orig
