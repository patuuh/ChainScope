"""Tests for cli/cs_rust.py - the Rust-native Critical detectors.

The behaviour worth protecting is the R1 discrimination. Hydration's stableswap
contains three sites of the form

    let r: DispatchResult = (|| { ensure!(x >= y, Err); Ok(()) })();
    debug_assert!(r.is_ok(), "... invariant");
    r

which are correct - the `ensure!` is enforced and the Result is returned - and
three of the same file's `debug_assert_issuance_in_sync`, which returned `()` and
had no other check and was a real defect until commit 50a55673c4. A grep cannot
tell those apart. These tests make sure the scanner can.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cli.cs_rust import (
    RUST,
    scan,
    scan_debug_assert,
    scan_donation_shape,
    scan_missing_origin_gate,
    scan_saturating_on_supplied_amount,
    scan_swallowed_value_error,
    summary,
)


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


# ----------------------------------------------------------------- R1: true positives


def test_unit_fn_with_only_debug_assert_is_flagged(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn ensure_issuance_in_sync(pool_id: T::AssetId) {
            let tracked = ShareIssuance::<T>::get(pool_id);
            let total = T::Currency::total_issuance(pool_id);
            debug_assert_eq!(tracked, total, "virtual share issuance out of sync");
        }
    """)
    hits = scan_debug_assert(tmp_path)
    assert len(hits) == 1
    assert hits[0]["fn"] == "ensure_issuance_in_sync"
    assert hits[0]["severity_hint"] == "high"


def test_debug_assert_false_marked_low(tmp_path):
    """Unreachable arms are usually documentation, not an invariant."""
    _write(tmp_path, "lib.rs", """
        fn take_revenue(asset: Asset) {
            match asset {
                Asset { fun: Fungibility::Fungible(a) } => { let _ = a; }
                _ => {
                    debug_assert!(false, "Can only accept concrete fungible tokens");
                }
            }
        }
    """)
    hits = scan_debug_assert(tmp_path)
    assert len(hits) == 1
    assert hits[0]["severity_hint"] == "low"


# ------------------------------------------------------------- R1: false positives


def test_result_returning_fn_with_ensure_is_not_flagged(tmp_path):
    """The exact Hydration shape: ensure! enforced, debug_assert diagnostic."""
    _write(tmp_path, "lib.rs", """
        fn ensure_add_liquidity_invariant(pool_id: T::AssetId) -> DispatchResult {
            let r: DispatchResult = (|| {
                let d = calculate_d(&reserves)?;
                ensure!(final_r >= initial_r, Error::<T>::InvariantError);
                Ok(())
            })();
            debug_assert!(r.is_ok(), "Stableswap add_liquidity invariant: {r:?}");
            r
        }
    """)
    assert scan_debug_assert(tmp_path) == []


def test_question_mark_body_is_not_flagged(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn check(a: u64) {
            let v = compute(a)?;
            debug_assert_eq!(v, expected);
        }
    """)
    assert scan_debug_assert(tmp_path) == []


def test_result_returning_fn_is_not_flagged(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn ensure_x(id: u32) -> Result<(), Error> {
            debug_assert!(total(id) > 0, "issuance must be positive");
            Ok(())
        }
    """)
    assert scan_debug_assert(tmp_path) == []


# ------------------------------------------------------------------- exclusions


def test_test_and_target_dirs_are_skipped(tmp_path):
    _write(tmp_path, "src/lib.rs", """
        fn f() {
            debug_assert_eq!(1, 2, "real");
        }
    """)
    _write(tmp_path, "tests/it.rs", """
        fn g() {
            debug_assert_eq!(1, 2, "test only");
        }
    """)
    _write(tmp_path, "target/debug/x.rs", """
        fn h() {
            debug_assert_eq!(1, 2, "build artifact");
        }
    """)
    hits = scan_debug_assert(tmp_path)
    assert [Path(h["file"]).name for h in hits] == ["lib.rs"]


# ------------------------------------------------------------------------ R2


def test_r2_flags_raw_balance_share_math(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn shares_for_deposit() -> Balance {
            let supply = total_supply();
            let assets = pool.free_balance();
            assets.checked_div(supply).unwrap_or_default()
        }
    """)
    hits = scan_donation_shape(tmp_path)
    assert hits and all(h["class_id"] == "R2" for h in hits)


def test_r2_suppressed_by_virtual_offset_in_file(tmp_path):
    """Royco-style VIRTUAL_SHARES/VIRTUAL_VALUE files are exonerated."""
    _write(tmp_path, "lib.rs", """
        const VIRTUAL_SHARES: u128 = 1;
        const VIRTUAL_VALUE: u128 = 1;
        fn shares_for_deposit() -> Balance {
            let supply = total_supply() + VIRTUAL_SHARES;
            let assets = pool.free_balance() + VIRTUAL_VALUE;
            assets.checked_div(supply).unwrap_or_default()
        }
    """)
    assert scan_donation_shape(tmp_path) == []


def test_r2_suppressed_by_first_depositor_guard(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn shares_for_deposit() -> Balance {
            let supply = total_supply();
            if supply == 0 { return amount; }
            let assets = pool.free_balance();
            assets.checked_div(supply).unwrap_or_default()
        }
    """)
    assert scan_donation_shape(tmp_path) == []


# ------------------------------------------------------------------- driver


def test_scan_and_summary(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn ensure_sync() {
            debug_assert_eq!(1, 2, "x");
        }
        fn shares() -> Balance {
            let s = total_supply();
            let a = pool.free_balance();
            a.checked_div(s).unwrap_or_default()
        }
    """)
    assert summary(tmp_path) == {"R1": 1, "R2": 1}
    ids = {h["class_id"] for h in scan(tmp_path)}
    assert ids == {"R1", "R2"}


def test_scan_survives_empty_tree(tmp_path):
    assert scan(tmp_path) == []
    assert summary(tmp_path) == {}


def test_scan_does_not_crash_on_broken_input(tmp_path):
    """A malformed tree must not abort the sweep."""
    (tmp_path / "weird").mkdir()
    (tmp_path / "weird" / "x.rs").write_bytes(b"\xff\xfe\x00broken rust \xc3\x28")
    scan(tmp_path)  # must not raise


def test_rust_extension_set_is_rs_only():
    assert RUST == {".rs"}

# --------------------------------------------------------------- extractor
#
# The extractor required the opening brace on the signature line, so it matched
# 7 of 89 `debug_assert!` sites in HydraDX-node. A 260k-line tree then reported
# "2 findings" and looked clean when it had never really been examined. These pin
# the multi-line cases that caused it.


def test_multiline_signature_is_captured(tmp_path):
    _write(tmp_path, "lib.rs", """
        pub fn ensure_trade_invariant(
            pool_id: T::AssetId,
            initial_reserves: &[AssetReserve],
        ) -> DispatchResult
        {
            debug_assert_eq!(a, b, "invariant");
        }
    """)
    assert len(scan_debug_assert(tmp_path)) == 1


def test_return_type_on_its_own_line_is_captured(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn check_state(id: u32)
            -> DispatchResult
        {
            debug_assert!(total(id) == 0, "unreachable");
        }
    """)
    assert len(scan_debug_assert(tmp_path)) == 1


def test_generic_and_nested_generics_do_not_break_extraction(tmp_path):
    _write(tmp_path, "lib.rs", """
        pub fn f<T: Config, V: Into<Option<(A, B)>>>(x: Vec<Option<u8>>) {
            debug_assert_eq!(x.len(), 0, "x");
        }
    """)
    assert len(scan_debug_assert(tmp_path)) == 1


def test_r1_demotes_assert_guarding_saturating_arithmetic(tmp_path):
    """debug_assert + saturating_div(0)==0 documents a precondition, not a gap."""
    _write(tmp_path, "lib.rs", """
        fn calculate_target_fee(current: &[(u32, u32)]) -> u32 {
            let b: u32 = delta.block_diff;
            debug_assert!(!b.is_zero(), "Block difference cannot be zero");
            let r = delta.delta.saturating_div(&b);
            r
        }
    """)
    hits = scan_debug_assert(tmp_path)
    assert len(hits) == 1
    assert hits[0]["severity_hint"] == "low"


def test_r3_clears_config_qualified_origin_gate(tmp_path):
    """`<T as Config>::AuthorityOrigin::ensure_origin(origin)` is a real gate."""
    _write(tmp_path, "lib.rs", """
        #[pallet::call]
        impl<T: Config> Pallet<T> {
            pub fn remove_collateral_asset(
                origin: OriginFor<T>,
                asset_id: T::AssetId,
            ) -> DispatchResult {
                <T as Config>::AuthorityOrigin::ensure_origin(origin)?;
                Collaterals::<T>::remove(asset_id);
                Ok(())
            }
        }
    """)
    assert scan_missing_origin_gate(tmp_path) == []


def test_r3_still_flags_genuinely_ungated_extrinsic(tmp_path):
    _write(tmp_path, "lib.rs", """
        #[pallet::call]
        impl<T: Config> Pallet<T> {
            pub fn set_fee(origin: OriginFor<T>, fee: Permill) -> DispatchResult {
                Fee::<T>::put(fee);
                Ok(())
            }
        }
    """)
    assert len(scan_missing_origin_gate(tmp_path)) == 1


def test_r4_ignores_multiline_call_that_propagates(tmp_path):
    """The `?` is usually on the closing line, not the opening one."""
    _write(tmp_path, "lib.rs", """
        fn ok() -> DispatchResult {
            let _ = <T as Config>::Currency::burn_from(
                debt_asset,
                &pallet_acc,
                debt_to_cover,
                Preservation::Expendable,
            )?;
            Ok(())
        }
    """)
    assert scan_swallowed_value_error(tmp_path) == []


def test_r4_catches_burn_from_swallowed(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn bad() -> DispatchResult {
            let _ = <T as Config>::Currency::burn_from(
                debt_asset,
                &pallet_acc,
                debt_to_cover,
                Preservation::Expendable,
            );
            Ok(())
        }
    """)
    assert len(scan_swallowed_value_error(tmp_path)) == 1


# --------------------------------------------------------------------- R5
#
# Grounded in Hydration's own $500k post-mortem: `let diff =
# atoken_balance.saturating_sub(amount)` where `amount` is caller-supplied, so
# underflow silently selected a "withdraw all" branch and aToken transfers never
# failed for insufficient balance. The detector must catch that shape and stay
# off the same-operation `value - remaining` idiom that cannot underflow.


def test_r5_catches_documented_atoken_shape(tmp_path):
    _write(tmp_path, "lib.rs", """
        fn transfer_a_token(currency_id: u32, who: u64, amount: Balance) -> DispatchResult {
            let atoken_balance = T::Erc20Currency::free_balance(contract, who);
            let diff = atoken_balance.saturating_sub(amount);
            if diff.is_zero() { do_withdraw_all(currency_id, who)?; }
            Ok(())
        }
    """)
    hits = scan_saturating_on_supplied_amount(tmp_path)
    assert len(hits) == 1
    assert hits[0]["class_id"] == "R5"


def test_r5_ignores_same_operation_idiom(tmp_path):
    """`value - unreserve_named(...)` cannot underflow; flagging it is noise."""
    _write(tmp_path, "lib.rs", """
        fn unreserve_named(
            id: &ReserveIdentifier,
            currency_id: u32,
            who: u64,
            value: Balance,
        ) -> Balance {
            let remaining = T::MultiCurrency::unreserve_named(id, currency_id, who, value);
            let unreserved = value.saturating_sub(remaining);
            unreserved
        }
    """)
    assert scan_saturating_on_supplied_amount(tmp_path) == []


def test_r5_requires_a_supplied_amount_parameter(tmp_path):
    """No caller-supplied amount in scope -> not the dangerous shape."""
    _write(tmp_path, "lib.rs", """
        fn classify(a: u128, b: u128) -> u128 {
            let issuance_increase = total_issuance.saturating_sub(last_issuance);
            issuance_increase.saturating_add(a)
        }
    """)
    assert scan_saturating_on_supplied_amount(tmp_path) == []
