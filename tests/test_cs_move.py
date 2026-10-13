"""Tests for cli/cs_move.py - Move-native detectors.

Two properties matter, and the second is the one that keeps catching me:

  1. recall  - a planted vulnerable shape is detected
  2. absence means something - the detectors do NOT fire on the safe idioms that
     look similar

(2) is not optional. `M5` was implemented as "a public function returning a
reference", which matched 101 ordinary getters across the Sui framework
(`public fun name(self: &Validator): &String`). Those are borrows bound to the
input's lifetime; the borrow checker makes the escape unrepresentable, so the
class was wrong and was deleted rather than tuned.

The same failure hit twice more in the Solidity scanner the same day: class 20's
bare `EntryPoint` and class 11's bare `healthFactor`. The recurring error is
writing a pattern that matches a safe idiom instead of a risk shape.
"""

from __future__ import annotations

from pathlib import Path

from cli.cs_move import MOVE, _fun_bodies, move_files, scan, summary


def _write(tmp_path: Path, body: str, name: str = "m.move") -> None:
    (tmp_path / name).write_text(body)


# --------------------------------------------------------------------- M1


def test_m1_detects_caller_supplied_dynamic_field_key(tmp_path):
    _write(tmp_path, """
    module 0x1::bad {
        use sui::dynamic_field;

        public fun record(pool: &mut Pool, k: String, value: u64) {
            dynamic_field::add(&mut pool.id, k, value);
        }
    }
    """)
    hits = scan(tmp_path, ["M1"])
    assert len(hits) == 1
    assert hits[0]["severity_hint"] == "high"


def test_m1_ignores_internally_derived_key(tmp_path):
    """A key derived from a struct tag, not from the caller, is the safe idiom."""
    _write(tmp_path, """
    module 0x1::good {
        use sui::dynamic_field;

        struct Key has copy, drop, store { tag: u64 }

        public fun record(pool: &mut Pool) {
            dynamic_field::add(&mut pool.id, Key { tag: 7 }, 1);
        }
    }
    """)
    assert scan(tmp_path, ["M1"]) == []


def test_m1_ignores_a_guarded_key(tmp_path):
    _write(tmp_path, """
    module 0x1::guarded {
        use sui::dynamic_field;

        public fun record(pool: &mut Pool, k: String, value: u64) {
            assert!(is_valid(&k), EBadKey);
            dynamic_field::add(&mut pool.id, k, value);
        }
    }
    """)
    hits = scan(tmp_path, ["M1"])
    assert len(hits) == 1
    assert hits[0]["severity_hint"] == "low"


def test_m1_does_not_bleed_across_function_boundaries(tmp_path):
    """The first M1 matched a dynamic_field call from the NEXT function.

    Its only hit reported a `dynamic_field::add` against a body of `{ create(ctx); }`,
    because the body was a fixed-size window rather than brace-matched.
    """
    _write(tmp_path, """
    module 0x1::bleed {
        use sui::dynamic_field;

        public fun innocent(ctx: &mut TxContext) {
            create(ctx);
        }

        public fun actual(k: String, v: u64) {
            dynamic_field::add(&mut id, k, v);
        }
    }
    """)
    hits = scan(tmp_path, ["M1"])
    assert len(hits) == 1
    assert hits[0]["fn"] == "actual", f"attributed to the wrong function: {hits[0]}"


# --------------------------------------------------------------------- M3


def test_m3_detects_unfrozen_upgrade_cap_handover(tmp_path):
    _write(tmp_path, """
    module 0x1::bad {
        use sui::package::UpgradeCap;
        use sui::transfer;

        public fun grant_upgrade_cap(cap: UpgradeCap, to: address) {
            transfer::public_transfer(cap, to);
        }
    }
    """)
    assert len(scan(tmp_path, ["M3"])) == 1


def test_m3_ignores_a_frozen_cap(tmp_path):
    _write(tmp_path, """
    module 0x1::good {
        use sui::package::UpgradeCap;

        public fun lock_cap(cap: UpgradeCap) {
            transfer::public_transfer(cap, @0x0);
            cap.into_immutable();
        }
    }
    """)
    assert scan(tmp_path, ["M3"]) == []


# ------------------------------------------------- the deleted class (M5)


def test_reference_returning_getters_are_not_flagged(tmp_path):
    """Move borrows are bound to the input's lifetime, so getters are safe.

    This is why M5 was deleted rather than tuned: it matched 101 Sui framework
    getters like `public fun name(self: &Validator): &String`.
    """
    _write(tmp_path, """
    module 0x1::getters {
        public fun name(self: &Validator): &String { &self.name }
        public fun uid(self: &Kiosk): &UID { &self.id }
        public fun profits_mut(self: &mut Kiosk): &mut Balance { &mut self.profits }
    }
    """)
    assert summary(tmp_path) == {}


# ------------------------------------------------------------- body parsing


def test_fun_bodies_are_brace_matched():
    text = """
    public fun a() { one(); }
    public fun b() { two(); three(); }
    public fun c() { }
    """
    got = {name: body for name, _p, body, _l in _fun_bodies(text)}
    assert set(got) == {"a", "b", "c"}
    assert "two()" in got["b"] and "one()" not in got["b"]
    assert "one()" in got["a"] and "two()" not in got["a"]


def test_move_files_excludes_build_and_test_dirs(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "x.move").write_text("module 0x1::b { }")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.move").write_text("module 0x1::t { }")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.move").write_text("module 0x1::a { }")
    assert {p.name for p in move_files(tmp_path)} == {"a.move"}


def test_extension_set_is_move_only():
    assert MOVE == {".move"}


def test_scan_survives_empty_tree(tmp_path):
    assert scan(tmp_path) == []


def test_m1_ignores_a_freshly_created_parent(tmp_path):
    """A new parent has no existing fields, so a caller key cannot collide.

    This is `Versioned::create` in the Sui framework, and it was the scanner's
    only hit on 117 files of the most-audited Move code in existence.
    """
    _write(tmp_path, """
    module 0x1::versioned {
        public fun create<T: store>(init_version: u64, init_value: T, ctx: &mut TxContext): Versioned {
            let mut self = Versioned { id: object::new(ctx), version: init_version };
            dynamic_field::add(&mut self.id, init_version, init_value);
            self
        }
    }
    """)
    assert scan(tmp_path, ["M1"]) == []


def test_m1_still_fires_on_an_existing_parent(tmp_path):
    """The carve-out must not swallow the real case: an existing mutable parent."""
    _write(tmp_path, """
    module 0x1::real {
        public fun record(pool: &mut Pool, k: String, value: u64) {
            dynamic_field::add(&mut pool.id, k, value);
        }
    }
    """)
    assert len(scan(tmp_path, ["M1"])) == 1


def test_m3_covers_treasury_cap_not_only_upgrade_cap(tmp_path):
    """M3 originally keyed on UpgradeCap only, so it was blind to a token's
    minting authority. Found by running it against bluefin_coin::blue, a 73-line
    contract whose whole security rests on an unfrozen TreasuryCap."""
    _write(tmp_path, """
    module bluefin_coin::blue {
        use sui::coin::TreasuryCap;

        struct TreasuryCapHolder<phantom T> has key, store {
            id: UID,
            treasury: TreasuryCap<T>
        }

        public entry fun hand_off_holder(holder: TreasuryCapHolder<BLUE>, to: address) {
            transfer::public_transfer(holder, to);
        }
    }
    """)
    hits = scan(tmp_path, ["M3"])
    assert len(hits) == 1
    assert "TreasuryCap" in hits[0]["class"] or "capability" in hits[0]["class"]


def test_m3_still_catches_upgrade_cap(tmp_path):
    _write(tmp_path, """
    module 0x1::pkg {
        use sui::package::UpgradeCap;
        public fun grant_upgrade_cap(cap: UpgradeCap, to: address) {
            transfer::public_transfer(cap, to);
        }
    }
    """)
    assert len(scan(tmp_path, ["M3"])) == 1


def test_m3_catches_a_cap_handed_out_from_init(tmp_path):
    """The real Bluefin shape.

    `init` is required to be *private* in Move, and it never names the cap type -
    it calls `coin::create_currency`, binds the result to `treasury_cap`, and
    transfers it. Three separate detectors missed this: one keyed on
    `UpgradeCap` only, one on `public`/`entry` funs only, and one on the
    capability *type name* rather than the operation.
    """
    _write(tmp_path, """
    module bluefin_coin::blue {
        use sui::coin::{Self, Coin, TreasuryCap};
        use sui::transfer;

        struct TreasuryCapHolder<phantom T> has key, store {
            id: UID,
            treasury: TreasuryCap<T>
        }

        fun init(witness: BLUE, ctx: &mut TxContext) {
            let (treasury_cap, metadata) = coin::create_currency<BLUE>(
                witness, 9, b"BLUE", b"Bluefin", b"", option::none(), ctx);
            transfer::public_share_object(metadata);
            let holder = TreasuryCapHolder { id: object::new(ctx), treasury: treasury_cap };
            transfer::public_transfer(holder, tx_context::sender(ctx))
        }

        public entry fun mint_tokens(
            holder: &mut TreasuryCapHolder<BLUE>, amount: u64, recipient: address, ctx: &mut TxContext
        ) {
            let total_supply = coin::total_supply(&holder.treasury);
            assert!(total_supply + amount <= MAX_SUPPLY, EMaxSupplyReached);
            coin::mint_and_transfer(&mut holder.treasury, amount, recipient, ctx)
        }
    }
    """)
    hits = scan(tmp_path, ["M3"])
    assert len(hits) == 1, f"expected the init handover, got {hits}"
    assert hits[0]["fn"] == "init"


def test_m3_ignores_a_frozen_cap_handed_from_init(tmp_path):
    _write(tmp_path, """
    module 0x1::locked {
        use sui::package::UpgradeCap;
        fun init(ctx: &mut TxContext) {
            let cap = package::publish(witness);
            transfer::public_transfer(cap, tx_context::sender(ctx));
            cap.into_immutable();
        }
    }
    """)
    assert scan(tmp_path, ["M3"]) == []
