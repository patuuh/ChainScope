"""Tests for cli/cs_move_parse.py - the structural Move parser.

Each test here pins a failure the regex detectors actually had:

  * a brace inside a string must not shift brace matching
  * a `//` comment containing `fun` or `}` must not create a phantom function
  * parameters must be readable as types, not text
  * `init` must be visible even though it is private
  * `acquires` must be attributable to the right function
"""

from __future__ import annotations

from cli.cs_move_parse import parse_module, tokenize


# ------------------------------------------------------------------ tokenizer


def test_braces_inside_strings_do_not_shift_matching():
    src = """
    module m::n {
        public fun a() {
            let s = b"}}} fun fake(";
        }
        public fun b() { let x = 1; }
    }
    """
    names = [f.name for f in parse_module(src)]
    assert names == ["a", "b"], f"string literal corrupted brace matching: {names}"


def test_comment_containing_fun_is_not_a_function():
    src = """
    module m::n {
        // public fun commented_out() { }
        /* public fun also_commented() { } */
        public fun real() { }
    }
    """
    names = [f.name for f in parse_module(src)]
    assert names == ["real"]


def test_nested_block_comments_are_handled():
    src = """
    module m::n {
        /* outer /* inner */ still comment */
        public fun real() { }
    }
    """
    assert [f.name for f in parse_module(src)] == ["real"]


def test_escaped_quote_in_string():
    src = r"""
    module m::n {
        public fun a() { let s = "a \" } b"; }
        public fun b() { }
    }
    """
    assert [f.name for f in parse_module(src)] == ["a", "b"]


def test_tokenizer_keeps_line_numbers():
    toks = tokenize("module a\n\nfun b() { }")
    fn = next(t for t in toks if t.value == "fun")
    assert fn.line == 3


# --------------------------------------------------------------------- params


def test_parameter_types_are_structured():
    src = """
    module m::n {
        public fun mint(
            holder: &mut TreasuryCapHolder<BLUE>,
            amount: u64,
            recipient: address,
            ctx: &mut TxContext
        ) { }
    }
    """
    fn = parse_module(src)[0]
    assert fn.params[0].name == "holder"
    assert "TreasuryCapHolder" in fn.params[0].type
    assert fn.params[0].is_ref and fn.params[0].is_mut_ref
    assert fn.params[1].type == "u64"
    assert fn.has_param_type("TreasuryCapHolder")


def test_generic_type_with_commas_does_not_split_params():
    """`a: Table<u64, Balance>` contains a comma but is one parameter."""
    src = """
    module m::n {
        public fun f(a: Table<u64, Balance>, b: vector<u8>) { }
    }
    """
    fn = parse_module(src)[0]
    assert len(fn.params) == 2, [p.type for p in fn.params]
    assert "Table" in fn.params[0].type


# ---------------------------------------------------------------- visibility


def test_init_is_parsed_despite_being_private():
    src = """
    module m::n {
        fun init(witness: BLUE, ctx: &mut TxContext) {
            let (cap, meta) = coin::create_currency<BLUE>(witness, 9, b"BLUE", b"B", b"", option::none(), ctx);
            transfer::public_transfer(cap, tx_context::sender(ctx));
        }
        public entry fun mint_tokens(h: &mut Holder, a: u64) { }
    }
    """
    funs = {f.name: f for f in parse_module(src)}
    assert set(funs) == {"init", "mint_tokens"}
    assert funs["init"].visibility == "private"
    assert funs["init"].is_public is False
    assert funs["mint_tokens"].is_entry is True


def test_package_visibility():
    src = """
    module m::n {
        public(package) fun helper() { }
        public(friend) fun buddy() { }
        public fun open() { }
    }
    """
    vis = {f.name: f.visibility for f in parse_module(src)}
    assert vis == {"helper": "public(package)", "buddy": "public(friend)", "open": "public"}


# ------------------------------------------------------------------- returns


def test_return_type_captured():
    src = """
    module m::n {
        public fun get(): u64 { 1 }
        public fun nothing() { }
    }
    """
    funs = {f.name: f for f in parse_module(src)}
    assert funs["get"].ret_type == "u64"
    assert funs["nothing"].ret_type is None


# -------------------------------------------------------------------- bodies


def test_body_is_exact_and_contains_real_calls():
    src = """
    module m::n {
        fun a() {
            dynamic_field::add(&mut id, k, v);
        }
        fun b() { }
    }
    """
    funs = {f.name: f for f in parse_module(src)}
    assert "dynamic_field::add" in funs["a"].body
    assert "dynamic_field::add" not in funs["b"].body


def test_no_cross_function_bleed():
    """The exact bug the regex had: a call credited to the wrong function."""
    src = """
    module m::n {
        public fun innocent(ctx: &mut TxContext) { create(ctx); }
        public fun real(k: String, v: u64) { dynamic_field::add(&mut id, k, v); }
    }
    """
    funs = {f.name: f for f in parse_module(src)}
    assert "dynamic_field::add" not in funs["innocent"].body
    assert "dynamic_field::add" in funs["real"].body


def test_acquires_attributed_to_the_right_function():
    src = """
    module m::n {
        public fun a() acquires R1 { }
        public fun b() acquires R2, R3 { }
        public fun c() { }
    """
    acq = {f.name: f.acquires for f in parse_module(src)}
    assert acq["a"] == ["R1"]
    assert acq["b"] == ["R2", "R3"]
    assert acq["c"] == []


# --------------------------------------------------------- the Bluefin source


def test_parses_the_real_bluefin_coin_contract():
    from pathlib import Path

    p = Path("/tmp/kilo/bluefin/bluefin-coin-contracts/sources/blue.move")
    if not p.exists():
        return  # corpus not present; parser covered by the fixtures above
    funcs = {f.name: f for f in parse_module(p.read_text())}
    assert set(funcs) >= {"init", "mint_tokens", "burn_tokens"}
    assert "create_currency" in funcs["init"].body
    assert funcs["mint_tokens"].has_param_type("TreasuryCapHolder")
    assert funcs["mint_tokens"].params[2].type == "address"
    # mint_tokens escrows nothing itself; it calls coin::mint_and_transfer
    assert "mint_and_transfer" in funcs["mint_tokens"].body