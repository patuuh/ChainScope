# Move: from regexes to a parser, and what it surfaced

The recommendation was to build a parser rather than a fifth regex. Four precision
iterations on M1 and four on M3 was the same signal twice, and every failure had one
cause: patterns matching **text** instead of **structure**.

## `cli/cs_move_parse.py`

Parses the subset the detectors need — `fun`, visibility/`entry` modifiers,
`acquires`, parameters with types, return type, brace-matched body.

* `tokenize` drops comments and string/byte-string literals, so a `}` inside
  `b"}}}"` cannot shift brace matching. Nested block comments handled.
* `parse_functions` brace-matches from the `fun` keyword, so a body is exact.
* Parameters are structured values, so a detector can ask "takes `&mut
  TreasuryCapHolder`" instead of "this line contains cap".
* `parse_module` attaches visibility from **both** placements — same-line
  (`public entry fun f()`, the dominant style) and stacked above.

Three bugs surfaced building it, each of which a test now pins:

1. Only scanning lines *above* `fun` meant **every same-line modifier was missed**
   and all functions parsed as private.
2. A trailing `\b` on the visibility regex let `public` match before the `(`, so
   `public(package)` collapsed to `public` and the qualifier was lost.
3. `_render` needed a real source span for parameter types.

14 tests, including a fixture reproducing the exact Bluefin `init` and the exact
cross-function bleed the regex had.

## The detectors, rebuilt on it

`M1` now reads the key *argument* of `dynamic_field::add`/`borrow_mut` rather than
scanning a window, so a struct literal `Key { tag: 7 }` is no longer mistaken for a
caller key, and a parent constructed in the same body is recognised.

`M3` now iterates parsed functions, so private `init` is included by construction
rather than by remembering to match it.

## What it surfaced on the Sui framework

| | regex | parser |
|---|---|---|
| M1 | 0 | 2 |
| M3 | 0 | 5 |

**Seven candidates the regex never saw**, all in the Sui coin machinery:

* `versioned.upgrade` — `new_version` *is* a caller-supplied dynamic-field key, but
  `VersionChangeCap` is a **hot potato** proving the round-trip from
  `remove_value_for_upgrade`, and `old_version < new_version` plus
  `self.version = new_version` keeps exactly one field keyed to the current version.
  Not exploitable.
* `coin.create_regulated_currency_v2`, `coin.mint_and_transfer`,
  `coin.create_regulated_currency` — capability creation for caller-chosen coin
  types, so the creator controls only their own.
* `coin_registry.finalize_registration`, `finalize_and_delete_metadata_cap` —
  `@0x0`-gated (`assert!(ctx.sender() == @0x0, ENotSystemAddress)`).

**No finding**, but each is a real place a human should look, and triaging all seven
took one pass because every hit arrived as a function with typed parameters and an
exact body. That is the difference the build was for.

## Honest status

This converts `cs_move` from *triage aid* toward *coverage*, but it is not a full
type checker and does not try to be — Move's own verifier guarantees the
resource-safety properties these detectors assume. It reads structure; it does not
prove safety.

Still not run against a real HackenProof Move target beyond Bluefin's 73 lines,
because the other 15 programmes' repositories are not public from here
(`hackenproof-public/bluefin-dex-contracts-v3` returns "not found", and HackenProof
itself is Cloudflare-403). That is the remaining gap, and it is an access problem
rather than a tooling one.