# Detector validation harness

Every wrong number this session came from the same place: **a detector that returned
an answer I could not distinguish from a correct one.** None of them raised. All were
believed.

| wrong number | why it looked fine |
|---|---|
| 274 "beacon proxies" | `classify` set the label whenever the impl slot was empty, so every direct contract matched |
| fabricated selectors | `initialized()` recorded as `0xf7a05767` instead of `0x158ef93e`; probes "reverted", which reads as evidence |
| `_initialized = 0` on two implementations | read implementation storage, where it is always empty — would have been a fabricated Critical |
| 273 / 137 "strong" class hits | classes keyed on bare identifiers, matching vocabulary not risk |
| GMX "done" | 20 lines of 3,586 |

## What the harness does

Two files, 31 fixtures, giving each detector cases where **the truth is known** and
failing the build when it disagrees. The point is not coverage — it is that a wrong
number now breaks CI instead of depending on me noticing it.

`tests/test_detector_validation.py` — deployment axis, RPC mocked. Exact and fast
because what broke was slot interpretation and model classification, not connectivity.
Covers: a direct contract must not be called a proxy (the beacon bug's own case); a
beacon proxy must resolve through to its implementation; an implementation proxy must
not be called a beacon; `initialized() == 0` must surface (known positive) and `== 1`
must not (known negative); a **reverting** read must never be reported as a value; a
selector behaving identically to a random one must be reported **indistinguishable**,
not as proven absent — the distinction the whole axis turned on; plus pins for the
resolved selectors and the fact that `cs_deploy._rpc` and `cs_init._rpc` take
incompatible signatures.

`tests/test_detector_fixtures.py` — M1, M3, R1, R2, class 20, class 11. Each gets a
known positive and 2–3 known negatives: an internally derived dynamic-field key, a
freshly created parent, a frozen capability, a virtual offset, a first-depositor
guard, a project-local `EntryPoint` contract name, a local variable named `postOp`.

Two semantic subtleties it pins deliberately:

- **class 11 must still MATCH `healthFactor`, but only at weak strength.** The class
  was demoted because 137 "strong" hits were Aave's canonical identifier. Fixing it
  meant stopping it *counting*, not stopping it *matching* — navigation is still useful.
- **R1's saturating-arithmetic demotion is a Rust-convention rule**, so its fixtures
  are written in Anchor syntax. An early version used Solidity `function`, and the
  scanner — correctly — found nothing, because it scans Rust `fn`.

## What the harness immediately found

Two genuine defects and four broken tests, in the harness's first run:

1. **`cs_rust`'s first-depositor guard missed indirection.** `let supply =
   total_supply(); if (supply == 0) { return amount; }` read as *unguarded* because the
   regex wanted `total_supply() == 0` literally. This is the identical indirection
   failure that produced the GMX monotonicity and `min_`/`max_` test bugs — the
   detector had the same blind spot the tests had. Now resolved through the same
   binding table used for the flag, and the guard pattern tolerates a parenthesised
   condition.

2. The remaining four were my own tests: a helper that passed a `StringIO` where the
   detectors `rglob` a `Path` (**so every assertion passed vacuously while scanning
   nothing**), Solidity syntax in a Rust scanner, `.sol` filenames for a `.rs`-only
   scanner, and a duplicated import from the wrong package.

The StringIO one is the most important: a green test that tested nothing is exactly
the failure mode this harness exists to eliminate, and it happened to the harness.

## Limits

These pin the *logic* of six detectors on synthetic inputs. They do not validate a
sweep against a live chain, and they cannot catch a detector that is right on fixtures
and wrong on real bytecode. The remaining Veck classes — 1, 6, 12, 13, 15, 18 — have
self-consistency tests but no known-positive assertions, and that is the obvious next
step.

This does not make me less likely to be wrong. It converts the one failure mode
that produced six wrong numbers today — a plausible number with nothing behind it —
into a red build.
