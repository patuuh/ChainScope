# HackenProof — where the asymmetry actually is

Prompted by "HackenProof has new programs". The catalogue holds 423 programmes, 153
active. The useful output is not the count — it is that the high ceilings are
mined and the real white space is somewhere else entirely.

## Correction first

My first pass reported "Zest Protocol — $100,000, 0 prior reports" and ranked it as
the standout asymmetry. **That was a parse artifact.** Its `submitted_reports` is
the string `"Private"`, and my `num()` helper silently coerced non-numeric strings
to `0`. Zest's report count is hidden, not zero. A `"Private"` value must be
treated as unknown, never as zero — the same class of error as the `debug_assert`
vs `ensure` distinction this session has been repeatedly making.

## The high ceilings are mined

| programme | ceiling | prior reports |
|---|---|---|
| Nado Smart Contracts | $500,000 | **1,319** |
| Sui Protocol | $250,000 | 1,046 |
| NEAR Protocol | $1,000,000 | 1,019 |
| NEAR Intents: Bridges | $300,000 | 664 |
| Citrea Protocol & Smart Contracts | $250,000 | 675 |
| 1inch Smart Contract | $500,000 | 467 |
| Account Abstraction Bugs | $250,000 | 349 |
| **Starknet Blockchain/DLT** | $250,000 | **94** |

**Of 50 active smart-contract programmes with ceiling ≥ $20k, only one has ≤30 prior
reports, and that one's count is private.** So the "big ceiling" names are a trap:
1,319 reports against a $500k ceiling means the accessible surface is long gone.
A ceiling is a maximum, not an expectation.

This is the Hydration/IPOR contrast inverted. Hydration looked expensive at
$222,222 but had 10 audits and thin prior bounty art. Nado looks cheaper at
$500,000 and has 1,319 prior reports.

## The real finding — Move

| language | programmes | total ceilings | ChainScope coverage |
|---|---|---|---|
| Solidity | 34 | $4,584,000 | complete (21 classes) |
| Rust | 14 | $3,035,000 | R1–R5 |
| **Move** | **16** | **$2,045,000** | **none** |
| Go | 8 | $200,000 | none |
| Wasm | 3 | $620,000 | partial (cs_substrate) |
| FunC / Clarity | 2 | $200,000 | none |
| unstated | 88 | — | — |

**Move is 16 active programmes carrying $2,045,000 in ceilings, and the entire
toolchain is blind to it.**

Two reasons that is the right place to spend the next block of effort, and they
compound:

1. **Scarcity.** Move is the language of Aptos and Sui. The auditor population
   working it is a fraction of the Solidity population, so the same bug class is
   correspondingly less likely to have been found — regardless of report counts.
2. **Different structure, so the existing classes transfer poorly.** Move's
   resource-linear typing (`&T` / `copy T` / `move T`) makes whole Solidity bug
   classes *unrepresentable* rather than merely rare — reentrancy across a resource
   boundary, double-spend of a linear value, storage aliasing via `copy` on a local
   that is then moved. A regex designed for `.sol` or `.rs` finds nothing useful
   here, and the classes that *would* transfer need re-deriving from Move's model,
   not porting.

## Recommendation

**Extend the scanner to Move, do not open another Solidity target.**

The case:

- 16 programmes, $2.0M of ceilings, ~1/50th the auditor density of Solidity
- Sui is in that set at $250,000 with 1,046 reports — Move's largest surface is
  the *most* mined, which is the argument for the other 15, not against them
- The bug classes that dominate Move's history (resource accounting, phantom move
  in public functions, `copy` on an owned value then move) are **not** in the 21
  classes, and they are exactly the Critical-tier ones

The honest cost: this is a tooling build, not a hunting session, and it is only
worth it if the resulting detectors get used on all 16. It is the same shape of
investment that produced R1–R5, which found the one genuine audit gap of the
session.

If a single hunting session is preferred instead: **Starknet Blockchain/DLT** at
$250,000 with 94 reports is the least-mined *named* high ceiling, and Starknet
Cairo is adjacent to the Wasm tooling `cs_substrate.py` already has.
