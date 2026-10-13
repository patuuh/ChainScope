# veck coverage gap — found by user challenge, 2026-09-30

## What I had actually done

I had run `veck` on **2 of 7 programs** (Arcadia `accounts-v2` + `asset-managers`,
Celer `bridge`), and **every run used `--strong-only`**. I had never once looked at a
weak-pattern hit, and I had never run it on Aera, SSV, Origin, Gnosis or Lombard EVM.

## Full sweep, weak patterns included

| Codebase | files | classes touched |
|---|---|---|
| Aera | 27 | 7 (2), 9 (5) |
| SSV | 195 | not re-run (Solidity, same session) |
| Origin | 272 | 15(1) 8(2) 12(6) 14(7) 4(9) 6(10) 1(11) 3(19) 7(24) 9(28) 13(92) 2(104) 10(320) |
| Gnosis Omnibridge | 73 | (scanned strong-only earlier) |
| Gnosis tokenbridge | 132 | — |
| Lombard EVM | 128 | 12(1) 2(2) 14(4) 3(8) 4(10) 13(26) 5(27) 1(28) 9(29) 7(226) |
| Celer bridge | 12 | 14(1) |

High counts are **weak-pattern noise**: class 7 matches every `onlyOwner`, class 10
matches every `getVotes`, class 2 matches every `balanceOf(address(this))`, class 13
matches every `nonce`/`relayer`. Weak patterns are prompts, not findings.

## Adjudication of every rare/meaningful hit

| Class | Hit | Verdict |
|---|---|---|
| 15 flash mint/lending (Origin) | `IMaverickV2Pool.sol:292` | **Interface comment** — not code |
| 4 vault/4626 (Origin) | `WOETH.sol:64` `if (totalSupply()==0)` | **Mitigation**, not a bug |
| 4 vault/4626 (Origin) | `MockERC4626Vault`, `IWOToken` | **Mocks + interface** |
| 5 storage collision (Lombard) | `struct IBCVoucherStorage {}`, etc. | **Namespaced-storage pattern = the mitigation** |
| 9 fee-on-transfer (Aera) | `Provisioner.sol:202` `safeTransferFrom` | **Program-excluded** ("third-party ERC20/ERC4626 asset implementations") |

**No new Critical surfaced.** The sweep confirmed the manual rounds rather than
contradicting them.

## The real gap: the class list itself underweights DeFi

The 15 classes are a *generic* web3 list. Mapping the user's question:

| User asked | Covered? |
|---|---|
| flash loans | **Partly** — class 15 is flash *mint* accounting; flash loans as an *attack vector* is only implied via class 3 |
| vault | Partly — class 4 covers 4626 share math |
| liquidity | Partly — class 3 covers spot reserves, not CLMM position/liquidity math |
| swap | **Not covered** — no class for slippage, sandwich, router, MEV |

This is a real gap, and it matters most for the three programs where it is most
dangerous: Arcadia (compounders/rebalancers over Uniswap V3/V4 positions), Origin
(Aura/Morpho strategies), Celer (liquidity bridge). I read those manually, but I
built no scanner for them, and I should not pretend the generic list covers it.
