# HackenProof Program Filter — ChainScope Results

**Date:** September 28, 2026
**Tool:** ChainScope `cli/cs_hacken.py` (live HackenProof dashboard API)
**Catalog:** 424 programs, fetched live
**Criteria:** active · reputation ≤ 80 · **no submission fee** · smart-contract scope

---

## Filter chain (applied to live data, not cache)

| Step | Filter | Remaining |
|---|---|---|
| 0 | Full catalog | 424 |
| 1 | Status = Active | 154 |
| 2 | `min_reputation_points` is null or ≤ 80 | 36 |
| 3 | Labels contain `smart contract` | 16 |
| 4 | Not an audit contest | 15 |
| 5 | **`submission_cost` == 0** | **5** |

---

## Matches (4 worth pursuing)

| # | Program | Rep gate | Reports | Max bounty | KYC | PoC required | Link |
|---|---|---|---|---|---|---|---|
| 1 | **Cronos zkEVM Smart Contracts** | **0** | 234 | $200,000 | Yes | No | [link](https://hackenproof.com/programs/cronos-zkevm-smart-contracts) |
| 2 | **Cronos Smart Contracts** | 50 | 210 | $250,000 | Yes | Yes | [link](https://hackenproof.com/programs/cronos-smart-contracts) |
| 3 | **Bluefin Dex Contracts** | **0** | 260 | $15,000 | Yes | Yes | [link](https://hackenproof.com/programs/bluefin-dex-contracts) |
| 4 | Whitechain Bridge | 50 | 1,515 | $10,000 | No | Yes | [link](https://hackenproof.com/programs/whitechain-bridge) |

**Excluded — pays nothing:** UACatsDivision Smart Contracts matches every filter (rep 0, fee 0, 81 reports, no KYC) but has `min_bounty: 0`, `max_bounty: 0`, `total_rewards: 0`. It is a Ukrainian Armed Forces NFT collection that pays $0. Not worth submitting to.

---

## Analysis

### 1. Cronos zkEVM — best target
`max $200k`, **no reputation gate at all**, 234 reports (thinner than most), and **`poc_required: false`**. You already have a built graph for this one:
`hacken-cronos-smart-contracts.db` and its `_surface/hotspots.json`. Lowest friction and highest ceiling in the set.

### 2. Cronos Smart Contracts
Highest ceiling ($250k) and thin-ish hunt (210 reports) at a 50-point gate. You also have `cronos_veno.db`, `cronos_vvs.db`, `cronos_zap.db` already indexed. Requires a PoC.

### 3. Bluefin Dex Contracts
Only **15k max** against 260 reports — poor risk/reward. Note it is **Move**, not Solidity, so the existing Solidity-oriented graph tooling does not apply directly. Recently updated (24 Sep 2026), so scope is fresh. Its low ceiling is the deciding factor.

### 4. Whitechain Bridge
1,515 reports makes this thoroughly picked over, and $10k is the lowest real ceiling. **No KYC** is the only real advantage. Scope is narrow and self-described: "on-chain contracts Bridge and Mapper and their direct dependencies," focused strictly on user-fund safety. Its own description calls it a *centralized* bridge — worth reading the program rules carefully before investing time.

---

## Friction to plan for

- **KYC required** on the top 3 (Cronos zkEVM, Cronos, Bluefin). Budget time for identity verification before payout.
- **PoC required** on Cronos and Bluefin. The Cronos zkEVM program does not require one, which makes it the most practical first submission.
- The submission fee is genuinely $0 across all four, so there is no financial risk in submitting.

---

## Tooling note

`cs_hacken.py` captures `submission_cost` in its `_row()` output but **no command filters on it** — `hacken list` has `--max-rep`, `--only-sc`, `--no-audits`, `--min-bounty`, but no `--max-fee`. The fee filter was applied externally against the fetched JSON.

Worth adding a `--max-fee` option to `list_programs` if this filter matters regularly:

```python
max_fee: float = typer.Option(None, "--max-fee", help="Max submission fee (0 = free only)")
...
and (max_fee is None or fee(p) <= max_fee)
```

Also note `hacken list --refresh` failed with `RemoteDisconnected` partway through pagination (page 16 of 21). The fetch has no retry logic, and a single dropped connection aborts the whole refresh, leaving the 24h cache stale. The pagination loop in `_fetch_all()` is worth hardening with retries and a per-page fallback.

---

## Data provenance

```bash
cd ~/Developments/Personal/Hacks/Immunefi/ChainScope
python3 -m cli hacken list --max-rep 80 --only-sc --top 200 --json
# fee filter applied externally (no --max-fee flag exists)
```

Live re-fetch of all 424 programs confirmed the cached results. All four program pages return `HTTP 200` and report status `Active`.

---

*Generated: September 28, 2026*
