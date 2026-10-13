# Gate pass — 38 untouched Immunefi programs

Systematic first pass over every program in the no-audit-evidence pool that was
not already triaged on disk. Previously each target was hand-picked and then
gated individually; this applies the same checks to all of them at once.

## Results

| Outcome | Count |
|---|---|
| Candidates | 38 |
| Rejected for having no retrievable scope | 7 |
| Readable scope (addresses or repos) | 31 |
| ERC4626 vaults detected among them | 8 |
| Vaults cleared against the inflation attack | 8 |

Vaults: 5 in `yearnfinance`, 3 in `yo-protocol`.

All eight cleared. The attack fails cleanly on each — the attacker loses the
donation (101 tokens) and the victim loses 1 wei — because each vault already
holds enough supply that a 1-wei seed buys a negligible fraction of it. This is
the empty-vault assumption in `cs_econ.donation_attack` showing up again: the
model's worst case is real arithmetic but not a reachable state on a seeded
vault, which is exactly why the fork is the authority.

## Programs with readable scope

yearnfinance(56) hyperlane(212) moneyonchain(53) benqi(36) pareto(26)
debridge(20) axelarnetwork(13) yo-protocol(7) gnosischain(4) hashflow(4)
gamma(3) synthetix(3) galagames(3) utix(1) ichi(4) glodollar(2)

With repos only: trufin chainlink wormhole arbitrum orca hydration obyte charm
starknet-staking mtpelerin berachain-webapps acala marinade harvest beefyfinance

`moneyonchain` reported every address unreachable and is flagged as an endpoint
fault, not a result.

## Caveat

This pass only detects ERC4626-shaped vaults and only tests the donation
attack. It does not run `gate repo` (no local clones for most of these), and it
does not exercise `rounding_drift` or the sandwich model against real
deployments. A "cleared" here means "not vulnerable to first-depositor
inflation", nothing broader.
