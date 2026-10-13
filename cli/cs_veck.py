#!/usr/bin/env python3
"""Scan a contract tree for the 15 Critical-severity web3 vulnerability classes.

This exists because the classes below are what actually convert to a Critical
on Immunefi/Sherlock/Cantina: drain or insolvency, permanent lock, or
unrecoverable governance takeover. Anything short of that (gas waste,
temporary griefing, best practice) is not payable, so a triage that spends its
whole budget on low-severity hunting is wasted.

The scanner is a *triage aid, not an oracle*. Every hit is a prompt to read the
code and adjudicate; the output deliberately carries no severity, because a
regex cannot know whether a real exploit path exists. Several hits will be
false positives by construction (e.g. every proxy has an upgrade function).

Usage:
    python -m cli veck scan path/to/contracts --top 40
    python -m cli veck scan path/to/contracts --class 1 --class 6
    python -m cli veck list
    python -m cli veck checklist
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import re
import typing

import typer

app = typer.Typer()

_SOL = {".sol"}


# Each class: id, name, why it is Critical, where to look, and the evidence
# patterns that justify escalating it. `strong` patterns are much less likely
# to be benign than `weak` ones.
CLASSES: list[dict[str, typing.Any]] = [
    {
        "id": 1,
        "name": "Uninitialized proxies & logic contracts",
        "why": "Attacker calls initialize() on the implementation, takes ownership, then selfdestructs or upgrades the proxy into a state they control.",
        "look": "Any OZ Initializable / UUPS / custom proxy factory. Wormhole $10M was paid for exactly this.",
        "strong": [
            # (?!.*only) excludes role-gated init. The trailing (?!...;) is a LOOKAHEAD
            # because the check is forward-looking: an interface DECLARATION ends in
            # `external;` while an implementation body continues with `external {`.
            # A lookbehind would be illegal here - Python's re requires fixed width.
            r"function\s+initialize\s*\([^)]*\)\s*external(?!.*only)(?!\s*;)",
        ],
        "weak": [
            r"selfdestruct\s*\(",
            r"_disableInitializers\s*\(\s*\)",   # mitigation, not a bug
        ],
    },
    {
        "id": 2,
        "name": "Cross-function / cross-contract read-only reentrancy",
        "why": "State is updated after an external call; a third party reads mid-flight state (virtual price, balances) and acts on skewed values.",
        "look": "Curve/Uniswap/vault integrations; state written after raw transfers.",
        "strong": [],
        "weak": [
            r"get_virtual_price",
            r"balanceOf\s*\(\s*address\(this\)",
        ],
    },
    {
        "id": 3,
        "name": "Oracle manipulation via spot/DEX reserves",
        "why": "Collateral, swap rate or liquidation threshold derived from spot price; flash loan skews the pool, acts, then unwinds.",
        "look": "getReserves, slot0, spot tick, or a spot-based TWAP substitute.",
        "strong": [
            r"getReserves\s*\(",
            r"slot0\s*\(",
            r"get_virtual_price\s*\(",
        ],
        "weak": [r"latestRoundData\s*\("],
    },
    {
        "id": 4,
        "name": "Rounding / inflation attack in share-to-asset ratios (4626)",
        "why": "Empty or first-deposit vault: 1 wei gets 1 share, donation inflates totalAssets, victims round down to 0 shares and the attacker takes their deposit.",
        "look": "ERC4626, yield aggregators, first-deposit paths.",
        "strong": [
            r"totalSupply\s*\(\s*\)\s*==\s*0",
            r"if\s*\(\s*_totalSupply\s*==\s*0\s*\)",
            r"decimalsOffset",
        ],
        "weak": [r"convertToShares", r"previewDeposit"],
    },
    {
        "id": 5,
        "name": "Storage collisions in upgradable contracts",
        "why": "A child contract adds/reorders state without matching the deployed layout, overwriting owner/balances and taking control or corrupting accounting.",
        "look": "Multiple inheritance, v1->v2 upgrade deltas, missing __gap.",
        "strong": [],
        "weak": [
            r"struct\s+\w+Storage",
            r"__gap\s*\[\s*\d+\s*\]",
        ],
    },
    {
        "id": 6,
        "name": "Cross-chain replay & signature malleability",
        "why": "EIP-712 domain omits chainid, so a signature replays on another chain; or s-value not bounded, giving a second valid signature.",
        "look": "Cross-chain messaging, permit, bridges, meta-transactions.",
        "strong": [
            r"ecrecover\s*\(\s*[^,]+,\s*v\s*,\s*r\s*,\s*s\s*\)",
        ],
        "weak": [
            r"EIP712Domain",
            r"DOMAIN_SEPARATOR",
        ],
    },
    {
        "id": 7,
        "name": "Missing/improper access control on admin functions",
        "why": "mint/burn/upgradeTo/withdrawFees/setOracle reachable without a guard -> unrestricted theft.",
        "look": "intended-internal marked public/external; AccessControl init that forgets the admin role.",
        "strong": [
            r"function\s+(upgradeTo|upgradeToAndCall|setOwner|changeOwner|setOracle|withdrawFees|setFeeRecipient)\s*\([^)]*\)\s*(external|public)(?![^{;]*only)",
        ],
        "weak": [r"onlyOwner|onlyRole|_checkOwner"],
    },
    {
        "id": 8,
        "name": "First-in / zero-supply precision in reward accrual",
        "why": "rewardPerToken divides by totalSupply; at zero supply rewards mis-accumulate to the first staker, who claims everything.",
        "look": "StakingRewards clones, reward-per-token accumulators, distribution pools.",
        "strong": [
            r"rewardPerTokenStored\s*\+=",
            r"accRewardPerShare\s*\+=",
        ],
        "weak": [r"accEthPerShare", r"rewardPerToken"],
    },
    {
        "id": 9,
        "name": "Incorrect token handling (fee-on-transfer, ERC-777, rebasing)",
        "why": "Code assumes transferFrom moved exactly `amount`; with a 2% fee the balance grows slower than accounting and the contract goes insolvent.",
        "look": "Multi-token pools, vaults, CDPs accepting arbitrary ERC-20s.",
        "strong": [
            r"balanceOf\([^)]*\)\s*-\s*\w+\s*(?!\s*//)",
        ],
        # The real fee-on-transfer bug: measure the balance, then credit the
        # NOMINAL argument instead of the measured delta. The two statements are
        # adjacent in practice but Solidity formatting puts them on separate
        # lines, so this cannot be matched line-by-line.
        "multiline": [
            r"=\s*\w+\.balanceOf\s*\([^)]*\)[\s\S]{0,400}?\w+\s*(?:\[[^\]]*\])?\s*\+=\s*"
            r"(?:amount|amt|value|assets|shares|depositAmount|tokenAmount)\b",
        ],
        "weak": [
            r"safeTransferFrom",
            r"transferFrom\s*\(",
        ],
    },
    {
        "id": 10,
        "name": "Flash-loan governance hijack",
        "why": "Voting power read from live balance with no snapshot; flash-borrow tokens, pass a proposal/vote in one tx, drain the treasury.",
        "look": "Governor contracts, ERC20Votes without checkpoints, weighted voting pools.",
        "strong": [],
        "weak": [r"getVotes\s*\(", r"getPastVotes", r"Governor"],
    },
    {
        "id": 11,
        "name": "Flawed liquidation math / health factor",
        "why": "Liquidation omits the penalty or lets a liquidator take 100% of collateral for less than the debt -> bad debt, or reserves are drained.",
        "look": "Lending markets, isolated debt pools, synthetic minting.",
        # Reshaped 2026-10-02. `healthFactor` and `liquidateBorrow` are the canonical
        # Aave/Compound V2/V3 identifiers: a portfolio sweep counted 137 "strong" hits
        # for this class, and sampling them showed interface declarations, local
        # variables, doc comments and the heavily-audited GenericLogic library. The
        # count was vocabulary, not risk.
        #
        # A `function healthFactor(` definition is the right place to *start*
        # reading - it is still a navigation aid - but it is not evidence. Real
        # liquidation-math bugs (health-factor comparison inverted, missing
        # MAX_HEALTH_FACTOR sentinel, no zero-collateral guard before dividing,
        # closeFactor treated as 100%) are semantic and need analysis, not a regex.
        "strong": [
            r"function\s+healthFactor\s*\(",
            r"MAX_HEALTH_FACTOR",
            r"liquidationThreshold\s*(?:<|>)\s*(?:ltf|ltc|loan)",
        ],
        "weak": [r"liquidationThreshold", r"closeFactor", r"healthFactor", r"liquidateBorrow"],
    },
    {
        "id": 12,
        "name": "delegatecall to untrusted / user-controlled target",
        "why": "delegatecall runs attacker code in this contract's storage; writing slot 0 overrides owner and hands over control.",
        "look": "Routers, ERC-4337 accounts, multisig implementations, execution proxies.",
        "strong": [
            # key on the TARGET expression, not the first argument. The old
            # (?![\"']) lookahead sat after delegatecall( and so inspected
            # the argument, letting `"0x1234".delegatecall(data)` fire.
            r"(\w[\w.\[\]]*)\.delegatecall\s*\(",
        ],
        "weak": [r"function\s+execute\s*\("],
    },
    {
        "id": 13,
        "name": "Bridge proof verification / relayer logic",
        "why": "Malformed proof, replayed receipt hash, or a verifier bypass mints bridged tokens with no backing deposit.",
        "look": "Merkle/ZK/threshold-sig bridges, L2 lock-and-mint, LayerZero/Wormhole.",
"strong": [
            r"verifyCalldata\s*\(|MerkleProof\.verify|processProof\s*\(",
        ],
        # A finaliser with no proof logic is worth reading but is not evidence of
        # a broken check, so it navigates rather than counts.
        "weak": [r"nonce", r"relayer", r"finalizeDeposit|finalizeWithdrawal|completeDeposit"],
    },
    {
        "id": 14,
        "name": "Unchecked return values / silent failures",
        "why": "Low-level call returns (bool, bytes) instead of reverting; ignored, execution continues assuming the transfer worked.",
        "look": "Batchers, multicall wrappers, splitters, non-standard tokens (USDT).",
        "strong": [
            r"\.call\s*\{\s*value",
            r"\.call\s*\([^)]*\)\s*;",
        ],
        "weak": [r"requireCallResult|verifyCallResult|checkReturn"],
    },
    {
        "id": 15,
        "name": "Accounting mismatch in flash mint / flash lending",
        "why": "Fee, supply update or burn validation happens after control returns, so minted tokens are retained without burning them.",
        "look": "Custom ERC-20, native stablecoins, bespoke lending.",
        "strong": [r"flashMint|_flashLoan"],
        "weak": [r"flash\s*loan|onFlashLoan"],
    },
    {
        "id": 16,
        "name": "Flash-loan-assisted price / collateral manipulation",
        "why": "A protocol prices collateral, rates or thresholds off an instantaneous pool value. A flash loan skews that value within one transaction, the protocol acts on it, the attacker unwinds and keeps the difference.",
        "look": "Pricing helpers that read live reserves/tick instead of a TWAP. Distinct from class 3: this is the *valuation* use, not a raw pool read.",
        "strong": [
            # Intentionally empty. A bare `getReserves(`/`slot0(` is class 3's
            # signal (a raw pool read); class 16 is specifically the *valuation*
            # use - a price/collateral/threshold helper that reads a pool. Putting
            # the pool-read pattern here made the two classes indistinguishable and
            # fired on every AMM interface declaration.
        ],
        "multiline": [
            r"function\s+\w*[Pp]rice\w*\s*\([^)]*\)[\s\S]{0,600}?"
            r"\{\s*[\s\S]{0,400}?(getReserves|slot0|observe|getSqrtRatioAtTick)",
            r"function\s+(?:get|compute|calc|calculate|price|value|collateral|threshold|oracle|quote)\w*\s*\([^)]*\)[\s\S]{0,600}?"
            r"\{\s*[\s\S]{0,400}?(getReserves|slot0|observe|getSqrtRatioAtTick)",
        ],
        "weak": [
            r"twap|TWAP|timeWeightedAveragePrice",   # the MITIGATION - shows intent
            r"getAmountOut\s*\(",
        ],
    },
    {
        "id": 17,
        "name": "Concentrated-liquidity position / pool math",
        "why": "Uniswap V3/V4-style positions are valued by walking ticks and fee growth. Off-by-one tick ranges, wrong fee accounting, or mishandled sqrtPrice precision lets a position be over-valued, or value be extracted by a rebalancer.",
        "look": "Asset managers and strategies that rebalance or compound concentrated-liquidity positions.",
        "strong": [
            r"sqrtPriceX96",
            r"getSqrtRatioAtTick",
            r"feeGrowthInside",
            r"slot0\(\)\.tick|slot0\(\)[^;]*\btick\b",
        ],
        "weak": [
            r"tickLower|tickUpper|positions\(",
            r"TickMath|PositionInfo|CLPool|IClPool",
            r"liquidity\(\)",
        ],
    },
    {
        "id": 18,
        "name": "Swap slippage / sandwich / MEV",
        "why": "A swap is routed without a binding minimum-out or deadline, or a user-facing quote is computed off-manifold. An attacker sandwiches the transaction and extracts the difference from the user.",
        "look": "Routers, zappers, swap-periphery, and any user-facing quote the protocol then trusts.",
        "strong": [
            r"swapExactTokensFor(Token|ETH)SupportingFeeOnTransferTokens",
            r"amountOutMin(imum)?\s*=\s*0\b",
            # getAmountOut over reserves is ordinary AMM code, not a finding.
            # The zero-slippage form above is the real signal.
            r"amountOutMin(imum)?\s*=\s*0\b",
        ],
        "weak": [
            r"deadline",
            r"amountOutMinimum|minAmountOut|minimumOut",
            r"\bswap\b|SwapRouter|amountOut\b",
        ],
    },
    {
        "id": 19,
        "name": "Vault donation / first-depositor inflation",
        "why": "An empty or first-depositor vault mints a trivially small share balance. A donation inflates totalAssets, later deposits round down to 0 shares, and the first depositor withdraws everyone's money.",
        "look": "ERC-4626 vaults, share/reward tokens with a raw totalSupply division. Distinct from class 4: that is generic rounding; this is the donation inflation attack specifically.",
        "strong": [
            r"convertToShares\s*\([^)]*\+\s*1",
            r"virtualShares|virtualAssets|VIRTUAL_SHARES",
            # single-line form of the vulnerable shape: a "total assets" slot assigned
            # straight from this contract's own token balance. Matches xGamma
            # (`totalGamma = gamma.balanceOf(address(this))`) and the Hypervisor's
            # `getTotalAmounts` (`total0 = token0.balanceOf(address(this)).add(base0)`).
            r"\w*[Tt]otal\w*\s*=\s*\w+\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
        ],
        # The two patterns below span identifiers on different lines, so they must
        # live here: `strong`/`weak` are matched per stripped source line and can
        # never fire on a cross-line shape.
        "multiline": [
            # --- the vulnerable shape itself, not just the presence of a mitigation ---
            # Added after xGamma (Gamma, in scope): a Bancor-style checkpoints
            # rebase token. Its enter/leave divide by a raw balanceOf(address(this))
            # with no virtual offset, yet classes 4 and 19 both stayed silent
            # because the only patterns here were the ERC4626 mitigations.
            # PowerToken and the Hypervisor share the same shape and were found by
            # hand, so a regex that only knows how to spot a *fix* misses the bug
            # class it exists to find.
            # Bancor checkpoints: enter/leave, or any mint/redeem pair.
            r"function\s+(?:enter|leave)\w*\s*\([^)]*\)[\s\S]{0,900}?"
            r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)[\s\S]{0,600}?\.div(?:ision)?\s*\(",
            # share price derived from this contract's own idle token balance.
            # The divisor need not be the first argument: IPOR's PowerToken does
            # `MathOperation.division(balanceOfGovernanceToken * 1e18, baseTotalSupply)`,
            # so the total/supply identifier can appear anywhere in the argument list.
            r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)[\s\S]{0,900}?"
            r"\.div(?:ision|mulDiv)?\s*\([^;]{0,160}?\w*[Tt]otal(?:Shares|Supply|Assets|Balance)?\b",
        ],
        "weak": [
            r"totalSupply\s*\(\s*\)\s*==\s*0",     # first-depositor guard = the MITIGATION
            r"previewMint|previewDeposit",
            r"donat|\bskim\b",
        ],
    },
    {
        "id": 20,
        "name": "ERC-4337 paymaster gas-accounting / deposit drain",
        "why": "The paymaster holds an ETH deposit at the EntryPoint and sponsors gas. If any UserOperation field that affects cost is not covered by the signed commitment - or a cap the whitelisted path ignores - one sponsored operation can drain the entire deposit.",
        "look": "Gasless/sponsored-transaction paymasters and relayers. PROVEN FERTILE: the ADI Chain GaslessPaymaster was audited by Hacken in Feb 2026 and still yielded a Critical (unsigned preVerificationGas in the commitment hash, full deposit drain) plus two Highs, all fixed.",
        "strong": [
            r"validatePaymasterUserOp",
            r"_validatePaymasterUserOp",
            # Anchored, not bare names. `postOp\b` matched a local variable named
            # postOp in RoycoDayAccountant, and a bare `EntryPoint` matched
            # Royco's own `RoycoEntryPoint` contract - neither is an ERC-4337
            # paymaster. The 4337 `postOp` is a hook; require the shape.
            r"function\s+postOp\b|postOp\s*\(",
            r"paymasterAndData",
            r"preVerificationGas",
            # EntryPoint only counts when used as the 4337 singleton, i.e. a call
            # site on it - not when it is merely named in a declaration.
            r"EntryPoint\s*\.\s*(?:depositTo|withdrawTo|balanceOf|addStake|"
            r"unlockStake|handleOps|getUserOpHash|getNonce)",
        ],
        "weak": [
            r"BasePaymaster|IPaymaster",
            r"verifyingSigner|VERIFIER_ROLE",
        ],
    },
    {
        "id": 21,
        "name": "Modular account execution (ERC-7579 / account abstraction)",
        "why": "An account is modules, not one contract. A validate/execute split that lets a module, guardian or executor act outside the owner's intent bypasses the account's own authorisation; an unguarded executeBatch or executeFromExecutor drains everything the account holds.",
        "look": "Smart accounts, registrars, module installation, session keys. Systematically younger than the token code these accounts hold, which is why they surface the ADI-class bug.",
        "strong": [
            r"executeFromExecutor",
            r"executeFromModule",
            r"installModule",
            r"uninstallModule",
            r"supportsModule",
            r"ERC7579|ERC-7579|IERC7579",
        ],
        "weak": [
            r"executeBatch",
            r"__validate__|__validate_deploy__",
            r"getGuardian|addGuardian|removeGuardian",
            r"sessionKey|SessionKey",
        ],
    },
]

_BY_ID = {c["id"]: c for c in CLASSES}


# Directories whose contents are not the project's own logic. Scanning them turns
# hit counts into noise: a vendored `lib/openzeppelin-contracts` alone produced more
# class-13 hits (MerkleProof mocks) than every first-party contract put together, and
# a repository's own `test/` tree imports the very helpers the classes look for.
_VENDOR_DIRS = frozenset({
    "node_modules", "lib", "libs", "vendor", "vendors", "out", "cache",
    "artifacts", "artifacts-contracts", "build", "dist", "coverage",
    ".git", ".forge", "broadcast", "typechain", "typechain-types",
    "external", "externals", "deps", "dependencies",
})
_TEST_DIRS = frozenset({
    "test", "tests", "mocks", "mock", "__mocks__", "mocks_contracts",
    "test_contracts", "testnet", "fixtures", "test-fixtures",
})


def _sol_files(
    root: Path, *, include_tests: bool = False, include_vendor: bool = False
) -> list[Path]:
    """Collect first-party Solidity sources under `root`.

    By default, vendored dependency trees and test/mock directories are excluded.
    Both are excluded because they are not the code under audit and they dominate
    hit counts: scanning them can bury a real finding under thousands of hits from
    OpenZeppelin's own mocks, and it can equally make a target look clean because
    the match landed in a vendored copy rather than in first-party code.
    """
    out: list[Path] = []
    for p in root.rglob("*"):
        if p.suffix not in _SOL or not p.is_file():
            continue
        parts = set(p.relative_to(root).parts[:-1]) if p != root else set()
        if not include_vendor and parts & _VENDOR_DIRS:
            continue
        if not include_tests and parts & _TEST_DIRS:
            continue
        out.append(p)
    return out


def _strip(line: str) -> str:
    """Remove line comments so commented-out code does not produce hits."""
    out = re.sub(r"//.*$", "", line)
    return out.split("/*")[0]


# Per-class veto: a match is suppressed when the surrounding line shows the
# pattern is actually handled. Needed where "is this a bug" cannot be decided by
# the presence of a token alone.
#
# Class 14 was the motivating case. Its strong pattern is just `\.call\s*\{\s*value`,
# which cannot distinguish an ignored return from a captured-and-checked one,
# because the two differ only in what sits BEFORE the call:
#
#     to.call{value: amt}("");                                  // ignored - a bug
#     (bool sent,) = payable(to).call{value: amt}("");          // captured
#     if (!sent) revert EthTransferFailed();                     // ...and checked
#
# A variable-length lookbehind would be needed for the regex, which Python's
# `re` does not support. Matching this in the scanner instead keeps the class
# pattern simple and makes the suppression explicit and testable. Without it,
# LRTWithdrawalManager._transferAsset and the treasury-interest path were both
# reported as unchecked-value-transfer bugs despite checking `sent` immediately.
# Per-class veto: a match is suppressed when the surrounding context shows the
# pattern is actually handled. Needed where "is this a bug" cannot be decided by
# the presence of a token alone.
#
# Class 14 is the motivating case. Its strong pattern is just `\.call\s*\{\s*value`,
# which cannot distinguish an ignored return from a captured-and-checked one,
# because the two differ only in what surrounds the call:
#
#     to.call{value: amt}("");                                  // ignored  - a bug
#     (bool success, ) = to.call{value: amt}("");                // captured, UNUSED - a bug
#     (bool sent,) = to.call{value: amt}("");                    // captured
#     if (!sent) revert EthTransferFailed();                     // ...and CHECKED
#
# Capture alone is not enough: the middle case is exactly what cs_veck's own
# planted fixture contains, and it is a real finding. So suppression requires the
# captured variable to actually be referenced shortly afterwards, which needs a
# window across lines. Without this, LRTWithdrawalManager._transferAsset and the
# treasury-interest path were both reported as unchecked-value-transfer bugs
# despite checking `sent` immediately below.
_CAPTURE_BEFORE_CALL = re.compile(
    r"\(\s*bool\s+(\w+)\s*,?\s*\)\s*=\s*[^;]*\.call\b"
    r"|\(\s*bool\s+(\w+)\s*,\s*[^;=]*\)\s*=\s*[^;]*\.call\b"
)
_PER_LINE_VETO: dict[int, re.Pattern[str]] = {}
# classes whose hit is suppressed when the pattern is demonstrably handled
_WINDOW_CHECK: dict[int, int] = {14: 3}
_CALLED_IN_HANDLED = re.compile(r"\brequire\s*\([^;]*\.call|\.call\b[^;]*\bif\s*\(")


def _pattern_is_handled(lines: list[str], idx: int) -> bool:
    """True when the call on `lines[idx]` has its result captured AND used."""
    m = _CAPTURE_BEFORE_CALL.search(lines[idx])
    if not m:
        # not a captured call - only suppressed if it is plainly guarded inline
        return bool(_CALLED_IN_HANDLED.search(lines[idx]))
    name = m.group(1) or m.group(2)
    if not name:
        return False
    window = _WINDOW_CHECK.get(14, 3)
    pat = re.compile(rf"\b{re.escape(name)}\b")
    return any(pat.search(lines[j]) for j in range(idx + 1, min(idx + 1 + window, len(lines))))


def scan(
    root: Path,
    class_ids: list[int] | None = None,
    *,
    include_tests: bool = False,
    include_vendor: bool = False,
) -> list[dict[str, typing.Any]]:
    """Return ranked hits: {class_id, class, strength, file, line, snippet}.

    Two matching passes per file:
      * `strong`/`weak` are matched per stripped source line.
      * `multiline` patterns are matched against the whole comment-stripped file,
        because some bugs are only visible as a *combination* that Solidity's
        formatting reliably splits across lines (a `price()` helper whose body
        reads `getReserves()` is essentially never written on one line).
        A hit records the line where the match starts.
    """
    hits: list[dict[str, typing.Any]] = []
    wanted = class_ids or [c["id"] for c in CLASSES]
    for f in _sol_files(root, include_tests=include_tests, include_vendor=include_vendor):
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            continue
        stripped = [_strip(ln) for ln in lines]
        # Build the multi-line window while recording, for each retained line,
        # the character offset at which it starts - so a regex match on the
        # window can be mapped back to a real source line number.
        window_parts: list[str] = []
        offsets: list[tuple[int, int]] = []
        cursor = 0
        for n, s in enumerate(stripped, 1):
            if not s.strip():
                continue
            offsets.append((cursor, n))
            window_parts.append(s)
            cursor += len(s) + 1
        window = "\n".join(window_parts)

        def line_at(pos: int) -> int:
            lineno = offsets[0][1]
            for start, n in offsets:
                if start > pos:
                    break
                lineno = n
            return lineno
        for i, code in enumerate(stripped, 1):
            if not code.strip():
                continue
            for cid in wanted:
                cls = _BY_ID[cid]
                # NB: not named `window` - that shadows the multiline window below
                win = _WINDOW_CHECK.get(cid)
                if win is not None and _pattern_is_handled(stripped, i - 1):
                    continue
                veto = _PER_LINE_VETO.get(cid)
                if veto is not None and veto.search(code):
                    continue
                for strength in ("strong", "weak"):
                    for pat in cls[strength]:
                        if re.search(pat, code):
                            hits.append({
                                "class_id": cid,
                                "class": cls["name"],
                                "strength": strength,
                                "file": str(f.relative_to(root)) if root in f.parents else str(f),
                                "line": i,
                                "snippet": code.strip()[:160],
                            })
                            break
        for cid in wanted:
            cls = _BY_ID[cid]
            for pat in cls.get("multiline", ()):
                m = re.search(pat, window)
                if not m:
                    continue
                hits.append({
                    "class_id": cid,
                    "class": cls["name"],
                    "strength": "strong",
                    "file": str(f.relative_to(root)) if root in f.parents else str(f),
                    "line": line_at(m.start()),
                    "snippet": m.group(0).strip().replace("\n", " ")[:160],
                })
                break
    # strong first, then fewer hits per class (rarer class = more signal)
    hits.sort(key=lambda h: (h["strength"] != "strong", h["class_id"]))
    return hits


@app.command(name="list")
def list_classes():
    """Show the 15 Critical classes this scanner looks for."""
    typer.echo(f"{len(CLASSES)} Critical-severity web3 vulnerability classes:\n")
    for c in CLASSES:
        typer.echo(f"  {c['id']:>2}. {c['name']}")
        typer.echo(f"      why : {c['why']}")
        typer.echo(f"      look: {c['look']}")


@app.command(name="checklist")
def checklist():
    """Print the methodology that turns a hit into a submittable report."""
    typer.echo(
        "\n".join(
            [
                "Method to convert a hit into a Critical submission:",
                "",
                "1. Invariant mapping",
                "   State the single condition that must never break, e.g.",
                "   'vault assets >= totalShareBalances * pricePerShare'.",
                "",
                "2. State-shift analysis",
                "   For every path that moves value, diff internal accounting",
                "   against actual token balance. A mismatch is the bug.",
                "",
                "3. Fork execution",
                "   Reproduce on a local fork of mainnet at a pinned block",
                "   (forge test --fork-url). Show >= USD 50k at risk and that",
                "   the loss path actually executes. A PoC is a condition",
                "   precedent for reward on most programs.",
                "",
                "Bar to clear: loss of protocol funds, permanent lock, or",
                "governance takeover. Not gas waste, not temporary griefing.",
            ]
        )
    )


@app.command(name="scan")
def scan_cmd(
    path: str = typer.Argument(..., help="Path to a contract directory"),
    class_id: list[int] = typer.Option([], "--class", "-c", help="Only this class id (repeatable)"),
    strong_only: bool = typer.Option(False, "--strong-only", help="Only strong-evidence patterns"),
    top: int = typer.Option(40, "--top", help="Max hits to show"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Scan a contract tree and rank hits across the 15 Critical classes."""
    import json as _json

    root = Path(path).resolve()
    if not root.exists():
        typer.echo(f"no such path: {root}", err=True)
        raise typer.Exit(1)
    ids = list(class_id) or None
    if ids:
        bad = [i for i in ids if i not in _BY_ID]
        if bad:
            typer.echo(f"unknown class id(s): {bad}; valid 1..{len(CLASSES)}", err=True)
            raise typer.Exit(1)
    hits = scan(root, ids)
    if strong_only:
        hits = [h for h in hits if h["strength"] == "strong"]

    files = len(_sol_files(root))
    by_class: dict[int, int] = {}
    for h in hits:
        by_class[h["class_id"]] = by_class.get(h["class_id"], 0) + 1

    typer.echo(f"{files} .sol file(s) under {root}")
    typer.echo(f"{len(hits)} hit(s) across {len(by_class)}/{len(CLASSES)} classes\n")
    if by_class:
        typer.echo("classes touched (lower count = rarer = usually more signal):")
        for cid, n in sorted(by_class.items(), key=lambda kv: kv[1]):
            typer.echo(f"  {cid:>2}. {n:>4d}  {_BY_ID[cid]['name']}")
        typer.echo("")
    typer.echo("hits (strong evidence first):")
    for h in hits[: int(top)]:
        mark = "**" if h["strength"] == "strong" else "  "
        typer.echo(f"  {mark} [{h['class_id']:>2}] {h['file']}:{h['line']}")
        typer.echo(f"        {h['snippet']}")
    typer.echo(
        "\nReminder: a regex cannot prove exploitability. For each survivor, state\n"
        "the invariant, show the state shift, and build a fork PoC before writing up."
    )
    if json_output:
        typer.echo(_json.dumps({"root": str(root), "files": files, "hits": hits}, indent=2))


if __name__ == "__main__":
    app()
