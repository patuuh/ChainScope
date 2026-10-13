#!/usr/bin/env python3
"""Run a systematic 30-class attack-pattern sweep over a set of Solid sources.

This closes the "read-audit only" gap: instead of listing suspicious functions one by one,
``cs_sweep`` walks a source tree (e.g. a cs_fetch output dir or a cloned repo) and reports a
verdict for each of the classic smart-contract vulnerability classes. It is a *hypothesis
generator* - it flags things to review, not a final verdict (Keizo: volume -> pattern -> verify
by hand/fork-PoC).

    python cs_sweep.py /path/to/-fetched/source
    python cs_sweep.py target_ethena_usdtb --chain 1        # also accept a cs_fetch target dir
    python cs_sweep.py . --json

Output: one row per class: [potential-signal | clean | n/a] + file:line of the hit. Classes are
0-indexed to match the MonoCooler sweep that found the setTreasuryBorrower latent-critical.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import pathlib
import re
import sys
import typing

import typer

app = typer.Typer()

# Each class: (name, regexes that indicate a potential issue, blocker patterns that usually make it safe)
CLASSES: list[tuple[str, list[str], list[str]]] = [
    ("reentrancy-external-call", [r"\.call\s*\{value:|\.delegatecall\(|\.call\("], [r"nonReentrant|ReentrancyGuard|checks-effects"]),
    ("unchecked-math", [r"unchecked\s*\{", r"// SAFE: %|// safe: %", r"\-=|\+=|\*\=|\/="], [r"checked|SafeMath|require|revert"]),
    ("access-control-missing", [r"function\s+\w+\([^)]*\)\s*(public|external)\b(?![^{]*\{\s*\()"], [r"only[A-Z]|onlyRole|msg\.sender\s*==|require\s*\([^)]*msg\.sender|auth\b|_isAdmin|hasRole"]),
    ("tx-origin", [r"tx\.origin"], [r"msg\.sender"]),
    ("delegatecall", [r"delegatecall"], []),
    ("selfdestruct", [r"selfdestruct|suicide"], []),
    ("arbitrary-spender-approve", [r"approve\(\s*\w+,\s*.*\b(amount|type\(uint256\)\.max|balance)\b|forceApprove"], [r"require\b|only|_check|allowlist|whitelist"]),
    ("low-level-call-untrusted", [r"[a-z]+\.call\s*\("], [r"only|require\s*\([^)]*address|isValid|trusted"]),
    ("oracle-single-source", [r"latestRoundData|getPrice|priceFeed|oracle\.|AggregatorV3|chainlink"], [r"stale|heartbeat|deviation|updatedAt|sequencer|min|max|depeg|capped"]),
    ("share-inflation-donation", [r"totalAssets\s*\(|convertToShares|_convertToShares|ERC4626|previewDeposit"], [r"virtual|offset|decimalsOffset|deadAddress|maxDeposit|freeze|firstDepositor|donat"]),
    ("fee-on-transfer-break", [r"safeTransferFrom|transferFrom\s*\([^)]*amount"], [r"amount\s*=|balanceOf\s*\([^)]*\)\s*\-|received|balanceBefore|actual"]),
    ("signature-malleability/eip712", [r"ecrecover|ECDSA\.(recover|tryRecover)|_hashTypedDataV4|\bdigest\b"], [r"SignatureChecker|nonce|deadline|replay|used\[|signatureUses|s\s*\|\s*isValid|low-s|HIGH_S|277|275"]),
    ("initialization-footgun", [r"function initialize\s*\(|reinitializer|initializer\b"], [r"initializer\b|onlyInitializing|_disableInitializers|reinitializer|already|__initialized"]),
    ("permissionless-privileged-setup", [r"if\s*\([^)]*==\s*address\(0\)[^)]*&&|set[A-Z]\w*\([^)]*external\b"], [r"only[A-Z]|_isAdmin|require\s*\([^)]*!=|not\s*address\(0\)|constructor\s*\([^)]*set"]),
    ("governance-voting", [r"propose|castVote|quorum\s*=|vote\s*\("], [r"quorum|Votes|deadline|clone|mode|support"]),
    ("cross-chain-message", [r"lzReceive|_srcEid|_lz|ccip|sendMessage|Received|trustedRemote|_trustedRemote|handlePayload"], [r"peers\[|trustedRemote|_srcEid|_srcChainId|nonce|_isTrustedRemote|onlyAuthorized|msgSender\s*==|validate"]),
    ("unbounded-loop", [r"for\s*\([^)]*;[^)]*;[^)]*\)\s*\{\s*[^}]{0,80}extern(al|al)\s|while\s*\([^)]*\)"], [r"calldata|requiresGas|limit|MAX_|bounded|amount\s*<"]),
    ("rounding-direction", [r"mulDivDown|mulDivUp|divWadUp|divWadDown|Math\.ceil|Math\.floor|/ \d*[02]|/ u\d|Rounding\.(Ceil|Down)"], []),
    ("token-decimal-mismatch", [r"10\s*\*\*\s*(|decimals)|1e18|1e6|1e8|10\^|decimals\(\)"], [r"require\s*\([^)]*decimals|_EXPECTED_DECIMALS|assert\s*\([^)]*decimals"]),
    ("approval-race-permit", [r"permit\s*\(|_nonces|PERMIT_TYPEHASH"], [r"deadline|nonces|used\[|verify"]),
    ("fee-math-overclaim", [r"fee\s*=|incentive\s*=|_min\(|collateral\s*\-\s*incentive|amountOut\s*=\s*[a-zA-Z]+\s*[<>]" ], [r"require\s*\([^)]*fee|cap|= collateral|<=|mulDivUp|ceil"]),
    ("uninitialized-role-takeover", [
        r"if\s*\(\s*address\((\w+)\)\s*!=\s*address\(0\)\s*&&",        # permissionless-first-set guard
        r"set[A-Z]\w*\s*\([^)]*\)\s*external[^{]*\{[^{}]{0,260}!= *(\w+)",# setX not holding the authority
        r"if\s*\([^)]*\([a-zA-Z]+\)\s*!= *0[^)]*&&\s*!\s*_?[iI]s[A-Z]", ], [r"onlyInitializing|constructor\s*\([^)]*set|require\s*\([^)]*msg\.sender|onlyOwner|onlyRole"]),
    ("rebase/inconsistent-state", [r"balanceOf\(address\(this\)\)|_totalSupply|totalShares|exchangeRate|converter"], [r"accru|checkpoint|sync|index"]),
    ("unverified-return", [r"\.deposit\s*\(|\.withdraw\s*\(|\.redeem\s*\("], [r"return\s+value|received|!=|require\s*\([^)]*==|checked"]),
    ("wrong-recipient-redirect", [r"safeTransfer\s*\([^,]+,\s*msg\.sender|transfer\s*\([^,]+,\s*msg\.sender"], [r"recipient\s*==|to\s*==|overwrite|only"]),
    ("input-validation", [r"abi\.decode|function .*\w+\s*\((address|uint256|bytes)\s*\w+\)\s*external\b"], []),
]

_VIEW = re.compile(r"\b(view|pure)\b")


def _classify(src: str, pats: list[str], blockers: list[str]) -> list[tuple[int, str]]:
    """Return a list of (line, snippet) hits that are NOT covered by a blocker (i.e. worth review)."""
    hits: list[tuple[int, str]] = []
    for p in pats:
        for m in re.finditer(p, src):
            window = src[max(0, m.start() - 160):m.end() + 160]
            if any(re.search(b, window) for b in blockers):
                continue
            line = src.count("\n", 0, m.start()) + 1
            hits.append((line, m.group(0)[:40]))
    return hits


@app.command()
def sweep(
    path: str = typer.Argument(".", help="Directory of .sol files (or a cs_fetch target dir)"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON"),
    min_hits: int = typer.Option(0, "--min-hits", help="Only report classes with this many hits"),
):
    root = pathlib.Path(path)
    files = sorted(root.rglob("*.sol"))
    if not files:
        typer.echo(f"no .sol files under {root}", err=True)
        raise typer.Exit(1)
    all_src = "\n".join(f.read_text(errors="ignore") for f in files)
    # strip comments so patterns don't fire on docstrings
    all_src = re.sub(r"//[^\n]*|/\*.*?\*/", "", all_src, flags=re.S)

    rows = []
    for idx, (name, pats, blockers) in enumerate(CLASSES, start=1):
        hits = _classify(all_src, pats, blockers)
        if hits:
            rows.append((idx, name, "potential-signal", hits[:6]))
        else:
            rows.append((idx, name, "clean", []))
    if json_output:
        import json
        typer.echo(json.dumps([r for r in rows], indent=2, default=str))
        return
    typer.echo(f"=== cs_sweep: {len(files)} sol files, {len(CLASSES)} classes (hypothesis generator) ===")
    for idx, name, verdict, hits in rows:
        if verdict == "clean":
            continue
        print(f"  [{idx}] {name} -- SIGNAL ({len(hits)} hits)")
        for line, snippet in hits:
            print(f"      L{line}: {snippet}")


if __name__ == "__main__":
    app()
