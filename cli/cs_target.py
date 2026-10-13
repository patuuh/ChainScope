#!/usr/bin/env python3
"""cs_target: a Keizo-style target scorer for bug bounty hunting.

ChainScope finds *structure*; cs_target finds the *attack surface to point AI at*.
It ranks in-scope contracts (from cs_discover) by the signals that predict where
UNKNOWN critical bugs live:

    1. POSTMISSIVE MONEY PATH — the contract has an external/public function that moves
       funds (deposit/withdraw/mint/burn/transfer/claim/call{value}/delegatecall) and is
       NOT gated by a role/auth/pause modifier. This is the cash.
    2. FRESHNESS — recently added to scope = recently deployed = fewer audit cycles.
    3. LOW-AUDIT — few/no audits listed for the program.
    4. REACHABLE — on-chain, fork-able (mainnet/Base/Arb), not a private/deployments repo.

Ranking = freshness & low-audit (program level) x "has a permissionless money path"
(contract level). Output feeds straight into cs_fetch + the graph queries, then a fork PoC.

This tool's design is inspired by the methodology of KeiZo_Zo (AI-led, long-tail,
thin-audit, permissionless-money-path targeting). See README.md.
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

from core.cs_discover import fetch_assets
from core import deploy_source

app = typer.Typer()

_REACHABLE_HOSTS = ("etherscan.io", "basescan.org", "arbiscan.io")

# Modifier names that indicate the function is role / auth / pause gated.
_ROLE_MODIFIERS = re.compile(
    r"\b(only[A-Za-z0-9_]*|requiresAuth|isAuthorized|whenNotPaused|whenNot[Pp]aused"
    r"|isOwner|auth[A-Za-z0-9_]*|onlyRole[A-Za-z0-9_]*)\b"
)
# Low-level / token call sites that move value.
_MONEY_CALLS = re.compile(
    r"\b(transfer|transferFrom|safeTransfer|safeTransferFrom|deposit|withdraw|mint|burn|claim)\b"
    r"|\b\.(call|delegatecall|functionCallWithValue)\s*(?:\(|\{)"
)
_FUNC_HEAD = re.compile(
    r"function\s+([a-zA-Z0-9_]+)\s*\([^;{]*?\)\s*([^{]*?)\{", re.S | re.M
)


def _block(body: str, open_idx: int) -> int:
    """Return index of the matching close brace for the brace at ``open_idx``."""
    depth = 0
    for i in range(open_idx, len(body)):
        if body[i] == "{":
            depth += 1
        elif body[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(body)


def analyze_contract(source_dir: str) -> dict[str, typing.Any]:
    """Scan a fetched source tree for permissionless (role-ungated) money-path functions.

    Heuristic first-pass: marks a function as a money path if its body contains a
    transfer/value call and its signature (or modifier chain) has no role/auth/pause
    guard. Manual exploitability is still required (structural signal, not a verdict).
    """
    import pathlib

    results: list[dict[str, typing.Any]] = []
    for path in pathlib.Path(source_dir).rglob("*.sol"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        for m in _FUNC_HEAD.finditer(text):
            name = m.group(1)
            sig = m.group(2)
            fn_has_role = any(_ROLE_MODIFIERS.search(t) for t in (sig,))
            # whole file up to the function: catch modifiers on separate lines
            head_end = text.find("{", m.start())
            if head_end < 0:
                continue
            head = text[max(0, m.start() - 500): head_end]
            fn_has_role = fn_has_role or bool(_ROLE_MODIFIERS.search(head))
            body_end = _block(text, head_end)
            body = text[head_end:body_end]
            money = bool(_MONEY_CALLS.search(body))
            if "external" in head or "public" in head:
                results.append({
                    "file": str(path.relative_to(source_dir)),
                    "fn": name,
                    "gated": fn_has_role,
                    "money": money,
                })
    perm = [r for r in results if r["money"] and not r["gated"]]
    return {
        "functions": len(results),
        "permissionless_money_functions": perm,
        "has_permissionless_money_path": bool(perm),
    }


def _audit_count(slug: str) -> int:
    """Roughly count audit reports listed on a program scope page."""
    import json
    import urllib.request
    try:
        req = urllib.request.Request(
            f"https://immunefi.com/bug-bounty/{slug}/scope/", headers={"User-Agent": "Mozilla/5.0"}
        )
        raw = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "ignore")
        un = raw.replace('\\\\"', '"').replace('\\"', '"')
        # audits is usually an array of audit report entries; count occurrences of audit-ish objects
        count = len(re.findall(r'"audit[s]?"\s*:\s*\[', un))
        if count == 0:
            # fallback: count "audit" report links/objects
            count = len(set(re.findall(r'"(?:name|title|report|url)":"[^"]*audit[^"]*"', un, re.I)))
        return count
    except Exception:  # noqa: BLE001
        return -1


@app.command()
def target(
    slug: str = typer.Argument(..., help="Immunefi program slug (e.g. 'veda')"),
    recent_since: str = typer.Option("2025-06-01", "--recent-since", help="Freshness cutoff (YYYY-MM-DD)"),
    max_fetch: int = typer.Option(8, "--max-fetch", help="How many reachable contracts to fetch+scan"),
    audit_threshold: int = typer.Option(2, "--audit-threshold", help="Flag low-audit if audits <= N"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Rank a program's in-scope contracts by attack-surface (Keizo-style scoring)."""
    max_fetch = int(max_fetch)
    audit_threshold = int(audit_threshold)
    assets = [a for a in fetch_assets(slug) if a["addedAt"] >= recent_since and
              any(h in a["url"] for h in _REACHABLE_HOSTS) and "0x" in a["url"]]
    audits = _audit_count(slug)
    assets.sort(key=lambda a: a["addedAt"], reverse=True)

    if not assets:
        typer.echo(f"No recent reachable on-chain in-scope contracts for '{slug}'.", err=True)
        raise typer.Exit(1)

    typer.echo(f"Program '{slug}': audits~{audits}, {len(assets)} recent reachable on-chain contracts. "
               f"Scanning own the freshest {max_fetch}.")
    scored: list[dict[str, typing.Any]] = []
    for a in assets[:max_fetch]:
        addr = re.search(r"0x[a-fA-F0-9]{40}", a["url"]).group(0)
        chain_h = a["url"].split("/")[2]
        try:
            chain = deploy_source.chain_id(chain_h.split(".")[0].replace("optimistic-", "").replace("etherscan-", ""))
        except Exception:  # noqa: BLE001
            chain = 1
        out = f"target_{slug}_{chain}_{addr.lower()}"
        try:
            det = deploy_source.fetch_sourcify_source(chain, addr, out_dir=out, timeout=45)
            scan = analyze_contract(det["out_dir"])
            perm = scan["has_permissionless_money_path"]
            n = len(scan["permissionless_money_functions"])
            scored.append({
                "slug": slug, "contract": a["description"], "address": addr,
                "added": a["addedAt"], "audits": audits,
                "fresh": a["addedAt"] >= recent_since,
                "low_audit": audits >= 0 and audits <= audit_threshold,
                "has_permissionless_money_path": perm,
                "num_permissionless_money_functions": n,
                "target_score": int((a["addedAt"] >= recent_since) and (audits == -1 or audits <= audit_threshold) and perm),
            })
        except Exception as exc:  # noqa: BLE001
            scored.append({"slug": slug, "contract": a["description"], "address": addr,
                           "added": a["addedAt"], "error": str(exc)})

    scored.sort(key=lambda s: (s.get("target_score", 0), s.get("added", "")), reverse=True)
    typer.echo("\nKeizo-style attack-surface ranking (target_score=1 means fresh+low-audit+permissionless-money-path):")
    for s in scored:
        flag = s.get("has_permissionless_money_path") and s.get("low_audit") and s.get("fresh")
        typer.echo(
            f"  {'**' if flag else '  '}{s['contract']:28} score={s.get('target_score',0)} "
            f"perm_money={s.get('has_permissionless_money_path', False)} "
            f"({s.get('num_permissionless_money_functions',0)} fns) audits={s.get('audits','?')} "
            f"added={s.get('added')} addr={s.get('address')}"
            + (f" err={s.get('error')}" if s.get("error") else "")
        )
    if json_output:
        typer.echo(__import__("json").dumps(scored, indent=2))


if __name__ == "__main__":
    app()
