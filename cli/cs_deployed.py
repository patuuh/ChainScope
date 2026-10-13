#!/usr/bin/env python3
"""cs_deployed: check if contracts in an Immunefi program scope are deployed on-chain.

ChainScope finds *structure*; cs_deployed finds the *deployed attack surface*.
It checks each in-scope contract address against the on-chain RPC to determine
whether the contract is actually deployed (has bytecode) or is just a source-code
reference (private/deployments-only repo). This is critical for the Immunefi OOS
rule: "Only accept reports targeting DEPLOYED contracts."

Usage:
    python cs_deployed.py lido --rpc https://ethereum.publicnode.com
    python cs_deployed.py lido --rpc http://127.0.0.1:8545 --json
    python cs_deployed.py lido --rpc https://ethereum.publicnode.com --output deployed_contracts.txt
"""
from __future__ import annotations

import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


import json
import re
import typing

import typer

from core.cs_discover import fetch_assets

app = typer.Typer()

CHAIN_RPC: dict[str, str] = {
    "1": "https://ethereum.publicnode.com",
    "mainnet": "https://ethereum.publicnode.com",
    "eth": "https://ethereum.publicnode.com",
    "base": "https://base.publicnode.com",
    "8453": "https://base.publicnode.com",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "42161": "https://arb1.arbitrum.io/rpc",
    "137": "https://polygon-rpc.com",
    "polygon": "https://polygon-rpc.com",
    "optimism": "https://mainnet.optimism.io/rpc",
    "10": "https://mainnet.optimism.io/rpc",
}


def _check_deployed(address: str, rpc: str) -> dict[str, typing.Any]:
    import urllib.request
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getCode",
        "params": [address, "latest"],
    }
    req = urllib.request.Request(
        rpc,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        code = result.get("result", "")
        is_deployed = len(code) > 2
        return {"address": address, "deployed": is_deployed, "code_length": len(code) if is_deployed else 0}
    except Exception:
        return {"address": address, "deployed": False, "code_length": 0, "error": "RPC call failed"}


def _extract_addresses(assets: list[dict[str, typing.Any]]) -> list[str]:
    addresses: list[str] = []
    for a in assets:
        url = a.get("url", "")
        desc = a.get("description", "")
        combined = url + " " + desc
        found = re.findall(r"0x[0-9a-fA-F]{40}", combined)
        for addr in found:
            if addr not in addresses:
                addresses.append(addr)
    return addresses


@app.command()
def check(
    slug: str = typer.Argument(..., help="Program slug (e.g. lido)"),
    rpc: str = typer.Option("https://ethereum.publicnode.com", "--rpc", help="RPC URL"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    output: str = typer.Option("", "--output", help="Write deployed addresses to file"),
):
    try:
        assets = fetch_assets(slug)
    except Exception as exc:
        typer.echo(f"[err] Failed to fetch assets for {slug}: {exc}", err=True)
        raise typer.Exit(1)

    addresses = _extract_addresses(assets)
    if not addresses:
        raw = json.dumps(assets)
        all_addrs = re.findall(r"0x[0-9a-fA-F]{40}", raw)
        addresses = list(dict.fromkeys(all_addrs))
    if not addresses:
        typer.echo(f"[err] No addresses found in scope for {slug}", err=True)
        raise typer.Exit(1)

    typer.echo(f"[info] Checking {len(addresses)} addresses for {slug}...")
    deployed: list[dict[str, typing.Any]] = []
    not_deployed: list[dict[str, typing.Any]] = []
    for addr in addresses:
        result = _check_deployed(addr, rpc)
        if result["deployed"]:
            deployed.append(result)
        else:
            not_deployed.append(result)

    if json_output:
        typer.echo(json.dumps({"slug": slug, "total": len(addresses), "deployed": deployed, "not_deployed": not_deployed}, indent=2))
    else:
        typer.echo(f"[ok] {slug}: {len(deployed)} deployed, {len(not_deployed)} not deployed")
        typer.echo()
        typer.echo("=== DEPLOYED ===")
        for d in deployed:
            typer.echo(f"  {d['address']} (code length: {d['code_length']})")
        typer.echo()
        typer.echo("=== NOT DEPLOYED ===")
        for d in not_deployed:
            typer.echo(f"  {d['address']}")

    if output:
        with open(output, "w") as f:
            for d in deployed:
                f.write(f"{d['address']}\n")
        typer.echo(f"[ok] Deployed addresses written to {output}")

    return {"slug": slug, "deployed": deployed, "not_deployed": not_deployed}


if __name__ == "__main__":
    app()
