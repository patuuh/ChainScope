"""`python -m cli re` - bytecode reverse engineering for deployed targets."""
from __future__ import annotations

import json
import typing as t
from pathlib import Path

import typer

from core import cs_re
from core.cs_rpc import load_dotenv, rpc_for

app = typer.Typer(help="Reverse engineer deployed contracts: interfaces, proxies, differentials.")


@app.command(name="probe")
def probe_cmd(
    address: str = typer.Argument(..., help="Contract address"),
    chain: str = typer.Option("1", "--chain"),
    no_4byte: bool = typer.Option(False, "--no-4byte", help="Skip openchain signature lookups"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Structural analysis of one address: proxy kind, interfaces, dangerous opcodes."""
    load_dotenv()
    if not rpc_for(chain):
        typer.echo(f"no RPC for chain {chain}")
        raise typer.Exit(2)
    try:
        info = cs_re.analyze(chain, address, resolve_4byte=not no_4byte)
    except cs_re.REError as exc:
        typer.echo(f"unreachable: {exc}")
        raise typer.Exit(2)
    if json_output:
        out = {k: v for k, v in info.items() if k != "code_hex"}
        typer.echo(json.dumps(out, indent=2, default=str))
        return
    typer.echo(cs_re.summarize(info))
    for impl in info.get("implementations", []):
        if impl.get("error"):
            typer.echo(f"  impl {impl['address']}: {impl['error']}")


@app.command(name="selectors")
def selectors_cmd(
    address: str = typer.Argument(...),
    chain: str = typer.Option("1", "--chain"),
    resolve: bool = typer.Option(True, "--resolve/--no-resolve"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Function selectors extracted from the dispatcher, optionally 4byte-resolved."""
    load_dotenv()
    try:
        code = cs_re.runtime_code(chain, address)
    except cs_re.REError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2)
    sel = cs_re.extract_selectors(code)
    resolved = cs_re.resolve_selectors(sel["dispatcher"]) if resolve else {}
    if json_output:
        typer.echo(json.dumps({"selectors": sel, "resolved": resolved}, indent=2))
        return
    typer.echo(f"{len(sel['dispatcher'])} dispatcher selectors, "
               f"{len(sel['other_constants'])} other PUSH4 constants")
    for s in sel["dispatcher"]:
        names = ", ".join(resolved.get(s, [])) or "?"
        typer.echo(f"  {s}  {names}")


@app.command(name="scan")
def scan_cmd(
    addresses: list[str] = typer.Argument(..., help="Addresses to triage"),
    chain: str = typer.Option("1", "--chain"),
    no_4byte: bool = typer.Option(False, "--no-4byte"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Triage many addresses at once; surfaces the ones worth reading.

    Reads like a gate: a diamond, a beacon, or an unreachable target is called
    out separately, because each of those needs a different approach before any
    code is worth reading.
    """
    load_dotenv()
    results = cs_re.analyze_many(chain, list(addresses), resolve_4byte=not no_4byte)
    if json_output:
        typer.echo(json.dumps([{k: v for k, v in r.items() if k != "code_hex"}
                               for r in results], indent=2, default=str))
        return
    for r in results:
        if r.get("error"):
            typer.echo(f"  {r['address']}  ERROR {r['error'][:60]}")
            continue
        proxy = r.get("proxy", {})
        ifs = r.get("inference", {}).get("interfaces", {})
        flags = []
        if proxy.get("facets"):
            flags.append(f"DIAMOND/{len(proxy['facets'])}facets")
        if proxy.get("beacon"):
            flags.append("BEACON")
        if proxy.get("kind", "").startswith("UNREACHABLE"):
            flags.append("UNREACHABLE")
        typer.echo(
            f"  {r['address']}  {proxy.get('kind', '?'):<22} "
            f"sel={len(r.get('selectors', {}).get('dispatcher', [])):<4} "
            f"{','.join(ifs) or '-':<28} {' '.join(flags)}"
        )
        if r.get("surface_caveat"):
            typer.echo(f"      caveat: {r['surface_caveat'][:96]}")


@app.command(name="diff")
def diff_cmd(
    a: str = typer.Argument(..., help="Address A"),
    b: str = typer.Argument(..., help="Address B"),
    chain: str = typer.Option("1", "--chain"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Structural diff of two contracts - the one-line-divergence hunt.

    Most exploited contracts differ from a known-good sibling by one line, and a
    Sourcify entry is not proof the deployed bytecode matches what is published.
    """
    load_dotenv()
    # Comparing proxy shells is misleading: two upgradeable proxies deployed
    # from the same implementation bytecode are byte-identical while the code
    # that actually runs is entirely different. Resolve first, and say so.
    resolved_from = {}
    def _impl(addr: str) -> str:
        if addr in resolved_from:
            return resolved_from[addr]
        p = cs_re.resolve_proxy(chain, addr)
        impls = p.get("implementations") or []
        if p.get("facets"):
            typer.echo(f"  note: {addr} is a DIAMOND ({len(p['facets'])} facets); "
                       "compare the facets individually")
        if len(impls) == 1:
            typer.echo(f"  resolving {addr[:10]}.. -> implementation {impls[0][:10]}..")
            resolved_from[addr] = impls[0]
            return impls[0]
        resolved_from[addr] = addr
        return addr

    ta, tb = _impl(a), _impl(b)
    try:
        ca = cs_re.runtime_code(chain, ta)
        cb = cs_re.runtime_code(chain, tb)
    except cs_re.REError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2)
    d = cs_re.diff_bytecode(ca, cb)
    if ta != a or tb != b:
        d["compared"] = f"implementations of {a} and {b}"
    if json_output:
        typer.echo(json.dumps(d, indent=2))
        return
    typer.echo(f"identical            : {d['identical']}")
    typer.echo(f"logic identical      : {d['logic_identical']}")
    typer.echo(f"metadata-only diff   : {d['metadata_only_difference']}")
    typer.echo(f"selectors only in A  : {d['selectors_only_in_a'] or '-'}")
    typer.echo(f"selectors only in B  : {d['selectors_only_in_b'] or '-'}")
    typer.echo(f"selectors shared     : {d['selectors_shared']}")
    if d["opcode_delta"]:
        top = sorted(d["opcode_delta"].items(), key=lambda kv: -abs(kv[1]))[:12]
        typer.echo(f"opcode delta (top)   : " + ", ".join(f"{k}:{v:+d}" for k, v in top))
    if d["dangerous_delta"]:
        typer.echo(f"dangerous opcode diff: {d['dangerous_delta']}")
    ra = cs_re.resolve_selectors(d["selectors_only_in_a"])
    rb = cs_re.resolve_selectors(d["selectors_only_in_b"])
    for label, res in (("only in A", ra), ("only in B", rb)):
        for sel, names in res.items():
            if names:
                typer.echo(f"  {label}: {sel} -> {', '.join(names)}")

@app.command(name="compare-source")
def compare_source_cmd(
    address: str = typer.Argument(...),
    path: str = typer.Option(..., "--path", help="Local source tree to compare against"),
    chain: str = typer.Option("1", "--chain"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Compare a source tree's declared selectors against deployed bytecode.

    Answers the question Sourcify cannot: is the published source the thing that
    is actually deployed? Needs no compiler, so it works on repos that will not
    build.
    """
    load_dotenv()
    root = Path(path)
    if not root.is_dir():
        typer.echo(f"not a directory: {path}")
        raise typer.Exit(2)
    try:
        r = cs_re.compare_source_to_deployed(chain, address, root)
    except cs_re.REError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2)
    if json_output:
        typer.echo(json.dumps(r, indent=2, default=str))
        return
    typer.echo(f"address            : {r['address']}")
    typer.echo(f"source root        : {r['source_root']}")
    typer.echo(f"deployed selectors : {r['deployed_selector_count']}")
    typer.echo(f"source selectors   : {r['source_selector_count']}")
    typer.echo(f"shared             : {r['shared']}")
    typer.echo(f"verdict            : {r['verdict']}")
    if r["only_in_source"]:
        typer.echo(f"only in source ({len(r['only_in_source'])}) : {r['only_in_source'][:12]}")
    if r["only_in_deployed"]:
        typer.echo(f"only in deployed ({len(r['only_in_deployed'])}): {r['only_in_deployed'][:12]}")
        for sel, names in list(r.get("only_in_deployed_resolved", {}).items())[:20]:
            if names:
                typer.echo(f"    {sel} -> {', '.join(names)}")


@app.command(name="uninit")
def uninit_cmd(
    address: str = typer.Argument(...),
    chain: str = typer.Option("1", "--chain"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Probe whether an initializer is still callable (takeover risk).

    An uninitialised proxy or implementation can be claimed by anyone: calling
    `initialize(you)` makes you owner. eth_call only - nothing is submitted.
    """
    load_dotenv()
    try:
        r = cs_re.uninitialized_probe(chain, address)
    except cs_re.REError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2)
    if json_output:
        typer.echo(json.dumps(r, indent=2, default=str))
        return
    typer.echo(f"address : {r['address']}")
    typer.echo(f"verdict : {r['verdict']}")
    for p in r.get("probes", []):
        typer.echo(f"  {p['signature']:<28} args={p['args']:<3} call_ok={p['call_succeeded']} -> {p['verdict']}")
    typer.echo(f"caveat  : {r.get('caveat', '')}")


@app.command(name="access")
def access_cmd(
    address: str = typer.Argument(...),
    chain: str = typer.Option("1", "--chain"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Infer caller-identity guards from bytecode shape.

    Replaces reading `onlyOwner` by hand across a large codebase. Shape-based and
    explicitly a heuristic: it can say a guard looks present, never that it is
    correct, and "no guard detected" is absence of evidence.
    """
    load_dotenv()
    try:
        code = cs_re.runtime_code(chain, address)
    except cs_re.REError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2)
    h = cs_re.access_control_hints(code)
    if json_output:
        typer.echo(json.dumps(h, indent=2, default=str))
        return
    typer.echo(f"address         : {address}")
    typer.echo(f"verdict         : {h['verdict']}  (confidence: {h['confidence']})")
    typer.echo(f"caller reads    : {h['caller_checks']}   branches: {h['branches']}")
    if h["immutable_owners"]:
        typer.echo(f"immutable owners: {h['immutable_owners'][:4]}")
    if h["role_hashes"]:
        typer.echo(f"role/storage keys: {h['role_hashes'][:4]}")
    typer.echo(f"note            : {h['note']}")


@app.command(name="relations")
def relations_cmd(
    address: str = typer.Argument(...),
    chain: str = typer.Option("1", "--chain"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Who this contract talks to: embedded counterparties and call sites."""
    load_dotenv()
    try:
        r = cs_re.infer_relationships(chain, address)
    except cs_re.REError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2)
    if json_output:
        typer.echo(json.dumps(r, indent=2, default=str))
        return
    typer.echo(f"counterparties : {r['immutable_count']} "
               f"(sentinels ignored: {len(r['sentinels_ignored'])})")
    for a in r["with_code"]:
        typer.echo(f"  contract  {a}")
    for a in r["without_code"]:
        typer.echo(f"  no code   {a}")
    typer.echo(f"calls           : {r['calls']['by_op']}")
    typer.echo(f"foreign code ok : {r['calls']['can_execute_foreign_code_in_own_storage']}")
    typer.echo(f"note            : {r['explanation']}")


@app.command(name="source")
def source_cmd(
    address: str = typer.Argument(...),
    chain: str = typer.Option("1", "--chain"),
    fetch: bool = typer.Option(False, "--fetch", help="Attempt IPFS retrieval of the published source"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Recover the metadata IPFS hash, and optionally the published source."""
    load_dotenv()
    try:
        code = cs_re.runtime_code(chain, address)
    except cs_re.REError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2)
    m = cs_re.extract_metadata(code)
    out: dict = {"address": address, "metadata": m}
    if fetch and m.get("cid"):
        out["source"] = cs_re.fetch_published_source(m["cid"])
    if json_output:
        typer.echo(json.dumps(out, indent=2, default=str))
        return
    typer.echo(f"metadata found : {m['found']}   ({m['reason']})")
    if m.get("cid"):
        typer.echo(f"ipfs cid       : {m['cid']}")
        if fetch:
            s = out.get("source", {})
            typer.echo(f"source fetched : {s.get('fetched')}")
            if s.get("fetched"):
                typer.echo(f"bytes          : {s.get('bytes')}")
            else:
                for a in s.get("attempts", []):
                    typer.echo(f"  {a['gateway']}  ok={a['ok']} {a.get('error','')[:60]}")
    typer.echo("note            : the hash proves which source produced THIS bytecode; "
                "it is not proof the program intended to publish it, and on an "
                "upgradeable proxy it describes the implementation, not the address.")


@app.command(name="runtime")
def runtime_cmd(
    address: str = typer.Argument(...),
    chain: str = typer.Option("1", "--chain"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Identify the execution runtime before applying any EVM logic to it."""
    load_dotenv()
    r = cs_re.identify_target(chain, address)
    if json_output:
        typer.echo(json.dumps(r, indent=2, default=str))
        return
    typer.echo(f"address           : {r.get('address')}")
    typer.echo(f"chain             : {r.get('chain')}  (expected {r.get('expected_runtime')})")
    typer.echo(f"runtime           : {r.get('runtime')}")
    typer.echo(f"supported by RE   : {r.get('supported')}")
    typer.echo(f"guidance          : {r.get('guidance')}")
