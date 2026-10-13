"""The hunt procedure. Run it before reading a line of contract code.

Every wrong conclusion in the first session came from a skipped step, not a
failed one. So the steps live here, in order, and the procedure refuses to emit a
GO without all of them resolved.

    GO      every gate resolved PASS or a recorded, understood FAIL
    BLOCKED at least one gate UNKNOWN - not "probably fine", UNKNOWN

The distinction is the whole point. `re uninit` returning UNKNOWN on 7 of 9
contracts would have closed 1,070,000 tokens of admin surface had I read the
absence of a result as a result. A finding is not a licence to skip a gate; a
passing gate is.

Steps, and the failure each one exists to prevent:

1  program live            a paused program still lists scope and fetches clean
2  $0 filing fee           Sherlock 122 charges $250 to file
3  pool within ceiling    a bigger number is not a better target
4  scope retrievable      no addresses and no repos means nothing to review
5  AUDITED CONTRACTS EXIST this is the one that cost the most. IPOR's three
                           reports name Milton, Joseph, Stanley, StrategyAave,
                           IporSwapLogic - nine contracts with ZERO files in the
                           current tree. "Thin coverage" was wrong; the
                           fund-holding Amm* code was never audited at all.
6  in-scope mapped         addresses that are routers/lenses, not the contracts
                           holding funds, change what is reportable
7  deployed == source      byte comparison, not a selector ratio. Selector
                           ratios are meaningless for an inherited contract
                           (it carries every inherited public function) and
                           misleading when one contract is compared to a whole
                           source tree
8  no uninitialised admin  onlyRole on a recovery path turns a typo into a
                           permanent freeze
9  reachable value         an empty instance has no users to harm

Steps 5, 6 and 9 do not exist in the CLI today. They are the reason this file
does.
"""
from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "cs_immune", Path(__file__).resolve().parent.parent / "cli" / "cs_immune.py"
)
cs_immune = importlib.util.module_from_spec(_spec)
sys.modules["cs_immune"] = cs_immune
_spec.loader.exec_module(cs_immune)

import core.cs_re as cs_re  # noqa: E402
from core import deploy_source  # noqa: E402
from core.cs_rpc import load_dotenv, rpc_for  # noqa: E402

PASS, FAIL, UNKNOWN = "PASS", "FAIL", "UNKNOWN"

# Names appearing in an audit scope/commit that are unambiguously code, used to
# decide whether the audited code still exists in the tree.
_CODEISH = re.compile(r"^[A-Z][A-Za-z0-9_]*\.(sol|vy)$")


@dataclass
class Gate:
    n: int
    name: str
    status: str
    detail: str = ""
    data: dict = field(default_factory=dict)

    def line(self) -> str:
        mark = {PASS: "ok  ", FAIL: "FAIL", UNKNOWN: "UNKN"}[self.status]
        return f"  {self.n}. {self.name:<34} {mark}  {self.detail}"


def _audit_contract_names(md_dir: Path) -> set[str]:
    """Contract names referenced in a local audit corpus's markdown summaries."""
    names: set[str] = set()
    if not md_dir.is_dir():
        return names
    for f in md_dir.glob("*.md"):
        for m in re.finditer(r"`?([A-Z][A-Za-z0-9_]*\.(?:sol|vy))`?", f.read_text(errors="replace")):
            names.add(m.group(1))
    return names


def run(slug: str, audit_dir: Path | None, repo_dir: Path | None,
        check_uninit: bool = True, max_addrs: int = 6) -> list[Gate]:
    g: list[Gate] = []
    prog = cs_immune._program(slug)
    if not prog:
        return [Gate(1, "program live", FAIL, "not on Immunefi")]
    row = cs_immune._keiko if False else cs_immune._keizo(prog, time.time())

    # 1 liveness
    status = row.get("status_code")
    g.append(Gate(1, "program live", PASS if status == "LIVE" else FAIL, str(status)))

    # 2 fee / 3 ceiling
    elig = cs_immune.submit_eligibility(row)
    fee_blocked = any("SUBMISSION_FEE" in r for r in elig["reasons"])
    g.append(Gate(2, "$0 filing fee", FAIL if fee_blocked else PASS,
                  f"${elig.get('submission_fee_usd')}" if fee_blocked else "no fee"))
    # The CEILING that decides whether this hunt is worth the hours comes from the
    # rendered page, not the payload. IPOR's payload claims Critical $100,000; the
    # page says "Critical: Flat: $1,000" with $100k only as a cap on catastrophic
    # impact. Quoting the payload turned a $1,000 program into a $10,000 one.
    from core.cs_immune_payout import displayed_payouts

    disp = displayed_payouts(row.get("url") or f"https://immunefi.com/bug-bounty/{slug}/information/")
    flat = disp.get("critical_flat")
    ceiling_ok = (flat is not None and flat <= 100_000) if flat is not None else None
    detail = f"displayed flat ${flat:,}" if flat else disp.get("note", "not read")
    if disp.get("impact_scaling"):
        detail += " (impact-scaled upward on catastrophic findings)"
    g.append(Gate(3, "pool within ceiling",
                  PASS if ceiling_ok else (FAIL if ceiling_ok is False else UNKNOWN), detail))

    # 4 scope
    try:
        sc = cs_immune._scope(slug)
    except Exception as exc:  # noqa: BLE001
        return g + [Gate(4, "scope retrievable", UNKNOWN, f"{type(exc).__name__}")]
    addrs = sc.get("addresses") or []
    repos = sc.get("repos") or []
    g.append(Gate(4, "scope retrievable", PASS if (addrs or repos) else FAIL,
                  f"{len(addrs)} addr, {len(repos)} repo"))

    # 5 audited contracts still exist
    if audit_dir and repo_dir and repo_dir.is_dir():
        audited = _audit_contract_names(audit_dir)
        if not audited:
            g.append(Gate(5, "audited contracts exist", UNKNOWN, "no audit corpus markdown to read"))
        else:
            present = {p.name for p in repo_dir.rglob("*.sol")} | \
                      {p.name for p in repo_dir.rglob("*.vy")}
            missing = sorted(n for n in audited if n not in present)
            verdict = PASS if not missing else FAIL
            g.append(Gate(5, "audited contracts exist", verdict,
                          f"{len(audited) - len(missing)}/{len(audited)} still present"
                          + (f"  MISSING: {missing[:4]}" if missing else "")))
    else:
        g.append(Gate(5, "audited contracts exist", UNKNOWN, "supply --audit-dir and --repo-dir"))

    # 6 in-scope addresses mapped to contracts
    if addrs:
        mapped, unmapped = [], 0
        for a in addrs[:max_addrs]:
            try:
                px = cs_re.resolve_proxy(str(a["chain"]), a["address"])
                tgt = (px.get("implementations") or [a["address"]])[0]
                res = deploy_source.fetch_many(
                    [f"{a['chain']}:{tgt}"], Path(f"/tmp/hunt_src/{a['address']}"), timeout=120
                )
                d = Path(res[0]["out_dir"])
                own = [p.name for p in d.rglob("*.sol")
                       if "/lib/" not in str(p) and "@openzeppelin" not in str(p)]
                if own:
                    mapped.append(f"{a['address'][:8]}..={own[0]}")
                else:
                    unmapped += 1
            except Exception:  # noqa: BLE001
                unmapped += 1
        verdict = PASS if mapped and not unmapped else (UNKNOWN if unmapped else FAIL)
        g.append(Gate(6, "in-scope mapped", verdict,
                      f"{len(mapped)} mapped, {unmapped} unmapped"))
    else:
        g.append(Gate(6, "in-scope mapped", UNKNOWN, "no in-scope addresses"))

    # 7 deployed == source (byte comparison, never a selector ratio)
    if addrs and repo_dir:
        notes = []
        verdict = UNKNOWN
        for a in addrs[:2]:
            if not rpc_for(str(a["chain"])):
                continue
            try:
                px = cs_re.resolve_proxy(str(a["chain"]), a["address"])
                impl = (px.get("implementations") or [None])[0]
                if not impl:
                    notes.append("no implementation resolved")
                    continue
                res = deploy_source.fetch_many(
                    [f"{a['chain']}:{impl}"], Path(f"/tmp/hunt_impl/{a['address']}"), timeout=180
                )
                d = Path(res[0]["out_dir"])
                own = [p for p in d.rglob("*.sol")
                       if "/lib/" not in str(p) and "@openzeppelin" not in str(p)]
                same = None
                for p in own:
                    local = repo_dir / p.name
                    if local.exists():
                        import hashlib
                        same = (hashlib.md5(local.read_bytes()).hexdigest()
                                == hashlib.md5(p.read_bytes()).hexdigest())
                        notes.append(f"{p.name} identical={same}")
                        break
                if same is not None:
                    verdict = PASS if same else FAIL
            except Exception as exc:  # noqa: BFLA
                notes.append(f"{type(exc).__name__}")
        g.append(Gate(7, "deployed == source", verdict, "; ".join(notes)[:90] or "not attempted"))
    else:
        g.append(Gate(7, "deployed == source", UNKNOWN, "no addresses or repo"))

    # 8 uninitialised admin
    if check_uninit and addrs:
        verdicts, unknown = [], 0
        for a in addrs[:max_addrs]:
            if not rpc_for(str(a["chain"])):
                continue
            try:
                u = cs_re.uninitialized_probe(str(a["chain"]), a["address"], max_args=4)
                verdicts.append(u["verdict"])
                if u["verdict"] == "UNKNOWN":
                    unknown += 1
            except Exception:  # noqa: BLE001
                unknown += 1
        if not verdicts:
            g.append(Gate(8, "no uninitialised admin", UNKNOWN, "no probes completed"))
        elif unknown:
            g.append(Gate(8, "no uninitialised admin", UNKNOWN,
                          f"{unknown} address(es) unresolved"))
        elif any(v == "UNINITIALIZED" for v in verdicts):
            g.append(Gate(8, "no uninitialised admin", FAIL,
                          f"{verdicts.count('UNINITIALIZED')} takeover-able"))
        else:
            g.append(Gate(8, "no uninitialised admin", PASS, f"{len(verdicts)} initialised"))
    else:
        g.append(Gate(8, "no uninitialised admin", UNKNOWN, "not requested"))

    # 9 reachable value
    if addrs:
        holding, unknown = 0, 0
        for a in addrs[:max_addrs]:
            if not rpc_for(str(a["chain"])):
                continue
            try:
                v = cs_re.has_value(str(a["chain"]), a["address"])
                if v.get("live"):
                    holding += 1
                elif v.get("status") == "UNKNOWN":
                    unknown += 1
            except Exception:  # noqa: BLE001
                unknown += 1
        if not (holding or unknown):
            g.append(Gate(9, "reachable value", FAIL, "no in-scope address holds value"))
        elif holding:
            g.append(Gate(9, "reachable value", PASS, f"{holding} address(es) hold value"))
        else:
            g.append(Gate(9, "reachable value", UNKNOWN, "could not read balances"))
    else:
        g.append(Gate(9, "reachable value", UNKNOWN, "no in-scope addresses"))

    return g


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Run the hunt procedure before reading code.")
    ap.add_argument("slug")
    ap.add_argument("--audit-dir", default="", help="local markdown audit corpus")
    ap.add_argument("--repo-dir", default="", help="local source tree the audits describe")
    ap.add_argument("--no-uninit", action="store_true")
    a = ap.parse_args()

    load_dotenv()
    gates = run(a.slug, Path(a.audit_dir) if a.audit_dir else None,
                Path(a.repo_dir) if a.repo_dir else None,
                check_uninit=not a.no_uninit)

    print(f"\nhunt procedure: {a.slug}\n")
    for gate in gates:
        print(gate.line())

    unknown = [x for x in gates if x.status == UNKNOWN]
    failed = [x for x in gates if x.status == FAIL]
    print()
    if failed:
        print(f"REJECT  {len(failed)} gate(s) failed: " + ", ".join(x.name for x in failed))
    if unknown:
        print(f"BLOCKED {len(unknown)} gate(s) unresolved: " + ", ".join(x.name for x in unknown))
        print("        an unresolved gate is not a pass. Resolve it before reading code.")
    if not failed and not unknown:
        print("GO      all gates resolved. Reading code is now justified.")
    return 1 if (failed or unknown) else 0


if __name__ == "__main__":
    raise SystemExit(main())