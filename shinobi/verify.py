"""Shinobi verification: kill-tests a triage candidate before you report it.

Every engine candidate is a *triage seed* -- NOT a finding. Before a report is
defensible it must pass the ChainScope kill-test:

  1. Listed impact + defensible $ *today* (against the program severity table)
  2. Permissionless reach (or fully owned+captured chain)
  3. Intended-design check (could this be how the app is meant to behave?)
  4. PoC rule (reproducible, non-destructive, compliant with platform policy;
     mainnet-fork PoCs allowed, mainnet interaction prohibited)
  5. Prior-audit / duplicate check (read disclosed reports first)
  6. Scope: surface + asset + permission are in scope / not in OOS
  7. MFA bypassability (does MFA actually protect the broken action?)
  8. Read vs write: data changed (higher severity) or only viewed

This module also builds a reproducible PoC shell from the stored candidate.
"""
from __future__ import annotations

import dataclasses
import json
import typing

from shinobi.store import Store

CHECK_WEIGHTS = {
    "impact_todays_dollar": "the reported impact maps to a concrete (and paid) severity TODAY; no invented hypotheticals",
    "permissionless_reach": "the trigger is reachable without privileged precondition (or the attacker owns the whole chain of trust)",
    "intended_design": "the behaviour is not just how the product is supposed to work (safe-check against 'working as intended')",
    "poc_compliance": "working, reproducible PoC; non-destructive; mainnet-fork compliant (mainnet interaction prohibited)",
    "duplicate_check": "not a known/claimed issue (search disclosures + prior hacks before writing the report)",
    "in_scope_asset": "endpoint/asset and the permission used are in-scope, none of the OOS prefixes apply",
    "mfa_verdict": "MFA does not rescue the broken action (or the report says why MFA is by both sides reachable)",

    "read_vs_write": "known: data-read is informational, write/integrity actions escalate severity (pick impact from the boss move, not the demo)",
}


@dataclasses.dataclass
class KillTest:
    checks: list[tuple[str, str, str]]      # (check_id, verdict, note)  verdict: pass|warn|fail|manual
    verdict: str                            # submittable | needs_work | not_submittable

    def summary(self) -> str:
        counts: dict[str, int] = {}
        for _, verdict, _ in self.checks:
            counts[verdict] = counts.get(verdict, 0) + 1
        return (f"kill-test: {self.verdict} "
                f"(pass={counts.get('pass', 0)} warn={counts.get('warn', 0)} "
                f"fail={counts.get('fail', 0)} manual={counts.get('manual', 0)})")


def kill_test(program: dict, candidate: dict, poc_ready: bool = False) -> KillTest:
    """Run the checklist for one triage candidate row from the store."""
    severity = (candidate.get("severity") or "candidate").lower()
    title = candidate.get("title") or "?"
    evidence: dict = _as_dict(candidate.get("evidence") or {})
    has_writable_claim = any(w in title.lower() for w in
                             ("write", "takover", "privilege", "admin", "withdraw",
                              "transfer", "stored", "delete", "create"))
    checks: list[tuple[str, str, str]] = []

    # 1 impact + dollar today
    if severity in ("critical", "high", "medium", "low"):
        checks.append(("impact_todays_dollar", "pass",
                       f"severity {severity} mapped from the candidate"))
    else:
        checks.append(("impact_todays_dollar", "warn",
                       "severity is 'candidate' - you must derive a real severity from the impact & the program's severity table"))

    # 2 permissionless reach
    role = evidence.get("role", "anonymous")
    check_reach = "pass" if role in ("anonymous", "user") else "warn"
    checks.append(("permissionless_reach", check_reach,
                   f"executed as '{role}' - confirm no privileged precondition"))

    # 4 PoC rule
    checks.append(("poc_compliance", "pass" if poc_ready else "manual",
                   "build a reproducible PoC (bash/curl or browser repro) the reviewer can rerun; keep it non-destructive"))

    # 5 duplicate check - always manual
    checks.append(("duplicate_check", "manual",
                   "search the program's disclosed reports + public hacks before submitting"))

    # 6 in-scope
    status = "pass" if program.get("paused") is not True else "fail"
    checks.append(("in_scope_asset", status,
                   "program live=" + str(program.get("paused") is not True)))

    # 3 intended design - manual
    checks.append(("intended_design", "manual",
                   "determine if the observed behaviour is intended app design (authorize/bypass patterns often are)"))

    # 7 MFA verdict - manual
    checks.append(("mfa_verdict", "manual",
                   "check if 2FA/MFA gates the vulnerable action for BOTH attacker and victim"))

    # 8 read vs write
    checks.append(("read_vs_write",
                   "pass" if has_writable_claim else "warn",
                   "'write' claims (data modification) get the higher severity; reads cap at informational/low"))

    verdicts = [v for _, v, _ in checks]
    if "fail" in verdicts:
        verdict: str = "not_submittable"
    elif verdicts.count("warn") >= 3:
        verdict = "needs_work"
    elif verdicts.count("manual") and verdicts.count("manual") > 3:
        verdict = "needs_work"
    else:
        verdict = "submittable"
    return KillTest(checks, verdict)


def build_poc(candidate: dict) -> str:
    """Render a rerunnable PoC shell (curl-based for API candidates)."""
    evidence: dict = _as_dict(candidate.get("evidence") or {})
    method = evidence.get("method", "GET").upper()
    url = evidence.get("endpoint") or _url_from_title(candidate.get("title", ""))
    param = evidence.get("param", "")
    payload = evidence.get("payload", "")
    lines = [
        "#!/usr/bin/env bash",
        "# PoC repro - {title}".format(title=candidate.get("title", "candidate")),
        "# ChainScope: replace tokens, run, capture the output; keep it non-destructive.",
        "",
        "# Before running: (1) in-scope? (2) non-destructive? (3) fresh throwaway assets?",
        "set -euo pipefail",
        "",
    ]
    if all([method, url]):
        if method in ("POST", "PUT", "PATCH"):
            lines.append(f"curl -i -X {method} -H 'Content-Type: application/json' \\")
            lines.append(f"     -d '{json.dumps({param: payload})}' \\")
            lines.append(f"     '{url}'")
        elif param:
            lines.append(f"curl -i -X {method} \\")
            lines.append(f"     '{url}{'&' if '?' in url else '?'}{param}={_quote(payload)}'")
        else:
            lines.append(f"curl -i -X {method} '{url}'")
        lines += [
            "",
            "# Evidence to capture: the response line + the diff vs a benign request",
            "# Severity is driven by IMPACT (what can be done with it), not the signal.",
        ]
    else:
        lines += [
            "# no parseable endpoint; paste your manual repro steps here:",
            "# 1. login as <role>, open <url>",
            "# 2. submit <param> = <payload>",
            "# 3. observe <signal>",
        ]
    return "\n".join(lines) + "\n"


def _url_from_title(title: str) -> str:
    import re
    m = re.search(r"https?://\S+", title)
    if not m:
        return ""
    url = m.group(0).rstrip(".,;")
    url = url.split(")")[0] if ")" in url else url
    return url.split(" (")[0]


def _quote(value: str) -> str:
    import urllib.parse
    return urllib.parse.quote(value, safe="")


def _as_dict(data: typing.Any) -> dict:
    if isinstance(data, dict):
        return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except ValueError:
            return {}
    return {}