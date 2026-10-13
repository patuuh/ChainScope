"""Shinobi report generator.

Turns confirmed findings into a submission-ready markdown report following the
Immunefi-style policy notes carried in ChainScope:

  * Title, scope asset, severity, CWE/OWASP
  * Summary + vulnerability details
  * Steps to reproduce (concise, rerunnable)
  * Impact (the boss move, not the demo)
  * Remediation
  * References (disclosed reports / prior audits)

Only findings that passed the kill-test (confirmed candidates) are eligible.
The output is Markdown; convert to the platform's own template when filing.
"""
from __future__ import annotations

import json
import typing

SEVERITY_LADDER = {
    "critical": "direct loss of funds / permanent compromise; CharlieChaos threshold",
    "high":   "significant impact: mass private-data leak, account takeover at scale, "
              "loss of a class of funds",
    "medium": "meaningful impact: single-victim takeover, partial data breach, "
              "limited funds loss",
    "low":    "info-ish: limited data exposure, minor config",
}

CWE_BY_CLASS = {
    "reflected/stored XSS": "CWE-79",
    "SQLi": "CWE-89",
    "NoSQLi": "CWE-943",
    "SSTI": "CWE-1336",
    "path traversal / LFI": "CWE-22",
    "SSRF / redirect": "CWE-918",
    "OS command injection": "CWE-78",
    "mass assignment": "CWE-915",
    "HTML injection": "CWE-80",
    "IDOR": "CWE-639",
}


def render_report(program: dict, findings: list[dict]) -> str:
    lines: list[str] = []
    f = findings[0]
    ok = 0 < len(findings) < 8
    title = f.get("title") or "Untitled finding"
    evidence: dict = _as_dict(f.get("evidence") or {})
    severity = (f.get("severity") or "candidate").lower()
    cls = (f.get("vuln_class") or "").strip() or "web"
    cwe = CWE_BY_CLASS.get(cls, "CWE-N/A")

    lines += [
        f"# {title}",
        "",
        f"- **Program**: {program.get('name') or program.get('slug')}",
        f"- **Asset**: {evidence.get('endpoint') or f.get('title', '')}",
        f"- **Severity**: {severity if severity in SEVERITY_LADDER else 'candidate (derive from impact)'}",
        f"- **CWE**: {cwe}",
        f"- **Class**: {cls}",
        f"- **Platform**: {program.get('platform') or 'manual'}",
        "",
        "## Summary",
        "",
        _short_summary(cls, severity, evidence),
        "",
        "## Vulnerability details",
        "",
        _detail_paragraph(cls, evidence),
        "",
        "## Steps to reproduce",
        "",
        "```bash",
        (f.get("poc") or _poc_text(evidence))[:1500],
        "```",
        "",
        "## Impact",
        "",
        SEVERITY_LADDER.get(severity,
            "Impact drives severity: state the boss move (what an attacker can really do), "
            "then map it to the program's severity table. Reads cap at informational."),
        "",
        "## Remediation",
        "",
        _remediation(cls),
        "",
        "## References",
        "",
        "- Disclosed reports on this program (search before filing)",
        "- Related audits / bug-bounty disclosures",
        "",
    ]
    if ok:
        pass
    return "\n".join(lines)


def _short_summary(cls: str, severity: str, evidence: dict) -> str:
    param = evidence.get("param", "")
    method = evidence.get("method", "GET")
    endpoint = evidence.get("endpoint", "endpoint")
    if "XSS" in cls:
        return (f"User-controlled input passed via `{method} {endpoint}` (parameter `{param}`) "
                "is reflected unescaped into the served document, allowing an attacker to execute "
                "arbitrary script in a victim's session.")
    if "SQLi" in cls or "NoSQLi" in cls:
        return (f"The `{param}` parameter of `{method} {endpoint}` reaches a database query "
                "unsanitised; an authentication/authorisation boundary can be bypassed or data "
                "beyond the caller's own read scope disclosed.")
    if "traversal" in cls:
        return f"`{param}` on `{method} {endpoint}` permits path traversal out of the static root."
    if "SSRF" in cls:
        return f"`{param}` on `{method} {endpoint}` lets the server-side fetcher hit arbitrary URLs."
    return (f"Input accepted by `{param}` on `{method} {endpoint}` produced an anomalous "
            "response (reflection/error/timing) outside the benign baseline.")


def _detail_paragraph(cls: str, evidence: dict) -> str:
    payload = evidence.get("payload", "")
    profile = evidence.get("profile", "")
    return (
        "The engine flagged this surface during an in-scope testing pass; the candidate "
        f"class is `{cls}`. Evidence: payload `{payload or '(see repro)'}`; response "
        f"signature `{profile or 'n/a'}`. Confirm with the included repro and tighten "
        "the impact claim in the report body (read-vs-write, victim privilege, MFA)."
    )


def _poc_text(evidence: dict) -> str:
    method = (evidence.get("method") or "GET").upper()
    url = evidence.get("endpoint", "")
    param = evidence.get("param", "")
    payload = evidence.get("payload", "")
    if url.startswith("http"):
        return f"curl -i -X {method} '{url}{'&' if '?' in url else '?'}{param}={payload}'"
    return "# paste the reproduction steps here"


def _remediation(cls: str) -> str:
    table = {
        "reflected/stored XSS": "context-aware output encoding; Content-Security-Policy; "
                                "sanitise on storage for stored cases.",
        "SQLi": "parameterised queries for all dynamic SQL; least-privilege DB accounts.",
        "NoSQLi": "strict schema validation; reject operator-objects from client input; "
                  "typed comparisons.",
        "SSTI": "never render user input inside templates; policy-strict template engine.",
        "path traversal / LFI": "resolve+verify the canonical path stays under the served root.",
        "SSRF / redirect": "allowlist destinations; block link-local/loopback ranges server-side.",
        "OS command injection": "avoid shell construction; use arg-array exec without a shell.",
        "mass assignment": "explicit allow-lists for writable fields when binding bodies.",
        "HTML injection": "escape untrusted output; sanitise where HTML is required.",
        "IDOR": "authorise object access inside the service, keyed to the session, not client-supplied IDs.",
    }
    return table.get(cls, "Encode/validate input on ingestion, permit only intended values; "
                           "place authorisation server-side keyed to the authenticated principal.")


def bundle_summary(program: dict, findings: list[dict]) -> str:
    lines = [f"# Report bundle - {program.get('name') or program.get('slug')}", ""]
    for i, f in enumerate(findings, 1):
        lines.append(f"{i}. {f.get('title')} [{f.get('severity') or 'candidate'}]")
    lines.append("")
    lines.append(f"{len(findings)} confirmed finding(s). File each as its own report; "
                 "mention only in-scope assets and a working PoC.")
    return "\n".join(lines)


def _as_dict(data: typing.Any) -> dict:
    if isinstance(data, dict):
        return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except ValueError:
            return {}
    return {}