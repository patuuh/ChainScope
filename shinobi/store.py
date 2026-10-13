"""SQLite persistence for the Shinobi layer.

All dynamic-pentest state lives in `~/.chainscope/shinobi.db` (override with
CHAINSCOPE_DATA_DIR). Tables:

    programs      - scope records (assets, rewards, rules per program)
    credentials   - encrypted test-account credentials per program/role
    sessions      - per-role session state (cookies, headers, status)
    surfaces      - discovered endpoints / attack model
    findings      - validated findings (the thing reports are built from)
    activities    - audit trail of every request / decision the engine makes

Credentials are stored encrypted (Fernet); the key is read from CHAINSCOPE_KEY
or ~/.chainscope/enc.key (see `cs_scope keygen`).
"""
from __future__ import annotations

import json
import os
import pathlib
import sqlite3
import typing
import uuid
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
    id            TEXT PRIMARY KEY,
    slug          TEXT NOT NULL,
    platform      TEXT NOT NULL DEFAULT 'manual',
    name          TEXT,
    url           TEXT,
    max_bounty    INTEGER,
    reward_json   TEXT,
    in_scope_json TEXT,
    oos_json      TEXT,
    rules_json    TEXT,
    eligibility_json TEXT,
    created_at    TEXT,
    updated_at    TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_programs_slug ON programs(slug);

CREATE TABLE IF NOT EXISTS credentials (
    id           TEXT PRIMARY KEY,
    program_id   TEXT NOT NULL,
    role         TEXT NOT NULL,
    label        TEXT,
    username     TEXT,
    secret_cipher TEXT,
    extra_json   TEXT,
    created_at   TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    program_id   TEXT NOT NULL,
    role         TEXT NOT NULL,
    cookie_json  TEXT,
    headers_json TEXT,
    status       TEXT DEFAULT 'new',
    created_at   TEXT,
    last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS surfaces (
    id           TEXT PRIMARY KEY,
    program_id   TEXT NOT NULL,
    kind         TEXT,                 -- web | api | graphql | mobile | ...
    url          TEXT NOT NULL,
    method       TEXT,
    params_json  TEXT,
    headers_json TEXT,
    auth_required INTEGER DEFAULT 0,
    tech_json    TEXT,
    discovered_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id           TEXT PRIMARY KEY,
    program_id   TEXT NOT NULL,
    surface_id   TEXT,
    title        TEXT,
    vuln_class   TEXT,
    severity     TEXT,                 -- critical | high | medium | low | info
    status       TEXT DEFAULT 'candidate',  -- candidate | confirmed | verified-fixed | escaped-fix
    evidence_json TEXT,
    poc          TEXT,
    repro        TEXT,
    remediation  TEXT,
    cwe          TEXT,
    owasp        TEXT,
    created_at   TEXT,
    updated_at   TEXT
);

CREATE TABLE IF NOT EXISTS activities (
    id          TEXT PRIMARY KEY,
    program_id  TEXT,
    ts          TEXT,
    actor       TEXT,                  -- engine | crawler | auth | user | verify
    verb        TEXT,                  -- request | finding | login | scope-check
    target      TEXT,
    detail_json TEXT
);
"""


def data_dir() -> pathlib.Path:
    base = pathlib.Path(os.environ.get("CHAINSCOPE_DATA_DIR", "~/.chainscope"))
    base = base.expanduser()
    base.mkdir(parents=True, exist_ok=True)
    return base


def db_path() -> str:
    return str(data_dir() / "shinobi.db")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return uuid.uuid4().hex[:16]


def _j(obj: typing.Any) -> str:
    return json.dumps(obj, default=str)


def _un(a: str | None, default: typing.Any = None) -> typing.Any:
    if not a:
        return default
    try:
        return json.loads(a)
    except (ValueError, TypeError):
        return default


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


class Store:
    """Thin DAO over the shinobi DB. Every method takes/returns plain dicts."""

    def __init__(self, path: str | None = None) -> None:
        self._path = path or db_path()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.executescript(_SCHEMA)
        return conn

    # ---------------------------------------------------------------- programs
    def upsert_program(self, program: dict) -> str:
        pid = program.get("id") or _new_id()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO programs
                   (id, slug, platform, name, url, max_bounty, reward_json,
                    in_scope_json, oos_json, rules_json, eligibility_json,
                    created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT DO UPDATE SET
                     slug=excluded.slug, platform=excluded.platform,
                     name=excluded.name, url=excluded.url,
                     max_bounty=excluded.max_bounty,
                     reward_json=excluded.reward_json,
                     in_scope_json=excluded.in_scope_json,
                     oos_json=excluded.oos_json,
                     rules_json=excluded.rules_json,
                     eligibility_json=excluded.eligibility_json,
                     updated_at=excluded.updated_at""",
                (
                    pid, program["slug"], program.get("platform", "manual"),
                    program.get("name"), program.get("url"),
                    program.get("max_bounty"),
                    _j(program.get("rewards")), _j(program.get("in_scope")),
                    _j(program.get("oos")), _j(program.get("rules")),
                    _j(program.get("eligibility")),
                    program.get("created_at") or _now(), _now(),
                ),
            )
            # the surviving row may keep a different id (slug collision)
            row = conn.execute(
                "SELECT id FROM programs WHERE slug=?", (program["slug"],)).fetchone()
        return row["id"] if row else pid

    def get_program(self, slug: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM programs WHERE slug=?", (slug,)).fetchone()
        return self._row_to_program(row) if row else None

    def get_program_by_id(self, pid: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM programs WHERE id=?", (pid,)).fetchone()
        return self._row_to_program(row) if row else None

    def list_programs(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM programs ORDER BY updated_at DESC").fetchall()
        return [self._row_to_program(r) for r in rows]

    def delete_program(self, slug: str) -> None:
        with self._conn() as conn:
            pid_row = conn.execute(
                "SELECT id FROM programs WHERE slug=?", (slug,)).fetchone()
            if pid_row:
                conn.execute("DELETE FROM credentials WHERE program_id=?", (pid_row[0],))
                conn.execute("DELETE FROM sessions WHERE program_id=?", (pid_row[0],))
                conn.execute("DELETE FROM surfaces WHERE program_id=?", (pid_row[0],))
                conn.execute("DELETE FROM findings WHERE program_id=?", (pid_row[0],))
                conn.execute("DELETE FROM activities WHERE program_id=?", (pid_row[0],))
                conn.execute("DELETE FROM programs WHERE id=?", (pid_row[0],))

    @staticmethod
    def _row_to_program(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "slug": row["slug"], "platform": row["platform"],
            "name": row["name"], "url": row["url"], "max_bounty": row["max_bounty"],
            "rewards": _un(row["reward_json"]), "in_scope": _un(row["in_scope_json"]),
            "oos": _un(row["oos_json"]), "rules": _un(row["rules_json"]),
            "eligibility": _un(row["eligibility_json"]),
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    # ------------------------------------------------------------ credentials
    def add_credential(self, program_id: str, role: str, label: str | None,
                       username: str, secret_cipher: str, extra: dict | None = None) -> str:
        cid = _new_id()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO credentials (id, program_id, role, label, username,"
                " secret_cipher, extra_json, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (cid, program_id, role, label, username, secret_cipher,
                 _j(extra or {}), _now()),
            )
        return cid

    def list_credentials(self, program_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM credentials WHERE program_id=? ORDER BY role",
                (program_id,)).fetchall()
        return [dict(r) for r in rows]

    def delete_credentials(self, program_id: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM credentials WHERE program_id=?", (program_id,))

    # --------------------------------------------------------------- sessions
    def upsert_session(self, program_id: str, role: str, cookies: dict,
                       headers: dict | None = None, status: str = "active") -> str:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id FROM sessions WHERE program_id=? AND role=?",
                (program_id, role)).fetchone()
            sid = row[0] if row else _new_id()
            if row:
                conn.execute(
                    "UPDATE sessions SET cookie_json=?, headers_json=?, status=?,"
                    " last_seen_at=? WHERE id=?",
                    (_j(cookies), _j(headers or {}), status, _now(), sid))
            else:
                conn.execute(
                    "INSERT INTO sessions (id, program_id, role, cookie_json,"
                    " headers_json, status, created_at, last_seen_at)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (sid, program_id, role, _j(cookies), _j(headers or {}),
                     status, _now(), _now()))
        return sid

    def get_session(self, program_id: str, role: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE program_id=? AND role=?",
                (program_id, role)).fetchone()
        if not row:
            return None
        return {
            "id": row["id"], "program_id": row["program_id"], "role": row["role"],
            "cookies": _un(row["cookie_json"], {}), "headers": _un(row["headers_json"], {}),
            "status": row["status"],
        }

    # --------------------------------------------------------------- surfaces
    def add_surface(self, program_id: str, kind: str, url: str,
                    method: str | None = None, params: dict | None = None,
                    headers: dict | None = None, auth_required: bool = False,
                    tech: dict | None = None) -> str:
        sid = _new_id()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO surfaces (id, program_id, kind, url, method,"
                " params_json, headers_json, auth_required, tech_json,"
                " discovered_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (sid, program_id, kind, url, method, _j(params or {}),
                 _j(headers or {}), int(auth_required), _j(tech or {}), _now()),
            )
        return sid

    def list_surfaces(self, program_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM surfaces WHERE program_id=? ORDER BY discovered_at",
                (program_id,)).fetchall()
        return [{
            "id": r["id"], "kind": r["kind"], "url": r["url"],
            "method": r["method"], "params": _un(r["params_json"], {}),
            "headers": _un(r["headers_json"], {}), "auth_required": bool(r["auth_required"]),
            "tech": _un(r["tech_json"], {}),
        } for r in rows]

    def clear_surfaces(self, program_id: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM surfaces WHERE program_id=?", (program_id,))

    def delete_surfaces(self, program_id: str, ids: list[str]) -> int:
        if not ids:
            return 0
        placeholders = ",".join("?" * len(ids))
        with self._conn() as conn:
            cur = conn.execute(
                f"DELETE FROM surfaces WHERE program_id=? AND id IN ({placeholders})",
                [program_id, *ids])
        return cur.rowcount

    # ---------------------------------------------------------------- findings
    def add_finding(self, program_id: str, surface_id: str | None, title: str,
                    vuln_class: str, severity: str = "candidate", status: str = "candidate",
                    evidence: dict | None = None, poc: str | None = None,
                    repro: str | None = None, remediation: str | None = None,
                    cwe: str | None = None, owasp: str | None = None) -> str:
        fid = _new_id()
        now = _now()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO findings (id, program_id, surface_id, title,"
                " vuln_class, severity, status, evidence_json, poc, repro,"
                " remediation, cwe, owasp, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fid, program_id, surface_id, title, vuln_class, severity, status,
                 _j(evidence or {}), poc, repro, remediation, cwe, owasp, now, now),
            )
        return fid

    def update_finding(self, finding_id: str, **fields) -> None:
        allowed = {"severity", "status", "title", "evidence_json", "poc",
                   "repro", "remediation", "cwe", "owasp"}
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k in ("evidence_json",):
                v = _j(v) if not isinstance(v, str) else v
            sets.append(f"{k}=?")
            vals.append(v)
        vals.append(_now())
        if not sets:
            return
        with self._conn() as conn:
            conn.execute(
                f"UPDATE findings SET {', '.join(sets)}, updated_at=? WHERE id=?",
                (*vals, finding_id))

    def list_findings(self, program_id: str, status: str | None = None) -> list[dict]:
        q = "SELECT * FROM findings WHERE program_id=?"
        args: list[typing.Any] = [program_id]
        if status:
            q += " AND status=?"
            args.append(status)
        q += " ORDER BY date(updated_at) DESC"
        with self._conn() as conn:
            rows = conn.execute(q, args).fetchall()
        return [{
            "id": r["id"], "surface_id": r["surface_id"], "title": r["title"],
            "vuln_class": r["vuln_class"], "severity": r["severity"],
            "status": r["status"], "evidence": _un(r["evidence_json"], {}),
            "poc": r["poc"], "repro": r["repro"], "remediation": r["remediation"],
            "cwe": r["cwe"], "owasp": r["owasp"],
        } for r in rows]

    def get_finding(self, finding_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            return None
        return {
            "id": row["id"], "program_id": row["program_id"],
            "surface_id": row["surface_id"], "title": row["title"],
            "vuln_class": row["vuln_class"], "severity": row["severity"],
            "status": row["status"], "evidence": _un(row["evidence_json"], {}),
            "poc": row["poc"], "repro": row["repro"], "remediation": row["remediation"],
            "cwe": row["cwe"], "owasp": row["owasp"],
        }

    # ---------------------------------------------------------------- activity
    def log_activity(self, program_id: str | None, actor: str, verb: str,
                     target: str = "", detail: dict | None = None) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO activities (id, program_id, ts, actor, verb, target,"
                " detail_json) VALUES (?,?,?,?,?,?,?)",
                (_new_id(), program_id, _now(), actor, verb, target,
                 _j(detail or {})))

    def list_activities(self, program_id: str | None = None, limit: int = 50) -> list[dict]:
        q = "SELECT * FROM activities"
        args: list[typing.Any] = []
        if program_id:
            q += " WHERE program_id=?"
            args.append(program_id)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        with self._conn() as conn:
            rows = conn.execute(q, args).fetchall()
        return [dict(r) for r in rows]