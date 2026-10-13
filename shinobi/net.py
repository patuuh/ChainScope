"""Guarded HTTP transport for the Shinobi engine.

Every outbound request made by the engine, crawler and fuzzer runs through
`GuardedSession`. It wraps `httpx` and will not send a request to a host that
the program scope does not authorise - it refuses by default. This is the
safety rail that makes autonomous active testing acceptable: the engine can
only ever talk to the targets the program says it owns.

The session also keeps per-role cookie state (so a crawl/fuzz run stays on the
authenticated session it started with) and logs every request to the activity
trail.
"""
from __future__ import annotations

import typing
import urllib.parse

import httpx

from shinobi import scope as scope_mod
from shinobi.store import Store

Response = httpx.Response


class GuardedSession:
    """httpx.Client with scope enforcement, cookie jar, and activity logging."""

    def __init__(self, scope_obj: scope_mod.ProgramScope, store: Store,
                 role: str = "default", headers: dict | None = None,
                 timeout: float = 25.0, log_actor: str = "engine",
                 strict: bool = True) -> None:
        self.scope = scope_obj
        self.store = store
        self.role = role
        self.log_actor = log_actor
        self.strict = strict
        saved = store.get_session(scope_obj.slug, role)
        self._cookies: dict[str, str] = dict(saved["cookies"]) if saved else {}
        hdrs = dict(headers or {})
        if saved and saved.get("headers"):
            hdrs.update(saved["headers"])
        self._headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                          " (KHTML, like Gecko) Chrome/131 Safari/537.36",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            **hdrs,
        }
        self.timeout = timeout
        self.client = httpx.Client(
            headers=self._headers, timeout=timeout,
            follow_redirects=False, cookies=self._cookies,
        )

    # ------------------------------------------------------------------ guard
    def _check(self, url: str) -> str:
        if not self.scope.authorized(url):
            self.store.log_activity(
                self.scope.slug, self.log_actor, "scope-block",
                url, {"role": self.role})
            if self.strict:
                raise scope_mod.ScopeError(
                    f"refusing out-of-scope request: {url} (program={self.scope.slug})")
        return url

    # ---------------------------------------------------------------- requests
    def request(self, method: str, url: str, **kwargs: typing.Any) -> Response:
        self._check(url)
        current = url
        resp = self.client.request(method, current, **kwargs)
        # follow redirects one hop at a time, refusing out-of-scope locations
        hops = 0
        while resp.is_redirect and hops < 5:
            loc = resp.headers.get("location", "")
            if not loc:
                break
            next_url = urllib.parse.urljoin(current, loc)
            if not self.scope.authorized(next_url):
                self.store.log_activity(
                    self.scope.slug, self.log_actor, "scope-block",
                    next_url, {"role": self.role, "reason": "redirect"})
                if self.strict:
                    break
            current = next_url
            try:
                resp = self.client.request(method, current, **kwargs)
            except Exception:  # noqa: BLE001
                break
            hops += 1
        self._sync_cookies()
        self.store.log_activity(
            self.scope.slug, self.log_actor, "request",
            f"{method} {url} -> {resp.status_code}",
            {"role": self.role, "len": len(resp.content)})
        return resp

    def get(self, url: str, **kwargs: typing.Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: typing.Any) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: typing.Any) -> Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: typing.Any) -> Response:
        return self.request("DELETE", url, **kwargs)

    def close(self) -> None:
        self._sync_cookies()
        self.client.close()

    def __enter__(self) -> "GuardedSession":
        return self

    def __exit__(self, *exc: typing.Any) -> None:
        self.close()

    # ------------------------------------------------------------------ state
    def _sync_cookies(self) -> None:
        if self.client.cookies:
            self._cookies = {c.name: c.value for c in self.client.cookies.jar}
            self.store.upsert_session(
                self.scope.slug, self.role, self._cookies,
                dict(self.client.headers))

    def cookies(self) -> dict[str, str]:
        return dict(self._cookies)

    def set_header(self, key: str, value: str) -> None:
        self.client.headers[key] = value
        self._headers[key] = value