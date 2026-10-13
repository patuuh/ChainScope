"""Browser-backed transport for guarded requests (Phase 3.5).

Some programs (e.g. Leather) gate their API behind Cloudflare/bot rules that
reject every non-browser TLS fingerprint. ``BrowserSession`` drives the same
real Chrome the crawler uses: it keeps one page alive on an in-scope origin
and runs ``fetch()`` from inside that page, so requests carry a genuine
browser fingerprint and pass the WAF exactly like the SPA does.

Scope is enforced at the network boundary: a Playwright ``route`` handler
aborts every request whose URL leaves the program scope before it leaves the
browser (this also covers redirect hops the browser would otherwise follow
silently). Cookies from the page context persist across the run (Cloudflare
clearance, app session).

The interface mirrors ``GuardedSession`` (``request/get/post`` returning an
``httpx.Response``) so the testing engine can use it interchangeably via a
session factory.
"""
from __future__ import annotations

import typing
import urllib.parse

import httpx

from shinobi import probe as probe_mod
from shinobi import scope as scope_mod
from shinobi.store import Store

_FETCH_JS = r"""
([u, method, hdrs, bodyJson, ms]) => (async () => {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), ms);
  const opts = {method: method, headers: hdrs || {}, redirect: 'follow', signal: ac.signal};
  if (bodyJson !== null) {
    const headers = opts.headers || {};
    if (!Object.keys(headers).some(k => k.toLowerCase() === 'content-type'))
      opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(bodyJson);
  }
  try {
    const r = await fetch(u, opts);
    clearTimeout(timer);
    let t = '';
    try { t = await r.text(); } catch (_) {}
    return {status: r.status, headers: Object.fromEntries(
      Array.from(new Headers(r.headers)).map(([k, v]) => [k.toLowerCase(), v])),
      text: t.slice(0, 2000000)};
  } catch (e) {
    clearTimeout(timer);
    return {status: 0, headers: {}, text: ''};
  }
})()
"""


class BrowserSession:
    """Guarded fetch()s executed inside a real Chrome page."""

    def __init__(self, scope_obj: scope_mod.ProgramScope, store: Store,
                 role: str = "browser", headless: bool = True,
                 timeout: float = 25.0, start_url: str | None = None) -> None:
        self.scope = scope_obj
        self.store = store
        self.role = role
        self.headless = headless
        self.timeout = timeout
        self._start = start_url
        self._pw = None
        self._page = None

    # ------------------------------------------------------------ lifecycle
    def _install_route(self) -> None:
        def _guard(route) -> None:
            u = route.request.url
            if self.scope.authorized(u):
                route.continue_()
                return
            self.store.log_activity(
                self.scope.slug, self.role, "scope-block",
                u, {"reason": "browser-route"})
            route.abort()

        self._page.route("**/*", _guard)

    def _ensure_page(self, url: str) -> None:
        if self._pw is not None:
            cur = urllib.parse.urlsplit(self._page.url)
            target = urllib.parse.urlsplit(url)
            if (cur.netloc or "").lower() == target.netloc.lower():
                return
        if self._pw is None:
            from playwright.sync_api import sync_playwright
            self._pw = sync_playwright().start()
            browser = self._pw.chromium.launch(
                executable_path=probe_mod._chrome_path(),
                headless=not self.headless,
                args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"])
            self._page = browser.new_page(
                user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                            " (KHTML, like Gecko) Chrome/131 Safari/537.36"))
            self._install_route()
        target = urllib.parse.urlsplit(url)
        origin = f"{target.scheme}://{target.netloc}/"
        try:
            self._page.goto(origin, wait_until="domcontentloaded", timeout=30000)
        except Exception:  # noqa: BLE001
            # a non-200 origin (e.g. a 403 SPA shell) still finalises the
            # navigation; the route guard keeps every later fetch in scope
            try:
                self._page.wait_for_load_state("domcontentloaded")
            except Exception:  # noqa: BLE001
                pass

    # ---------------------------------------------------------------- guard
    def _check(self, url: str) -> None:
        if not self.scope.authorized(url):
            self.store.log_activity(
                self.scope.slug, self.role, "scope-block",
                url, {"reason": "browser-bridge"})
            raise scope_mod.ScopeError(
                f"refusing out-of-scope browser request: {url}")

    def request(self, method: str, url: str, **kwargs: typing.Any) -> httpx.Response:
        self._check(url)
        params = kwargs.pop("params", None) or {}
        json_body = kwargs.pop("json", kwargs.pop("json_body", None))
        headers = dict(kwargs.pop("headers", None) or {})
        timeout_ms = int((kwargs.pop("timeout", None) or self.timeout) * 1000)
        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(
                {k: (v if isinstance(v, str) else str(v)) for k, v in params.items()})
        self._ensure_page(url)
        try:
            raw = self._page.evaluate(_FETCH_JS,
                                      [url, method, headers, json_body, timeout_ms])
        except Exception:  # noqa: BLE001
            return self._resp(method, url, 0, b"", {})
        body = (raw.get("text") or "").encode("utf-8", "ignore")
        resp = self._resp(method, url, int(raw.get("status") or 0),
                          body, raw.get("headers") or {})
        self.store.log_activity(
            self.scope.slug, self.role, "request",
            f"{method} {url} -> {resp.status_code}",
            {"len": len(resp.content)})
        return resp

    def get(self, url: str, **kwargs: typing.Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: typing.Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    @staticmethod
    def _resp(method: str, url: str, status: int, content: bytes,
              headers: dict) -> httpx.Response:
        return httpx.Response(
            status_code=status, headers=headers, content=content,
            request=httpx.Request(method, url), history=[])

    def close(self) -> None:
        if self._pw is not None:
            try:
                self._pw.stop()
            finally:
                self._pw = None
                self._page = None

    def __enter__(self) -> "BrowserSession":
        return self

    def __exit__(self, *exc: typing.Any) -> None:
        self.close()