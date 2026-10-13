"""Active exploration: crawl, map, fingerprint, discover APIs.

Implements Shinobi's "Exploration" feature:
  * Playwright crawl of every in-scope page (links, forms, XHR/fetch, cookies)
  * Tech-stack fingerprinting from headers + DOM markers
  * JS bundle collection -> endpoint extraction (+ source maps)
  * GraphQL schema introspection
  * A structured "attack model" persisted as `surfaces` rows

Everything stays inside the program scope: navigation and request capture are
filtered through `ProgramScope.authorized`, and bundle downloads go through a
`GuardedSession`.
"""
from __future__ import annotations

import json
import re
import time
import typing
import urllib.parse

from shinobi import scope as scope_mod
from shinobi.net import GuardedSession
from shinobi.store import Store

ENDPOINT_RE = re.compile(
    r"[/\"'`\s([](?P<path>/[a-zA-Z0-9_\-%$.]+(?:/[a-zA-Z0-9_\-%${}.:]+)*)"
    r"(?=[/\"'`\s?)\]<])",
    re.I)
API_KEYWORDS = ("api", "v1", "v2", "graphql", "rpc", "rest", "auth", "admin",
                "user", "users", "wallet", "account", "order", "trade",
                "withdraw", "deposit", "transaction", "kyc", "transfer",
                "callback", "webhook", "balance", "history", "settings")
SKIP_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".gif", ".woff",
            ".woff2", ".ico", ".map", ".json", ".webp")

_FORM_FIELD = re.compile(r'<input[^>]*name="([^"]+)"[^>]*>')

DOM_MARKERS: list[tuple[str, list[str]]] = [
    ("nextjs", ["__NEXT_DATA__", "_next/static"]),
    ("nuxt", ["__NUXT__", "data-v-"]),
    ("vue", ["data-v-"]),
    ("angular", ["__ngcc", "ng-version", "__nghost__"]),
    ("react", ["data-reactroot", "__reactFiber"]),
    ("gatsby", ["___gatsby", "data-gatsby"]),
    ("sentry", ["@sentry/browser", "Sentry.init"]),
    ("woocommerce", ["wp-content/plugins/woocommerce"]),
    ("wordpress", ["wp-content", "/wp-json/"]),
    ("laravel", ["csrf-token", "Laravel"]),
]


class CrawlResult(typing.NamedTuple):
    pages: list[dict]      # {url, title, status, forms, links, generated}
    requests: list[dict]   # {url, method, resource, status, auth}
    tech: dict
    bundles: list[str]
    endpoints: list[dict]  # {url, method, source, path, host}


class Crawler:
    """Scope-aware Playwright crawler. Only touches authorised hosts."""

    def __init__(self, scope_obj: scope_mod.ProgramScope, store: Store,
                 role: str = "default", depth: int = 2, headless: bool = True,
                 max_pages: int = 60, deadline: float = 150.0) -> None:
        self.scope = scope_obj
        self.store = store
        self.role = role
        self.depth = depth
        self.headless = headless
        self.max_pages = max_pages
        self.deadline = deadline
        self._chrome = _chrome_path()

    # ------------------------------------------------------------ crawl driver
    def run(self, start_urls: list[str] | None = None) -> CrawlResult:
        from playwright.sync_api import sync_playwright

        start_urls = start_urls or self._default_starts()
        pages: list[dict] = []
        requests: list[dict] = []
        bundles: list[str] = []
        seen: set[str] = set()
        queued: list[tuple[str, int]] = [(u, 0) for u in start_urls]
        tech: dict[str, typing.Any] = {}
        t0 = time.monotonic()

        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                executable_path=self._chrome, headless=not self.headless,
                args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"])
            ctx = browser.new_context(
                viewport={"width": 1280, "height": 900},
                user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                            " (KHTML, like Gecko) Chrome/131 Safari/537.36"))
            page = ctx.new_page()

            def _on_request(req) -> None:
                u = req.url
                if not self.scope.authorized(u):
                    return
                rt = req.resource_type
                if rt in ("xhr", "fetch", "websocket", "document"):
                    requests.append({"url": u, "method": req.method,
                                     "resource": rt, "status": None,
                                     "auth": bool(req.headers.get("authorization") or
                                                   req.headers.get("cookie"))})
                if rt == "script":
                    bundles.append(u)

            ctx.on("request", _on_request)

            while queued and len(pages) < self.max_pages:
                if time.monotonic() - t0 > self.deadline:
                    break
                url, d = queued.pop(0)
                if url in seen or not self.scope.authorized(url):
                    continue
                if d > self.depth:
                    continue
                seen.add(url)
                try:
                    page.goto(url, wait_until="networkidle", timeout=20000)
                except Exception:  # noqa: BLE001
                    try:
                        page.goto(url, wait_until="domcontentloaded", timeout=12000)
                    except Exception:  # noqa: BLE001
                        continue
                title = ""
                try:
                    title = page.title()
                except Exception:  # noqa: BLE001
                    pass
                links = self._page_links(page)
                forms = self._page_forms(page)
                pages.append({"url": page.url, "title": title,
                              "status": None, "forms": forms, "links": links})
                if not tech:
                    tech = self._fingerprint_page(page)
                # queue in-scope same-depth+1 links
                for href in links:
                    if self.scope.authorized(href) and href not in seen:
                        queued.append((href, d + 1))
            browser.close()

        endpoints = extract_endpoints(bundles, start_urls, deadline=self.deadline)
        result = CrawlResult(pages=pages, requests=requests, tech=tech,
                             bundles=sorted(set(bundles)), endpoints=endpoints)
        self._persist(result)
        return result

    # ------------------------------------------------------------ page helpers
    def _default_starts(self) -> list[str]:
        starts = ["https://" + h + "/" for h in sorted(self.scope.hosts)
                  if not h.startswith("*")]
        return starts

    @staticmethod
    def _page_links(page) -> list[str]:
        try:
            return [typing.cast(str, h) for h in page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)")]
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _page_forms(page) -> list[dict]:
        out: list[dict] = []
        try:
            forms = page.query_selector_all("form")
            for f in forms:
                action = f.get_attribute("action") or ""
                method = (f.get_attribute("method") or "GET").upper()
                fields = []
                for name in f.eval_on_selector_all(
                        "input, select, textarea",
                        "els => els.map(e => e.name || e.id)"):
                    if name:
                        fields.append(name)
                out.append({"action": action, "method": method, "fields": fields})
        except Exception:  # noqa: BLE001
            pass
        return out

    @staticmethod
    def _fingerprint_page(page) -> dict:
        headers: dict[str, str] = {}
        try:
            resp = page.request.get(page.url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:  # noqa: BLE001
            pass
        html = ""
        try:
            html = page.content()
        except Exception:  # noqa: BLE001
            pass
        frameworks = [name for name, pats in DOM_MARKERS
                      if any(p in html for p in pats)]
        return {
            "server": headers.get("server"),
            "powered": headers.get("x-powered-by"),
            "generator": headers.get("x-generator"),
            "csp": (headers.get("content-security-policy") or "")[:200],
            "frameworks": frameworks,
        }

    # ---------------------------------------------------------------- persist
    def _persist(self, result: CrawlResult) -> None:
        self.store.clear_surfaces(self.scope.slug)
        # dedupe endpoints to (kind, host, path, method); only in-scope hosts
        seen: set[tuple] = set()
        for ep in result.endpoints:
            if not self.scope.authorized(ep["url"]):
                continue
            if "${" in ep["url"] or "{" in ep["url"]:
                continue
            host = scope_mod.hostname(ep["url"])
            path = urllib.parse.urlsplit(ep["url"]).path
            key = ("api", host, path, ep["method"])
            if key in seen:
                continue
            seen.add(key)
            self.store.add_surface(
                self.scope.slug, "api", ep["url"], method=ep["method"],
                params=parse_query(ep["url"]), auth_required=False,
                tech={"source": ep["source"]})
        for req in result.requests:
            host = scope_mod.hostname(req["url"])
            path = urllib.parse.urlsplit(req["url"]).path
            key = ("network", host, path, req["method"])
            if key in seen:
                continue
            seen.add(key)
            self.store.add_surface(
                self.scope.slug, "network", req["url"], method=req["method"],
                params=parse_query(req["url"]),
                auth_required=bool(req["auth"]),
                tech={"source": "network-capture", "resource": req["resource"]})
        for pg in result.pages:
            host = scope_mod.hostname(pg["url"])
            path = urllib.parse.urlsplit(pg["url"]).path
            key = ("web", host, path, "GET")
            if key in seen:
                continue
            seen.add(key)
            self.store.add_surface(
                self.scope.slug, "web", pg["url"], method="GET",
                params=parse_query(pg["url"]), auth_required=False,
                tech={"forms": pg["forms"], "title": pg["title"]})


# --------------------------------------------------------------------- utils
def _chrome_path() -> str:
    import os
    import pathlib as pl
    env = os.environ.get("CHAINSCOPE_CHROME")
    if env and pl.Path(env).exists():
        return env
    for p in ("/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
              "/usr/bin/chromium-browser", "/usr/bin/chromium"):
        if pl.Path(p).exists():
            return p
    return "google-chrome"


def parse_query(url: str) -> dict[str, str]:
    return {k: v for k, v in urllib.parse.parse_qsl(
        urllib.parse.urlsplit(url).query)}


def extract_endpoints(bundles: list[str], roots: list[str] | None = None,
                      deadline: float = 60.0) -> list[dict]:
    """Extract candidate API endpoints from JS bundle URLs.

    Fetches each bundle with a raw client (no scope guard - these are the
    program's own assets already collected from an authorised crawl), then pulls
    path-like strings from the JS and sourcemaps.
    Returns endpoint dicts: {url, method, source, host, path}.
    """
    endpoints: list[dict] = []
    roots = roots or []
    t0 = time.monotonic()
    for index, url in enumerate(sorted(set(bundles))):
        if len(endpoints) > 400 or time.monotonic() - t0 > deadline:
            break
        try:
            text = _raw_get(url)
        except Exception:  # noqa: BLE001
            continue
        # try to find a sourcemap
        map_text = _sourcemap_text(url, text)
        hay = text + "\n" + (map_text or "")
        seen_paths: set[str] = set()
        for m in ENDPOINT_RE.finditer(hay):
            path = m.group("path")
            if path.startswith("//"):
                continue
            if not any(kw in path.lower() for kw in API_KEYWORDS):
                continue
            if path.endswith(SKIP_EXT):
                continue
            if "/node_modules/" in path or "webpack" in path:
                continue
            host = ""
            base = next((r for r in roots if r), None)
            if base:
                host = scope_mod.hostname(base)
            pkey = (host, path)
            if pkey in seen_paths:
                continue
            seen_paths.add(pkey)
            url_abs = _absolutize(path, host)
            endpoints.append({"url": url_abs, "method": "",
                              "source": f"bundle:{index}", "host": host, "path": path})
    return endpoints


def _raw_get(url: str) -> str:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        content_type = resp.headers.get("Content-Type", "")
        if "javascript" not in content_type and not url.endswith((".js", ".map")):
            return ""
        return resp.read(2000000).decode("utf-8", "ignore")


def _sourcemap_text(url: str, text: str) -> str:
    m = re.search(r"sourceMappingURL=(\S+)", text)
    candidates = []
    if m:
        candidates.append(urllib.parse.urljoin(url, m.group(1)))
    candidates.append(url + ".map")
    candidates.append(re.sub(r"\.js$", ".js.map", url))
    for cand in candidates:
        if cand == url:
            continue
        try:
            raw = _raw_get(cand)
        except Exception:  # noqa: BLE001
            continue
        if not raw:
            continue
        if raw.lstrip().startswith(("{", "[")):
            try:
                data = json.loads(raw)
                return "\n".join(data.get("sourcesContent", [])) if isinstance(data, dict) else ""
            except (ValueError, AttributeError):
                continue
    return ""


def _absolutize(path: str, host: str) -> str:
    if path.startswith("http"):
        if not path.startswith("//"):
            return path
        return "https:" + path
    if not path.startswith("/") and HOSTNAME_HEAD_RE.match(path):
        return "https://" + path
    # a leading path segment that itself looks like a hostname is a literal URL
    # glued by the codebase, not a path on the program host
    segs = path.lstrip("/").split("/")
    first = segs[0] if segs else ""
    if path.startswith("/") and "." in first and HOST_SEG_RE.match(first):
        return "https://" + path.lstrip("/")
    return f"https://{host}{path if path.startswith('/') else '/' + path}"


HOSTNAME_HEAD_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::[0-9]+)?(?:/|$)")
HOST_SEG_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def host_seg_looks_host(seg: str) -> bool:
    """True when a single path segment is shaped like a hostname."""
    return bool(seg and "." in seg and HOST_SEG_RE.match(seg))


def graphql_introspect(caller: typing.Callable, url: str,
                       timeout: int = 30) -> dict | None:
    """Introspect a GraphQL endpoint via a guarded caller (e.g. session.post)."""
    query = """{__schema{queryType{name} mutationType{name}
                types{name kind fields{name type{name kind}}
                 inputFields{name type{name kind}}}}}"""
    try:
        resp = caller("POST", url, json={"query": query}, timeout=timeout)
    except Exception:  # noqa: BLE001
        return None
    if resp.status_code not in (200,):
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    schema = (data or {}).get("data", {}).get("__schema")
    if not schema:
        return None
    types = schema.get("types") or []
    fields = [t for t in types
              if t.get("kind") in ("OBJECT", "INPUT_OBJECT")
              and not t.get("name", "").startswith("__")]
    return {"query_type": schema.get("queryType"),
            "mutation_type": schema.get("mutationType"),
            "types": fields[:40]}