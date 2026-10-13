"""Program scope model + hard guardrails.

A `ProgramScope` decides whether a URL is authorised before any dynamic action.
The rule set (matching Shinobi's "scoping"):

  * Only hosts listed by the program (in-scope asset hostnames, plus their
    subdomains when the asset is a registrable domain) are allowed.
  * Explicit out-of-scope URL prefixes always win.
  * A request to an unlisted host is DENIED by default (refuse by default).
  * Live/paused status of the program is carried along so the engine can stop
    when the program is paused.

Common helpers build the host set from the asset URLs the platform publishes
(https://apps.apple.com/... -> note the app-store pages are metadata, and the
*app's own* hosts come from a separate apk/ipa/native config - see probe.py).
"""
from __future__ import annotations

import re
import urllib.parse
import typing

_TLD = r"(?:com|org|net|io|app|dev|xyz|co|info|me|tech|finance|exchange|wallet|ai|gg|x|zh|tw|pro|systems|app)"  # noqa: E501
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:"
    + _TLD + r")?$", re.I)

# Hosts that appear as "assets" on bounty platforms but are listing/repo
# metadata owned by a THIRD PARTY - never dynamically testable (the real app
# API hosts are discovered from the binary/native config instead).
SKIP_LISTING_HOSTS = {
    "apps.apple.com", "itunes.apple.com", "play.google.com",
    "chromewebstore.google.com", "github.com", "gitlab.com",
    "bitbucket.org",
}


class ScopeError(Exception):
    """Raised when a request violates the program scope."""


def hostname(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or ""


def registrable(host: str) -> str:
    """Best-effort eTLD+1 for a host (handles common cases; 2-letter ccTLDs
    like .com.au / .co.uk use the public-suffix rule via explicit list)."""
    parts = host.lower().split(".")
    if len(parts) <= 2:
        return host.lower()
    if parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac", "or") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class ProgramScope:
    """Authorisation model for one program.

    Usually built by `cs_scope` from a platform fetch (Immunefi/HackenProof) or
    by hand. Mutations that change the authorisation set are forbidden once the
    scope is "locked" (engine started); call `freeze()` to lock.
    """

    def __init__(self, slug: str, name: str | None = None, platform: str = "manual",
                 assets: list[dict] | None = None,
                 oos_prefixes: list[str] | None = None,
                 live: bool = True) -> None:
        self.slug = slug
        self.name = name or slug
        self.platform = platform
        self.assets: list[dict] = assets or []
        self.oos_prefixes = [p.rstrip("/") for p in (oos_prefixes or [])]
        self.live = live
        self._frozen = False
        self.hosts: set[str] = set()
        self.prefixes: list[str] = []
        self._index_assets()

    def _index_assets(self) -> None:
        """Build the rule set from the asset list.

        Rules:
          * 'host' assets become host rules (subdomains included for the
            registrable domain).
          * 'prefix' assets (a URL path) become path-prefix rules pinned to
            their host.
        """
        for a in self.assets:
            url = (a or {}).get("url", "")
            if not url:
                continue
            host = hostname(url)
            if not host:
                continue
            if host.lower() in SKIP_LISTING_HOSTS:
                continue
            path = urllib.parse.urlsplit(url).path
            if path and path != "/":
                self.prefixes.append((host, path.rstrip("/")))
            else:
                self.hosts.add(host)
                if _DOMAIN_RE.match(host):
                    self.hosts.add(registrable(host))

    def freeze(self) -> None:
        self._frozen = True

    def add_host(self, host: str) -> None:
        if self._frozen:
            raise ScopeError("scope is frozen; add hosts before locking")
        self.hosts.add(host)

    def add_prefix(self, host: str, path: str) -> None:
        if self._frozen:
            raise ScopeError("scope is frozen; add prefixes before locking")
        self.prefixes.append((host.lower(), path.rstrip("/")))

    def authorized(self, url: str) -> bool:
        """True when `url` may be touched under this program's scope."""
        raw = url.strip()
        if not raw.startswith(("http://", "https://")):
            return False
        host = hostname(raw).lower()
        path = urllib.parse.urlsplit(raw).path.rstrip("/")
        if not host:
            return False
        # out-of-scope prefixes always win
        for oos in self.oos_prefixes:
            ohost = hostname(oos).lower()
            opath = urllib.parse.urlsplit(oos).path.rstrip("/")
            if ohost == host and (not opath or path == opath or path.startswith(opath + "/")):
                return False
        # path-prefix assets are allow rules pinned to their exact host
        for oh, op in self.prefixes:
            if oh == host and (path == op or path.startswith(op + "/")):
                return True
        # host rules (with subdomain coverage for registrable domains)
        if host in self.hosts:
            return True
        reg = registrable(host)
        if reg != host and reg in self.hosts:
            return True
        return False

    def describe(self) -> str:
        hosts = ", ".join(sorted(self.hosts)) or "-"
        prefixes = ", ".join(f"{h}{p}" for h, p in self.prefixes) or "-"
        return f"scope[{self.slug}] live={self.live}\n  hosts: {hosts}\n  prefixes: {prefixes}"


def scope_from_program_record(rec: dict) -> ProgramScope:
    """Build a ProgramScope from a store.programs dict (in_scope assets list)."""
    in_scope = rec.get("in_scope") or []
    assets: list[dict] = []
    oos_prefixes: list[str] = []
    for a in in_scope if isinstance(in_scope, list) else []:
        url = a.get("url") if isinstance(a, dict) else None
        if isinstance(a, dict) and a.get("type") == "oos":
            if url:
                oos_prefixes.append(url.split("~/**")[0])
        elif isinstance(a, dict) and url:
            assets.append(a)
    live = True
    el = rec.get("eligibility") or {}
    if isinstance(el, dict) and el.get("paused"):
        live = False
    return ProgramScope(
        slug=rec["slug"], name=rec.get("name"), platform=rec.get("platform"),
        assets=assets, oos_prefixes=oos_prefixes, live=live)