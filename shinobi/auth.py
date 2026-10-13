"""Authentication, MFA, and session management for the Shinobi engine.

This module implements the Shinobi "Authentication Support" feature locally:
  * Encrypted credential storage (Fernet, key in CHAINSCOPE_KEY or enc.key)
  * TOTP generation for authenticator-app MFA
  * IMAP email-OTP reader
  * Per-role cookie jar persistence (via the store)
  * httpx form-login wizard (fast path)
  * Playwright SSO/MFA fallback (headless google-chrome)

Every `GuardedSession` is constructed with a RoleAuth object that owns the
login state for one program + role combination.

Usage (programmatic):
    auth = RoleAuth(store, program_scope, role="user")
    auth.add_credentials(username, password, totp_secret="...")
    auth.login()                       # try httpx first, then Playwright
    session = auth.session()           # GuardedSession with valid cookies
"""
from __future__ import annotations

import base64
import imaplib
import io
import os
import pathlib
import re
import typing
import urllib.parse
from email import policy
from email.parser import BytesParser

import httpx
import pyotp

from shinobi import scope as scope_mod
from shinobi.net import GuardedSession
from shinobi.store import Store

_TIMEOUT = 35.0
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/131 Safari/537.36"
)

_CHROME_PATHS = [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
]


def _find_chrome() -> str:
    env = os.environ.get("CHAINSCOPE_CHROME")
    if env and pathlib.Path(env).exists():
        return env
    for p in _CHROME_PATHS:
        if pathlib.Path(p).exists():
            return p
    return "google-chrome"


def _get_key() -> bytes:
    raw = os.environ.get("CHAINSCOPE_KEY")
    if raw:
        return raw.encode() if isinstance(raw, str) else raw
    kp = pathlib.Path("~/.chainscope/enc.key").expanduser()
    if kp.exists():
        return kp.read_text().strip().encode()
    raise RuntimeError(
        "no encryption key found: set CHAINSCOPE_KEY or run 'cs_scope keygen'")


def encrypt_secret(plaintext: str) -> str:
    from cryptography.fernet import Fernet
    return Fernet(_get_key()).encrypt(plaintext.encode()).decode()


def decrypt_secret(cipher: str) -> str:
    from cryptography.fernet import Fernet
    return Fernet(_get_key()).decrypt(cipher.encode()).decode()


class OTPSource(typing.Protocol):
    def generate(self) -> str: ...


class TOTPGenerator:
    def __init__(self, secret: str, digits: int = 6, interval: int = 30) -> None:
        self._tp = pyotp.TOTP(secret, digits=digits, interval=interval)

    def generate(self) -> str:
        return self._tp.now()


class IMAPOTPReader:
    """Fetch the latest TOTP/email code from an IMAP mailbox.

    Format: ``imap(s)://user:password@host:port/folder``
    """

    def __init__(self, imap_url: str, timeout: int = 30) -> None:
        parsed = urllib.parse.urlparse(imap_url)
        use_ssl = parsed.scheme == "imaps" or (parsed.port or 993) == 993
        host = parsed.hostname or "localhost"
        port = parsed.port or (993 if use_ssl else 143)
        self.user = urllib.parse.unquote(parsed.username or "")
        self.password = urllib.parse.unquote(parsed.password or "")
        self.folder = (parsed.path or "/INBOX").lstrip("/") or "INBOX"
        self._conn: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        self._host = host
        self._port = port
        self._use_ssl = use_ssl

    def _connect(self) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        if self._conn is None:
            self._conn = (imaplib.IMAP4_SSL if self._use_ssl
                          else imaplib.IMAP4)(self._host, self._port)
            self._conn.login(self.user, self.password)
        return self._conn

    def generate(self) -> str:
        conn = self._connect()
        conn.select(self.folder, readonly=True)
        _, nums = conn.search(None, "ALL")
        ids = nums[0].split()
        if not ids:
            return ""
        uid = ids[-1]
        _, data = conn.fetch(uid, "(RFC822)")
        raw = data[0][1] if isinstance(data[0], tuple) else b""
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct in ("text/plain", "text/html"):
                    body = (body + "\n" + part.get_content()).strip()
        else:
            body = msg.get_content() or str(msg.get_payload(decode=True))
        return self._extract_code(body)

    @staticmethod
    def _extract_code(text: str) -> str:
        # look for 6-8 digit OTP; prefer "Your code is 123456" patterns
        for pat in [r"code\s+(\d{6,8})", r"OTP[:\s]+(\d{6,8})",
                    r"verification\s+code[:\s]+(\d{6,8})",
                    r"\b(\d{6})\b"]:
            m = re.search(pat, text, re.I)
            if m:
                return m.group(1)
        # fall back: last 6-digit number in the body
        codes = re.findall(r"\b(\d{6})\b", text)
        return codes[-1] if codes else ""


class FormLoginAttempter:
    """Try an httpx-based form login. Detects CSRF tokens, submits, and
    catches MFA pages (redirects to /mfa, /2fa, /verify). Returns True on
    success or False if Playwright fallback is needed."""

    def __init__(self, client: httpx.Client, base_url: str, username: str,
                 password: str, username_field: str = "email",
                 password_field: str = "password", login_path: str = "/login",
                 otp: OTPSource | None = None) -> None:
        self.client = client
        self.base = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.login_path = login_path
        self.otp = otp

    def attempt(self) -> bool:
        login_url = self.base + self.login_path
        try:
            resp = self.client.get(login_url)
        except httpx.HTTPError:
            return False
        html = resp.text
        # detect CSRF token
        csrf = None
        csrf_patterns = [
            r'name="_token"\s+value="([^"]+)"',
            r'name="csrf[_-]token"\s+value="([^"]+)"',
            r'"_token"\s*:\s*"([^"]+)"',
        ]
        for pat in csrf_patterns:
            m = re.search(pat, html)
            if m:
                csrf = m.group(1)
                break
        payload: dict[str, str] = {self.username_field: self.username,
                                   self.password_field: self.password}
        if csrf:
            payload["_token"] = csrf
        try:
            resp2 = self.client.post(login_url, data=payload, follow_redirects=True)
        except httpx.HTTPError:
            return False
        redirected = str(resp2.url)
        body2 = resp2.text.lower()
        # success indicators
        if any(k in redirected for k in ("/dashboard", "/account", "/app", "/wallet")):
            return True
        if any(k in body2 for k in ("logged in", "welcome", "dashboard")):
            return True
        # MFA/OTP required
        if any(k in redirected for k in ("/mfa", "/2fa", "/verify", "/otp")):
            if self.otp:
                code = self.otp.generate()
                if code:
                    return self._submit_mfa(code, redirected)
            return False
        if any(k in body2 for k in ("two-factor", "mfa", "verification code",
                                     "enter the code")):
            if self.otp:
                code = self.otp.generate()
                if code:
                    return self._submit_mfa(code, redirected)
            return False
        return False

    def _submit_mfa(self, code: str, mfa_url: str) -> bool:
        # try common MFA code field names
        for field in ["code", "otp", "token", "totp", "mfa_code", "mfaToken"]:
            try:
                resp3 = self.client.post(mfa_url, data={field: code},
                                         follow_redirects=True)
                url3 = str(resp3.url).lower()
                body3 = resp3.text.lower()
                if any(k in url3 for k in ("/dashboard", "/account", "/app", "/wallet")):
                    return True
                if any(k in body3 for k in ("logged in", "welcome", "dashboard")):
                    return True
            except httpx.HTTPError:
                continue
        return False


class PlaywrightSSOLogin:
    """Use Playwright + system google-chrome for SSO/MFA/JSSP flows.

    The login wizard is interactive: it opens the login page, fills fields,
    navigates SSO redirects, and handles TOTP/email OTP when needed.
    """

    def __init__(self, program_slug: str, role: str, base_url: str,
                 store: Store, username: str, password: str,
                 otp: OTPSource | None = None,
                 headed: bool = False) -> None:
        self.program_slug = program_slug
        self.role = role
        self.base_url = base_url.rstrip("/")
        self.store = store
        self.username = username
        self.password = password
        self.otp = otp
        self.headed = headed

    def login(self) -> dict[str, str]:
        """Run the login flow and return cookies as a dict."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # noqa: BLE001
            raise RuntimeError(
                "playwright not installed: pip install playwright") from exc
        cookies: dict[str, str] = {}
        chrome = _find_chrome()
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                executable_path=chrome,
                headless=not self.headed,
                args=["--no-sandbox", "--disable-gpu"],
            )
            ctx = browser.new_context(
                user_agent=_USER_AGENT,
                viewport={"width": 1280, "height": 800},
            )
            page = ctx.new_page()
            page.goto(self.base_url, wait_until="networkidle")
            self._fill_login_form(page)
            # detect and handle MFA
            self._handle_mfa(page)
            # capture cookies
            for c in ctx.cookies():
                cookies[c["name"]] = c["value"]
            browser.close()
        # persist to store
        self.store.upsert_session(self.program_slug, self.role, cookies,
                                  {"login_method": "playwright"})
        return cookies

    def _fill_login_form(self, page) -> None:
        """Find login form fields and fill credentials."""
        username_sels = ["input[type='email']", "input[name='email']",
                         "input[name='username']", "input[name='login']",
                         "input[id='email']", "input[id='username']"]
        password_sels = ["input[type='password']", "input[name='password']"]
        for sel in username_sels:
            el = page.query_selector(sel)
            if el:
                el.fill(self.username)
                break
        for sel in password_sels:
            el = page.query_selector(sel)
            if el:
                el.fill(self.password)
                break
        # submit
        submit_sels = ["button[type='submit']", "input[type='submit']",
                       "button:has-text('Sign in')", "button:has-text('Log in')"]
        for sel in submit_sels:
            el = page.query_selector(sel)
            if el:
                el.click()
                break
        page.wait_for_load_state("networkidle")

    def _handle_mfa(self, page) -> None:
        """If TOTP/email OTP page appears, fill code."""
        if not self.otp:
            return
        url = page.url.lower()
        body = page.content().lower()
        if any(k in url for k in ("/mfa", "/2fa", "/verify", "/otp")) or \
           any(k in body for k in ("two-factor", "verification code", "enter the code")):
            code = self.otp.generate()
            if not code:
                return
            code_sels = ["input[name='code']", "input[name='otp']",
                         "input[name='token']", "input[name='totp']",
                         "input[name='mfa_code']", "input[type='tel']"]
            for sel in code_sels:
                el = page.query_selector(sel)
                if el:
                    el.fill(code)
                    break
            submit = page.query_selector("button[type='submit']")
            if submit:
                submit.click()
            page.wait_for_load_state("networkidle")


class RoleAuth:
    """Manage authentication state for one program + role.

    Credential workflow:
      1. add_credentials(username, password, ...)  -- encrypts + stores
      2. login()  -- tries httpx form-login, falls back to Playwright
      3. session()  -- GuardedSession with valid cookies
      4. logout()   -- clear session
    """

    def __init__(self, store: Store, scope_obj: scope_mod.ProgramScope,
                 role: str = "default",
                 otp_method: str | None = None,
                 otp_config: str | None = None) -> None:
        self.store = store
        self.scope = scope_obj
        self.role = role
        self._otp_method = otp_method  # totp | imap
        self._otp_config = otp_config

    def add_credentials(self, username: str, password: str,
                        totp_secret: str | None = None,
                        extra: dict | None = None) -> str:
        extra = dict(extra or {})
        if totp_secret:
            extra["totp_secret"] = encrypt_secret(totp_secret)
        cipher = encrypt_secret(password)
        return self.store.add_credential(
            self.scope.slug, self.role, label=username,
            username=username, secret_cipher=cipher, extra=extra)

    def _get_otp(self, extra: dict | None = None) -> OTPSource | None:
        if self._otp_method == "totp" and (extra or {}).get("totp_secret"):
            return TOTPGenerator(decrypt_secret(extra["totp_secret"]))
        if self._otp_method == "imap" and self._otp_config:
            return IMAPOTPReader(self._otp_config)
        if (extra or {}).get("totp_secret"):
            return TOTPGenerator(decrypt_secret(extra["totp_secret"]))
        return None

    def _load_creds(self) -> dict | None:
        creds = self.store.list_credentials(self.scope.slug)
        for c in creds:
            if c.get("role") == self.role:
                return c
        return creds[0] if creds else None

    def login(self, headed: bool = False) -> dict[str, str]:
        """Attempt login (httpx → Playwright). Returns cookie dict."""
        cred = self._load_creds()
        if not cred:
            raise RuntimeError(
                f"no credentials for {self.scope.slug}/{self.role}: "
                "run cs_auth add-credential first")
        username = cred["username"]
        password = decrypt_secret(cred["secret_cipher"])
        extra = cred.get("extra_json") or {}
        if isinstance(extra, str):
            try:
                import json
                extra = json.loads(extra)
            except Exception:
                extra = {}
        otp = self._get_otp(extra)
        host = next(iter(self.scope.hosts), None)
        if not host:
            raise RuntimeError(f"no in-scope hosts for {self.scope.slug}")
        base_url = f"https://{host}"
        # try httpx form login first
        with GuardedSession(self.scope, self.store, role=self.role,
                            log_actor="auth") as session:
            attempt = FormLoginAttempter(session.client, base_url,
                                         username, password, otp=otp)
            if attempt.attempt():
                return session.cookies()
        # fallback: Playwright
        playwright_login = PlaywrightSSOLogin(
            self.scope.slug, self.role, base_url, self.store,
            username, password, otp=otp, headed=headed)
        return playwright_login.login()

    def session(self) -> GuardedSession:
        """Return a GuardedSession with the persisted cookie state."""
        return GuardedSession(self.scope, self.store, role=self.role,
                              log_actor="engine")

    def logout(self) -> None:
        """Clear the session cookies for this role."""
        self.store.upsert_session(self.scope.slug, self.role, {},
                                  status="logged-out")