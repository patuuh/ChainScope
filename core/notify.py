# SPDX-License-Identifier: MIT
"""Small notification helper: webhook, SMTP email, or local-log fallback.

Config (environment variables):
  NOTIFY_WEBHOOK_URL   - Discord / Slack / Telegram / generic webhook URL
  NOTIFY_WEBHOOK_KIND  - one of: discord | slack | telegram | generic (default: discord)
  SMTP_HOST            - SMTP server (for Bird email: eu1.smtp.bird.com)
  SMTP_PORT            - SMTP port (default 587; 465 = implicit SSL/TLS, 2525/587 = STARTTLS)
  SMTP_USER            - SMTP username (for Bird: bird)
  SMTP_PASS            - SMTP password (for Bird: your bk_ ... key)
  SMTP_FROM            - from address (default SMTP_USER)
  SMTP_TO              - comma-separated recipients
  NOTIFY_LOG           - local log file to append to when no channel is configured
                         (default: ~/.chainscope/notifications.log)

If neither a webhook nor SMTP is configured, notifications are appended to the local log
and printed to stdout so nothing is silently dropped.

Bird (email): set SMTP_HOST=eu1.smtp.bird.com, SMTP_PORT=465, SMTP_USER=bird,
SMTP_PASS=<your bk_ key>, SMTP_TO=you@example.com. Port 465 uses implicit SSL/TLS; 587/2525
use STARTTLS. The key is read from the environment only - never hardcode it in source.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import smtplib
import subprocess
import sys
import typing
import urllib.error
import urllib.request
from email.message import EmailMessage


def _default_log() -> str:
    return str(pathlib.Path.home() / ".chainscope" / "notifications.log")


def _post_webhook(url: str, kind: str, subject: str, body: str) -> None:
    if kind == "telegram":
        payload = {"text": f"{subject}\n\n{body}"}
    elif kind == "slack":
        payload = {"text": f"{subject}\n\n{body}"}
    elif kind == "generic":
        payload = {"text": f"{subject}\n\n{body}"}
    else:  # discord
        payload = {"content": f"{subject}\n\n{body}"}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()


def _send_email(subject: str, body: str) -> None:
    host = os.environ.get("SMTP_HOST", "").strip()
    user = os.environ.get("SMTP_USER", "").strip()
    pw = os.environ.get("SMTP_PASS", "")
    to = [x.strip() for x in os.environ.get("SMTP_TO", "").split(",") if x.strip()]
    if not host or not to:
        raise RuntimeError("SMTP_HOST and SMTP_TO required for email notifications")
    port = int(os.environ.get("SMTP_PORT", "587"))
    frm = os.environ.get("SMTP_FROM", "").strip() or user
    msg = EmailMessage()
    msg["From"] = frm
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.set_content(body)
    if port == 465:
        # implicit SSL/TLS (Bird / port 465)
        with smtplib.SMTP_SSL(host, port) as server:
            if user and pw:
                server.login(user, pw)
            server.send_message(msg)
        return
    with smtplib.SMTP(host, port) as server:
        server.ehlo()
        if port in (587, 2525):
            server.starttls()
            server.ehlo()
        if user and pw:
            server.login(user, pw)
        server.send_message(msg)


def _log_locally(subject: str, body: str) -> None:
    log = pathlib.Path(os.environ.get("NOTIFY_LOG", "") or _default_log())
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(f"--- {subject} ---\n{body}\n\n")
    print(f"[notify] (local log {log}) {subject}\n{body}", file=sys.stdout)


def _dunst(subject: str, body: str) -> bool:
    """Fire a desktop popup (dunst/notify-send). Best-effort; returns True if a popup was shown."""
    if not os.environ.get("NOTIFY_DUNST", "1").strip():
        return False
    sender = shutil.which("notify-send")
    if sender:
        try:
            subprocess.run([sender, "cs_watch - " + subject, body[:300]], timeout=5, check=False)
            return True
        except Exception:  # noqa: BLE001
            pass
    # fall back to dunstctl (dunst's own CLI) if present
    dctl = shutil.which("dunstctl")
    if dctl:
        try:
            subprocess.run([dctl, "notify", body[:300]], timeout=5, check=False)
            return True
        except Exception:  # noqa: BLE001
            pass
    return False


def local(subject: str, body: str) -> bool:
    """Local-only notification: dunst popup + log. No webhook/SMTP (no email spam for heartbeats)."""
    _dunst(subject, body)
    _log_locally(subject, body)
    return False


def notify(subject: str, body: str) -> bool:
    """Send a notification via webhook/SMTP (best-effort) and ALWAYS fire a dunst popup + log.

    Returns True if any remote channel (webhook or SMTP) delivered; a local dunst popup and a
    log entry are always written so nothing is silently dropped.
    """
    _dunst(subject, body)  # always show a desktop popup (if a display is available)
    webhook = os.environ.get("NOTIFY_WEBHOOK_URL", "").strip()
    if webhook:
        try:
            _post_webhook(webhook, os.environ.get("NOTIFY_WEBHOOK_KIND", "discord"), subject, body)
            return True
        except Exception as exc:  # noqa: BLE001
            print(f"[notify] webhook failed ({exc}); falling back", file=sys.stderr)
    if os.environ.get("SMTP_HOST", "").strip():
        try:
            _send_email(subject, body)
            return True
        except Exception as exc:  # noqa: BLE001
            print(f"[notify] smtp failed ({exc}); falling back to log", file=sys.stderr)
    _log_locally(subject, body)
    return False
