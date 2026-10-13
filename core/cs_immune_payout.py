"""Read the payout a program actually displays.

The payload's `rewards` tiers are stale. IPOR reports Critical = $100,000 there,
while the live page says "Critical: Flat: $1,000" with $100k reachable only as a
cap on catastrophic findings. That error inverted a target assessment: an IPOR High
was quoted as $10,000 when the base is $1,000.

So the ceiling a hunt should be judged against comes from the rendered page, with
the payload kept only as a cross-check.
"""
from __future__ import annotations

import html
import re
import typing as t

_TAGS = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def _text(raw: str) -> str:
    return _WS.sub(" ", html.unescape(_TAGS.sub(" ", raw or "")))


def displayed_payouts(url: str, timeout: int = 90) -> dict[str, t.Any]:
    """Return {'critical_flat': int|None, 'raw': str, 'note': str}."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "_ci", Path(__file__).resolve().parent.parent / "cli" / "cs_immune.py"
    )
    ci = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ci)
    try:
        raw = ci._get(url, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return {"critical_flat": None, "raw": "", "note": f"fetch failed: {type(exc).__name__}"}
    txt = _text(raw)
    i = txt.find("Rewards by Threat Level")
    seg = txt[i:i + 320] if i >= 0 else ""
    m = re.search(r"Critical[^$]{0,48}\$\s*([\d,]+)", seg)
    flat = int(m.group(1).replace(",", "")) if m else None
    scale = re.search(r"payout is calculated linearly between[^.]{0,120}", txt)
    return {
        "critical_flat": flat,
        "raw": seg[:180],
        "impact_scaling": scale.group(0) if scale else None,
        "note": "" if flat else "no displayed Critical payout found - do not infer one",
    }
