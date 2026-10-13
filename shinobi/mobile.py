"""Shinobi mobile app audit stub (Phase 8 skeleton).

Intended future flow:
  1. APK/IPA download + install manifest via chosen store helper
  2. Frida / objection / radare2 baseline instrumentation
  3. Traffic capture (Magisk root / emulator + mitmproxy) mapped into the
     Shinobi surfaces DB
  4. The same Shinobi engine (shinobi.engine) fires payloads against the
     captured web/API surfaces
  5. Results flow into the same kill-test/report path

This module is the orchestration skeleton. It exposes the public API without
pulling in mobile-only dependencies (frida, objection, adb, radare2) so the
rest of ChainScope remains installable on a laptop.
"""
from __future__ import annotations

import typing

if typing.TYPE_CHECKING:
    from shinobi.store import Store

_phantom = True  # when True: installs are simulated, no real device needed


class MobileAuditError(Exception):
    """Raised when a mobile-specific step fails (dependencies, device, scope)."""


class MobileAuditor:
    """Orchestrates an APK/IPA audit and wires results into the Shinobi DB."""

    def __init__(self, store: "Store", slug: str, artifact: str,
                 device_id: str | None = None) -> None:
        self.store = store
        self.slug = slug
        self.artifact = artifact
        self.device_id = device_id

    # ------------------------------------------------------------------ acquire
    def acquire(self) -> str:
        """Download / stage the artifact for testing.

        Returns a local path to the APK/IPA or a Frida-compatible session ID.
        """
        raise MobileAuditError(
            "acquire: install Frida + objection + an emulator/physical device, "
            "configure the device ID (adb devices), then implement the "
            "download logic for the target platform (App Store, Play Store, "
            "enterprise IPA, .apk bundle).")

    # ---------------------------------------------------------------- install
    def install(self) -> str:
        """Push the artifact onto a test device / emulator.

        Returns the package name or Frida attach target.
        """
        raise MobileAuditError(
            "install: adb install -r <apk> (or `objection -g <pkg> explore`). "
            "For IPA, use a signing server or an enterprise distribution "
            "workflow; confirm jailbroken / provisioned test device.")

    # ---------------------------------------------------------------- explore
    def explore(self) -> list[dict]:
        """Capture traffic + filesystem/API mapping; populate the surfaces DB.

        Returns a list of discovered surfaces (for chaining into the engine).
        """
        raise MobileAuditError(
            "explore: start Frida on the device, hook OkHttp/Retrofit (Android) "
            "or URLSession (iOS), dump the host/path map into surfaces, then "
            "re-run `cs_active probe crawl <slug>` for the API endpoints.")

    # ------------------------------------------------------------------ test
    def test(self) -> list[dict]:
        """Run the Shinobi testing engine against discovered surfaces.

        Returns the same TestOutcome list the engine produces.
        """
        raise MobileAuditError(
            "test: `engine.Engine(self.slug, self.store, roles=[...]).run()`")

    # --------------------------------------------------------------- triage
    def triage(self) -> list[dict]:
        """Collect triage candidates from the engine (see engine.run)."""
        raise MobileAuditError("triage: see engine + verify workflows")


def install_tip(target: str) -> str:
    return (
        f"Install tips for {target}:\n"
        "- Android: `adb devices` -> `adb install -r <apk>` -> "
        "`objection -g <package> explore` or Frida attachment.\n"
        "- iOS: provisioned device -> `cfgutil install <ipa>` / "
        "`frida -U -l <script>.js <bundle-id>`.\n"
        "- Keep the device on a dedicated test network; Magisk + proxy for "
        "self-signed certs."
    )