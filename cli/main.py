"""ChainScope CLI main entry point.

Usage:
    python -m cli
    chain-scope deployed lido --rpc https://ethereum.publicnode.com
    chain-scope surface graph.db --top 30
    chain-scope web fingerprint https://example.com
"""
import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import typer
from cli.cs_deployed import app as deploy_app
from cli.cs_surface import app as surface_app
from cli.cs_web import app as web_app
from cli.cs_build import app as build_app
from cli.cs_cross import app as cross_app
from cli.cs_paths import app as paths_app
from cli.cs_profile import app as profile_app
from cli.cs_reach import app as reach_app
from cli.cs_report import app as report_app
from cli.cs_scan import app as scan_app
from cli.cs_trace import app as trace_app
from cli.cs_verify import app as verify_app
from cli.cs_watch import app as watch_app
from cli.cs_audits import app as audits_app
from cli.cs_auth import app as auth_app
from cli.cs_prowl import app as prowl_app
from cli.cs_scope import app as scope_app
from cli.cs_sinks import app as sinks_app
from cli.cs_state import app as state_app
from cli.cs_summary import app as summary_app
from cli.cs_sweep import app as sweep_app
from cli.cs_target import app as target_app
from cli.cs_active import app as active_app
from cli.cs_divergence import app as divergence_app
from cli.cs_fetch import app as fetch_app
from cli.cs_re import app as re_app
from cli.cs_hacken import app as hacken_app
from cli.cs_immune import app as immune_app
from cli.cs_veck import app as veck_app
from cli.cs_screen import app as screen_app
from cli.cs_bugcrowd import app as bugcrowd_app
from cli.cs_google import app as google_app
from cli.cs_intigriti import app as intigriti_app
from cli.cs_pays import app as pays_app
from cli.cs_sherlock import app as sherlock_app
from cli.cs_gate import app as gate_app
from core.cs_discover import app as discover_app

app = typer.Typer()
app.add_typer(deploy_app, name="deployed")
app.add_typer(surface_app, name="surface")
app.add_typer(web_app, name="web")
app.add_typer(build_app, name="build")
app.add_typer(cross_app, name="cross")
app.add_typer(paths_app, name="paths")
app.add_typer(profile_app, name="profile")
app.add_typer(reach_app, name="reach")
app.add_typer(report_app, name="report")
app.add_typer(scan_app, name="scan")
app.add_typer(trace_app, name="trace")
app.add_typer(verify_app, name="verify")
app.add_typer(watch_app, name="watch")
app.add_typer(audits_app, name="audits")
app.add_typer(auth_app, name="auth")
app.add_typer(prowl_app, name="prowl")
app.add_typer(scope_app, name="scope")
app.add_typer(sinks_app, name="sinks")
app.add_typer(state_app, name="state")
app.add_typer(summary_app, name="summary")
app.add_typer(sweep_app, name="sweep")
app.add_typer(target_app, name="target")
app.add_typer(active_app, name="active")
app.add_typer(divergence_app, name="divergence")
app.add_typer(fetch_app, name="fetch")
app.add_typer(re_app, name="re")
app.add_typer(hacken_app, name="hacken")
app.add_typer(immune_app, name="immune")
app.add_typer(veck_app, name="veck")
app.add_typer(screen_app, name="screen")
app.add_typer(bugcrowd_app, name="bugcrowd")
app.add_typer(google_app, name="google")
app.add_typer(intigriti_app, name="intigriti")
app.add_typer(pays_app, name="pays")
app.add_typer(sherlock_app, name="sherlock")
app.add_typer(gate_app, name="gate")
app.add_typer(discover_app, name="discover")

if __name__ == "__main__":
    app()