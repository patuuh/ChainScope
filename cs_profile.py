#!/usr/bin/env python3
"""Profile a repository or workspace before building a ChainScope graph."""
import json
from pathlib import Path
import typer

from core.project_profile import profile_repository

app = typer.Typer()


@app.command()
def profile(
    repo_path: str = typer.Argument(..., help="Path to repository or workspace"),
    top: int = typer.Option(20, help="Number of top projects/extensions to show"),
    strategy: str = typer.Option("balanced", help="Ranking strategy: balanced or bounty"),
    include_research: bool = typer.Option(False, help="Include scripts/poc/fuzz/invariant/certora research artifacts"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    repo = Path(repo_path)
    if not repo.is_dir():
        typer.echo(f"Error: {repo_path} is not a directory", err=True)
        raise typer.Exit(1)

    data = profile_repository(str(repo), top=top, strategy=strategy, include_research=include_research)

    if json_output:
        typer.echo(json.dumps(data, indent=2))
        return

    typer.echo(f"Profile: {repo_path}")
    typer.echo(f"  Strategy: {data.get('ranking_strategy', strategy)}")
    typer.echo(f"  Workspace mode: {data.get('workspace_mode', False)}")
    typer.echo(f"  Include research: {data.get('include_research', include_research)}")
    typer.echo(f"  Total files scanned: {data.get('total_files_scanned', 0)}")
    typer.echo(f"  Supported source files: {data.get('source_files_supported', 0)}")

    languages = data.get("languages", {})
    if languages:
        typer.echo(f"  Languages: {', '.join(sorted(languages.keys()))}")

    build_plan = data.get("build_plan", [])
    if build_plan:
        typer.echo(f"\nBuild Plan ({len(build_plan)}):")
        for item in build_plan[:top]:
            reason = item.get("why", "")
            typer.echo(
                f"  {item.get('path', '?')} "
                f"[{', '.join(sorted(item.get('languages', {}).keys())) or 'unknown'}]"
            )
            if reason:
                typer.echo(f"    reason: {reason}")

    clusters = data.get("recommended_clusters") or data.get("workspace_clusters") or []
    if clusters:
        typer.echo(f"\nRecommended Clusters ({len(clusters)}):")
        for cluster in clusters[:top]:
            typer.echo(
                f"  {cluster.get('cluster', cluster.get('name', '?'))}: "
                f"{cluster.get('project_count', 0)} projects, "
                f"{cluster.get('source_files', 0)} source files"
            )


if __name__ == "__main__":
    app()
