import json
def google_programs(min_bounty: float = 0.0) -> str:
    """List Google VRP programs.
    
    Args:
        min_bounty: Minimum max bounty filter.
    """
    from cli.cs_google import _load, _row
    try:
        programs = _load(refresh=False)
        rows = [_row(p) for p in programs if float(p["max_bounty"] or 0) >= min_bounty]
        return json.dumps(rows, default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)})

def intigriti_programs(min_bounty: float = 0.0) -> str:
    """List Intigriti bug bounty programs.
    
    Args:
        min_bounty: Minimum max bounty filter.
    """
    from cli.cs_intigriti import _load, _row
    try:
        programs = _load(refresh=False)
        rows = [_row(p) for p in programs if str(p.get("status", "")) in ("3", "4", "3.0") or p.get("status") in (3, 4)]
        rows = [r for r in rows if r["max_bounty"] >= min_bounty]
        return json.dumps(rows, default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)})

def hacken_programs(min_bounty: float = 0.0) -> str:
    """List HackenProof bug bounty programs.
    
    Args:
        min_bounty: Minimum max bounty filter.
    """
    from cli.cs_hacken import _load, _row
    try:
        programs = _load(refresh=False)
        rows = [_row(p) for p in programs if str(p.get("status", {}).get("name", "")).lower() == "active"]
        rows = [r for r in rows if r["max_bounty"] >= min_bounty]
        return json.dumps(rows, default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)})
