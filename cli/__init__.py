"""ChainScope CLI commands."""
import sys
from pathlib import Path

# Ensure parent directory (ChainScope root) is in sys.path so that
# core, shinobi, mcp_server, cs_discover, typer modules are importable.
_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)
