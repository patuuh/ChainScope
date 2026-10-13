"""ChainScope CLI entry point.

Usage:
    python -m cli
    python cli/cs_deployed.py ...
    chain-scope deployed lido --rpc https://ethereum.publicnode.com
"""
import sys
from pathlib import Path

_PARENT = str(Path(__file__).resolve().parent.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from cli.main import app

if __name__ == "__main__":
    app()