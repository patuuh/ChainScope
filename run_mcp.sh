#!/usr/bin/env bash
# Launcher that works in both Docker (/opt/ChainScope) and local (symlinked)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Prefer an explicit override, then local virtualenvs, then system python
if [ -n "${CHAINSCOPE_PYTHON:-}" ] && [ -x "${CHAINSCOPE_PYTHON}" ]; then
    PYTHON="${CHAINSCOPE_PYTHON}"
elif [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
    PYTHON="$SCRIPT_DIR/.venv/bin/python"
elif [ -x "$SCRIPT_DIR/../.venv/bin/python" ]; then
    PYTHON="$SCRIPT_DIR/../.venv/bin/python"
else
    PYTHON="$(command -v python3)"
fi

export PYTHONPATH="$SCRIPT_DIR"
exec "$PYTHON" "$SCRIPT_DIR/mcp_server.py" "$@"
