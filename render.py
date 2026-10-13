#!/usr/bin/env python3
"""ChainScope render entry point — starts the MCP server over streamable HTTP."""
import os
from mcp_server import mcp

mcp.run(transport="streamable-http")
