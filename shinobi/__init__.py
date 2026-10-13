"""Shinobi layer for ChainScope - autonomous offensive-security engine.

Implements the Shinobi Security feature set as local-first tooling:
scoping + guardrails, auth/MFA handling, active exploration, a response-adaptive
testing engine with vulnerability chaining, instant verify-fix, structured
reporting, MCP integration and static mobile analysis.

Everything here is safe by construction: every outbound request from this
package goes through `shinobi.net.GuardedSession`, which refuses to touch any
host that is not in the program's in-scope set.
"""