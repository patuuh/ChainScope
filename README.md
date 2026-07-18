# ChainScope

[![License](https://img.shields.io/badge/license-MIT-2ea44f)](./LICENSE)
[![Focus](https://img.shields.io/badge/focus-blockchain%20security-0969da)](#best-fit)
[![Interface](https://img.shields.io/badge/interfaces-MCP%20%2B%20CLI-8250df)](#query-surface)
[![Scope](https://img.shields.io/badge/scope-local--first-f0883e)](#limitations)

ChainScope is a local-first code graph for blockchain and protocol security research.

It indexes repositories into SQLite knowledge graphs and gives humans and AI agents fast structural queries over:
- call paths
- state readers and writers
- trust boundaries
- state transitions
- sink reachability
- ranked hotspots
- research-vs-production provenance

## Why use it

High-severity protocol bugs rarely live in one function. They emerge across:
- public entry points
- internal call chains
- external calls
- admin and upgrade surfaces
- state mutations
- helper scripts, PoCs, and fuzz harnesses

ChainScope gives you that structural map before you start deep manual reading.

It is also built for agentic research. Instead of forcing an agent to read a large repository linearly, ChainScope lets it ask high-signal questions first:
- What are the riskiest functions?
- Who writes `balances`?
- Is there a path from `deposit` to `delegatecall`?
- Which functions cross trust boundaries?
- Which findings come from production code vs research scaffolding?

That means more context goes to exploitability and impact, and less to rebuilding repository structure from scratch.

## Who it is for

| Audience | What ChainScope helps with |
| --- | --- |
| Protocol security researchers | Fast graph-backed triage and path tracing |
| Bug bounty hunters | Exploit-surface-first target selection |
| Auditors | Structural navigation through large contract repos |
| AI-agent workflows | High-signal code relations without linear reading |
| Protocol/backend engineers | Trust-boundary and state-flow investigation |

## Field notes

| Signal | Note |
| --- | --- |
| Role | Map, not researcher |
| Best use | Graph-backed targeting, not verdicts |
| Speed | Finds risky intersections fast |
| Output quality | Good for hypothesis generation |
| Limitation | Manual exploitability still required |

## At a glance

| Area | What ChainScope gives you |
| --- | --- |
| Triage | Workspace profiling and exploit-surface-first target selection |
| Graphing | Functions, state vars, calls, reads/writes, transitions, sinks |
| Discovery | Hotspots, DeFi patterns, unsafe backend patterns |
| Tracing | Paths, state access, cross-boundary calls, state machines |
| Provenance | Research-mode indexing plus production-only query scope |
| Interfaces | MCP server for agents and CLI wrappers for local workflows |

## Best fit

ChainScope is strongest on:
- smart contract repos
- multi-repo blockchain workspaces
- protocol backends, keepers, relayers, indexers, and node code
- mixed Solidity/Rust/Go/Java/Python/TypeScript blockchain systems
- cross-chain messaging and bridge-style repos

Current language and ecosystem coverage includes:
- Solidity
- Vyper
- Move
- Clarity
- TON
- Cairo
- Sway
- Rust
- Go
- Java
- Python
- TypeScript / JavaScript
- C / C++
- protobuf
- Stellar XDR

## Installation

### Python environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### MCP setup

The exported MCP server name is `chainscope`:

```json
{
  "mcpServers": {
    "chainscope": {
      "command": "/opt/ChainScope/run_mcp.sh",
      "args": []
    }
  }
}
```

### Sandbox image

```bash
docker build -f Dockerfile.sandbox -t chainscope-sandbox .
```

The Dockerfile copies the project to `/opt/ChainScope/`.

## Working with agents

When Codex or Claude starts in a blockchain repo with the ChainScope MCP config loaded, the tools are available natively. Useful prompts include:
- `Profile this blockchain folder and recommend which subrepos to build first`
- `Build the knowledge graph for this repo, then show me the attack surface`
- `Trace who writes to balances`
- `Path from deposit to the delegatecall`
- `Tell me everything about deposit()`
- `Run all ChainScope tools and output a summarized report`

Typical tool flow:
1. `cs_profile` to choose the right target
2. `cs_build` to create the graph
3. `cs_summary` to confirm graph health, build metadata, and scope
4. `cs_audit` or `cs_hotspots` to rank the attack surface
5. `cs_paths`, `cs_trace`, `cs_cross`, and `cs_state` to validate the structure

`graph.db` is written to the current working directory unless you pass `--db`. After `.mcp.json` changes, start a fresh Codex session so the tool list reloads. In Claude Code, `/mcp` is the quickest way to confirm that the server is connected.

### Sandbox workflow

1. Copy `.mcp.json` into the target project folder.
2. From that project folder, run `docker sandbox run --template chainscope-sandbox claude`.

The custom image includes:
- Python plus the runtime dependencies from `Dockerfile.sandbox`
- tree-sitter parsers for the supported languages
- the ChainScope source tree at `/opt/ChainScope/`

Rebuild the image after local ChainScope changes:

```bash
docker build -f Dockerfile.sandbox -t chainscope-sandbox .
```

## Workflow

```text
cs_profile
   ->
pick target repo or package
   ->
cs_build
   ->
cs_summary
   ->
cs_hotspots / cs_audit
   ->
cs_paths / cs_trace / cs_cross / cs_state
   ->
manual source review
   ->
PoC or report
```

### Quick start

Profile a repo or workspace first:

```bash
python cs_profile.py /path/to/workspace --strategy bounty --json
```

Why:
- `--strategy bounty` prioritizes exploit surface over raw repository size
- build plans come back with per-target graph DB paths
- you avoid indexing a giant workspace blindly

Build a graph:

```bash
python cs_build.py /path/to/repo --db graph.db
```

If a build is time-limited or partial, ChainScope prioritizes production
protocol roots such as `src/`, `contracts/`, `programs/`, `pallets/`, and
`crates/` before lower-signal operational or config code. This keeps partial
graphs useful for agent triage.

Query it:

```bash
python cs_summary.py --db graph.db
python cs_paths.py --db graph.db --from deposit --to withdraw
python cs_trace.py --db graph.db --var balances
python cs_cross.py --db graph.db --external-calls
python cs_state.py --db graph.db --all
```

For agents, the usual loop is:
1. `cs_profile` to choose the right subrepo
2. `cs_build` to create the graph
3. `cs_summary` via MCP to confirm the DB is populated and scoped correctly
4. `cs_hotspots` or `cs_audit` via MCP to identify promising surfaces
5. `cs_paths`, `cs_trace`, `cs_cross`, and `cs_state` to validate structure
6. direct source reading only where the graph indicates it matters

For common function names, prefer qualified `cs_lookup` queries such as
`Vault.deposit` or `TokenMessaging.send`. Broad lookups are capped by default
so agents get candidates instead of an oversized response; set `max_matches=0`
only when exhaustive output is intentional.

## Query surface

### MCP tools

- `cs_profile`
- `cs_build`
- `cs_summary`
- `cs_hotspots`
- `cs_audit`
- `cs_defi`
- `cs_unsafe`
- `cs_paths`
- `cs_trace`
- `cs_cross`
- `cs_state`
- `cs_lookup`

### CLI wrappers

- `python cs_profile.py ...`
- `python cs_build.py ...`
- `python cs_summary.py ...`
- `python cs_paths.py ...`
- `python cs_trace.py ...`
- `python cs_cross.py ...`
- `python cs_state.py ...`
- `python cs_sinks.py ...`

## Research mode

By default, ChainScope stays production-first and skips low-signal or research-only paths such as:
- `scripts/`
- `poc/`
- `fuzz/`
- `invariant/`
- `certora/`
- `echidna/`

If you want those artifacts included:

```bash
python cs_profile.py /path/to/repo --include-research --json
python cs_build.py /path/to/repo --include-research
```

Mixed graphs preserve provenance with `source_context` tags such as:
- `production`
- `script`
- `poc`
- `fuzz`
- `invariant`

### Production-only querying

When you build a mixed graph, you can still query just production code:

```bash
python cs_summary.py --db graph.db --exclude-research
python cs_paths.py --db graph.db --from start --to finish --exclude-research
python cs_trace.py --db graph.db --var total --exclude-research
python cs_cross.py --db graph.db --external-calls --exclude-research
python cs_state.py --db graph.db --all --exclude-research
python cs_sinks.py --db graph.db --type self_destruct --exclude-research
```

The MCP server exposes the same scope control through `exclude_research=true`.

## Limitations

ChainScope is high-signal, but it is not a verdict engine.

Keep these limits in mind:
- exploitability still requires manual verification
- live state, balances, roles, and deployment wiring are outside pure static structure
- business-logic intent is not inferred reliably from graph shape alone
- some findings are intentionally noisy because they are meant to prioritize investigation, not replace it
- it is not yet a strong general web application security platform

ChainScope does not currently model:
- HTTP routes and middleware stacks
- session and cookie flows
- CSRF and browser-side auth semantics
- template rendering and XSS sinks
- file upload pipelines
- framework-specific ORM behavior
- cloud/IAM/runtime policy boundaries

You can still use it on backend code, and it already catches useful cross-language patterns such as command execution, deserialization, weak crypto, SQL injection, unsafe blocks, and race-like behavior. But the highest-signal heuristics are still blockchain-first.

## Sample output

### `cs_profile`

```json
{
  "workspace_mode": true,
  "strategy": "bounty",
  "recommended_clusters": [
    {
      "name": "bridges-and-messaging",
      "reason": "high trust-boundary density and externally reachable execution"
    }
  ],
  "build_plan": [
    {
      "label": "gmx-synthetics",
      "tool_call": {
        "tool": "cs_build",
        "repo_path": "/path/to/repo",
        "db": "graphs/gmx-synthetics.db"
      }
    }
  ]
}
```

### `cs_trace`

```json
{
  "query_scope": "production_only",
  "variable_matches": 1,
  "variables": [
    {
      "variable": "balances",
      "writers": [
        "Vault.deposit",
        "Vault.withdraw"
      ],
      "readers": [
        "Vault.previewWithdraw",
        "Vault.totalAssets"
      ]
    }
  ]
}
```

These outputs are intentionally structural. They tell you where to look next, not whether something is exploitable.

## Contributing

Contributions are welcome, especially in:
- parser quality for blockchain ecosystems
- protocol semantics and higher-signal heuristics
- CLI and MCP parity
- test fixtures for real protocol patterns

Start with [CONTRIBUTING.md](./CONTRIBUTING.md).

## Roadmap

Near-term expansion areas:
- richer protocol semantics for roles, upgrades, assets, and config surfaces
- broader parser-grade support for additional blockchain ecosystems
- stronger runtime and fork-aware workflows for validating live exploit paths
- better backend/web framework understanding beyond protocol-heavy repos
- more publish-ready CLI parity for every MCP query surface

## Verification

The current exported copy was verified with:

```bash
pytest -q
```

Result at the time of this README update:

`404 passed`
