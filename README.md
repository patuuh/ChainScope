# ChainScope

ChainScope is a local-first code graph for blockchain and protocol security research.

It turns source repositories into queryable SQLite knowledge graphs so you can trace:
- who can call what
- what writes critical state
- where trust boundaries exist
- which functions combine multiple risk signals
- how production code differs from scripts, PoCs, and fuzz harnesses

## Why use it

Most high-severity protocol bugs are not visible from one file at a time. They show up across:
- entry points
- internal call chains
- state transitions
- external calls
- admin and upgrade surfaces
- helper scripts and hidden research artifacts

ChainScope gives you a structural view of the repo before you start deep manual reading.

Use it when you want to:
- triage a large target workspace quickly
- rank likely bug-hunting surfaces
- trace attack paths through contracts and supporting services
- separate production findings from research scaffolding
- keep graph queries local and deterministic instead of relying on hosted analysis

## Best fit

ChainScope is strongest on:
- smart contract repos
- multi-repo blockchain workspaces
- protocol backends, keepers, relayers, indexers, and node code
- mixed Solidity/Rust/Go/Java/Python/TypeScript blockchain systems

It already supports graphing and scanning beyond pure contracts, but the highest-signal heuristics are still blockchain-first.

## Not a general web-app scanner

ChainScope is not yet a strong web application security platform.

It does **not** currently model:
- HTTP routes and middleware stacks
- sessions, cookies, CSRF, auth flows
- template rendering and XSS sinks
- file upload flows
- framework-specific ORM semantics
- cloud/IAM/runtime policy boundaries

You can still use it on backend code, and it already catches useful cross-language issues like command execution, deserialization, weak crypto, SQL injection, unsafe blocks, and race-like patterns. But the product should be understood as **protocol and blockchain security tooling first**.

## What it does

### Graph build

ChainScope indexes repositories into SQLite graphs containing:
- functions
- contracts/modules/types
- state variables
- call edges
- state read/write edges
- state transitions
- sink metadata
- source provenance metadata

### Query surface

It exposes:
- MCP tools for agent workflows
- small CLI wrappers for local use and scripting

Core tasks:
- workspace profiling: `cs_profile`
- graph build: `cs_build`
- top-level graph stats: `cs_summary`
- attack-surface ranking: `cs_hotspots`
- full audit rollup: `cs_audit`
- DeFi-specific scanners: `cs_defi`
- unsafe/backend scanners: `cs_unsafe`
- path tracing: `cs_paths`
- state tracing: `cs_trace`
- cross-boundary discovery: `cs_cross`
- state-machine analysis: `cs_state`
- deep function lookup: `cs_lookup`

## Supported code families

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

In practice, this makes ChainScope useful for:
- EVM protocols
- Solana/Anchor projects
- Substrate/Cosmos-style systems
- blockchain nodes and protocol services
- cross-chain messaging stacks

## Quick start

### 1. Profile a repo or workspace

Use the profiler first on anything large:

```bash
python cs_profile.py /path/to/workspace --strategy bounty --json
```

Why:
- `--strategy bounty` prioritizes exploit surface over raw repository size
- build plans come back with per-target database paths
- you avoid building one giant graph before you know where to look

### 2. Build a graph

```bash
python cs_build.py /path/to/repo --db graph.db
```

### 3. Query it

```bash
python cs_summary.py --db graph.db
python cs_paths.py --db graph.db --from deposit --to withdraw
python cs_trace.py --db graph.db --var balances
python cs_cross.py --db graph.db --external-calls
python cs_state.py --db graph.db --all
```

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

## MCP server

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

## Sandbox image

Build the sandbox image with:

```bash
docker build -f Dockerfile.sandbox -t chainscope-sandbox .
```

The Dockerfile copies the project to `/opt/ChainScope/`.

## Verification

The exported copy was verified at export time with:

```bash
pytest -q
```

Current result: `393 passed`
