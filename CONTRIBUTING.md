# Contributing to ChainScope

## Scope

ChainScope is a local-first structural analysis tool for blockchain and protocol security research. Good contributions usually improve one of:
- graph extraction accuracy
- query quality or consistency
- protocol-specific semantics
- CLI and MCP usability
- test coverage for real security patterns

## Development setup

Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the test suite:

```bash
pytest -q
```

## Change guidelines

- Keep changes scoped.
- Prefer repo-local import patterns already used in the codebase.
- Add or update tests for behavior changes.
- Do not mix unrelated refactors into feature patches.
- If you change CLI behavior, keep MCP behavior aligned where possible.
- If you add heuristics, document their intended signal and likely noise profile.

## High-value contribution areas

- better parser coverage for blockchain ecosystems
- higher-signal role, asset, config, and upgrade semantics
- improved provenance handling across mixed production and research graphs
- stronger backend-service modeling around protocol infrastructure
- realistic fixtures that capture trust-boundary and state-machine edge cases

## Pull request notes

When opening a change, include:
- what problem the change solves
- what files or query surfaces it affects
- how you verified it
- any expected false positives or known limitations

## Reporting issues

Useful bug reports include:
- target language or ecosystem
- minimal repro repository or fixture
- expected vs actual graph/query behavior
- whether the issue affects CLI, MCP, or both
