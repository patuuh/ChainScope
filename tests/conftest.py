import os
import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def tmp_db(tmp_path):
    """Provides a temporary database path."""
    return str(tmp_path / "test.db")


@pytest.fixture
def sol_vault_path():
    return str(FIXTURES_DIR / "simple_vault.sol")


@pytest.fixture
def sol_token_path():
    return str(FIXTURES_DIR / "token.sol")


@pytest.fixture
def anchor_vault_path():
    return str(FIXTURES_DIR / "anchor_vault.rs")


@pytest.fixture
def substrate_pallet_path():
    return str(FIXTURES_DIR / "substrate_pallet.rs")


@pytest.fixture
def sol_repo(tmp_path):
    """Creates a temporary repo with Solidity fixtures."""
    repo = tmp_path / "sol_repo"
    repo.mkdir()
    for f in ["simple_vault.sol", "token.sol"]:
        src = FIXTURES_DIR / f
        if src.exists():
            (repo / f).write_text(src.read_text())
    return str(repo)


@pytest.fixture
def anchor_repo(tmp_path):
    """Creates a temporary repo with Anchor fixtures."""
    repo = tmp_path / "anchor_repo"
    repo.mkdir()
    src = FIXTURES_DIR / "anchor_vault.rs"
    if src.exists():
        (repo / "anchor_vault.rs").write_text(src.read_text())
    (repo / "Cargo.toml").write_text('[dependencies]\nanchor-lang = "0.29"\n')
    return str(repo)


@pytest.fixture
def substrate_repo(tmp_path):
    """Creates a temporary repo with Substrate fixtures."""
    repo = tmp_path / "substrate_repo"
    repo.mkdir()
    src = FIXTURES_DIR / "substrate_pallet.rs"
    if src.exists():
        (repo / "substrate_pallet.rs").write_text(src.read_text())
    (repo / "Cargo.toml").write_text('[dependencies]\nframe-support = "4.0"\n')
    return str(repo)
