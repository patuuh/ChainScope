"""Tests for Soroban/Stellar knowledge graph extraction."""

import json
import pytest
from pathlib import Path
from core.web3.soroban import SorobanExtractor


# --- Token fixture ---

@pytest.fixture(scope="module")
def token_result():
    ext = SorobanExtractor()
    src = Path("tests/fixtures/soroban_token.rs").read_bytes()
    return ext.extract_from_source(src, "soroban_token.rs")


@pytest.fixture(scope="module")
def token_nodes(token_result):
    return {n["label"]: n for n in token_result.nodes}


@pytest.fixture(scope="module")
def token_edges(token_result):
    return token_result.edges


@pytest.fixture(scope="module")
def token_transitions(token_result):
    return token_result.transitions


# --- Vault fixture ---

@pytest.fixture(scope="module")
def vault_result():
    ext = SorobanExtractor()
    src = Path("tests/fixtures/soroban_vault.rs").read_bytes()
    return ext.extract_from_source(src, "soroban_vault.rs")


@pytest.fixture(scope="module")
def vault_nodes(vault_result):
    return {n["label"]: n for n in vault_result.nodes}


@pytest.fixture(scope="module")
def vault_edges(vault_result):
    return vault_result.edges


@pytest.fixture(scope="module")
def vault_transitions(vault_result):
    return vault_result.transitions


def _meta(node):
    """Parse metadata JSON from a node."""
    return json.loads(node.get("metadata", "{}"))


# ===========================================================================
# TOKEN TESTS
# ===========================================================================

class TestTokenContractNode:
    def test_contract_exists(self, token_nodes):
        assert "StellarToken" in token_nodes
        assert token_nodes["StellarToken"]["type"] == "contract"

    def test_contract_metadata(self, token_nodes):
        meta = _meta(token_nodes["StellarToken"])
        assert meta.get("is_contract") is True


class TestTokenErrorEnum:
    def test_error_enum_exists(self, token_nodes):
        assert "TokenError" in token_nodes
        assert token_nodes["TokenError"]["type"] == "error"

    def test_error_codes(self, token_nodes):
        meta = _meta(token_nodes["TokenError"])
        assert meta.get("contracterror") is True
        codes = meta.get("error_codes", {})
        assert codes.get("NotAuthorized") == 1
        assert codes.get("InsufficientBalance") == 2
        assert codes.get("InvalidAmount") == 3


class TestTokenContractTypeEnums:
    def test_datakey_enum(self, token_nodes):
        assert "DataKey" in token_nodes
        assert token_nodes["DataKey"]["type"] == "enum"
        meta = _meta(token_nodes["DataKey"])
        assert meta.get("contracttype") is True
        assert "Admin" in meta.get("variants", [])
        assert "Balance" in meta.get("variants", [])

    def test_token_state_enum(self, token_nodes):
        assert "TokenState" in token_nodes
        meta = _meta(token_nodes["TokenState"])
        assert "Active" in meta.get("variants", [])
        assert "Paused" in meta.get("variants", [])


class TestTokenFunctionExtraction:
    def test_public_functions_exist(self, token_nodes):
        for name in ("initialize", "mint", "transfer", "approve",
                      "transfer_from", "burn", "set_admin", "balance",
                      "total_supply", "name", "symbol", "decimals",
                      "pause", "use_nonce", "random_airdrop"):
            assert name in token_nodes, f"Missing function: {name}"
            assert token_nodes[name]["type"] == "function"

    def test_function_visibility(self, token_nodes):
        assert token_nodes["initialize"]["visibility"] == "public"
        assert token_nodes["mint"]["visibility"] == "public"

    def test_entry_point_detection(self, token_nodes):
        meta = _meta(token_nodes["initialize"])
        assert meta.get("is_entry_point") is True

    def test_auth_detection_on_mint(self, token_nodes):
        meta = _meta(token_nodes["mint"])
        assert meta.get("has_auth") is True

    def test_auth_detection_on_transfer(self, token_nodes):
        meta = _meta(token_nodes["transfer"])
        assert meta.get("has_auth") is True


class TestTokenStorageOps:
    def test_mint_has_instance_reads(self, token_nodes):
        meta = _meta(token_nodes["mint"])
        ops = meta.get("storage_ops", {})
        assert "instance" in ops
        assert "reads" in ops["instance"]

    def test_mint_has_persistent_writes(self, token_nodes):
        meta = _meta(token_nodes["mint"])
        ops = meta.get("storage_ops", {})
        assert "persistent" in ops
        assert "writes" in ops["persistent"]

    def test_mint_has_ttl_extension(self, token_nodes):
        meta = _meta(token_nodes["mint"])
        ops = meta.get("storage_ops", {})
        assert "ttl" in ops.get("persistent", {})


class TestTokenEdges:
    def test_storage_read_edges(self, token_edges):
        reads = [e for e in token_edges if e["relation"] == "reads_state"]
        assert len(reads) > 0

    def test_storage_write_edges(self, token_edges):
        writes = [e for e in token_edges if e["relation"] == "writes_state"]
        assert len(writes) > 0

    def test_event_edges(self, token_edges):
        events = [e for e in token_edges if e["relation"] == "emits_event"]
        assert len(events) > 0
        event_names = [json.loads(e["attributes"]).get("event") for e in events]
        assert "init" in event_names
        assert "mint" in event_names
        assert "xfer" in event_names

    def test_auth_guard_edges(self, token_edges):
        guards = [e for e in token_edges if e["relation"] == "guards"]
        assert len(guards) > 0


class TestTokenSecurityPatterns:
    def test_pause_missing_auth(self, token_nodes):
        """A2: pause() has no require_auth."""
        meta = _meta(token_nodes["pause"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "missing_auth" in risk_types or "missing_admin_auth" in risk_types

    def test_burn_missing_event(self, token_nodes):
        """G2: burn() does not emit event."""
        meta = _meta(token_nodes["burn"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "missing_token_event" in risk_types

    def test_mint_missing_amount_validation(self, token_nodes):
        """G4: mint() doesn't validate amount > 0."""
        meta = _meta(token_nodes["mint"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "missing_amount_validation" in risk_types

    def test_transfer_missing_ttl(self, token_nodes):
        """C7: transfer() writes persistent storage without extend_ttl."""
        meta = _meta(token_nodes["transfer"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "missing_extend_ttl" in risk_types

    def test_use_nonce_temporary_security(self, token_nodes):
        """C3/C8: use_nonce() stores security data in temporary storage."""
        meta = _meta(token_nodes["use_nonce"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "security_in_temporary" in risk_types

    def test_random_airdrop_insecure_prng(self, token_nodes):
        """H1: random_airdrop uses env.prng()."""
        meta = _meta(token_nodes["random_airdrop"])
        assert meta.get("insecure_randomness") is True
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "insecure_prng" in risk_types

    def test_initialize_unstructured_panic(self, token_nodes):
        """E1: initialize() uses panic!() instead of panic_with_error!()."""
        meta = _meta(token_nodes["initialize"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "unstructured_panic" in risk_types

    def test_unwrap_detection(self, token_nodes):
        """E2: Functions using .unwrap() are flagged."""
        meta = _meta(token_nodes["mint"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "unsafe_unwrap" in risk_types


# ===========================================================================
# VAULT TESTS
# ===========================================================================

class TestVaultContractNode:
    def test_contract_exists(self, vault_nodes):
        assert "DeFiVault" in vault_nodes
        assert vault_nodes["DeFiVault"]["type"] == "contract"


class TestVaultErrorEnum:
    def test_error_enum(self, vault_nodes):
        assert "VaultError" in vault_nodes
        meta = _meta(vault_nodes["VaultError"])
        codes = meta.get("error_codes", {})
        assert codes.get("NotAuthorized") == 1
        assert codes.get("SlippageExceeded") == 6


class TestVaultStateEnum:
    def test_vault_state_enum(self, vault_nodes):
        assert "VaultState" in vault_nodes
        meta = _meta(vault_nodes["VaultState"])
        variants = meta.get("variants", [])
        assert "Active" in variants
        assert "Paused" in variants
        assert "Deprecated" in variants


class TestVaultFunctions:
    def test_key_functions_exist(self, vault_nodes):
        for name in ("initialize", "deposit", "withdraw", "upgrade",
                      "set_fee_rate", "set_admin", "batch_distribute",
                      "calculate_compound", "execute_strategy",
                      "select_winner", "pause", "resume", "shares",
                      "total_shares", "unsafe_decode"):
            assert name in vault_nodes, f"Missing function: {name}"

    def test_deposit_has_auth(self, vault_nodes):
        meta = _meta(vault_nodes["deposit"])
        assert meta.get("has_auth") is True

    def test_upgrade_is_flagged(self, vault_nodes):
        meta = _meta(vault_nodes["upgrade"])
        assert meta.get("is_upgrade") is True


class TestVaultSecurityPatterns:
    def test_upgrade_missing_auth(self, vault_nodes):
        """A3: upgrade() has no require_auth."""
        meta = _meta(vault_nodes["upgrade"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "unprotected_upgrade" in risk_types

    def test_upgrade_no_event(self, vault_nodes):
        """I3: upgrade() doesn't emit event."""
        meta = _meta(vault_nodes["upgrade"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "upgrade_no_event" in risk_types

    def test_deposit_reentrancy(self, vault_nodes):
        """F2: deposit() writes state after cross-contract call."""
        meta = _meta(vault_nodes["deposit"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "state_after_external_call" in risk_types

    def test_deposit_unbounded_instance(self, vault_nodes):
        """C1: deposit() grows Vec in instance storage."""
        meta = _meta(vault_nodes["deposit"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "unbounded_instance_storage" in risk_types

    def test_calculate_compound_xor(self, vault_nodes):
        """B3: calculate_compound uses ^ instead of .pow()."""
        edges_for_func = []
        # Check via edges
        meta = _meta(vault_nodes["calculate_compound"])
        # The XOR detection is via edges, not risks
        # Just verify the function exists and is detected
        assert "calculate_compound" in vault_nodes

    def test_select_winner_timestamp(self, vault_nodes):
        """H2: select_winner uses ledger timestamp."""
        meta = _meta(vault_nodes["select_winner"])
        assert meta.get("time_dependent") is True
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "timestamp_randomness" in risk_types

    def test_unsafe_decode_block(self, vault_nodes):
        """E6: unsafe_decode has unsafe block."""
        meta = _meta(vault_nodes["unsafe_decode"])
        assert meta.get("unsafe") is True
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "unsafe_block" in risk_types

    def test_batch_distribute_unbounded(self, vault_nodes):
        """J1: batch_distribute loops over dynamic data."""
        meta = _meta(vault_nodes["batch_distribute"])
        risks = meta.get("soroban_risks", [])
        risk_types = [r["type"] for r in risks]
        assert "unbounded_loop" in risk_types

    def test_set_admin_custom_auth(self, vault_nodes):
        """Custom auth args detection."""
        meta = _meta(vault_nodes["set_admin"])
        assert meta.get("custom_auth_args") is True


class TestVaultCrossContractEdges:
    def test_deposit_has_cross_contract_call(self, vault_edges):
        cross_calls = [
            e for e in vault_edges
            if e["relation"] == "calls"
            and json.loads(e.get("attributes", "{}")).get("cross_contract")
        ]
        assert len(cross_calls) > 0

    def test_execute_strategy_cross_contract(self, vault_edges):
        cross_calls = [
            e for e in vault_edges
            if e["relation"] == "calls"
            and json.loads(e.get("attributes", "{}")).get("cross_contract")
            and "execute_strategy" in e["source"]
        ]
        assert len(cross_calls) > 0


class TestVaultStateTransitions:
    def test_pause_transition(self, vault_transitions):
        """Pause transitions VaultState to Paused."""
        pause_transitions = [
            t for t in vault_transitions
            if t["to_state"] == "Paused" and "VaultState" in t["entity"]
        ]
        assert len(pause_transitions) > 0

    def test_resume_transition(self, vault_transitions):
        """Resume transitions VaultState to Active."""
        resume_transitions = [
            t for t in vault_transitions
            if t["to_state"] == "Active" and "VaultState" in t["entity"]
        ]
        assert len(resume_transitions) > 0


class TestVaultDivisionBeforeMultiplication:
    def test_deposit_precision_loss(self, vault_edges):
        """B2: deposit() has division before multiplication."""
        precision_edges = [
            e for e in vault_edges
            if e["relation"] == "unchecked_math"
            and json.loads(e.get("attributes", "{}")).get("precision_loss")
        ]
        assert len(precision_edges) > 0


class TestVaultXorExponentiation:
    def test_xor_detected(self, vault_edges):
        """B3: ^ used instead of .pow()."""
        xor_edges = [
            e for e in vault_edges
            if e["relation"] == "unchecked_math"
            and json.loads(e.get("attributes", "{}")).get("xor_as_exponentiation")
        ]
        assert len(xor_edges) > 0


# ===========================================================================
# CHAIN DETECTION TESTS
# ===========================================================================

class TestChainDetection:
    def test_detect_soroban_from_cargo(self):
        from core.web3.base import detect_chain
        assert detect_chain("fn main() {}", "lib.rs", 'soroban-sdk = "20"') == "soroban"

    def test_detect_soroban_from_source(self):
        from core.web3.base import detect_chain
        source = '#[contract]\npub struct MyContract;\n#[contractimpl]\nimpl MyContract {}'
        assert detect_chain(source, "lib.rs") == "soroban"

    def test_detect_soroban_from_import(self):
        from core.web3.base import detect_chain
        source = 'use soroban_sdk::{contract, contractimpl};'
        assert detect_chain(source, "lib.rs") == "soroban"

    def test_anchor_takes_priority_over_soroban(self):
        from core.web3.base import detect_chain
        assert detect_chain("", "lib.rs", 'anchor-lang = "0.29"') == "anchor"

    def test_substrate_takes_priority_over_soroban(self):
        from core.web3.base import detect_chain
        assert detect_chain("", "lib.rs", 'frame-support = "4.0"') == "substrate"

    def test_generic_rust_fallback(self):
        from core.web3.base import detect_chain
        assert detect_chain("fn main() {}", "main.rs") == "rust"
