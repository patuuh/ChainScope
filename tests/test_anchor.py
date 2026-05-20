import json
import pytest
from pathlib import Path
from core.web3.anchor import AnchorExtractor

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def extractor():
    return AnchorExtractor()


@pytest.fixture
def vault_result(extractor):
    code = (FIXTURES / "anchor_vault.rs").read_bytes()
    return extractor.extract_from_source(code, "anchor_vault.rs")


class TestFunctionExtraction:
    def test_extracts_all_functions(self, vault_result):
        labels = {n["label"] for n in vault_result.nodes if n["type"] == "function"}
        assert "initialize" in labels
        assert "deposit" in labels
        assert "withdraw" in labels
        assert "pause" in labels
        assert "update_fee" in labels

    def test_function_visibility(self, vault_result):
        funcs = {n["label"]: n for n in vault_result.nodes if n["type"] == "function"}
        assert funcs["deposit"]["visibility"] == "public"

    def test_function_has_line_range(self, vault_result):
        funcs = {n["label"]: n for n in vault_result.nodes if n["type"] == "function"}
        dep = funcs["deposit"]
        assert dep["line_start"] > 0
        assert dep["line_end"] > dep["line_start"]

    def test_function_has_context_type(self, vault_result):
        funcs = {n["label"]: n for n in vault_result.nodes if n["type"] == "function"}
        meta = json.loads(funcs["deposit"]["metadata"])
        assert meta["context_type"] == "Deposit"


class TestAccountStructs:
    def test_extracts_accounts_context(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        assert "Initialize" in structs
        assert "Deposit" in structs
        assert "Withdraw" in structs
        assert "AdminOnly" in structs
        assert "UpdateFee" in structs

    def test_accounts_have_fields(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Deposit"]["metadata"])
        assert "vault" in meta["fields"]
        assert "user" in meta["fields"]

    def test_signer_constraints(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Deposit"]["metadata"])
        signer_constraints = [c for c in meta.get("constraints", []) if "Signer" in c]
        assert len(signer_constraints) > 0

    def test_state_account_struct(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        assert "Vault" in structs
        meta = json.loads(structs["Vault"]["metadata"])
        assert meta.get("is_account") is True
        assert "authority" in meta["fields"]
        assert "total_deposits" in meta["fields"]

    def test_fee_config_state_struct(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        assert "FeeConfig" in structs
        meta = json.loads(structs["FeeConfig"]["metadata"])
        assert meta.get("is_account") is True
        assert "fee" in meta["fields"]
        assert "base_fee" in meta["fields"]


class TestCPIDetection:
    def test_cpi_transfer_detected(self, vault_result):
        sinks = []
        for n in vault_result.nodes:
            meta = json.loads(n.get("metadata", "{}"))
            if meta.get("is_sink"):
                sinks.append(meta)
        types = {s.get("sink_type") for s in sinks}
        assert "fund_transfer" in types

    def test_deposit_has_cpi_call(self, vault_result):
        calls = [e for e in vault_result.edges if e["relation"] == "calls"]
        deposit_calls = [e for e in calls if "deposit" in e["source"]]
        assert len(deposit_calls) > 0

    def test_sink_type_classifications(self, vault_result):
        """Verify the CPI sink type classification map is correct."""
        from core.web3.anchor import CPI_SINK_TYPES
        assert CPI_SINK_TYPES["transfer"] == "fund_transfer"
        assert CPI_SINK_TYPES["transfer_checked"] == "fund_transfer"
        assert CPI_SINK_TYPES["mint_to"] == "fund_creation"
        assert CPI_SINK_TYPES["mint_to_checked"] == "fund_creation"
        assert CPI_SINK_TYPES["burn"] == "fund_destruction"
        assert CPI_SINK_TYPES["burn_checked"] == "fund_destruction"
        assert CPI_SINK_TYPES["close_account"] == "fund_destruction"
        assert CPI_SINK_TYPES["approve"] == "token_authority"
        assert CPI_SINK_TYPES["revoke"] == "token_authority"
        assert CPI_SINK_TYPES["freeze_account"] == "token_authority"
        assert CPI_SINK_TYPES["thaw_account"] == "token_authority"

    def test_close_account_creates_sink(self, vault_result):
        """AdminOnly has close = authority, which should create a fund_destruction sink."""
        sinks = []
        for n in vault_result.nodes:
            meta = json.loads(n.get("metadata", "{}"))
            if meta.get("is_sink") and meta.get("close_target"):
                sinks.append(meta)
        assert len(sinks) >= 1
        assert sinks[0]["sink_type"] == "fund_destruction"
        assert sinks[0]["close_target"] == "authority"


class TestStateMachine:
    def test_state_transitions(self, vault_result):
        assert len(vault_result.transitions) > 0
        entities = {t["entity"] for t in vault_result.transitions}
        assert "VaultState" in entities

    def test_pause_transition(self, vault_result):
        pause_trans = [t for t in vault_result.transitions
                       if "pause" in t["function_id"]]
        assert len(pause_trans) >= 1
        assert pause_trans[0]["to_state"] == "Paused"
        assert pause_trans[0]["from_state"] == "Active"


class TestProgramMetadata:
    def test_program_in_metadata(self, vault_result):
        funcs = [n for n in vault_result.nodes if n["type"] == "function"]
        for f in funcs:
            meta = json.loads(f.get("metadata", "{}"))
            assert "program" in meta
            assert meta["program"] == "vault"


class TestPDASeeds:
    def test_initialize_has_pda_seeds(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Initialize"]["metadata"])
        assert "pda_fields" in meta
        assert "vault" in meta["pda_fields"]
        pda = meta["pda_fields"]["vault"]
        assert len(pda["pda_seeds"]) == 2
        assert 'b"vault"' in pda["pda_seeds"][0]
        assert "authority" in pda["pda_seeds"][1]
        assert pda["has_bump"] is True

    def test_deposit_has_no_pda_seeds(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Deposit"]["metadata"])
        assert "pda_fields" not in meta


class TestAccessControls:
    def test_withdraw_has_one_authority(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Withdraw"]["metadata"])
        assert "access_controls" in meta
        assert "has_one:authority" in meta["access_controls"]

    def test_admin_only_has_one_authority(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["AdminOnly"]["metadata"])
        assert "access_controls" in meta
        assert "has_one:authority" in meta["access_controls"]

    def test_guards_edge_created(self, vault_result):
        guards = [e for e in vault_result.edges if e["relation"] == "guards"]
        assert len(guards) >= 1
        # AdminOnly guards the pause function
        admin_guards = [e for e in guards if "AdminOnly" in e["source"]]
        assert len(admin_guards) >= 1
        assert "pause" in admin_guards[0]["target"]


class TestCloseConstraint:
    def test_admin_only_close_target(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["AdminOnly"]["metadata"])
        assert "close_targets" in meta
        assert meta["close_targets"]["vault"] == "authority"

    def test_close_creates_sink_edge(self, vault_result):
        """The pause function (using AdminOnly context) should have a close sink edge."""
        close_edges = []
        for e in vault_result.edges:
            attrs = json.loads(e.get("attributes", "{}"))
            if attrs.get("close"):
                close_edges.append(e)
        assert len(close_edges) >= 1
        assert "pause" in close_edges[0]["source"]


class TestEventEmission:
    def test_emit_creates_edge(self, vault_result):
        emit_edges = [e for e in vault_result.edges if e["relation"] == "emits_event"]
        assert len(emit_edges) >= 1

    def test_deposit_emits_deposit_event(self, vault_result):
        emit_edges = [e for e in vault_result.edges if e["relation"] == "emits_event"]
        deposit_emits = [e for e in emit_edges if "deposit" in e["source"]]
        assert len(deposit_emits) >= 1
        attrs = json.loads(deposit_emits[0]["attributes"])
        assert attrs["event"] == "DepositEvent"


class TestRequireMacroVariants:
    def test_require_macros_set(self):
        from core.web3.anchor import REQUIRE_MACROS
        assert "require" in REQUIRE_MACROS
        assert "require_keys_eq" in REQUIRE_MACROS
        assert "require_gt" in REQUIRE_MACROS
        assert "require_gte" in REQUIRE_MACROS
        assert "require_eq" in REQUIRE_MACROS
        assert "require_neq" in REQUIRE_MACROS
        assert "require_keys_neq" in REQUIRE_MACROS
        # The dead "require!" should NOT be present
        assert "require!" not in REQUIRE_MACROS

    def test_expanded_cpi_patterns(self):
        from core.web3.anchor import CPI_TRANSFER_PATTERNS
        for p in ["mint_to", "burn", "approve", "revoke", "freeze_account",
                   "thaw_account", "close_account", "transfer_checked",
                   "mint_to_checked", "burn_checked"]:
            assert p in CPI_TRANSFER_PATTERNS


# ── New tests for CRITICAL and HIGH fixes ──────────────────────────────


class TestInitIfNeeded:
    """C1: Detect init_if_needed reinitialization attack."""

    def test_init_if_needed_flagged_in_metadata(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["UpdateFee"]["metadata"])
        assert meta.get("init_if_needed") is True

    def test_init_if_needed_field_metadata(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["UpdateFee"]["metadata"])
        fm = meta.get("field_metadata", {})
        assert fm["config"]["init_if_needed"] is True

    def test_init_if_needed_warning(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["UpdateFee"]["metadata"])
        warnings = meta.get("warnings", [])
        assert any("init_if_needed" in w and "reinitialization" in w for w in warnings)

    def test_initialize_not_flagged_init_if_needed(self, vault_result):
        """Regular init should NOT be flagged as init_if_needed."""
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Initialize"]["metadata"])
        assert meta.get("init_if_needed") is not True


class TestOwnerCheck:
    """C2: Owner check detection."""

    def test_owner_check_parsed(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["UpdateFee"]["metadata"])
        fm = meta.get("field_metadata", {})
        assert fm["fee_destination"]["owner_check"] == "token_program"

    def test_unchecked_account_flagged(self, vault_result):
        """AccountInfo without owner check should be flagged."""
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Deposit"]["metadata"])
        fm = meta.get("field_metadata", {})
        assert fm["vault_token"]["unchecked_account"] is True

    def test_unchecked_account_type_in_updatefee(self, vault_result):
        """UncheckedAccount fields should be flagged."""
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["UpdateFee"]["metadata"])
        fm = meta.get("field_metadata", {})
        assert fm["oracle"]["unchecked_account"] is True


class TestTypeCosplay:
    """C3: Type cosplay detection."""

    def test_account_info_cosplay_risk(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Deposit"]["metadata"])
        fm = meta.get("field_metadata", {})
        assert fm["vault_token"]["type_cosplay_risk"] is True

    def test_unchecked_account_cosplay_risk(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["UpdateFee"]["metadata"])
        fm = meta.get("field_metadata", {})
        assert fm["oracle"]["type_cosplay_risk"] is True

    def test_typed_account_no_cosplay_risk(self, vault_result):
        """Account<'info, Vault> should NOT have cosplay risk."""
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Deposit"]["metadata"])
        fm = meta.get("field_metadata", {})
        # vault is Account<'info, Vault> — should not be flagged
        vault_fm = fm.get("vault", {})
        assert vault_fm.get("type_cosplay_risk") is not True


class TestUncheckedArithmetic:
    """H1: Arithmetic overflow flagging."""

    def test_deposit_compound_arithmetic_flagged(self, vault_result):
        """vault.total_deposits += amount should be flagged."""
        arith_edges = [e for e in vault_result.edges if e["relation"] == "unchecked_math"]
        deposit_arith = [e for e in arith_edges if "deposit" in e["source"]]
        assert len(deposit_arith) >= 1
        attrs = json.loads(deposit_arith[0]["attributes"])
        assert attrs["unchecked_arithmetic"] is True

    def test_withdraw_compound_arithmetic_flagged(self, vault_result):
        """vault.total_deposits -= amount should be flagged."""
        arith_edges = [e for e in vault_result.edges if e["relation"] == "unchecked_math"]
        withdraw_arith = [e for e in arith_edges if "withdraw" in e["source"]]
        assert len(withdraw_arith) >= 1

    def test_update_fee_binary_arithmetic_flagged(self, vault_result):
        """config.base_fee + new_fee should be flagged."""
        arith_edges = [e for e in vault_result.edges if e["relation"] == "unchecked_math"]
        fee_arith = [e for e in arith_edges if "update_fee" in e["source"]]
        assert len(fee_arith) >= 1
        attrs = json.loads(fee_arith[0]["attributes"])
        assert attrs["unchecked_arithmetic"] is True


class TestConstraintExprs:
    """H2: Extract constraint = <expr> clauses."""

    def test_constraint_expr_extracted(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["UpdateFee"]["metadata"])
        assert "constraint_exprs" in meta
        exprs = meta["constraint_exprs"]
        assert any("authority.key()" in e and "config.admin" in e for e in exprs)


class TestMutConstraint:
    """H3: Track mut constraint."""

    def test_mut_detected_on_vault(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Deposit"]["metadata"])
        fm = meta.get("field_metadata", {})
        assert fm["vault"]["mutable"] is True

    def test_mut_detected_on_user(self, vault_result):
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Deposit"]["metadata"])
        fm = meta.get("field_metadata", {})
        assert fm["user"]["mutable"] is True

    def test_non_mut_field_not_flagged(self, vault_result):
        """system_program has no mut, should not be flagged."""
        structs = {n["label"]: n for n in vault_result.nodes if n["type"] == "struct"}
        meta = json.loads(structs["Deposit"]["metadata"])
        fm = meta.get("field_metadata", {})
        sp = fm.get("system_program", {})
        assert sp.get("mutable") is not True
