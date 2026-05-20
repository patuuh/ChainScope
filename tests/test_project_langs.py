import json

from core.indexer import Indexer
from core.web3.project_langs import (
    ClarityExtractor,
    MoveExtractor,
    PythonExtractor,
    ProtoExtractor,
    TonExtractor,
    TypeScriptExtractor,
    VyperExtractor,
    XdrExtractor,
)


def _functions(result):
    return [n for n in result.nodes if n["type"] == "function"]


def _meta_for(result, label):
    for node in _functions(result):
        if node["label"] == label:
            return json.loads(node["metadata"] or "{}")
    raise AssertionError(f"function not found: {label}")


def test_move_extractor_tracks_transfer_and_state():
    src = b"""
module bridge::vault;

public struct Vault has key { value: u64 }

public entry fun deposit(account: &signer, ctx: &mut TxContext) {
    assert!(tx_context::sender(ctx) == signer::address_of(account), 1);
    move_to<Vault>(account, Vault { value: 1 });
    transfer::public_transfer(object, tx_context::sender(ctx));
}
"""
    result = MoveExtractor().extract_from_source(src, "sources/vault.move")
    labels = {n["label"] for n in result.nodes}
    assert "deposit" in labels
    meta = _meta_for(result, "deposit")
    assert meta["language"] == "move"
    assert meta["move_entry"] is True
    assert "transfer_sinks" in meta
    assert any(e["relation"] == "writes_state" for e in result.edges)


def test_clarity_extractor_tracks_public_writes_and_transfer():
    src = b"""
(define-data-var configured bool false)

(define-public (set-config (new-value bool))
    (begin
        (asserts! (is-eq tx-sender contract-owner) (err u1))
        (var-set configured new-value)
        (stx-transfer? u1 tx-sender contract-caller)))
"""
    result = ClarityExtractor().extract_from_source(src, "pox.clar")
    meta = _meta_for(result, "set-config")
    assert meta["language"] == "clarity"
    assert "stx-transfer?" in meta["transfer_sinks"]
    assert any(e["relation"] == "guards" for e in result.edges)
    assert any(e["relation"] == "writes_state" for e in result.edges)


def test_vyper_extractor_flags_unchecked_raw_call():
    src = b"""
sealables: DynArray[address, 8]
expiry_timestamp: uint256

@external
def seal(target: address):
    assert msg.sender == self.sealables[0]
    self.expiry_timestamp = block.timestamp
    raw_call(target, b"", max_outsize=32, revert_on_failure=False)
"""
    result = VyperExtractor().extract_from_source(src, "GateSeal.vy")
    meta = _meta_for(result, "seal")
    assert meta["language"] == "vyper"
    assert "unchecked_calls" in meta
    assert "timestamp_dependence" in meta
    assert any(e["relation"] == "writes_state" for e in result.edges)


def test_typescript_extractor_flags_transaction_and_key_material():
    src = b"""
export const depositStake = async (connection, secretKey) => {
  const payer = Keypair.fromSecretKey(secretKey);
  await sendAndConfirmTransaction(connection, tx, [payer]);
}
"""
    result = TypeScriptExtractor().extract_from_source(src, "src/depositStake.ts")
    meta = _meta_for(result, "depositStake")
    assert meta["language"] == "typescript"
    assert meta["private_key_material"] is True
    assert "cross_contract_calls" in meta
    assert any(e["relation"] == "writes_state" for e in result.edges)


def test_typescript_extractor_keeps_later_top_level_functions_unscoped():
    src = b"""
export class WalletClient {
  send() {
    return 1;
  }
}

export function afterClass() {
  return 2;
}
"""
    result = TypeScriptExtractor().extract_from_source(src, "src/client.ts")
    node_ids = {n["id"] for n in result.nodes}
    assert "src/client.ts::WalletClient.send" in node_ids
    assert "src/client.ts::afterClass" in node_ids
    assert "src/client.ts::WalletClient.afterClass" not in node_ids


def test_python_extractor_flags_command_deserialization_and_sql():
    src = b"""
import os
import pickle

def load_and_run(payload, cmd, cur):
    obj = pickle.loads(payload)
    os.system(cmd)
    cur.execute(f"select * from users where id = {obj}")
    return obj
"""
    result = PythonExtractor().extract_from_source(src, "oracle/tasks.py")
    meta = _meta_for(result, "load_and_run")
    assert meta["language"] == "python"
    assert "command_injection_risk" in meta
    assert "deserialization_sinks" in meta
    assert "sql_injection_risk" in meta


def test_ton_extractor_tracks_recv_internal_storage_and_sends():
    src = b"""
() save_data(int x) impure inline {
    set_data(begin_cell().store_uint(x, 32).end_cell());
}

() recv_internal(int balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    accept_message();
    int x = in_msg_body~load_uint(32);
    save_data(x);
    send_raw_message(in_msg_full, 64);
}
"""
    result = TonExtractor().extract_from_source(src, "multisig.func")
    meta = _meta_for(result, "recv_internal")
    assert meta["language"] == "ton"
    assert meta["ton_accept_message"] is True
    assert "send_raw_message" in meta["transfer_sinks"]
    assert any(e["relation"] == "writes_state" for e in result.edges)


def test_tact_extractor_tracks_receive_methods_and_bounce():
    src = b"""
message Ping { value: Int; }
contract Demo {
    counter: Int;
    receive(msg: Ping) {
        self.counter = self.counter + msg.value;
        send(SendParameters{to: sender(), value: 0});
    }
    bounced(msg: Slice) { }
}
"""
    result = TonExtractor().extract_from_source(src, "demo.tact")
    meta = _meta_for(result, "receive_Ping")
    assert meta["language"] == "ton"
    assert "send" in meta["transfer_sinks"]
    assert any(e["relation"] == "writes_state" for e in result.edges)
    bounce_meta = _meta_for(result, "bounced")
    assert bounce_meta["ignored_bounce"] is True


def test_proto_extractor_profiles_rpc_boundaries():
    src = b"""
syntax = "proto3";
package bam_api;

message AuthChallengeRequest {}
message AuthChallengeResponse {}

service BamNodeApi {
  rpc GetAuthChallenge(AuthChallengeRequest) returns (AuthChallengeResponse) {}
  rpc InitSchedulerStream(stream SchedulerMessage) returns (stream SchedulerResponse) {}
}
"""
    result = ProtoExtractor().extract_from_source(src, "bam_api.proto")
    auth_meta = _meta_for(result, "GetAuthChallenge")
    stream_meta = _meta_for(result, "InitSchedulerStream")
    assert auth_meta["auth_boundary"] is True
    assert stream_meta["streaming_rpc"] is True


def test_xdr_extractor_tracks_protocol_state_and_auth_schema():
    src = b"""
namespace stellar {

enum AuthResultCode {
    AUTH_OK = 0,
    AUTH_BAD_SIGNATURE = -1
};

struct LedgerEntry {
    AccountID accountID;
    uint64 balance;
};

union TransactionEnvelope switch (EnvelopeType type) {
case ENVELOPE_TYPE_TX:
    Transaction tx;
};

}
"""
    result = XdrExtractor().extract_from_source(src, "Stellar-transaction.x")
    auth_meta = _meta_for(result, "AuthResultCode")
    ledger_meta = _meta_for(result, "LedgerEntry")
    tx_meta = _meta_for(result, "TransactionEnvelope")
    assert auth_meta["auth_boundary"] is True
    assert ledger_meta["protocol_state_schema"] is True
    assert tx_meta["variant_switch"] is True
    assert any(e["relation"] == "reads_state" for e in result.edges)


def test_repository_profile_recommends_supported_targets(tmp_path):
    from core.project_profile import profile_repository

    repo = tmp_path / "workspace"
    move_repo = repo / "move-proj"
    ton_repo = repo / "ton-proj"
    move_repo.mkdir(parents=True)
    ton_repo.mkdir(parents=True)
    (move_repo / "Move.toml").write_text("[package]\n", encoding="utf-8")
    (move_repo / "mod.move").write_text("module a::m; public fun f() {}", encoding="utf-8")
    nested = repo / "umbrella" / "packages" / "contract"
    nested.mkdir(parents=True)
    (nested / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (nested / "Vault.sol").write_text("pragma solidity ^0.8.0; contract Vault {}", encoding="utf-8")
    (nested / "Vault.t.sol").write_text("pragma solidity ^0.8.0; contract VaultTest {}", encoding="utf-8")
    (nested / "Vault.s.sol").write_text("pragma solidity ^0.8.0; contract VaultScript {}", encoding="utf-8")
    (ton_repo / "main.fc").write_text("() recv_internal() impure {}", encoding="utf-8")
    (repo / "scripts").mkdir()
    (repo / "scripts" / "deploy.ts").write_text("export function deploy() {}", encoding="utf-8")
    (repo / "service.pb.go").write_text("package pb\n", encoding="utf-8")
    (repo / "test_keys.py").write_text("def test_keys(): pass\n", encoding="utf-8")

    profile = profile_repository(str(repo), top=5)
    assert profile["languages"]["move"] == 1
    assert profile["languages"]["ton"] == 1
    assert profile["languages"]["solidity"] == 1
    assert "go" not in profile["languages"]
    assert "python" not in profile["languages"]
    assert profile["source_files_detected"] == 7
    assert profile["source_files_supported"] == 3
    assert profile["source_files_skipped_as_noise"] == 4
    assert profile["skipped_source_reasons"]["foundry_test_or_script"] == 2
    assert profile["skipped_source_reasons"]["generated_file"] == 1
    assert profile["skipped_source_reasons"]["test_file"] == 1
    assert profile["frameworks"]["foundry"] == 1
    assert profile["frameworks"]["evm"] == 1
    assert profile["frameworks"]["move-package"] == 1
    assert profile["frameworks"]["ton"] == 1
    assert profile["package_roots_detected"] >= 2
    assert any("move-proj" in item["path"] and "move" in item["frameworks"] for item in profile["recommended_build_targets"])
    assert any("umbrella/packages/contract" in item["path"] and "foundry" in item["frameworks"] for item in profile["recommended_build_targets"])
    assert "move" in profile["recommended_by_language"]
    assert any(item["language"] == "solidity" for item in profile["risk_first_targets"])
    assert profile["build_plan"]
    assert all(item["tool_call"]["tool"] == "cs_build" for item in profile["build_plan"])
    assert profile["research_signal_dirs"]["scripts"] == 1

    bounty_profile = profile_repository(str(repo), top=5, strategy="bounty")
    assert bounty_profile["ranking_strategy"] == "bounty"
    assert bounty_profile["recommended_build_targets"][0]["dominant"] == "solidity"
    assert "risk-first" in bounty_profile["recommended_build_targets"][0]["selection_reason"]
    assert bounty_profile["workspace_mode"] is True
    assert bounty_profile["workspace_clusters"]
    assert any(cluster["cluster"] == "umbrella" for cluster in bounty_profile["workspace_clusters"])

    research_profile = profile_repository(str(repo), top=5, include_research=True)
    assert research_profile["include_research"] is True
    assert "scripts" in research_profile["research_mode_dirs"]
    assert research_profile["source_files_detected"] == 8
    assert research_profile["source_files_supported"] == 5
    assert research_profile["skipped_source_reasons"]["foundry_test_or_script"] == 1
    assert any(item["tool_call"]["include_research"] is True for item in research_profile["build_plan"])


def test_indexer_detects_project_specific_languages(tmp_path, tmp_db):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.move").write_text("module a::m; public fun f() {}", encoding="utf-8")
    (repo / "pox.clar").write_text("(define-public (f) (ok true))", encoding="utf-8")
    (repo / "c.vy").write_text("@external\ndef f():\n    pass\n", encoding="utf-8")
    (repo / "client.ts").write_text("export function f() { return 1; }", encoding="utf-8")
    (repo / "job.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (repo / "main.fc").write_text("() recv_internal() impure {}", encoding="utf-8")
    (repo / "api.proto").write_text("service S { rpc F (A) returns (B) {} }", encoding="utf-8")
    (repo / "Stellar-ledger.x").write_text("struct LedgerEntry { uint64 balance; };", encoding="utf-8")

    indexer = Indexer(str(repo))
    assert {"move", "clarity", "vyper", "typescript", "python", "ton", "proto", "xdr"} <= indexer.all_chains

    stats = indexer.index(tmp_db)
    assert stats["files_indexed"] == 8
    assert stats["nodes"] >= 5
