"""Automated pytest suite for AQMP Paper #2:
  1. Stateless Post-Quantum Threshold / MPC Signing (t-of-n + cold backup restore)
  2. Knowledge-Asymmetry Frozen UTXO Rescue (580 B + 96 B DCL + Fukuda window)
"""

from __future__ import annotations

import hashlib
import os
import pytest

from aqmp_sdk.mpc.stateless_pq_mpc import (
    P2MRKeyRegistryBinding,
    StatelessPQThresholdCommittee,
    simulate_cold_backup_restore,
)
from aqmp_sdk.rescue.utxo_rescue import (
    BIP32LegacyAccount,
    KnowledgeAsymmetryRescueEngine,
    RESCUE_PROOF_BYTES,
    build_snapshot_merkle_tree,
)


@pytest.mark.parametrize(
    ("threshold", "total_signers", "active_set"),
    [
        (2, 3, [1, 3]),
        (3, 5, [1, 2, 5]),
        (5, 7, [1, 2, 4, 6, 7]),
    ],
)
def test_stateless_pq_threshold_t_of_n_soundness(
    threshold: int, total_signers: int, active_set: list[int]
):
    committee = StatelessPQThresholdCommittee(
        threshold=threshold, total_signers=total_signers
    )
    msg = b"AQMP Paper #2 treasury transfer"
    epoch_salt = b"epoch-2026-q4"
    binding = P2MRKeyRegistryBinding(
        p2mr_merkle_root=hashlib.sha3_256(b"BIP360_P2MR_LEAF").digest(),
        key_registry_idx=105,
    )

    sig = committee.sign_threshold(msg, active_set, epoch_salt, binding)
    assert sig.threshold == threshold
    assert sig.total_signers == total_signers
    assert binding.block_footprint_plonky3(250) == 11_300

    assert StatelessPQThresholdCommittee.verify_threshold_signature(
        committee.matrix_seed, committee.group_public_key_b, msg, sig
    )

    # Wrong message must fail
    assert not StatelessPQThresholdCommittee.verify_threshold_signature(
        committee.matrix_seed, committee.group_public_key_b, b"tampered-msg", sig
    )

    # Insufficient subset (< t) cannot sign
    if threshold > 1:
        with pytest.raises(ValueError):
            committee.sign_threshold(msg, active_set[:-1], epoch_salt, binding)

    # Tampered aggregate z must fail
    bad_z = list(sig.aggregate_z)
    bad_z[0] = (bad_z[0] + 1) % 8_380_417
    tampered_sig = type(sig)(
        active_set=sig.active_set,
        threshold=sig.threshold,
        total_signers=sig.total_signers,
        aggregate_w=sig.aggregate_w,
        aggregate_z=tuple(bad_z),
        challenge_c=sig.challenge_c,
        message_digest=sig.message_digest,
        epoch_salt=sig.epoch_salt,
        binding=sig.binding,
        aggregate_time_ms=sig.aggregate_time_ms,
    )
    assert not StatelessPQThresholdCommittee.verify_threshold_signature(
        committee.matrix_seed, committee.group_public_key_b, msg, tampered_sig
    )


def test_stateless_mpc_backup_restore_state_wipe_safety():
    committee = StatelessPQThresholdCommittee(threshold=3, total_signers=5)
    active_set = [1, 3, 4]
    msg_a = b"custody-withdrawal-A"
    msg_b = b"custody-withdrawal-B"
    epoch_salt = b"az-east-1-cold-restore"
    binding = P2MRKeyRegistryBinding(
        p2mr_merkle_root=b"\x33" * 32,
        key_registry_idx=77,
    )

    sig_a = committee.sign_threshold(msg_a, active_set, epoch_salt, binding)
    sig_b = committee.sign_threshold(msg_b, active_set, epoch_salt, binding)

    report = simulate_cold_backup_restore(
        share=committee.shares[3],
        message_a=msg_a,
        message_b=msg_b,
        active_set=active_set,
        aggregate_w_a=sig_a.aggregate_w,
        aggregate_w_b=sig_b.aggregate_w,
        epoch_salt=epoch_salt,
        binding=binding,
    )
    assert report["deterministic_replay_identical"] is True
    assert report["distinct_message_fresh_nonce"] is True
    assert report["no_mutable_counter_in_backup"] is True


def test_knowledge_asymmetry_utxo_rescue_and_front_running_defense():
    owner = BIP32LegacyAccount.from_master_seed(b"owner-seed-1999", derivation_index=42)
    decoy = BIP32LegacyAccount.from_master_seed(b"decoy-seed-2000", derivation_index=42)
    utxo_id = hashlib.sha3_256(b"btc-frozen-txid:0").digest()

    rec_owner = KnowledgeAsymmetryRescueEngine.build_frozen_utxo_record(
        owner, utxo_id=utxo_id, satoshis=500_000_000, freeze_height=915_000
    )
    rec_decoy = KnowledgeAsymmetryRescueEngine.build_frozen_utxo_record(
        decoy, utxo_id=hashlib.sha3_256(b"other-txid:1").digest(), satoshis=10_000, freeze_height=915_000
    )
    root, levels = build_snapshot_merkle_tree([rec_owner, rec_decoy])
    engine = KnowledgeAsymmetryRescueEngine(snapshot_utxo_root=root, hash_alg="sha256")

    pqc_dest = hashlib.sha3_256(b"new-quantum-safe-vault").digest()
    x0 = os.urandom(32)
    x1 = os.urandom(32)
    anchor_y0 = engine.dcl_verifier.create_anchor(x0)

    bundle = engine.create_rescue_bundle(
        account=owner,
        utxo_record=rec_owner,
        merkle_levels=levels,
        leaf_index=0,
        pqc_dest_address=pqc_dest,
        dcl_secret_x=x0,
        dcl_next_secret_x_prime=x1,
    )
    assert bundle.rescue_witness_bytes == RESCUE_PROOF_BYTES == 580
    assert bundle.dcl_cycle_bytes == 96
    assert bundle.total_on_chain_bytes == 676

    # Raw ECDSA keys / chain code MUST NOT appear in plaintext inside serialized witness
    witness_blob = bundle.serialized_witness_blob()
    assert owner.parent_pubkey_compressed not in witness_blob
    assert owner.child_pubkey_compressed not in witness_blob
    assert owner.parent_chain_code not in witness_blob

    # 1. Early reveal violating Fukuda window (eps=0.50 -> Delta*=8, delta_eff=7) fails
    early = engine.verify_rescue_bundle(bundle, anchor_y=anchor_y0, delta_eff=7, epsilon=0.50)
    assert early.valid is False

    # 2. Mempool destination hijacking attempt fails Dual-Commit XOR and PoK binding
    attacker_dest = hashlib.sha3_256(b"attacker-stolen-vault").digest()
    hijacked = type(bundle)(
        utxo_record=bundle.utxo_record,
        pqc_dest_address=attacker_dest,
        chaincode_commitment=bundle.chaincode_commitment,
        derivation_binding=bundle.derivation_binding,
        merkle_inclusion_proof=bundle.merkle_inclusion_proof,
        pqc_destination_nizk=bundle.pqc_destination_nizk,
        dcl_commit_tx1=bundle.dcl_commit_tx1,
        dcl_reveal_tx2=bundle.dcl_reveal_tx2,
        rescue_message=bundle.rescue_message,
    )
    hijack_res = engine.verify_rescue_bundle(hijacked, anchor_y=anchor_y0, delta_eff=8, epsilon=0.50)
    assert hijack_res.valid is False
    assert hijack_res.knowledge_binding_valid is False

    # 3. Valid rescue at delta_eff=8 >= Delta*(0.50)=8 succeeds and rotates anchor
    ok = engine.verify_rescue_bundle(bundle, anchor_y=anchor_y0, delta_eff=8, epsilon=0.50)
    assert ok.valid is True
    assert ok.merkle_valid is True
    assert ok.knowledge_binding_valid is True
    assert ok.xor_commit_valid is True
    assert ok.delta_star_blocks == 8
    assert ok.rotated_anchor == engine.dcl_verifier.create_anchor(x1)

    # 4. Replay of consumed DCL preimage x0 fails
    replay = engine.verify_rescue_bundle(bundle, anchor_y=anchor_y0, delta_eff=8, epsilon=0.50)
    assert replay.valid is False
