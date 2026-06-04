//! End-to-end Resolution tests for issue #40.
//!
//! After the scheduler claims a Resolution Task, the host must transform inputs
//! to EnclaveCiphertextV1, invoke Enclave Execution through the EnclaveRuntime
//! boundary, receive EnclaveExecutionOutcome, and bind it to the output Handle
//! Record so the handle transitions Pending -> Ready.
//!
//! Acceptance criteria:
//! - Pending Derived Handle with ready inputs resolves to Ready through the
//!   full claim -> transform -> execute -> materialize path.
//! - The Ready Handle State includes SystemCiphertextV1 and MaterializationReceipt.
//! - The Internal Coordinator API returns Ready for the resolved handle.
//! - The claim is released after successful materialization.
//! - Select input order (predicate, when-true, when-false) is preserved into
//!   the enclave ResolutionTask.input_ciphertexts.
//! - No plaintext Private Value appears in HandleStateView::Ready.
//! - FakeEnclaveRuntime::with_expected_attestation succeeds when the host
//!   targets the attestation material's measurement digest.

use std::cell::RefCell;

use coprocessor_ciphertext_binding::{
    self as cbinding, EnclaveAadV1, EnclaveCiphertextV1,
    SystemCiphertextV1 as EnvelopeSystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_enclave_runtime::{
    AttestationDigest, EnclaveExecutionError, EnclaveExecutionOutcome, EnclaveRuntime,
    FakeEnclaveRuntime, ResolutionTask as EnclaveResolutionTask,
};
use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleType, ImportedHandle, IngestionOutcome, OperationCode,
    SystemCiphertextV1,
};
use coprocessor_host::{CoprocessorHost, HandleStateFailureCategory, HandleStateView, HostConfig};
use coprocessor_mpc_client::{
    MpcSourceError, MpcToEnclaveResponse, MpcToEnclaveSource, ToEnclaveTransformationRequest,
};
use coprocessor_nitro_enclave::{
    EnclaveAttestationMaterial, EnclaveAttestationSource, LocalEnclaveAttestationConfig,
    LocalEnclaveAttestationSource,
};

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 7;
const DEFAULT_DOMAIN: u8 = 9;
const DEFAULT_KEY_SEED: u8 = 0xAB;
const DEFAULT_MEASUREMENT_SEED: u8 = 0x33;
const TASK_REQUEST_ID_SEED: u8 = 0x77;

#[test]
fn full_path_pending_derived_handle_resolves_to_ready() {
    let mut host = running_host();
    let a = handle_key(1);
    let b = handle_key(2);
    let a_ciphertext = well_formed_system_ciphertext(a, "suint256");
    let b_ciphertext = well_formed_system_ciphertext(b, "suint256");
    ingest_imported(
        &mut host,
        a,
        HandleType::Suint256,
        a_ciphertext.clone(),
        1,
        1,
    );
    ingest_imported(
        &mut host,
        b,
        HandleType::Suint256,
        b_ciphertext.clone(),
        1,
        2,
    );
    let derived = handle_key(10);
    ingest_derived(
        &mut host,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );

    // Claim the resolution task
    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1);
    let task = &tasks[0];
    assert_eq!(task.output_handle_key, derived);

    let attestation_source = local_attestation_source();
    let enclave_a = fake_enclave_ciphertext(a, 0xC0);
    let enclave_b = fake_enclave_ciphertext(b, 0xC1);
    let mpc_server = ProgrammableMpcServer::with_successes(vec![enclave_a, enclave_b]);

    // Execute via FakeEnclaveRuntime
    let fake_enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &fake_enclave);

    // Assert Ready state
    assert!(
        matches!(view, HandleStateView::Ready { .. }),
        "resolved handle must be Ready, got {view:?}"
    );

    // Assert get_handle_state also returns Ready
    let state_view = host.get_handle_state(&derived);
    assert!(
        matches!(state_view, HandleStateView::Ready { .. }),
        "get_handle_state must return Ready, got {state_view:?}"
    );

    let resolve_view = host.resolve_handle(coprocessor_host::RequestId([0x44; 32]), &derived);
    assert!(
        matches!(resolve_view, HandleStateView::Ready { .. }),
        "resolve_handle must return Ready, got {resolve_view:?}"
    );

    // Assert claim is released
    assert!(
        !host.is_resolution_task_claimed(&derived),
        "claim must be released after successful resolution"
    );
}

#[test]
fn select_input_order_preserved_into_enclave_resolution_task() {
    let mut host = running_host();
    let predicate = handle_key(20);
    let when_true = handle_key(21);
    let when_false = handle_key(22);
    let predicate_ct = well_formed_system_ciphertext(predicate, "sbool");
    let when_true_ct = well_formed_system_ciphertext(when_true, "suint256");
    let when_false_ct = well_formed_system_ciphertext(when_false, "suint256");

    ingest_imported(&mut host, predicate, HandleType::Sbool, predicate_ct, 1, 20);
    ingest_imported(
        &mut host,
        when_true,
        HandleType::Suint256,
        when_true_ct,
        1,
        21,
    );
    ingest_imported(
        &mut host,
        when_false,
        HandleType::Suint256,
        when_false_ct,
        1,
        22,
    );
    let select_derived = handle_key(23);
    ingest_derived(
        &mut host,
        select_derived,
        OperationCode::Select,
        HandleType::Suint256,
        vec![predicate, when_true, when_false],
        2,
        1,
    );

    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1);
    let task = &tasks[0];

    let attestation_source = local_attestation_source();
    let enc_predicate = fake_enclave_ciphertext(predicate, 0xD0);
    let enc_when_true = fake_enclave_ciphertext(when_true, 0xD1);
    let enc_when_false = fake_enclave_ciphertext(when_false, 0xD2);
    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        enc_predicate.clone(),
        enc_when_true.clone(),
        enc_when_false.clone(),
    ]);

    // Capture the enclave task via a recording enclave
    let recorder = RecordingEnclaveRuntime::new(FakeEnclaveRuntime::deterministic());

    let _ = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &recorder);

    let captured = recorder
        .captured_task()
        .expect("enclave must have been called");
    assert_eq!(
        captured.input_handle_keys,
        vec![predicate, when_true, when_false],
        "Select input_handle_keys must be in predicate, when-true, when-false order"
    );
    assert_eq!(
        captured.input_ciphertexts,
        vec![enc_predicate, enc_when_true, enc_when_false],
        "Select input_ciphertexts must be in predicate, when-true, when-false order"
    );
}

#[test]
fn ready_view_contains_no_plaintext_and_ciphertext_round_trips_encode() {
    let mut host = running_host();
    let a = handle_key(1);
    let b = handle_key(2);
    ingest_imported(
        &mut host,
        a,
        HandleType::Suint256,
        well_formed_system_ciphertext(a, "suint256"),
        1,
        1,
    );
    ingest_imported(
        &mut host,
        b,
        HandleType::Suint256,
        well_formed_system_ciphertext(b, "suint256"),
        1,
        2,
    );
    let derived = handle_key(10);
    ingest_derived(
        &mut host,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];
    let attestation_source = local_attestation_source();
    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);

    let recorder = RecordingEnclaveRuntime::new(FakeEnclaveRuntime::deterministic());
    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &recorder);

    let HandleStateView::Ready {
        system_ciphertext,
        materialization_receipt,
        ..
    } = view
    else {
        panic!("expected Ready view, got {view:?}");
    };

    // The system_ciphertext bytes must be non-empty but opaque (no plaintext)
    assert!(
        !system_ciphertext.0.is_empty(),
        "system_ciphertext must be non-empty"
    );

    // Round-trip: the stored bytes must be the encode() of the enclave-runtime
    // SystemCiphertextV1 that the FakeEnclaveRuntime produced.
    let captured = recorder.captured_task().unwrap();
    let fake_outcome = FakeEnclaveRuntime::deterministic()
        .execute(&captured)
        .expect("fake enclave must produce deterministic outcome");
    let expected_bytes = fake_outcome.system_ciphertext.encode();
    assert_eq!(
        system_ciphertext.0, expected_bytes,
        "stored SystemCiphertextV1 bytes must equal encode() of the enclave-runtime output"
    );

    // The receipt is opaque bytes (non-empty), not a structured plaintext payload
    assert!(
        !materialization_receipt.0.is_empty(),
        "materialization_receipt must be non-empty"
    );
}

#[test]
fn with_expected_attestation_succeeds_when_digest_matches_measurement() {
    let mut host = running_host();
    let a = handle_key(1);
    let b = handle_key(2);
    ingest_imported(
        &mut host,
        a,
        HandleType::Suint256,
        well_formed_system_ciphertext(a, "suint256"),
        1,
        1,
    );
    ingest_imported(
        &mut host,
        b,
        HandleType::Suint256,
        well_formed_system_ciphertext(b, "suint256"),
        1,
        2,
    );
    let derived = handle_key(10);
    ingest_derived(
        &mut host,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];
    let attestation_source = local_attestation_source();
    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);

    let attestation = attestation_source
        .current_attestation_material()
        .expect("attestation");

    // Fake with matching expected attestation digest
    let enclave = FakeEnclaveRuntime::with_expected_attestation(attestation.enclave_measurement);

    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    assert!(matches!(view, HandleStateView::Ready { .. }));
}

#[test]
fn attestation_mismatch_is_terminal_and_transitions_handle_to_failed() {
    let mut host = running_host();
    let a = handle_key(1);
    let b = handle_key(2);
    ingest_imported(
        &mut host,
        a,
        HandleType::Suint256,
        well_formed_system_ciphertext(a, "suint256"),
        1,
        1,
    );
    ingest_imported(
        &mut host,
        b,
        HandleType::Suint256,
        well_formed_system_ciphertext(b, "suint256"),
        1,
        2,
    );
    let derived = handle_key(10);
    ingest_derived(
        &mut host,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];
    let attestation_source = local_attestation_source();
    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);
    let expected = AttestationDigest([0x99; 32]);
    let enclave = FakeEnclaveRuntime::with_expected_attestation(expected);

    // AttestationVerificationFailure is a terminal enclave error.
    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    assert!(
        matches!(
            view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::EnclaveExecutionFailure,
                ..
            }
        ),
        "attestation mismatch must produce a terminal Failed view, got {view:?}"
    );
    assert!(
        matches!(
            host.get_handle_state(&derived),
            HandleStateView::Failed {
                category: HandleStateFailureCategory::EnclaveExecutionFailure,
                ..
            }
        ),
        "handle must be Failed after terminal enclave failure"
    );
    assert!(
        !host.is_resolution_task_claimed(&derived),
        "claim must be released after terminal failure"
    );
    // Failed handle has no Resolution Readiness; cannot re-claim.
    assert_eq!(host.claim_resolution_tasks().len(), 0);
}

#[test]
fn mpc_unavailable_is_retryable_keeps_handle_pending_and_allows_reclaim() {
    let mut host = running_host();
    let a = handle_key(1);
    let b = handle_key(2);
    ingest_imported(
        &mut host,
        a,
        HandleType::Suint256,
        well_formed_system_ciphertext(a, "suint256"),
        1,
        1,
    );
    ingest_imported(
        &mut host,
        b,
        HandleType::Suint256,
        well_formed_system_ciphertext(b, "suint256"),
        1,
        2,
    );
    let derived = handle_key(10);
    ingest_derived(
        &mut host,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];
    let attestation_source = local_attestation_source();
    let mpc_server = FailingMpcServer;
    let enclave = FakeEnclaveRuntime::deterministic();

    // MPC Unavailable is retryable; handle stays Pending.
    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    assert_eq!(
        view,
        HandleStateView::Pending,
        "retryable MPC unavailability must keep handle Pending"
    );
    assert_eq!(host.get_handle_state(&derived), HandleStateView::Pending);
    assert!(
        !host.is_resolution_task_claimed(&derived),
        "claim must be released after retryable failure so the scheduler can re-claim"
    );
    // Handle is still Pending so it remains ready for re-claim.
    assert_eq!(host.claim_resolution_tasks().len(), 1);
}

// ---------- issue #43: structured receipt tests ----------

#[test]
fn ready_derived_handle_exposes_structured_receipt_with_correct_fields() {
    let mut host = running_host();
    let a = handle_key(1);
    let b = handle_key(2);
    ingest_imported(
        &mut host,
        a,
        HandleType::Suint256,
        well_formed_system_ciphertext(a, "suint256"),
        1,
        1,
    );
    ingest_imported(
        &mut host,
        b,
        HandleType::Suint256,
        well_formed_system_ciphertext(b, "suint256"),
        1,
        2,
    );
    let derived = handle_key(10);
    ingest_derived(
        &mut host,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];
    let attestation_source = local_attestation_source();
    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    let HandleStateView::Ready {
        derived_receipt, ..
    } = view
    else {
        panic!("expected Ready, got {view:?}");
    };

    let receipt = derived_receipt.expect("Derived Handle must have structured receipt");
    assert_eq!(receipt.operation_code, OperationCode::Add);
    assert_eq!(receipt.output_handle_key, derived);
    assert_eq!(receipt.input_handle_keys, vec![a, b]);
    assert_eq!(
        receipt.attestation_digest,
        AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32])
    );
}

#[test]
fn select_structured_receipt_preserves_predicate_when_true_when_false_order() {
    let mut host = running_host();
    let predicate = handle_key(20);
    let when_true = handle_key(21);
    let when_false = handle_key(22);

    ingest_imported(
        &mut host,
        predicate,
        HandleType::Sbool,
        well_formed_system_ciphertext(predicate, "sbool"),
        1,
        20,
    );
    ingest_imported(
        &mut host,
        when_true,
        HandleType::Suint256,
        well_formed_system_ciphertext(when_true, "suint256"),
        1,
        21,
    );
    ingest_imported(
        &mut host,
        when_false,
        HandleType::Suint256,
        well_formed_system_ciphertext(when_false, "suint256"),
        1,
        22,
    );
    let select_derived = handle_key(23);
    ingest_derived(
        &mut host,
        select_derived,
        OperationCode::Select,
        HandleType::Suint256,
        vec![predicate, when_true, when_false],
        2,
        1,
    );

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];
    let attestation_source = local_attestation_source();
    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(predicate, 0xD0),
        fake_enclave_ciphertext(when_true, 0xD1),
        fake_enclave_ciphertext(when_false, 0xD2),
    ]);
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    let HandleStateView::Ready {
        derived_receipt, ..
    } = view
    else {
        panic!("expected Ready, got {view:?}");
    };
    let receipt = derived_receipt.expect("Select Derived Handle must have structured receipt");
    assert_eq!(receipt.operation_code, OperationCode::Select);
    assert_eq!(receipt.output_handle_key, select_derived);
    assert_eq!(
        receipt.input_handle_keys,
        vec![predicate, when_true, when_false],
        "Select receipt must preserve predicate, when-true, when-false order"
    );
}

#[test]
fn source_imported_handle_has_no_derived_receipt() {
    let mut host = running_host();
    let key = handle_key(1);
    ingest_imported(
        &mut host,
        key,
        HandleType::Suint256,
        well_formed_system_ciphertext(key, "suint256"),
        1,
        1,
    );

    let view = host.get_handle_state(&key);

    let HandleStateView::Ready {
        derived_receipt, ..
    } = view
    else {
        panic!("expected Ready, got {view:?}");
    };
    assert_eq!(
        derived_receipt, None,
        "Source (Imported) Handle must not have a derived receipt"
    );
}

#[test]
fn receipt_round_trip_decode_encode_for_each_arity() {
    // Unary: Not
    {
        let mut host = running_host();
        let a = handle_key(1);
        ingest_imported(
            &mut host,
            a,
            HandleType::Sbool,
            well_formed_system_ciphertext(a, "sbool"),
            1,
            1,
        );
        let not_derived = handle_key(5);
        ingest_derived(
            &mut host,
            not_derived,
            OperationCode::Not,
            HandleType::Sbool,
            vec![a],
            2,
            1,
        );
        let tasks = host.claim_resolution_tasks();
        let task = &tasks[0];
        let attestation_source = local_attestation_source();
        let mpc_server =
            ProgrammableMpcServer::with_successes(vec![fake_enclave_ciphertext(a, 0xE0)]);
        let enclave = FakeEnclaveRuntime::deterministic();
        let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);
        let HandleStateView::Ready {
            derived_receipt, ..
        } = view
        else {
            panic!("expected Ready");
        };
        let decoded = derived_receipt.expect("Not must have structured receipt");
        assert_eq!(decoded.operation_code, OperationCode::Not);
        assert_eq!(decoded.output_handle_key, not_derived);
        assert_eq!(decoded.input_handle_keys, vec![a]);
        assert_eq!(
            decoded.attestation_digest,
            AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32])
        );
    }

    // Binary: Add (already tested above; verify arity=2 explicitly)
    {
        let mut host = running_host();
        let a = handle_key(1);
        let b = handle_key(2);
        ingest_imported(
            &mut host,
            a,
            HandleType::Suint256,
            well_formed_system_ciphertext(a, "suint256"),
            1,
            1,
        );
        ingest_imported(
            &mut host,
            b,
            HandleType::Suint256,
            well_formed_system_ciphertext(b, "suint256"),
            1,
            2,
        );
        let derived = handle_key(10);
        ingest_derived(
            &mut host,
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            2,
            1,
        );
        let tasks = host.claim_resolution_tasks();
        let task = &tasks[0];
        let attestation_source = local_attestation_source();
        let mpc_server = ProgrammableMpcServer::with_successes(vec![
            fake_enclave_ciphertext(a, 0xC0),
            fake_enclave_ciphertext(b, 0xC1),
        ]);
        let enclave = FakeEnclaveRuntime::deterministic();
        let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);
        let HandleStateView::Ready {
            derived_receipt, ..
        } = view
        else {
            panic!("expected Ready");
        };
        let decoded = derived_receipt.expect("Add must have structured receipt");
        assert_eq!(decoded.operation_code, OperationCode::Add);
        assert_eq!(decoded.output_handle_key, derived);
        assert_eq!(decoded.input_handle_keys, vec![a, b]);
        assert_eq!(
            decoded.attestation_digest,
            AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32])
        );
    }

    {
        let mut host = running_host();
        let predicate = handle_key(20);
        let when_true = handle_key(21);
        let when_false = handle_key(22);
        ingest_imported(
            &mut host,
            predicate,
            HandleType::Sbool,
            well_formed_system_ciphertext(predicate, "sbool"),
            1,
            20,
        );
        ingest_imported(
            &mut host,
            when_true,
            HandleType::Suint256,
            well_formed_system_ciphertext(when_true, "suint256"),
            1,
            21,
        );
        ingest_imported(
            &mut host,
            when_false,
            HandleType::Suint256,
            well_formed_system_ciphertext(when_false, "suint256"),
            1,
            22,
        );
        let derived = handle_key(23);
        ingest_derived(
            &mut host,
            derived,
            OperationCode::Select,
            HandleType::Suint256,
            vec![predicate, when_true, when_false],
            2,
            1,
        );
        let tasks = host.claim_resolution_tasks();
        let task = &tasks[0];
        let attestation_source = local_attestation_source();
        let mpc_server = ProgrammableMpcServer::with_successes(vec![
            fake_enclave_ciphertext(predicate, 0xD0),
            fake_enclave_ciphertext(when_true, 0xD1),
            fake_enclave_ciphertext(when_false, 0xD2),
        ]);
        let enclave = FakeEnclaveRuntime::deterministic();
        let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);
        let HandleStateView::Ready {
            derived_receipt, ..
        } = view
        else {
            panic!("expected Ready");
        };
        let decoded = derived_receipt.expect("Select must have structured receipt");
        assert_eq!(decoded.operation_code, OperationCode::Select);
        assert_eq!(decoded.output_handle_key, derived);
        assert_eq!(
            decoded.input_handle_keys,
            vec![predicate, when_true, when_false]
        );
        assert_eq!(
            decoded.attestation_digest,
            AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32])
        );
    }
}

// ---------- fixtures ----------

fn running_host() -> CoprocessorHost {
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    host
}

fn handle_key(seed: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(DEFAULT_CHAIN),
        contract_address: ContractAddress([DEFAULT_CONTRACT_SEED; 20]),
        handle_id: HandleId([seed; 32]),
    }
}

fn event_ref(block_number: u64, log_index: u32) -> ChainEventRef {
    ChainEventRef {
        chain_id: ChainId(DEFAULT_CHAIN),
        block_number,
        block_hash: [11u8; 32],
        tx_hash: [12u8; 32],
        log_index,
    }
}

fn attestation_material() -> EnclaveAttestationMaterial {
    EnclaveAttestationMaterial {
        enclave_public_key: vec![0x44; 48],
        enclave_measurement: AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32]),
        attestation: vec![0x55; 96],
    }
}

fn local_attestation_source() -> LocalEnclaveAttestationSource {
    let material = attestation_material();
    LocalEnclaveAttestationSource::new(LocalEnclaveAttestationConfig {
        enclave_public_key: material.enclave_public_key,
        enclave_measurement: material.enclave_measurement,
        attestation: material.attestation,
    })
}

fn well_formed_system_ciphertext(key: HandleKey, type_tag: &str) -> SystemCiphertextV1 {
    let aad = SystemHandleAadV1 {
        version: 1,
        chain_id: key.chain_id.0,
        domain_id: cbinding::DomainId([DEFAULT_DOMAIN; 32]),
        handle_id: cbinding::HandleId(key.handle_id.0),
        type_tag: type_tag.to_string(),
        key_id: cbinding::KeyId([DEFAULT_KEY_SEED; 32]),
    }
    .encode();
    SystemCiphertextV1(
        EnvelopeSystemCiphertextV1 {
            version: 1,
            aad,
            wrapped_key: vec![0xAA; 32],
            ciphertext: vec![0xBB; 64],
        }
        .encode(),
    )
}

fn fake_enclave_ciphertext(key: HandleKey, payload_seed: u8) -> EnclaveCiphertextV1 {
    let aad = EnclaveAadV1 {
        version: 1,
        chain_id: key.chain_id.0,
        domain_id: cbinding::DomainId([DEFAULT_DOMAIN; 32]),
        request_id: cbinding::RequestId([TASK_REQUEST_ID_SEED; 32]),
        handle_id: cbinding::HandleId(key.handle_id.0),
        type_tag: "suint256".to_string(),
        attestation_digest: AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32]),
        key_id: cbinding::KeyId([DEFAULT_KEY_SEED; 32]),
    }
    .encode();
    EnclaveCiphertextV1 {
        version: 1,
        aad,
        wrapped_key: vec![payload_seed; 32],
        ciphertext: vec![payload_seed; 64],
    }
}

fn ingest_imported(
    host: &mut CoprocessorHost,
    handle_key: HandleKey,
    handle_type: HandleType,
    system_ciphertext: SystemCiphertextV1,
    block_number: u64,
    log_index: u32,
) {
    let outcome = host
        .handle_graph_core_mut()
        .apply_chain_event(ChainEvent::ImportedHandle(ImportedHandle {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key,
            handle_type,
            system_ciphertext,
            event_ref: event_ref(block_number, log_index),
        }));
    assert!(matches!(outcome, IngestionOutcome::Recorded(_)));
}

fn ingest_derived(
    host: &mut CoprocessorHost,
    handle_key: HandleKey,
    operation_code: OperationCode,
    output_handle_type: HandleType,
    input_handle_keys: Vec<HandleKey>,
    block_number: u64,
    log_index: u32,
) {
    let outcome =
        host.handle_graph_core_mut()
            .apply_chain_event(ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
                domain_id: DomainId([DEFAULT_DOMAIN; 32]),
                handle_key,
                operation_code,
                output_handle_type,
                input_handle_keys,
                event_ref: event_ref(block_number, log_index),
            }));
    assert!(matches!(outcome, IngestionOutcome::Recorded(_)));
}

// ---------- fake MPC source ----------

struct ProgrammableMpcServer {
    queued: RefCell<Vec<EnclaveCiphertextV1>>,
}

impl ProgrammableMpcServer {
    fn with_successes(envelopes: Vec<EnclaveCiphertextV1>) -> Self {
        Self {
            queued: RefCell::new(envelopes),
        }
    }
}

impl MpcToEnclaveSource for ProgrammableMpcServer {
    fn request_to_enclave_transformation(
        &self,
        _request: &ToEnclaveTransformationRequest,
    ) -> Result<MpcToEnclaveResponse, MpcSourceError> {
        let next = self
            .queued
            .borrow_mut()
            .drain(..1)
            .next()
            .expect("ProgrammableMpcServer ran out of queued envelopes");
        Ok(MpcToEnclaveResponse::Success(next))
    }
}

struct FailingMpcServer;

impl MpcToEnclaveSource for FailingMpcServer {
    fn request_to_enclave_transformation(
        &self,
        _request: &ToEnclaveTransformationRequest,
    ) -> Result<MpcToEnclaveResponse, MpcSourceError> {
        Err(MpcSourceError::Unavailable {
            detail: "mpc unavailable".to_string(),
        })
    }
}

// ---------- recording enclave runtime ----------

/// Wraps an inner EnclaveRuntime and captures the ResolutionTask it receives,
/// so tests can assert the host built the task with correct fields/ordering.
struct RecordingEnclaveRuntime {
    inner: FakeEnclaveRuntime,
    captured: RefCell<Option<EnclaveResolutionTask>>,
}

impl RecordingEnclaveRuntime {
    fn new(inner: FakeEnclaveRuntime) -> Self {
        Self {
            inner,
            captured: RefCell::new(None),
        }
    }

    fn captured_task(&self) -> Option<EnclaveResolutionTask> {
        self.captured.borrow().clone()
    }
}

impl EnclaveRuntime for RecordingEnclaveRuntime {
    fn execute(
        &self,
        task: &EnclaveResolutionTask,
    ) -> Result<EnclaveExecutionOutcome, EnclaveExecutionError> {
        *self.captured.borrow_mut() = Some(task.clone());
        self.inner.execute(task)
    }
}
