//! Resolution failure and retry semantics tests for issue #41.
//!
//! Acceptance criteria:
//! - MpcTransformationFailure, EnclaveExecutionFailure, and MaterializationFailure
//!   are represented as Failed categories for terminal errors.
//! - Transient MPC or Enclave backend availability failures keep the handle
//!   Pending while retry budget remains and do not create a duplicate concurrent
//!   Resolution Task.
//! - A subsequent tick after a retryable failure can re-claim the handle, and the
//!   attempt budget decrements.
//! - Terminal MPC transformation failure transitions to Failed(MpcTransformationFailure).
//! - Terminal Enclave execution failure transitions to Failed(EnclaveExecutionFailure).
//! - Materialization failure transitions to Failed(MaterializationFailure).
//! - Retry budget exhaustion converts repeated retryable failures into terminal Failed.
//! - A Failed Derived Handle survives persistence and restore_from_persistence.
//! - Reason strings contain only handle ids/counts/category — never ciphertext,
//!   keys, or plaintext.

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
    FailureReason, HandleGraphCore, HandleId, HandleKey, HandleState, HandleType, ImportedHandle,
    InMemoryHandlePersistence, IngestionOutcome, MaterializationReceipt, OperationCode,
    SystemCiphertextV1,
};
use coprocessor_host::{
    CoprocessorHost, HandleStateFailureCategory, HandleStateView, HostConfig, RetryPolicy,
};
use coprocessor_mpc_client::{
    MpcSourceError, MpcToEnclaveResponse, MpcToEnclaveSource, ToEnclaveTransformationRequest,
};
use coprocessor_nitro_enclave::{LocalEnclaveAttestationConfig, LocalEnclaveAttestationSource};

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 7;
const DEFAULT_DOMAIN: u8 = 9;
const DEFAULT_KEY_SEED: u8 = 0xAB;
const DEFAULT_MEASUREMENT_SEED: u8 = 0x33;
const TASK_REQUEST_ID_SEED: u8 = 0x77;

// ---------- Retryable MPC: keeps Pending, allows re-claim ----------

#[test]
fn retryable_mpc_unavailability_keeps_handle_pending_and_allows_reclaim() {
    let mut host = running_host_with_retries(3);
    let (a, b, derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1);
    let task = tasks[0].clone();

    let attestation_source = local_attestation_source();
    let mpc_server = UnavailableMpcServer;
    let enclave = FakeEnclaveRuntime::deterministic();

    // First attempt: retryable, budget = 2 remaining.
    let view = host.resolve_claimed_task(&task, &mpc_server, &attestation_source, &enclave);
    assert_eq!(view, HandleStateView::Pending, "retryable failure must keep handle Pending");
    assert_eq!(host.get_handle_state(&derived), HandleStateView::Pending);

    // Claim released, handle still Pending → re-claim allowed.
    assert!(!host.is_resolution_task_claimed(&derived));
    let reclaimed = host.claim_resolution_tasks();
    assert_eq!(reclaimed.len(), 1, "re-claim must succeed after retryable failure");
    assert_eq!(reclaimed[0].output_handle_key, derived);

    let _ = a;
    let _ = b;
}

#[test]
fn retryable_mpc_unavailability_does_not_produce_duplicate_concurrent_task() {
    let mut host = running_host_with_retries(3);
    let (a, b, derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    let task = tasks[0].clone();

    let attestation_source = local_attestation_source();
    let mpc_server = UnavailableMpcServer;
    let enclave = FakeEnclaveRuntime::deterministic();

    let _ = host.resolve_claimed_task(&task, &mpc_server, &attestation_source, &enclave);

    // A second claim tick should yield exactly one task — not two.
    let second_claim = host.claim_resolution_tasks();
    assert_eq!(second_claim.len(), 1);

    // No concurrent claim: only one active claim at a time.
    assert_eq!(host.claimed_resolution_task_count(), 1);

    let _ = a;
    let _ = b;
    let _ = derived;
}

// ---------- Retryable Enclave: keeps Pending ----------

#[test]
fn retryable_enclave_backend_unavailable_keeps_handle_pending_and_allows_reclaim() {
    let mut host = running_host_with_retries(3);
    let (a, b, derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    let task = tasks[0].clone();

    let attestation_source = local_attestation_source();
    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);
    let enclave = AlwaysUnavailableEnclave;

    let view = host.resolve_claimed_task(&task, &mpc_server, &attestation_source, &enclave);
    assert_eq!(view, HandleStateView::Pending, "BackendUnavailable must keep handle Pending");
    assert_eq!(host.get_handle_state(&derived), HandleStateView::Pending);

    assert!(!host.is_resolution_task_claimed(&derived));
    assert_eq!(host.claim_resolution_tasks().len(), 1);
}

// ---------- Terminal MPC: transitions to Failed(MpcTransformationFailure) ----------

#[test]
fn terminal_mpc_failure_transitions_handle_to_failed_mpc_transformation_failure() {
    let mut host = running_host_with_retries(1); // no retries
    let (_, _, derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    let task = tasks[0].clone();
    let attestation_source = local_attestation_source();

    // MPC rejects with Unauthorized (terminal, not Unavailable).
    let mpc_server = UnauthorizedMpcServer;
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(&task, &mpc_server, &attestation_source, &enclave);

    assert!(
        matches!(
            &view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::MpcTransformationFailure,
                ..
            }
        ),
        "terminal MPC failure must produce MpcTransformationFailure, got {view:?}"
    );
    let HandleStateView::Failed { reason, .. } = &view else { unreachable!() };
    assert!(
        !reason.contains("ciphertext") && !reason.contains("key") && !reason.contains("secret"),
        "reason must not contain secret material: {reason}"
    );

    // Handle transitioned to Failed — visible through GET.
    assert!(
        matches!(
            host.get_handle_state(&derived),
            HandleStateView::Failed {
                category: HandleStateFailureCategory::MpcTransformationFailure,
                ..
            }
        )
    );
    // Failed handle has no Resolution Readiness.
    assert_eq!(host.claim_resolution_tasks().len(), 0);
}

// ---------- Terminal Enclave: transitions to Failed(EnclaveExecutionFailure) ----------

#[test]
fn terminal_enclave_failure_transitions_handle_to_failed_enclave_execution_failure() {
    let mut host = running_host_with_retries(1);
    let (a, b, derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    let task = tasks[0].clone();
    let attestation_source = local_attestation_source();
    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);
    // AttestationVerificationFailure is terminal.
    let enclave = FakeEnclaveRuntime::with_expected_attestation(AttestationDigest([0xFF; 32]));

    let view = host.resolve_claimed_task(&task, &mpc_server, &attestation_source, &enclave);

    assert!(
        matches!(
            &view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::EnclaveExecutionFailure,
                ..
            }
        ),
        "terminal enclave failure must produce EnclaveExecutionFailure, got {view:?}"
    );
    let HandleStateView::Failed { reason, .. } = &view else { unreachable!() };
    assert!(
        !reason.contains("ciphertext") && !reason.contains("key") && !reason.contains("secret"),
        "reason must not contain secret material: {reason}"
    );

    assert!(matches!(
        host.get_handle_state(&derived),
        HandleStateView::Failed {
            category: HandleStateFailureCategory::EnclaveExecutionFailure,
            ..
        }
    ));
    assert_eq!(host.claim_resolution_tasks().len(), 0);
}

// ---------- Materialization failure: transitions to Failed(MaterializationFailure) ----------

#[test]
fn core_materialization_failure_transitions_handle_to_failed_materialization_failure() {
    // Set up core with a pending handle and force a materialization failure
    // by directly calling fail_derived_handle with a MaterializationFailure reason.
    // (The real path requires core.materialize_derived_handle to fail, e.g. NotPending.)
    let mut core = HandleGraphCore::new();
    let a = handle_key(1);
    let b = handle_key(2);
    let derived = handle_key(10);
    ingest_pair_and_derived_into_core(&mut core, a, b, derived);

    // Use fail_derived_handle with MaterializationFailure reason.
    let reason = FailureReason::MaterializationFailure {
        reason: "materialization failed: not pending".to_string(),
    };
    let record = core
        .fail_derived_handle(&derived, reason)
        .expect("fail_derived_handle must succeed on a Pending Derived handle");

    assert!(
        matches!(
            record.state,
            HandleState::Failed {
                reason: FailureReason::MaterializationFailure { .. }
            }
        ),
        "fail_derived_handle must produce MaterializationFailure state, got {:?}",
        record.state
    );

    // The canonical handle reflects Failed state.
    let canonical = core.canonical_handle(&derived).expect("canonical must exist");
    assert!(
        matches!(
            canonical.state,
            HandleState::Failed {
                reason: FailureReason::MaterializationFailure { .. }
            }
        )
    );
}

// ---------- Retry budget exhaustion ----------

#[test]
fn retryable_mpc_failure_exhausts_budget_and_transitions_to_failed() {
    // max_attempts = 2: first attempt uses the attempt, one retry allowed.
    let mut host = running_host_with_retries(2);
    let (_, _, derived) = seed_add_derived(&mut host);

    let attestation_source = local_attestation_source();
    let enclave = FakeEnclaveRuntime::deterministic();

    // Attempt 1: retryable, budget now = 0 remaining.
    let tasks = host.claim_resolution_tasks();
    let task = tasks[0].clone();
    let view1 = host.resolve_claimed_task(
        &task,
        &UnavailableMpcServer,
        &attestation_source,
        &enclave,
    );
    assert_eq!(view1, HandleStateView::Pending, "first failure must stay Pending");

    // Attempt 2: budget = 0, this failure becomes terminal.
    let tasks2 = host.claim_resolution_tasks();
    assert_eq!(tasks2.len(), 1, "re-claim must succeed after first retryable failure");
    let task2 = tasks2[0].clone();
    let view2 = host.resolve_claimed_task(
        &task2,
        &UnavailableMpcServer,
        &attestation_source,
        &enclave,
    );
    assert!(
        matches!(
            view2,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::MpcTransformationFailure,
                ..
            }
        ),
        "budget-exhausted retryable must produce terminal Failed, got {view2:?}"
    );
    assert!(
        matches!(
            host.get_handle_state(&derived),
            HandleStateView::Failed { .. }
        ),
        "handle must be Failed after budget exhaustion"
    );
    // No more re-claims for a Failed handle.
    assert_eq!(host.claim_resolution_tasks().len(), 0);
}

#[test]
fn retryable_enclave_failure_exhausts_budget_and_transitions_to_failed_enclave_category() {
    let mut host = running_host_with_retries(2);
    let (a, b, derived) = seed_add_derived(&mut host);

    let attestation_source = local_attestation_source();

    // Attempt 1: BackendUnavailable → Retryable, budget → 0.
    let tasks = host.claim_resolution_tasks();
    let task = tasks[0].clone();
    let mpc1 = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);
    let view1 = host.resolve_claimed_task(&task, &mpc1, &attestation_source, &AlwaysUnavailableEnclave);
    assert_eq!(view1, HandleStateView::Pending);

    // Attempt 2: budget = 0 → terminal EnclaveExecutionFailure.
    let tasks2 = host.claim_resolution_tasks();
    let task2 = tasks2[0].clone();
    let mpc2 = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);
    let view2 = host.resolve_claimed_task(&task2, &mpc2, &attestation_source, &AlwaysUnavailableEnclave);
    assert!(
        matches!(
            view2,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::EnclaveExecutionFailure,
                ..
            }
        ),
        "budget-exhausted enclave unavailability must produce EnclaveExecutionFailure, got {view2:?}"
    );

    let _ = derived;
}

// ---------- Persistence round-trip for Failed with resolution categories ----------

#[test]
fn failed_derived_handle_with_mpc_failure_survives_persistence_and_restore() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let a = handle_key(1);
    let b = handle_key(2);
    let derived = handle_key(10);

    ingest_pair_and_derived_into_core_with_persistence(&mut core, &mut store, a, b, derived);

    // Transition to Failed via fail_derived_handle_with_persistence.
    let reason = FailureReason::MpcTransformationFailure {
        reason: "mpc transformation rejected at input 0: unauthorized".to_string(),
    };
    let _ = core
        .fail_derived_handle_with_persistence(&derived, reason.clone(), &mut store)
        .expect("fail must succeed");

    // Restore from persistence.
    let restored = HandleGraphCore::restore_from_persistence(&store);
    let record = restored
        .canonical_handle(&derived)
        .expect("restored canonical must exist");

    assert!(
        matches!(
            &record.state,
            HandleState::Failed {
                reason: FailureReason::MpcTransformationFailure { .. }
            }
        ),
        "MpcTransformationFailure must survive persistence round-trip, got {:?}",
        record.state
    );
}

#[test]
fn failed_derived_handle_with_enclave_failure_survives_persistence_and_restore() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let a = handle_key(1);
    let b = handle_key(2);
    let derived = handle_key(10);

    ingest_pair_and_derived_into_core_with_persistence(&mut core, &mut store, a, b, derived);

    let reason = FailureReason::EnclaveExecutionFailure {
        reason: "enclave attestation verification failed".to_string(),
    };
    let _ = core
        .fail_derived_handle_with_persistence(&derived, reason, &mut store)
        .expect("fail must succeed");

    let restored = HandleGraphCore::restore_from_persistence(&store);
    let record = restored
        .canonical_handle(&derived)
        .expect("restored canonical must exist");

    assert!(matches!(
        &record.state,
        HandleState::Failed {
            reason: FailureReason::EnclaveExecutionFailure { .. }
        }
    ));
}

#[test]
fn failed_derived_handle_with_materialization_failure_survives_persistence_and_restore() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let a = handle_key(1);
    let b = handle_key(2);
    let derived = handle_key(10);

    ingest_pair_and_derived_into_core_with_persistence(&mut core, &mut store, a, b, derived);

    let reason = FailureReason::MaterializationFailure {
        reason: "materialization failed: not pending".to_string(),
    };
    let _ = core
        .fail_derived_handle_with_persistence(&derived, reason, &mut store)
        .expect("fail must succeed");

    let restored = HandleGraphCore::restore_from_persistence(&store);
    let record = restored
        .canonical_handle(&derived)
        .expect("restored canonical must exist");

    assert!(matches!(
        &record.state,
        HandleState::Failed {
            reason: FailureReason::MaterializationFailure { .. }
        }
    ));
}

// ---------- Reason string safety ----------

#[test]
fn failure_reason_strings_contain_no_secret_material() {
    let mut host = running_host_with_retries(1);
    let (_, _, _derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    let task = tasks[0].clone();
    let attestation_source = local_attestation_source();
    let mpc_server = UnauthorizedMpcServer;
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(&task, &mpc_server, &attestation_source, &enclave);

    let HandleStateView::Failed { reason, .. } = view else {
        panic!("expected Failed view, got {view:?}");
    };

    // Reason must not contain secret material.
    let secret_keywords = ["ciphertext", "wrapped_key", "aad", "plaintext", "secret",
                            "private_key", "attestation_doc", "decrypted"];
    for keyword in secret_keywords {
        assert!(
            !reason.to_lowercase().contains(keyword),
            "reason contains secret keyword '{keyword}': {reason}"
        );
    }
    // Reason must be non-empty and human-readable.
    assert!(!reason.is_empty(), "reason must be non-empty");
}

// ---------- fail_derived_handle guard invariants ----------

#[test]
fn fail_derived_handle_rejects_non_derived_source_handle() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1);
    // Ingest as an imported (Source) handle.
    let _ = core.apply_chain_event(ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key: key,
        handle_type: HandleType::Suint256,
        system_ciphertext: SystemCiphertextV1(vec![1]),
        materialization_receipt: MaterializationReceipt(vec![2]),
        event_ref: event_ref(1, 1),
    }));

    let err = core.fail_derived_handle(
        &key,
        FailureReason::EnclaveExecutionFailure {
            reason: "test".to_string(),
        },
    );
    assert!(
        matches!(err, Err(coprocessor_handle_graph_core::FailDerivedError::NotDerived)),
        "Source handles must not be failed via fail_derived_handle, got {err:?}"
    );
}

#[test]
fn fail_derived_handle_rejects_already_failed_handle() {
    let mut core = HandleGraphCore::new();
    let a = handle_key(1);
    let b = handle_key(2);
    let derived = handle_key(10);
    ingest_pair_and_derived_into_core(&mut core, a, b, derived);

    // First fail succeeds.
    let _ = core
        .fail_derived_handle(
            &derived,
            FailureReason::MpcTransformationFailure {
                reason: "first".to_string(),
            },
        )
        .expect("first fail must succeed");

    // Second fail must be rejected (NotPending).
    let err = core.fail_derived_handle(
        &derived,
        FailureReason::EnclaveExecutionFailure {
            reason: "second".to_string(),
        },
    );
    assert!(
        matches!(err, Err(coprocessor_handle_graph_core::FailDerivedError::NotPending)),
        "already-Failed handle must reject second fail_derived_handle, got {err:?}"
    );
}

// ---------- fixtures ----------

fn running_host_with_retries(max_attempts: u32) -> CoprocessorHost {
    let config = HostConfig {
        deployment_label: "test".to_string(),
        chain_view: Default::default(),
        retry_policy: RetryPolicy { max_attempts },
    };
    let mut host = CoprocessorHost::new(config);
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

fn local_attestation_source() -> LocalEnclaveAttestationSource {
    LocalEnclaveAttestationSource::new(LocalEnclaveAttestationConfig {
        enclave_public_key: vec![0x44; 48],
        enclave_measurement: AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32]),
        attestation: vec![0x55; 96],
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

fn ingest_imported_into_host(
    host: &mut CoprocessorHost,
    handle_key: HandleKey,
    block_number: u64,
    log_index: u32,
) {
    let outcome = host.handle_graph_core_mut().apply_chain_event(ChainEvent::ImportedHandle(
        ImportedHandle {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key,
            handle_type: HandleType::Suint256,
            system_ciphertext: well_formed_system_ciphertext(handle_key, "suint256"),
            materialization_receipt: MaterializationReceipt(vec![0x02]),
            event_ref: event_ref(block_number, log_index),
        },
    ));
    assert!(matches!(outcome, IngestionOutcome::Recorded(_)));
}

/// Seed a + b (imported) and derived (Add of a+b) into the host, return all three keys.
fn seed_add_derived(host: &mut CoprocessorHost) -> (HandleKey, HandleKey, HandleKey) {
    let a = handle_key(1);
    let b = handle_key(2);
    let derived = handle_key(10);
    ingest_imported_into_host(host, a, 1, 1);
    ingest_imported_into_host(host, b, 1, 2);
    let outcome = host
        .handle_graph_core_mut()
        .apply_chain_event(ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key: derived,
            operation_code: OperationCode::Add,
            output_handle_type: HandleType::Suint256,
            input_handle_keys: vec![a, b],
            event_ref: event_ref(2, 1),
        }));
    assert!(matches!(outcome, IngestionOutcome::Recorded(_)));
    (a, b, derived)
}

fn ingest_pair_and_derived_into_core(
    core: &mut HandleGraphCore,
    a: HandleKey,
    b: HandleKey,
    derived: HandleKey,
) {
    let import_a = ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key: a,
        handle_type: HandleType::Suint256,
        system_ciphertext: well_formed_system_ciphertext(a, "suint256"),
        materialization_receipt: MaterializationReceipt(vec![1]),
        event_ref: event_ref(1, 1),
    });
    let import_b = ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key: b,
        handle_type: HandleType::Suint256,
        system_ciphertext: well_formed_system_ciphertext(b, "suint256"),
        materialization_receipt: MaterializationReceipt(vec![2]),
        event_ref: event_ref(1, 2),
    });
    let derive = ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key: derived,
        operation_code: OperationCode::Add,
        output_handle_type: HandleType::Suint256,
        input_handle_keys: vec![a, b],
        event_ref: event_ref(2, 1),
    });
    assert!(matches!(core.apply_chain_event(import_a), IngestionOutcome::Recorded(_)));
    assert!(matches!(core.apply_chain_event(import_b), IngestionOutcome::Recorded(_)));
    assert!(matches!(core.apply_chain_event(derive), IngestionOutcome::Recorded(_)));
}

fn ingest_pair_and_derived_into_core_with_persistence(
    core: &mut HandleGraphCore,
    store: &mut InMemoryHandlePersistence,
    a: HandleKey,
    b: HandleKey,
    derived: HandleKey,
) {
    let import_a = ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key: a,
        handle_type: HandleType::Suint256,
        system_ciphertext: well_formed_system_ciphertext(a, "suint256"),
        materialization_receipt: MaterializationReceipt(vec![1]),
        event_ref: event_ref(1, 1),
    });
    let import_b = ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key: b,
        handle_type: HandleType::Suint256,
        system_ciphertext: well_formed_system_ciphertext(b, "suint256"),
        materialization_receipt: MaterializationReceipt(vec![2]),
        event_ref: event_ref(1, 2),
    });
    let derive = ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key: derived,
        operation_code: OperationCode::Add,
        output_handle_type: HandleType::Suint256,
        input_handle_keys: vec![a, b],
        event_ref: event_ref(2, 1),
    });
    assert!(matches!(
        core.apply_chain_event_with_persistence(import_a, store),
        IngestionOutcome::Recorded(_)
    ));
    assert!(matches!(
        core.apply_chain_event_with_persistence(import_b, store),
        IngestionOutcome::Recorded(_)
    ));
    assert!(matches!(
        core.apply_chain_event_with_persistence(derive, store),
        IngestionOutcome::Recorded(_)
    ));
}

// ---------- fake backends ----------

struct UnavailableMpcServer;

impl MpcToEnclaveSource for UnavailableMpcServer {
    fn request_to_enclave_transformation(
        &self,
        _request: &ToEnclaveTransformationRequest,
    ) -> Result<MpcToEnclaveResponse, MpcSourceError> {
        Err(MpcSourceError::Unavailable {
            detail: "mpc unavailable".to_string(),
        })
    }
}

struct UnauthorizedMpcServer;

impl MpcToEnclaveSource for UnauthorizedMpcServer {
    fn request_to_enclave_transformation(
        &self,
        _request: &ToEnclaveTransformationRequest,
    ) -> Result<MpcToEnclaveResponse, MpcSourceError> {
        Ok(MpcToEnclaveResponse::Unauthorized)
    }
}

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

struct AlwaysUnavailableEnclave;

impl EnclaveRuntime for AlwaysUnavailableEnclave {
    fn execute(
        &self,
        _task: &EnclaveResolutionTask,
    ) -> Result<EnclaveExecutionOutcome, EnclaveExecutionError> {
        Err(EnclaveExecutionError::BackendUnavailable)
    }
}

