//! End-to-end failure scenario coverage for issue #48.
//!
//! Starts from spec-shaped symVM Chain Events and drives the full Coprocessor
//! Host pipeline to assert that:
//! - Lineage Violations remain visible as Failed through the Internal
//!   Coordinator API (both get_handle_state and resolve_handle).
//! - Operation Violations remain visible as Failed through both API paths.
//! - Terminal MPC and Enclave failures become Failed with stable non-secret
//!   reason strings, visible through both API paths.
//! - Retryable backend unavailability keeps the Derived Handle Pending while
//!   retry budget remains and does not create a duplicate Resolution Task.
//!
//! Non-goals: Disclosure/Reader flows, real cryptography, new failure
//! categories, or changes to classification logic in resolve_enclave.rs.

use std::cell::RefCell;

use coprocessor_ciphertext_binding::{
    self as cbinding, EnclaveAadV1, EnclaveCiphertextV1,
    SystemCiphertextV1 as EnvelopeSystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_enclave_runtime::{AttestationDigest, FakeEnclaveRuntime};
use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleType, ImportedHandle, IngestionOutcome, OperationCode,
    SystemCiphertextV1,
};
use coprocessor_host::{
    CoprocessorHost, HandleStateFailureCategory, HandleStateView, HostConfig, RequestId,
    RetryPolicy,
};
use coprocessor_mpc::{
    MpcSourceError, MpcToEnclaveResponse, MpcToEnclaveSource, ToEnclaveTransformationRequest,
};
use coprocessor_nitro_enclave::{LocalEnclaveAttestationConfig, LocalEnclaveAttestationSource};

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 0xCC;
const DEFAULT_DOMAIN: u8 = 0xDD;
const DEFAULT_KEY_SEED: u8 = 0xEE;
const DEFAULT_MEASUREMENT_SEED: u8 = 0x42;
const TASK_REQUEST_ID_SEED: u8 = 0x88;

// ---------------------------------------------------------------------------
// Scenario 1: Lineage Violation
// ---------------------------------------------------------------------------

/// Ingesting a derived operation that references an unknown input Handle causes
/// the Derived Handle to become Failed(LineageViolation), visible through both
/// get_handle_state and resolve_handle.
#[test]
fn lineage_violation_unknown_input_is_failed_via_get_and_resolve() {
    let mut host = running_host();

    let known = handle_key(0x01);
    let unknown = handle_key(0x02); // never ingested
    let derived = handle_key(0x10);

    ingest_imported(&mut host, known, HandleType::Suint256, 1, 1);

    // Derived operation references unknown — triggers LineageViolation::UnknownInputHandle.
    let outcome =
        host.handle_graph_core_mut()
            .apply_chain_event(ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
                domain_id: DomainId([DEFAULT_DOMAIN; 32]),
                handle_key: derived,
                operation_code: OperationCode::Add,
                output_handle_type: HandleType::Suint256,
                input_handle_keys: vec![known, unknown],
                event_ref: event_ref(2, 1),
            }));
    // Handle is stored in Failed state (not a DuplicateHandleKeyRejected).
    assert!(
        matches!(outcome, IngestionOutcome::Recorded(_)),
        "lineage-violated derived handle must be Recorded in Failed state, got {outcome:?}"
    );

    let get_view = host.get_handle_state(&derived);
    assert!(
        matches!(
            &get_view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::LineageViolation,
                ..
            }
        ),
        "get_handle_state must return LineageViolation, got {get_view:?}"
    );

    let resolve_view = host.resolve_handle(RequestId([0x01; 32]), &derived);
    assert!(
        matches!(
            &resolve_view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::LineageViolation,
                ..
            }
        ),
        "resolve_handle must return LineageViolation, got {resolve_view:?}"
    );
    assert_eq!(get_view, resolve_view, "get and resolve must agree");

    let HandleStateView::Failed { reason, .. } = &get_view else {
        unreachable!()
    };
    assert!(!reason.is_empty(), "reason must be non-empty");
    assert_reason_is_non_secret(reason);

    // Failed Derived Handle must not be claimable for resolution.
    assert_eq!(
        host.claim_resolution_tasks().len(),
        0,
        "Failed handle must not appear in resolution readiness"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: Operation Violation
// ---------------------------------------------------------------------------

/// Wrong arity — Add with only one input — fails the Derived Handle with
/// Failed(OperationViolation) visible through both API paths.
#[test]
fn operation_violation_wrong_arity_is_failed_via_get_and_resolve() {
    let mut host = running_host();

    let a = handle_key(0x01);
    let derived = handle_key(0x10);

    ingest_imported(&mut host, a, HandleType::Suint256, 1, 1);

    // Add requires 2 inputs; supply 1 → OperationViolation::WrongArity.
    let outcome =
        host.handle_graph_core_mut()
            .apply_chain_event(ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
                domain_id: DomainId([DEFAULT_DOMAIN; 32]),
                handle_key: derived,
                operation_code: OperationCode::Add,
                output_handle_type: HandleType::Suint256,
                input_handle_keys: vec![a],
                event_ref: event_ref(2, 1),
            }));
    assert!(matches!(outcome, IngestionOutcome::Recorded(_)));

    let get_view = host.get_handle_state(&derived);
    assert!(
        matches!(
            &get_view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::OperationViolation,
                ..
            }
        ),
        "get_handle_state must return OperationViolation(WrongArity), got {get_view:?}"
    );

    let resolve_view = host.resolve_handle(RequestId([0x02; 32]), &derived);
    assert!(
        matches!(
            &resolve_view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::OperationViolation,
                ..
            }
        ),
        "resolve_handle must return OperationViolation(WrongArity), got {resolve_view:?}"
    );
    assert_eq!(get_view, resolve_view, "get and resolve must agree");

    let HandleStateView::Failed { reason, .. } = &get_view else {
        unreachable!()
    };
    assert!(!reason.is_empty(), "reason must be non-empty");
    assert_reason_is_non_secret(reason);

    assert_eq!(host.claim_resolution_tasks().len(), 0);
}

/// Wrong input handle type — Add(suint256, sbool) — fails with
/// Failed(OperationViolation) visible through both API paths.
#[test]
fn operation_violation_wrong_input_type_is_failed_via_get_and_resolve() {
    let mut host = running_host();

    let suint = handle_key(0x01);
    let sbool = handle_key(0x02);
    let derived = handle_key(0x10);

    ingest_imported(&mut host, suint, HandleType::Suint256, 1, 1);
    ingest_imported(&mut host, sbool, HandleType::Sbool, 1, 2);

    // Add requires Suint256 inputs; sbool at index 1 → WrongInputHandleType.
    let outcome =
        host.handle_graph_core_mut()
            .apply_chain_event(ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
                domain_id: DomainId([DEFAULT_DOMAIN; 32]),
                handle_key: derived,
                operation_code: OperationCode::Add,
                output_handle_type: HandleType::Suint256,
                input_handle_keys: vec![suint, sbool],
                event_ref: event_ref(2, 1),
            }));
    assert!(matches!(outcome, IngestionOutcome::Recorded(_)));

    let get_view = host.get_handle_state(&derived);
    assert!(
        matches!(
            &get_view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::OperationViolation,
                ..
            }
        ),
        "get_handle_state must return OperationViolation(WrongInputHandleType), got {get_view:?}"
    );

    let resolve_view = host.resolve_handle(RequestId([0x03; 32]), &derived);
    assert!(
        matches!(
            &resolve_view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::OperationViolation,
                ..
            }
        ),
        "resolve_handle must return OperationViolation(WrongInputHandleType), got {resolve_view:?}"
    );
    assert_eq!(
        get_view, resolve_view,
        "get and resolve must agree on OperationViolation"
    );

    let HandleStateView::Failed { reason, .. } = &get_view else {
        unreachable!()
    };
    assert!(!reason.is_empty(), "reason must be non-empty");
    assert_reason_is_non_secret(reason);

    assert_eq!(host.claim_resolution_tasks().len(), 0);
}

// ---------------------------------------------------------------------------
// Scenario 3: Terminal MPC failure
// ---------------------------------------------------------------------------

/// Terminal MPC transformation failure (Unauthorized response) projects
/// Failed(MpcTransformationFailure) with a non-secret reason string through
/// both get_handle_state and resolve_handle.
#[test]
fn terminal_mpc_failure_is_failed_mpc_category_via_get_and_resolve() {
    let mut host = running_host();
    let (_, _, derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1);
    let task = tasks[0].clone();

    let mpc_server = UnauthorizedMpcServer;
    let attestation_source = local_attestation_source();
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

    let HandleStateView::Failed { reason, .. } = &view else {
        unreachable!()
    };
    assert!(!reason.is_empty(), "reason must be non-empty");
    assert_reason_is_non_secret(reason);

    // Both API paths reflect the same Failed state.
    let get_view = host.get_handle_state(&derived);
    assert_eq!(
        view, get_view,
        "get_handle_state must agree with resolve_claimed_task"
    );

    let resolve_view = host.resolve_handle(RequestId([0x04; 32]), &derived);
    assert!(
        matches!(
            &resolve_view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::MpcTransformationFailure,
                ..
            }
        ),
        "resolve_handle must return MpcTransformationFailure, got {resolve_view:?}"
    );
    assert_eq!(
        get_view, resolve_view,
        "get and resolve must agree on MpcTransformationFailure"
    );

    // Failed handle is no longer claimable.
    assert_eq!(host.claim_resolution_tasks().len(), 0);
    assert!(!host.is_resolution_task_claimed(&derived));
}

// ---------------------------------------------------------------------------
// Scenario 4: Terminal Enclave failure
// ---------------------------------------------------------------------------

/// Terminal Enclave execution failure (attestation digest mismatch) projects
/// Failed(EnclaveExecutionFailure) with a non-secret reason string through
/// both API paths.
#[test]
fn terminal_enclave_failure_is_failed_enclave_category_via_get_and_resolve() {
    let mut host = running_host();
    let (a, b, derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1);
    let task = tasks[0].clone();

    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(a, 0xD0),
        fake_enclave_ciphertext(b, 0xD1),
    ]);
    let attestation_source = local_attestation_source();
    // Wrong expected digest causes AttestationVerificationFailure (terminal).
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

    let HandleStateView::Failed { reason, .. } = &view else {
        unreachable!()
    };
    assert!(!reason.is_empty(), "reason must be non-empty");
    assert_reason_is_non_secret(reason);

    let get_view = host.get_handle_state(&derived);
    assert_eq!(
        view, get_view,
        "get_handle_state must agree with resolve_claimed_task"
    );

    let resolve_view = host.resolve_handle(RequestId([0x05; 32]), &derived);
    assert!(
        matches!(
            &resolve_view,
            HandleStateView::Failed {
                category: HandleStateFailureCategory::EnclaveExecutionFailure,
                ..
            }
        ),
        "resolve_handle must return EnclaveExecutionFailure, got {resolve_view:?}"
    );
    assert_eq!(
        get_view, resolve_view,
        "get and resolve must agree on EnclaveExecutionFailure"
    );

    assert_eq!(host.claim_resolution_tasks().len(), 0);
    assert!(!host.is_resolution_task_claimed(&derived));
}

// ---------------------------------------------------------------------------
// Scenario 5: Retryable backend unavailability
// ---------------------------------------------------------------------------

/// Retryable MPC unavailability keeps the handle Pending, releases the claim,
/// and allows exactly one re-claim — claimed_resolution_task_count never
/// exceeds 1 (no duplicate concurrent Resolution Task).
#[test]
fn retryable_mpc_unavailability_keeps_pending_releases_claim_and_no_duplicate_task() {
    let mut host = running_host_with_retries(3);
    let (_, _, derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1, "exactly one task must be claimed initially");
    assert_eq!(host.claimed_resolution_task_count(), 1);

    let task = tasks[0].clone();
    let mpc_server = UnavailableMpcServer;
    let attestation_source = local_attestation_source();
    let enclave = FakeEnclaveRuntime::deterministic();

    // First attempt: retryable → handle stays Pending, claim released.
    let view = host.resolve_claimed_task(&task, &mpc_server, &attestation_source, &enclave);
    assert_eq!(
        view,
        HandleStateView::Pending,
        "retryable MPC failure must keep handle Pending"
    );
    assert_eq!(host.get_handle_state(&derived), HandleStateView::Pending);

    // Claim is released after the retryable failure.
    assert!(
        !host.is_resolution_task_claimed(&derived),
        "claim must be released after retryable failure"
    );
    assert_eq!(
        host.claimed_resolution_task_count(),
        0,
        "no active claims after retryable failure releases"
    );

    // A second scheduler tick re-claims exactly one task for the same handle.
    let reclaimed = host.claim_resolution_tasks();
    assert_eq!(
        reclaimed.len(),
        1,
        "re-claim must succeed after retryable failure"
    );
    assert_eq!(
        reclaimed[0].output_handle_key, derived,
        "re-claimed task must target the same Derived Handle"
    );

    // Only one active claim — never inflated to 2.
    assert_eq!(
        host.claimed_resolution_task_count(),
        1,
        "claimed_resolution_task_count must stay at 1, never become 2"
    );
}

// ---------------------------------------------------------------------------
// Secret-material safety across all violation categories
// ---------------------------------------------------------------------------

/// Lineage and Operation violation reason strings expose only stable category
/// labels, counts, and indices — never ciphertext bytes, wrapped keys,
/// plaintext, attestation documents, reader secrets, or enclave private keys.
#[test]
fn violation_reason_strings_contain_no_secret_material() {
    let mut host = running_host();

    // Lineage violation via unknown input handle.
    let known = handle_key(0x01);
    let unknown = handle_key(0x02);
    let derived_lineage = handle_key(0x10);
    ingest_imported(&mut host, known, HandleType::Suint256, 1, 1);
    let _ = host
        .handle_graph_core_mut()
        .apply_chain_event(ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key: derived_lineage,
            operation_code: OperationCode::Add,
            output_handle_type: HandleType::Suint256,
            input_handle_keys: vec![known, unknown],
            event_ref: event_ref(2, 1),
        }));

    let HandleStateView::Failed {
        reason: lineage_reason,
        ..
    } = host.get_handle_state(&derived_lineage)
    else {
        panic!("expected Failed(LineageViolation)");
    };
    assert!(
        !lineage_reason.is_empty(),
        "lineage reason must be non-empty"
    );
    assert_reason_is_non_secret(&lineage_reason);

    // Operation violation via wrong arity.
    let a = handle_key(0x21);
    let derived_op = handle_key(0x20);
    ingest_imported(&mut host, a, HandleType::Suint256, 3, 1);
    let _ = host
        .handle_graph_core_mut()
        .apply_chain_event(ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key: derived_op,
            operation_code: OperationCode::Add,
            output_handle_type: HandleType::Suint256,
            input_handle_keys: vec![a],
            event_ref: event_ref(4, 1),
        }));

    let HandleStateView::Failed {
        reason: op_reason, ..
    } = host.get_handle_state(&derived_op)
    else {
        panic!("expected Failed(OperationViolation)");
    };
    assert!(!op_reason.is_empty(), "operation reason must be non-empty");
    assert_reason_is_non_secret(&op_reason);
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn running_host() -> CoprocessorHost {
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    host
}

fn running_host_with_retries(max_attempts: u32) -> CoprocessorHost {
    let config = HostConfig {
        deployment_label: "test".to_string(),
        retry_policy: RetryPolicy { max_attempts },
        ..HostConfig::for_local_development()
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
        block_hash: [0xAA; 32],
        tx_hash: [0xBB; 32],
        log_index,
    }
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

fn local_attestation_source() -> LocalEnclaveAttestationSource {
    LocalEnclaveAttestationSource::new(LocalEnclaveAttestationConfig {
        enclave_public_key: vec![0x44; 48],
        enclave_measurement: AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32]),
        attestation: vec![0x55; 96],
    })
}

fn ingest_imported(
    host: &mut CoprocessorHost,
    handle_key: HandleKey,
    handle_type: HandleType,
    block_number: u64,
    log_index: u32,
) {
    let type_tag = match handle_type {
        HandleType::Suint256 => "suint256",
        HandleType::Sbool => "sbool",
    };
    let outcome = host
        .handle_graph_core_mut()
        .apply_chain_event(ChainEvent::ImportedHandle(ImportedHandle {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key,
            handle_type,
            system_ciphertext: well_formed_system_ciphertext(handle_key, type_tag),
            event_ref: event_ref(block_number, log_index),
        }));
    assert!(matches!(outcome, IngestionOutcome::Recorded(_)));
}

/// Seed a + b (imported suint256) and Add(a, b) derived handle into the host.
fn seed_add_derived(host: &mut CoprocessorHost) -> (HandleKey, HandleKey, HandleKey) {
    let a = handle_key(0x01);
    let b = handle_key(0x02);
    let derived = handle_key(0x10);
    ingest_imported(host, a, HandleType::Suint256, 1, 1);
    ingest_imported(host, b, HandleType::Suint256, 1, 2);
    let outcome =
        host.handle_graph_core_mut()
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

fn assert_reason_is_non_secret(reason: &str) {
    const FORBIDDEN: &[&str] = &[
        "ciphertext",
        "wrapped_key",
        "plaintext",
        "private_key",
        "secret",
        "decrypted",
        "attestation_doc",
        "reader_secret",
    ];
    for keyword in FORBIDDEN {
        assert!(
            !reason.to_lowercase().contains(keyword),
            "reason must not contain secret keyword '{keyword}': {reason}"
        );
    }
}

// ---------------------------------------------------------------------------
// Fake backends
// ---------------------------------------------------------------------------

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
