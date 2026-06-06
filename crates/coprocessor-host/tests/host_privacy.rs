//! Privacy regression tests for the Internal Coordinator API (issue #46).
//!
//! Locks the invariants that:
//! - `HandleStateView::Ready` exposes only opaque `SystemCiphertextV1` bytes
//!   and `MaterializationReceipt` — no plaintext Private Values, DEKs, reader
//!   secrets, enclave private keys, or raw decrypted payloads.
//! - `HandleStateView::Failed` reason strings contain only category labels,
//!   input counts, and indices — never secret material — while remaining
//!   non-empty so callers receive useful diagnostics.
//! - `HandleId` and `RequestId` are permitted in the API surface and not
//!   stripped.
//! - Both `get_handle_state` and `resolve_handle` honour these invariants.

use std::cell::RefCell;

use coprocessor_ciphertext_binding::{
    self as cbinding, EnclaveAadV1, EnclaveCiphertextV1,
    SystemCiphertextV1 as EnvelopeSystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_enclave_runtime::{AttestationDigest, FakeEnclaveRuntime};
use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    FailureReason, HandleId, HandleKey, HandleType, ImportedHandle, IngestionOutcome,
    OperationCode, SystemCiphertextV1,
};
use coprocessor_host::{
    CoprocessorHost, HandleStateFailureCategory, HandleStateView, HostConfig, RequestId,
};
use coprocessor_mpc::{
    MpcSourceError, MpcToEnclaveResponse, MpcToEnclaveSource, ToEnclaveTransformationRequest,
};
use coprocessor_nitro_enclave::{
    EnclaveAttestationMaterial, LocalEnclaveAttestationConfig, LocalEnclaveAttestationSource,
};

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 7;
const DEFAULT_DOMAIN: u8 = 9;
const DEFAULT_KEY_SEED: u8 = 0xAB;
const DEFAULT_MEASUREMENT_SEED: u8 = 0x33;
const TASK_REQUEST_ID_SEED: u8 = 0x77;

// ---------------------------------------------------------------------------
// Success path: Ready view exposes only opaque ciphertext and receipt
// ---------------------------------------------------------------------------

#[test]
fn success_path_ready_view_exposes_only_opaque_ciphertext_and_receipt() {
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
    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);
    let enclave = FakeEnclaveRuntime::deterministic();
    let attestation_source = local_attestation_source();

    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    let HandleStateView::Ready {
        ref system_ciphertext,
        ref materialization_receipt,
        ..
    } = view
    else {
        panic!("expected Ready, got {view:?}");
    };

    // Opaque bytes must be non-empty
    assert!(
        !system_ciphertext.0.is_empty(),
        "system_ciphertext must be non-empty"
    );
    assert!(
        !materialization_receipt.0.is_empty(),
        "materialization_receipt must be non-empty"
    );

    // The view must contain no secret keywords that would indicate a plaintext
    // value, DEK, or raw key bytes leaked into the API surface.
    assert_no_forbidden_keywords_in_view(&view);

    // Both API paths agree
    let get_view = host.get_handle_state(&derived);
    assert!(
        matches!(get_view, HandleStateView::Ready { .. }),
        "get_handle_state must return Ready, got {get_view:?}"
    );
    let resolve_view = host.resolve_handle(RequestId([0x44; 32]), &derived);
    assert!(
        matches!(resolve_view, HandleStateView::Ready { .. }),
        "resolve_handle must return Ready, got {resolve_view:?}"
    );
}

// ---------------------------------------------------------------------------
// Failure path: MPC terminal — reason is non-secret but non-empty
// ---------------------------------------------------------------------------

#[test]
fn mpc_terminal_failure_reason_is_non_secret_and_non_empty() {
    let mut host = running_host();
    let (_, _, derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];
    let attestation_source = local_attestation_source();
    // UnauthorizedMpcServer returns Unauthorized — classified as terminal.
    let mpc_server = UnauthorizedMpcServer;
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    let HandleStateView::Failed {
        category,
        ref reason,
    } = view
    else {
        panic!("expected Failed, got {view:?}");
    };
    assert_eq!(
        category,
        HandleStateFailureCategory::MpcTransformationFailure,
        "unauthorized MPC must produce MpcTransformationFailure"
    );

    // Reason must be non-empty — the category label IS permitted for diagnostics.
    assert!(!reason.is_empty(), "failure reason must be non-empty");

    // Reason must contain no secret material: no raw ciphertext bytes, wrapped
    // keys, plaintext values, reader secrets, or enclave private keys.
    assert_reason_is_non_secret(reason);

    // Both API paths reflect the same Failed state.
    assert!(
        matches!(
            host.get_handle_state(&derived),
            HandleStateView::Failed {
                category: HandleStateFailureCategory::MpcTransformationFailure,
                ..
            }
        ),
        "get_handle_state must return MpcTransformationFailure after terminal MPC failure"
    );
}

// ---------------------------------------------------------------------------
// Failure path: Enclave terminal — reason is non-secret but non-empty
// ---------------------------------------------------------------------------

#[test]
fn enclave_terminal_failure_reason_is_non_secret_and_non_empty() {
    let mut host = running_host();
    let (a, b, derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];
    let attestation_source = local_attestation_source();
    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        fake_enclave_ciphertext(a, 0xC0),
        fake_enclave_ciphertext(b, 0xC1),
    ]);
    // Wrong attestation digest is a terminal enclave failure.
    let enclave = FakeEnclaveRuntime::with_expected_attestation(AttestationDigest([0xFF; 32]));

    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    let HandleStateView::Failed {
        category,
        ref reason,
    } = view
    else {
        panic!("expected Failed, got {view:?}");
    };
    assert_eq!(
        category,
        HandleStateFailureCategory::EnclaveExecutionFailure,
        "attestation mismatch must produce EnclaveExecutionFailure"
    );

    // Non-empty: category label is permitted for diagnostics.
    assert!(!reason.is_empty(), "failure reason must be non-empty");

    // No secret material.
    assert_reason_is_non_secret(reason);

    assert!(
        matches!(
            host.get_handle_state(&derived),
            HandleStateView::Failed {
                category: HandleStateFailureCategory::EnclaveExecutionFailure,
                ..
            }
        ),
        "get_handle_state must reflect EnclaveExecutionFailure after terminal enclave failure"
    );
}

// ---------------------------------------------------------------------------
// Positive allowance: HandleId and RequestId are permitted — not stripped
// ---------------------------------------------------------------------------

#[test]
fn handle_id_and_request_id_are_permitted_diagnostics_not_stripped() {
    let mut host = running_host();
    let (_, _, derived) = seed_add_derived(&mut host);

    let tasks = host.claim_resolution_tasks();
    let task = &tasks[0];
    let attestation_source = local_attestation_source();
    let mpc_server = UnauthorizedMpcServer;
    let enclave = FakeEnclaveRuntime::deterministic();

    // Force terminal MPC failure.
    host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    // HandleId is permitted: get_handle_state(&derived) looks up by HandleId
    // and returns the Failed view without stripping it.
    let get_view = host.get_handle_state(&derived);
    assert!(
        matches!(get_view, HandleStateView::Failed { .. }),
        "HandleId-based lookup must return the Failed view, got {get_view:?}"
    );

    // RequestId is permitted: resolve_handle with a known RequestId returns the
    // same view; the RequestId is used for intent tracking, not exposed in the
    // reason string.
    let request_id = RequestId([0x99; 32]);
    let resolve_view = host.resolve_handle(request_id, &derived);
    assert_eq!(
        resolve_view, get_view,
        "resolve_handle with a RequestId must return the same view as get_handle_state"
    );

    // The Failed reason is non-empty: category info is NOT stripped.
    let HandleStateView::Failed { ref reason, .. } = get_view else {
        unreachable!()
    };
    assert!(
        !reason.is_empty(),
        "Failed reason must be non-empty — category labels are permitted for diagnostics"
    );
    // Reason is valid UTF-8 printable ASCII (no embedded binary key material).
    assert!(
        reason.chars().all(|c| c.is_ascii()),
        "Failed reason must be ASCII only, got: {reason:?}"
    );
}

#[test]
fn api_projection_sanitizes_secret_bearing_terminal_failure_reasons() {
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

    let cases = [
        (
            handle_key(20),
            FailureReason::MpcTransformationFailure {
                reason: "wrapped_key=aaaa plaintext=secret".to_string(),
            },
            HandleStateFailureCategory::MpcTransformationFailure,
            "mpc transformation failure",
        ),
        (
            handle_key(21),
            FailureReason::EnclaveExecutionFailure {
                reason: "raw decrypted payload contained private_value".to_string(),
            },
            HandleStateFailureCategory::EnclaveExecutionFailure,
            "enclave execution failure",
        ),
        (
            handle_key(22),
            FailureReason::MaterializationFailure {
                reason: "data-encryption-key leaked in adapter detail".to_string(),
            },
            HandleStateFailureCategory::MaterializationFailure,
            "materialization failure",
        ),
    ];

    for (index, (derived, failure_reason, expected_category, expected_reason)) in
        cases.into_iter().enumerate()
    {
        ingest_derived(
            &mut host,
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            2,
            index as u32 + 1,
        );
        host.handle_graph_core_mut()
            .fail_derived_handle(&derived, failure_reason)
            .expect("pending derived handle can be failed");

        assert_eq!(
            host.get_handle_state(&derived),
            HandleStateView::Failed {
                category: expected_category,
                reason: expected_reason.to_string(),
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Privacy helpers
// ---------------------------------------------------------------------------

/// Byte-level secret-material keywords that must never appear in failure
/// reason strings. Counts, indices, and stable category labels are permitted.
fn assert_reason_is_non_secret(reason: &str) {
    // Words associated with secret material that must never appear:
    const FORBIDDEN: &[&str] = &[
        "wrapped_key",
        "plaintext",
        "private_key",
        "decrypted",
        "reader_secret",
    ];
    for word in FORBIDDEN {
        assert!(
            !reason.to_lowercase().contains(word),
            "failure reason must not contain secret keyword '{word}': {reason:?}"
        );
    }
    // Known test-fixture byte seeds that could signal raw key/ciphertext leakage
    // if hex-encoded into the reason string.
    const FORBIDDEN_HEX: &[&str] = &["0xaa", "0xbb", "0xc0", "0xc1", "aaaa", "bbbb"];
    for pattern in FORBIDDEN_HEX {
        assert!(
            !reason.to_lowercase().contains(pattern),
            "failure reason must not contain hex byte pattern '{pattern}': {reason:?}"
        );
    }
}

/// Asserts that no secret-material keywords appear in the debug form of the
/// view. Applied to the Ready variant where no reason string exists — the
/// check targets field labels in case a future change accidentally adds a
/// plaintext field to `HandleStateView`.
fn assert_no_forbidden_keywords_in_view(view: &HandleStateView) {
    let debug_str = format!("{view:?}").to_lowercase();
    const FORBIDDEN: &[&str] = &[
        "plaintext",
        "private_key",
        "decrypted",
        "reader_secret",
        "wrapped_key",
    ];
    for word in FORBIDDEN {
        assert!(
            !debug_str.contains(word),
            "HandleStateView debug output must not contain secret keyword '{word}': {debug_str}"
        );
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

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
            key_id: cbinding::KeyId([DEFAULT_KEY_SEED; 32]),
            enc: vec![0x99; 32],
            wrapped_key: vec![0xAA; 32],
            nonce: [0x55; 12],
            ciphertext: vec![0xBB; 64],
            aad,
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

/// Seed inputs a, b (imported suint256) and a Derived Add(a, b) into the host.
fn seed_add_derived(host: &mut CoprocessorHost) -> (HandleKey, HandleKey, HandleKey) {
    let a = handle_key(1);
    let b = handle_key(2);
    let derived = handle_key(10);
    ingest_imported(
        host,
        a,
        HandleType::Suint256,
        well_formed_system_ciphertext(a, "suint256"),
        1,
        1,
    );
    ingest_imported(
        host,
        b,
        HandleType::Suint256,
        well_formed_system_ciphertext(b, "suint256"),
        1,
        2,
    );
    ingest_derived(
        host,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );
    (a, b, derived)
}

// ---------------------------------------------------------------------------
// Fake backends
// ---------------------------------------------------------------------------

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

/// Returns `Unauthorized` — a terminal MPC failure.
struct UnauthorizedMpcServer;

impl MpcToEnclaveSource for UnauthorizedMpcServer {
    fn request_to_enclave_transformation(
        &self,
        _request: &ToEnclaveTransformationRequest,
    ) -> Result<MpcToEnclaveResponse, MpcSourceError> {
        Ok(MpcToEnclaveResponse::Unauthorized)
    }
}
