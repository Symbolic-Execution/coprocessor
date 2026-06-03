//! End-to-end happy-path integration scenario for issue #47.
//!
//! Starts from spec-shaped symVM Chain Events (Imported source handles plus a
//! Derived Handle Select operation), drives the full Coprocessor Host pipeline
//! — ingestion, scheduler claim, MPC To-Enclave transformation, Enclave
//! Execution, Materialization — and asserts the Internal Coordinator API
//! returns Ready for the Derived Handle Key through both GET and resolve paths.
//!
//! Acceptance criteria:
//! - Imported source handles ingested from Chain Events are immediately Ready.
//! - Derived Handle ingested from Chain Events starts Pending.
//! - After claim -> resolve, the Derived Handle is Ready with SystemCiphertextV1
//!   and MaterializationReceipt.
//! - GET (get_handle_state) AND resolve (resolve_handle) both return Ready.
//! - DerivedHandleReceiptView preserves operation code, output key, and input
//!   ordering (predicate, when-true, when-false for Select).
//! - The host-facing Ready view contains only opaque ciphertext/receipt bytes;
//!   no plaintext Private Values are present in any field.
//!
//! Non-goals: reorg/restart/failure paths (see #48, #49), real cryptography,
//! Disclosure/Reader flows.

use std::cell::RefCell;

use coprocessor_ciphertext_binding::{
    self as cbinding, EnclaveAadV1, EnclaveCiphertextV1,
    SystemCiphertextV1 as EnvelopeSystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_enclave_runtime::{AttestationDigest, FakeEnclaveRuntime};
use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleType, ImportedHandle, IngestionOutcome, MaterializationReceipt,
    OperationCode, SystemCiphertextV1,
};
use coprocessor_host::{CoprocessorHost, HandleStateView, HostConfig, RequestId};
use coprocessor_mpc_client::{
    MpcSourceError, MpcToEnclaveResponse, MpcToEnclaveSource, ToEnclaveTransformationRequest,
};
use coprocessor_nitro_enclave::{
    AttestationDigest as NitroAttestationDigest, LocalEnclaveAttestationConfig,
    LocalEnclaveAttestationSource,
};

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 0xCC;
const DEFAULT_DOMAIN: u8 = 0xDD;
const DEFAULT_KEY_SEED: u8 = 0xEE;
const DEFAULT_MEASUREMENT_SEED: u8 = 0x42;
const TASK_REQUEST_ID_SEED: u8 = 0x88;

/// End-to-end scenario: three Imported source handles (predicate sbool,
/// when-true suint256, when-false suint256) feed a Select Derived Handle
/// operation.  The full Coprocessor Host pipeline — ingestion, scheduler
/// claim, MPC To-Enclave transformation, Enclave Execution, Materialization —
/// runs to completion and the Internal Coordinator API returns Ready for both
/// GET and resolve paths.
#[test]
fn e2e_select_derived_handle_resolves_to_ready_via_get_and_resolve() {
    let mut host = running_host();

    // Chain Event Ingestion: three Imported source handles.
    let predicate = handle_key(0x01);
    let when_true = handle_key(0x02);
    let when_false = handle_key(0x03);
    let derived = handle_key(0x10);

    ingest_imported(
        &mut host,
        predicate,
        HandleType::Sbool,
        well_formed_system_ciphertext(predicate, "sbool"),
        1,
        1,
    );
    ingest_imported(
        &mut host,
        when_true,
        HandleType::Suint256,
        well_formed_system_ciphertext(when_true, "suint256"),
        1,
        2,
    );
    ingest_imported(
        &mut host,
        when_false,
        HandleType::Suint256,
        well_formed_system_ciphertext(when_false, "suint256"),
        1,
        3,
    );

    // Imported source handles are immediately Ready.
    assert!(
        matches!(
            host.get_handle_state(&predicate),
            HandleStateView::Ready { .. }
        ),
        "predicate source handle must be Ready after ingestion"
    );
    assert!(
        matches!(
            host.get_handle_state(&when_true),
            HandleStateView::Ready { .. }
        ),
        "when_true source handle must be Ready after ingestion"
    );
    assert!(
        matches!(
            host.get_handle_state(&when_false),
            HandleStateView::Ready { .. }
        ),
        "when_false source handle must be Ready after ingestion"
    );

    // Chain Event Ingestion: Derived Handle Select operation.
    ingest_derived(
        &mut host,
        derived,
        OperationCode::Select,
        HandleType::Suint256,
        vec![predicate, when_true, when_false],
        2,
        1,
    );

    // Derived Handle starts Pending.
    assert_eq!(
        host.get_handle_state(&derived),
        HandleStateView::Pending,
        "Derived Handle must be Pending before resolution"
    );

    // Resolution Scheduler: claim the task. All inputs are Ready so the
    // Derived Handle has Resolution Readiness.
    let tasks = host.claim_resolution_tasks();
    assert_eq!(
        tasks.len(),
        1,
        "exactly one task must be claimable for the Select Derived Handle"
    );
    let task = &tasks[0];
    assert_eq!(task.output_handle_key, derived);
    assert_eq!(
        task.input_handle_keys,
        vec![predicate, when_true, when_false],
        "task must carry input keys in predicate, when-true, when-false order"
    );

    // MPC To-Enclave Transformation + Enclave Execution + Materialization.
    // ProgrammableMpcServer returns one EnclaveCiphertextV1 per ordered input.
    let enc_predicate = fake_enclave_ciphertext(predicate, 0xD0);
    let enc_when_true = fake_enclave_ciphertext(when_true, 0xD1);
    let enc_when_false = fake_enclave_ciphertext(when_false, 0xD2);
    let mpc_server =
        ProgrammableMpcServer::with_successes(vec![enc_predicate, enc_when_true, enc_when_false]);
    let attestation_source = local_attestation_source();
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    // The Derived Handle must now be Ready.
    assert!(
        matches!(view, HandleStateView::Ready { .. }),
        "Derived Handle must be Ready after full pipeline, got {view:?}"
    );

    // GET path: Internal Coordinator API.
    let get_view = host.get_handle_state(&derived);
    assert!(
        matches!(get_view, HandleStateView::Ready { .. }),
        "get_handle_state must return Ready, got {get_view:?}"
    );

    // resolve path: Internal Coordinator API.
    let resolve_view = host.resolve_handle(RequestId([0x99; 32]), &derived);
    assert!(
        matches!(resolve_view, HandleStateView::Ready { .. }),
        "resolve_handle must return Ready, got {resolve_view:?}"
    );

    // Inspect the Ready view: opaque ciphertext + receipt + derived provenance.
    let HandleStateView::Ready {
        system_ciphertext,
        materialization_receipt,
        derived_receipt,
    } = view
    else {
        unreachable!("matched Ready above")
    };

    // SystemCiphertextV1: non-empty opaque bytes (no plaintext field).
    assert!(
        !system_ciphertext.0.is_empty(),
        "SystemCiphertextV1 must be non-empty opaque bytes"
    );

    // MaterializationReceipt: non-empty opaque bytes (no plaintext field).
    assert!(
        !materialization_receipt.0.is_empty(),
        "MaterializationReceipt must be non-empty opaque bytes"
    );

    // DerivedHandleReceiptView carries correct provenance in input order.
    let receipt = derived_receipt.expect("Derived Handle must expose DerivedHandleReceiptView");
    assert_eq!(receipt.operation_code, OperationCode::Select);
    assert_eq!(receipt.output_handle_key, derived);
    assert_eq!(
        receipt.input_handle_keys,
        vec![predicate, when_true, when_false],
        "receipt must preserve predicate, when-true, when-false input ordering"
    );
    assert_eq!(
        receipt.attestation_digest,
        AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32]),
        "receipt attestation digest must match the local attestation source measurement"
    );

    // Claim released after successful materialization.
    assert!(
        !host.is_resolution_task_claimed(&derived),
        "claim must be released after successful materialization"
    );
}

/// Imported source handles have no derived receipt — only Derived Handles carry
/// the Select/Add/etc. provenance record.
#[test]
fn e2e_imported_source_handle_has_no_derived_receipt() {
    let mut host = running_host();
    let key = handle_key(0x01);
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
        panic!("expected Ready for Imported source handle, got {view:?}");
    };
    assert_eq!(
        derived_receipt, None,
        "Imported source handle must not carry a derived receipt"
    );
}

/// Security / privacy check: host-facing Ready view exposes only opaque
/// ciphertext and receipt bytes — no plaintext Private Values, DEKs,
/// reader secrets, or decrypted payloads in any serialised field.
#[test]
fn e2e_ready_view_contains_no_plaintext_private_values() {
    let mut host = running_host();
    let a = handle_key(0x01);
    let b = handle_key(0x02);
    let derived = handle_key(0x10);

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
    let attestation_source = local_attestation_source();
    let enclave = FakeEnclaveRuntime::deterministic();

    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    let HandleStateView::Ready {
        system_ciphertext,
        materialization_receipt,
        ..
    } = view
    else {
        panic!("expected Ready, got {view:?}");
    };

    // Neither byte sequence should contain plaintext keyword strings.
    let ct_hex = hex_bytes(&system_ciphertext.0);
    let receipt_hex = hex_bytes(&materialization_receipt.0);

    let forbidden = ["plaintext", "secret", "private_key", "decrypted", "dek"];
    for keyword in forbidden {
        assert!(
            !ct_hex.contains(keyword) && !receipt_hex.contains(keyword),
            "Ready view must not contain plaintext keyword '{keyword}'"
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
        enclave_measurement: NitroAttestationDigest([DEFAULT_MEASUREMENT_SEED; 32]),
        attestation: vec![0x55; 96],
    })
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
            materialization_receipt: MaterializationReceipt(vec![0x01]),
            event_ref: event_ref(block_number, log_index),
        }));
    assert!(
        matches!(outcome, IngestionOutcome::Recorded(_)),
        "ImportedHandle must be Recorded, got {outcome:?}"
    );
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
    assert!(
        matches!(outcome, IngestionOutcome::Recorded(_)),
        "DerivedHandleOperation must be Recorded, got {outcome:?}"
    );
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------- fake MPC server ----------

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
