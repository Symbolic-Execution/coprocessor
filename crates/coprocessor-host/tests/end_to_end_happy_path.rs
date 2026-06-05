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

use std::{cell::RefCell, collections::VecDeque};

use coprocessor_ciphertext_binding::{
    self as cbinding, EnclaveAadV1, EnclaveCiphertextV1,
    SystemCiphertextV1 as EnvelopeSystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_enclave_runtime::{AttestationDigest, FakeEnclaveRuntime};
use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleType, ImportedHandle, OperationCode, SystemCiphertextV1,
};
use coprocessor_host::{
    ChainEventSource, ChainView, ChainViewPoll, CoprocessorHost, HandleStateView, HostConfig,
    RequestId,
};
use coprocessor_mpc::{
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

    let predicate = handle_key(0x01);
    let when_true = handle_key(0x02);
    let when_false = handle_key(0x03);
    let derived = handle_key(0x10);

    ingest_events(
        &mut host,
        vec![
            imported_event(
                predicate,
                HandleType::Sbool,
                well_formed_system_ciphertext(predicate, "sbool"),
                1,
                1,
            ),
            imported_event(
                when_true,
                HandleType::Suint256,
                well_formed_system_ciphertext(when_true, "suint256"),
                1,
                2,
            ),
            imported_event(
                when_false,
                HandleType::Suint256,
                well_formed_system_ciphertext(when_false, "suint256"),
                1,
                3,
            ),
        ],
        3,
    );

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

    ingest_events(
        &mut host,
        vec![derived_event(
            derived,
            OperationCode::Select,
            HandleType::Suint256,
            vec![predicate, when_true, when_false],
            2,
            1,
        )],
        1,
    );

    assert_eq!(
        host.get_handle_state(&derived),
        HandleStateView::Pending,
        "Derived Handle must be Pending before resolution"
    );

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

    let enc_predicate = fake_enclave_ciphertext(predicate, 0xD0);
    let enc_when_true = fake_enclave_ciphertext(when_true, 0xD1);
    let enc_when_false = fake_enclave_ciphertext(when_false, 0xD2);
    let expected_enclave_inputs = vec![
        enc_predicate.clone(),
        enc_when_true.clone(),
        enc_when_false.clone(),
    ];
    let mpc_server = ProgrammableMpcServer::with_successes(vec![
        enc_predicate.clone(),
        enc_when_true.clone(),
        enc_when_false.clone(),
        enc_predicate,
        enc_when_true,
        enc_when_false,
    ]);
    let attestation_source = local_attestation_source();
    let enclave = FakeEnclaveRuntime::deterministic();

    let transformed = host
        .transform_resolution_task_inputs(task, &mpc_server, &attestation_source)
        .expect("MPC To-Enclave transformation must succeed");
    assert_eq!(
        transformed, expected_enclave_inputs,
        "MPC To-Enclave transformation must preserve Select input order"
    );

    let view = host.resolve_claimed_task(task, &mpc_server, &attestation_source, &enclave);

    assert!(
        matches!(view, HandleStateView::Ready { .. }),
        "Derived Handle must be Ready after full pipeline, got {view:?}"
    );

    let get_view = host.get_handle_state(&derived);
    assert!(
        matches!(get_view, HandleStateView::Ready { .. }),
        "get_handle_state must return Ready, got {get_view:?}"
    );

    let resolve_view = host.resolve_handle(RequestId([0x99; 32]), &derived);
    assert!(
        matches!(resolve_view, HandleStateView::Ready { .. }),
        "resolve_handle must return Ready, got {resolve_view:?}"
    );

    let HandleStateView::Ready {
        system_ciphertext,
        materialization_receipt,
        derived_receipt,
    } = view
    else {
        unreachable!("matched Ready above")
    };

    assert!(
        !system_ciphertext.0.is_empty(),
        "SystemCiphertextV1 must be non-empty opaque bytes"
    );
    assert!(
        !materialization_receipt.0.is_empty(),
        "MaterializationReceipt must be non-empty opaque bytes"
    );

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

fn imported_event(
    handle_key: HandleKey,
    handle_type: HandleType,
    system_ciphertext: SystemCiphertextV1,
    block_number: u64,
    log_index: u32,
) -> ChainEvent {
    ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key,
        handle_type,
        system_ciphertext,
        event_ref: event_ref(block_number, log_index),
    })
}

fn derived_event(
    handle_key: HandleKey,
    operation_code: OperationCode,
    output_handle_type: HandleType,
    input_handle_keys: Vec<HandleKey>,
    block_number: u64,
    log_index: u32,
) -> ChainEvent {
    ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key,
        operation_code,
        output_handle_type,
        input_handle_keys,
        event_ref: event_ref(block_number, log_index),
    })
}

fn ingest_events(host: &mut CoprocessorHost, events: Vec<ChainEvent>, expected_recorded: usize) {
    let mut source = FixedChainSource::new(events);
    let report = host.ingest_chain_events(&mut source);

    assert_eq!(report.recorded, expected_recorded);
    assert_eq!(report.idempotent, 0);
    assert_eq!(report.duplicates_rejected, 0);
    assert_eq!(report.directly_tombstoned, 0);
    assert_eq!(report.cascade_tombstoned, 0);
    assert_eq!(source.poll_views, vec![ChainView::Safe]);
}

struct FixedChainSource {
    events: Vec<ChainEvent>,
    poll_views: Vec<ChainView>,
}

impl FixedChainSource {
    fn new(events: Vec<ChainEvent>) -> Self {
        Self {
            events,
            poll_views: Vec::new(),
        }
    }
}

impl ChainEventSource for FixedChainSource {
    fn poll(&mut self, view: ChainView) -> ChainViewPoll {
        self.poll_views.push(view);
        ChainViewPoll {
            events: std::mem::take(&mut self.events),
            orphaned_event_refs: Vec::new(),
        }
    }
}

// ---------- fake MPC server ----------

struct ProgrammableMpcServer {
    queued: RefCell<VecDeque<EnclaveCiphertextV1>>,
}

impl ProgrammableMpcServer {
    fn with_successes(envelopes: Vec<EnclaveCiphertextV1>) -> Self {
        Self {
            queued: RefCell::new(envelopes.into()),
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
            .pop_front()
            .expect("ProgrammableMpcServer ran out of queued envelopes");
        Ok(MpcToEnclaveResponse::Success(next))
    }
}
