//! Persistence privacy regression tests for issue #46.
//!
//! Asserts that durable `HandleRecord` state never contains plaintext Private
//! Values or task-scoped `EnclaveCiphertextV1` bytes, and that provenance
//! fields (`domain_id`, `handle_key`, `handle_type`, `event_ref`, `lineage`,
//! `is_canonical`) survive the persistence round-trip unchanged.
//!
//! Per ADR 0004 the only durable state is:
//! - Canonical `HandleRecord`s: `SystemCiphertextV1` + `MaterializationReceipt`
//!   for Ready; `FailureReason` (non-secret strings) for Failed; and provenance.
//! - Consumed `ChainEventRef` markers for idempotent replay.
//!
//! `EnclaveCiphertextV1` is task-scoped and must never appear in durable
//! storage; this file locks that invariant with runtime assertions.

use coprocessor_ciphertext_binding::{
    self as cbinding, AttestationDigest, EnclaveAadV1, EnclaveCiphertextV1,
};
use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    FailureReason, HandleGraphCore, HandleId, HandleKey, HandleLineage, HandlePersistence,
    HandleRecord, HandleState, HandleType, ImportedHandle, InMemoryHandlePersistence,
    IngestionOutcome, MaterializationReceipt, OperationCode, SystemCiphertextV1,
};

const DEFAULT_DOMAIN: u8 = 9;
const KEY_SEED: u8 = 0xAB;
const MEASUREMENT_SEED: u8 = 0x33;
const REQUEST_SEED: u8 = 0x77;

// ---------------------------------------------------------------------------
// Test 1: Ready source handle — persists SystemCiphertextV1 + receipt + provenance
// ---------------------------------------------------------------------------

#[test]
fn ready_source_handle_persists_exact_system_ciphertext_and_provenance() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();

    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    let ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB, 0xCC]);
    let receipt = MaterializationReceipt(vec![0xDD, 0xEE]);
    let domain = DomainId(bytes32(DEFAULT_DOMAIN));

    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        imported_event(
            key,
            HandleType::Suint256,
            event_ref,
            ciphertext.clone(),
            receipt.clone(),
        ),
        &mut store,
    ));

    let stored = store.handle_record(&key).expect("must be persisted");

    // Provenance is preserved verbatim.
    assert_eq!(stored.domain_id, domain);
    assert_eq!(stored.handle_key, key);
    assert_eq!(stored.handle_type, HandleType::Suint256);
    assert_eq!(stored.event_ref, event_ref);
    assert_eq!(stored.lineage, HandleLineage::Source);
    assert!(stored.is_canonical, "source handle must be canonical");
    assert!(
        !stored.is_tombstoned,
        "source handle must not be tombstoned"
    );

    // The Ready state holds exactly the SystemCiphertextV1 and receipt we
    // supplied — no plaintext Private Value.
    let HandleState::Ready {
        system_ciphertext,
        materialization_receipt,
    } = stored.state
    else {
        panic!("expected Ready state in persistence");
    };
    assert_eq!(
        system_ciphertext, ciphertext,
        "persisted SystemCiphertextV1 must equal the bytes supplied at ingestion"
    );
    assert_eq!(
        materialization_receipt, receipt,
        "persisted MaterializationReceipt must equal the bytes supplied at ingestion"
    );

    // Opaque bytes are non-empty.
    assert!(!system_ciphertext.0.is_empty());
    assert!(!materialization_receipt.0.is_empty());
}

// ---------------------------------------------------------------------------
// Test 2: EnclaveCiphertextV1 bytes are never stored in durable persistence
// ---------------------------------------------------------------------------

#[test]
fn enclave_ciphertext_v1_bytes_never_appear_in_persisted_ready_state() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();

    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let derived = handle_key(1, 7, 10);

    record_imported_suint(
        &mut core,
        &mut store,
        a,
        chain_event_ref(1, 1, 1),
        SystemCiphertextV1(vec![1]),
        MaterializationReceipt(vec![2]),
    );
    record_imported_suint(
        &mut core,
        &mut store,
        b,
        chain_event_ref(1, 1, 2),
        SystemCiphertextV1(vec![3]),
        MaterializationReceipt(vec![4]),
    );
    record_pending_add(
        &mut core,
        &mut store,
        derived,
        vec![a, b],
        chain_event_ref(1, 2, 1),
    );

    // Build a known EnclaveCiphertextV1 with distinct byte patterns to use as
    // a sentinel: if its encoded form appeared in the persisted
    // SystemCiphertextV1, it would indicate a privacy boundary violation.
    let enclave_ct = make_enclave_ciphertext(handle_key(1, 7, 1), 0xDE);
    let enclave_ct_bytes = enclave_ct.encode();

    // The SystemCiphertextV1 we store for the derived handle uses different
    // bytes — this is what the host would supply after enclave execution.
    let system_ct = SystemCiphertextV1(vec![0x01, 0x02, 0x03, 0x04]);
    let receipt = MaterializationReceipt(vec![0xFE]);

    // Precondition: the system and enclave bytes must differ.
    assert_ne!(
        system_ct.0, enclave_ct_bytes,
        "test precondition: SystemCiphertextV1 and EnclaveCiphertextV1.encode() must differ"
    );

    let _ = core
        .materialize_derived_handle_with_persistence(
            &derived,
            system_ct.clone(),
            receipt,
            &mut store,
        )
        .expect("materialize must succeed");

    let stored = store.handle_record(&derived).expect("must be persisted");

    let HandleState::Ready {
        system_ciphertext, ..
    } = &stored.state
    else {
        panic!("expected Ready state, got {:?}", stored.state);
    };

    // The persisted bytes equal the SystemCiphertextV1 we supplied — never the
    // task-scoped EnclaveCiphertextV1.
    assert_eq!(
        system_ciphertext.0, system_ct.0,
        "stored SystemCiphertextV1 must equal the bytes supplied to materialize_derived_handle"
    );
    assert_ne!(
        system_ciphertext.0, enclave_ct_bytes,
        "EnclaveCiphertextV1 encoded bytes must never appear as the persisted SystemCiphertextV1"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Failure reason strings in persistence are non-secret
// ---------------------------------------------------------------------------

#[test]
fn failure_reason_strings_in_persistence_contain_no_secret_material() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();

    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let derived_mpc = handle_key(1, 7, 20);
    let derived_enclave = handle_key(1, 7, 21);

    record_imported_suint(
        &mut core,
        &mut store,
        a,
        chain_event_ref(1, 1, 1),
        SystemCiphertextV1(vec![1]),
        MaterializationReceipt(vec![2]),
    );
    record_imported_suint(
        &mut core,
        &mut store,
        b,
        chain_event_ref(1, 1, 2),
        SystemCiphertextV1(vec![3]),
        MaterializationReceipt(vec![4]),
    );
    record_pending_add(
        &mut core,
        &mut store,
        derived_mpc,
        vec![a, b],
        chain_event_ref(1, 2, 1),
    );
    record_pending_add(
        &mut core,
        &mut store,
        derived_enclave,
        vec![a, b],
        chain_event_ref(1, 2, 2),
    );

    // Terminal MPC transformation failure.
    let mpc_reason = FailureReason::MpcTransformationFailure {
        reason: "mpc transformation rejected at input 0: unauthorized".to_string(),
    };
    let _ = core
        .fail_derived_handle_with_persistence(&derived_mpc, mpc_reason, &mut store)
        .expect("fail must succeed");

    // Terminal Enclave execution failure.
    let enclave_reason = FailureReason::EnclaveExecutionFailure {
        reason: "enclave attestation verification failed".to_string(),
    };
    let _ = core
        .fail_derived_handle_with_persistence(&derived_enclave, enclave_reason, &mut store)
        .expect("fail must succeed");

    // Read back and assert non-secret reason strings.
    let mpc_record = store.handle_record(&derived_mpc).expect("mpc record");
    let enclave_record = store
        .handle_record(&derived_enclave)
        .expect("enclave record");

    let mpc_reason_str = extract_failure_reason_string(&mpc_record);
    let enclave_reason_str = extract_failure_reason_string(&enclave_record);

    // Reasons must be non-empty (category info is preserved).
    assert!(
        !mpc_reason_str.is_empty(),
        "MPC failure reason must be non-empty"
    );
    assert!(
        !enclave_reason_str.is_empty(),
        "Enclave failure reason must be non-empty"
    );

    // Reasons must not contain secret material.
    assert_reason_is_non_secret(&mpc_reason_str, "MPC");
    assert_reason_is_non_secret(&enclave_reason_str, "Enclave");
}

// ---------------------------------------------------------------------------
// Test 4: Provenance fields are preserved for Ready derived handle
// ---------------------------------------------------------------------------

#[test]
fn provenance_fields_survive_persistence_round_trip_for_ready_derived_handle() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();

    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let derived = handle_key(1, 7, 10);
    let derived_event_ref = chain_event_ref(1, 2, 1);
    let domain = DomainId(bytes32(DEFAULT_DOMAIN));

    record_imported_suint(
        &mut core,
        &mut store,
        a,
        chain_event_ref(1, 1, 1),
        SystemCiphertextV1(vec![1]),
        MaterializationReceipt(vec![2]),
    );
    record_imported_suint(
        &mut core,
        &mut store,
        b,
        chain_event_ref(1, 1, 2),
        SystemCiphertextV1(vec![3]),
        MaterializationReceipt(vec![4]),
    );
    record_pending_add(
        &mut core,
        &mut store,
        derived,
        vec![a, b],
        derived_event_ref,
    );

    let system_ct = SystemCiphertextV1(vec![0x10, 0x20, 0x30]);
    let receipt = MaterializationReceipt(vec![0x40]);

    let _ = core
        .materialize_derived_handle_with_persistence(
            &derived,
            system_ct.clone(),
            receipt.clone(),
            &mut store,
        )
        .expect("materialize must succeed");

    // Restore from persistence to simulate a process restart.
    let restored = HandleGraphCore::restore_from_persistence(&store);
    let record = restored
        .canonical_handle(&derived)
        .expect("derived handle must be canonical after restore");

    // All provenance fields must survive the persistence round-trip.
    assert_eq!(record.domain_id, domain, "domain_id must be preserved");
    assert_eq!(record.handle_key, derived, "handle_key must be preserved");
    assert_eq!(
        record.handle_type,
        HandleType::Suint256,
        "handle_type must be preserved"
    );
    assert_eq!(
        record.event_ref, derived_event_ref,
        "event_ref must be preserved"
    );
    assert_eq!(
        record.lineage,
        HandleLineage::Derived {
            operation_code: OperationCode::Add,
            input_handle_keys: vec![a, b],
        },
        "lineage must be preserved"
    );
    assert!(record.is_canonical, "is_canonical must be preserved");
    assert!(!record.is_tombstoned, "is_tombstoned must be preserved");

    // State payload is intact.
    assert_eq!(
        record.state,
        HandleState::Ready {
            system_ciphertext: system_ct,
            materialization_receipt: receipt,
        },
        "Ready state with ciphertext and receipt must survive persistence round-trip"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_failure_reason_string(record: &HandleRecord) -> String {
    match &record.state {
        HandleState::Failed { reason } => match reason {
            FailureReason::MpcTransformationFailure { reason }
            | FailureReason::EnclaveExecutionFailure { reason }
            | FailureReason::MaterializationFailure { reason } => reason.clone(),
            FailureReason::LineageViolation(_) => "lineage violation".to_string(),
            FailureReason::OperationViolation(_) => "operation violation".to_string(),
        },
        other => panic!("expected Failed state, got {other:?}"),
    }
}

fn assert_reason_is_non_secret(reason: &str, label: &str) {
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
            "{label} failure reason must not contain secret keyword '{word}': {reason:?}"
        );
    }
    // Known test fixture byte seeds that would indicate raw key/ciphertext leaked.
    const FORBIDDEN_HEX: &[&str] = &["0xde", "0xad", "ded", "dead"];
    for pattern in FORBIDDEN_HEX {
        assert!(
            !reason.to_lowercase().contains(pattern),
            "{label} failure reason must not contain hex pattern '{pattern}': {reason:?}"
        );
    }
}

/// Build an EnclaveCiphertextV1 with a known payload seed for use as a
/// byte-pattern sentinel in persistence assertions.
fn make_enclave_ciphertext(key: HandleKey, payload_seed: u8) -> EnclaveCiphertextV1 {
    let aad = EnclaveAadV1 {
        version: 1,
        chain_id: key.chain_id.0,
        domain_id: cbinding::DomainId([DEFAULT_DOMAIN; 32]),
        request_id: cbinding::RequestId([REQUEST_SEED; 32]),
        handle_id: cbinding::HandleId(key.handle_id.0),
        type_tag: "suint256".to_string(),
        attestation_digest: AttestationDigest([MEASUREMENT_SEED; 32]),
        key_id: cbinding::KeyId([KEY_SEED; 32]),
    }
    .encode();
    EnclaveCiphertextV1 {
        version: 1,
        aad,
        wrapped_key: vec![payload_seed; 32],
        ciphertext: vec![payload_seed; 64],
    }
}

// ---------------------------------------------------------------------------
// Fixtures (shared with existing persistence tests style)
// ---------------------------------------------------------------------------

fn record_imported_suint(
    core: &mut HandleGraphCore,
    store: &mut InMemoryHandlePersistence,
    handle_key: HandleKey,
    event_ref: ChainEventRef,
    system_ciphertext: SystemCiphertextV1,
    materialization_receipt: MaterializationReceipt,
) {
    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        imported_event(
            handle_key,
            HandleType::Suint256,
            event_ref,
            system_ciphertext,
            materialization_receipt,
        ),
        store,
    ));
}

fn record_pending_add(
    core: &mut HandleGraphCore,
    store: &mut InMemoryHandlePersistence,
    handle_key: HandleKey,
    input_handle_keys: Vec<HandleKey>,
    event_ref: ChainEventRef,
) {
    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
            domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
            handle_key,
            operation_code: OperationCode::Add,
            output_handle_type: HandleType::Suint256,
            input_handle_keys,
            event_ref,
        }),
        store,
    ));
}

fn expect_recorded(outcome: IngestionOutcome) -> HandleRecord {
    match outcome {
        IngestionOutcome::Recorded(record) => record,
        other => panic!("expected Recorded, got {other:?}"),
    }
}

fn imported_event(
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
    system_ciphertext: SystemCiphertextV1,
    materialization_receipt: MaterializationReceipt,
) -> ChainEvent {
    ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
        handle_key,
        handle_type,
        system_ciphertext,
        materialization_receipt,
        event_ref,
    })
}

fn handle_key(chain_id: u64, contract_seed: u8, handle_seed: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(chain_id),
        contract_address: ContractAddress([contract_seed; 20]),
        handle_id: HandleId(bytes32(handle_seed)),
    }
}

fn chain_event_ref(chain_id: u64, block_number: u64, log_index: u32) -> ChainEventRef {
    ChainEventRef {
        chain_id: ChainId(chain_id),
        block_number,
        block_hash: bytes32(11),
        tx_hash: bytes32(12),
        log_index,
    }
}

fn bytes32(seed: u8) -> [u8; 32] {
    [seed; 32]
}
