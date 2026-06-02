//! Canonical and audit/debug query semantics, exercised through the public
//! Handle Graph Core interface.
//!
//! Canonical queries (`canonical_handle`) are the read path future normal API
//! reads and Resolution checks will use: unknown Handle Keys and tombstoned
//! Handle Records appear as unknown. Audit/debug queries
//! (`handle_record_for_audit`) are an operator/tooling read path: they include
//! tombstoned Handle Records retained by Orphan Discard, and expose enough
//! preserved data to inspect ChainEventRef, Handle Key, HandleType, Handle
//! State, and tombstone/canonicality status. The audit path is intentionally
//! separate from the future Internal Coordinator API surface.

use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    FailureReason, HandleGraphCore, HandleId, HandleKey, HandleRecord, HandleState, HandleType,
    ImportedHandle, IngestionOutcome, LineageViolation, MaterializationReceipt, OperationCode,
    OperationViolation, PlaintextHandle, PublicPlaintextValue, SystemCiphertextV1,
};

const DEFAULT_DOMAIN: u8 = 9;

// ---------- Canonical query: unknown ----------

#[test]
fn canonical_query_returns_none_for_unknown_handle_key() {
    let core = HandleGraphCore::new();
    let unknown = handle_key(1, 7, 99);

    assert!(
        core.canonical_handle(&unknown).is_none(),
        "unknown Handle Keys must appear unknown, not as Pending or any other state"
    );
}

#[test]
fn canonical_query_for_unknown_key_is_not_pending() {
    // Spec: Pending applies only to known Canonical Handle Records.
    // An unknown handle must not be represented as Pending.
    let core = HandleGraphCore::new();
    let unknown = handle_key(1, 7, 99);

    let result = core.canonical_handle(&unknown);

    assert!(
        result.is_none(),
        "unknown handle must be None, not a Pending placeholder; got {:?}",
        result
    );
}

// ---------- Canonical query: Ready source handles ----------

#[test]
fn canonical_query_returns_imported_ready_source_handle_with_ciphertext_and_receipt() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    let ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB]);
    let receipt = MaterializationReceipt(vec![0xCC, 0xDD]);
    let _ = expect_recorded(core.apply_chain_event(imported_event_with(
        key,
        HandleType::Suint256,
        event_ref,
        ciphertext.clone(),
        receipt.clone(),
    )));

    let record = core
        .canonical_handle(&key)
        .expect("imported handle must be canonical");

    assert_eq!(record.handle_key, key);
    assert_eq!(record.handle_type, HandleType::Suint256);
    match &record.state {
        HandleState::Ready {
            system_ciphertext,
            materialization_receipt,
        } => {
            assert_eq!(
                system_ciphertext, &ciphertext,
                "canonical query must surface the imported SystemCiphertextV1"
            );
            assert_eq!(
                materialization_receipt, &receipt,
                "canonical query must surface the imported MaterializationReceipt"
            );
        }
        other => panic!("expected Ready source handle, got {:?}", other),
    }
}

#[test]
fn canonical_query_returns_plaintext_ready_source_handle_with_ciphertext_and_receipt() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 2);
    let event_ref = chain_event_ref(1, 1, 2);
    let _ = expect_recorded(core.apply_chain_event(plaintext_event(
        key,
        HandleType::Sbool,
        event_ref,
        PublicPlaintextValue(vec![0x01]),
    )));

    let record = core
        .canonical_handle(&key)
        .expect("plaintext handle must be canonical");

    assert_eq!(record.handle_type, HandleType::Sbool);
    let HandleState::Ready {
        system_ciphertext,
        materialization_receipt,
    } = &record.state
    else {
        panic!(
            "plaintext handle must materialize as Ready, got {:?}",
            record.state
        );
    };
    assert!(
        !system_ciphertext.0.is_empty(),
        "plaintext materialization must produce a non-empty placeholder SystemCiphertextV1"
    );
    assert!(
        !materialization_receipt.0.is_empty(),
        "plaintext materialization must produce a non-empty placeholder MaterializationReceipt"
    );
}

// ---------- Canonical query: Pending derived ----------

#[test]
fn canonical_query_returns_pending_derived_handle() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core);
    let derived = handle_key(1, 7, 10);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        chain_event_ref(1, 2, 1),
    )));

    let record = core
        .canonical_handle(&derived)
        .expect("derived handle must be canonical");

    assert_eq!(
        record.state,
        HandleState::Pending,
        "valid derived handle must be Pending until Resolution is implemented"
    );
    assert_eq!(record.handle_type, HandleType::Suint256);
}

// ---------- Canonical query: Failed records (Lineage + Operation violations) ----------

#[test]
fn canonical_query_returns_failed_derived_handle_with_lineage_violation_reason() {
    let mut core = HandleGraphCore::new();
    let known = handle_key(1, 7, 1);
    seed_imported(
        &mut core,
        known,
        HandleType::Suint256,
        chain_event_ref(1, 1, 1),
    );
    let unknown_input = handle_key(1, 7, 77);
    let derived = handle_key(1, 7, 10);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![known, unknown_input],
        chain_event_ref(1, 2, 1),
    )));

    let record = core
        .canonical_handle(&derived)
        .expect("failed derived must remain canonical and visible");

    match &record.state {
        HandleState::Failed {
            reason:
                FailureReason::LineageViolation(LineageViolation::UnknownInputHandle {
                    input_handle_key,
                }),
        } => {
            assert_eq!(
                *input_handle_key, unknown_input,
                "canonical query must surface the offending input handle key"
            );
        }
        other => panic!(
            "expected Failed/LineageViolation/UnknownInputHandle, got {:?}",
            other
        ),
    }
}

#[test]
fn canonical_query_returns_failed_derived_handle_with_operation_violation_reason() {
    let mut core = HandleGraphCore::new();
    let (a, _) = seed_suint_pair(&mut core);
    // Add expects arity 2; supplying 1 input is a WrongArity OperationViolation.
    let derived = handle_key(1, 7, 30);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a],
        chain_event_ref(1, 2, 1),
    )));

    let record = core
        .canonical_handle(&derived)
        .expect("failed derived must remain canonical and visible");

    match &record.state {
        HandleState::Failed {
            reason:
                FailureReason::OperationViolation(OperationViolation::WrongArity {
                    operation_code,
                    expected,
                    actual,
                }),
        } => {
            assert_eq!(*operation_code, OperationCode::Add);
            assert_eq!(*expected, 2);
            assert_eq!(*actual, 1);
        }
        other => panic!(
            "expected Failed/OperationViolation/WrongArity, got {:?}",
            other
        ),
    }
}

// ---------- Canonical query: tombstoned hidden ----------

#[test]
fn canonical_query_hides_tombstoned_source_handle_as_unknown() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, key, HandleType::Suint256, event_ref);
    assert!(core.canonical_handle(&key).is_some(), "precondition");

    let _ = core.apply_orphan_discard(&[event_ref]);

    assert!(
        core.canonical_handle(&key).is_none(),
        "tombstoned source handle must be hidden from canonical query, indistinguishable from unknown"
    );
}

#[test]
fn canonical_query_hides_cascade_tombstoned_derived_handle() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core);
    let a_event = chain_event_ref(1, 1, 1); // matches seed_suint_pair's first input
    let derived = handle_key(1, 7, 10);
    let derived_event = chain_event_ref(1, 2, 1);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        derived_event,
    )));
    assert!(core.canonical_handle(&derived).is_some(), "precondition");

    let _ = core.apply_orphan_discard(&[a_event]);

    assert!(
        core.canonical_handle(&derived).is_none(),
        "cascade-tombstoned derived must be hidden from canonical query even though its own ChainEventRef was not orphaned"
    );
}

// ---------- Audit/debug query: returns every state, including tombstoned ----------

#[test]
fn audit_query_returns_none_for_unknown_handle_key() {
    let core = HandleGraphCore::new();
    let unknown = handle_key(1, 7, 99);

    assert!(
        core.handle_record_for_audit(&unknown).is_none(),
        "audit query must not invent records for unknown Handle Keys"
    );
}

#[test]
fn audit_query_returns_ready_imported_source_handle() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, key, HandleType::Suint256, event_ref);

    let record = core
        .handle_record_for_audit(&key)
        .expect("audit must see Ready source handle");

    assert!(matches!(record.state, HandleState::Ready { .. }));
    assert!(!record.is_tombstoned);
}

#[test]
fn audit_query_returns_pending_derived_handle() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core);
    let derived = handle_key(1, 7, 10);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        chain_event_ref(1, 2, 1),
    )));

    let record = core
        .handle_record_for_audit(&derived)
        .expect("audit must see Pending derived");

    assert_eq!(record.state, HandleState::Pending);
    assert!(!record.is_tombstoned);
}

#[test]
fn audit_query_returns_failed_derived_handle_with_reason_payload() {
    let mut core = HandleGraphCore::new();
    let (a, _) = seed_suint_pair(&mut core);
    let derived = handle_key(1, 7, 30);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a], // wrong arity
        chain_event_ref(1, 2, 1),
    )));

    let record = core
        .handle_record_for_audit(&derived)
        .expect("audit must see Failed derived");

    assert!(
        matches!(record.state, HandleState::Failed { .. }),
        "audit must preserve Failed state, got {:?}",
        record.state
    );
}

#[test]
fn audit_query_returns_tombstoned_record_hidden_from_canonical() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, key, HandleType::Suint256, event_ref);
    let _ = core.apply_orphan_discard(&[event_ref]);

    assert!(
        core.canonical_handle(&key).is_none(),
        "precondition: tombstoned record must be hidden from canonical query"
    );
    let record = core
        .handle_record_for_audit(&key)
        .expect("audit query must still expose the tombstoned record");

    assert!(
        record.is_tombstoned,
        "audit query must reveal tombstone status"
    );
}

// ---------- Audit/debug query exposes ChainEventRef, HandleKey, HandleType, HandleState, status ----------

#[test]
fn audit_query_exposes_tombstoned_record_metadata_and_status() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, key, HandleType::Suint256, event_ref);
    let _ = core.apply_orphan_discard(&[event_ref]);

    let record = core
        .handle_record_for_audit(&key)
        .expect("audit must expose tombstoned record");

    // Every field required by the acceptance criteria must remain inspectable.
    assert_eq!(
        record.event_ref, event_ref,
        "audit must preserve ChainEventRef on tombstoned records"
    );
    assert_eq!(
        record.handle_key, key,
        "audit must preserve Handle Key on tombstoned records"
    );
    assert_eq!(
        record.handle_type,
        HandleType::Suint256,
        "audit must preserve HandleType on tombstoned records"
    );
    assert!(
        matches!(record.state, HandleState::Ready { .. }),
        "audit must preserve the original Handle State on tombstoned records, got {:?}",
        record.state
    );
    assert!(
        record.is_canonical,
        "audit must expose canonicality status — original canonicality is preserved even after tombstoning"
    );
    assert!(record.is_tombstoned, "audit must expose tombstone status");
}

#[test]
fn audit_query_exposes_cascade_tombstoned_derived_handle_with_original_event_ref() {
    let mut core = HandleGraphCore::new();
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let a_event = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, a, HandleType::Suint256, a_event);
    seed_imported(&mut core, b, HandleType::Suint256, chain_event_ref(1, 1, 2));
    let derived = handle_key(1, 7, 10);
    let derived_event = chain_event_ref(1, 2, 1);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        derived_event,
    )));

    let _ = core.apply_orphan_discard(&[a_event]);

    let record = core
        .handle_record_for_audit(&derived)
        .expect("cascade-tombstoned derived must remain audit-inspectable");
    assert_eq!(
        record.event_ref, derived_event,
        "cascade tombstone must not rewrite the derived handle's original ChainEventRef"
    );
    assert!(record.is_tombstoned);
}

// ---------- Tombstoned records do not appear in Resolution Readiness via canonical paths ----------

#[test]
fn tombstoned_records_remain_inspectable_but_excluded_from_resolution_readiness() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core);
    let derived = handle_key(1, 7, 10);
    let derived_event = chain_event_ref(1, 2, 1);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        derived_event,
    )));
    assert_eq!(
        core.resolution_readiness().len(),
        1,
        "precondition: derived must be ready before tombstoning"
    );

    let _ = core.apply_orphan_discard(&[derived_event]);

    assert!(
        core.canonical_handle(&derived).is_none(),
        "tombstoned derived must be hidden from canonical query"
    );
    assert!(
        core.resolution_readiness().is_empty(),
        "tombstoned derived must not participate in Resolution Readiness"
    );
    let audit = core
        .handle_record_for_audit(&derived)
        .expect("tombstoned derived must remain inspectable via audit query");
    assert!(audit.is_tombstoned);
}

// ---------- Helpers (kept private to this test file; tests run against the
// public Handle Graph Core interface only). ----------

fn seed_suint_pair(core: &mut HandleGraphCore) -> (HandleKey, HandleKey) {
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    seed_imported(core, a, HandleType::Suint256, chain_event_ref(1, 1, 1));
    seed_imported(core, b, HandleType::Suint256, chain_event_ref(1, 1, 2));
    (a, b)
}

fn seed_imported(
    core: &mut HandleGraphCore,
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
) {
    let _ = expect_recorded(core.apply_chain_event(imported_event_with(
        handle_key,
        handle_type,
        event_ref,
        SystemCiphertextV1(vec![0x01]),
        MaterializationReceipt(vec![0x02]),
    )));
}

fn imported_event_with(
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

fn plaintext_event(
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
    public_value: PublicPlaintextValue,
) -> ChainEvent {
    ChainEvent::PlaintextHandle(PlaintextHandle {
        domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
        handle_key,
        handle_type,
        public_value,
        event_ref,
    })
}

fn derived_operation_event(
    handle_key: HandleKey,
    operation_code: OperationCode,
    output_handle_type: HandleType,
    input_handle_keys: Vec<HandleKey>,
    event_ref: ChainEventRef,
) -> ChainEvent {
    ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
        handle_key,
        operation_code,
        output_handle_type,
        input_handle_keys,
        event_ref,
    })
}

fn expect_recorded(outcome: IngestionOutcome) -> HandleRecord {
    match outcome {
        IngestionOutcome::Recorded(record) => record,
        other => panic!("expected Recorded, got {:?}", other),
    }
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
