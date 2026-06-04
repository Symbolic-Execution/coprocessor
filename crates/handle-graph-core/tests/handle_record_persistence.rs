//! Persistence semantics for Handle Records and consumed Chain Events,
//! exercised through the domain-facing HandlePersistence interface.
//!
//! These tests cover the acceptance criteria of issues #32 and #33: canonical
//! Pending, Ready, and Failed Handle Records persist with their state-specific
//! payloads; consumed ChainEventRefs persist so ingestion replay remains
//! idempotent across restarts; tombstoned records remain hidden from canonical
//! reads and visible to audit reads; Ready persists SystemCiphertextV1 and
//! Materialization Receipt (not plaintext Private Values); and the
//! domain-facing persistence interface is the test surface used here.

use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    FailureReason, HandleGraphCore, HandleId, HandleKey, HandleLineage, HandlePersistence,
    HandleRecord, HandleState, HandleType, ImportedHandle, InMemoryHandlePersistence,
    IngestionOutcome, MaterializationReceipt, OperationCode, OperationViolation, PlaintextHandle,
    PublicPlaintextValue, SystemCiphertextV1,
};

const DEFAULT_DOMAIN: u8 = 9;

#[test]
fn imported_ready_handle_persists_with_system_ciphertext_and_empty_receipt() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    let ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB, 0xCC]);

    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        imported_event(key, HandleType::Suint256, event_ref, ciphertext.clone()),
        &mut store,
    ));

    let stored = store
        .handle_record(&key)
        .expect("imported handle should be persisted");
    assert_eq!(stored.handle_key, key);
    assert_eq!(stored.handle_type, HandleType::Suint256);
    assert_eq!(stored.event_ref, event_ref);
    assert!(stored.is_canonical);
    assert!(!stored.is_tombstoned);
    assert_eq!(stored.lineage, HandleLineage::Source);
    // Per spec, imported handles carry an empty materialization receipt.
    assert_eq!(
        stored.state,
        HandleState::Ready {
            system_ciphertext: ciphertext,
            materialization_receipt: MaterializationReceipt(Vec::new()),
        }
    );
}

#[test]
fn plaintext_ready_handle_persists_with_system_ciphertext_and_materialization_receipt() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let key = handle_key(1, 7, 2);
    let event_ref = chain_event_ref(1, 1, 2);
    let public_value = PublicPlaintextValue(vec![0x01, 0x02]);

    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        ChainEvent::PlaintextHandle(PlaintextHandle {
            domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
            handle_key: key,
            handle_type: HandleType::Sbool,
            public_value,
            event_ref,
        }),
        &mut store,
    ));

    let stored = store
        .handle_record(&key)
        .expect("plaintext handle should be persisted");
    assert_eq!(stored.handle_type, HandleType::Sbool);
    assert_eq!(stored.event_ref, event_ref);
    match &stored.state {
        HandleState::Ready {
            system_ciphertext,
            materialization_receipt,
        } => {
            // The store must surface a SystemCiphertextV1 and Materialization
            // Receipt for the Plaintext source handle, not the raw
            // PublicPlaintextValue: per spec we never persist plaintext as
            // Private Value.
            assert!(!system_ciphertext.0.is_empty());
            assert!(!materialization_receipt.0.is_empty());
        }
        other => panic!("expected Ready plaintext source handle, got {:?}", other),
    }
}

#[test]
fn pending_derived_handle_persists_with_lineage_and_pending_state() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let (a, b) = seed_imported_suint_pair(&mut core, &mut store, 11, 12);
    let derived = handle_key(1, 7, 13);

    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            chain_event_ref(1, 2, 1),
        ),
        &mut store,
    ));

    let stored = store
        .handle_record(&derived)
        .expect("pending derived handle should persist");
    assert_eq!(stored.handle_type, HandleType::Suint256);
    assert_eq!(stored.state, HandleState::Pending);
    assert_eq!(
        stored.lineage,
        HandleLineage::Derived {
            operation_code: OperationCode::Add,
            input_handle_keys: vec![a, b],
        }
    );
}

#[test]
fn failed_derived_handle_persists_with_operation_violation_reason() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let (a, _) = seed_imported_suint_pair(&mut core, &mut store, 21, 22);
    let derived = handle_key(1, 7, 23);

    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a],
            chain_event_ref(1, 2, 1),
        ),
        &mut store,
    ));

    let stored = store
        .handle_record(&derived)
        .expect("failed derived handle should persist");
    assert!(matches!(
        stored.state,
        HandleState::Failed {
            reason: FailureReason::OperationViolation(OperationViolation::WrongArity {
                operation_code: OperationCode::Add,
                expected: 2,
                actual: 1,
            }),
        }
    ));
}

#[test]
fn consumed_chain_event_ref_persists_so_replay_is_idempotent_after_restart() {
    let mut original = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let key = handle_key(1, 7, 30);
    let event_ref = chain_event_ref(1, 1, 7);
    let event = imported_event(
        key,
        HandleType::Suint256,
        event_ref,
        SystemCiphertextV1(vec![1, 2, 3]),
    );

    let _ = expect_recorded(original.apply_chain_event_with_persistence(event.clone(), &mut store));
    assert!(store.is_consumed_event(&event_ref));

    drop(original);
    let mut restored = HandleGraphCore::restore_from_persistence(&store);

    let replay = restored.apply_chain_event_with_persistence(event, &mut store);
    assert!(
        matches!(replay, IngestionOutcome::Idempotent),
        "replay after restart must be Idempotent by ChainEventRef, got {:?}",
        replay,
    );
}

#[test]
fn restored_core_serves_canonical_records_for_pending_ready_and_failed_states() {
    let mut original = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();

    let imported = handle_key(1, 7, 40);
    let other = handle_key(1, 7, 41);
    let _ = expect_recorded(original.apply_chain_event_with_persistence(
        imported_event(
            imported,
            HandleType::Suint256,
            chain_event_ref(1, 1, 1),
            SystemCiphertextV1(vec![0xAA]),
        ),
        &mut store,
    ));
    let _ = expect_recorded(original.apply_chain_event_with_persistence(
        imported_event(
            other,
            HandleType::Suint256,
            chain_event_ref(1, 1, 2),
            SystemCiphertextV1(vec![0xCC]),
        ),
        &mut store,
    ));

    let pending = handle_key(1, 7, 42);
    let _ = expect_recorded(original.apply_chain_event_with_persistence(
        derived_event(
            pending,
            OperationCode::Add,
            HandleType::Suint256,
            vec![imported, other],
            chain_event_ref(1, 2, 1),
        ),
        &mut store,
    ));

    let failed = handle_key(1, 7, 43);
    let _ = expect_recorded(original.apply_chain_event_with_persistence(
        derived_event(
            failed,
            OperationCode::Add,
            HandleType::Suint256,
            vec![imported],
            chain_event_ref(1, 2, 2),
        ),
        &mut store,
    ));

    drop(original);
    let restored = HandleGraphCore::restore_from_persistence(&store);

    assert!(matches!(
        restored
            .canonical_handle(&imported)
            .expect("imported")
            .state,
        HandleState::Ready { .. }
    ));
    assert_eq!(
        restored.canonical_handle(&pending).expect("pending").state,
        HandleState::Pending,
    );
    assert!(matches!(
        restored.canonical_handle(&failed).expect("failed").state,
        HandleState::Failed { .. }
    ));
}

#[test]
fn tombstone_persists_and_canonical_reads_remain_hidden_after_restart() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let imported = handle_key(1, 7, 50);
    let imported_event_ref = chain_event_ref(1, 1, 1);
    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        imported_event(
            imported,
            HandleType::Suint256,
            imported_event_ref,
            SystemCiphertextV1(vec![1]),
        ),
        &mut store,
    ));

    core.apply_orphan_discard_with_persistence(&[imported_event_ref], &mut store);

    drop(core);
    let restored = HandleGraphCore::restore_from_persistence(&store);

    assert!(
        restored.canonical_handle(&imported).is_none(),
        "tombstoned Handle Record must not appear in canonical reads after restart"
    );
    let audit = restored
        .handle_record_for_audit(&imported)
        .expect("tombstoned record retained for audit after restart");
    assert!(audit.is_tombstoned);
    assert_eq!(audit.event_ref, imported_event_ref);
}

#[test]
fn cascade_tombstone_persists_and_remains_hidden_from_canonical_reads_after_restart() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let a = handle_key(1, 7, 100);
    let b = handle_key(1, 7, 101);
    let a_event_ref = chain_event_ref(1, 1, 1);
    let derived = handle_key(1, 7, 102);

    record_imported_suint(
        &mut core,
        &mut store,
        a,
        a_event_ref,
        SystemCiphertextV1(vec![1]),
    );
    record_imported_suint(
        &mut core,
        &mut store,
        b,
        chain_event_ref(1, 1, 2),
        SystemCiphertextV1(vec![3]),
    );
    record_pending_add(
        &mut core,
        &mut store,
        derived,
        vec![a, b],
        chain_event_ref(1, 2, 1),
    );

    let outcome = core.apply_orphan_discard_with_persistence(&[a_event_ref], &mut store);
    assert_eq!(outcome.directly_tombstoned, vec![a]);
    assert_eq!(
        outcome.cascade_tombstoned,
        vec![derived],
        "precondition: orphan discard must cascade through derived handle"
    );

    drop(core);
    let restored = HandleGraphCore::restore_from_persistence(&store);

    assert!(
        restored.canonical_handle(&a).is_none(),
        "directly-tombstoned source must remain hidden from canonical reads after restart"
    );
    assert!(
        restored.canonical_handle(&derived).is_none(),
        "cascade-tombstoned derived must remain hidden from canonical reads after restart"
    );
    let audit_a = restored
        .handle_record_for_audit(&a)
        .expect("directly-tombstoned source retained for audit after restart");
    assert!(audit_a.is_tombstoned);
    let audit_derived = restored
        .handle_record_for_audit(&derived)
        .expect("cascade-tombstoned derived retained for audit after restart");
    assert!(
        audit_derived.is_tombstoned,
        "cascade tombstone flag must be persisted"
    );
}

#[test]
fn tombstoned_record_audit_preserves_chain_event_ref_lineage_and_state_after_restart() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let a = handle_key(1, 7, 110);
    let b = handle_key(1, 7, 111);
    let a_event_ref = chain_event_ref(1, 1, 1);
    let imported_ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB]);
    let derived = handle_key(1, 7, 112);
    let derived_event_ref = chain_event_ref(1, 2, 1);

    record_imported_suint(
        &mut core,
        &mut store,
        a,
        a_event_ref,
        imported_ciphertext.clone(),
    );
    record_imported_suint(
        &mut core,
        &mut store,
        b,
        chain_event_ref(1, 1, 2),
        SystemCiphertextV1(vec![3]),
    );
    record_pending_add(
        &mut core,
        &mut store,
        derived,
        vec![a, b],
        derived_event_ref,
    );

    let _ = core.apply_orphan_discard_with_persistence(&[a_event_ref], &mut store);

    drop(core);
    let restored = HandleGraphCore::restore_from_persistence(&store);

    let audit_a = restored
        .handle_record_for_audit(&a)
        .expect("audit must expose directly-tombstoned source after restart");
    assert_eq!(
        audit_a.event_ref, a_event_ref,
        "audit must preserve original ChainEventRef after restart"
    );
    assert_eq!(
        audit_a.lineage,
        HandleLineage::Source,
        "audit must preserve original lineage after restart"
    );
    assert_eq!(
        audit_a.state,
        HandleState::Ready {
            system_ciphertext: imported_ciphertext,
            materialization_receipt: MaterializationReceipt(Vec::new()),
        },
        "audit must preserve original Handle State after restart"
    );
    assert!(audit_a.is_tombstoned);

    let audit_derived = restored
        .handle_record_for_audit(&derived)
        .expect("audit must expose cascade-tombstoned derived after restart");
    assert_eq!(
        audit_derived.event_ref, derived_event_ref,
        "audit must preserve derived's original ChainEventRef after restart"
    );
    assert_eq!(
        audit_derived.lineage,
        HandleLineage::Derived {
            operation_code: OperationCode::Add,
            input_handle_keys: vec![a, b],
        },
        "audit must preserve derived lineage after restart"
    );
    assert_eq!(
        audit_derived.state,
        HandleState::Pending,
        "audit must preserve derived's original Handle State after restart"
    );
    assert!(audit_derived.is_tombstoned);
}

#[test]
fn duplicate_rejected_record_is_not_persisted_but_event_is_marked_consumed() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let key = handle_key(1, 7, 60);
    let first_event = chain_event_ref(1, 1, 1);
    let second_event = chain_event_ref(1, 1, 2);

    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        imported_event(
            key,
            HandleType::Suint256,
            first_event,
            SystemCiphertextV1(vec![1]),
        ),
        &mut store,
    ));

    let outcome = core.apply_chain_event_with_persistence(
        imported_event(
            key,
            HandleType::Suint256,
            second_event,
            SystemCiphertextV1(vec![9]),
        ),
        &mut store,
    );
    assert!(matches!(
        outcome,
        IngestionOutcome::DuplicateHandleKeyRejected(_)
    ));

    let stored = store
        .handle_record(&key)
        .expect("first canonical record preserved");
    assert_eq!(stored.event_ref, first_event);
    assert!(
        store.is_consumed_event(&second_event),
        "rejected duplicate event must still be marked consumed so restart replay is idempotent"
    );
}

#[test]
fn handle_records_listing_returns_all_persisted_records() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let a = handle_key(1, 7, 70);
    let b = handle_key(1, 7, 71);
    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        imported_event(
            a,
            HandleType::Suint256,
            chain_event_ref(1, 1, 1),
            SystemCiphertextV1(vec![1]),
        ),
        &mut store,
    ));
    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        imported_event(
            b,
            HandleType::Suint256,
            chain_event_ref(1, 1, 2),
            SystemCiphertextV1(vec![3]),
        ),
        &mut store,
    ));

    let records = store.handle_records();
    let keys: std::collections::HashSet<HandleKey> =
        records.iter().map(|record| record.handle_key).collect();
    assert!(keys.contains(&a));
    assert!(keys.contains(&b));
    assert_eq!(records.len(), 2);
}

fn seed_imported_suint_pair(
    core: &mut HandleGraphCore,
    store: &mut InMemoryHandlePersistence,
    a_seed: u8,
    b_seed: u8,
) -> (HandleKey, HandleKey) {
    let a = handle_key(1, 7, a_seed);
    let b = handle_key(1, 7, b_seed);
    record_imported_suint(
        core,
        store,
        a,
        chain_event_ref(1, 1, a_seed as u32),
        SystemCiphertextV1(vec![1]),
    );
    record_imported_suint(
        core,
        store,
        b,
        chain_event_ref(1, 1, b_seed as u32),
        SystemCiphertextV1(vec![3]),
    );
    (a, b)
}

fn record_imported_suint(
    core: &mut HandleGraphCore,
    store: &mut InMemoryHandlePersistence,
    handle_key: HandleKey,
    event_ref: ChainEventRef,
    system_ciphertext: SystemCiphertextV1,
) {
    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        imported_event(handle_key, HandleType::Suint256, event_ref, system_ciphertext),
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
        derived_event(
            handle_key,
            OperationCode::Add,
            HandleType::Suint256,
            input_handle_keys,
            event_ref,
        ),
        store,
    ));
}

fn expect_recorded(outcome: IngestionOutcome) -> HandleRecord {
    match outcome {
        IngestionOutcome::Recorded(record) => record,
        other => panic!("expected Recorded, got {:?}", other),
    }
}

fn imported_event(
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
    system_ciphertext: SystemCiphertextV1,
) -> ChainEvent {
    ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
        handle_key,
        handle_type,
        system_ciphertext,
        event_ref,
    })
}

fn derived_event(
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
