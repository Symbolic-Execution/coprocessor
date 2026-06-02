//! Persistence semantics for Handle Records and consumed Chain Events,
//! exercised through the domain-facing HandlePersistence interface.
//!
//! These tests cover the acceptance criteria of issue #32: canonical Pending,
//! Ready, and Failed Handle Records persist with their state-specific
//! payloads; consumed ChainEventRefs persist so ingestion replay remains
//! idempotent across restarts; Ready persists SystemCiphertextV1 and
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
fn imported_ready_handle_persists_with_system_ciphertext_and_materialization_receipt() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    let ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB, 0xCC]);
    let receipt = MaterializationReceipt(vec![0xDD, 0xEE]);

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

    let stored = store
        .handle_record(&key)
        .expect("imported handle should be persisted");
    assert_eq!(stored.handle_key, key);
    assert_eq!(stored.handle_type, HandleType::Suint256);
    assert_eq!(stored.event_ref, event_ref);
    assert!(stored.is_canonical);
    assert!(!stored.is_tombstoned);
    assert_eq!(stored.lineage, HandleLineage::Source);
    assert_eq!(
        stored.state,
        HandleState::Ready {
            system_ciphertext: ciphertext,
            materialization_receipt: receipt,
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
        MaterializationReceipt(vec![4, 5, 6]),
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
            MaterializationReceipt(vec![0xBB]),
        ),
        &mut store,
    ));
    let _ = expect_recorded(original.apply_chain_event_with_persistence(
        imported_event(
            other,
            HandleType::Suint256,
            chain_event_ref(1, 1, 2),
            SystemCiphertextV1(vec![0xCC]),
            MaterializationReceipt(vec![0xDD]),
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
        restored.canonical_handle(&imported).expect("imported").state,
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
            MaterializationReceipt(vec![2]),
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
            MaterializationReceipt(vec![2]),
        ),
        &mut store,
    ));

    let outcome = core.apply_chain_event_with_persistence(
        imported_event(
            key,
            HandleType::Suint256,
            second_event,
            SystemCiphertextV1(vec![9]),
            MaterializationReceipt(vec![8]),
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
            MaterializationReceipt(vec![2]),
        ),
        &mut store,
    ));
    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        imported_event(
            b,
            HandleType::Suint256,
            chain_event_ref(1, 1, 2),
            SystemCiphertextV1(vec![3]),
            MaterializationReceipt(vec![4]),
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
    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        imported_event(
            a,
            HandleType::Suint256,
            chain_event_ref(1, 1, a_seed as u32),
            SystemCiphertextV1(vec![1]),
            MaterializationReceipt(vec![2]),
        ),
        store,
    ));
    let _ = expect_recorded(core.apply_chain_event_with_persistence(
        imported_event(
            b,
            HandleType::Suint256,
            chain_event_ref(1, 1, b_seed as u32),
            SystemCiphertextV1(vec![3]),
            MaterializationReceipt(vec![4]),
        ),
        store,
    ));
    (a, b)
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
