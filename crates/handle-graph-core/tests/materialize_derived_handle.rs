//! Tests for `HandleGraphCore::materialize_derived_handle` and the
//! `_with_persistence` variant, exercising the Pending -> Ready transition
//! invariant owned by the core (issue #40).
//!
//! Acceptance criteria:
//! - A Pending Derived Handle transitions to Ready with the supplied
//!   SystemCiphertextV1 and MaterializationReceipt.
//! - Rejections for: UnknownHandle, Tombstoned, NotDerived (Source lineage),
//!   NotPending (already Ready).
//! - No state mutation on rejection.
//! - The _with_persistence variant persists the updated record so
//!   restore_from_persistence rehydrates Ready.

use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleGraphCore, HandleId, HandleKey, HandlePersistence, HandleState, HandleType,
    ImportedHandle, InMemoryHandlePersistence, IngestionOutcome, MaterializationReceipt,
    MaterializeDerivedError, OperationCode, SystemCiphertextV1,
};

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 7;
const DEFAULT_DOMAIN: u8 = 9;

#[test]
fn materialize_pending_derived_handle_transitions_to_ready() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core);
    let derived = handle_key(10);
    ingest_derived(
        &mut core,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );

    let system_ciphertext = SystemCiphertextV1(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let receipt = MaterializationReceipt(vec![0x01, 0x02, 0x03]);

    let record = core
        .materialize_derived_handle(&derived, system_ciphertext.clone(), receipt.clone())
        .expect("pending derived handle must materialize successfully");

    assert_eq!(record.handle_key, derived);
    assert_eq!(
        record.state,
        HandleState::Ready {
            system_ciphertext: system_ciphertext.clone(),
            materialization_receipt: receipt.clone(),
        }
    );

    let canonical = core
        .canonical_handle(&derived)
        .expect("canonical handle must be present after materialization");
    assert_eq!(
        canonical.state,
        HandleState::Ready {
            system_ciphertext,
            materialization_receipt: receipt,
        },
        "canonical_handle must reflect Ready after materialization"
    );
}

#[test]
fn materialize_unknown_handle_key_returns_error() {
    let mut core = HandleGraphCore::new();
    let unknown = handle_key(99);

    let err = core
        .materialize_derived_handle(
            &unknown,
            SystemCiphertextV1(vec![0xAA]),
            MaterializationReceipt(vec![0xBB]),
        )
        .expect_err("unknown handle key must return MaterializeDerivedError");

    assert_eq!(err, MaterializeDerivedError::UnknownHandle);
}

#[test]
fn materialize_tombstoned_handle_returns_error() {
    let mut core = HandleGraphCore::new();
    let a = handle_key(1);
    let ref1 = event_ref(1, 1);
    ingest_imported(
        &mut core,
        a,
        HandleType::Suint256,
        ref1,
        SystemCiphertextV1(vec![0xA1]),
    );
    core.apply_orphan_discard(&[ref1]);

    let err = core
        .materialize_derived_handle(
            &a,
            SystemCiphertextV1(vec![0xAA]),
            MaterializationReceipt(vec![0xBB]),
        )
        .expect_err("tombstoned handle must return MaterializeDerivedError");

    assert_eq!(err, MaterializeDerivedError::Tombstoned);
}

#[test]
fn materialize_non_canonical_handle_returns_unknown_without_mutation() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();
    let (a, b) = seed_suint_pair(&mut core);
    let derived = handle_key(10);
    let recorded = expect_recorded(core.apply_chain_event(ChainEvent::DerivedHandleOperation(
        DerivedHandleOperation {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key: derived,
            operation_code: OperationCode::Add,
            output_handle_type: HandleType::Suint256,
            input_handle_keys: vec![a, b],
            event_ref: event_ref(2, 1),
        },
    )));
    let mut non_canonical = recorded;
    non_canonical.is_canonical = false;
    store.put_handle_record(non_canonical);

    let mut restored = HandleGraphCore::restore_from_persistence(&store);
    assert!(
        restored.canonical_handle(&derived).is_none(),
        "non-canonical records must be hidden from canonical reads"
    );

    let err = restored
        .materialize_derived_handle(
            &derived,
            SystemCiphertextV1(vec![0xAA]),
            MaterializationReceipt(vec![0xBB]),
        )
        .expect_err("non-canonical handle must return MaterializeDerivedError");

    assert_eq!(err, MaterializeDerivedError::UnknownHandle);
    let audit = restored
        .handle_record_for_audit(&derived)
        .expect("non-canonical record remains audit-visible");
    assert_eq!(
        audit.state,
        HandleState::Pending,
        "state must not mutate on rejected materialization"
    );
}

#[test]
fn materialize_source_lineage_handle_returns_not_derived_error() {
    let mut core = HandleGraphCore::new();
    let a = handle_key(1);
    ingest_imported(
        &mut core,
        a,
        HandleType::Suint256,
        event_ref(1, 1),
        SystemCiphertextV1(vec![0xA1]),
    );

    let err = core
        .materialize_derived_handle(
            &a,
            SystemCiphertextV1(vec![0xAA]),
            MaterializationReceipt(vec![0xBB]),
        )
        .expect_err("source lineage handle must return NotDerived error");

    assert_eq!(err, MaterializeDerivedError::NotDerived);
}

#[test]
fn materialize_already_ready_handle_returns_not_pending_error_without_mutation() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core);
    let derived = handle_key(10);
    ingest_derived(
        &mut core,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );

    let first_ciphertext = SystemCiphertextV1(vec![0x11]);
    let first_receipt = MaterializationReceipt(vec![0x22]);
    core.materialize_derived_handle(&derived, first_ciphertext.clone(), first_receipt.clone())
        .expect("first materialization must succeed");

    let err = core
        .materialize_derived_handle(
            &derived,
            SystemCiphertextV1(vec![0xFF]),
            MaterializationReceipt(vec![0xEE]),
        )
        .expect_err("already-ready handle must return NotPending error");

    assert_eq!(err, MaterializeDerivedError::NotPending);

    let canonical = core.canonical_handle(&derived).unwrap();
    assert_eq!(
        canonical.state,
        HandleState::Ready {
            system_ciphertext: first_ciphertext,
            materialization_receipt: first_receipt,
        },
        "state must not mutate on rejected materialization"
    );
}

#[test]
fn materialize_with_persistence_writes_ready_record_rehydrated_after_restore() {
    let mut core = HandleGraphCore::new();
    let mut store = InMemoryHandlePersistence::new();

    let a = handle_key(1);
    let b = handle_key(2);
    let derived = handle_key(10);

    let _ = core.apply_chain_event_with_persistence(
        imported_event(
            a,
            HandleType::Suint256,
            event_ref(1, 1),
            SystemCiphertextV1(vec![0xA1]),
        ),
        &mut store,
    );
    let _ = core.apply_chain_event_with_persistence(
        imported_event(
            b,
            HandleType::Suint256,
            event_ref(1, 2),
            SystemCiphertextV1(vec![0xB2]),
        ),
        &mut store,
    );
    let _ = core.apply_chain_event_with_persistence(
        ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key: derived,
            operation_code: OperationCode::Add,
            output_handle_type: HandleType::Suint256,
            input_handle_keys: vec![a, b],
            event_ref: event_ref(2, 1),
        }),
        &mut store,
    );

    let system_ciphertext = SystemCiphertextV1(vec![0xDE, 0xAD]);
    let receipt = MaterializationReceipt(vec![0x01]);

    core.materialize_derived_handle_with_persistence(
        &derived,
        system_ciphertext.clone(),
        receipt.clone(),
        &mut store,
    )
    .expect("with_persistence materialization must succeed");

    drop(core);
    let restored = HandleGraphCore::restore_from_persistence(&store);

    let canonical = restored
        .canonical_handle(&derived)
        .expect("derived handle must exist after restore");
    assert_eq!(
        canonical.state,
        HandleState::Ready {
            system_ciphertext,
            materialization_receipt: receipt,
        },
        "restored core must reflect Ready state from persisted materialization"
    );
}

// ---------- fixtures ----------

fn seed_suint_pair(core: &mut HandleGraphCore) -> (HandleKey, HandleKey) {
    let a = handle_key(1);
    let b = handle_key(2);
    ingest_imported(
        core,
        a,
        HandleType::Suint256,
        event_ref(1, 1),
        SystemCiphertextV1(vec![0xA1]),
    );
    ingest_imported(
        core,
        b,
        HandleType::Suint256,
        event_ref(1, 2),
        SystemCiphertextV1(vec![0xB2]),
    );
    (a, b)
}

fn ingest_imported(
    core: &mut HandleGraphCore,
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
    system_ciphertext: SystemCiphertextV1,
) {
    let outcome = core.apply_chain_event(imported_event(
        handle_key,
        handle_type,
        event_ref,
        system_ciphertext,
    ));
    assert!(
        matches!(outcome, IngestionOutcome::Recorded(_)),
        "imported handle must be recorded"
    );
}

fn ingest_derived(
    core: &mut HandleGraphCore,
    handle_key: HandleKey,
    operation_code: OperationCode,
    output_handle_type: HandleType,
    input_handle_keys: Vec<HandleKey>,
    block_number: u64,
    log_index: u32,
) {
    let outcome =
        core.apply_chain_event(ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key,
            operation_code,
            output_handle_type,
            input_handle_keys,
            event_ref: event_ref(block_number, log_index),
        }));
    assert!(
        matches!(outcome, IngestionOutcome::Recorded(_)),
        "derived handle must be recorded"
    );
}

fn expect_recorded(outcome: IngestionOutcome) -> coprocessor_handle_graph_core::HandleRecord {
    match outcome {
        IngestionOutcome::Recorded(record) => record,
        other => panic!("expected Recorded outcome, got {other:?}"),
    }
}

fn imported_event(
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
    system_ciphertext: SystemCiphertextV1,
) -> ChainEvent {
    ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key,
        handle_type,
        system_ciphertext,
        event_ref,
    })
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
