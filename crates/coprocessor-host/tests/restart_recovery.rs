//! Coprocessor Host restart recovery tests for issue #34.
//!
//! These tests exercise rehydration at the host boundary: a persistence store
//! is populated through the Handle Graph's persisting APIs to simulate the
//! pre-restart state, then a fresh `CoprocessorHost` is constructed via
//! `restore_from_persistence` and the Coordinator-facing reads,
//! Resolution Readiness, and ingestion idempotence are asserted to behave as
//! if the in-memory Handle Graph Core had not been lost.
//!
//! Acceptance criteria (issue #34):
//!
//! - Startup rehydrates Handle Records, consumed ChainEventRefs, and tombstone
//!   state into the host-owned graph view.
//! - Resolution Readiness after restart matches readiness before restart.
//! - Unknown and tombstoned Handle Keys keep their normal API behavior.
//! - Tests cover Pending, Ready, Failed, and tombstoned records.

use coprocessor_enclave_runtime::AttestationDigest;
use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleGraphCore, HandleId, HandleKey, HandlePersistence, HandleRecord, HandleState, HandleType,
    ImportedHandle, InMemoryHandlePersistence, IngestionOutcome, MaterializationReceipt,
    OperationCode, ResolutionReadiness, SystemCiphertextV1,
};
use coprocessor_host::{
    CoprocessorHost, HandleStateFailureCategory, HandleStateView, HostConfig, LifecycleState,
};

const DEFAULT_DOMAIN: u8 = 9;

#[test]
fn restored_host_starts_in_not_started_and_starts_running() {
    let store = InMemoryHandlePersistence::new();
    let mut host =
        CoprocessorHost::restore_from_persistence(HostConfig::for_local_development(), &store);

    assert_eq!(host.lifecycle(), LifecycleState::NotStarted);
    host.start().expect("restored host must start cleanly");
    assert_eq!(host.lifecycle(), LifecycleState::Running);
}

#[test]
fn restored_host_serves_ready_record_via_get_handle_state() {
    let mut store = InMemoryHandlePersistence::new();
    let mut before_restart = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB]);
    record_event(
        &mut before_restart,
        &mut store,
        imported_event(
            key,
            HandleType::Suint256,
            chain_event_ref(1, 1, 1),
            ciphertext.clone(),
        ),
    );

    let host = boot_restored_host(&store);

    assert_eq!(
        host.get_handle_state(&key),
        HandleStateView::Ready {
            system_ciphertext: ciphertext,
            materialization_receipt: MaterializationReceipt(Vec::new()),
            derived_receipt: None,
        }
    );
}

#[test]
fn restored_host_serves_pending_derived_record_via_get_handle_state() {
    let mut store = InMemoryHandlePersistence::new();
    let mut before_restart = HandleGraphCore::new();
    let (a, b) = seed_imported_pair(&mut before_restart, &mut store);
    let derived = handle_key(1, 7, 3);
    record_event(
        &mut before_restart,
        &mut store,
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            chain_event_ref(1, 2, 1),
        ),
    );

    let host = boot_restored_host(&store);

    assert_eq!(host.get_handle_state(&derived), HandleStateView::Pending);
}

#[test]
fn restored_host_serves_failed_derived_record_with_stable_category() {
    let mut store = InMemoryHandlePersistence::new();
    let mut before_restart = HandleGraphCore::new();
    let (a, _) = seed_imported_pair(&mut before_restart, &mut store);
    let failed = handle_key(1, 7, 4);
    record_event(
        &mut before_restart,
        &mut store,
        derived_event(
            failed,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a],
            chain_event_ref(1, 2, 1),
        ),
    );

    let host = boot_restored_host(&store);

    assert_eq!(
        host.get_handle_state(&failed),
        HandleStateView::Failed {
            category: HandleStateFailureCategory::OperationViolation,
            reason: "wrong arity: expected 2, actual 1".to_string(),
        }
    );
}

#[test]
fn restored_host_hides_tombstoned_record_from_canonical_reads() {
    let mut store = InMemoryHandlePersistence::new();
    let mut before_restart = HandleGraphCore::new();
    let key = handle_key(1, 7, 5);
    let event_ref = chain_event_ref(1, 1, 1);
    record_event(
        &mut before_restart,
        &mut store,
        imported_event(
            key,
            HandleType::Suint256,
            event_ref,
            SystemCiphertextV1(vec![1]),
        ),
    );
    before_restart.apply_orphan_discard_with_persistence(&[event_ref], &mut store);

    let host = boot_restored_host(&store);

    assert_eq!(host.get_handle_state(&key), HandleStateView::Unknown);
}

#[test]
fn restored_host_reports_unknown_for_handle_keys_that_were_never_recorded() {
    let store = InMemoryHandlePersistence::new();
    let host = boot_restored_host(&store);

    let arbitrary = handle_key(1, 7, 99);
    assert_eq!(host.get_handle_state(&arbitrary), HandleStateView::Unknown);
}

#[test]
fn restored_host_resolution_readiness_matches_pre_restart_readiness() {
    let mut store = InMemoryHandlePersistence::new();
    let mut before_restart = HandleGraphCore::new();
    let (a, b) = seed_imported_pair(&mut before_restart, &mut store);
    let derived = handle_key(1, 7, 6);
    record_event(
        &mut before_restart,
        &mut store,
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            chain_event_ref(1, 2, 1),
        ),
    );
    let before = before_restart.resolution_readiness();
    assert_eq!(before.len(), 1, "precondition: derived should be ready");

    let host = boot_restored_host(&store);
    let after = host.handle_graph_core().resolution_readiness();

    assert_eq!(
        sort_by_handle_key(after),
        sort_by_handle_key(before),
        "readiness after restart must match readiness before restart for the same records"
    );
}

#[test]
fn restored_host_excludes_tombstoned_derived_from_resolution_readiness() {
    let mut store = InMemoryHandlePersistence::new();
    let mut before_restart = HandleGraphCore::new();
    let (a, b) = seed_imported_pair(&mut before_restart, &mut store);
    let a_event_ref = before_restart
        .canonical_handle(&a)
        .expect("seeded a record must be canonical")
        .event_ref;
    let derived = handle_key(1, 7, 7);
    record_event(
        &mut before_restart,
        &mut store,
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            chain_event_ref(1, 2, 1),
        ),
    );
    let outcome = before_restart.apply_orphan_discard_with_persistence(&[a_event_ref], &mut store);
    assert_eq!(
        outcome.cascade_tombstoned,
        vec![derived],
        "precondition: orphan discard must cascade through derived",
    );

    let host = boot_restored_host(&store);

    assert!(
        host.handle_graph_core().resolution_readiness().is_empty(),
        "tombstoned derived must not be ready after restart"
    );
}

#[test]
fn restored_host_replays_consumed_events_idempotently() {
    let mut store = InMemoryHandlePersistence::new();
    let mut before_restart = HandleGraphCore::new();
    let key = handle_key(1, 7, 8);
    let event_ref = chain_event_ref(1, 1, 1);
    let event = imported_event(
        key,
        HandleType::Suint256,
        event_ref,
        SystemCiphertextV1(vec![1, 2, 3]),
    );
    record_event(&mut before_restart, &mut store, event.clone());

    let mut host = boot_restored_host(&store);
    let replay = host.handle_graph_core_mut().apply_chain_event(event);

    assert!(
        matches!(replay, IngestionOutcome::Idempotent),
        "replay after restart must be Idempotent by ChainEventRef, got {replay:?}",
    );
}

#[test]
fn restored_host_audit_view_exposes_tombstoned_record_with_original_state() {
    let mut store = InMemoryHandlePersistence::new();
    let mut before_restart = HandleGraphCore::new();
    let key = handle_key(1, 7, 9);
    let event_ref = chain_event_ref(1, 1, 1);
    let ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB]);
    record_event(
        &mut before_restart,
        &mut store,
        imported_event(key, HandleType::Suint256, event_ref, ciphertext.clone()),
    );
    before_restart.apply_orphan_discard_with_persistence(&[event_ref], &mut store);

    let host = boot_restored_host(&store);

    let audit = host
        .handle_graph_core()
        .handle_record_for_audit(&key)
        .expect("audit must expose tombstoned record after restart");
    assert!(audit.is_tombstoned);
    assert_eq!(audit.event_ref, event_ref);
    assert_eq!(
        audit.state,
        HandleState::Ready {
            system_ciphertext: ciphertext,
            materialization_receipt: MaterializationReceipt(Vec::new()),
        }
    );
}

// ---------- issue #43: receipt rehydration tests ----------

#[test]
fn restored_host_ready_derived_handle_exposes_structured_receipt_after_restart() {
    // Build a Ready Derived Handle by materializing it directly using the
    // encoded receipt bytes (same format as resolve_enclave produces) and
    // persist through the store.
    let mut store = InMemoryHandlePersistence::new();
    let mut before_restart = HandleGraphCore::new();

    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let derived = handle_key(1, 7, 3);
    let attestation_digest = AttestationDigest([0x42; 32]);

    record_event(
        &mut before_restart,
        &mut store,
        imported_event(
            a,
            HandleType::Suint256,
            chain_event_ref(1, 1, 1),
            SystemCiphertextV1(vec![0xA1]),
        ),
    );
    record_event(
        &mut before_restart,
        &mut store,
        imported_event(
            b,
            HandleType::Suint256,
            chain_event_ref(1, 1, 2),
            SystemCiphertextV1(vec![0xB1]),
        ),
    );
    record_event(
        &mut before_restart,
        &mut store,
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            chain_event_ref(1, 2, 1),
        ),
    );

    let receipt = derived_receipt(OperationCode::Add, derived, &[a, b], attestation_digest);
    let ciphertext = SystemCiphertextV1(vec![0xCC; 16]);

    before_restart
        .materialize_derived_handle_with_persistence(
            &derived,
            ciphertext.clone(),
            receipt,
            &mut store,
        )
        .expect("materialize must succeed");

    // Restore and verify the structured receipt survives rehydration
    let host = boot_restored_host(&store);
    let view = host.get_handle_state(&derived);

    let HandleStateView::Ready {
        derived_receipt, ..
    } = view
    else {
        panic!("expected Ready after rehydration, got {view:?}");
    };
    let r = derived_receipt.expect("Derived Handle must have structured receipt after rehydration");
    assert_eq!(r.operation_code, OperationCode::Add);
    assert_eq!(r.output_handle_key, derived);
    assert_eq!(r.input_handle_keys, vec![a, b]);
    assert_eq!(r.attestation_digest, attestation_digest);
}

#[test]
fn restored_host_ready_derived_handle_persistence_contains_no_raw_attestation_doc() {
    // Assert that the persisted MaterializationReceipt contains only non-secret
    // evidence (OperationCode + Handle Keys + digest), not raw attestation docs.
    let mut store = InMemoryHandlePersistence::new();
    let mut before_restart = HandleGraphCore::new();

    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let derived = handle_key(1, 7, 3);

    record_event(
        &mut before_restart,
        &mut store,
        imported_event(
            a,
            HandleType::Suint256,
            chain_event_ref(1, 1, 1),
            SystemCiphertextV1(vec![0xA1]),
        ),
    );
    record_event(
        &mut before_restart,
        &mut store,
        imported_event(
            b,
            HandleType::Suint256,
            chain_event_ref(1, 1, 2),
            SystemCiphertextV1(vec![0xB1]),
        ),
    );
    record_event(
        &mut before_restart,
        &mut store,
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            chain_event_ref(1, 2, 1),
        ),
    );

    let attestation_digest = AttestationDigest([0x77; 32]);
    let receipt = derived_receipt(OperationCode::Add, derived, &[a, b], attestation_digest);
    let expected_receipt_len = 1 + 60 + 4 + 2 * 60 + 32;
    assert_eq!(
        receipt.0.len(),
        expected_receipt_len,
        "receipt must be minimal deterministic encoding with no raw attestation blob"
    );

    before_restart
        .materialize_derived_handle_with_persistence(
            &derived,
            SystemCiphertextV1(vec![0xCC; 16]),
            receipt,
            &mut store,
        )
        .expect("materialize");

    let restored = store
        .handle_record(&derived)
        .expect("persistence must contain the Ready derived record");
    if let HandleState::Ready {
        materialization_receipt,
        ..
    } = restored.state
    {
        assert_eq!(
            materialization_receipt.0.len(),
            expected_receipt_len,
            "persisted receipt must not include raw attestation document or EnclaveCiphertextV1"
        );
    } else {
        panic!("expected Ready state");
    }
}

fn boot_restored_host(store: &InMemoryHandlePersistence) -> CoprocessorHost {
    let mut host =
        CoprocessorHost::restore_from_persistence(HostConfig::for_local_development(), store);
    host.start().expect("restored host must start cleanly");
    host
}

fn seed_imported_pair(
    pre: &mut HandleGraphCore,
    store: &mut InMemoryHandlePersistence,
) -> (HandleKey, HandleKey) {
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    record_event(
        pre,
        store,
        imported_event(
            a,
            HandleType::Suint256,
            chain_event_ref(1, 1, 1),
            SystemCiphertextV1(vec![0xA1]),
        ),
    );
    record_event(
        pre,
        store,
        imported_event(
            b,
            HandleType::Suint256,
            chain_event_ref(1, 1, 2),
            SystemCiphertextV1(vec![0xB1]),
        ),
    );
    (a, b)
}

fn sort_by_handle_key(mut readiness: Vec<ResolutionReadiness>) -> Vec<ResolutionReadiness> {
    readiness.sort_by_key(|entry| {
        (
            entry.handle_key.chain_id.0,
            entry.handle_key.contract_address.0,
            entry.handle_key.handle_id.0,
        )
    });
    readiness
}

fn record_event(
    core: &mut HandleGraphCore,
    store: &mut InMemoryHandlePersistence,
    event: ChainEvent,
) -> HandleRecord {
    match core.apply_chain_event_with_persistence(event, store) {
        IngestionOutcome::Recorded(record) => record,
        other => panic!("expected recorded chain event, got {other:?}"),
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

fn derived_event(
    handle_key: HandleKey,
    operation_code: OperationCode,
    output_handle_type: HandleType,
    input_handle_keys: Vec<HandleKey>,
    event_ref: ChainEventRef,
) -> ChainEvent {
    ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key,
        operation_code,
        output_handle_type,
        input_handle_keys,
        event_ref,
    })
}

fn derived_receipt(
    operation_code: OperationCode,
    output_handle_key: HandleKey,
    input_handle_keys: &[HandleKey],
    attestation_digest: AttestationDigest,
) -> MaterializationReceipt {
    let mut bytes = Vec::new();
    bytes.push(op_code_byte(operation_code));
    encode_handle_key(&mut bytes, output_handle_key);
    let input_count =
        u32::try_from(input_handle_keys.len()).expect("fixture input count exceeds u32::MAX");
    bytes.extend_from_slice(&input_count.to_be_bytes());
    for input_handle_key in input_handle_keys {
        encode_handle_key(&mut bytes, *input_handle_key);
    }
    bytes.extend_from_slice(&attestation_digest.0);
    MaterializationReceipt(bytes)
}

fn encode_handle_key(bytes: &mut Vec<u8>, handle_key: HandleKey) {
    bytes.extend_from_slice(&handle_key.chain_id.0.to_be_bytes());
    bytes.extend_from_slice(&handle_key.contract_address.0);
    bytes.extend_from_slice(&handle_key.handle_id.0);
}

fn op_code_byte(operation_code: OperationCode) -> u8 {
    match operation_code {
        OperationCode::Add => 1,
        OperationCode::Sub => 2,
        OperationCode::Eq => 3,
        OperationCode::Lt => 4,
        OperationCode::Lte => 5,
        OperationCode::Gt => 6,
        OperationCode::Gte => 7,
        OperationCode::And => 8,
        OperationCode::Or => 9,
        OperationCode::Not => 10,
        OperationCode::Select => 11,
    }
}

fn handle_key(chain_id: u64, contract_seed: u8, handle_seed: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(chain_id),
        contract_address: ContractAddress([contract_seed; 20]),
        handle_id: HandleId([handle_seed; 32]),
    }
}

fn chain_event_ref(chain_id: u64, block_number: u64, log_index: u32) -> ChainEventRef {
    ChainEventRef {
        chain_id: ChainId(chain_id),
        block_number,
        block_hash: [11; 32],
        tx_hash: [12; 32],
        log_index,
    }
}
