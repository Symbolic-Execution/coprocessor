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

use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleGraphCore, HandleId, HandleKey, HandleType, ImportedHandle, InMemoryHandlePersistence,
    IngestionOutcome, MaterializationReceipt, OperationCode, SystemCiphertextV1,
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
    let mut pre = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB]);
    let receipt = MaterializationReceipt(vec![0xCC, 0xDD]);
    let _ = pre.apply_chain_event_with_persistence(
        imported_event(
            key,
            HandleType::Suint256,
            chain_event_ref(1, 1, 1),
            ciphertext.clone(),
            receipt.clone(),
        ),
        &mut store,
    );

    let host = boot_restored_host(&store);

    assert_eq!(
        host.get_handle_state(&key),
        HandleStateView::Ready {
            system_ciphertext: ciphertext,
            materialization_receipt: receipt,
        }
    );
}

#[test]
fn restored_host_serves_pending_derived_record_via_get_handle_state() {
    let mut store = InMemoryHandlePersistence::new();
    let mut pre = HandleGraphCore::new();
    let (a, b) = seed_imported_pair(&mut pre, &mut store);
    let derived = handle_key(1, 7, 3);
    let _ = pre.apply_chain_event_with_persistence(
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            chain_event_ref(1, 2, 1),
        ),
        &mut store,
    );

    let host = boot_restored_host(&store);

    assert_eq!(host.get_handle_state(&derived), HandleStateView::Pending);
}

#[test]
fn restored_host_serves_failed_derived_record_with_stable_category() {
    let mut store = InMemoryHandlePersistence::new();
    let mut pre = HandleGraphCore::new();
    let (a, _) = seed_imported_pair(&mut pre, &mut store);
    let failed = handle_key(1, 7, 4);
    let _ = pre.apply_chain_event_with_persistence(
        derived_event(
            failed,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a],
            chain_event_ref(1, 2, 1),
        ),
        &mut store,
    );

    let host = boot_restored_host(&store);

    assert_eq!(
        host.get_handle_state(&failed),
        HandleStateView::Failed {
            category: HandleStateFailureCategory::OperationViolation,
        }
    );
}

#[test]
fn restored_host_hides_tombstoned_record_from_canonical_reads() {
    let mut store = InMemoryHandlePersistence::new();
    let mut pre = HandleGraphCore::new();
    let key = handle_key(1, 7, 5);
    let event_ref = chain_event_ref(1, 1, 1);
    let _ = pre.apply_chain_event_with_persistence(
        imported_event(
            key,
            HandleType::Suint256,
            event_ref,
            SystemCiphertextV1(vec![1]),
            MaterializationReceipt(vec![2]),
        ),
        &mut store,
    );
    pre.apply_orphan_discard_with_persistence(&[event_ref], &mut store);

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
    let mut pre = HandleGraphCore::new();
    let (a, b) = seed_imported_pair(&mut pre, &mut store);
    let derived = handle_key(1, 7, 6);
    let _ = pre.apply_chain_event_with_persistence(
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            chain_event_ref(1, 2, 1),
        ),
        &mut store,
    );
    let before = pre.resolution_readiness();
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
    let mut pre = HandleGraphCore::new();
    let (a, b) = seed_imported_pair(&mut pre, &mut store);
    let a_event_ref = pre
        .canonical_handle(&a)
        .expect("seeded a record must be canonical")
        .event_ref;
    let derived = handle_key(1, 7, 7);
    let _ = pre.apply_chain_event_with_persistence(
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            chain_event_ref(1, 2, 1),
        ),
        &mut store,
    );
    let outcome = pre.apply_orphan_discard_with_persistence(&[a_event_ref], &mut store);
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
    let mut pre = HandleGraphCore::new();
    let key = handle_key(1, 7, 8);
    let event_ref = chain_event_ref(1, 1, 1);
    let event = imported_event(
        key,
        HandleType::Suint256,
        event_ref,
        SystemCiphertextV1(vec![1, 2, 3]),
        MaterializationReceipt(vec![4, 5, 6]),
    );
    let _ = pre.apply_chain_event_with_persistence(event.clone(), &mut store);

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
    let mut pre = HandleGraphCore::new();
    let key = handle_key(1, 7, 9);
    let event_ref = chain_event_ref(1, 1, 1);
    let ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB]);
    let receipt = MaterializationReceipt(vec![0xCC, 0xDD]);
    let _ = pre.apply_chain_event_with_persistence(
        imported_event(
            key,
            HandleType::Suint256,
            event_ref,
            ciphertext.clone(),
            receipt.clone(),
        ),
        &mut store,
    );
    pre.apply_orphan_discard_with_persistence(&[event_ref], &mut store);

    let host = boot_restored_host(&store);

    let audit = host
        .handle_graph_core()
        .handle_record_for_audit(&key)
        .expect("audit must expose tombstoned record after restart");
    assert!(audit.is_tombstoned);
    assert_eq!(audit.event_ref, event_ref);
    assert_eq!(
        audit.state,
        coprocessor_handle_graph_core::HandleState::Ready {
            system_ciphertext: ciphertext,
            materialization_receipt: receipt,
        }
    );
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
    let _ = pre.apply_chain_event_with_persistence(
        imported_event(
            a,
            HandleType::Suint256,
            chain_event_ref(1, 1, 1),
            SystemCiphertextV1(vec![0xA1]),
            MaterializationReceipt(vec![0xA2]),
        ),
        store,
    );
    let _ = pre.apply_chain_event_with_persistence(
        imported_event(
            b,
            HandleType::Suint256,
            chain_event_ref(1, 1, 2),
            SystemCiphertextV1(vec![0xB1]),
            MaterializationReceipt(vec![0xB2]),
        ),
        store,
    );
    (a, b)
}

fn sort_by_handle_key(
    mut readiness: Vec<coprocessor_handle_graph_core::ResolutionReadiness>,
) -> Vec<coprocessor_handle_graph_core::ResolutionReadiness> {
    readiness.sort_by_key(|entry| (entry.handle_key.chain_id.0, entry.handle_key.handle_id.0));
    readiness
}

fn imported_event(
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
    system_ciphertext: SystemCiphertextV1,
    materialization_receipt: MaterializationReceipt,
) -> ChainEvent {
    ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
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
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
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
