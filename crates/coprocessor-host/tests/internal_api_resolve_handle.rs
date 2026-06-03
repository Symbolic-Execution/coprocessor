//! Internal Coordinator API tests for the Resolve Handle Request read path
//! against the current Handle Graph state.
//!
//! This slice of the Resolve Handle Request returns the current Handle State
//! for already-known Canonical Handle Records, mirroring the GET Handle State
//! response shape. It does not create placeholder Handle Records, does not
//! schedule Resolution work, and must never mutate the Handle Graph by itself,
//! even when called repeatedly against unknown or tombstoned Handle Keys.
//!
//! The four acceptance criteria from issue #27:
//! - Resolve returns Pending, Ready, or Failed for known Canonical Handle
//!   Records using the same projection as GET Handle State.
//! - Resolve for an unknown Handle Key returns Unknown and does not create a
//!   Handle Record (no placeholder appears for canonical or audit reads).
//! - Resolve for a tombstoned Handle Key collapses to Unknown.
//! - A Resolve Handle Request must not change Handle Graph state by itself.

use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleRecord, HandleType, ImportedHandle, IngestionOutcome,
    MaterializationReceipt, OperationCode, SystemCiphertextV1,
};
use coprocessor_host::{
    CoprocessorHost, HandleStateFailureCategory, HandleStateView, HostConfig, RequestId,
};

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 7;
const DEFAULT_DOMAIN: u8 = 9;
const DEFAULT_REQUEST_SEED: u8 = 0xA1;

#[test]
fn resolve_handle_returns_unknown_for_unknown_handle_key() {
    let mut host = running_host();
    let unknown = default_handle_key(99);

    assert_eq!(
        host.resolve_handle(default_request_id(), &unknown),
        HandleStateView::Unknown,
    );
}

#[test]
fn resolve_handle_returns_ready_with_ciphertext_and_receipt_for_imported_handle() {
    let mut host = running_host();
    let key = default_handle_key(1);
    let ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB, 0xCC]);
    let receipt = MaterializationReceipt(vec![0xDD, 0xEE]);
    let expected = HandleStateView::Ready {
        system_ciphertext: ciphertext.clone(),
        materialization_receipt: receipt.clone(),
    };
    ingest(
        &mut host,
        imported_event(
            key,
            HandleType::Suint256,
            ciphertext,
            receipt,
            default_event_ref(1, 1),
        ),
    );

    assert_eq!(host.resolve_handle(default_request_id(), &key), expected);
}

#[test]
fn resolve_handle_returns_pending_for_canonical_pending_derived_handle() {
    let mut host = running_host();
    let (a, b) = seed_suint_pair(&mut host);
    let derived = default_handle_key(10);
    ingest(
        &mut host,
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            default_event_ref(2, 1),
        ),
    );

    assert_eq!(
        host.resolve_handle(default_request_id(), &derived),
        HandleStateView::Pending,
    );
}

#[test]
fn resolve_handle_returns_failed_with_lineage_violation_category_for_unknown_input_handle() {
    let mut host = running_host();
    let known = default_handle_key(1);
    seed_imported(
        &mut host,
        known,
        HandleType::Suint256,
        default_event_ref(1, 1),
    );
    let derived = default_handle_key(10);
    ingest(
        &mut host,
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![known, default_handle_key(77)],
            default_event_ref(2, 1),
        ),
    );

    assert_eq!(
        host.resolve_handle(default_request_id(), &derived),
        HandleStateView::Failed {
            category: HandleStateFailureCategory::LineageViolation,
            reason: "unknown input handle".to_string(),
        },
    );
}

#[test]
fn resolve_handle_returns_failed_with_operation_violation_category_for_wrong_arity() {
    let mut host = running_host();
    let (a, _) = seed_suint_pair(&mut host);
    let derived = default_handle_key(11);
    ingest(
        &mut host,
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a],
            default_event_ref(2, 2),
        ),
    );

    assert_eq!(
        host.resolve_handle(default_request_id(), &derived),
        HandleStateView::Failed {
            category: HandleStateFailureCategory::OperationViolation,
            reason: "wrong arity: expected 2, actual 1".to_string(),
        },
    );
}

#[test]
fn resolve_handle_returns_unknown_for_tombstoned_source_handle() {
    let mut host = running_host();
    let key = default_handle_key(1);
    let event_ref = default_event_ref(1, 1);
    seed_imported(&mut host, key, HandleType::Suint256, event_ref);
    assert!(matches!(
        host.resolve_handle(default_request_id(), &key),
        HandleStateView::Ready { .. }
    ));

    let _ = host
        .handle_graph_core_mut()
        .apply_orphan_discard(&[event_ref]);

    assert_eq!(
        host.resolve_handle(default_request_id(), &key),
        HandleStateView::Unknown,
        "tombstoned record must collapse to Unknown on the Resolve Handle Request path"
    );
}

#[test]
fn resolve_handle_for_unknown_key_does_not_create_handle_record() {
    let mut host = running_host();
    let unknown = default_handle_key(99);

    let _ = host.resolve_handle(default_request_id(), &unknown);
    let _ = host.resolve_handle(default_request_id(), &unknown);

    assert!(
        host.handle_graph_core()
            .canonical_handle(&unknown)
            .is_none(),
        "Resolve must not create a placeholder Canonical Handle Record"
    );
    assert!(
        host.handle_graph_core()
            .handle_record_for_audit(&unknown)
            .is_none(),
        "Resolve must not create any Handle Record, even a tombstoned one for audit"
    );
}

#[test]
fn resolve_handle_does_not_change_handle_graph_state_for_known_records() {
    let mut host = running_host();
    let (a, b) = seed_suint_pair(&mut host);
    let pending_derived = default_handle_key(10);
    ingest(
        &mut host,
        derived_event(
            pending_derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            default_event_ref(2, 1),
        ),
    );
    let failed_derived = default_handle_key(11);
    ingest(
        &mut host,
        derived_event(
            failed_derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a],
            default_event_ref(2, 2),
        ),
    );
    let unknown = default_handle_key(99);
    let observed_keys = [a, b, pending_derived, failed_derived, unknown];

    let snapshot_before = handle_state_snapshot(&host, &observed_keys);
    let readiness_before = host.handle_graph_core().resolution_readiness();

    for key in &observed_keys {
        let _ = host.resolve_handle(default_request_id(), key);
        let _ = host.resolve_handle(default_request_id(), key);
    }

    let snapshot_after = handle_state_snapshot(&host, &observed_keys);
    let readiness_after = host.handle_graph_core().resolution_readiness();

    assert_eq!(
        snapshot_before, snapshot_after,
        "Resolve Handle Requests must not move any Handle State"
    );
    assert_eq!(
        readiness_before, readiness_after,
        "Resolve Handle Requests must not change Resolution Readiness"
    );
}

#[test]
fn resolve_handle_matches_get_handle_state_across_known_and_unknown_keys() {
    let mut host = running_host();
    let (a, b) = seed_suint_pair(&mut host);
    let derived = default_handle_key(10);
    ingest(
        &mut host,
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            default_event_ref(2, 1),
        ),
    );
    let unknown = default_handle_key(99);

    for key in [&a, &b, &derived, &unknown] {
        let projected = host.get_handle_state(key);
        let resolved = host.resolve_handle(default_request_id(), key);
        assert_eq!(
            resolved, projected,
            "Resolve must project the same Handle State view as GET for {key:?}"
        );
    }
}

// ---------- helpers ----------

fn running_host() -> CoprocessorHost {
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    host
}

fn ingest(host: &mut CoprocessorHost, event: ChainEvent) -> HandleRecord {
    match host.handle_graph_core_mut().apply_chain_event(event) {
        IngestionOutcome::Recorded(record) => record,
        other => panic!("expected recorded chain event, got {other:?}"),
    }
}

fn seed_suint_pair(host: &mut CoprocessorHost) -> (HandleKey, HandleKey) {
    let a = default_handle_key(1);
    let b = default_handle_key(2);
    seed_imported(host, a, HandleType::Suint256, default_event_ref(1, 1));
    seed_imported(host, b, HandleType::Suint256, default_event_ref(1, 2));
    (a, b)
}

fn seed_imported(
    host: &mut CoprocessorHost,
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
) {
    ingest(
        host,
        imported_event(
            handle_key,
            handle_type,
            SystemCiphertextV1(vec![0x01]),
            MaterializationReceipt(vec![0x02]),
            event_ref,
        ),
    );
}

fn imported_event(
    handle_key: HandleKey,
    handle_type: HandleType,
    system_ciphertext: SystemCiphertextV1,
    materialization_receipt: MaterializationReceipt,
    event_ref: ChainEventRef,
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

fn handle_state_snapshot(
    host: &CoprocessorHost,
    handle_keys: &[HandleKey],
) -> Vec<HandleStateView> {
    handle_keys
        .iter()
        .map(|handle_key| host.get_handle_state(handle_key))
        .collect()
}

fn default_handle_key(handle_seed: u8) -> HandleKey {
    handle_key(DEFAULT_CHAIN, DEFAULT_CONTRACT_SEED, handle_seed)
}

fn handle_key(chain_id: u64, contract_seed: u8, handle_seed: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(chain_id),
        contract_address: ContractAddress([contract_seed; 20]),
        handle_id: HandleId([handle_seed; 32]),
    }
}

fn default_event_ref(block_number: u64, log_index: u32) -> ChainEventRef {
    chain_event_ref(DEFAULT_CHAIN, block_number, log_index)
}

fn default_request_id() -> RequestId {
    RequestId([DEFAULT_REQUEST_SEED; 32])
}

fn chain_event_ref(chain_id: u64, block_number: u64, log_index: u32) -> ChainEventRef {
    ChainEventRef {
        chain_id: ChainId(chain_id),
        block_number,
        block_hash: [11u8; 32],
        tx_hash: [12u8; 32],
        log_index,
    }
}
