//! Internal Coordinator API tests for the GET Handle State read path.
//!
//! The Internal Coordinator API is the Coprocessor's backend surface used by
//! the Coordinator to fetch Canonical Handle Records. This test file exercises
//! the read path through the public host interface and drives setup through
//! the host-owned Handle Graph Core. Handle State, payload visibility, and the
//! unknown/tombstoned collapse must all be observable from the
//! Coordinator-facing surface.
//!
//! The four acceptance criteria from issue #26:
//! - Pending Canonical Handle Records read back as `Pending`.
//! - Ready Canonical Handle Records read back as `Ready` carrying both
//!   `SystemCiphertextV1` and the Materialization Receipt.
//! - Failed Canonical Handle Records read back as `Failed` with a stable
//!   non-secret category, never with raw failure detail strings or plaintext.
//! - Unknown Handle Keys and tombstoned Handle Records both read back as
//!   `Unknown` — the read path must not invent a Pending placeholder.

use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleRecord, HandleType, ImportedHandle, IngestionOutcome,
    MaterializationReceipt, OperationCode, SystemCiphertextV1,
};
use coprocessor_host::{CoprocessorHost, HandleStateFailureCategory, HandleStateView, HostConfig};

const DEFAULT_DOMAIN: u8 = 9;

#[test]
fn get_handle_state_returns_unknown_for_unknown_handle_key() {
    let host = running_host();
    let unknown = handle_key(1, 7, 99);

    assert_eq!(host.get_handle_state(&unknown), HandleStateView::Unknown);
}

#[test]
fn get_handle_state_returns_ready_with_ciphertext_and_receipt_for_imported_handle() {
    let mut host = running_host();
    let key = handle_key(1, 7, 1);
    let ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB, 0xCC]);
    let receipt = MaterializationReceipt(vec![0xDD, 0xEE]);
    ingest(
        &mut host,
        ChainEvent::ImportedHandle(ImportedHandle {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key: key,
            handle_type: HandleType::Suint256,
            system_ciphertext: ciphertext.clone(),
            materialization_receipt: receipt.clone(),
            event_ref: chain_event_ref(1, 1, 1),
        }),
    );

    match host.get_handle_state(&key) {
        HandleStateView::Ready {
            system_ciphertext,
            materialization_receipt,
        } => {
            assert_eq!(system_ciphertext, ciphertext);
            assert_eq!(materialization_receipt, receipt);
        }
        other => panic!("expected Ready view, got {other:?}"),
    }
}

#[test]
fn get_handle_state_returns_pending_for_canonical_pending_derived_handle() {
    let mut host = running_host();
    let (a, b) = seed_suint_pair(&mut host);
    let derived = handle_key(1, 7, 10);
    ingest(
        &mut host,
        ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key: derived,
            operation_code: OperationCode::Add,
            output_handle_type: HandleType::Suint256,
            input_handle_keys: vec![a, b],
            event_ref: chain_event_ref(1, 2, 1),
        }),
    );

    assert_eq!(host.get_handle_state(&derived), HandleStateView::Pending);
}

#[test]
fn get_handle_state_returns_failed_with_lineage_violation_category_for_unknown_input_handle() {
    let mut host = running_host();
    let known = handle_key(1, 7, 1);
    seed_imported(
        &mut host,
        known,
        HandleType::Suint256,
        chain_event_ref(1, 1, 1),
    );
    let derived = handle_key(1, 7, 10);
    ingest(
        &mut host,
        ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key: derived,
            operation_code: OperationCode::Add,
            output_handle_type: HandleType::Suint256,
            input_handle_keys: vec![known, handle_key(1, 7, 77)],
            event_ref: chain_event_ref(1, 2, 1),
        }),
    );

    assert_eq!(
        host.get_handle_state(&derived),
        HandleStateView::Failed {
            category: HandleStateFailureCategory::LineageViolation,
            reason: "unknown input handle".to_string(),
        },
    );
}

#[test]
fn get_handle_state_returns_failed_with_operation_violation_category_for_wrong_arity() {
    let mut host = running_host();
    let (a, _) = seed_suint_pair(&mut host);
    let derived = handle_key(1, 7, 11);
    ingest(
        &mut host,
        ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key: derived,
            operation_code: OperationCode::Add,
            output_handle_type: HandleType::Suint256,
            input_handle_keys: vec![a],
            event_ref: chain_event_ref(1, 2, 2),
        }),
    );

    assert_eq!(
        host.get_handle_state(&derived),
        HandleStateView::Failed {
            category: HandleStateFailureCategory::OperationViolation,
            reason: "wrong arity: expected 2, actual 1".to_string(),
        },
    );
}

#[test]
fn get_handle_state_returns_unknown_for_tombstoned_source_handle() {
    let mut host = running_host();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    seed_imported(&mut host, key, HandleType::Suint256, event_ref);
    assert!(matches!(
        host.get_handle_state(&key),
        HandleStateView::Ready { .. }
    ));

    let _ = host
        .handle_graph_core_mut()
        .apply_orphan_discard(&[event_ref]);

    assert_eq!(
        host.get_handle_state(&key),
        HandleStateView::Unknown,
        "tombstoned record must collapse to Unknown, not Pending or its prior state"
    );
}

#[test]
fn get_handle_state_returns_unknown_for_cascade_tombstoned_derived_handle() {
    let mut host = running_host();
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let a_event = chain_event_ref(1, 1, 1);
    seed_imported(&mut host, a, HandleType::Suint256, a_event);
    seed_imported(&mut host, b, HandleType::Suint256, chain_event_ref(1, 1, 2));
    let derived = handle_key(1, 7, 10);
    ingest(
        &mut host,
        ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key: derived,
            operation_code: OperationCode::Add,
            output_handle_type: HandleType::Suint256,
            input_handle_keys: vec![a, b],
            event_ref: chain_event_ref(1, 2, 1),
        }),
    );
    assert_eq!(host.get_handle_state(&derived), HandleStateView::Pending);

    let _ = host
        .handle_graph_core_mut()
        .apply_orphan_discard(&[a_event]);

    assert_eq!(host.get_handle_state(&derived), HandleStateView::Unknown);
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
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    seed_imported(host, a, HandleType::Suint256, chain_event_ref(1, 1, 1));
    seed_imported(host, b, HandleType::Suint256, chain_event_ref(1, 1, 2));
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
        ChainEvent::ImportedHandle(ImportedHandle {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key,
            handle_type,
            system_ciphertext: SystemCiphertextV1(vec![0x01]),
            materialization_receipt: MaterializationReceipt(vec![0x02]),
            event_ref,
        }),
    );
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
        block_hash: [11u8; 32],
        tx_hash: [12u8; 32],
        log_index,
    }
}
