//! Internal Coordinator API tests for Handle Resolution Request dedup.
//!
//! A Handle Resolution Request carries a `RequestId` that identifies the
//! request flow only — it is never the Handle Graph lookup key. Multiple
//! requests for the same Pending Derived Handle must collapse onto a single
//! resolution intent, and requests against Ready, Failed, or Unknown Handle
//! Keys must return the stable current state without registering one.
//!
//! The four acceptance criteria from issue #28:
//! - Repeated resolve requests for the same known Pending Derived Handle share
//!   one resolution intent.
//! - Repeated resolve requests for Ready and Failed handles return the stable
//!   current state.
//! - RequestId is treated as request-flow identity and never as the Handle
//!   lookup key.
//! - Tests cover duplicate RequestIds, distinct RequestIds for the same Handle
//!   Key, and distinct Handle Keys.

use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleRecord, HandleType, ImportedHandle, IngestionOutcome,
    MaterializationReceipt, OperationCode, SystemCiphertextV1,
};
use coprocessor_host::{
    CoprocessorHost, HandleStateFailureCategory, HandleStateView, HostConfig, RequestId,
    ResolutionIntent,
};

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 7;
const DEFAULT_DOMAIN: u8 = 9;

#[test]
fn duplicate_request_ids_for_same_pending_handle_share_one_intent() {
    let mut host = running_host();
    let pending = seed_pending_derived(&mut host);
    let request_id = request_id(0xA1);

    let first = host.resolve_handle(request_id, &pending);
    let second = host.resolve_handle(request_id, &pending);

    assert_eq!(first, HandleStateView::Pending);
    assert_eq!(second, HandleStateView::Pending);
    assert_eq!(
        host.pending_resolution_intent(&pending),
        Some(ResolutionIntent {
            handle_key: pending,
            attached_request_ids: vec![request_id],
        }),
    );
    assert_eq!(host.pending_resolution_intent_count(), 1);
}

#[test]
fn distinct_request_ids_for_same_pending_handle_share_one_intent() {
    let mut host = running_host();
    let pending = seed_pending_derived(&mut host);
    let request_a = request_id(0xA1);
    let request_b = request_id(0xB2);

    assert_eq!(
        host.resolve_handle(request_a, &pending),
        HandleStateView::Pending,
    );
    assert_eq!(
        host.resolve_handle(request_b, &pending),
        HandleStateView::Pending,
    );

    let intent = host
        .pending_resolution_intent(&pending)
        .expect("Pending Derived Handle must carry a resolution intent");
    assert_eq!(intent.handle_key, pending);
    assert_eq!(intent.attached_request_ids, vec![request_a, request_b]);
    assert_eq!(host.pending_resolution_intent_count(), 1);
}

#[test]
fn distinct_handle_keys_yield_distinct_intents() {
    let mut host = running_host();
    let pending_one = seed_pending_derived_at(&mut host, 10, default_event_ref(2, 1));
    let pending_two = seed_pending_derived_at(&mut host, 11, default_event_ref(2, 2));
    let request_a = request_id(0xA1);
    let request_b = request_id(0xB2);

    host.resolve_handle(request_a, &pending_one);
    host.resolve_handle(request_b, &pending_two);

    assert_eq!(
        host.pending_resolution_intent(&pending_one)
            .map(|i| i.attached_request_ids),
        Some(vec![request_a]),
    );
    assert_eq!(
        host.pending_resolution_intent(&pending_two)
            .map(|i| i.attached_request_ids),
        Some(vec![request_b]),
    );
    assert_eq!(host.pending_resolution_intent_count(), 2);
}

#[test]
fn same_request_id_against_distinct_handles_treats_request_id_as_request_flow_only() {
    let mut host = running_host();
    let pending_one = seed_pending_derived_at(&mut host, 10, default_event_ref(2, 1));
    let pending_two = seed_pending_derived_at(&mut host, 11, default_event_ref(2, 2));
    let shared = request_id(0xC3);

    host.resolve_handle(shared, &pending_one);
    host.resolve_handle(shared, &pending_two);

    // RequestId is request-flow identity, so the same RequestId may legitimately
    // appear in different Handle Resolution Requests. The Handle Key is what
    // identifies the resolution intent — both calls register intents against
    // their own Handle Key, never against the shared RequestId.
    assert_eq!(host.pending_resolution_intent_count(), 2);
    assert_eq!(
        host.pending_resolution_intent(&pending_one)
            .map(|i| i.attached_request_ids),
        Some(vec![shared]),
    );
    assert_eq!(
        host.pending_resolution_intent(&pending_two)
            .map(|i| i.attached_request_ids),
        Some(vec![shared]),
    );
}

#[test]
fn repeated_resolve_for_ready_handle_returns_stable_state_without_registering_intent() {
    let mut host = running_host();
    let key = default_handle_key(1);
    let ciphertext = SystemCiphertextV1(vec![0xAA, 0xBB]);
    let receipt = MaterializationReceipt(vec![0xCC]);
    ingest(
        &mut host,
        imported_event(
            key,
            HandleType::Suint256,
            ciphertext.clone(),
            receipt.clone(),
            default_event_ref(1, 1),
        ),
    );
    let expected = HandleStateView::Ready {
        system_ciphertext: ciphertext,
        materialization_receipt: receipt,
    };

    let first = host.resolve_handle(request_id(0xA1), &key);
    let second = host.resolve_handle(request_id(0xB2), &key);

    assert_eq!(first, expected);
    assert_eq!(second, expected);
    assert_eq!(host.pending_resolution_intent(&key), None);
    assert_eq!(host.pending_resolution_intent_count(), 0);
}

#[test]
fn repeated_resolve_for_failed_handle_returns_stable_state_without_registering_intent() {
    let mut host = running_host();
    let (a, _) = seed_suint_pair(&mut host);
    let failed = default_handle_key(11);
    ingest(
        &mut host,
        derived_event(
            failed,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a],
            default_event_ref(2, 2),
        ),
    );
    let expected = HandleStateView::Failed {
        category: HandleStateFailureCategory::OperationViolation,
    };

    let first = host.resolve_handle(request_id(0xA1), &failed);
    let second = host.resolve_handle(request_id(0xB2), &failed);

    assert_eq!(first, expected);
    assert_eq!(second, expected);
    assert_eq!(host.pending_resolution_intent(&failed), None);
    assert_eq!(host.pending_resolution_intent_count(), 0);
}

#[test]
fn repeated_resolve_for_unknown_handle_does_not_register_intent() {
    let mut host = running_host();
    let unknown = default_handle_key(99);

    assert_eq!(
        host.resolve_handle(request_id(0xA1), &unknown),
        HandleStateView::Unknown,
    );
    assert_eq!(
        host.resolve_handle(request_id(0xB2), &unknown),
        HandleStateView::Unknown,
    );

    assert_eq!(host.pending_resolution_intent(&unknown), None);
    assert_eq!(host.pending_resolution_intent_count(), 0);
    assert!(
        host.handle_graph_core()
            .canonical_handle(&unknown)
            .is_none(),
        "Resolve must not create a placeholder Canonical Handle Record"
    );
}

#[test]
fn resolve_handle_does_not_change_handle_graph_state_when_registering_intent() {
    let mut host = running_host();
    let pending = seed_pending_derived(&mut host);
    let readiness_before = host.handle_graph_core().resolution_readiness();
    let state_before = host.get_handle_state(&pending);

    host.resolve_handle(request_id(0xA1), &pending);
    host.resolve_handle(request_id(0xB2), &pending);

    assert_eq!(host.get_handle_state(&pending), state_before);
    assert_eq!(
        host.handle_graph_core().resolution_readiness(),
        readiness_before,
        "registering a resolution intent must not change Handle Graph state",
    );
}

// ---------- helpers ----------

fn running_host() -> CoprocessorHost {
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    host
}

fn seed_pending_derived(host: &mut CoprocessorHost) -> HandleKey {
    seed_pending_derived_at(host, 10, default_event_ref(2, 1))
}

fn seed_pending_derived_at(
    host: &mut CoprocessorHost,
    derived_seed: u8,
    event_ref: ChainEventRef,
) -> HandleKey {
    let (a, b) = seed_suint_pair(host);
    let derived = default_handle_key(derived_seed);
    ingest(
        host,
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![a, b],
            event_ref,
        ),
    );
    derived
}

fn seed_suint_pair(host: &mut CoprocessorHost) -> (HandleKey, HandleKey) {
    let a = default_handle_key(1);
    let b = default_handle_key(2);
    if host.handle_graph_core().canonical_handle(&a).is_none() {
        seed_imported(host, a, HandleType::Suint256, default_event_ref(1, 1));
    }
    if host.handle_graph_core().canonical_handle(&b).is_none() {
        seed_imported(host, b, HandleType::Suint256, default_event_ref(1, 2));
    }
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

fn ingest(host: &mut CoprocessorHost, event: ChainEvent) -> HandleRecord {
    match host.handle_graph_core_mut().apply_chain_event(event) {
        IngestionOutcome::Recorded(record) => record,
        other => panic!("expected recorded chain event, got {other:?}"),
    }
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

fn default_handle_key(handle_seed: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(DEFAULT_CHAIN),
        contract_address: ContractAddress([DEFAULT_CONTRACT_SEED; 20]),
        handle_id: HandleId([handle_seed; 32]),
    }
}

fn default_event_ref(block_number: u64, log_index: u32) -> ChainEventRef {
    ChainEventRef {
        chain_id: ChainId(DEFAULT_CHAIN),
        block_number,
        block_hash: [11u8; 32],
        tx_hash: [12u8; 32],
        log_index,
    }
}

fn request_id(seed: u8) -> RequestId {
    RequestId([seed; 32])
}
