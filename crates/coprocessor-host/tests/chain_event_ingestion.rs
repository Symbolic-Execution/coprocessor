//! Chain Event Ingestion tests.
//!
//! These tests drive the public ingestion seam: a [`ChainEventSource`] supplies
//! decoded Chain Events, and the host pulls, orders, and applies them to its
//! Handle Graph Core idempotently.

use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleState, HandleType, ImportedHandle, MaterializationReceipt,
    OperationCode, SystemCiphertextV1,
};
use coprocessor_host::{
    ChainEventSource, ChainView, ChainViewPoll, CoprocessorHost, HostConfig, IngestionReport,
};

const TEST_CHAIN: ChainId = ChainId(1);
const TEST_CONTRACT: ContractAddress = ContractAddress([0x77; 20]);
const TEST_DOMAIN: DomainId = DomainId([0xD0; 32]);

#[test]
fn chain_view_defaults_to_safe() {
    assert_eq!(ChainView::default(), ChainView::Safe);
    assert_eq!(
        HostConfig::for_local_development().chain_view,
        ChainView::Safe,
    );
}

#[test]
fn host_can_be_configured_for_finalized_chain_view() {
    let mut config = HostConfig::for_local_development();
    config.chain_view = ChainView::Finalized;
    let host = CoprocessorHost::new(config);
    assert_eq!(host.config().chain_view, ChainView::Finalized);
}

#[test]
fn ingestion_polls_the_source_at_the_configured_chain_view() {
    let mut config = HostConfig::for_local_development();
    config.chain_view = ChainView::Finalized;
    let mut host = started_host(config);

    let mut source = FakeChainSource::default();
    host.ingest_chain_events(&mut source);

    assert_eq!(source.poll_views, vec![ChainView::Finalized]);
}

#[test]
fn ingestion_sorts_events_into_canonical_log_order_before_applying() {
    let input_key = handle_key(0xAA);
    let derived_key = handle_key(0xBB);

    let imported = imported_event(input_key, 100, 0);
    let derived = derived_event(
        derived_key,
        OperationCode::Not,
        HandleType::Sbool,
        vec![input_key],
        101,
        0,
    );

    let mut source = FakeChainSource::default();
    source.enqueue(vec![derived.clone(), imported]);

    let mut host = started_local_host();
    let report = host.ingest_chain_events(&mut source);

    assert_eq!(report.recorded, 2);
    assert_eq!(report.idempotent, 0);
    assert_eq!(report.duplicates_rejected, 0);

    let derived_record = host
        .handle_graph_core()
        .canonical_handle(&derived_key)
        .expect("derived handle should be canonical");
    assert_eq!(derived_record.state, HandleState::Pending);
}

#[test]
fn ingestion_sorts_events_within_the_same_block_by_log_index() {
    let input_key = handle_key(0xC1);
    let bystander_key = handle_key(0xC2);
    let derived_key = handle_key(0xC3);

    let import_low = imported_event(input_key, 7, 0);
    let import_high = imported_event(bystander_key, 7, 1);
    let derived = derived_event(
        derived_key,
        OperationCode::Not,
        HandleType::Sbool,
        vec![input_key],
        7,
        2,
    );

    let mut source = FakeChainSource::default();
    source.enqueue(vec![import_high, derived.clone(), import_low]);

    let mut host = started_local_host();
    host.ingest_chain_events(&mut source);

    let derived_record = host
        .handle_graph_core()
        .canonical_handle(&derived_key)
        .expect("derived handle should be canonical");
    assert_eq!(derived_record.state, HandleState::Pending);
}

#[test]
fn replay_of_already_consumed_chain_event_is_idempotent() {
    let key = handle_key(0xEE);
    let event = imported_event(key, 1, 0);

    let mut source = FakeChainSource::default();
    source.enqueue(vec![event.clone()]);

    let mut host = started_local_host();
    let first = host.ingest_chain_events(&mut source);
    assert_eq!(first.recorded, 1);
    assert_eq!(first.idempotent, 0);

    source.enqueue(vec![event]);
    let second = host.ingest_chain_events(&mut source);
    assert_eq!(second.recorded, 0);
    assert_eq!(second.idempotent, 1);
    assert_eq!(second.duplicates_rejected, 0);
}

#[test]
fn ingestion_returns_empty_report_when_source_has_no_events() {
    let mut source = FakeChainSource::default();
    let mut host = started_local_host();
    let report = host.ingest_chain_events(&mut source);
    assert_eq!(report, IngestionReport::default());
    assert_eq!(source.poll_views, vec![ChainView::Safe]);
}

#[test]
fn ingestion_reports_a_duplicate_handle_key_as_duplicate_rejection() {
    let key = handle_key(0xF0);
    let first = imported_event(key, 5, 0);
    let second = imported_event(key, 5, 1);

    let mut source = FakeChainSource::default();
    source.enqueue(vec![first, second]);

    let mut host = started_local_host();
    let report = host.ingest_chain_events(&mut source);

    assert_eq!(report.recorded, 1);
    assert_eq!(report.duplicates_rejected, 1);
    assert_eq!(report.idempotent, 0);
}

// Chain View canonicality changes drive Orphan Discard through the ingestion
// seam: the source surfaces previously consumed ChainEventRefs that have left
// the chosen Chain View, and the host tombstones the matching Handle Records
// (and any Handle Lineage descendants).

#[test]
fn ingestion_tombstones_source_handle_for_orphaned_event_ref_from_chain_view() {
    let key = handle_key(0x10);
    let event = imported_event(key, 5, 0);
    let event_ref_for_key = imported_event_ref(&event);

    let mut source = FakeChainSource::default();
    source.enqueue(vec![event]);
    let mut host = started_local_host();
    let first = host.ingest_chain_events(&mut source);
    assert_eq!(first.recorded, 1);
    assert!(host.handle_graph_core().canonical_handle(&key).is_some());

    source.enqueue_orphans(vec![event_ref_for_key]);
    let second = host.ingest_chain_events(&mut source);

    assert_eq!(second.directly_tombstoned, 1);
    assert_eq!(second.cascade_tombstoned, 0);
    assert!(
        host.handle_graph_core().canonical_handle(&key).is_none(),
        "orphaned source handle must disappear from canonical reads"
    );
    let audit = host
        .handle_graph_core()
        .handle_record_for_audit(&key)
        .expect("tombstoned record must remain available for audit");
    assert_eq!(audit.event_ref, event_ref_for_key);
}

#[test]
fn ingestion_tombstones_derived_handle_for_orphaned_event_ref_from_chain_view() {
    let a = handle_key(0x20);
    let b = handle_key(0x21);
    let derived_key = handle_key(0x22);
    let a_event = imported_event(a, 5, 0);
    let b_event = imported_event(b, 5, 1);
    let derived = derived_event(
        derived_key,
        OperationCode::And,
        HandleType::Sbool,
        vec![a, b],
        6,
        0,
    );
    let derived_ref = derived_event_ref(&derived);

    let mut source = FakeChainSource::default();
    source.enqueue(vec![a_event, b_event, derived]);
    let mut host = started_local_host();
    host.ingest_chain_events(&mut source);

    source.enqueue_orphans(vec![derived_ref]);
    let report = host.ingest_chain_events(&mut source);

    assert_eq!(report.directly_tombstoned, 1);
    assert_eq!(report.cascade_tombstoned, 0);
    assert!(host
        .handle_graph_core()
        .canonical_handle(&derived_key)
        .is_none());
    // Untouched inputs must remain canonical.
    assert!(host.handle_graph_core().canonical_handle(&a).is_some());
    assert!(host.handle_graph_core().canonical_handle(&b).is_some());
}

#[test]
fn ingestion_cascades_orphan_discard_through_multi_hop_handle_lineage() {
    // a -> c -> d -> e, with b/other_input/other_input_2 as untouched inputs.
    let a = handle_key(0x30);
    let b = handle_key(0x31);
    let other_input = handle_key(0x32);
    let other_input_2 = handle_key(0x33);
    let c = handle_key(0x34);
    let d = handle_key(0x35);
    let e = handle_key(0x36);

    let a_event = imported_event(a, 5, 0);
    let a_ref = imported_event_ref(&a_event);
    let b_event = imported_event(b, 5, 1);
    let other_event = imported_event(other_input, 5, 2);
    let other_2_event = imported_event(other_input_2, 5, 3);
    let c_event = derived_event(c, OperationCode::And, HandleType::Sbool, vec![a, b], 6, 0);
    let d_event = derived_event(
        d,
        OperationCode::And,
        HandleType::Sbool,
        vec![c, other_input],
        6,
        1,
    );
    let e_event = derived_event(
        e,
        OperationCode::And,
        HandleType::Sbool,
        vec![d, other_input_2],
        6,
        2,
    );

    let mut source = FakeChainSource::default();
    source.enqueue(vec![
        a_event,
        b_event,
        other_event,
        other_2_event,
        c_event,
        d_event,
        e_event,
    ]);
    let mut host = started_local_host();
    host.ingest_chain_events(&mut source);

    source.enqueue_orphans(vec![a_ref]);
    let report = host.ingest_chain_events(&mut source);

    assert_eq!(report.directly_tombstoned, 1);
    assert_eq!(
        report.cascade_tombstoned, 3,
        "every descendant of the orphan source must be cascade-tombstoned"
    );

    assert!(host.handle_graph_core().canonical_handle(&a).is_none());
    assert!(host.handle_graph_core().canonical_handle(&c).is_none());
    assert!(host.handle_graph_core().canonical_handle(&d).is_none());
    assert!(host.handle_graph_core().canonical_handle(&e).is_none());

    assert!(host.handle_graph_core().canonical_handle(&b).is_some());
    assert!(host
        .handle_graph_core()
        .canonical_handle(&other_input)
        .is_some());
    assert!(host
        .handle_graph_core()
        .canonical_handle(&other_input_2)
        .is_some());
}

#[test]
fn ingestion_orphan_discard_is_idempotent_for_repeated_reorg_signals() {
    let key = handle_key(0x40);
    let event = imported_event(key, 5, 0);
    let event_ref_for_key = imported_event_ref(&event);

    let mut source = FakeChainSource::default();
    source.enqueue(vec![event]);
    let mut host = started_local_host();
    host.ingest_chain_events(&mut source);

    source.enqueue_orphans(vec![event_ref_for_key]);
    let first = host.ingest_chain_events(&mut source);
    assert_eq!(first.directly_tombstoned, 1);

    source.enqueue_orphans(vec![event_ref_for_key]);
    let second = host.ingest_chain_events(&mut source);

    assert_eq!(
        second.directly_tombstoned, 0,
        "re-reporting the same orphan ref must not double-count"
    );
    assert_eq!(second.cascade_tombstoned, 0);
    assert!(host.handle_graph_core().canonical_handle(&key).is_none());
}

#[test]
fn ingestion_applies_orphan_discard_before_new_events_in_the_same_poll() {
    // Demonstrates that a single poll carrying both events and orphans applies
    // discard alongside the new events. We model a reorg-style poll where the
    // source signals the orphan in the same batch as fresh, unrelated events.
    let orphan_key = handle_key(0x50);
    let orphan_event = imported_event(orphan_key, 5, 0);
    let orphan_ref = imported_event_ref(&orphan_event);

    let mut source = FakeChainSource::default();
    source.enqueue(vec![orphan_event]);
    let mut host = started_local_host();
    host.ingest_chain_events(&mut source);

    let fresh_key = handle_key(0x51);
    let fresh_event = imported_event(fresh_key, 6, 0);
    source.enqueue(vec![fresh_event]);
    source.enqueue_orphans(vec![orphan_ref]);
    let report = host.ingest_chain_events(&mut source);

    assert_eq!(report.recorded, 1);
    assert_eq!(report.directly_tombstoned, 1);
    assert!(host
        .handle_graph_core()
        .canonical_handle(&orphan_key)
        .is_none());
    assert!(host
        .handle_graph_core()
        .canonical_handle(&fresh_key)
        .is_some());
}

// ---------- fakes and helpers ----------

fn started_local_host() -> CoprocessorHost {
    started_host(HostConfig::for_local_development())
}

fn started_host(config: HostConfig) -> CoprocessorHost {
    let mut host = CoprocessorHost::new(config);
    host.start().unwrap();
    host
}

#[derive(Default)]
struct FakeChainSource {
    queued: Vec<ChainEvent>,
    queued_orphans: Vec<ChainEventRef>,
    poll_views: Vec<ChainView>,
}

impl FakeChainSource {
    fn enqueue(&mut self, events: Vec<ChainEvent>) {
        self.queued.extend(events);
    }

    fn enqueue_orphans(&mut self, orphans: Vec<ChainEventRef>) {
        self.queued_orphans.extend(orphans);
    }
}

impl ChainEventSource for FakeChainSource {
    fn poll(&mut self, view: ChainView) -> ChainViewPoll {
        self.poll_views.push(view);
        ChainViewPoll {
            events: std::mem::take(&mut self.queued),
            orphaned_event_refs: std::mem::take(&mut self.queued_orphans),
        }
    }
}

fn imported_event_ref(event: &ChainEvent) -> ChainEventRef {
    match event {
        ChainEvent::ImportedHandle(e) => e.event_ref,
        other => panic!("expected ImportedHandle event, got {other:?}"),
    }
}

fn derived_event_ref(event: &ChainEvent) -> ChainEventRef {
    match event {
        ChainEvent::DerivedHandleOperation(e) => e.event_ref,
        other => panic!("expected DerivedHandleOperation event, got {other:?}"),
    }
}

fn handle_key(seed: u8) -> HandleKey {
    HandleKey {
        chain_id: TEST_CHAIN,
        contract_address: TEST_CONTRACT,
        handle_id: HandleId([seed; 32]),
    }
}

fn event_ref(block_number: u64, log_index: u32) -> ChainEventRef {
    ChainEventRef {
        chain_id: TEST_CHAIN,
        block_number,
        block_hash: [0xB0; 32],
        tx_hash: [0xC0; 32],
        log_index,
    }
}

fn imported_event(key: HandleKey, block_number: u64, log_index: u32) -> ChainEvent {
    ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: TEST_DOMAIN,
        handle_key: key,
        handle_type: HandleType::Sbool,
        system_ciphertext: SystemCiphertextV1(vec![0x01]),
        materialization_receipt: MaterializationReceipt(vec![0x02]),
        event_ref: event_ref(block_number, log_index),
    })
}

fn derived_event(
    key: HandleKey,
    operation_code: OperationCode,
    output_handle_type: HandleType,
    input_handle_keys: Vec<HandleKey>,
    block_number: u64,
    log_index: u32,
) -> ChainEvent {
    ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id: TEST_DOMAIN,
        handle_key: key,
        operation_code,
        output_handle_type,
        input_handle_keys,
        event_ref: event_ref(block_number, log_index),
    })
}
