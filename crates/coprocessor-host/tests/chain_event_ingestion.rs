//! Chain Event Ingestion tests.
//!
//! These tests drive the Coprocessor Host's chain ingestion seam through its
//! public interface: a [`ChainEventSource`] supplies decoded Chain Events, and
//! the host pulls, canonically orders, and applies them to the owned Handle
//! Graph Core idempotently. The fake source exists only in this test file —
//! production sources will live behind the same trait without changing
//! ingestion behavior.

use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleState, HandleType, ImportedHandle, MaterializationReceipt,
    OperationCode, SystemCiphertextV1,
};
use coprocessor_host::{ChainEventSource, ChainView, CoprocessorHost, HostConfig, IngestionReport};

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
    let mut host = CoprocessorHost::new(config);
    host.start().unwrap();

    let mut source = FakeChainSource::default();
    host.ingest_chain_events(&mut source);

    assert_eq!(source.poll_views, vec![ChainView::Finalized]);
}

#[test]
fn ingestion_sorts_events_into_canonical_log_order_before_applying() {
    // Source returns the derived operation BEFORE its imported input. Without
    // canonical-order sort the derived op would land Failed with
    // UnknownInputHandle. With canonical sort applied to the pulled batch,
    // the import lands first and the derivation lands Pending.
    let input_key = handle_key(0xAA);
    let derived_key = handle_key(0xBB);

    let imported = imported_event(input_key, 100, 0); // (block 100, log 0)
    let derived = derived_event(
        derived_key,
        OperationCode::Not,
        HandleType::Sbool,
        vec![input_key],
        101,
        0,
    ); // (block 101, log 0)

    let mut source = FakeChainSource::default();
    source.enqueue(vec![derived.clone(), imported.clone()]); // wrong order on the wire

    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    let report = host.ingest_chain_events(&mut source);

    assert_eq!(report.recorded, 2);
    assert_eq!(report.idempotent, 0);
    assert_eq!(report.duplicates_rejected, 0);

    // The derived handle must be Pending because the input was applied first.
    let derived_record = host
        .handle_graph_core()
        .canonical_handle(&derived_key)
        .expect("derived handle should be canonical");
    // Not over an sbool input is well-typed; Pending proves the input was
    // already known when the derivation was applied.
    assert_eq!(derived_record.state, HandleState::Pending);
}

#[test]
fn ingestion_sorts_events_within_the_same_block_by_log_index() {
    // Two imports in the same block; the derived op consumes the lower
    // log-index one. Source enqueues them in (high, low, derived) order so a
    // naive in-order apply would race; canonical sort puts log 0 first.
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

    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
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

    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    let first = host.ingest_chain_events(&mut source);
    assert_eq!(first.recorded, 1);
    assert_eq!(first.idempotent, 0);

    // The source re-serves the same ChainEventRef; ingestion must treat it as
    // a no-op rather than re-applying the imported handle.
    source.enqueue(vec![event]);
    let second = host.ingest_chain_events(&mut source);
    assert_eq!(second.recorded, 0);
    assert_eq!(second.idempotent, 1);
    assert_eq!(second.duplicates_rejected, 0);
}

#[test]
fn ingestion_returns_empty_report_when_source_has_no_events() {
    let mut source = FakeChainSource::default();
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    let report = host.ingest_chain_events(&mut source);
    assert_eq!(report, IngestionReport::default());
    // The empty pass still polled the source once with the configured view.
    assert_eq!(source.poll_views, vec![ChainView::Safe]);
}

#[test]
fn ingestion_reports_a_duplicate_handle_key_as_duplicate_rejection() {
    // Two distinct chain events that bind the same Handle Key. The first
    // becomes canonical and the second is rejected. Both consume their ref,
    // so a re-poll of either is idempotent.
    let key = handle_key(0xF0);
    let first = imported_event(key, 5, 0);
    let second = imported_event(key, 5, 1); // same key, distinct event ref

    let mut source = FakeChainSource::default();
    source.enqueue(vec![first, second]);

    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    let report = host.ingest_chain_events(&mut source);

    assert_eq!(report.recorded, 1);
    assert_eq!(report.duplicates_rejected, 1);
    assert_eq!(report.idempotent, 0);
}

// ---------- fakes and helpers ----------

#[derive(Default)]
struct FakeChainSource {
    queued: Vec<ChainEvent>,
    poll_views: Vec<ChainView>,
}

impl FakeChainSource {
    fn enqueue(&mut self, events: Vec<ChainEvent>) {
        self.queued.extend(events);
    }
}

impl ChainEventSource for FakeChainSource {
    fn poll_events(&mut self, view: ChainView) -> Vec<ChainEvent> {
        self.poll_views.push(view);
        std::mem::take(&mut self.queued)
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
    // sbool keeps the derived-op cases in scope (Not has arity 1, sbool input/output).
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
