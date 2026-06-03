//! End-to-end reorg and restart recovery integration scenarios for issue #49.
//!
//! Acceptance criteria:
//!
//! - A reorg or Chain View orphan tombstones directly-affected Handle Records
//!   and cascades through Derived Handles (even Ready ones).
//! - Normal API reads treat tombstoned Handle Keys as Unknown while audit/debug
//!   reads retain provenance (ChainEventRef, is_tombstoned).
//! - After restart, consuming the same Chain Events again (by ChainEventRef) is
//!   idempotent — no duplicate Handle Records are created.
//! - After restart, Resolution Readiness and Internal Coordinator API
//!   projections (Ready/Pending/Unknown) match the persisted state.
//! - A handle tombstoned before restart remains tombstoned after restore.

use std::{cell::RefCell, collections::VecDeque};

use coprocessor_ciphertext_binding::{
    self as cbinding, EnclaveAadV1, EnclaveCiphertextV1,
    SystemCiphertextV1 as EnvelopeSystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_enclave_runtime::{AttestationDigest, FakeEnclaveRuntime};
use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleGraphCore, HandleId, HandleKey, HandlePersistence, HandleType, ImportedHandle,
    InMemoryHandlePersistence, IngestionOutcome, MaterializationReceipt, OperationCode,
    SystemCiphertextV1,
};
use coprocessor_host::{
    ChainEventSource, ChainView, ChainViewPoll, CoprocessorHost, HandleStateView, HostConfig,
    RequestId,
};
use coprocessor_mpc_client::{
    MpcSourceError, MpcToEnclaveResponse, MpcToEnclaveSource, ToEnclaveTransformationRequest,
};
use coprocessor_nitro_enclave::{
    AttestationDigest as NitroAttestationDigest, LocalEnclaveAttestationConfig,
    LocalEnclaveAttestationSource,
};

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 0x77;
const DEFAULT_DOMAIN: u8 = 0x09;
const DEFAULT_KEY_SEED: u8 = 0xAB;
const DEFAULT_MEASUREMENT_SEED: u8 = 0x42;
const TASK_REQUEST_ID_SEED: u8 = 0x88;

// ============================================================
// Reorg / Chain View orphan scenarios
// ============================================================

/// A reorg orphan on a source handle tombstones it directly and cascades to a
/// Ready Derived Handle that depends on it. Both appear Unknown via the normal
/// Internal Coordinator API (get_handle_state and resolve_handle). The
/// unaffected sibling source remains Ready.
#[test]
fn reorg_orphan_tombstones_source_and_cascades_to_ready_derived_both_unknown_via_normal_api() {
    let mut host = running_host();

    let source_a = handle_key(0x01);
    let source_b = handle_key(0x02);
    let derived = handle_key(0x10);

    let source_a_ref = event_ref(1, 1);
    let source_b_ref = event_ref(1, 2);
    let derived_ref = event_ref(2, 1);

    ingest_events(
        &mut host,
        vec![
            imported_event(
                source_a,
                HandleType::Suint256,
                well_formed_ciphertext(source_a, "suint256"),
                source_a_ref,
            ),
            imported_event(
                source_b,
                HandleType::Suint256,
                well_formed_ciphertext(source_b, "suint256"),
                source_b_ref,
            ),
        ],
        2,
    );
    ingest_events(
        &mut host,
        vec![derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![source_a, source_b],
            derived_ref,
        )],
        1,
    );

    assert!(matches!(
        host.get_handle_state(&source_a),
        HandleStateView::Ready { .. }
    ));
    assert!(matches!(
        host.get_handle_state(&source_b),
        HandleStateView::Ready { .. }
    ));
    assert_eq!(host.get_handle_state(&derived), HandleStateView::Pending);

    // Resolve derived to Ready through the full pipeline.
    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1);
    let task = tasks[0].clone();
    let enc_a = fake_enclave_ciphertext(source_a, 0xC0);
    let enc_b = fake_enclave_ciphertext(source_b, 0xC1);
    let mpc = ProgrammableMpcServer::with_successes(vec![enc_a, enc_b]);
    let attestation = local_attestation_source();
    let enclave = FakeEnclaveRuntime::deterministic();
    let view = host.resolve_claimed_task(&task, &mpc, &attestation, &enclave);
    assert!(
        matches!(view, HandleStateView::Ready { .. }),
        "derived must be Ready after full pipeline, got {view:?}"
    );

    // Apply a reorg orphan for source_a through the Chain View orphan seam.
    let report = host.ingest_chain_events(&mut OrphanChainSource::new(vec![source_a_ref]));
    assert_eq!(
        report.directly_tombstoned, 1,
        "source_a must be directly tombstoned"
    );
    assert_eq!(
        report.cascade_tombstoned, 1,
        "derived must be cascade-tombstoned"
    );

    // Normal API: both tombstoned handles appear Unknown.
    assert_eq!(
        host.get_handle_state(&source_a),
        HandleStateView::Unknown,
        "orphaned source_a must be Unknown via get_handle_state"
    );
    assert_eq!(
        host.get_handle_state(&derived),
        HandleStateView::Unknown,
        "cascade-tombstoned derived must be Unknown via get_handle_state"
    );
    assert_eq!(
        host.resolve_handle(RequestId([0x01; 32]), &source_a),
        HandleStateView::Unknown,
        "orphaned source_a must be Unknown via resolve_handle"
    );
    assert_eq!(
        host.resolve_handle(RequestId([0x02; 32]), &derived),
        HandleStateView::Unknown,
        "cascade-tombstoned derived must be Unknown via resolve_handle"
    );

    // Unaffected sibling source remains Ready.
    assert!(
        matches!(host.get_handle_state(&source_b), HandleStateView::Ready { .. }),
        "unaffected source_b must remain Ready"
    );
}

/// After a reorg orphan, the normal API hides tombstoned Handle Records while
/// the audit/debug query retains provenance: ChainEventRef is preserved and
/// is_tombstoned is true for both the directly-tombstoned source and the
/// cascade-tombstoned Derived Handle.
#[test]
fn reorg_audit_query_retains_provenance_for_tombstoned_source_and_cascade_derived() {
    let mut host = running_host();

    let source_a = handle_key(0x01);
    let source_b = handle_key(0x02);
    let derived = handle_key(0x10);

    let source_a_ref = event_ref(1, 1);
    let source_b_ref = event_ref(1, 2);
    let derived_ref = event_ref(2, 1);

    ingest_events(
        &mut host,
        vec![
            imported_event(
                source_a,
                HandleType::Suint256,
                well_formed_ciphertext(source_a, "suint256"),
                source_a_ref,
            ),
            imported_event(
                source_b,
                HandleType::Suint256,
                well_formed_ciphertext(source_b, "suint256"),
                source_b_ref,
            ),
        ],
        2,
    );
    ingest_events(
        &mut host,
        vec![derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![source_a, source_b],
            derived_ref,
        )],
        1,
    );

    // Apply orphan for source_a (cascades to derived).
    let report = host.ingest_chain_events(&mut OrphanChainSource::new(vec![source_a_ref]));
    assert_eq!(report.directly_tombstoned, 1);
    assert_eq!(report.cascade_tombstoned, 1);

    // Normal API hides both tombstoned handles.
    assert_eq!(host.get_handle_state(&source_a), HandleStateView::Unknown);
    assert_eq!(host.get_handle_state(&derived), HandleStateView::Unknown);

    // Audit retains provenance and tombstone status for source_a.
    let audit_a = host
        .handle_graph_core()
        .handle_record_for_audit(&source_a)
        .expect("audit must expose tombstoned source_a");
    assert!(
        audit_a.is_tombstoned,
        "source_a must be tombstoned in audit"
    );
    assert_eq!(
        audit_a.event_ref, source_a_ref,
        "audit must preserve source_a ChainEventRef"
    );

    // Audit retains the derived handle's own ChainEventRef (not source_a's).
    let audit_derived = host
        .handle_graph_core()
        .handle_record_for_audit(&derived)
        .expect("audit must expose cascade-tombstoned derived");
    assert!(
        audit_derived.is_tombstoned,
        "derived must be tombstoned in audit"
    );
    assert_eq!(
        audit_derived.event_ref, derived_ref,
        "cascade tombstone must not rewrite derived handle's own ChainEventRef"
    );
}

// ============================================================
// Restart recovery scenarios (persistence-backed)
// ============================================================

/// After restore_from_persistence, re-ingesting the same Chain Events that were
/// consumed before restart is idempotent by ChainEventRef. Persisted Handle
/// Record counts and state projections remain stable.
#[test]
fn restart_replaying_consumed_events_is_idempotent_by_chain_event_ref() {
    let mut store = InMemoryHandlePersistence::new();
    let mut pre = HandleGraphCore::new();

    let source_a = handle_key(0x01);
    let source_b = handle_key(0x02);
    let derived = handle_key(0x10);

    let ev_a = imported_event(
        source_a,
        HandleType::Suint256,
        well_formed_ciphertext(source_a, "suint256"),
        event_ref(1, 1),
    );
    let ev_b = imported_event(
        source_b,
        HandleType::Suint256,
        well_formed_ciphertext(source_b, "suint256"),
        event_ref(1, 2),
    );
    let ev_derived = derived_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![source_a, source_b],
        event_ref(2, 1),
    );

    expect_recorded(pre.apply_chain_event_with_persistence(ev_a.clone(), &mut store));
    expect_recorded(pre.apply_chain_event_with_persistence(ev_b.clone(), &mut store));
    expect_recorded(pre.apply_chain_event_with_persistence(ev_derived.clone(), &mut store));

    let persisted_record_count = store.handle_records().len();
    let persisted_consumed_event_count = store.consumed_events().len();
    let mut host = boot_restored_host(&store);

    let replay_report = host.ingest_chain_events(&mut FixedChainSource::new(vec![
        ev_a, ev_b, ev_derived,
    ]));
    assert_eq!(
        replay_report.recorded, 0,
        "replay after restart must not create new Handle Records"
    );
    assert_eq!(
        replay_report.idempotent, 3,
        "each replayed event must be Idempotent by ChainEventRef"
    );
    assert_eq!(replay_report.duplicates_rejected, 0);
    assert_eq!(replay_report.directly_tombstoned, 0);
    assert_eq!(replay_report.cascade_tombstoned, 0);
    assert_eq!(
        store.handle_records().len(),
        persisted_record_count,
        "persistence must still contain one record per pre-restart Handle Key"
    );
    assert_eq!(
        store.consumed_events().len(),
        persisted_consumed_event_count,
        "persistence must still contain one consumed ChainEventRef per pre-restart event"
    );

    assert!(matches!(
        host.get_handle_state(&source_a),
        HandleStateView::Ready { .. }
    ));
    assert!(matches!(
        host.get_handle_state(&source_b),
        HandleStateView::Ready { .. }
    ));
    assert_eq!(host.get_handle_state(&derived), HandleStateView::Pending);
    assert_eq!(
        host.resolve_handle(RequestId([0x03; 32]), &derived),
        HandleStateView::Pending,
        "resolve_handle projection must match get_handle_state after replay"
    );
}

/// After restore_from_persistence, Resolution Readiness and Internal
/// Coordinator API projections match the persisted canonical state. A Ready
/// Derived Handle materialized before restart stays Ready; there are no
/// spurious pending readiness entries.
#[test]
fn restart_resolution_readiness_and_api_state_match_pre_restart_state() {
    let mut store = InMemoryHandlePersistence::new();
    let mut pre = HandleGraphCore::new();

    let source_a = handle_key(0x01);
    let source_b = handle_key(0x02);
    let derived = handle_key(0x10);

    expect_recorded(pre.apply_chain_event_with_persistence(
        imported_event(
            source_a,
            HandleType::Suint256,
            well_formed_ciphertext(source_a, "suint256"),
            event_ref(1, 1),
        ),
        &mut store,
    ));
    expect_recorded(pre.apply_chain_event_with_persistence(
        imported_event(
            source_b,
            HandleType::Suint256,
            well_formed_ciphertext(source_b, "suint256"),
            event_ref(1, 2),
        ),
        &mut store,
    ));
    expect_recorded(pre.apply_chain_event_with_persistence(
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![source_a, source_b],
            event_ref(2, 1),
        ),
        &mut store,
    ));

    // Materialize the derived handle to Ready — simulates a completed resolution.
    pre.materialize_derived_handle_with_persistence(
        &derived,
        SystemCiphertextV1(vec![0xCC; 16]),
        MaterializationReceipt(vec![0xAA; 8]),
        &mut store,
    )
    .expect("materialize must succeed");

    // Pre-restart: no pending derived handles (derived is Ready).
    assert!(
        pre.resolution_readiness().is_empty(),
        "precondition: derived is Ready so readiness must be empty"
    );

    let mut host = boot_restored_host(&store);

    // All three handles reflect their persisted state after restore.
    assert!(
        matches!(host.get_handle_state(&source_a), HandleStateView::Ready { .. }),
        "source_a must be Ready after restart"
    );
    assert!(
        matches!(host.get_handle_state(&source_b), HandleStateView::Ready { .. }),
        "source_b must be Ready after restart"
    );
    assert!(
        matches!(host.get_handle_state(&derived), HandleStateView::Ready { .. }),
        "Ready derived must stay Ready after restart"
    );
    assert!(
        matches!(
            host.resolve_handle(RequestId([0x04; 32]), &derived),
            HandleStateView::Ready { .. }
        ),
        "resolve_handle must return the same Ready projection after restart"
    );

    // Resolution Readiness after restart must be empty (derived is already Ready).
    let post_readiness = host.handle_graph_core().resolution_readiness();
    assert!(
        post_readiness.is_empty(),
        "no pending derived handles after restart, got {post_readiness:?}"
    );
}

/// A handle tombstoned before restart (directly or by cascade) remains
/// tombstoned after restore_from_persistence. Normal reads return Unknown;
/// audit reads still expose provenance and is_tombstoned.
#[test]
fn restart_tombstoned_before_restart_remains_tombstoned_after_restore() {
    let mut store = InMemoryHandlePersistence::new();
    let mut pre = HandleGraphCore::new();

    let source_a = handle_key(0x01);
    let source_b = handle_key(0x02);
    let derived = handle_key(0x10);

    let source_a_ref = event_ref(1, 1);
    let derived_ref = event_ref(2, 1);

    expect_recorded(pre.apply_chain_event_with_persistence(
        imported_event(
            source_a,
            HandleType::Suint256,
            well_formed_ciphertext(source_a, "suint256"),
            source_a_ref,
        ),
        &mut store,
    ));
    expect_recorded(pre.apply_chain_event_with_persistence(
        imported_event(
            source_b,
            HandleType::Suint256,
            well_formed_ciphertext(source_b, "suint256"),
            event_ref(1, 2),
        ),
        &mut store,
    ));
    expect_recorded(pre.apply_chain_event_with_persistence(
        derived_event(
            derived,
            OperationCode::Add,
            HandleType::Suint256,
            vec![source_a, source_b],
            derived_ref,
        ),
        &mut store,
    ));

    // Orphan source_a with persistence — cascades to derived.
    let outcome = pre.apply_orphan_discard_with_persistence(&[source_a_ref], &mut store);
    assert_eq!(outcome.directly_tombstoned, vec![source_a]);
    assert_eq!(outcome.cascade_tombstoned, vec![derived]);

    // Restore from persistence.
    let mut host = boot_restored_host(&store);

    // Normal API: tombstoned handles are Unknown.
    assert_eq!(
        host.get_handle_state(&source_a),
        HandleStateView::Unknown,
        "tombstoned source_a must be Unknown after restart"
    );
    assert_eq!(
        host.get_handle_state(&derived),
        HandleStateView::Unknown,
        "cascade-tombstoned derived must be Unknown after restart"
    );
    assert_eq!(
        host.resolve_handle(RequestId([0x05; 32]), &source_a),
        HandleStateView::Unknown,
        "tombstoned source_a must also be Unknown via resolve_handle after restart"
    );
    assert_eq!(
        host.resolve_handle(RequestId([0x06; 32]), &derived),
        HandleStateView::Unknown,
        "cascade-tombstoned derived must also be Unknown via resolve_handle after restart"
    );
    assert!(
        matches!(host.get_handle_state(&source_b), HandleStateView::Ready { .. }),
        "untouched source_b must remain Ready after restart"
    );

    // Audit exposes tombstoned source_a with original provenance.
    let audit_a = host
        .handle_graph_core()
        .handle_record_for_audit(&source_a)
        .expect("audit must expose tombstoned source_a after restart");
    assert!(audit_a.is_tombstoned);
    assert_eq!(
        audit_a.event_ref, source_a_ref,
        "source_a ChainEventRef must survive restart"
    );

    // Audit exposes cascade-tombstoned derived with its own ChainEventRef.
    let audit_derived = host
        .handle_graph_core()
        .handle_record_for_audit(&derived)
        .expect("audit must expose cascade-tombstoned derived after restart");
    assert!(audit_derived.is_tombstoned);
    assert_eq!(
        audit_derived.event_ref, derived_ref,
        "derived ChainEventRef must survive restart"
    );

    // Tombstoned handles must not appear in Resolution Readiness.
    assert!(
        host.handle_graph_core().resolution_readiness().is_empty(),
        "tombstoned handles must not appear in Resolution Readiness after restart"
    );
}

// ============================================================
// Fixtures
// ============================================================

fn running_host() -> CoprocessorHost {
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    host
}

fn boot_restored_host(store: &InMemoryHandlePersistence) -> CoprocessorHost {
    let mut host =
        CoprocessorHost::restore_from_persistence(HostConfig::for_local_development(), store);
    host.start().expect("restored host must start cleanly");
    host
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
        block_hash: [0xAA; 32],
        tx_hash: [0xBB; 32],
        log_index,
    }
}

fn well_formed_ciphertext(key: HandleKey, type_tag: &str) -> SystemCiphertextV1 {
    let aad = SystemHandleAadV1 {
        version: 1,
        chain_id: key.chain_id.0,
        domain_id: cbinding::DomainId([DEFAULT_DOMAIN; 32]),
        handle_id: cbinding::HandleId(key.handle_id.0),
        type_tag: type_tag.to_string(),
        key_id: cbinding::KeyId([DEFAULT_KEY_SEED; 32]),
    }
    .encode();
    SystemCiphertextV1(
        EnvelopeSystemCiphertextV1 {
            version: 1,
            aad,
            wrapped_key: vec![0xAA; 32],
            ciphertext: vec![0xBB; 64],
        }
        .encode(),
    )
}

fn fake_enclave_ciphertext(key: HandleKey, payload_seed: u8) -> EnclaveCiphertextV1 {
    let aad = EnclaveAadV1 {
        version: 1,
        chain_id: key.chain_id.0,
        domain_id: cbinding::DomainId([DEFAULT_DOMAIN; 32]),
        request_id: cbinding::RequestId([TASK_REQUEST_ID_SEED; 32]),
        handle_id: cbinding::HandleId(key.handle_id.0),
        type_tag: "suint256".to_string(),
        attestation_digest: AttestationDigest([DEFAULT_MEASUREMENT_SEED; 32]),
        key_id: cbinding::KeyId([DEFAULT_KEY_SEED; 32]),
    }
    .encode();
    EnclaveCiphertextV1 {
        version: 1,
        aad,
        wrapped_key: vec![payload_seed; 32],
        ciphertext: vec![payload_seed; 64],
    }
}

fn local_attestation_source() -> LocalEnclaveAttestationSource {
    LocalEnclaveAttestationSource::new(LocalEnclaveAttestationConfig {
        enclave_public_key: vec![0x44; 48],
        enclave_measurement: NitroAttestationDigest([DEFAULT_MEASUREMENT_SEED; 32]),
        attestation: vec![0x55; 96],
    })
}

fn imported_event(
    handle_key: HandleKey,
    handle_type: HandleType,
    system_ciphertext: SystemCiphertextV1,
    event_ref: ChainEventRef,
) -> ChainEvent {
    ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId([DEFAULT_DOMAIN; 32]),
        handle_key,
        handle_type,
        system_ciphertext,
        materialization_receipt: MaterializationReceipt(vec![0x01]),
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

fn ingest_events(host: &mut CoprocessorHost, events: Vec<ChainEvent>, expected_recorded: usize) {
    let mut source = FixedChainSource::new(events);
    let report = host.ingest_chain_events(&mut source);
    assert_eq!(report.recorded, expected_recorded);
    assert_eq!(report.idempotent, 0);
    assert_eq!(report.duplicates_rejected, 0);
    assert_eq!(report.directly_tombstoned, 0);
    assert_eq!(report.cascade_tombstoned, 0);
}

fn expect_recorded(outcome: IngestionOutcome) {
    match outcome {
        IngestionOutcome::Recorded(_) => {}
        other => panic!("expected Recorded, got {other:?}"),
    }
}

// ---------- fake sources ----------

struct FixedChainSource {
    events: Vec<ChainEvent>,
}

impl FixedChainSource {
    fn new(events: Vec<ChainEvent>) -> Self {
        Self { events }
    }
}

impl ChainEventSource for FixedChainSource {
    fn poll(&mut self, _view: ChainView) -> ChainViewPoll {
        ChainViewPoll {
            events: std::mem::take(&mut self.events),
            orphaned_event_refs: Vec::new(),
        }
    }
}

/// A [`ChainEventSource`] that delivers orphaned event refs with no new events.
/// Drives the Chain View orphan seam in `ingest_chain_events` to trigger
/// Orphan Discard and cascade tombstoning without introducing new Handle Records.
struct OrphanChainSource {
    orphaned_event_refs: Vec<ChainEventRef>,
}

impl OrphanChainSource {
    fn new(orphaned_event_refs: Vec<ChainEventRef>) -> Self {
        Self { orphaned_event_refs }
    }
}

impl ChainEventSource for OrphanChainSource {
    fn poll(&mut self, _view: ChainView) -> ChainViewPoll {
        ChainViewPoll {
            events: Vec::new(),
            orphaned_event_refs: std::mem::take(&mut self.orphaned_event_refs),
        }
    }
}

// ---------- fake MPC server ----------

struct ProgrammableMpcServer {
    queued: RefCell<VecDeque<EnclaveCiphertextV1>>,
}

impl ProgrammableMpcServer {
    fn with_successes(envelopes: Vec<EnclaveCiphertextV1>) -> Self {
        Self {
            queued: RefCell::new(envelopes.into()),
        }
    }
}

impl MpcToEnclaveSource for ProgrammableMpcServer {
    fn request_to_enclave_transformation(
        &self,
        _request: &ToEnclaveTransformationRequest,
    ) -> Result<MpcToEnclaveResponse, MpcSourceError> {
        let next = self
            .queued
            .borrow_mut()
            .pop_front()
            .expect("ProgrammableMpcServer ran out of queued envelopes");
        Ok(MpcToEnclaveResponse::Success(next))
    }
}
