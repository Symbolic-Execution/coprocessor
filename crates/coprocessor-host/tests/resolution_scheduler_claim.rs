//! Resolution Scheduler tests for issue #38.
//!
//! The Resolution Scheduler observes Resolution Readiness and claims one
//! Resolution Task per Pending Derived Handle. It deduplicates work for the
//! same Handle Key while a task is in flight, and the underlying Handle State
//! stays Pending across the claim so repeated Resolve Handle Requests still
//! attach to the existing Pending state without moving the graph.
//!
//! The acceptance criteria from issue #38:
//! - Resolution Readiness entries create Resolution Tasks with the output
//!   Handle Key, OperationCode, output HandleType, ordered input Handle Keys,
//!   and the ready input `SystemCiphertextV1` values.
//! - Only one active Resolution Task exists per Handle Key.
//! - Repeated Resolve Handle Requests attach to the current Pending state
//!   while a task is claimed or running.
//! - Tests cover duplicate scheduler ticks, duplicate resolve requests, and
//!   multiple independent ready derived handles.

use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleRecord, HandleType, ImportedHandle, IngestionOutcome, OperationCode,
    SystemCiphertextV1,
};
use coprocessor_host::{
    CoprocessorHost, HandleStateView, HostConfig, RequestId, ResolutionIntent, ResolutionTask,
};

const DEFAULT_CHAIN: u64 = 1;
const DEFAULT_CONTRACT_SEED: u8 = 7;
const DEFAULT_DOMAIN: u8 = 9;

#[test]
fn claim_resolution_tasks_builds_one_task_per_ready_derived_handle() {
    let mut host = running_host();
    let a = default_handle_key(1);
    let b = default_handle_key(2);
    let a_ciphertext = SystemCiphertextV1(vec![0xA1]);
    let b_ciphertext = SystemCiphertextV1(vec![0xB2]);
    ingest_imported(
        &mut host,
        a,
        HandleType::Suint256,
        a_ciphertext.clone(),
        1,
        1,
    );
    ingest_imported(
        &mut host,
        b,
        HandleType::Suint256,
        b_ciphertext.clone(),
        1,
        2,
    );
    let derived = default_handle_key(10);
    ingest_derived(
        &mut host,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );

    let tasks = host.claim_resolution_tasks();

    assert_eq!(
        tasks.len(),
        1,
        "one Pending Derived Handle => one task, got {tasks:?}"
    );
    let task = &tasks[0];
    assert_eq!(task.output_handle_key, derived);
    assert_eq!(task.operation_code, OperationCode::Add);
    assert_eq!(task.output_handle_type, HandleType::Suint256);
    assert_eq!(task.input_handle_keys, vec![a, b]);
    assert_eq!(
        task.input_system_ciphertexts,
        vec![a_ciphertext, b_ciphertext]
    );
    assert!(host.is_resolution_task_claimed(&derived));
    assert_eq!(host.claimed_resolution_task_count(), 1);
}

#[test]
fn duplicate_scheduler_ticks_only_claim_each_handle_key_once() {
    let mut host = running_host();
    let (a, b) = seed_suint_pair(&mut host);
    let derived = default_handle_key(10);
    ingest_derived(
        &mut host,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );

    let first = host.claim_resolution_tasks();
    let second = host.claim_resolution_tasks();

    assert_eq!(first.len(), 1, "first tick must claim the ready handle");
    assert!(
        second.is_empty(),
        "second tick must not re-claim the same handle, got {second:?}",
    );
    assert!(host.is_resolution_task_claimed(&derived));
    assert_eq!(host.claimed_resolution_task_count(), 1);
}

#[test]
fn claim_resolution_tasks_emits_one_task_per_independent_ready_handle() {
    let mut host = running_host();
    let (a, b) = seed_suint_pair(&mut host);
    let first_derived = default_handle_key(10);
    let second_derived = default_handle_key(11);
    ingest_derived(
        &mut host,
        first_derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );
    ingest_derived(
        &mut host,
        second_derived,
        OperationCode::Eq,
        HandleType::Sbool,
        vec![a, b],
        2,
        2,
    );

    let tasks = host.claim_resolution_tasks();

    assert_eq!(
        tasks.len(),
        2,
        "two independent ready derived handles must produce two tasks"
    );
    let first = task_for(&tasks, first_derived);
    assert_eq!(first.operation_code, OperationCode::Add);
    assert_eq!(first.output_handle_type, HandleType::Suint256);
    let second = task_for(&tasks, second_derived);
    assert_eq!(second.operation_code, OperationCode::Eq);
    assert_eq!(second.output_handle_type, HandleType::Sbool);

    assert!(host.is_resolution_task_claimed(&first_derived));
    assert!(host.is_resolution_task_claimed(&second_derived));
    assert_eq!(host.claimed_resolution_task_count(), 2);
}

#[test]
fn claim_resolution_tasks_preserves_select_input_order_with_ciphertexts() {
    let mut host = running_host();
    let predicate = default_handle_key(20);
    let when_true = default_handle_key(21);
    let when_false = default_handle_key(22);
    let predicate_ciphertext = SystemCiphertextV1(vec![0xC0]);
    let when_true_ciphertext = SystemCiphertextV1(vec![0xC1]);
    let when_false_ciphertext = SystemCiphertextV1(vec![0xC2]);
    ingest_imported(
        &mut host,
        predicate,
        HandleType::Sbool,
        predicate_ciphertext.clone(),
        1,
        20,
    );
    ingest_imported(
        &mut host,
        when_true,
        HandleType::Suint256,
        when_true_ciphertext.clone(),
        1,
        21,
    );
    ingest_imported(
        &mut host,
        when_false,
        HandleType::Suint256,
        when_false_ciphertext.clone(),
        1,
        22,
    );
    let select_derived = default_handle_key(23);
    ingest_derived(
        &mut host,
        select_derived,
        OperationCode::Select,
        HandleType::Suint256,
        vec![predicate, when_true, when_false],
        2,
        1,
    );

    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1);
    let task = &tasks[0];
    assert_eq!(task.output_handle_key, select_derived);
    assert_eq!(task.operation_code, OperationCode::Select);
    assert_eq!(
        task.input_handle_keys,
        vec![predicate, when_true, when_false],
        "Select task must preserve predicate, when-true, when-false order"
    );
    assert_eq!(
        task.input_system_ciphertexts,
        vec![
            predicate_ciphertext,
            when_true_ciphertext,
            when_false_ciphertext
        ],
        "Select ciphertexts must match input handle key order"
    );
}

#[test]
fn claim_resolution_tasks_keeps_handle_state_pending() {
    let mut host = running_host();
    let pending = seed_pending_derived(&mut host);
    assert_eq!(host.get_handle_state(&pending), HandleStateView::Pending);

    let tasks = host.claim_resolution_tasks();
    assert_eq!(tasks.len(), 1);

    assert_eq!(
        host.get_handle_state(&pending),
        HandleStateView::Pending,
        "Handle State must stay Pending while a Resolution Task is in flight",
    );
}

#[test]
fn resolve_handle_request_during_claim_returns_pending_and_attaches_intent() {
    let mut host = running_host();
    let pending = seed_pending_derived(&mut host);
    let _ = host.claim_resolution_tasks();
    assert!(host.is_resolution_task_claimed(&pending));

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
    assert_eq!(
        host.resolve_handle(request_a, &pending),
        HandleStateView::Pending,
        "Repeated resolve requests during a claim still return Pending"
    );

    assert_eq!(
        host.pending_resolution_intent(&pending),
        Some(ResolutionIntent {
            handle_key: pending,
            attached_request_ids: vec![request_a, request_b],
        }),
        "Repeated resolve requests attach to the current Pending intent while a task is claimed"
    );
    assert_eq!(host.pending_resolution_intent_count(), 1);

    let next_tick = host.claim_resolution_tasks();
    assert!(
        next_tick.is_empty(),
        "Resolve Handle Requests must not produce a second Resolution Task"
    );
}

#[test]
fn release_resolution_task_allows_a_future_claim_to_pick_it_up_again() {
    let mut host = running_host();
    let pending = seed_pending_derived(&mut host);

    let first = host.claim_resolution_tasks();
    assert_eq!(first.len(), 1);
    assert!(host.is_resolution_task_claimed(&pending));

    let released = host.release_resolution_task(&pending);
    assert!(
        released,
        "release must report the previously claimed handle"
    );
    assert!(!host.is_resolution_task_claimed(&pending));
    assert_eq!(host.claimed_resolution_task_count(), 0);

    let again = host.claim_resolution_tasks();
    assert_eq!(
        again.len(),
        1,
        "after release the same ready handle must be claimable again"
    );
    assert!(host.is_resolution_task_claimed(&pending));
}

#[test]
fn release_unknown_handle_key_is_a_no_op() {
    let mut host = running_host();
    let unknown = default_handle_key(99);

    assert!(!host.release_resolution_task(&unknown));
    assert_eq!(host.claimed_resolution_task_count(), 0);
}

#[test]
fn claim_resolution_tasks_skips_failed_handles() {
    let mut host = running_host();
    let (a, _) = seed_suint_pair(&mut host);
    let failed_wrong_arity = default_handle_key(40);
    ingest_derived(
        &mut host,
        failed_wrong_arity,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a],
        2,
        1,
    );
    let failed_unknown_input = default_handle_key(41);
    ingest_derived(
        &mut host,
        failed_unknown_input,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, default_handle_key(99)],
        2,
        2,
    );

    let tasks = host.claim_resolution_tasks();

    assert!(
        tasks.is_empty(),
        "Failed handles must not be claimed, got {tasks:?}",
    );
    assert!(!host.is_resolution_task_claimed(&failed_wrong_arity));
    assert!(!host.is_resolution_task_claimed(&failed_unknown_input));
    assert_eq!(host.claimed_resolution_task_count(), 0);
}

// ---------- helpers ----------

fn running_host() -> CoprocessorHost {
    let mut host = CoprocessorHost::new(HostConfig::for_local_development());
    host.start().unwrap();
    host
}

fn seed_pending_derived(host: &mut CoprocessorHost) -> HandleKey {
    let (a, b) = seed_suint_pair(host);
    let derived = default_handle_key(10);
    ingest_derived(
        host,
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        2,
        1,
    );
    derived
}

fn seed_suint_pair(host: &mut CoprocessorHost) -> (HandleKey, HandleKey) {
    let a = default_handle_key(1);
    let b = default_handle_key(2);
    if host.handle_graph_core().canonical_handle(&a).is_none() {
        ingest_imported(
            host,
            a,
            HandleType::Suint256,
            SystemCiphertextV1(vec![0xA1]),
            1,
            1,
        );
    }
    if host.handle_graph_core().canonical_handle(&b).is_none() {
        ingest_imported(
            host,
            b,
            HandleType::Suint256,
            SystemCiphertextV1(vec![0xB2]),
            1,
            2,
        );
    }
    (a, b)
}

fn ingest_imported(
    host: &mut CoprocessorHost,
    handle_key: HandleKey,
    handle_type: HandleType,
    system_ciphertext: SystemCiphertextV1,
    block_number: u64,
    log_index: u32,
) {
    ingest(
        host,
        ChainEvent::ImportedHandle(ImportedHandle {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key,
            handle_type,
            system_ciphertext,
            event_ref: default_event_ref(block_number, log_index),
        }),
    );
}

fn ingest_derived(
    host: &mut CoprocessorHost,
    handle_key: HandleKey,
    operation_code: OperationCode,
    output_handle_type: HandleType,
    input_handle_keys: Vec<HandleKey>,
    block_number: u64,
    log_index: u32,
) {
    ingest(
        host,
        ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
            domain_id: DomainId([DEFAULT_DOMAIN; 32]),
            handle_key,
            operation_code,
            output_handle_type,
            input_handle_keys,
            event_ref: default_event_ref(block_number, log_index),
        }),
    );
}

fn ingest(host: &mut CoprocessorHost, event: ChainEvent) -> HandleRecord {
    match host.handle_graph_core_mut().apply_chain_event(event) {
        IngestionOutcome::Recorded(record) => record,
        other => panic!("expected recorded chain event, got {other:?}"),
    }
}

fn task_for(tasks: &[ResolutionTask], handle_key: HandleKey) -> &ResolutionTask {
    tasks
        .iter()
        .find(|task| task.output_handle_key == handle_key)
        .expect("expected task for handle")
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
