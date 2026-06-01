use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleGraphCore, HandleId, HandleKey, HandleRecord, HandleState, HandleType, ImportedHandle,
    IngestionOutcome, MaterializationReceipt, OperationCode, PlaintextHandle, PublicPlaintextValue,
    SystemCiphertextV1,
};

const DEFAULT_DOMAIN: u8 = 9;

#[test]
fn orphan_discard_tombstones_imported_handle_and_hides_from_canonical_queries() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, key, HandleType::Suint256, event_ref);

    let outcome = core.apply_orphan_discard(&[event_ref]);

    assert_eq!(outcome.directly_tombstoned, vec![key]);
    assert!(outcome.cascade_tombstoned.is_empty());
    assert!(
        core.canonical_handle(&key).is_none(),
        "tombstoned imported handle must not appear in canonical queries"
    );
}

#[test]
fn orphan_discard_tombstones_plaintext_handle_and_hides_from_canonical_queries() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 2);
    let event_ref = chain_event_ref(1, 1, 2);
    let _ = expect_recorded(core.apply_chain_event(plaintext_handle_event(
        key,
        event_ref,
        HandleType::Suint256,
        PublicPlaintextValue(vec![0xAB]),
    )));

    let outcome = core.apply_orphan_discard(&[event_ref]);

    assert_eq!(outcome.directly_tombstoned, vec![key]);
    assert!(
        core.canonical_handle(&key).is_none(),
        "tombstoned plaintext handle must not appear in canonical queries"
    );
}

#[test]
fn orphan_discard_tombstones_derived_handle_directly() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core);
    let derived = handle_key(1, 7, 10);
    let derived_event = chain_event_ref(1, 2, 1);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        derived_event,
    )));

    let outcome = core.apply_orphan_discard(&[derived_event]);

    assert_eq!(outcome.directly_tombstoned, vec![derived]);
    assert!(core.canonical_handle(&derived).is_none());
}

#[test]
fn orphan_discard_does_not_physically_delete_handle_records() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, key, HandleType::Suint256, event_ref);
    let original = core.canonical_handle(&key).cloned().expect("seeded record");

    let _ = core.apply_orphan_discard(&[event_ref]);

    let audit = core
        .handle_record_for_audit(&key)
        .expect("tombstoned record must remain available for audit");
    assert_eq!(audit.handle_key, key);
    assert_eq!(audit.event_ref, event_ref);
    assert_eq!(
        audit.handle_type, original.handle_type,
        "audit query must return preserved HandleType"
    );
}

#[test]
fn orphan_discard_is_not_failed_handle_state() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, key, HandleType::Suint256, event_ref);

    let _ = core.apply_orphan_discard(&[event_ref]);

    let audit = core
        .handle_record_for_audit(&key)
        .expect("tombstoned record must remain available for audit");
    assert!(
        !matches!(audit.state, HandleState::Failed { .. }),
        "Orphan Discard must not represent tombstoning as Failed Handle State, was {:?}",
        audit.state
    );
}

#[test]
fn orphan_discard_preserves_chain_event_ref_for_audit() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, key, HandleType::Suint256, event_ref);

    let _ = core.apply_orphan_discard(&[event_ref]);

    let audit = core
        .handle_record_for_audit(&key)
        .expect("tombstoned record must remain available for audit");
    assert_eq!(
        audit.event_ref, event_ref,
        "ChainEventRef must remain available on tombstoned records for audit"
    );
}

#[test]
fn tombstoning_source_handle_cascades_to_derived_handle_that_depends_on_it() {
    let mut core = HandleGraphCore::new();
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let source_event = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, a, HandleType::Suint256, source_event);
    seed_imported(
        &mut core,
        b,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
    );
    let derived = handle_key(1, 7, 10);
    let derived_event = chain_event_ref(1, 2, 1);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        derived_event,
    )));

    let outcome = core.apply_orphan_discard(&[source_event]);

    assert_eq!(outcome.directly_tombstoned, vec![a]);
    assert_eq!(outcome.cascade_tombstoned, vec![derived]);
    assert!(core.canonical_handle(&a).is_none());
    assert!(
        core.canonical_handle(&derived).is_none(),
        "derived handle must be tombstoned because its input was tombstoned"
    );
}

#[test]
fn cascade_applies_even_when_downstream_derived_event_ref_is_still_canonical() {
    let mut core = HandleGraphCore::new();
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let source_event = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, a, HandleType::Suint256, source_event);
    seed_imported(
        &mut core,
        b,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
    );
    let derived = handle_key(1, 7, 10);
    let still_canonical_derived_event = chain_event_ref(1, 99, 99);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        still_canonical_derived_event,
    )));

    let _ = core.apply_orphan_discard(&[source_event]);

    let audit = core
        .handle_record_for_audit(&derived)
        .expect("derived must remain in audit");
    assert_eq!(
        audit.event_ref, still_canonical_derived_event,
        "derived handle's own ChainEventRef is preserved even though it was cascade-tombstoned"
    );
    assert!(
        core.canonical_handle(&derived).is_none(),
        "derived cascade-tombstoned even though its own event_ref was not orphaned"
    );
}

#[test]
fn tombstoning_derived_handle_cascades_to_downstream_derived_handle() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core);
    let first_derived = handle_key(1, 7, 10);
    let first_derived_event = chain_event_ref(1, 2, 1);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        first_derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        first_derived_event,
    )));
    let other_input = handle_key(1, 7, 11);
    seed_imported(
        &mut core,
        other_input,
        HandleType::Suint256,
        chain_event_ref(1, 1, 11),
    );
    let second_derived = handle_key(1, 7, 12);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        second_derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![first_derived, other_input],
        chain_event_ref(1, 2, 2),
    )));

    let outcome = core.apply_orphan_discard(&[first_derived_event]);

    assert_eq!(outcome.directly_tombstoned, vec![first_derived]);
    assert_eq!(outcome.cascade_tombstoned, vec![second_derived]);
    assert!(core.canonical_handle(&first_derived).is_none());
    assert!(
        core.canonical_handle(&second_derived).is_none(),
        "second derived must be cascade-tombstoned because it depends on the first"
    );
}

#[test]
fn multi_hop_cascade_tombstones_all_descendants_through_handle_graph() {
    // Graph: a -> b -> c -> d
    // a, b: source handles
    // c: derived from a, b
    // d: derived from c, other_input
    // e: derived from d, other_input2
    // Tombstoning a should cascade to c, d, e (all descendants).
    let mut core = HandleGraphCore::new();
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let a_event = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, a, HandleType::Suint256, a_event);
    seed_imported(
        &mut core,
        b,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
    );
    let other_input = handle_key(1, 7, 3);
    let other_input_2 = handle_key(1, 7, 4);
    seed_imported(
        &mut core,
        other_input,
        HandleType::Suint256,
        chain_event_ref(1, 1, 3),
    );
    seed_imported(
        &mut core,
        other_input_2,
        HandleType::Suint256,
        chain_event_ref(1, 1, 4),
    );
    let c = handle_key(1, 7, 10);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        c,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        chain_event_ref(1, 2, 1),
    )));
    let d = handle_key(1, 7, 11);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        d,
        OperationCode::Add,
        HandleType::Suint256,
        vec![c, other_input],
        chain_event_ref(1, 2, 2),
    )));
    let e = handle_key(1, 7, 12);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        e,
        OperationCode::Add,
        HandleType::Suint256,
        vec![d, other_input_2],
        chain_event_ref(1, 2, 3),
    )));

    let outcome = core.apply_orphan_discard(&[a_event]);

    assert_eq!(outcome.directly_tombstoned, vec![a]);
    let cascaded: std::collections::HashSet<HandleKey> =
        outcome.cascade_tombstoned.iter().copied().collect();
    let expected: std::collections::HashSet<HandleKey> = [c, d, e].into_iter().collect();
    assert_eq!(
        cascaded, expected,
        "multi-hop cascade must tombstone every descendant"
    );

    assert!(core.canonical_handle(&a).is_none());
    assert!(core.canonical_handle(&c).is_none());
    assert!(core.canonical_handle(&d).is_none());
    assert!(core.canonical_handle(&e).is_none());

    assert!(
        core.canonical_handle(&b).is_some(),
        "untouched sibling source must remain canonical"
    );
    assert!(
        core.canonical_handle(&other_input).is_some(),
        "uninvolved source must remain canonical"
    );
    assert!(
        core.canonical_handle(&other_input_2).is_some(),
        "uninvolved source must remain canonical"
    );
}

#[test]
fn tombstoned_handle_records_stop_participating_in_resolution_readiness() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core);
    let derived = handle_key(1, 7, 10);
    let derived_event = chain_event_ref(1, 2, 1);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        derived_event,
    )));

    let ready_before = core.resolution_readiness();
    assert_eq!(
        ready_before.len(),
        1,
        "derived handle should be ready before orphan discard"
    );

    let _ = core.apply_orphan_discard(&[derived_event]);

    let ready_after = core.resolution_readiness();
    assert!(
        ready_after.is_empty(),
        "tombstoned derived handle must not appear in resolution readiness, got {:?}",
        ready_after
    );
}

#[test]
fn cascaded_tombstone_excludes_downstream_handle_from_resolution_readiness() {
    let mut core = HandleGraphCore::new();
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let a_event = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, a, HandleType::Suint256, a_event);
    seed_imported(
        &mut core,
        b,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
    );
    let derived = handle_key(1, 7, 10);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        chain_event_ref(1, 2, 1),
    )));
    assert_eq!(
        core.resolution_readiness().len(),
        1,
        "derived must be ready before any tombstone"
    );

    let _ = core.apply_orphan_discard(&[a_event]);

    assert!(
        core.resolution_readiness().is_empty(),
        "cascade-tombstoned derived must drop out of resolution readiness"
    );
}

#[test]
fn orphan_discard_on_unknown_event_ref_is_a_noop() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, key, HandleType::Suint256, event_ref);

    let unknown = chain_event_ref(7, 7, 7);
    let outcome = core.apply_orphan_discard(&[unknown]);

    assert!(outcome.directly_tombstoned.is_empty());
    assert!(outcome.cascade_tombstoned.is_empty());
    assert!(
        core.canonical_handle(&key).is_some(),
        "untargeted records must remain canonical"
    );
}

#[test]
fn orphan_discard_is_idempotent_for_already_tombstoned_records() {
    let mut core = HandleGraphCore::new();
    let key = handle_key(1, 7, 1);
    let event_ref = chain_event_ref(1, 1, 1);
    seed_imported(&mut core, key, HandleType::Suint256, event_ref);
    let first = core.apply_orphan_discard(&[event_ref]);
    assert_eq!(first.directly_tombstoned, vec![key]);

    let second = core.apply_orphan_discard(&[event_ref]);

    assert!(
        second.directly_tombstoned.is_empty(),
        "re-applying orphan discard for already-tombstoned record must report no new tombstones"
    );
    assert!(second.cascade_tombstoned.is_empty());
    assert!(core.canonical_handle(&key).is_none());
}

#[test]
fn discarding_multiple_event_refs_in_one_call_tombstones_each() {
    let mut core = HandleGraphCore::new();
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let a_event = chain_event_ref(1, 1, 1);
    let b_event = chain_event_ref(1, 1, 2);
    seed_imported(&mut core, a, HandleType::Suint256, a_event);
    seed_imported(&mut core, b, HandleType::Suint256, b_event);

    let outcome = core.apply_orphan_discard(&[a_event, b_event]);

    let directly: std::collections::HashSet<HandleKey> =
        outcome.directly_tombstoned.iter().copied().collect();
    assert_eq!(directly, [a, b].into_iter().collect());
    assert!(core.canonical_handle(&a).is_none());
    assert!(core.canonical_handle(&b).is_none());
}

fn seed_suint_pair(core: &mut HandleGraphCore) -> (HandleKey, HandleKey) {
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    seed_imported(core, a, HandleType::Suint256, chain_event_ref(1, 1, 1));
    seed_imported(core, b, HandleType::Suint256, chain_event_ref(1, 1, 2));
    (a, b)
}

fn seed_imported(
    core: &mut HandleGraphCore,
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
) {
    let _ = expect_recorded(core.apply_chain_event(ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
        handle_key,
        handle_type,
        system_ciphertext: SystemCiphertextV1(vec![0x01]),
        materialization_receipt: MaterializationReceipt(vec![0x02]),
        event_ref,
    })));
}

fn expect_recorded(outcome: IngestionOutcome) -> HandleRecord {
    match outcome {
        IngestionOutcome::Recorded(record) => record,
        other => panic!("expected Recorded, got {:?}", other),
    }
}

fn derived_operation_event(
    handle_key: HandleKey,
    operation_code: OperationCode,
    output_handle_type: HandleType,
    input_handle_keys: Vec<HandleKey>,
    event_ref: ChainEventRef,
) -> ChainEvent {
    ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
        handle_key,
        operation_code,
        output_handle_type,
        input_handle_keys,
        event_ref,
    })
}

fn plaintext_handle_event(
    handle_key: HandleKey,
    event_ref: ChainEventRef,
    handle_type: HandleType,
    public_value: PublicPlaintextValue,
) -> ChainEvent {
    ChainEvent::PlaintextHandle(PlaintextHandle {
        domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
        handle_key,
        handle_type,
        public_value,
        event_ref,
    })
}

fn handle_key(chain_id: u64, contract_seed: u8, handle_seed: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(chain_id),
        contract_address: ContractAddress([contract_seed; 20]),
        handle_id: HandleId(bytes32(handle_seed)),
    }
}

fn chain_event_ref(chain_id: u64, block_number: u64, log_index: u32) -> ChainEventRef {
    ChainEventRef {
        chain_id: ChainId(chain_id),
        block_number,
        block_hash: bytes32(11),
        tx_hash: bytes32(12),
        log_index,
    }
}

fn bytes32(seed: u8) -> [u8; 32] {
    [seed; 32]
}
