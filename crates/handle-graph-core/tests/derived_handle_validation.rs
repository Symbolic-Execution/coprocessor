use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    FailureReason, HandleGraphCore, HandleId, HandleKey, HandleLineage, HandleState, HandleType,
    ImportedHandle, IngestionOutcome, LineageViolation, MaterializationReceipt, OperationCode,
    OperationViolation, SystemCiphertextV1,
};

const DEFAULT_DOMAIN: u8 = 9;
const OTHER_DOMAIN: u8 = 10;

#[test]
fn add_with_two_suint256_inputs_creates_pending_derived_handle() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core, 1, 2);
    let derived = handle_key(1, 7, 10);
    let event_ref = chain_event_ref(1, 2, 1);

    let outcome = core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        event_ref,
        DEFAULT_DOMAIN,
    ));

    assert!(matches!(outcome, IngestionOutcome::Recorded(_)));
    let record = core
        .canonical_handle(&derived)
        .expect("derived handle stored");
    assert_eq!(record.handle_type, HandleType::Suint256);
    assert_eq!(record.state, HandleState::Pending);
    assert_eq!(record.event_ref, event_ref);
    assert!(record.is_canonical);
    assert_eq!(
        record.lineage,
        HandleLineage::Derived {
            operation_code: OperationCode::Add,
            input_handle_keys: vec![a, b],
        }
    );
}

#[test]
fn select_preserves_input_order_as_predicate_when_true_when_false() {
    let mut core = HandleGraphCore::new();
    let predicate = handle_key(1, 7, 20);
    let when_true = handle_key(1, 7, 21);
    let when_false = handle_key(1, 7, 22);
    seed_imported(
        &mut core,
        predicate,
        HandleType::Sbool,
        chain_event_ref(1, 1, 20),
    );
    seed_imported(
        &mut core,
        when_true,
        HandleType::Suint256,
        chain_event_ref(1, 1, 21),
    );
    seed_imported(
        &mut core,
        when_false,
        HandleType::Suint256,
        chain_event_ref(1, 1, 22),
    );

    let derived = handle_key(1, 7, 23);
    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Select,
        HandleType::Suint256,
        vec![predicate, when_true, when_false],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core
        .canonical_handle(&derived)
        .expect("select handle stored");
    let HandleLineage::Derived {
        operation_code,
        ref input_handle_keys,
    } = record.lineage
    else {
        panic!("expected Derived lineage, got {:?}", record.lineage);
    };
    assert_eq!(operation_code, OperationCode::Select);
    assert_eq!(
        input_handle_keys,
        &vec![predicate, when_true, when_false],
        "Select must preserve predicate, when-true, when-false order"
    );
    assert_eq!(record.state, HandleState::Pending);
}

#[test]
fn derived_handles_never_become_ready_in_this_slice() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core, 1, 2);
    let derived = handle_key(1, 7, 30);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core.canonical_handle(&derived).expect("derived stored");
    assert!(
        !matches!(record.state, HandleState::Ready { .. }),
        "derived handle must not be Ready, was {:?}",
        record.state
    );
    assert_eq!(record.state, HandleState::Pending);
}

#[test]
fn duplicate_canonical_handle_key_creation_fails_later_handle_with_lineage_violation() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core, 1, 2);
    let shared = handle_key(1, 7, 40);
    let first_event = chain_event_ref(1, 2, 1);
    let second_event = chain_event_ref(1, 2, 2);

    let first = core.apply_chain_event(derived_operation_event(
        shared,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        first_event,
        DEFAULT_DOMAIN,
    ));
    assert!(matches!(first, IngestionOutcome::Recorded(_)));

    let second = core.apply_chain_event(derived_operation_event(
        shared,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        second_event,
        DEFAULT_DOMAIN,
    ));
    let rejected = match second {
        IngestionOutcome::DuplicateHandleKeyRejected(record) => record,
        other => panic!("expected DuplicateHandleKeyRejected, got {:?}", other),
    };
    assert_eq!(rejected.handle_key, shared);
    assert_eq!(rejected.event_ref, second_event);
    match rejected.state {
        HandleState::Failed {
            reason:
                FailureReason::LineageViolation(LineageViolation::DuplicateHandleKey {
                    existing_event_ref,
                }),
        } => assert_eq!(existing_event_ref, first_event),
        other => panic!("expected DuplicateHandleKey reason, got {:?}", other),
    }

    let canonical = core
        .canonical_handle(&shared)
        .expect("first canonical record preserved");
    assert_eq!(canonical.event_ref, first_event);
    assert_eq!(canonical.state, HandleState::Pending);
}

#[test]
fn unknown_input_handle_in_same_domain_fails_with_lineage_violation() {
    let mut core = HandleGraphCore::new();
    let known = handle_key(1, 7, 50);
    seed_imported(
        &mut core,
        known,
        HandleType::Suint256,
        chain_event_ref(1, 1, 1),
    );
    let unknown = handle_key(1, 7, 51);
    let derived = handle_key(1, 7, 52);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![known, unknown],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core
        .canonical_handle(&derived)
        .expect("failed record stored");
    match &record.state {
        HandleState::Failed {
            reason:
                FailureReason::LineageViolation(LineageViolation::UnknownInputHandle {
                    input_handle_key,
                }),
        } => assert_eq!(*input_handle_key, unknown),
        other => panic!("expected UnknownInputHandle, got {:?}", other),
    }
}

#[test]
fn input_handle_from_other_domain_is_a_lineage_violation() {
    let mut core = HandleGraphCore::new();
    let other_domain_input = handle_key(1, 7, 60);
    core.apply_chain_event(imported_event_owned(
        other_domain_input,
        HandleType::Suint256,
        chain_event_ref(1, 1, 1),
        OTHER_DOMAIN,
    ));
    let same_domain_input = handle_key(1, 7, 61);
    seed_imported(
        &mut core,
        same_domain_input,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
    );
    let derived = handle_key(1, 7, 62);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![other_domain_input, same_domain_input],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core
        .canonical_handle(&derived)
        .expect("failed record stored");
    match &record.state {
        HandleState::Failed {
            reason:
                FailureReason::LineageViolation(LineageViolation::UnknownInputHandle {
                    input_handle_key,
                }),
        } => assert_eq!(*input_handle_key, other_domain_input),
        other => panic!("expected cross-domain UnknownInputHandle, got {:?}", other),
    }
}

#[test]
fn wrong_operation_arity_is_an_operation_violation() {
    let mut core = HandleGraphCore::new();
    let (a, _) = seed_suint_pair(&mut core, 1, 2);
    let derived = handle_key(1, 7, 70);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core
        .canonical_handle(&derived)
        .expect("failed record stored");
    match &record.state {
        HandleState::Failed {
            reason:
                FailureReason::OperationViolation(OperationViolation::WrongArity {
                    operation_code,
                    expected,
                    actual,
                }),
        } => {
            assert_eq!(*operation_code, OperationCode::Add);
            assert_eq!(*expected, 2);
            assert_eq!(*actual, 1);
        }
        other => panic!("expected WrongArity, got {:?}", other),
    }
}

#[test]
fn wrong_input_handle_type_is_an_operation_violation() {
    let mut core = HandleGraphCore::new();
    let suint = handle_key(1, 7, 80);
    let sbool = handle_key(1, 7, 81);
    seed_imported(
        &mut core,
        suint,
        HandleType::Suint256,
        chain_event_ref(1, 1, 1),
    );
    seed_imported(
        &mut core,
        sbool,
        HandleType::Sbool,
        chain_event_ref(1, 1, 2),
    );
    let derived = handle_key(1, 7, 82);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![suint, sbool],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core
        .canonical_handle(&derived)
        .expect("failed record stored");
    match &record.state {
        HandleState::Failed {
            reason:
                FailureReason::OperationViolation(OperationViolation::WrongInputHandleType {
                    input_index,
                    expected,
                    actual,
                }),
        } => {
            assert_eq!(*input_index, 1);
            assert_eq!(*expected, HandleType::Suint256);
            assert_eq!(*actual, HandleType::Sbool);
        }
        other => panic!("expected WrongInputHandleType, got {:?}", other),
    }
}

#[test]
fn wrong_output_handle_type_is_an_operation_violation() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core, 1, 2);
    let derived = handle_key(1, 7, 90);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Sbool,
        vec![a, b],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core
        .canonical_handle(&derived)
        .expect("failed record stored");
    match &record.state {
        HandleState::Failed {
            reason:
                FailureReason::OperationViolation(OperationViolation::WrongOutputHandleType {
                    expected,
                    actual,
                }),
        } => {
            assert_eq!(*expected, HandleType::Suint256);
            assert_eq!(*actual, HandleType::Sbool);
        }
        other => panic!("expected WrongOutputHandleType, got {:?}", other),
    }
}

#[test]
fn comparison_with_two_suint256_inputs_produces_pending_sbool() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core, 1, 2);
    let derived = handle_key(1, 7, 100);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Eq,
        HandleType::Sbool,
        vec![a, b],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core.canonical_handle(&derived).expect("derived stored");
    assert_eq!(record.handle_type, HandleType::Sbool);
    assert_eq!(record.state, HandleState::Pending);
}

#[test]
fn comparison_with_sbool_input_is_wrong_input_type() {
    let mut core = HandleGraphCore::new();
    let suint = handle_key(1, 7, 110);
    let sbool = handle_key(1, 7, 111);
    seed_imported(
        &mut core,
        suint,
        HandleType::Suint256,
        chain_event_ref(1, 1, 1),
    );
    seed_imported(
        &mut core,
        sbool,
        HandleType::Sbool,
        chain_event_ref(1, 1, 2),
    );
    let derived = handle_key(1, 7, 112);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Eq,
        HandleType::Sbool,
        vec![suint, sbool],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core.canonical_handle(&derived).expect("failed");
    assert!(matches!(
        record.state,
        HandleState::Failed {
            reason: FailureReason::OperationViolation(OperationViolation::WrongInputHandleType {
                input_index: 1,
                ..
            }),
        }
    ));
}

#[test]
fn boolean_and_with_two_sbool_inputs_produces_pending_sbool() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_sbool_pair(&mut core, 3, 4);
    let derived = handle_key(1, 7, 120);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::And,
        HandleType::Sbool,
        vec![a, b],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core.canonical_handle(&derived).expect("derived stored");
    assert_eq!(record.handle_type, HandleType::Sbool);
    assert_eq!(record.state, HandleState::Pending);
}

#[test]
fn boolean_and_with_suint_input_is_wrong_input_type() {
    let mut core = HandleGraphCore::new();
    let suint = handle_key(1, 7, 130);
    let sbool = handle_key(1, 7, 131);
    seed_imported(
        &mut core,
        suint,
        HandleType::Suint256,
        chain_event_ref(1, 1, 1),
    );
    seed_imported(
        &mut core,
        sbool,
        HandleType::Sbool,
        chain_event_ref(1, 1, 2),
    );
    let derived = handle_key(1, 7, 132);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::And,
        HandleType::Sbool,
        vec![suint, sbool],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core.canonical_handle(&derived).expect("failed");
    assert!(matches!(
        record.state,
        HandleState::Failed {
            reason: FailureReason::OperationViolation(OperationViolation::WrongInputHandleType {
                input_index: 0,
                ..
            }),
        }
    ));
}

#[test]
fn not_with_one_sbool_input_produces_pending_sbool() {
    let mut core = HandleGraphCore::new();
    let sbool = handle_key(1, 7, 140);
    seed_imported(
        &mut core,
        sbool,
        HandleType::Sbool,
        chain_event_ref(1, 1, 1),
    );
    let derived = handle_key(1, 7, 141);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Not,
        HandleType::Sbool,
        vec![sbool],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core.canonical_handle(&derived).expect("derived stored");
    assert_eq!(record.state, HandleState::Pending);
}

#[test]
fn not_with_two_inputs_is_wrong_arity() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_sbool_pair(&mut core, 3, 4);
    let derived = handle_key(1, 7, 150);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Not,
        HandleType::Sbool,
        vec![a, b],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core.canonical_handle(&derived).expect("failed");
    assert!(matches!(
        record.state,
        HandleState::Failed {
            reason: FailureReason::OperationViolation(OperationViolation::WrongArity {
                operation_code: OperationCode::Not,
                expected: 1,
                actual: 2,
            }),
        }
    ));
}

#[test]
fn select_with_two_inputs_is_wrong_arity() {
    let mut core = HandleGraphCore::new();
    let predicate = handle_key(1, 7, 160);
    let when_true = handle_key(1, 7, 161);
    seed_imported(
        &mut core,
        predicate,
        HandleType::Sbool,
        chain_event_ref(1, 1, 1),
    );
    seed_imported(
        &mut core,
        when_true,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
    );
    let derived = handle_key(1, 7, 162);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Select,
        HandleType::Suint256,
        vec![predicate, when_true],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core.canonical_handle(&derived).expect("failed");
    assert!(matches!(
        record.state,
        HandleState::Failed {
            reason: FailureReason::OperationViolation(OperationViolation::WrongArity {
                operation_code: OperationCode::Select,
                expected: 3,
                actual: 2,
            }),
        }
    ));
}

#[test]
fn select_with_non_sbool_predicate_is_wrong_input_type_at_index_zero() {
    let mut core = HandleGraphCore::new();
    let predicate = handle_key(1, 7, 170);
    let when_true = handle_key(1, 7, 171);
    let when_false = handle_key(1, 7, 172);
    seed_imported(
        &mut core,
        predicate,
        HandleType::Suint256,
        chain_event_ref(1, 1, 1),
    );
    seed_imported(
        &mut core,
        when_true,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
    );
    seed_imported(
        &mut core,
        when_false,
        HandleType::Suint256,
        chain_event_ref(1, 1, 3),
    );
    let derived = handle_key(1, 7, 173);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Select,
        HandleType::Suint256,
        vec![predicate, when_true, when_false],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core.canonical_handle(&derived).expect("failed");
    match &record.state {
        HandleState::Failed {
            reason:
                FailureReason::OperationViolation(OperationViolation::WrongInputHandleType {
                    input_index,
                    expected,
                    actual,
                }),
        } => {
            assert_eq!(*input_index, 0);
            assert_eq!(*expected, HandleType::Sbool);
            assert_eq!(*actual, HandleType::Suint256);
        }
        other => panic!(
            "expected WrongInputHandleType at predicate, got {:?}",
            other
        ),
    }
}

#[test]
fn select_with_mismatched_branch_types_is_wrong_input_type_at_index_two() {
    let mut core = HandleGraphCore::new();
    let predicate = handle_key(1, 7, 180);
    let when_true = handle_key(1, 7, 181);
    let when_false = handle_key(1, 7, 182);
    seed_imported(
        &mut core,
        predicate,
        HandleType::Sbool,
        chain_event_ref(1, 1, 1),
    );
    seed_imported(
        &mut core,
        when_true,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
    );
    seed_imported(
        &mut core,
        when_false,
        HandleType::Sbool,
        chain_event_ref(1, 1, 3),
    );
    let derived = handle_key(1, 7, 183);

    core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Select,
        HandleType::Suint256,
        vec![predicate, when_true, when_false],
        chain_event_ref(1, 2, 1),
        DEFAULT_DOMAIN,
    ));

    let record = core.canonical_handle(&derived).expect("failed");
    match &record.state {
        HandleState::Failed {
            reason:
                FailureReason::OperationViolation(OperationViolation::WrongInputHandleType {
                    input_index,
                    expected,
                    actual,
                }),
        } => {
            assert_eq!(*input_index, 2);
            assert_eq!(*expected, HandleType::Suint256);
            assert_eq!(*actual, HandleType::Sbool);
        }
        other => panic!("expected branch mismatch at index 2, got {:?}", other),
    }
}

fn seed_suint_pair(core: &mut HandleGraphCore, a_seed: u8, b_seed: u8) -> (HandleKey, HandleKey) {
    let a = handle_key(1, 7, a_seed);
    let b = handle_key(1, 7, b_seed);
    seed_imported(
        core,
        a,
        HandleType::Suint256,
        chain_event_ref(1, 1, a_seed as u32),
    );
    seed_imported(
        core,
        b,
        HandleType::Suint256,
        chain_event_ref(1, 1, b_seed as u32),
    );
    (a, b)
}

fn seed_sbool_pair(core: &mut HandleGraphCore, a_seed: u8, b_seed: u8) -> (HandleKey, HandleKey) {
    let a = handle_key(1, 7, a_seed);
    let b = handle_key(1, 7, b_seed);
    seed_imported(
        core,
        a,
        HandleType::Sbool,
        chain_event_ref(1, 1, a_seed as u32),
    );
    seed_imported(
        core,
        b,
        HandleType::Sbool,
        chain_event_ref(1, 1, b_seed as u32),
    );
    (a, b)
}

fn seed_imported(
    core: &mut HandleGraphCore,
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
) {
    core.apply_chain_event(imported_event_owned(
        handle_key,
        handle_type,
        event_ref,
        DEFAULT_DOMAIN,
    ));
}

fn imported_event_owned(
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
    domain: u8,
) -> ChainEvent {
    ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId(bytes32(domain)),
        handle_key,
        handle_type,
        system_ciphertext: SystemCiphertextV1(vec![1]),
        materialization_receipt: MaterializationReceipt(vec![2]),
        event_ref,
    })
}

fn derived_operation_event(
    handle_key: HandleKey,
    operation_code: OperationCode,
    output_handle_type: HandleType,
    input_handle_keys: Vec<HandleKey>,
    event_ref: ChainEventRef,
    domain: u8,
) -> ChainEvent {
    ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id: DomainId(bytes32(domain)),
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
