use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleGraphCore, HandleId, HandleKey, HandleRecord, HandleType, ImportedHandle,
    IngestionOutcome, OperationCode, PlaintextHandle, PublicPlaintextValue, ResolutionReadiness,
    SystemCiphertextV1,
};

const DEFAULT_DOMAIN: u8 = 9;

#[test]
fn derived_handle_with_all_ready_inputs_is_reported_ready() {
    let mut core = HandleGraphCore::new();
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    let a_ciphertext = SystemCiphertextV1(vec![0xAA]);
    let b_ciphertext = SystemCiphertextV1(vec![0xBB]);
    seed_imported_with_ciphertext(
        &mut core,
        a,
        HandleType::Suint256,
        chain_event_ref(1, 1, 1),
        a_ciphertext.clone(),
    );
    seed_imported_with_ciphertext(
        &mut core,
        b,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
        b_ciphertext.clone(),
    );
    let derived = handle_key(1, 7, 3);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        chain_event_ref(1, 2, 1),
    )));

    let ready = core.resolution_readiness();
    let entry = find_readiness(&ready, &derived).expect("derived must be reported ready");
    assert_eq!(entry.operation_code, OperationCode::Add);
    assert_eq!(entry.output_handle_type, HandleType::Suint256);
    assert_eq!(entry.input_handle_keys, vec![a, b]);
    assert_eq!(
        entry.input_system_ciphertexts,
        vec![a_ciphertext, b_ciphertext]
    );
}

#[test]
fn derived_handle_with_pending_input_is_not_reported_ready() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core);
    // first derived is Pending but has Ready inputs => itself ready
    let first_derived = handle_key(1, 7, 10);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        first_derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        chain_event_ref(1, 2, 1),
    )));
    // second derived depends on the first derived which is Pending (never becomes Ready in this slice)
    let other_input = handle_key(1, 7, 11);
    seed_imported_with_ciphertext(
        &mut core,
        other_input,
        HandleType::Suint256,
        chain_event_ref(1, 1, 11),
        SystemCiphertextV1(vec![0x11]),
    );
    let second_derived = handle_key(1, 7, 12);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        second_derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![first_derived, other_input],
        chain_event_ref(1, 2, 2),
    )));

    let ready = core.resolution_readiness();
    assert!(
        find_readiness(&ready, &first_derived).is_some(),
        "first derived has Ready inputs and must be reported"
    );
    assert!(
        find_readiness(&ready, &second_derived).is_none(),
        "second derived depends on a Pending derived and must not be reported"
    );
}

#[test]
fn derived_handle_with_failed_input_is_not_reported_ready() {
    let mut core = HandleGraphCore::new();
    let (a, _) = seed_suint_pair(&mut core);
    // Build a Failed derived by giving the wrong arity
    let failed = handle_key(1, 7, 20);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        failed,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a],
        chain_event_ref(1, 2, 1),
    )));
    // Build a derived whose inputs include the Failed handle
    let other = handle_key(1, 7, 21);
    seed_imported_with_ciphertext(
        &mut core,
        other,
        HandleType::Suint256,
        chain_event_ref(1, 1, 21),
        SystemCiphertextV1(vec![0x21]),
    );
    let depends_on_failed = handle_key(1, 7, 22);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        depends_on_failed,
        OperationCode::Add,
        HandleType::Suint256,
        vec![failed, other],
        chain_event_ref(1, 2, 2),
    )));

    let ready = core.resolution_readiness();
    assert!(
        find_readiness(&ready, &depends_on_failed).is_none(),
        "derived depending on a Failed input must not be reported ready"
    );
}

#[test]
fn failed_derived_handle_is_never_reported_ready() {
    let mut core = HandleGraphCore::new();
    let (a, _) = seed_suint_pair(&mut core);
    let failed = handle_key(1, 7, 30);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        failed,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a],
        chain_event_ref(1, 2, 1),
    )));

    let ready = core.resolution_readiness();
    assert!(
        find_readiness(&ready, &failed).is_none(),
        "Failed derived handle must never be reported ready"
    );
}

#[test]
fn select_readiness_preserves_predicate_when_true_when_false_order() {
    let mut core = HandleGraphCore::new();
    let predicate = handle_key(1, 7, 40);
    let when_true = handle_key(1, 7, 41);
    let when_false = handle_key(1, 7, 42);
    let predicate_ciphertext = SystemCiphertextV1(vec![0xC0]);
    let when_true_ciphertext = SystemCiphertextV1(vec![0xC1]);
    let when_false_ciphertext = SystemCiphertextV1(vec![0xC2]);
    seed_imported_with_ciphertext(
        &mut core,
        predicate,
        HandleType::Sbool,
        chain_event_ref(1, 1, 40),
        predicate_ciphertext.clone(),
    );
    seed_imported_with_ciphertext(
        &mut core,
        when_true,
        HandleType::Suint256,
        chain_event_ref(1, 1, 41),
        when_true_ciphertext.clone(),
    );
    seed_imported_with_ciphertext(
        &mut core,
        when_false,
        HandleType::Suint256,
        chain_event_ref(1, 1, 42),
        when_false_ciphertext.clone(),
    );
    let derived = handle_key(1, 7, 43);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Select,
        HandleType::Suint256,
        vec![predicate, when_true, when_false],
        chain_event_ref(1, 2, 1),
    )));

    let ready = core.resolution_readiness();
    let entry = find_readiness(&ready, &derived).expect("select ready");
    assert_eq!(entry.operation_code, OperationCode::Select);
    assert_eq!(entry.output_handle_type, HandleType::Suint256);
    assert_eq!(
        entry.input_handle_keys,
        vec![predicate, when_true, when_false],
        "Select readiness must preserve predicate, when-true, when-false order"
    );
    assert_eq!(
        entry.input_system_ciphertexts,
        vec![
            predicate_ciphertext,
            when_true_ciphertext,
            when_false_ciphertext
        ],
        "Select ciphertexts must match the input handle key order"
    );
}

#[test]
fn plaintext_source_inputs_are_reported_with_their_ciphertext() {
    let mut core = HandleGraphCore::new();
    let plaintext_input = handle_key(1, 7, 50);
    let imported_input = handle_key(1, 7, 51);
    let imported_ciphertext = SystemCiphertextV1(vec![0x51]);
    let _ = expect_recorded(core.apply_chain_event(plaintext_handle_event(
        plaintext_input,
        chain_event_ref(1, 1, 50),
        HandleType::Suint256,
        PublicPlaintextValue(vec![0x01, 0x02]),
    )));
    seed_imported_with_ciphertext(
        &mut core,
        imported_input,
        HandleType::Suint256,
        chain_event_ref(1, 1, 51),
        imported_ciphertext.clone(),
    );
    let plaintext_ciphertext = core
        .canonical_handle(&plaintext_input)
        .and_then(|record| match &record.state {
            coprocessor_handle_graph_core::HandleState::Ready {
                system_ciphertext, ..
            } => Some(system_ciphertext.clone()),
            _ => None,
        })
        .expect("plaintext source handle must be Ready");
    let derived = handle_key(1, 7, 52);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        derived,
        OperationCode::Add,
        HandleType::Suint256,
        vec![plaintext_input, imported_input],
        chain_event_ref(1, 2, 1),
    )));

    let ready = core.resolution_readiness();
    let entry = find_readiness(&ready, &derived).expect("mixed-source derived ready");
    assert_eq!(
        entry.input_system_ciphertexts,
        vec![plaintext_ciphertext, imported_ciphertext]
    );
}

#[test]
fn empty_core_reports_no_resolution_readiness() {
    let core = HandleGraphCore::new();
    assert!(core.resolution_readiness().is_empty());
}

#[test]
fn source_handles_are_not_themselves_resolution_ready_targets() {
    let mut core = HandleGraphCore::new();
    let _ = seed_suint_pair(&mut core);
    // Source handles are Ready already; they are not Resolution targets.
    let ready = core.resolution_readiness();
    assert!(
        ready.is_empty(),
        "Resolution Readiness reports Derived targets only, got {:?}",
        ready
    );
}

#[test]
fn multiple_independent_derived_handles_are_all_reported() {
    let mut core = HandleGraphCore::new();
    let (a, b) = seed_suint_pair(&mut core);
    let first = handle_key(1, 7, 60);
    let second = handle_key(1, 7, 61);
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        first,
        OperationCode::Add,
        HandleType::Suint256,
        vec![a, b],
        chain_event_ref(1, 2, 1),
    )));
    let _ = expect_recorded(core.apply_chain_event(derived_operation_event(
        second,
        OperationCode::Eq,
        HandleType::Sbool,
        vec![a, b],
        chain_event_ref(1, 2, 2),
    )));

    let ready = core.resolution_readiness();
    assert_eq!(
        ready.len(),
        2,
        "two independent Pending derived handles with Ready inputs should both be reported, got {:?}",
        ready
    );
    let first_entry = find_readiness(&ready, &first).expect("first derived ready");
    assert_eq!(first_entry.operation_code, OperationCode::Add);
    assert_eq!(first_entry.output_handle_type, HandleType::Suint256);
    let second_entry = find_readiness(&ready, &second).expect("second derived ready");
    assert_eq!(second_entry.operation_code, OperationCode::Eq);
    assert_eq!(second_entry.output_handle_type, HandleType::Sbool);
}

fn find_readiness<'a>(
    ready: &'a [ResolutionReadiness],
    handle_key: &HandleKey,
) -> Option<&'a ResolutionReadiness> {
    ready.iter().find(|entry| entry.handle_key == *handle_key)
}

fn seed_suint_pair(core: &mut HandleGraphCore) -> (HandleKey, HandleKey) {
    let a = handle_key(1, 7, 1);
    let b = handle_key(1, 7, 2);
    seed_imported_with_ciphertext(
        core,
        a,
        HandleType::Suint256,
        chain_event_ref(1, 1, 1),
        SystemCiphertextV1(vec![0xA1]),
    );
    seed_imported_with_ciphertext(
        core,
        b,
        HandleType::Suint256,
        chain_event_ref(1, 1, 2),
        SystemCiphertextV1(vec![0xB2]),
    );
    (a, b)
}

fn seed_imported_with_ciphertext(
    core: &mut HandleGraphCore,
    handle_key: HandleKey,
    handle_type: HandleType,
    event_ref: ChainEventRef,
    system_ciphertext: SystemCiphertextV1,
) {
    let _ = expect_recorded(
        core.apply_chain_event(ChainEvent::ImportedHandle(ImportedHandle {
            domain_id: DomainId(bytes32(DEFAULT_DOMAIN)),
            handle_key,
            handle_type,
            system_ciphertext,
            event_ref,
        })),
    );
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
