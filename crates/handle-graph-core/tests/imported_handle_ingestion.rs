use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DomainId, HandleGraphCore, HandleId,
    HandleKey, HandleRecord, HandleState, HandleType, ImportedHandle, IngestionOutcome,
    MaterializationReceipt, SystemCiphertextV1,
};

#[test]
fn imported_handle_chain_event_creates_ready_canonical_handle_record() {
    let mut core = HandleGraphCore::new();
    let handle_key = handle_key(1, 7, 42);
    let event_ref = chain_event_ref(1, 10, 3);
    let system_ciphertext = SystemCiphertextV1(vec![1, 2, 3]);

    let _ = expect_recorded(core.apply_chain_event(imported_handle_event(
        handle_key,
        event_ref,
        HandleType::Suint256,
        system_ciphertext.clone(),
    )));

    let record = core
        .canonical_handle(&handle_key)
        .expect("imported handle should be queryable by Handle Key");

    assert_eq!(record.handle_key, handle_key);
    assert_eq!(record.handle_type, HandleType::Suint256);
    assert_eq!(record.event_ref, event_ref);
    assert!(record.is_canonical);
    // Per spec, imported handles carry an empty materialization receipt;
    // the SystemCiphertextV1 from the event is the ready source value.
    assert_eq!(
        record.state,
        HandleState::Ready {
            system_ciphertext,
            materialization_receipt: MaterializationReceipt(Vec::new()),
        }
    );
}

#[test]
fn unknown_handle_key_is_not_pending() {
    let core = HandleGraphCore::new();

    assert!(core.canonical_handle(&handle_key(1, 7, 99)).is_none());
}

#[test]
fn re_consuming_same_chain_event_ref_does_not_replace_imported_handle_record() {
    let mut core = HandleGraphCore::new();
    let handle_key = handle_key(1, 7, 42);
    let event_ref = chain_event_ref(1, 10, 3);
    let original_ciphertext = SystemCiphertextV1(vec![1, 2, 3]);

    let _ = expect_recorded(core.apply_chain_event(imported_handle_event(
        handle_key,
        event_ref,
        HandleType::Suint256,
        original_ciphertext.clone(),
    )));

    assert!(matches!(
        core.apply_chain_event(imported_handle_event(
            handle_key,
            event_ref,
            HandleType::Suint256,
            SystemCiphertextV1(vec![7, 8, 9]),
        )),
        IngestionOutcome::Idempotent,
    ));

    assert_eq!(
        core.canonical_handle(&handle_key)
            .map(|record| &record.state),
        Some(&HandleState::Ready {
            system_ciphertext: original_ciphertext,
            materialization_receipt: MaterializationReceipt(Vec::new()),
        })
    );
}

#[test]
fn handle_key_distinguishes_same_handle_id_across_chain_id_and_contract_address() {
    let mut core = HandleGraphCore::new();
    let first = handle_key(1, 7, 42);
    let different_chain = handle_key(2, 7, 42);
    let different_contract = handle_key(1, 8, 42);

    for (handle_key, event_ref, ciphertext) in [
        (first, chain_event_ref(1, 10, 1), vec![1]),
        (different_chain, chain_event_ref(2, 10, 2), vec![2]),
        (different_contract, chain_event_ref(1, 10, 3), vec![3]),
    ] {
        let _ = expect_recorded(core.apply_chain_event(imported_handle_event(
            handle_key,
            event_ref,
            HandleType::Suint256,
            SystemCiphertextV1(ciphertext),
        )));
    }

    assert_eq!(
        core.canonical_handle(&first)
            .map(|record| record.handle_key),
        Some(first)
    );
    assert_eq!(
        core.canonical_handle(&different_chain)
            .map(|record| record.handle_key),
        Some(different_chain)
    );
    assert_eq!(
        core.canonical_handle(&different_contract)
            .map(|record| record.handle_key),
        Some(different_contract)
    );
}

fn expect_recorded(outcome: IngestionOutcome) -> HandleRecord {
    match outcome {
        IngestionOutcome::Recorded(record) => record,
        other => panic!("expected Recorded, got {:?}", other),
    }
}

fn imported_handle_event(
    handle_key: HandleKey,
    event_ref: ChainEventRef,
    handle_type: HandleType,
    system_ciphertext: SystemCiphertextV1,
) -> ChainEvent {
    ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId(bytes32(9)),
        handle_key,
        handle_type,
        system_ciphertext,
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
