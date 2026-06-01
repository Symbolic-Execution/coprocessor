use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DomainId, HandleGraphCore, HandleId,
    HandleKey, HandleState, HandleType, PlaintextHandle, PublicPlaintextValue,
};

#[test]
fn plaintext_handle_suint256_chain_event_creates_ready_canonical_record() {
    let mut core = HandleGraphCore::new();
    let handle_key = handle_key(1, 7, 42);
    let event_ref = chain_event_ref(1, 10, 3);

    core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Suint256,
        PublicPlaintextValue(vec![0xAB, 0xCD]),
    ));

    let record = core
        .canonical_handle(&handle_key)
        .expect("plaintext handle should be queryable by Handle Key");

    assert_eq!(record.handle_key, handle_key);
    assert_eq!(record.handle_type, HandleType::Suint256);
    assert_eq!(record.event_ref, event_ref);
    assert!(record.is_canonical);
    assert!(
        matches!(record.state, HandleState::Ready { .. }),
        "plaintext handle must be Ready immediately after Chain Event ingestion"
    );
}

#[test]
fn plaintext_handle_sbool_chain_event_creates_ready_canonical_record() {
    let mut core = HandleGraphCore::new();
    let handle_key = handle_key(1, 7, 100);
    let event_ref = chain_event_ref(1, 10, 5);

    core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Sbool,
        PublicPlaintextValue(vec![0x01]),
    ));

    let record = core
        .canonical_handle(&handle_key)
        .expect("plaintext handle should be queryable by Handle Key");

    assert_eq!(record.handle_type, HandleType::Sbool);
    assert_eq!(record.event_ref, event_ref);
    assert!(record.is_canonical);
    assert!(matches!(record.state, HandleState::Ready { .. }));
}

#[test]
fn plaintext_handle_ready_state_carries_opaque_ciphertext_and_receipt() {
    let mut core = HandleGraphCore::new();
    let handle_key = handle_key(1, 7, 42);
    let event_ref = chain_event_ref(1, 10, 3);

    core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Suint256,
        PublicPlaintextValue(vec![0xAB, 0xCD]),
    ));

    let record = core.canonical_handle(&handle_key).unwrap();
    match &record.state {
        HandleState::Ready {
            system_ciphertext,
            materialization_receipt,
        } => {
            assert!(
                !system_ciphertext.0.is_empty(),
                "Ready must carry an opaque placeholder SystemCiphertextV1"
            );
            assert!(
                !materialization_receipt.0.is_empty(),
                "Ready must carry an opaque placeholder Materialization Receipt"
            );
        }
    }
}

#[test]
fn plaintext_handle_does_not_store_public_plaintext_value_as_ciphertext() {
    // Plaintext Handle names the source: a Public Plaintext Value. The Handle
    // itself still expresses Ready through opaque materialization values, not by
    // surfacing the raw plaintext as Handle State.
    let mut core = HandleGraphCore::new();
    let handle_key = handle_key(1, 7, 42);
    let event_ref = chain_event_ref(1, 10, 3);
    let raw_public_value = vec![0xDE, 0xAD, 0xBE, 0xEF];

    core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Suint256,
        PublicPlaintextValue(raw_public_value.clone()),
    ));

    let record = core.canonical_handle(&handle_key).unwrap();
    match &record.state {
        HandleState::Ready {
            system_ciphertext,
            materialization_receipt,
        } => {
            assert_ne!(
                system_ciphertext.0, raw_public_value,
                "Plaintext Handle SystemCiphertextV1 must be a materialization placeholder, \
                 not the raw Public Plaintext Value bytes"
            );
            assert_ne!(
                materialization_receipt.0, raw_public_value,
                "Plaintext Handle Materialization Receipt must be a placeholder, \
                 not the raw Public Plaintext Value bytes"
            );
        }
    }
}

#[test]
fn re_consuming_same_plaintext_chain_event_ref_does_not_replace_record() {
    let mut core = HandleGraphCore::new();
    let handle_key = handle_key(1, 7, 42);
    let event_ref = chain_event_ref(1, 10, 3);

    core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Suint256,
        PublicPlaintextValue(vec![1, 2, 3]),
    ));

    let original = core.canonical_handle(&handle_key).cloned().unwrap();

    core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Sbool,
        PublicPlaintextValue(vec![9, 9, 9]),
    ));

    let after = core.canonical_handle(&handle_key).cloned().unwrap();
    assert_eq!(
        after, original,
        "re-consuming the same ChainEventRef must be idempotent"
    );
}

#[test]
fn plaintext_handle_key_distinguishes_handle_id_across_chain_id_and_contract_address() {
    let mut core = HandleGraphCore::new();
    let first = handle_key(1, 7, 42);
    let different_chain = handle_key(2, 7, 42);
    let different_contract = handle_key(1, 8, 42);

    for (handle_key, event_ref, value) in [
        (first, chain_event_ref(1, 10, 1), vec![1]),
        (different_chain, chain_event_ref(2, 10, 2), vec![2]),
        (different_contract, chain_event_ref(1, 10, 3), vec![3]),
    ] {
        core.apply_chain_event(plaintext_handle_event(
            handle_key,
            event_ref,
            HandleType::Suint256,
            PublicPlaintextValue(value),
        ));
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

fn plaintext_handle_event(
    handle_key: HandleKey,
    event_ref: ChainEventRef,
    handle_type: HandleType,
    public_value: PublicPlaintextValue,
) -> ChainEvent {
    ChainEvent::PlaintextHandle(PlaintextHandle {
        domain_id: DomainId(bytes32(9)),
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
