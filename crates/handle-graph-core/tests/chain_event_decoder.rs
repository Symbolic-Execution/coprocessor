use coprocessor_handle_graph_core::{
    decode_chain_log, ChainEvent, ChainEventRef, ChainId, ChainLog, ChainLogDecodeError,
    ContractAddress, DomainId, HandleGraphCore, HandleId, HandleKey, HandleType, IngestionOutcome,
    MaterializationReceipt, OperationCode, PublicPlaintextValue, SystemCiphertextV1,
    HANDLE_FROM_PLAINTEXT_V1_SIGNATURE, HANDLE_IMPORTED_V1_SIGNATURE,
    OPERATION_REQUESTED_V1_SIGNATURE,
};

#[test]
fn handle_imported_v1_log_decodes_into_imported_handle_chain_event() {
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 100,
        block_hash: bytes32(0xB1),
        tx_hash: bytes32(0xC1),
        log_index: 2,
        topics: vec![HANDLE_IMPORTED_V1_SIGNATURE, bytes32(0xD0), bytes32(0x42)],
        data: encode_imported_v1_data(HandleType::Suint256, &[1, 2, 3, 4], &[9, 9]),
    };

    let event = decode_chain_log(&log).expect("imported v1 log should decode");
    let ChainEvent::ImportedHandle(imported) = event else {
        panic!("expected ImportedHandle, got {:?}", event);
    };
    assert_eq!(imported.domain_id, DomainId(bytes32(0xD0)));
    assert_eq!(
        imported.handle_key,
        HandleKey {
            chain_id: ChainId(1),
            contract_address: ContractAddress([7; 20]),
            handle_id: HandleId(bytes32(0x42)),
        }
    );
    assert_eq!(imported.handle_type, HandleType::Suint256);
    assert_eq!(
        imported.system_ciphertext,
        SystemCiphertextV1(vec![1, 2, 3, 4])
    );
    assert_eq!(
        imported.materialization_receipt,
        MaterializationReceipt(vec![9, 9])
    );
    assert_eq!(
        imported.event_ref,
        ChainEventRef {
            chain_id: ChainId(1),
            block_number: 100,
            block_hash: bytes32(0xB1),
            tx_hash: bytes32(0xC1),
            log_index: 2,
        }
    );
}

#[test]
fn handle_imported_v1_preserves_opaque_ciphertext_bytes_unchanged() {
    let ciphertext: Vec<u8> = (0u8..=255u8).collect();
    let receipt: Vec<u8> = vec![0xAB; 73];
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![HANDLE_IMPORTED_V1_SIGNATURE, bytes32(0xD0), bytes32(1)],
        data: encode_imported_v1_data(HandleType::Sbool, &ciphertext, &receipt),
    };

    let event = decode_chain_log(&log).expect("imported v1 log should decode");
    let ChainEvent::ImportedHandle(imported) = event else {
        panic!("expected ImportedHandle");
    };
    assert_eq!(imported.system_ciphertext.0, ciphertext);
    assert_eq!(imported.materialization_receipt.0, receipt);
}

#[test]
fn handle_from_plaintext_v1_log_decodes_into_plaintext_handle_chain_event() {
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 200,
        block_hash: bytes32(0xB2),
        tx_hash: bytes32(0xC2),
        log_index: 5,
        topics: vec![
            HANDLE_FROM_PLAINTEXT_V1_SIGNATURE,
            bytes32(0xD0),
            bytes32(0x43),
        ],
        data: encode_plaintext_v1_data(HandleType::Suint256, &[10, 20, 30]),
    };

    let event = decode_chain_log(&log).expect("plaintext v1 log should decode");
    let ChainEvent::PlaintextHandle(plaintext) = event else {
        panic!("expected PlaintextHandle, got {:?}", event);
    };
    assert_eq!(plaintext.domain_id, DomainId(bytes32(0xD0)));
    assert_eq!(
        plaintext.handle_key,
        HandleKey {
            chain_id: ChainId(1),
            contract_address: ContractAddress([7; 20]),
            handle_id: HandleId(bytes32(0x43)),
        }
    );
    assert_eq!(plaintext.handle_type, HandleType::Suint256);
    assert_eq!(
        plaintext.public_value,
        PublicPlaintextValue(vec![10, 20, 30])
    );
    assert_eq!(
        plaintext.event_ref,
        ChainEventRef {
            chain_id: ChainId(1),
            block_number: 200,
            block_hash: bytes32(0xB2),
            tx_hash: bytes32(0xC2),
            log_index: 5,
        }
    );
}

#[test]
fn operation_requested_v1_log_preserves_ordered_input_handles() {
    let input_a = bytes32(0xA0);
    let input_b = bytes32(0xB0);
    let input_c = bytes32(0xC0);
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 300,
        block_hash: bytes32(0xB3),
        tx_hash: bytes32(0xC3),
        log_index: 1,
        topics: vec![
            OPERATION_REQUESTED_V1_SIGNATURE,
            bytes32(0xD0),
            bytes32(0x99),
        ],
        data: encode_operation_v1_data(
            OperationCode::Select,
            HandleType::Suint256,
            &[input_a, input_b, input_c],
        ),
    };

    let event = decode_chain_log(&log).expect("operation v1 log should decode");
    let ChainEvent::DerivedHandleOperation(op) = event else {
        panic!("expected DerivedHandleOperation, got {:?}", event);
    };
    assert_eq!(op.operation_code, OperationCode::Select);
    assert_eq!(op.output_handle_type, HandleType::Suint256);
    assert_eq!(
        op.input_handle_keys,
        vec![
            HandleKey {
                chain_id: ChainId(1),
                contract_address: ContractAddress([7; 20]),
                handle_id: HandleId(input_a),
            },
            HandleKey {
                chain_id: ChainId(1),
                contract_address: ContractAddress([7; 20]),
                handle_id: HandleId(input_b),
            },
            HandleKey {
                chain_id: ChainId(1),
                contract_address: ContractAddress([7; 20]),
                handle_id: HandleId(input_c),
            },
        ]
    );
}

#[test]
fn operation_requested_v1_decodes_every_operation_code_discriminant() {
    // The decoder only needs to round-trip each OperationCode discriminant.
    // Type and arity semantics are enforced later by HandleGraphCore, so
    // `arity` here just picks how many input ids to pack into the log.
    let cases: &[(OperationCode, HandleType, usize)] = &[
        (OperationCode::Add, HandleType::Suint256, 2),
        (OperationCode::Sub, HandleType::Suint256, 2),
        (OperationCode::Eq, HandleType::Sbool, 2),
        (OperationCode::Lt, HandleType::Sbool, 2),
        (OperationCode::Lte, HandleType::Sbool, 2),
        (OperationCode::Gt, HandleType::Sbool, 2),
        (OperationCode::Gte, HandleType::Sbool, 2),
        (OperationCode::And, HandleType::Sbool, 2),
        (OperationCode::Or, HandleType::Sbool, 2),
        (OperationCode::Not, HandleType::Sbool, 1),
        (OperationCode::Select, HandleType::Suint256, 3),
    ];
    for (operation_code, output_type, arity) in cases {
        let inputs: Vec<[u8; 32]> = (0..*arity).map(|i| bytes32(0x10 + i as u8)).collect();
        let log = ChainLog {
            chain_id: ChainId(1),
            contract_address: ContractAddress([7; 20]),
            block_number: 1,
            block_hash: bytes32(1),
            tx_hash: bytes32(1),
            log_index: 0,
            topics: vec![
                OPERATION_REQUESTED_V1_SIGNATURE,
                bytes32(0xD0),
                bytes32(0x55),
            ],
            data: encode_operation_v1_data(*operation_code, *output_type, &inputs),
        };
        let event = decode_chain_log(&log)
            .unwrap_or_else(|err| panic!("opcode {:?} must decode, got {:?}", operation_code, err));
        let ChainEvent::DerivedHandleOperation(op) = event else {
            panic!(
                "expected DerivedHandleOperation for opcode {:?}",
                operation_code
            );
        };
        assert_eq!(op.operation_code, *operation_code);
        assert_eq!(op.output_handle_type, *output_type);
        assert_eq!(op.input_handle_keys.len(), *arity);
        for (i, input_key) in op.input_handle_keys.iter().enumerate() {
            assert_eq!(input_key.handle_id, HandleId(bytes32(0x10 + i as u8)));
        }
    }
}

#[test]
fn empty_topics_log_is_rejected() {
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![],
        data: vec![],
    };
    assert!(matches!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::EmptyTopics)
    ));
}

#[test]
fn unknown_event_signature_is_rejected() {
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![bytes32(0xEE), bytes32(0), bytes32(0)],
        data: vec![],
    };
    let err = decode_chain_log(&log).expect_err("unknown signature should not decode");
    let ChainLogDecodeError::UnknownEventSignature(sig) = err else {
        panic!("expected UnknownEventSignature, got {:?}", err);
    };
    assert_eq!(sig, bytes32(0xEE));
}

#[test]
fn unexpected_topic_count_for_imported_v1_is_rejected() {
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![HANDLE_IMPORTED_V1_SIGNATURE, bytes32(0xD0)],
        data: encode_imported_v1_data(HandleType::Suint256, &[1], &[2]),
    };
    let err = decode_chain_log(&log).expect_err("missing handle_id topic should fail");
    assert!(matches!(
        err,
        ChainLogDecodeError::UnexpectedTopicCount {
            expected: 3,
            actual: 2,
            ..
        }
    ));
}

#[test]
fn truncated_imported_v1_data_is_rejected() {
    let mut data = encode_imported_v1_data(HandleType::Suint256, &[1, 2, 3, 4], &[5]);
    data.truncate(data.len() - 3);
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![HANDLE_IMPORTED_V1_SIGNATURE, bytes32(0xD0), bytes32(0x42)],
        data,
    };
    assert!(matches!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::TruncatedData { .. })
    ));
}

#[test]
fn truncated_operation_v1_input_list_is_rejected() {
    let mut data = encode_operation_v1_data(
        OperationCode::Add,
        HandleType::Suint256,
        &[bytes32(0xA0), bytes32(0xB0)],
    );
    data.truncate(data.len() - 5);
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![
            OPERATION_REQUESTED_V1_SIGNATURE,
            bytes32(0xD0),
            bytes32(0x99),
        ],
        data,
    };
    assert!(matches!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::TruncatedData { .. })
    ));
}

#[test]
fn oversized_operation_v1_input_count_is_rejected_without_allocating_inputs() {
    let mut data = Vec::new();
    data.push(operation_code_byte(OperationCode::Add));
    data.push(handle_type_byte(HandleType::Suint256));
    data.extend_from_slice(&u32::MAX.to_be_bytes());
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![
            OPERATION_REQUESTED_V1_SIGNATURE,
            bytes32(0xD0),
            bytes32(0x99),
        ],
        data,
    };
    assert_eq!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::TruncatedData {
            needed: 32,
            available: 0,
        })
    );
}

#[test]
fn unknown_operation_code_byte_is_rejected() {
    let mut data = encode_operation_v1_data(
        OperationCode::Add,
        HandleType::Suint256,
        &[bytes32(0xA0), bytes32(0xB0)],
    );
    data[0] = 200; // overwrite operation code with an out-of-range discriminant
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![
            OPERATION_REQUESTED_V1_SIGNATURE,
            bytes32(0xD0),
            bytes32(0x99),
        ],
        data,
    };
    assert_eq!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::UnknownOperationCode(200))
    );
}

#[test]
fn unknown_handle_type_byte_is_rejected() {
    let mut data = encode_imported_v1_data(HandleType::Suint256, &[1], &[2]);
    data[0] = 99; // overwrite handle type with an out-of-range discriminant
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![HANDLE_IMPORTED_V1_SIGNATURE, bytes32(0xD0), bytes32(0x42)],
        data,
    };
    assert_eq!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::UnknownHandleType(99))
    );
}

#[test]
fn trailing_data_after_imported_v1_is_rejected() {
    let mut data = encode_imported_v1_data(HandleType::Suint256, &[1], &[2]);
    data.push(0xFF);
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![HANDLE_IMPORTED_V1_SIGNATURE, bytes32(0xD0), bytes32(0x42)],
        data,
    };
    assert!(matches!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::TrailingData { .. })
    ));
}

#[test]
fn decoded_imported_handle_event_flows_into_apply_chain_event() {
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(0xB1),
        tx_hash: bytes32(0xC1),
        log_index: 0,
        topics: vec![HANDLE_IMPORTED_V1_SIGNATURE, bytes32(0xD0), bytes32(0x42)],
        data: encode_imported_v1_data(HandleType::Suint256, &[1, 2, 3], &[7, 8]),
    };
    let event = decode_chain_log(&log).expect("decode imported");

    let mut core = HandleGraphCore::new();
    let outcome = core.apply_chain_event(event);
    assert!(matches!(outcome, IngestionOutcome::Recorded(_)));

    let record = core
        .canonical_handle(&HandleKey {
            chain_id: ChainId(1),
            contract_address: ContractAddress([7; 20]),
            handle_id: HandleId(bytes32(0x42)),
        })
        .expect("decoded imported handle should be canonical");
    assert_eq!(record.handle_type, HandleType::Suint256);
}

// Test-side encoders mirror the wire layout the decoder owns; keeping them here
// keeps the encoder/decoder symmetric for tests without exposing helpers from
// the production surface.

fn encode_imported_v1_data(handle_type: HandleType, ciphertext: &[u8], receipt: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.push(handle_type_byte(handle_type));
    data.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    data.extend_from_slice(ciphertext);
    data.extend_from_slice(&(receipt.len() as u32).to_be_bytes());
    data.extend_from_slice(receipt);
    data
}

fn encode_plaintext_v1_data(handle_type: HandleType, value: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.push(handle_type_byte(handle_type));
    data.extend_from_slice(&(value.len() as u32).to_be_bytes());
    data.extend_from_slice(value);
    data
}

fn encode_operation_v1_data(
    op: OperationCode,
    output_type: HandleType,
    inputs: &[[u8; 32]],
) -> Vec<u8> {
    let mut data = Vec::new();
    data.push(operation_code_byte(op));
    data.push(handle_type_byte(output_type));
    data.extend_from_slice(&(inputs.len() as u32).to_be_bytes());
    for input in inputs {
        data.extend_from_slice(input);
    }
    data
}

fn handle_type_byte(handle_type: HandleType) -> u8 {
    match handle_type {
        HandleType::Suint256 => 0,
        HandleType::Sbool => 1,
    }
}

fn operation_code_byte(op: OperationCode) -> u8 {
    match op {
        OperationCode::Add => 0,
        OperationCode::Sub => 1,
        OperationCode::Eq => 2,
        OperationCode::Lt => 3,
        OperationCode::Lte => 4,
        OperationCode::Gt => 5,
        OperationCode::Gte => 6,
        OperationCode::And => 7,
        OperationCode::Or => 8,
        OperationCode::Not => 9,
        OperationCode::Select => 10,
    }
}

fn bytes32(seed: u8) -> [u8; 32] {
    [seed; 32]
}
