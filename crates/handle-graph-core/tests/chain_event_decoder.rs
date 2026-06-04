use coprocessor_handle_graph_core::{
    decode_chain_log, ChainEvent, ChainEventRef, ChainId, ChainLog, ChainLogDecodeError,
    ContractAddress, DomainId, HandleGraphCore, HandleId, HandleKey, HandleType, IngestionOutcome,
    OperationCode, PublicPlaintextValue, SystemCiphertextV1, HANDLE_FROM_PLAINTEXT_V1_SIGNATURE,
    HANDLE_IMPORTED_V1_SIGNATURE, OPERATION_REQUESTED_V1_SIGNATURE,
};

// ---------------------------------------------------------------------------
// Decode happy-path tests
// ---------------------------------------------------------------------------

#[test]
fn handle_imported_v1_log_decodes_into_imported_handle_chain_event() {
    let contract_addr = [7u8; 20];
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([0xFF; 20]), // emitter — irrelevant, topic2 wins
        block_number: 100,
        block_hash: bytes32(0xB1),
        tx_hash: bytes32(0xC1),
        log_index: 2,
        topics: vec![
            HANDLE_IMPORTED_V1_SIGNATURE,
            bytes32(0xD0),
            address_topic(contract_addr),
            bytes32(0x42),
        ],
        data: encode_imported_data(HandleType::Suint256, &[1, 2, 3, 4]),
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
            contract_address: ContractAddress(contract_addr),
            handle_id: HandleId(bytes32(0x42)),
        }
    );
    assert_eq!(imported.handle_type, HandleType::Suint256);
    assert_eq!(
        imported.system_ciphertext,
        SystemCiphertextV1(vec![1, 2, 3, 4])
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
fn contract_address_is_decoded_from_topic2_not_log_emitter() {
    let topic_addr = [0xAA; 20];
    let emitter_addr = [0xBB; 20]; // different from topic2
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress(emitter_addr),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![
            HANDLE_IMPORTED_V1_SIGNATURE,
            bytes32(0xD0),
            address_topic(topic_addr),
            bytes32(0x42),
        ],
        data: encode_imported_data(HandleType::Suint256, &[1, 2, 3]),
    };

    let event = decode_chain_log(&log).expect("should decode");
    let ChainEvent::ImportedHandle(imported) = event else {
        panic!("expected ImportedHandle");
    };
    assert_eq!(
        imported.handle_key.contract_address,
        ContractAddress(topic_addr),
        "contract_address must be decoded from topic2, not from ChainLog.contract_address"
    );
}

#[test]
fn handle_imported_v1_preserves_opaque_ciphertext_bytes_unchanged() {
    let ciphertext: Vec<u8> = (0u8..=255u8).collect();
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![
            HANDLE_IMPORTED_V1_SIGNATURE,
            bytes32(0xD0),
            address_topic([7; 20]),
            bytes32(1),
        ],
        data: encode_imported_data(HandleType::Sbool, &ciphertext),
    };

    let event = decode_chain_log(&log).expect("imported v1 log should decode");
    let ChainEvent::ImportedHandle(imported) = event else {
        panic!("expected ImportedHandle");
    };
    assert_eq!(imported.system_ciphertext.0, ciphertext);
}

#[test]
fn handle_from_plaintext_v1_log_decodes_into_plaintext_handle_chain_event() {
    let plaintext = bytes32(0xAB);
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
            address_topic([7; 20]),
            bytes32(0x43),
        ],
        data: encode_plaintext_data(HandleType::Suint256, &plaintext),
    };

    let event = decode_chain_log(&log).expect("plaintext v1 log should decode");
    let ChainEvent::PlaintextHandle(pt) = event else {
        panic!("expected PlaintextHandle, got {:?}", event);
    };
    assert_eq!(pt.domain_id, DomainId(bytes32(0xD0)));
    assert_eq!(
        pt.handle_key,
        HandleKey {
            chain_id: ChainId(1),
            contract_address: ContractAddress([7; 20]),
            handle_id: HandleId(bytes32(0x43)),
        }
    );
    assert_eq!(pt.handle_type, HandleType::Suint256);
    assert_eq!(pt.public_value, PublicPlaintextValue(plaintext.to_vec()));
    assert_eq!(
        pt.event_ref,
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
            address_topic([7; 20]),
            bytes32(0x99),
        ],
        data: encode_operation_data(
            HandleType::Suint256,
            OperationCode::Select,
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
                address_topic([7; 20]),
                bytes32(0x55),
            ],
            data: encode_operation_data(*output_type, *operation_code, &inputs),
        };
        let event = decode_chain_log(&log).unwrap_or_else(|err| {
            panic!("opcode {:?} must decode, got {:?}", operation_code, err)
        });
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
fn handle_type_discriminants_are_1_based_both_values_roundtrip() {
    for (handle_type, disc) in [(HandleType::Suint256, 1u8), (HandleType::Sbool, 2u8)] {
        let mut data = encode_imported_data(HandleType::Suint256, &[1]);
        data[31] = disc; // overwrite handleType in the first ABI slot
        let log = ChainLog {
            chain_id: ChainId(1),
            contract_address: ContractAddress([7; 20]),
            block_number: 1,
            block_hash: bytes32(1),
            tx_hash: bytes32(1),
            log_index: 0,
            topics: vec![
                HANDLE_IMPORTED_V1_SIGNATURE,
                bytes32(0xD0),
                address_topic([7; 20]),
                bytes32(0x42),
            ],
            data,
        };
        let event = decode_chain_log(&log).unwrap_or_else(|err| {
            panic!("HandleType disc {} should decode, got {:?}", disc, err)
        });
        let ChainEvent::ImportedHandle(imported) = event else {
            panic!("expected ImportedHandle");
        };
        assert_eq!(imported.handle_type, handle_type);
    }
}

// ---------------------------------------------------------------------------
// Error rejection tests
// ---------------------------------------------------------------------------

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
        topics: vec![bytes32(0xEE), bytes32(0), bytes32(0), bytes32(0)],
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
        // Only 3 topics — missing the handleId topic.
        topics: vec![
            HANDLE_IMPORTED_V1_SIGNATURE,
            bytes32(0xD0),
            address_topic([7; 20]),
        ],
        data: encode_imported_data(HandleType::Suint256, &[1]),
    };
    let err = decode_chain_log(&log).expect_err("missing handle_id topic should fail");
    assert!(matches!(
        err,
        ChainLogDecodeError::UnexpectedTopicCount {
            expected: 4,
            actual: 3,
            ..
        }
    ));
}

#[test]
fn truncated_imported_v1_data_is_rejected() {
    // Use a 100-byte ciphertext. The ABI-encoded data has:
    //   [0..32]:    handleType slot
    //   [32..64]:   offset = 64
    //   [64..96]:   length = 100
    //   [96..196]:  actual 100 ciphertext bytes
    //   [196..224]: 28 padding bytes
    // Removing 30 bytes cuts into the actual payload (only 98 of 100 bytes
    // remain), so ABI decoding must fail.
    let ciphertext = vec![0xAA; 100];
    let mut data = encode_imported_data(HandleType::Suint256, &ciphertext);
    data.truncate(data.len() - 30);
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![
            HANDLE_IMPORTED_V1_SIGNATURE,
            bytes32(0xD0),
            address_topic([7; 20]),
            bytes32(0x42),
        ],
        data,
    };
    assert!(matches!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::MalformedAbiData)
    ));
}

#[test]
fn truncated_operation_v1_input_list_is_rejected() {
    let mut data = encode_operation_data(
        HandleType::Suint256,
        OperationCode::Add,
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
            address_topic([7; 20]),
            bytes32(0x99),
        ],
        data,
    };
    assert!(matches!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::MalformedAbiData)
    ));
}

#[test]
fn oversized_operation_v1_input_count_is_rejected() {
    // Construct ABI head for (uint8 outputType, uint8 operation, bytes32[])
    // but claim u32::MAX elements with no element data.
    let mut data = Vec::new();
    data.extend_from_slice(&abi_u8(1)); // outputType = Suint256
    data.extend_from_slice(&abi_u8(1)); // operation = Add
    data.extend_from_slice(&abi_u256(96)); // offset to array
    // Array length = u32::MAX — no elements follow
    let mut huge_len = [0u8; 32];
    huge_len[28..32].copy_from_slice(&u32::MAX.to_be_bytes());
    data.extend_from_slice(&huge_len);
    // No element data
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
            address_topic([7; 20]),
            bytes32(0x99),
        ],
        data,
    };
    assert!(matches!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::MalformedAbiData)
    ));
}

#[test]
fn unknown_operation_code_byte_is_rejected() {
    let mut data = encode_operation_data(
        HandleType::Suint256,
        OperationCode::Add,
        &[bytes32(0xA0), bytes32(0xB0)],
    );
    // operation byte is at offset 63 (last byte of the second 32-byte ABI slot)
    data[63] = 200;
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
            address_topic([7; 20]),
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
    let mut data = encode_imported_data(HandleType::Suint256, &[1]);
    // handleType byte is at offset 31 (last byte of the first 32-byte ABI slot)
    data[31] = 99;
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![
            HANDLE_IMPORTED_V1_SIGNATURE,
            bytes32(0xD0),
            address_topic([7; 20]),
            bytes32(0x42),
        ],
        data,
    };
    assert_eq!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::UnknownHandleType(99))
    );
}

#[test]
fn zero_handle_type_discriminant_is_rejected() {
    let mut data = encode_imported_data(HandleType::Suint256, &[1]);
    data[31] = 0; // 0 is not a valid 1-based HandleType
    let log = ChainLog {
        chain_id: ChainId(1),
        contract_address: ContractAddress([7; 20]),
        block_number: 1,
        block_hash: bytes32(1),
        tx_hash: bytes32(1),
        log_index: 0,
        topics: vec![
            HANDLE_IMPORTED_V1_SIGNATURE,
            bytes32(0xD0),
            address_topic([7; 20]),
            bytes32(0x42),
        ],
        data,
    };
    assert_eq!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::UnknownHandleType(0))
    );
}

#[test]
fn zero_operation_code_discriminant_is_rejected() {
    let mut data = encode_operation_data(
        HandleType::Suint256,
        OperationCode::Add,
        &[bytes32(0xA0), bytes32(0xB0)],
    );
    data[63] = 0; // 0 is not a valid 1-based OperationCode
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
            address_topic([7; 20]),
            bytes32(0x99),
        ],
        data,
    };
    assert_eq!(
        decode_chain_log(&log),
        Err(ChainLogDecodeError::UnknownOperationCode(0))
    );
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
        topics: vec![
            HANDLE_IMPORTED_V1_SIGNATURE,
            bytes32(0xD0),
            address_topic([7; 20]),
            bytes32(0x42),
        ],
        data: encode_imported_data(HandleType::Suint256, &[1, 2, 3]),
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

// ---------------------------------------------------------------------------
// Test-side ABI encoders.
//
// These mirror the spec ABI layout owned by the decoder. Keeping them here
// ensures tests verify the production decoder against a faithful ABI encoding
// without sharing encoder internals with production code.
// ---------------------------------------------------------------------------

/// ABI-encode `uint8 value` as a 32-byte slot (right-aligned, zero-padded).
fn abi_u8(value: u8) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[31] = value;
    slot
}

/// ABI-encode a uint256 value (fits in u64) as a 32-byte slot.
fn abi_u256(value: u64) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[24..32].copy_from_slice(&value.to_be_bytes());
    slot
}

/// Encode a 20-byte address into a 32-byte topic (right-aligned, 12 zero bytes prefix).
fn address_topic(addr: [u8; 20]) -> [u8; 32] {
    let mut topic = [0u8; 32];
    topic[12..32].copy_from_slice(&addr);
    topic
}

/// ABI-encode `(uint8 handleType, bytes systemCiphertext)` for HandleImportedV1.
fn encode_imported_data(handle_type: HandleType, ciphertext: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&abi_u8(handle_type_disc(handle_type)));
    // offset to bytes data = 64 (2-word head)
    data.extend_from_slice(&abi_u256(64));
    data.extend_from_slice(&abi_u256(ciphertext.len() as u64));
    data.extend_from_slice(ciphertext);
    let pad = (32 - ciphertext.len() % 32) % 32;
    data.extend(std::iter::repeat(0u8).take(pad));
    data
}

/// ABI-encode `(uint8 handleType, bytes32 plaintext)` for HandleFromPlaintextV1.
fn encode_plaintext_data(handle_type: HandleType, plaintext: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&abi_u8(handle_type_disc(handle_type)));
    data.extend_from_slice(plaintext);
    data
}

/// ABI-encode `(uint8 outputType, uint8 operation, bytes32[] inputHandles)`
/// for OperationRequestedV1.
fn encode_operation_data(
    output_type: HandleType,
    operation: OperationCode,
    inputs: &[[u8; 32]],
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&abi_u8(handle_type_disc(output_type)));
    data.extend_from_slice(&abi_u8(operation_code_disc(operation)));
    // offset to array = 96 (3-word head)
    data.extend_from_slice(&abi_u256(96));
    data.extend_from_slice(&abi_u256(inputs.len() as u64));
    for input in inputs {
        data.extend_from_slice(input);
    }
    data
}

/// 1-based HandleType discriminant per spec (Suint256=1, Sbool=2).
fn handle_type_disc(handle_type: HandleType) -> u8 {
    match handle_type {
        HandleType::Suint256 => 1,
        HandleType::Sbool => 2,
    }
}

/// 1-based OperationCode discriminant per spec (Add=1 .. Select=11).
fn operation_code_disc(op: OperationCode) -> u8 {
    match op {
        OperationCode::Add => 1,
        OperationCode::Sub => 2,
        OperationCode::Eq => 3,
        OperationCode::Lt => 4,
        OperationCode::Lte => 5,
        OperationCode::Gt => 6,
        OperationCode::Gte => 7,
        OperationCode::And => 8,
        OperationCode::Or => 9,
        OperationCode::Not => 10,
        OperationCode::Select => 11,
    }
}

fn bytes32(seed: u8) -> [u8; 32] {
    [seed; 32]
}
