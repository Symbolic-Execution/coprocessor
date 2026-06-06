//! Decode raw symVM Event Surface logs into normalized [`ChainEvent`]s.
//!
//! Uses alloy-sol-types to decode Ethereum ABI-encoded logs matching the
//! canonical symVM Event Surface (`symvm-event-surface.md`). Topic0 is a
//! keccak256 event signature; topics 1-3 carry indexed fields; `data` is
//! standard Solidity ABI-encoded event data.
//!
//! Topic layout (4 topics per event):
//!
//! * `topics[0]`: keccak256 event signature hash
//! * `topics[1]`: indexed `domainId` (bytes32)
//! * `topics[2]`: indexed `contractAddress` (address, right-aligned in 32 bytes)
//! * `topics[3]`: indexed `handleId` / `outputHandleId` (bytes32)
//!
//! Data layout per event:
//!
//! * `HandleImportedV1`: ABI-encoded `(uint8 handleType, bytes systemCiphertext)`
//! * `HandleFromPlaintextV1`: ABI-encoded `(uint8 handleType, bytes32 plaintext)`
//! * `OperationRequestedV1`: ABI-encoded `(uint8 outputType, uint8 operation, bytes32[] inputHandles)`
//!
//! HandleType discriminants are 1-based (Suint256=1, Sbool=2).
//! OperationCode discriminants are 1-based (Add=1 .. Select=11).
//!
//! Input handle ids in `OperationRequestedV1` are decoded into `HandleKey`s
//! using the chain id from the monitored log and the contract address from
//! topic2, not the log emitter address.

use alloy_primitives::B256;
use alloy_sol_types::{sol, SolEvent};
use coprocessor_ciphertext_binding::CanonicalSystemCiphertextV1;

use crate::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleType, ImportedHandle, OperationCode, PlaintextHandle,
    PublicPlaintextValue, SystemCiphertextV1,
};
use thiserror::Error;

sol! {
    event HandleImportedV1(
        bytes32 indexed domainId,
        address indexed contractAddress,
        bytes32 indexed handleId,
        uint8 handleType,
        bytes systemCiphertext
    );

    event HandleFromPlaintextV1(
        bytes32 indexed domainId,
        address indexed contractAddress,
        bytes32 indexed handleId,
        uint8 handleType,
        bytes32 plaintext
    );

    event OperationRequestedV1(
        bytes32 indexed domainId,
        address indexed contractAddress,
        bytes32 indexed outputHandleId,
        uint8 outputType,
        uint8 operation,
        bytes32[] inputHandles
    );
}

/// keccak256 signature hash for `HandleImportedV1`.
pub const HANDLE_IMPORTED_V1_SIGNATURE: [u8; 32] = HandleImportedV1::SIGNATURE_HASH.0;

/// keccak256 signature hash for `HandleFromPlaintextV1`.
pub const HANDLE_FROM_PLAINTEXT_V1_SIGNATURE: [u8; 32] = HandleFromPlaintextV1::SIGNATURE_HASH.0;

/// keccak256 signature hash for `OperationRequestedV1`.
pub const OPERATION_REQUESTED_V1_SIGNATURE: [u8; 32] = OperationRequestedV1::SIGNATURE_HASH.0;

/// Raw symVM event surface log, together with its chain metadata. This is the
/// input domain for [`decode_chain_log`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainLog {
    pub chain_id: ChainId,
    pub contract_address: ContractAddress,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub tx_hash: [u8; 32],
    pub log_index: u32,
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Why a [`ChainLog`] could not be turned into a [`ChainEvent`]. Malformed or
/// unknown logs are surfaced as errors so callers can drop them without
/// polluting the Handle Graph.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChainLogDecodeError {
    /// Log carried no topics, so the event signature is missing.
    #[error("empty topics")]
    EmptyTopics,
    /// `topics[0]` did not match a known symVM event signature.
    #[error("unknown event signature: {0:?}")]
    UnknownEventSignature([u8; 32]),
    /// The number of topics did not match the layout of the matched event
    /// (all V1 events require exactly 4 topics).
    #[error("unexpected topic count for {signature:?}: expected {expected}, actual {actual}")]
    UnexpectedTopicCount {
        signature: [u8; 32],
        expected: usize,
        actual: usize,
    },
    /// ABI decoding of the log data failed. Payload bytes are not included
    /// to avoid leaking ciphertext or plaintext content in error surfaces.
    #[error("malformed ABI event data")]
    MalformedAbiData,
    /// The encoded `OperationCode` byte did not match a known discriminant.
    #[error("unknown operation code: {0}")]
    UnknownOperationCode(u8),
    /// The encoded `HandleType` byte did not match a known discriminant.
    #[error("unknown handle type: {0}")]
    UnknownHandleType(u8),
}

/// Decode a [`ChainLog`] into a [`ChainEvent`]. Dispatches on `topics[0]` and
/// validates the ABI layout before mapping to domain types.
pub fn decode_chain_log(log: &ChainLog) -> Result<ChainEvent, ChainLogDecodeError> {
    let signature = *log.topics.first().ok_or(ChainLogDecodeError::EmptyTopics)?;
    let event_ref = chain_event_ref(log);
    match signature {
        HANDLE_IMPORTED_V1_SIGNATURE => decode_imported(log, event_ref),
        HANDLE_FROM_PLAINTEXT_V1_SIGNATURE => decode_plaintext(log, event_ref),
        OPERATION_REQUESTED_V1_SIGNATURE => decode_operation(log, event_ref),
        other => Err(ChainLogDecodeError::UnknownEventSignature(other)),
    }
}

fn expect_four_topics(log: &ChainLog, signature: [u8; 32]) -> Result<(), ChainLogDecodeError> {
    if log.topics.len() != 4 {
        return Err(ChainLogDecodeError::UnexpectedTopicCount {
            signature,
            expected: 4,
            actual: log.topics.len(),
        });
    }
    Ok(())
}

fn topics_as_b256(log: &ChainLog) -> Vec<B256> {
    log.topics.iter().map(|t| B256::from(*t)).collect()
}

fn decode_exact_event<E: SolEvent>(log: &ChainLog) -> Result<E, ChainLogDecodeError> {
    let topics = topics_as_b256(log);
    let decoded = E::decode_raw_log_validate(&topics, &log.data)
        .map_err(|_| ChainLogDecodeError::MalformedAbiData)?;
    if decoded.encode_data() != log.data {
        return Err(ChainLogDecodeError::MalformedAbiData);
    }
    Ok(decoded)
}

fn decode_imported(
    log: &ChainLog,
    event_ref: ChainEventRef,
) -> Result<ChainEvent, ChainLogDecodeError> {
    expect_four_topics(log, HANDLE_IMPORTED_V1_SIGNATURE)?;
    let decoded = decode_exact_event::<HandleImportedV1>(log)?;
    let handle_type = handle_type_from_byte(decoded.handleType)?;
    let contract_address = ContractAddress(decoded.contractAddress.0 .0);
    Ok(ChainEvent::ImportedHandle(ImportedHandle {
        domain_id: DomainId(decoded.domainId.0),
        handle_key: HandleKey {
            chain_id: log.chain_id,
            contract_address,
            handle_id: HandleId(decoded.handleId.0),
        },
        handle_type,
        system_ciphertext: {
            let bytes = decoded.systemCiphertext.to_vec();
            CanonicalSystemCiphertextV1::decode(&bytes)
                .map_err(|_| ChainLogDecodeError::MalformedAbiData)?;
            SystemCiphertextV1(bytes)
        },
        event_ref,
    }))
}

fn decode_plaintext(
    log: &ChainLog,
    event_ref: ChainEventRef,
) -> Result<ChainEvent, ChainLogDecodeError> {
    expect_four_topics(log, HANDLE_FROM_PLAINTEXT_V1_SIGNATURE)?;
    let decoded = decode_exact_event::<HandleFromPlaintextV1>(log)?;
    let handle_type = handle_type_from_byte(decoded.handleType)?;
    let contract_address = ContractAddress(decoded.contractAddress.0 .0);
    Ok(ChainEvent::PlaintextHandle(PlaintextHandle {
        domain_id: DomainId(decoded.domainId.0),
        handle_key: HandleKey {
            chain_id: log.chain_id,
            contract_address,
            handle_id: HandleId(decoded.handleId.0),
        },
        handle_type,
        public_value: PublicPlaintextValue(decoded.plaintext.0.to_vec()),
        event_ref,
    }))
}

fn decode_operation(
    log: &ChainLog,
    event_ref: ChainEventRef,
) -> Result<ChainEvent, ChainLogDecodeError> {
    expect_four_topics(log, OPERATION_REQUESTED_V1_SIGNATURE)?;
    let decoded = decode_exact_event::<OperationRequestedV1>(log)?;
    let output_handle_type = handle_type_from_byte(decoded.outputType)?;
    let operation_code = operation_code_from_byte(decoded.operation)?;
    let contract_address = ContractAddress(decoded.contractAddress.0 .0);
    let input_handle_keys = decoded
        .inputHandles
        .iter()
        .map(|h| HandleKey {
            chain_id: log.chain_id,
            contract_address,
            handle_id: HandleId(h.0),
        })
        .collect();
    Ok(ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id: DomainId(decoded.domainId.0),
        handle_key: HandleKey {
            chain_id: log.chain_id,
            contract_address,
            handle_id: HandleId(decoded.outputHandleId.0),
        },
        operation_code,
        output_handle_type,
        input_handle_keys,
        event_ref,
    }))
}

fn chain_event_ref(log: &ChainLog) -> ChainEventRef {
    ChainEventRef {
        chain_id: log.chain_id,
        block_number: log.block_number,
        block_hash: log.block_hash,
        tx_hash: log.tx_hash,
        log_index: log.log_index,
    }
}

/// 1-based per spec: Suint256=1, Sbool=2. Rejects 0 and values >= 3.
fn handle_type_from_byte(byte: u8) -> Result<HandleType, ChainLogDecodeError> {
    match byte {
        1 => Ok(HandleType::Suint256),
        2 => Ok(HandleType::Sbool),
        other => Err(ChainLogDecodeError::UnknownHandleType(other)),
    }
}

/// 1-based per spec: Add=1 .. Select=11. Rejects 0 and values >= 12.
fn operation_code_from_byte(byte: u8) -> Result<OperationCode, ChainLogDecodeError> {
    match byte {
        1 => Ok(OperationCode::Add),
        2 => Ok(OperationCode::Sub),
        3 => Ok(OperationCode::Eq),
        4 => Ok(OperationCode::Lt),
        5 => Ok(OperationCode::Lte),
        6 => Ok(OperationCode::Gt),
        7 => Ok(OperationCode::Gte),
        8 => Ok(OperationCode::And),
        9 => Ok(OperationCode::Or),
        10 => Ok(OperationCode::Not),
        11 => Ok(OperationCode::Select),
        other => Err(ChainLogDecodeError::UnknownOperationCode(other)),
    }
}
