//! Decode raw symVM Event Surface logs into normalized [`ChainEvent`]s.
//!
//! The decoder is the only part of the crate that knows the byte layout of
//! `HandleImportedV1`, `HandleFromPlaintextV1`, and `OperationRequestedV1`
//! logs. Callers hand it a [`ChainLog`] and receive a [`ChainEvent`] that
//! [`crate::HandleGraphCore::apply_chain_event`] can consume.
//!
//! The decoder does not inspect application calldata or contract state. It
//! treats `SystemCiphertextV1`, `MaterializationReceipt`, and Public Plaintext
//! payloads as opaque byte slices.
//!
//! Wire layout owned by this module (versioned by the `V1` event signatures):
//!
//! * Each event signature occupies `topics[0]`. The remaining topics carry the
//!   indexed `DomainId` and the handle being created.
//! * `data` is a length-prefixed concatenation: every variable-length byte
//!   payload is preceded by its length as a big-endian `u32`. `HandleType` and
//!   `OperationCode` are encoded as single bytes; input handle ids are encoded
//!   as a `u32` count followed by that many 32-byte handle ids in order.
//!
//! Input handle ids in `OperationRequestedV1` are decoded into `HandleKey`s
//! against the chain id and contract address of the emitting log: symVM scopes
//! handles to the contract that expresses them, so operation inputs share the
//! same `(ChainId, ContractAddress)` as the output Handle Key.

use crate::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    HandleId, HandleKey, HandleType, ImportedHandle, MaterializationReceipt, OperationCode,
    PlaintextHandle, PublicPlaintextValue, SystemCiphertextV1,
};

/// Identifies a `HandleImportedV1` event in `topics[0]`.
pub const HANDLE_IMPORTED_V1_SIGNATURE: [u8; 32] = signature_bytes(b"HandleImportedV1");

/// Identifies a `HandleFromPlaintextV1` event in `topics[0]`.
pub const HANDLE_FROM_PLAINTEXT_V1_SIGNATURE: [u8; 32] = signature_bytes(b"HandleFromPlaintextV1");

/// Identifies an `OperationRequestedV1` event in `topics[0]`.
pub const OPERATION_REQUESTED_V1_SIGNATURE: [u8; 32] = signature_bytes(b"OperationRequestedV1");

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainLogDecodeError {
    /// Log carried no topics, so the event signature is missing.
    EmptyTopics,
    /// `topics[0]` did not match a known symVM event signature.
    UnknownEventSignature([u8; 32]),
    /// The number of topics did not match the layout of the matched event.
    UnexpectedTopicCount {
        signature: [u8; 32],
        expected: usize,
        actual: usize,
    },
    /// `data` ended before the layout demanded.
    TruncatedData { needed: usize, available: usize },
    /// `data` carried more bytes than the layout consumed.
    TrailingData { unused: usize },
    /// The encoded `OperationCode` byte did not match a known discriminant.
    UnknownOperationCode(u8),
    /// The encoded `HandleType` byte did not match a known discriminant.
    UnknownHandleType(u8),
}

/// Decode a [`ChainLog`] into a [`ChainEvent`]. The decoder dispatches on
/// `topics[0]` and validates that every byte of `data` is consumed.
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

fn decode_imported(log: &ChainLog, event_ref: ChainEventRef) -> Result<ChainEvent, ChainLogDecodeError> {
    let (domain_id, handle_id) = expect_source_handle_topics(log, HANDLE_IMPORTED_V1_SIGNATURE)?;
    let mut cursor = Cursor::new(&log.data);
    let handle_type = cursor.read_handle_type()?;
    let system_ciphertext = SystemCiphertextV1(cursor.read_length_prefixed_bytes()?.to_vec());
    let materialization_receipt =
        MaterializationReceipt(cursor.read_length_prefixed_bytes()?.to_vec());
    cursor.expect_consumed()?;
    Ok(ChainEvent::ImportedHandle(ImportedHandle {
        domain_id,
        handle_key: handle_key_from_log(log, handle_id),
        handle_type,
        system_ciphertext,
        materialization_receipt,
        event_ref,
    }))
}

fn decode_plaintext(log: &ChainLog, event_ref: ChainEventRef) -> Result<ChainEvent, ChainLogDecodeError> {
    let (domain_id, handle_id) =
        expect_source_handle_topics(log, HANDLE_FROM_PLAINTEXT_V1_SIGNATURE)?;
    let mut cursor = Cursor::new(&log.data);
    let handle_type = cursor.read_handle_type()?;
    let public_value = PublicPlaintextValue(cursor.read_length_prefixed_bytes()?.to_vec());
    cursor.expect_consumed()?;
    Ok(ChainEvent::PlaintextHandle(PlaintextHandle {
        domain_id,
        handle_key: handle_key_from_log(log, handle_id),
        handle_type,
        public_value,
        event_ref,
    }))
}

fn decode_operation(log: &ChainLog, event_ref: ChainEventRef) -> Result<ChainEvent, ChainLogDecodeError> {
    let (domain_id, output_handle_id) =
        expect_source_handle_topics(log, OPERATION_REQUESTED_V1_SIGNATURE)?;
    let mut cursor = Cursor::new(&log.data);
    let operation_code = cursor.read_operation_code()?;
    let output_handle_type = cursor.read_handle_type()?;
    let input_count = cursor.read_u32()? as usize;
    let mut input_handle_keys = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let raw = cursor.read_fixed::<32>()?;
        input_handle_keys.push(handle_key_from_log(log, HandleId(raw)));
    }
    cursor.expect_consumed()?;
    Ok(ChainEvent::DerivedHandleOperation(DerivedHandleOperation {
        domain_id,
        handle_key: handle_key_from_log(log, output_handle_id),
        operation_code,
        output_handle_type,
        input_handle_keys,
        event_ref,
    }))
}

/// All three V1 events carry `topics = [signature, domain_id, handle_id]`.
fn expect_source_handle_topics(
    log: &ChainLog,
    signature: [u8; 32],
) -> Result<(DomainId, HandleId), ChainLogDecodeError> {
    if log.topics.len() != 3 {
        return Err(ChainLogDecodeError::UnexpectedTopicCount {
            signature,
            expected: 3,
            actual: log.topics.len(),
        });
    }
    Ok((DomainId(log.topics[1]), HandleId(log.topics[2])))
}

fn handle_key_from_log(log: &ChainLog, handle_id: HandleId) -> HandleKey {
    HandleKey {
        chain_id: log.chain_id,
        contract_address: log.contract_address,
        handle_id,
    }
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

/// Byte cursor over a log's `data` field. Tracks position so the decoder can
/// report `TruncatedData` and `TrailingData` precisely.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], ChainLogDecodeError> {
        let slice = self.read_slice(N)?;
        let mut buf = [0u8; N];
        buf.copy_from_slice(slice);
        Ok(buf)
    }

    fn read_u8(&mut self) -> Result<u8, ChainLogDecodeError> {
        Ok(self.read_slice(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, ChainLogDecodeError> {
        Ok(u32::from_be_bytes(self.read_fixed::<4>()?))
    }

    fn read_slice(&mut self, n: usize) -> Result<&'a [u8], ChainLogDecodeError> {
        let end = self.pos.checked_add(n).ok_or(ChainLogDecodeError::TruncatedData {
            needed: n,
            available: self.bytes.len().saturating_sub(self.pos),
        })?;
        if end > self.bytes.len() {
            return Err(ChainLogDecodeError::TruncatedData {
                needed: n,
                available: self.bytes.len().saturating_sub(self.pos),
            });
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_length_prefixed_bytes(&mut self) -> Result<&'a [u8], ChainLogDecodeError> {
        let len = self.read_u32()? as usize;
        self.read_slice(len)
    }

    fn read_handle_type(&mut self) -> Result<HandleType, ChainLogDecodeError> {
        let byte = self.read_u8()?;
        handle_type_from_byte(byte)
    }

    fn read_operation_code(&mut self) -> Result<OperationCode, ChainLogDecodeError> {
        let byte = self.read_u8()?;
        operation_code_from_byte(byte)
    }

    fn expect_consumed(&self) -> Result<(), ChainLogDecodeError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(ChainLogDecodeError::TrailingData {
                unused: self.bytes.len() - self.pos,
            })
        }
    }
}

fn handle_type_from_byte(byte: u8) -> Result<HandleType, ChainLogDecodeError> {
    match byte {
        0 => Ok(HandleType::Suint256),
        1 => Ok(HandleType::Sbool),
        other => Err(ChainLogDecodeError::UnknownHandleType(other)),
    }
}

fn operation_code_from_byte(byte: u8) -> Result<OperationCode, ChainLogDecodeError> {
    match byte {
        0 => Ok(OperationCode::Add),
        1 => Ok(OperationCode::Sub),
        2 => Ok(OperationCode::Eq),
        3 => Ok(OperationCode::Lt),
        4 => Ok(OperationCode::Lte),
        5 => Ok(OperationCode::Gt),
        6 => Ok(OperationCode::Gte),
        7 => Ok(OperationCode::And),
        8 => Ok(OperationCode::Or),
        9 => Ok(OperationCode::Not),
        10 => Ok(OperationCode::Select),
        other => Err(ChainLogDecodeError::UnknownOperationCode(other)),
    }
}

/// Build a deterministic 32-byte signature from an ASCII event name. The name
/// fills the prefix; trailing bytes are zero. These constants live here so the
/// decoder owns the on-chain encoding contract end to end.
const fn signature_bytes(name: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < name.len() && i < 32 {
        out[i] = name[i];
        i += 1;
    }
    out
}
