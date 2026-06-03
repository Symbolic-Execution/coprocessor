//! Derived Handle Materialization Receipt encoding.
//!
//! The Handle Graph Core persists [`MaterializationReceipt`] as opaque bytes.
//! This module owns the host's deterministic byte format for Ready Derived
//! Handles and its inverse projection for the Internal Coordinator API.

use coprocessor_enclave_runtime::{AttestationDigest, EnclaveMaterializationReceipt};
use coprocessor_handle_graph_core::{
    ChainId, ContractAddress, HandleId, HandleKey, MaterializationReceipt, OperationCode,
};

const OP_CODE_LEN: usize = 1;
const HANDLE_KEY_LEN: usize = 8 + 20 + 32;
const INPUT_COUNT_LEN: usize = 4;
const ATTESTATION_DIGEST_LEN: usize = 32;

/// Structured, non-secret Materialization Receipt for a Ready Derived Handle.
/// Contains only audit evidence: the OperationCode evaluated, the output
/// Handle Key, the ordered input Handle Keys, and the attestation digest used
/// for Enclave Execution. Never contains plaintext, ciphertext bytes, wrapped
/// keys, or raw Attestation documents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedHandleReceiptView {
    pub operation_code: OperationCode,
    pub output_handle_key: HandleKey,
    pub input_handle_keys: Vec<HandleKey>,
    pub attestation_digest: AttestationDigest,
}

/// Minimal deterministic encoding of an `EnclaveMaterializationReceipt` into
/// opaque bytes suitable for the core's `MaterializationReceipt(Vec<u8>)`.
///
/// Format, all big-endian:
///
/// - 1 byte: OperationCode discriminant
/// - 60 bytes: output Handle Key
/// - 4 bytes: input count as u32
/// - 60 bytes: each ordered input Handle Key
/// - 32 bytes: attestation digest
///
/// Contains only non-secret evidence. Never embeds ciphertext, wrapped keys,
/// raw attestation documents, or enclave private key material.
pub(crate) fn encode_derived_materialization_receipt(
    receipt: &EnclaveMaterializationReceipt,
) -> MaterializationReceipt {
    let mut bytes = Vec::new();
    bytes.push(op_code_byte(receipt.operation_code));
    encode_handle_key_into(&mut bytes, &receipt.output_handle_key);
    let input_count = u32::try_from(receipt.input_handle_keys.len())
        .expect("derived receipt input count exceeds u32::MAX");
    bytes.extend_from_slice(&input_count.to_be_bytes());
    for input_key in &receipt.input_handle_keys {
        encode_handle_key_into(&mut bytes, input_key);
    }
    bytes.extend_from_slice(&receipt.attestation_digest.0);
    MaterializationReceipt(bytes)
}

/// Decodes bytes produced by [`encode_derived_materialization_receipt`].
/// Returns `None` for malformed bytes.
pub(crate) fn decode_derived_materialization_receipt(
    receipt: &MaterializationReceipt,
) -> Option<DerivedHandleReceiptView> {
    let bytes = &receipt.0;
    let mut pos = 0;

    let operation_code = op_code_from_byte(*bytes.get(pos)?)?;
    pos += OP_CODE_LEN;

    let output_handle_key = decode_handle_key(bytes, &mut pos)?;

    if pos + INPUT_COUNT_LEN > bytes.len() {
        return None;
    }
    let input_count = usize::try_from(u32::from_be_bytes(
        bytes[pos..pos + INPUT_COUNT_LEN].try_into().ok()?,
    ))
    .ok()?;
    pos += INPUT_COUNT_LEN;

    let expected_len = OP_CODE_LEN
        .checked_add(HANDLE_KEY_LEN)?
        .checked_add(INPUT_COUNT_LEN)?
        .checked_add(input_count.checked_mul(HANDLE_KEY_LEN)?)?
        .checked_add(ATTESTATION_DIGEST_LEN)?;
    if expected_len != bytes.len() {
        return None;
    }

    let mut input_handle_keys = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        input_handle_keys.push(decode_handle_key(bytes, &mut pos)?);
    }

    let digest: [u8; ATTESTATION_DIGEST_LEN] =
        bytes[pos..pos + ATTESTATION_DIGEST_LEN].try_into().ok()?;

    Some(DerivedHandleReceiptView {
        operation_code,
        output_handle_key,
        input_handle_keys,
        attestation_digest: AttestationDigest(digest),
    })
}

fn decode_handle_key(bytes: &[u8], pos: &mut usize) -> Option<HandleKey> {
    if *pos + HANDLE_KEY_LEN > bytes.len() {
        return None;
    }
    let chain_id = u64::from_be_bytes(bytes[*pos..*pos + 8].try_into().ok()?);
    *pos += 8;
    let contract_address: [u8; 20] = bytes[*pos..*pos + 20].try_into().ok()?;
    *pos += 20;
    let handle_id: [u8; 32] = bytes[*pos..*pos + 32].try_into().ok()?;
    *pos += 32;
    Some(HandleKey {
        chain_id: ChainId(chain_id),
        contract_address: ContractAddress(contract_address),
        handle_id: HandleId(handle_id),
    })
}

fn encode_handle_key_into(out: &mut Vec<u8>, key: &HandleKey) {
    out.extend_from_slice(&key.chain_id.0.to_be_bytes());
    out.extend_from_slice(&key.contract_address.0);
    out.extend_from_slice(&key.handle_id.0);
}

fn op_code_from_byte(byte: u8) -> Option<OperationCode> {
    match byte {
        1 => Some(OperationCode::Add),
        2 => Some(OperationCode::Sub),
        3 => Some(OperationCode::Eq),
        4 => Some(OperationCode::Lt),
        5 => Some(OperationCode::Lte),
        6 => Some(OperationCode::Gt),
        7 => Some(OperationCode::Gte),
        8 => Some(OperationCode::And),
        9 => Some(OperationCode::Or),
        10 => Some(OperationCode::Not),
        11 => Some(OperationCode::Select),
        _ => None,
    }
}

fn op_code_byte(op: OperationCode) -> u8 {
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
