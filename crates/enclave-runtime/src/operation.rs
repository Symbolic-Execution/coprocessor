/// Supported enclave operations and their evaluation logic.
/// Also owns the HandleType → type-tag mapping used by both operation
/// input validation and the sealing/unsealing paths.

use std::cmp::Ordering;

use coprocessor_handle_graph_core::{HandleType, OperationCode};

use crate::{EnclaveExecutionError, ResolutionTask};

pub(super) const SUINT256_TYPE_TAG: &str = "suint256";
pub(super) const SBOOL_TYPE_TAG: &str = "sbool";

pub(super) const fn type_tag_for_handle_type(handle_type: HandleType) -> &'static str {
    match handle_type {
        HandleType::Suint256 => SUINT256_TYPE_TAG,
        HandleType::Sbool => SBOOL_TYPE_TAG,
    }
}

/// Operations the local Enclave evaluates. Covers the full initial
/// OperationCode and HandleType surface: `suint256` arithmetic
/// (`Add`/`Sub`), comparison (`Eq`/`Lt`/`Lte`/`Gt`/`Gte`), `sbool` logic
/// (`And`/`Or`/`Not`), and the private conditional `Select` for both
/// `suint256` and `sbool` branches. Any other OperationCode or
/// OperationCode/output-type pair surfaces as
/// [`EnclaveExecutionError::OperationNotSupported`].
pub(super) enum SupportedOperation {
    Add,
    Sub,
    Eq,
    Lt,
    Lte,
    Gt,
    Gte,
    And,
    Or,
    Not,
    SelectSuint256,
    SelectSbool,
}

impl SupportedOperation {
    pub(super) fn for_task(task: &ResolutionTask) -> Result<Self, EnclaveExecutionError> {
        let supported = match (task.operation_code, task.output_handle_type) {
            (OperationCode::Add, HandleType::Suint256) => SupportedOperation::Add,
            (OperationCode::Sub, HandleType::Suint256) => SupportedOperation::Sub,
            (OperationCode::Eq, HandleType::Sbool) => SupportedOperation::Eq,
            (OperationCode::Lt, HandleType::Sbool) => SupportedOperation::Lt,
            (OperationCode::Lte, HandleType::Sbool) => SupportedOperation::Lte,
            (OperationCode::Gt, HandleType::Sbool) => SupportedOperation::Gt,
            (OperationCode::Gte, HandleType::Sbool) => SupportedOperation::Gte,
            (OperationCode::And, HandleType::Sbool) => SupportedOperation::And,
            (OperationCode::Or, HandleType::Sbool) => SupportedOperation::Or,
            (OperationCode::Not, HandleType::Sbool) => SupportedOperation::Not,
            (OperationCode::Select, HandleType::Suint256) => SupportedOperation::SelectSuint256,
            (OperationCode::Select, HandleType::Sbool) => SupportedOperation::SelectSbool,
            _ => {
                return Err(EnclaveExecutionError::OperationNotSupported(
                    task.operation_code,
                ))
            }
        };
        Ok(supported)
    }

    pub(super) fn arity(&self) -> usize {
        match self {
            SupportedOperation::Not => 1,
            SupportedOperation::Add
            | SupportedOperation::Sub
            | SupportedOperation::Eq
            | SupportedOperation::Lt
            | SupportedOperation::Lte
            | SupportedOperation::Gt
            | SupportedOperation::Gte
            | SupportedOperation::And
            | SupportedOperation::Or => 2,
            SupportedOperation::SelectSuint256 | SupportedOperation::SelectSbool => 3,
        }
    }

    /// Ordered input HandleType tags expected by this operation. Position is
    /// semantic: for `Select`, the tags are `(predicate sbool, when_true,
    /// when_false)`.
    pub(super) fn input_type_tags(&self) -> &'static [&'static str] {
        match self {
            SupportedOperation::Add
            | SupportedOperation::Sub
            | SupportedOperation::Eq
            | SupportedOperation::Lt
            | SupportedOperation::Lte
            | SupportedOperation::Gt
            | SupportedOperation::Gte => &[SUINT256_TYPE_TAG, SUINT256_TYPE_TAG],
            SupportedOperation::And | SupportedOperation::Or => &[SBOOL_TYPE_TAG, SBOOL_TYPE_TAG],
            SupportedOperation::Not => &[SBOOL_TYPE_TAG],
            SupportedOperation::SelectSuint256 => {
                &[SBOOL_TYPE_TAG, SUINT256_TYPE_TAG, SUINT256_TYPE_TAG]
            }
            SupportedOperation::SelectSbool => &[SBOOL_TYPE_TAG, SBOOL_TYPE_TAG, SBOOL_TYPE_TAG],
        }
    }

    pub(super) fn check_arity(&self, task: &ResolutionTask) -> Result<(), EnclaveExecutionError> {
        let expected = self.arity();
        let actual = task.input_handle_keys.len();
        if actual == expected {
            Ok(())
        } else {
            Err(EnclaveExecutionError::InputCountMismatch {
                handle_key_count: actual,
                ciphertext_count: task.input_ciphertexts.len(),
            })
        }
    }

    pub(super) fn evaluate(&self, inputs: &[[u8; 32]]) -> [u8; 32] {
        match self {
            SupportedOperation::Add => add_suint256(&inputs[0], &inputs[1]),
            SupportedOperation::Sub => sub_suint256(&inputs[0], &inputs[1]),
            SupportedOperation::Eq => bool_to_payload(inputs[0] == inputs[1]),
            SupportedOperation::Lt => {
                bool_to_payload(cmp_be_u256(&inputs[0], &inputs[1]) == Ordering::Less)
            }
            SupportedOperation::Lte => bool_to_payload(matches!(
                cmp_be_u256(&inputs[0], &inputs[1]),
                Ordering::Less | Ordering::Equal,
            )),
            SupportedOperation::Gt => {
                bool_to_payload(cmp_be_u256(&inputs[0], &inputs[1]) == Ordering::Greater)
            }
            SupportedOperation::Gte => bool_to_payload(matches!(
                cmp_be_u256(&inputs[0], &inputs[1]),
                Ordering::Greater | Ordering::Equal,
            )),
            SupportedOperation::And => {
                bool_to_payload(payload_to_bool(inputs[0]) && payload_to_bool(inputs[1]))
            }
            SupportedOperation::Or => {
                bool_to_payload(payload_to_bool(inputs[0]) || payload_to_bool(inputs[1]))
            }
            SupportedOperation::Not => bool_to_payload(!payload_to_bool(inputs[0])),
            SupportedOperation::SelectSuint256 | SupportedOperation::SelectSbool => {
                if payload_to_bool(inputs[0]) {
                    inputs[1]
                } else {
                    inputs[2]
                }
            }
        }
    }
}

/// Wrapping big-endian 256-bit add. Matches the spec's `suint256` semantics:
/// 2^256 modular addition with no overflow signalling.
fn add_suint256(lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let sum = lhs[i] as u16 + rhs[i] as u16 + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    out
}

/// Wrapping big-endian 256-bit subtract. Matches the spec's `suint256`
/// semantics: 2^256 modular subtraction with no underflow signalling.
fn sub_suint256(lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = lhs[i] as i16 - rhs[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

/// Big-endian unsigned 256-bit comparison.
fn cmp_be_u256(lhs: &[u8; 32], rhs: &[u8; 32]) -> Ordering {
    lhs.cmp(rhs)
}

/// Encode an sbool plaintext as a 32-byte payload: 31 leading zero bytes plus
/// a single `0x00` (false) or `0x01` (true) trailing byte.
pub(super) fn bool_to_payload(value: bool) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = u8::from(value);
    out
}

/// Decode an sbool plaintext from a 32-byte payload. Any non-zero byte means
/// true; this is deliberately lenient so producers that pad the encoding
/// differently still round-trip predictably.
pub(super) fn payload_to_bool(payload: [u8; 32]) -> bool {
    payload.iter().any(|&b| b != 0)
}
