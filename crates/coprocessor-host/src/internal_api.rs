//! Internal Coordinator API read path for Canonical Handle Records.
//!
//! The projection in this module is where Handle Graph internals become the
//! stable view returned by GET Handle State: unknown or tombstoned records
//! collapse to `Unknown`, `Ready` keeps its ciphertext and receipt payloads,
//! and `Failed` exposes only a stable category.

use coprocessor_handle_graph_core::{
    FailureReason, HandleLineage, HandleRecord, HandleState, LineageViolation,
    MaterializationReceipt, OperationViolation, SystemCiphertextV1,
};

use crate::derived_receipt::{decode_derived_materialization_receipt, DerivedHandleReceiptView};

/// Coordinator-facing view of a Canonical Handle Record. This is the response
/// shape the Internal Coordinator API will serialize for GET Handle State; the
/// host computes it from the Handle Graph Core without exposing any
/// implementation-internal fields (canonicality flag, tombstone flag, audit
/// `event_ref`, lineage, raw `FailureReason`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandleStateView {
    /// Handle Key is not known to the Coprocessor, or its Canonical Handle
    /// Record has been tombstoned by Orphan Discard. The spec mandates these
    /// two cases share the same observable response.
    Unknown,
    /// A known Canonical Handle Record whose Resolution is not complete.
    Pending,
    /// A known Canonical Handle Record materialized as `SystemCiphertextV1`
    /// and bound with a Materialization Receipt. For Derived Handles,
    /// `derived_receipt` carries the structured receipt decoded from the opaque
    /// bytes; for Source Handles (Imported/Plaintext) it is `None`.
    Ready {
        system_ciphertext: SystemCiphertextV1,
        materialization_receipt: MaterializationReceipt,
        derived_receipt: Option<DerivedHandleReceiptView>,
    },
    /// A known Canonical Handle Record whose Resolution concluded as Failed.
    /// The `category` is stable and non-secret. The `reason` is a
    /// non-secret human-readable string — it names the failure category and
    /// affected input position or count only, never ciphertext bytes, wrapped
    /// keys, reader secrets, enclave private keys, or plaintext.
    Failed {
        category: HandleStateFailureCategory,
        reason: String,
    },
}

/// Stable, non-secret Failed category surfaced through GET Handle State. The
/// initial taxonomy mirrors `CONTEXT.md`; new categories must extend this
/// enum so the wire shape stays explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleStateFailureCategory {
    LineageViolation,
    OperationViolation,
    MpcTransformationFailure,
    EnclaveExecutionFailure,
    MaterializationFailure,
}

/// Projects an optional Canonical Handle Record into the API view. The host
/// passes `None` when canonical lookup reports unknown or tombstoned, keeping
/// the read path total against any Handle Key.
///
/// For Ready Derived Handles the opaque `materialization_receipt` bytes are
/// decoded into a structured [`DerivedHandleReceiptView`]. For Source Handles
/// (Imported/Plaintext) the receipt bytes are surfaced as-is with
/// `derived_receipt: None`; fixture bytes share no format with the derived
/// encoding and must not be decoded.
pub(crate) fn project_canonical(record: Option<&HandleRecord>) -> HandleStateView {
    let Some(record) = record else {
        return HandleStateView::Unknown;
    };
    match &record.state {
        HandleState::Pending => HandleStateView::Pending,
        HandleState::Ready {
            system_ciphertext,
            materialization_receipt,
        } => {
            let derived_receipt = if matches!(record.lineage, HandleLineage::Derived { .. }) {
                decode_derived_materialization_receipt(materialization_receipt)
            } else {
                None
            };
            HandleStateView::Ready {
                system_ciphertext: system_ciphertext.clone(),
                materialization_receipt: materialization_receipt.clone(),
                derived_receipt,
            }
        }
        HandleState::Failed { reason } => HandleStateView::Failed {
            category: failure_category(reason),
            reason: failure_reason_string(reason),
        },
    }
}

fn failure_category(reason: &FailureReason) -> HandleStateFailureCategory {
    match reason {
        FailureReason::LineageViolation(_) => HandleStateFailureCategory::LineageViolation,
        FailureReason::OperationViolation(_) => HandleStateFailureCategory::OperationViolation,
        FailureReason::MpcTransformationFailure { .. } => {
            HandleStateFailureCategory::MpcTransformationFailure
        }
        FailureReason::EnclaveExecutionFailure { .. } => {
            HandleStateFailureCategory::EnclaveExecutionFailure
        }
        FailureReason::MaterializationFailure { .. } => {
            HandleStateFailureCategory::MaterializationFailure
        }
    }
}

/// Extract a non-secret, stable reason string from a `FailureReason`. The
/// returned string contains only category names, counts, and input indices —
/// never ciphertext bytes, wrapped keys, reader secrets, enclave private keys,
/// attestation documents, or decrypted payloads.
fn failure_reason_string(reason: &FailureReason) -> String {
    match reason {
        FailureReason::LineageViolation(v) => match v {
            LineageViolation::DuplicateHandleKey { .. } => "duplicate handle key".to_string(),
            LineageViolation::UnknownInputHandle { .. } => "unknown input handle".to_string(),
        },
        FailureReason::OperationViolation(v) => match v {
            OperationViolation::WrongArity {
                expected, actual, ..
            } => format!("wrong arity: expected {expected}, actual {actual}"),
            OperationViolation::WrongInputHandleType { input_index, .. } => {
                format!("wrong input handle type at index {input_index}")
            }
            OperationViolation::WrongOutputHandleType { .. } => {
                "wrong output handle type".to_string()
            }
        },
        FailureReason::MpcTransformationFailure { reason } => {
            sanitize_failure_reason(reason, "mpc transformation failure")
        }
        FailureReason::EnclaveExecutionFailure { reason } => {
            sanitize_failure_reason(reason, "enclave execution failure")
        }
        FailureReason::MaterializationFailure { reason } => {
            sanitize_failure_reason(reason, "materialization failure")
        }
    }
}

fn sanitize_failure_reason(reason: &str, fallback: &str) -> String {
    if reason.trim().is_empty()
        || reason.chars().any(|c| !c.is_ascii_graphic() && c != ' ')
        || contains_forbidden_secret_marker(reason)
    {
        return fallback.to_string();
    }
    reason.to_string()
}

fn contains_forbidden_secret_marker(reason: &str) -> bool {
    let normalized = reason.to_ascii_lowercase().replace(['-', ' '], "_");
    [
        "plaintext",
        "private_value",
        "private_key",
        "data_encryption_key",
        "decryption_key",
        "reader_secret",
        "wrapped_key",
        "decrypted",
        "raw_decrypted_payload",
        "enclave_private_key",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}
