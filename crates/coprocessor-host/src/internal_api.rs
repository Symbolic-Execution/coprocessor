//! Internal Coordinator API read path for Canonical Handle Records.
//!
//! The projection in this module is where Handle Graph internals become the
//! stable view returned by GET Handle State: unknown or tombstoned records
//! collapse to `Unknown`, `Ready` keeps its ciphertext and receipt payloads,
//! and `Failed` exposes only a stable category.

use coprocessor_handle_graph_core::{
    FailureReason, HandleRecord, HandleState, MaterializationReceipt, SystemCiphertextV1,
};

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
    /// and bound with a Materialization Receipt.
    Ready {
        system_ciphertext: SystemCiphertextV1,
        materialization_receipt: MaterializationReceipt,
    },
    /// A known Canonical Handle Record whose Resolution concluded as Failed.
    /// The category is stable, non-secret, and free of raw failure detail.
    Failed {
        category: HandleStateFailureCategory,
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
pub(crate) fn project_canonical(record: Option<&HandleRecord>) -> HandleStateView {
    let Some(record) = record else {
        return HandleStateView::Unknown;
    };
    match &record.state {
        HandleState::Pending => HandleStateView::Pending,
        HandleState::Ready {
            system_ciphertext,
            materialization_receipt,
        } => HandleStateView::Ready {
            system_ciphertext: system_ciphertext.clone(),
            materialization_receipt: materialization_receipt.clone(),
        },
        HandleState::Failed { reason } => HandleStateView::Failed {
            category: failure_category(reason),
        },
    }
}

fn failure_category(reason: &FailureReason) -> HandleStateFailureCategory {
    match reason {
        FailureReason::LineageViolation(_) => HandleStateFailureCategory::LineageViolation,
        FailureReason::OperationViolation(_) => HandleStateFailureCategory::OperationViolation,
    }
}
