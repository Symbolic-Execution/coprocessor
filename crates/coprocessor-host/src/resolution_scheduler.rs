//! Resolution Scheduler claim path for Pending Derived Handles.
//!
//! The scheduler observes [`ResolutionReadiness`] from the Handle Graph Core
//! and turns each entry into a [`ResolutionTask`] that the host can hand off
//! to MPC and the Enclave in later slices. A claim is the durable "I have
//! taken responsibility for this Handle Key" flag: it deduplicates work for
//! the same Pending Derived Handle so duplicate scheduler ticks and concurrent
//! Resolve Handle Requests never produce two competing Resolution Tasks.
//!
//! The claim does not touch Handle State: the underlying Derived Handle stays
//! Pending while the task is in flight, and a future slice will mark it Ready
//! or Failed when MPC and Enclave Execution return. Repeated Resolve Handle
//! Requests still observe Pending and continue attaching to the same intent.

use std::collections::HashSet;

use coprocessor_handle_graph_core::{
    HandleGraphCore, HandleKey, HandleType, OperationCode, ResolutionReadiness, SystemCiphertextV1,
};

/// A scheduler-claimed unit of resolution work for one Pending Derived Handle.
///
/// The task carries the output Handle Key, the OperationCode the Enclave will
/// evaluate, the output HandleType the result must satisfy, the ordered input
/// Handle Keys, and the ready input `SystemCiphertextV1` values paired by
/// index with those Handle Keys. For `Select`, the inputs stay in predicate,
/// when-true, when-false order.
///
/// The task does not yet include the `EnclaveCiphertextV1` form: MPC's
/// To-Enclave Transformation is a later step. Tasks built here are the
/// scheduler-side handoff, not the Enclave-runtime input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionTask {
    pub output_handle_key: HandleKey,
    pub operation_code: OperationCode,
    pub output_handle_type: HandleType,
    pub input_handle_keys: Vec<HandleKey>,
    pub input_system_ciphertexts: Vec<SystemCiphertextV1>,
}

impl ResolutionTask {
    fn from_readiness(readiness: ResolutionReadiness) -> Self {
        let ResolutionReadiness {
            handle_key,
            operation_code,
            output_handle_type,
            input_handle_keys,
            input_system_ciphertexts,
        } = readiness;
        Self {
            output_handle_key: handle_key,
            operation_code,
            output_handle_type,
            input_handle_keys,
            input_system_ciphertexts,
        }
    }
}

/// Per-Handle-Key claim registry. Only one active claim can exist per Handle
/// Key at a time. Claims are independent of the Resolve Handle Request intent
/// registry — those record which request flows attached to a Pending Handle,
/// while claims record that the scheduler has dispatched work for it.
#[derive(Default)]
pub(crate) struct ResolutionTaskClaims {
    claimed: HashSet<HandleKey>,
}

impl ResolutionTaskClaims {
    /// Drive one scheduler tick against `core`'s Resolution Readiness. Builds
    /// a [`ResolutionTask`] for each ready Handle Key that does not already
    /// have an active claim, marks the new claims, and returns the freshly
    /// claimed tasks. Re-ticking against the same readiness is a no-op until
    /// a claim is released.
    pub(crate) fn claim_from_readiness(&mut self, core: &HandleGraphCore) -> Vec<ResolutionTask> {
        let mut tasks = Vec::new();
        for entry in core.resolution_readiness() {
            if self.claimed.insert(entry.handle_key) {
                tasks.push(ResolutionTask::from_readiness(entry));
            }
        }
        tasks
    }

    pub(crate) fn is_claimed(&self, handle_key: &HandleKey) -> bool {
        self.claimed.contains(handle_key)
    }

    pub(crate) fn release(&mut self, handle_key: &HandleKey) -> bool {
        self.claimed.remove(handle_key)
    }

    pub(crate) fn count(&self) -> usize {
        self.claimed.len()
    }
}
