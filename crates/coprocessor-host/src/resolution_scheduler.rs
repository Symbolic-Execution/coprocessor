//! Resolution Scheduler claim path for Pending Derived Handles.
//!
//! The scheduler observes [`ResolutionReadiness`] from the Handle Graph Core
//! and turns each entry into a [`ResolutionTask`] that the host can hand off
//! to MPC and the Enclave in later slices. A claim records active responsibility
//! for one Handle Key: it deduplicates work for the same Pending Derived Handle
//! so duplicate scheduler ticks and concurrent Resolve Handle Requests never
//! produce two competing Resolution Tasks.
//!
//! The claim does not touch Handle State: the underlying Derived Handle stays
//! Pending while the task is in flight, and a future slice will mark it Ready
//! or Failed when MPC and Enclave Execution return. Repeated Resolve Handle
//! Requests still observe Pending and continue attaching to the same intent.

use std::collections::{HashMap, HashSet};

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
///
/// Each Handle Key also carries a retry budget (remaining attempts). When the
/// scheduler first claims a task, the budget is set to `max_attempts - 1`
/// (one attempt is consumed immediately). On a transient failure the budget
/// decrements; when it reaches zero the next failure is terminal. Budget
/// entries outlive active claims so a Handle that needed retries remembers
/// its consumed budget across re-claims.
#[derive(Default)]
pub(crate) struct ResolutionTaskClaims {
    claimed_handle_keys: HashSet<HandleKey>,
    /// Remaining retry budget per Handle Key. Initialised to `max_attempts - 1`
    /// on first claim. Absent = budget not yet consumed (first claim pending).
    retry_budgets: HashMap<HandleKey, u32>,
}

impl ResolutionTaskClaims {
    /// Drive one scheduler tick against `core`'s Resolution Readiness. Builds
    /// a [`ResolutionTask`] for each ready Handle Key that does not already
    /// have an active claim, marks the new claims, and returns the freshly
    /// claimed tasks. Re-ticking against the same readiness is a no-op until
    /// a claim is released. `max_attempts` initialises the budget for newly
    /// claimed Handle Keys that have no existing budget entry.
    pub(crate) fn claim_from_readiness(
        &mut self,
        core: &HandleGraphCore,
        max_attempts: u32,
    ) -> Vec<ResolutionTask> {
        let mut tasks = Vec::new();
        for entry in core.resolution_readiness() {
            if self.claimed_handle_keys.insert(entry.handle_key) {
                // First-ever claim for this Handle Key: set initial budget.
                // Re-claims after retryable failures already have an entry.
                self.retry_budgets
                    .entry(entry.handle_key)
                    .or_insert_with(|| max_attempts.saturating_sub(1));
                tasks.push(ResolutionTask::from_readiness(entry));
            }
        }
        tasks
    }

    pub(crate) fn is_claimed(&self, handle_key: &HandleKey) -> bool {
        self.claimed_handle_keys.contains(handle_key)
    }

    pub(crate) fn release(&mut self, handle_key: &HandleKey) -> bool {
        self.claimed_handle_keys.remove(handle_key)
    }

    pub(crate) fn count(&self) -> usize {
        self.claimed_handle_keys.len()
    }

    /// Return the remaining retry budget for `handle_key`, or `0` when no
    /// budget entry exists (the handle has not been claimed yet or the budget
    /// was exhausted and the entry removed on terminal failure).
    pub(crate) fn remaining_budget(&self, handle_key: &HandleKey) -> u32 {
        self.retry_budgets.get(handle_key).copied().unwrap_or(0)
    }

    /// Decrement the remaining budget for `handle_key` by one. Should be
    /// called only when a retryable failure occurs so the re-claim on the
    /// next scheduler tick inherits the updated budget.
    pub(crate) fn consume_budget(&mut self, handle_key: &HandleKey) {
        if let Some(budget) = self.retry_budgets.get_mut(handle_key) {
            *budget = budget.saturating_sub(1);
        }
    }

    /// Remove the budget entry for `handle_key`. Called when the Handle
    /// transitions to a terminal state (Ready or Failed) so the budget map
    /// does not grow unboundedly.
    pub(crate) fn clear_budget(&mut self, handle_key: &HandleKey) {
        self.retry_budgets.remove(handle_key);
    }
}
