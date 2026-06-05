/// Internal Coordinator resolution API, scheduler claims, and enclave handoff.
use coprocessor_enclave_runtime::EnclaveRuntime;
use coprocessor_handle_graph_core::HandleKey;
use coprocessor_mpc_client::{EnclaveCiphertextV1, MpcToEnclaveSource};
use coprocessor_nitro_enclave::EnclaveAttestationSource;

use super::{
    internal_api, resolve_enclave, transform_resolution_task_inputs, CoprocessorHost,
    HandleStateView, RequestId, ResolutionIntent, ResolutionTask, TransformResolutionInputsError,
};

impl CoprocessorHost {
    /// Internal Coordinator API: GET Handle State.
    ///
    /// Returns the Coordinator-facing [`HandleStateView`] for `handle_key`.
    /// Unknown Handle Keys and tombstoned Handle Records both resolve to
    /// [`HandleStateView::Unknown`]; known Canonical Handle Records project to
    /// `Pending`, `Ready { .. }`, or `Failed { category }` according to their
    /// Handle State. Lifecycle does not gate this read; callers that need
    /// the host to be Running must check [`Self::readiness`] first.
    pub fn get_handle_state(&self, handle_key: &HandleKey) -> HandleStateView {
        self.project_handle_state(handle_key)
    }

    /// Internal Coordinator API: Resolve Handle Request.
    ///
    /// Returns the same [`HandleStateView`] projection as
    /// [`Self::get_handle_state`]. If `handle_key` currently projects to
    /// [`HandleStateView::Pending`], the request is also attached to that
    /// Handle's resolution intent. Repeated requests for the same Pending
    /// Derived Handle share one [`ResolutionIntent`], with `RequestId` stored
    /// as request-flow metadata rather than as the lookup key.
    ///
    /// Ready, Failed, Unknown, and tombstoned Handle Keys do not register
    /// intents. Chain Event Ingestion remains the only source of Handle
    /// Records, so this call never creates placeholder records or moves Handle
    /// Graph state.
    pub fn resolve_handle(
        &mut self,
        request_id: RequestId,
        handle_key: &HandleKey,
    ) -> HandleStateView {
        let view = self.project_handle_state(handle_key);
        if matches!(view, HandleStateView::Pending) {
            self.resolution_intents.attach(*handle_key, request_id);
        }
        view
    }

    /// Snapshot of the resolution intent for `handle_key`, or `None` if no
    /// Handle Resolution Request has attached to it. The returned
    /// `attached_request_ids` list is sorted and deduplicated.
    pub fn pending_resolution_intent(&self, handle_key: &HandleKey) -> Option<ResolutionIntent> {
        self.resolution_intents.intent(handle_key)
    }

    /// Number of distinct Handle Keys that currently carry a resolution
    /// intent. Repeated `RequestId`s for the same Handle Key do not inflate
    /// this count.
    pub fn pending_resolution_intent_count(&self) -> usize {
        self.resolution_intents.len()
    }

    /// Resolution Scheduler tick: claim a [`ResolutionTask`] for every
    /// Resolution Readiness entry that does not already have an active claim
    /// for its Handle Key. Returns the freshly claimed tasks; Handle Keys
    /// already claimed by an earlier tick are skipped, so duplicate ticks are
    /// idempotent.
    ///
    /// Claims do not move Handle Graph state: the underlying Pending Derived
    /// Handle stays Pending while the task is in flight, and a future host
    /// slice will mark it Ready or Failed when MPC and Enclave Execution
    /// return. Repeated Resolve Handle Requests during a claim continue to
    /// observe Pending and attach to the same [`ResolutionIntent`].
    pub fn claim_resolution_tasks(&mut self) -> Vec<ResolutionTask> {
        self.resolution_claims.claim_from_readiness(
            &self.handle_graph_core,
            self.config.retry_policy.max_attempts,
        )
    }

    /// Transform a claimed Resolution Task's ordered input
    /// `SystemCiphertextV1` values into task-scoped `EnclaveCiphertextV1`
    /// values. This is the MPC boundary between scheduler claim and Enclave
    /// execution: the host obtains one Enclave attestation target for the
    /// task, asks MPC to transform each input ciphertext in order, and
    /// returns the transformed inputs without storing them in host state.
    pub fn transform_resolution_task_inputs(
        &self,
        task: &ResolutionTask,
        mpc_source: &dyn MpcToEnclaveSource,
        attestation_source: &dyn EnclaveAttestationSource,
    ) -> Result<Vec<EnclaveCiphertextV1>, TransformResolutionInputsError> {
        transform_resolution_task_inputs(task, mpc_source, attestation_source)
    }

    /// True when a Resolution Task is currently claimed for `handle_key`.
    pub fn is_resolution_task_claimed(&self, handle_key: &HandleKey) -> bool {
        self.resolution_claims.is_claimed(handle_key)
    }

    /// Number of distinct Handle Keys that currently have an active
    /// Resolution Task claim.
    pub fn claimed_resolution_task_count(&self) -> usize {
        self.resolution_claims.count()
    }

    /// Release the active Resolution Task claim for `handle_key`. Returns
    /// `true` if a claim was released, `false` if no claim existed. Used by
    /// the resolution-result path in a later slice so the same Handle Key
    /// becomes eligible again only after the in-flight work returns.
    pub fn release_resolution_task(&mut self, handle_key: &HandleKey) -> bool {
        self.resolution_claims.release(handle_key)
    }

    /// Execute one claimed Resolution Task through the Enclave boundary and
    /// materialize the result into the Handle Graph.
    pub fn resolve_claimed_task(
        &mut self,
        task: &ResolutionTask,
        mpc_source: &dyn MpcToEnclaveSource,
        attestation_source: &dyn EnclaveAttestationSource,
        enclave: &dyn EnclaveRuntime,
    ) -> HandleStateView {
        resolve_enclave::resolve_claimed_task(
            task,
            mpc_source,
            attestation_source,
            enclave,
            &mut self.handle_graph_core,
            &mut self.resolution_claims,
        )
    }

    fn project_handle_state(&self, handle_key: &HandleKey) -> HandleStateView {
        internal_api::project_canonical(self.handle_graph_core.canonical_handle(handle_key))
    }
}
