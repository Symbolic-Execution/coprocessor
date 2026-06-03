//! Transform the ordered input `SystemCiphertextV1` values of a claimed
//! Resolution Task into task-scoped `EnclaveCiphertextV1` envelopes by asking
//! MPC for one To-Enclave Transformation per input.
//!
//! The Resolution Scheduler claims one Resolution Task per Pending Derived
//! Handle. Before the Enclave can run the symbolic operation it needs every
//! input wrapped to the attested Enclave key. That wrapping is MPC's
//! responsibility (To-Enclave Transformation): the host forwards request
//! facts and the system ciphertext, MPC returns an `EnclaveCiphertextV1`
//! bound to the attested Enclave key, and the host hands the envelopes to
//! the Enclave runtime in input order.
//!
//! Ordering and purity:
//! - The returned `Vec<EnclaveCiphertextV1>` is index-aligned with
//!   [`ResolutionTask::input_handle_keys`], matching `Select`'s
//!   (predicate, when-true, when-false) shape and every other operation's
//!   input order.
//! - The function is a free function and owns no state. The transformed
//!   envelopes are returned to the caller and dropped at the end of the
//!   task; no host field retains them, so a failed task or restart cannot
//!   leak earlier task-scoped Enclave inputs.
//!
//! Failure surface:
//! - A malformed input envelope surfaces as
//!   [`TransformResolutionInputsError::MalformedSystemCiphertext`] with the
//!   offending input index. MPC is not called for later inputs.
//! - An MPC protocol or transport failure surfaces as
//!   [`TransformResolutionInputsError::MpcTransformationFailed`] with the
//!   offending input index and the typed MPC error. MPC is not called for
//!   later inputs.
//!
//! Privacy: the error surface carries the input index and the typed MPC
//! error; it never embeds the system ciphertext bytes, the wrapped key, or
//! the attestation evidence.

use coprocessor_ciphertext_binding::{
    EnclaveCiphertextV1, EnvelopeDecodeError, HandleId, RequestId,
    SystemCiphertextV1 as EnvelopeSystemCiphertextV1,
};
use coprocessor_mpc_client::{
    request_to_enclave_transformation, MpcToEnclaveSource, ToEnclaveTransformationError,
    ToEnclaveTransformationRequest,
};
use coprocessor_nitro_enclave::EnclaveAttestationMaterial;

use crate::resolution_scheduler::ResolutionTask;

/// Reasons [`transform_resolution_task_inputs`] can fail. Each variant
/// identifies the offending input position so the host can map the failure to
/// the corresponding input Handle Key without re-walking the task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransformResolutionInputsError {
    /// The input `SystemCiphertextV1` bytes at `input_index` could not be
    /// decoded as a canonical envelope. The host treats this as an upstream
    /// ingestion problem rather than an MPC failure.
    MalformedSystemCiphertext {
        input_index: usize,
        error: EnvelopeDecodeError,
    },
    /// MPC rejected the To-Enclave Transformation for the input at
    /// `input_index`. The wrapped [`ToEnclaveTransformationError`] keeps the
    /// spec-mandated five-variant distinction (transient transport,
    /// malformed response, unauthorized, invalid binding, invalid
    /// attestation) so the host can apply distinct retry policies.
    MpcTransformationFailed {
        input_index: usize,
        error: ToEnclaveTransformationError,
    },
}

/// Transform every input `SystemCiphertextV1` of `task` into a task-scoped
/// [`EnclaveCiphertextV1`] by asking `mpc_source` for one To-Enclave
/// Transformation per input.
///
/// `task_request_id` is the RequestId every per-input transformation shares;
/// it identifies the Resolution Task flow, not the Handle. `attestation`
/// carries the Enclave public key, the approved Enclave Measurement, and the
/// Attestation evidence MPC validates before transforming.
///
/// On success, the returned `Vec` is index-aligned with the task's input
/// Handle Keys. On failure, the first failing input short-circuits the
/// transformation and the error identifies that input's position.
pub fn transform_resolution_task_inputs(
    task: &ResolutionTask,
    task_request_id: RequestId,
    attestation: &EnclaveAttestationMaterial,
    mpc_source: &dyn MpcToEnclaveSource,
) -> Result<Vec<EnclaveCiphertextV1>, TransformResolutionInputsError> {
    let mut outputs = Vec::with_capacity(task.input_system_ciphertexts.len());
    for (input_index, (input_handle_key, system_ciphertext)) in task
        .input_handle_keys
        .iter()
        .zip(task.input_system_ciphertexts.iter())
        .enumerate()
    {
        let envelope = EnvelopeSystemCiphertextV1::decode(&system_ciphertext.0).map_err(
            |error| TransformResolutionInputsError::MalformedSystemCiphertext { input_index, error },
        )?;
        let request = ToEnclaveTransformationRequest {
            request_id: task_request_id,
            chain_id: input_handle_key.chain_id,
            handle_id: HandleId(input_handle_key.handle_id.0),
            enclave_public_key: attestation.enclave_public_key.clone(),
            enclave_measurement: attestation.enclave_measurement,
            attestation: attestation.attestation.clone(),
            system_ciphertext: envelope,
        };
        let enclave_ciphertext = request_to_enclave_transformation(mpc_source, &request).map_err(
            |error| TransformResolutionInputsError::MpcTransformationFailed { input_index, error },
        )?;
        outputs.push(enclave_ciphertext);
    }
    Ok(outputs)
}
