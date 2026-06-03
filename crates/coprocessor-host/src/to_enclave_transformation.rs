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
use coprocessor_nitro_enclave::{EnclaveAttestationError, EnclaveAttestationSource};

use crate::resolution_scheduler::ResolutionTask;

/// Reasons [`transform_resolution_task_inputs`] can fail. Each variant
/// identifies the offending input position so the host can map the failure to
/// the corresponding input Handle Key without re-walking the task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransformResolutionInputsError {
    /// The task's input Handle Keys and input ciphertexts are not
    /// index-aligned. Scheduler-built tasks should never hit this; the check
    /// protects the public host method from externally constructed malformed
    /// tasks.
    TaskInputLengthMismatch {
        handle_key_count: usize,
        system_ciphertext_count: usize,
    },
    /// The Enclave attestation seam could not provide the task-scoped
    /// material MPC must validate before transforming any input.
    EnclaveAttestationUnavailable { error: EnclaveAttestationError },
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
/// The Enclave attestation material is fetched once per task and reused for
/// every input, so all transformed inputs target the same Enclave key.
/// `RequestId`s are derived deterministically from the output Handle Key and
/// input index; they are correlation identifiers, not cryptographic
/// authenticators.
///
/// On success, the returned `Vec` is index-aligned with the task's input
/// Handle Keys. On failure, the first failing input short-circuits the
/// transformation and the error identifies that input's position.
pub fn transform_resolution_task_inputs(
    task: &ResolutionTask,
    mpc_source: &dyn MpcToEnclaveSource,
    attestation_source: &dyn EnclaveAttestationSource,
) -> Result<Vec<EnclaveCiphertextV1>, TransformResolutionInputsError> {
    if task.input_handle_keys.len() != task.input_system_ciphertexts.len() {
        return Err(TransformResolutionInputsError::TaskInputLengthMismatch {
            handle_key_count: task.input_handle_keys.len(),
            system_ciphertext_count: task.input_system_ciphertexts.len(),
        });
    }

    let attestation = attestation_source
        .current_attestation_material()
        .map_err(|error| TransformResolutionInputsError::EnclaveAttestationUnavailable { error })?;

    let mut outputs = Vec::with_capacity(task.input_system_ciphertexts.len());
    for (input_index, (input_handle_key, system_ciphertext)) in task
        .input_handle_keys
        .iter()
        .zip(task.input_system_ciphertexts.iter())
        .enumerate()
    {
        let envelope =
            EnvelopeSystemCiphertextV1::decode(&system_ciphertext.0).map_err(|error| {
                TransformResolutionInputsError::MalformedSystemCiphertext { input_index, error }
            })?;
        let request = ToEnclaveTransformationRequest {
            request_id: request_id_for_task_input(task, input_index),
            chain_id: input_handle_key.chain_id,
            handle_id: HandleId(input_handle_key.handle_id.0),
            enclave_public_key: attestation.enclave_public_key.clone(),
            enclave_measurement: attestation.enclave_measurement,
            attestation: attestation.attestation.clone(),
            system_ciphertext: envelope,
        };
        let enclave_ciphertext =
            request_to_enclave_transformation(mpc_source, &request).map_err(|error| {
                TransformResolutionInputsError::MpcTransformationFailed { input_index, error }
            })?;
        outputs.push(enclave_ciphertext);
    }
    Ok(outputs)
}

fn request_id_for_task_input(task: &ResolutionTask, input_index: usize) -> RequestId {
    let mut bytes = [0u8; 32];
    let mut state = 0xcbf2_9ce4_8422_2325u64;

    mix(&mut state, b"coprocessor-host:resolution-task-input:v1");
    mix(&mut state, &task.output_handle_key.chain_id.0.to_be_bytes());
    mix(&mut state, &task.output_handle_key.contract_address.0);
    mix(&mut state, &task.output_handle_key.handle_id.0);
    mix(&mut state, &(input_index as u64).to_be_bytes());

    for chunk in bytes.chunks_mut(8) {
        mix(&mut state, &[chunk.len() as u8]);
        chunk.copy_from_slice(&state.to_be_bytes()[..chunk.len()]);
    }

    RequestId(bytes)
}

fn mix(state: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *state ^= u64::from(*byte);
        *state = state.wrapping_mul(0x0000_0100_0000_01B3);
    }
}
