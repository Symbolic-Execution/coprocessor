//! Orchestrate the execute -> materialize path for one claimed Resolution Task.
//!
//! This module transforms the ordered `SystemCiphertextV1` inputs to
//! `EnclaveCiphertextV1` through MPC, builds the enclave-runtime
//! [`ResolutionTask`], calls the [`EnclaveRuntime`] boundary, and bridges the
//! [`EnclaveExecutionOutcome`] back into core domain types so the Handle Graph
//! can transition the Pending Derived Handle to Ready or Failed.
//!
//! Failure classification:
//! - **Terminal** (MPC or Enclave errors that indicate permanent failure):
//!   the Pending Derived Handle transitions to `Failed` with a stable
//!   non-secret category and reason, and the claim is released.
//! - **Retryable** (transient backend unavailability): the Handle stays
//!   Pending, the retry budget decrements, and the claim is released so the
//!   scheduler can re-claim on a later tick. When the budget is exhausted a
//!   retryable failure is promoted to terminal.
//! - **Materialization failures** (core rejects the Ready transition) are
//!   always terminal; they indicate an orchestration bug.
//!
//! Privacy: reason strings carry Handle Key identifiers, counts, and failure
//! categories only — never ciphertext bytes, wrapped keys, enclave private
//! key material, reader secrets, or decrypted payloads.

use coprocessor_ciphertext_binding::{EnclaveCiphertextV1, RequestId};
use coprocessor_enclave_runtime::{
    EnclaveExecutionError, EnclaveRuntime, ResolutionTask as EnclaveResolutionTask,
};
use coprocessor_handle_graph_core::{
    FailureReason, HandleGraphCore, MaterializeDerivedError, SystemCiphertextV1,
};
use coprocessor_mpc_client::{MpcToEnclaveSource, ToEnclaveTransformationError};
use coprocessor_nitro_enclave::{
    EnclaveAttestationError, EnclaveAttestationMaterial, EnclaveAttestationSource,
};

use crate::derived_receipt::encode_derived_materialization_receipt;
use crate::internal_api::{project_canonical, HandleStateView};
use crate::resolution_scheduler::ResolutionTask;
use crate::resolution_scheduler::ResolutionTaskClaims;
use crate::to_enclave_transformation::{
    transform_resolution_task_inputs, TransformResolutionInputsError,
};

/// Classification of a resolution failure: transient (retry budget applies)
/// vs terminal (handle must transition to Failed immediately).
enum FailureClass {
    /// Transient backend unavailability — decrement budget, keep Pending.
    /// `exhaustion_reason` is used when the budget hits zero: the failure
    /// then becomes terminal with the appropriate category and reason.
    Retryable { exhaustion_reason: FailureReason },
    /// Permanent failure — transition to Failed with this reason.
    Terminal(FailureReason),
}

/// Execute one claimed Resolution Task through the Enclave boundary and bind
/// the result into the Handle Graph Core.
///
/// 1. Fetches one Enclave attestation target and transforms the task's ordered
///    input `SystemCiphertextV1` values through MPC.
/// 2. Builds the enclave-runtime [`EnclaveResolutionTask`] and calls `enclave.execute`.
/// 3. On success: bridges the outcome into core domain types and calls
///    `core.materialize_derived_handle` to transition Pending -> Ready.
/// 4. On failure: classifies as Retryable or Terminal.
///    - Retryable with budget: decrements budget, releases claim (Pending).
///    - Retryable without budget: promotes to Terminal.
///    - Terminal: calls `core.fail_derived_handle` (Pending -> Failed).
/// 5. Releases the claim on all paths.
///
/// Returns the [`HandleStateView`] reflecting the handle's state after the
/// call: `Ready` on success, `Failed` on terminal failure, `Pending` on
/// retryable failure while budget remains.
pub(crate) fn resolve_claimed_task(
    task: &ResolutionTask,
    mpc_source: &dyn MpcToEnclaveSource,
    attestation_source: &dyn EnclaveAttestationSource,
    enclave: &dyn EnclaveRuntime,
    core: &mut HandleGraphCore,
    claims: &mut ResolutionTaskClaims,
) -> HandleStateView {
    let attestation = match attestation_source.current_attestation_material() {
        Ok(attestation) => attestation,
        Err(error) => {
            let class = classify_attestation_error(error);
            return handle_failure(task, core, claims, class);
        }
    };

    let pinned_attestation = PinnedAttestationSource {
        material: attestation.clone(),
    };
    let input_ciphertexts =
        match transform_resolution_task_inputs(task, mpc_source, &pinned_attestation) {
            Ok(input_ciphertexts) => input_ciphertexts,
            Err(error) => {
                let class = classify_transform_error(error);
                return handle_failure(task, core, claims, class);
            }
        };

    let enclave_task = build_enclave_task(task, input_ciphertexts, &attestation);

    let outcome = match enclave.execute(&enclave_task) {
        Ok(outcome) => outcome,
        Err(error) => {
            let class = classify_enclave_error(error);
            return handle_failure(task, core, claims, class);
        }
    };

    // Bridge: ciphertext-binding SystemCiphertextV1 -> core opaque bytes
    let core_ciphertext = SystemCiphertextV1(outcome.system_ciphertext.encode());

    // Bridge: EnclaveMaterializationReceipt -> minimal opaque bytes
    let core_receipt = encode_derived_materialization_receipt(&outcome.receipt);

    match core.materialize_derived_handle(&task.output_handle_key, core_ciphertext, core_receipt) {
        Ok(_) => {
            claims.clear_budget(&task.output_handle_key);
            claims.release(&task.output_handle_key);
            project_canonical(core.canonical_handle(&task.output_handle_key))
        }
        Err(error) => {
            let class = FailureClass::Terminal(FailureReason::MaterializationFailure {
                reason: format!("materialization failed: {}", materialize_error_label(error)),
            });
            handle_failure(task, core, claims, class)
        }
    }
}

/// Shared failure dispatch: check budget, either keep Pending or transition
/// to Failed, then release the claim and return the updated view.
fn handle_failure(
    task: &ResolutionTask,
    core: &mut HandleGraphCore,
    claims: &mut ResolutionTaskClaims,
    class: FailureClass,
) -> HandleStateView {
    let terminal_reason = match class {
        FailureClass::Retryable { exhaustion_reason } => {
            let remaining = claims.remaining_budget(&task.output_handle_key);
            if remaining > 0 {
                claims.consume_budget(&task.output_handle_key);
                claims.release(&task.output_handle_key);
                return HandleStateView::Pending;
            }
            // Budget exhausted: promote to terminal using the category-aware
            // exhaustion reason supplied by the classifier.
            exhaustion_reason
        }
        FailureClass::Terminal(reason) => reason,
    };

    apply_terminal_failure(task, core, claims, terminal_reason)
}

/// Apply a terminal failure: transition the Handle to Failed, clear the
/// budget, release the claim, and return the updated view.
fn apply_terminal_failure(
    task: &ResolutionTask,
    core: &mut HandleGraphCore,
    claims: &mut ResolutionTaskClaims,
    reason: FailureReason,
) -> HandleStateView {
    let _ = core.fail_derived_handle(&task.output_handle_key, reason);
    claims.clear_budget(&task.output_handle_key);
    claims.release(&task.output_handle_key);
    project_canonical(core.canonical_handle(&task.output_handle_key))
}

/// Classify an `EnclaveAttestationError` as Retryable or Terminal.
///
/// Backend unavailability is transient; malformed or policy-invalid
/// attestation material is terminal because retrying the same adapter state
/// cannot make the material valid.
fn classify_attestation_error(error: EnclaveAttestationError) -> FailureClass {
    match error {
        EnclaveAttestationError::BackendUnavailable { .. } => FailureClass::Retryable {
            exhaustion_reason: FailureReason::MpcTransformationFailure {
                reason: "enclave attestation unavailable: retry budget exhausted".to_string(),
            },
        },
        EnclaveAttestationError::MalformedAttestation { .. } => {
            FailureClass::Terminal(FailureReason::MpcTransformationFailure {
                reason: "enclave attestation malformed".to_string(),
            })
        }
        EnclaveAttestationError::MeasurementMismatch { .. } => {
            FailureClass::Terminal(FailureReason::MpcTransformationFailure {
                reason: "enclave attestation measurement mismatch".to_string(),
            })
        }
        EnclaveAttestationError::InvalidConfiguration { .. } => {
            FailureClass::Terminal(FailureReason::MpcTransformationFailure {
                reason: "enclave attestation invalid configuration".to_string(),
            })
        }
    }
}

/// Classify a `TransformResolutionInputsError` as Retryable or Terminal.
///
/// Only backend unavailability variants are retryable; all other variants are
/// terminal MPC transformation failures.
fn classify_transform_error(error: TransformResolutionInputsError) -> FailureClass {
    match error {
        TransformResolutionInputsError::EnclaveAttestationUnavailable { error } => {
            classify_attestation_error(error)
        }
        TransformResolutionInputsError::MpcTransformationFailed {
            error: ToEnclaveTransformationError::Unavailable { .. },
            ..
        } => FailureClass::Retryable {
            exhaustion_reason: FailureReason::MpcTransformationFailure {
                reason: "mpc transformation unavailable: retry budget exhausted".to_string(),
            },
        },
        TransformResolutionInputsError::MpcTransformationFailed { input_index, error } => {
            let reason = format!(
                "mpc transformation rejected at input {}: {}",
                input_index,
                transform_error_label(&error),
            );
            FailureClass::Terminal(FailureReason::MpcTransformationFailure { reason })
        }
        TransformResolutionInputsError::MalformedSystemCiphertext { input_index, .. } => {
            FailureClass::Terminal(FailureReason::MpcTransformationFailure {
                reason: format!("malformed system envelope at input {input_index}"),
            })
        }
        TransformResolutionInputsError::TaskInputLengthMismatch {
            handle_key_count,
            system_ciphertext_count,
        } => FailureClass::Terminal(FailureReason::MpcTransformationFailure {
            reason: format!(
                "task input length mismatch: {handle_key_count} handle keys, \
                 {system_ciphertext_count} input envelopes"
            ),
        }),
    }
}

/// Classify an `EnclaveExecutionError` as Retryable or Terminal.
///
/// Only `BackendUnavailable` is retryable; all other variants are terminal
/// enclave execution failures.
fn classify_enclave_error(error: EnclaveExecutionError) -> FailureClass {
    match error {
        EnclaveExecutionError::BackendUnavailable => FailureClass::Retryable {
            exhaustion_reason: FailureReason::EnclaveExecutionFailure {
                reason: "enclave backend unavailable: retry budget exhausted".to_string(),
            },
        },
        EnclaveExecutionError::AttestationVerificationFailure { .. } => {
            FailureClass::Terminal(FailureReason::EnclaveExecutionFailure {
                reason: "enclave attestation verification failed".to_string(),
            })
        }
        EnclaveExecutionError::InputCountMismatch {
            handle_key_count,
            ciphertext_count,
        } => FailureClass::Terminal(FailureReason::EnclaveExecutionFailure {
            reason: format!(
                "enclave input count mismatch: {handle_key_count} handle keys, \
                 {ciphertext_count} input envelopes"
            ),
        }),
        EnclaveExecutionError::OperationNotSupported(_) => {
            FailureClass::Terminal(FailureReason::EnclaveExecutionFailure {
                reason: "enclave operation not supported".to_string(),
            })
        }
        EnclaveExecutionError::InputAadVerificationFailed { input_index, .. } => {
            FailureClass::Terminal(FailureReason::EnclaveExecutionFailure {
                reason: format!("enclave input binding verification failed at index {input_index}"),
            })
        }
    }
}

fn transform_error_label(error: &ToEnclaveTransformationError) -> &'static str {
    match error {
        ToEnclaveTransformationError::Unavailable { .. } => "unavailable",
        ToEnclaveTransformationError::MalformedResponse => "malformed response",
        ToEnclaveTransformationError::Unauthorized => "unauthorized",
        ToEnclaveTransformationError::InvalidBinding => "invalid binding",
        ToEnclaveTransformationError::InvalidAttestation => "invalid attestation",
    }
}

fn materialize_error_label(error: MaterializeDerivedError) -> &'static str {
    match error {
        MaterializeDerivedError::UnknownHandle => "unknown handle",
        MaterializeDerivedError::Tombstoned => "tombstoned handle",
        MaterializeDerivedError::NotDerived => "not derived",
        MaterializeDerivedError::NotPending => "not pending",
    }
}

struct PinnedAttestationSource {
    material: EnclaveAttestationMaterial,
}

impl EnclaveAttestationSource for PinnedAttestationSource {
    fn current_attestation_material(
        &self,
    ) -> Result<EnclaveAttestationMaterial, EnclaveAttestationError> {
        Ok(self.material.clone())
    }
}

/// Build an enclave-runtime [`EnclaveResolutionTask`] from the host scheduler's
/// [`ResolutionTask`]. The `request_id` is derived deterministically from the
/// output Handle Key so restarts produce stable identifiers. The
/// `attestation_digest` is taken from `attestation.enclave_measurement` — the
/// same digest MPC used for the To-Enclave Transformation, so the
/// `FakeEnclaveRuntime::with_expected_attestation` check holds end-to-end.
fn build_enclave_task(
    task: &ResolutionTask,
    input_ciphertexts: Vec<EnclaveCiphertextV1>,
    attestation: &EnclaveAttestationMaterial,
) -> EnclaveResolutionTask {
    EnclaveResolutionTask {
        request_id: request_id_for_enclave_task(task),
        attestation_digest: attestation.enclave_measurement,
        output_handle_key: task.output_handle_key,
        operation_code: task.operation_code,
        output_handle_type: task.output_handle_type,
        input_handle_keys: task.input_handle_keys.clone(),
        input_ciphertexts,
    }
}

/// Derives a deterministic [`RequestId`] for the enclave task from the output
/// Handle Key. Uses the same FNV-1a–based mix as `request_id_for_task_input`
/// in `to_enclave_transformation.rs` with a different domain separator so the
/// two id spaces do not collide.
fn request_id_for_enclave_task(task: &ResolutionTask) -> RequestId {
    let mut bytes = [0u8; 32];
    let mut state = 0xcbf2_9ce4_8422_2325u64;

    mix(&mut state, b"coprocessor-host:enclave-task:v1");
    mix(&mut state, &task.output_handle_key.chain_id.0.to_be_bytes());
    mix(&mut state, &task.output_handle_key.contract_address.0);
    mix(&mut state, &task.output_handle_key.handle_id.0);

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
