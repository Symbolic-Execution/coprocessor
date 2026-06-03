//! Orchestrate the execute -> materialize path for one claimed Resolution Task.
//!
//! After MPC transforms the ordered `SystemCiphertextV1` inputs to
//! `EnclaveCiphertextV1`, this module builds the enclave-runtime
//! [`ResolutionTask`], calls the [`EnclaveRuntime`] boundary, and bridges the
//! [`EnclaveExecutionOutcome`] back into core domain types so the Handle Graph
//! can transition the Pending Derived Handle to Ready.
//!
//! Bridging:
//! - `ciphertext_binding::SystemCiphertextV1` (structured) → `encode()` →
//!   `core::SystemCiphertextV1(Vec<u8>)` (opaque bytes).
//! - `EnclaveMaterializationReceipt` → minimal deterministic byte encoding →
//!   `core::MaterializationReceipt(Vec<u8>)`. The encoding contains only
//!   non-secret evidence (OperationCode, output Handle Key, ordered input Handle
//!   Keys, attestation digest), never plaintext or key material.
//!
//! Privacy: errors carry Handle Key identifiers and counts but never ciphertext
//! bytes, wrapped keys, or enclave private key material.

use coprocessor_ciphertext_binding::{EnclaveCiphertextV1, RequestId};
use coprocessor_enclave_runtime::{
    EnclaveExecutionError, EnclaveRuntime,
    ResolutionTask as EnclaveResolutionTask,
};
use coprocessor_handle_graph_core::{
    HandleGraphCore, HandleKey, MaterializationReceipt, MaterializeDerivedError,
    OperationCode, SystemCiphertextV1,
};
use coprocessor_nitro_enclave::EnclaveAttestationMaterial;

use crate::internal_api::{project_canonical, HandleStateView};
use crate::resolution_scheduler::ResolutionTask;
use crate::resolution_scheduler::ResolutionTaskClaims;

/// Reasons [`crate::CoprocessorHost::resolve_claimed_task`] can fail.
///
/// On `EnclaveExecutionFailed` the Derived Handle remains Pending — no Handle
/// Graph state changes. On `MaterializationFailed` the call is a bug in the
/// orchestration layer (a claimed task should always have a Pending Derived
/// Handle); it is included for defensive completeness.
///
/// No variant embeds ciphertext bytes, wrapped keys, or enclave private key
/// material, mirroring the sanitized error surfaces elsewhere in this crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveClaimedTaskError {
    /// Enclave Execution failed. The Derived Handle remains Pending.
    EnclaveExecutionFailed(EnclaveExecutionError),
    /// The core rejected materialization. This indicates an orchestration bug.
    MaterializationFailed(MaterializeDerivedError),
}

/// Execute one claimed Resolution Task through the Enclave boundary and bind
/// the result into the Handle Graph Core.
///
/// 1. Builds the enclave-runtime [`EnclaveResolutionTask`] from the scheduler
///    `task` (preserving `input_ciphertexts` ordering exactly).
/// 2. Calls `enclave.execute`.
/// 3. Bridges the outcome: encodes the ciphertext-binding `SystemCiphertextV1`
///    via `.encode()` into the core's opaque `SystemCiphertextV1(Vec<u8>)`;
///    encodes the `EnclaveMaterializationReceipt` into a minimal deterministic
///    `MaterializationReceipt(Vec<u8>)`.
/// 4. Calls `core.materialize_derived_handle` to transition Pending -> Ready.
/// 5. Releases the claim via `claims.release`.
///
/// On `EnclaveExecutionFailed` the Handle State is left Pending (no mutation).
pub(crate) fn resolve_claimed_task(
    task: &ResolutionTask,
    input_ciphertexts: Vec<EnclaveCiphertextV1>,
    attestation: &EnclaveAttestationMaterial,
    enclave: &dyn EnclaveRuntime,
    core: &mut HandleGraphCore,
    claims: &mut ResolutionTaskClaims,
) -> Result<HandleStateView, ResolveClaimedTaskError> {
    let enclave_task = build_enclave_task(task, input_ciphertexts, attestation);

    let outcome = enclave
        .execute(&enclave_task)
        .map_err(ResolveClaimedTaskError::EnclaveExecutionFailed)?;

    // Bridge: ciphertext-binding SystemCiphertextV1 -> core opaque bytes
    let core_ciphertext = SystemCiphertextV1(outcome.system_ciphertext.encode());

    // Bridge: EnclaveMaterializationReceipt -> minimal opaque bytes
    let core_receipt = encode_materialization_receipt(&outcome.receipt);

    core.materialize_derived_handle(&task.output_handle_key, core_ciphertext, core_receipt)
        .map_err(ResolveClaimedTaskError::MaterializationFailed)?;

    claims.release(&task.output_handle_key);

    Ok(project_canonical(core.canonical_handle(&task.output_handle_key)))
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

/// Minimal deterministic encoding of an `EnclaveMaterializationReceipt` into
/// opaque bytes suitable for the core's `MaterializationReceipt(Vec<u8>)`.
///
/// Format (all big-endian):
///   1 byte  : OperationCode discriminant
///  60 bytes : output Handle Key (8 chain_id + 20 contract_address + 32 handle_id)
///   4 bytes : input count (u32)
///  60 bytes : each input Handle Key
///  32 bytes : attestation digest
///
/// Contains only non-secret evidence. Never embeds ciphertext, wrapped keys,
/// raw attestation documents, or enclave private key material.
fn encode_materialization_receipt(
    receipt: &coprocessor_enclave_runtime::EnclaveMaterializationReceipt,
) -> MaterializationReceipt {
    let mut bytes = Vec::new();
    bytes.push(op_code_byte(receipt.operation_code));
    encode_handle_key_into(&mut bytes, &receipt.output_handle_key);
    bytes.extend_from_slice(&(receipt.input_handle_keys.len() as u32).to_be_bytes());
    for input_key in &receipt.input_handle_keys {
        encode_handle_key_into(&mut bytes, input_key);
    }
    bytes.extend_from_slice(&receipt.attestation_digest.0);
    MaterializationReceipt(bytes)
}

fn encode_handle_key_into(out: &mut Vec<u8>, key: &HandleKey) {
    out.extend_from_slice(&key.chain_id.0.to_be_bytes());
    out.extend_from_slice(&key.contract_address.0);
    out.extend_from_slice(&key.handle_id.0);
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
