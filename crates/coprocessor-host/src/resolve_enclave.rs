//! Orchestrate the execute -> materialize path for one claimed Resolution Task.
//!
//! This module transforms the ordered `SystemCiphertextV1` inputs to
//! `EnclaveCiphertextV1` through MPC, builds the enclave-runtime
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
    EnclaveExecutionError, EnclaveRuntime, ResolutionTask as EnclaveResolutionTask,
};
use coprocessor_enclave_runtime::AttestationDigest;
use coprocessor_handle_graph_core::{
    ChainId, ContractAddress, HandleGraphCore, HandleId, HandleKey, MaterializationReceipt,
    MaterializeDerivedError, OperationCode, SystemCiphertextV1,
};

use crate::internal_api::DerivedHandleReceiptView;
use coprocessor_mpc_client::MpcToEnclaveSource;
use coprocessor_nitro_enclave::{
    EnclaveAttestationError, EnclaveAttestationMaterial, EnclaveAttestationSource,
};

use crate::internal_api::{project_canonical, HandleStateView};
use crate::resolution_scheduler::ResolutionTask;
use crate::resolution_scheduler::ResolutionTaskClaims;
use crate::to_enclave_transformation::{
    transform_resolution_task_inputs, TransformResolutionInputsError,
};

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
    /// MPC To-Enclave Transformation failed. The Derived Handle remains Pending.
    TransformFailed(TransformResolutionInputsError),
    /// Enclave Execution failed. The Derived Handle remains Pending.
    EnclaveExecutionFailed(EnclaveExecutionError),
    /// The core rejected materialization. This indicates an orchestration bug.
    MaterializationFailed(MaterializeDerivedError),
}

/// Execute one claimed Resolution Task through the Enclave boundary and bind
/// the result into the Handle Graph Core.
///
/// 1. Fetches one Enclave attestation target and transforms the task's ordered
///    input `SystemCiphertextV1` values through MPC.
/// 2. Builds the enclave-runtime [`EnclaveResolutionTask`] from the scheduler
///    `task` and transformed inputs, preserving input order exactly.
/// 3. Calls `enclave.execute`.
/// 4. Bridges the outcome: encodes the ciphertext-binding `SystemCiphertextV1`
///    via `.encode()` into the core's opaque `SystemCiphertextV1(Vec<u8>)`;
///    encodes the `EnclaveMaterializationReceipt` into a minimal deterministic
///    `MaterializationReceipt(Vec<u8>)`.
/// 5. Calls `core.materialize_derived_handle` to transition Pending -> Ready.
/// 6. Releases the claim via `claims.release`.
///
/// On transform or Enclave Execution failure the Handle State is left Pending.
/// The claim is released on every returned error so the task can be claimed
/// again while issue #41 defines retry classification and backoff.
pub(crate) fn resolve_claimed_task(
    task: &ResolutionTask,
    mpc_source: &dyn MpcToEnclaveSource,
    attestation_source: &dyn EnclaveAttestationSource,
    enclave: &dyn EnclaveRuntime,
    core: &mut HandleGraphCore,
    claims: &mut ResolutionTaskClaims,
) -> Result<HandleStateView, ResolveClaimedTaskError> {
    let attestation = match attestation_source.current_attestation_material() {
        Ok(attestation) => attestation,
        Err(error) => {
            claims.release(&task.output_handle_key);
            return Err(ResolveClaimedTaskError::TransformFailed(
                TransformResolutionInputsError::EnclaveAttestationUnavailable { error },
            ));
        }
    };

    let pinned_attestation = PinnedAttestationSource {
        material: attestation.clone(),
    };
    let input_ciphertexts =
        match transform_resolution_task_inputs(task, mpc_source, &pinned_attestation) {
            Ok(input_ciphertexts) => input_ciphertexts,
            Err(error) => {
                claims.release(&task.output_handle_key);
                return Err(ResolveClaimedTaskError::TransformFailed(error));
            }
        };

    let enclave_task = build_enclave_task(task, input_ciphertexts, &attestation);

    let outcome = match enclave.execute(&enclave_task) {
        Ok(outcome) => outcome,
        Err(error) => {
            claims.release(&task.output_handle_key);
            return Err(ResolveClaimedTaskError::EnclaveExecutionFailed(error));
        }
    };

    // Bridge: ciphertext-binding SystemCiphertextV1 -> core opaque bytes
    let core_ciphertext = SystemCiphertextV1(outcome.system_ciphertext.encode());

    // Bridge: EnclaveMaterializationReceipt -> minimal opaque bytes
    let core_receipt = encode_materialization_receipt(&outcome.receipt);

    if let Err(error) =
        core.materialize_derived_handle(&task.output_handle_key, core_ciphertext, core_receipt)
    {
        claims.release(&task.output_handle_key);
        return Err(ResolveClaimedTaskError::MaterializationFailed(error));
    }

    claims.release(&task.output_handle_key);

    Ok(project_canonical(
        core.canonical_handle(&task.output_handle_key),
    ))
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

/// Decode bytes produced by [`encode_materialization_receipt`] into structured
/// receipt fields. Returns `None` if the bytes are malformed or too short.
///
/// Co-located with `encode_materialization_receipt` so the format and its
/// inverse stay together — a deletion test: removing the encoder forces every
/// reader to re-learn the byte layout.
pub(crate) fn decode_materialization_receipt(
    receipt: &MaterializationReceipt,
) -> Option<DerivedHandleReceiptView> {
    let bytes = &receipt.0;
    let mut pos = 0;

    let op_code = op_code_from_byte(*bytes.get(pos)?)?;
    pos += 1;

    let output_handle_key = decode_handle_key(bytes, &mut pos)?;

    if pos + 4 > bytes.len() {
        return None;
    }
    let input_count = u32::from_be_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
    pos += 4;

    let mut input_handle_keys = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        input_handle_keys.push(decode_handle_key(bytes, &mut pos)?);
    }

    if pos + 32 > bytes.len() {
        return None;
    }
    let digest: [u8; 32] = bytes[pos..pos + 32].try_into().ok()?;
    pos += 32;

    if pos != bytes.len() {
        return None;
    }

    Some(DerivedHandleReceiptView {
        operation_code: op_code,
        output_handle_key,
        input_handle_keys,
        attestation_digest: AttestationDigest(digest),
    })
}

fn decode_handle_key(bytes: &[u8], pos: &mut usize) -> Option<HandleKey> {
    if *pos + 60 > bytes.len() {
        return None;
    }
    let chain_id = u64::from_be_bytes(bytes[*pos..*pos + 8].try_into().ok()?);
    *pos += 8;
    let contract_address: [u8; 20] = bytes[*pos..*pos + 20].try_into().ok()?;
    *pos += 20;
    let handle_id: [u8; 32] = bytes[*pos..*pos + 32].try_into().ok()?;
    *pos += 32;
    Some(HandleKey {
        chain_id: ChainId(chain_id),
        contract_address: ContractAddress(contract_address),
        handle_id: HandleId(handle_id),
    })
}

fn encode_handle_key_into(out: &mut Vec<u8>, key: &HandleKey) {
    out.extend_from_slice(&key.chain_id.0.to_be_bytes());
    out.extend_from_slice(&key.contract_address.0);
    out.extend_from_slice(&key.handle_id.0);
}

fn op_code_from_byte(byte: u8) -> Option<OperationCode> {
    match byte {
        1 => Some(OperationCode::Add),
        2 => Some(OperationCode::Sub),
        3 => Some(OperationCode::Eq),
        4 => Some(OperationCode::Lt),
        5 => Some(OperationCode::Lte),
        6 => Some(OperationCode::Gt),
        7 => Some(OperationCode::Gte),
        8 => Some(OperationCode::And),
        9 => Some(OperationCode::Or),
        10 => Some(OperationCode::Not),
        11 => Some(OperationCode::Select),
        _ => None,
    }
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
