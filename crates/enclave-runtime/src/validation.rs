/// Input AAD validation for the local Enclave runtime.
use coprocessor_ciphertext_binding::{EnclaveAadV1, EnclaveCiphertextV1};
use coprocessor_handle_graph_core::HandleKey;

use crate::{EnclaveExecutionError, ResolutionTask};

use super::local::{LocalEnclaveConfig, AAD_VERSION};

/// The specific AAD field whose verification failed. The variant is safe to
/// surface to the host: it names the failed check without exposing AAD bytes,
/// plaintext, or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputAadField {
    /// The bytes did not decode as a canonical [`coprocessor_ciphertext_binding::EnclaveAadV1`].
    Decode,
    /// The AAD version is not the one this runtime accepts.
    Version,
    /// `chain_id` does not match this runtime's configured chain.
    ChainId,
    /// `domain_id` does not match this runtime's configured domain.
    DomainId,
    /// `request_id` does not match the task's request id, so the ciphertext
    /// is bound to a different request flow.
    RequestId,
    /// `handle_id` does not match the ordered input handle key for this
    /// position in the task.
    HandleId,
    /// `type_tag` does not match the operation's expected input type at this
    /// position.
    TypeTag,
    /// `attestation_digest` does not match this runtime's configured
    /// Enclave key attestation.
    AttestationDigest,
    /// `key_id` does not match this runtime's configured Enclave key id.
    KeyId,
}

pub(super) fn input_aad_error(input_index: usize, field: InputAadField) -> EnclaveExecutionError {
    EnclaveExecutionError::InputAadVerificationFailed { input_index, field }
}

pub(super) fn verify_task_attestation(
    config: &LocalEnclaveConfig,
    task: &ResolutionTask,
) -> Result<(), EnclaveExecutionError> {
    if task.attestation_digest == config.attestation_digest {
        Ok(())
    } else {
        Err(EnclaveExecutionError::AttestationVerificationFailure {
            expected: config.attestation_digest,
            actual: task.attestation_digest,
        })
    }
}

pub(super) fn verify_input_aad(
    config: &LocalEnclaveConfig,
    task: &ResolutionTask,
    input_index: usize,
    input_handle_key: &HandleKey,
    ciphertext: &EnclaveCiphertextV1,
    expected_type_tag: &str,
) -> Result<(), EnclaveExecutionError> {
    let aad = EnclaveAadV1::decode(&ciphertext.aad)
        .map_err(|_| input_aad_error(input_index, InputAadField::Decode))?;
    if aad.version != AAD_VERSION {
        return Err(input_aad_error(input_index, InputAadField::Version));
    }
    if aad.chain_id != config.chain_id {
        return Err(input_aad_error(input_index, InputAadField::ChainId));
    }
    if aad.domain_id != config.domain_id {
        return Err(input_aad_error(input_index, InputAadField::DomainId));
    }
    if aad.request_id != task.request_id {
        return Err(input_aad_error(input_index, InputAadField::RequestId));
    }
    if aad.handle_id.0 != input_handle_key.handle_id.0 {
        return Err(input_aad_error(input_index, InputAadField::HandleId));
    }
    if aad.type_tag != expected_type_tag {
        return Err(input_aad_error(input_index, InputAadField::TypeTag));
    }
    if aad.attestation_digest != config.attestation_digest {
        return Err(input_aad_error(
            input_index,
            InputAadField::AttestationDigest,
        ));
    }
    if aad.key_id != config.enclave_key_id {
        return Err(input_aad_error(input_index, InputAadField::KeyId));
    }
    Ok(())
}
