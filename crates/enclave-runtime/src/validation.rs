/// Input AAD validation types for the local Enclave runtime.

use crate::EnclaveExecutionError;

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

pub(super) fn input_aad_error(
    input_index: usize,
    field: InputAadField,
) -> EnclaveExecutionError {
    EnclaveExecutionError::InputAadVerificationFailed { input_index, field }
}
