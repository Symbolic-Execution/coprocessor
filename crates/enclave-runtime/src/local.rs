//! Local, in-process Enclave runtime for deterministic integration testing.
//!
//! [`LocalEnclaveRuntime`] implements the host-facing [`EnclaveRuntime`] trait
//! while doing real work inside the boundary: it verifies the
//! [`EnclaveAadV1`] of each input ciphertext, unwraps the test-only sealed
//! payload, evaluates the full initial OperationCode surface over `suint256`
//! and `sbool` private values, and re-seals the result as a
//! [`SystemCiphertextV1`] bound to a [`SystemHandleAadV1`]. The host-visible
//! outputs are the encrypted envelope and the
//! [`EnclaveMaterializationReceipt`]; plaintext Private Values never cross the
//! trait surface.
//!
//! The sealing scheme is deliberately tiny and NOT cryptographic; it is a
//! deterministic, AAD-bound keystream sufficient for tests to assert the
//! boundary plumbing without standing up a real Enclave. Production runtimes
//! (Nitro or otherwise) implement the same trait against attested key material
//! and authenticated encryption.

use coprocessor_ciphertext_binding::{
    AttestationDigest, DomainId, EnclaveAadV1, EnclaveCiphertextV1, HandleId as AadHandleId, KeyId,
    RequestId, SystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_handle_graph_core::{HandleKey, HandleType};

use crate::{EnclaveExecutionError, EnclaveExecutionOutcome, EnclaveRuntime, ResolutionTask};

use super::operation::{
    bool_to_payload, payload_to_bool, type_tag_for_handle_type, SupportedOperation,
};
use super::sealing::{seal_payload, unseal_payload};
use super::validation::{input_aad_error, InputAadField};

/// AAD version the local Enclave produces and accepts. Anything else fails
/// AAD verification.
const AAD_VERSION: u8 = 1;

/// Envelope version the local Enclave stamps on the result.
const ENVELOPE_VERSION: u8 = 1;

/// Configuration the local Enclave is bound to. In production these values
/// come from attested key material and the chain context the host monitors.
#[derive(Clone, Debug)]
pub struct LocalEnclaveConfig {
    /// ChainId the Enclave is permitted to operate against.
    pub chain_id: u64,
    /// DomainId the Enclave is permitted to operate against.
    pub domain_id: DomainId,
    /// Attestation digest of the Enclave key MPC is expected to wrap inputs
    /// to. Tasks whose [`ResolutionTask::attestation_digest`] does not match
    /// are rejected before any input is touched.
    pub attestation_digest: AttestationDigest,
    /// Key id of the Enclave key MPC is expected to wrap inputs to. Inputs
    /// whose AAD binds a different `key_id` are rejected.
    pub enclave_key_id: KeyId,
    /// Key id stamped into the [`SystemHandleAadV1`] of the output envelope.
    pub system_key_id: KeyId,
    /// Test-only sealing secret. The local Enclave uses it as a domain-
    /// separated keystream seed for sealing inputs and outputs. It is NEVER
    /// emitted in errors or returned through the trait surface.
    pub sealing_secret: [u8; 32],
}

/// The local Enclave runtime. Construct with [`LocalEnclaveRuntime::new`] and
/// drive through the [`EnclaveRuntime`] trait the host uses.
///
/// Sealing helpers ([`LocalEnclaveRuntime::seal_suint256_input`],
/// [`LocalEnclaveRuntime::seal_sbool_input`],
/// [`LocalEnclaveRuntime::unseal_suint256_output`], and
/// [`LocalEnclaveRuntime::unseal_sbool_output`]) are provided so tests can
/// build sealed fixtures and verify sealed outputs without ever passing
/// plaintext across the trait surface.
pub struct LocalEnclaveRuntime {
    config: LocalEnclaveConfig,
}

impl LocalEnclaveRuntime {
    pub fn new(config: LocalEnclaveConfig) -> Self {
        Self { config }
    }

    /// Test-only helper: seal a 32-byte `suint256` plaintext into an
    /// [`EnclaveCiphertextV1`] bound to `(request_id, input_handle_key)` under
    /// this runtime's configured AAD. The plaintext bytes are XOR'd with a
    /// deterministic keystream derived from the runtime's sealing secret and
    /// the AAD bytes, so the resulting `ciphertext` is opaque to host code.
    pub fn seal_suint256_input(
        &self,
        request_id: RequestId,
        input_handle_key: HandleKey,
        plaintext: [u8; 32],
    ) -> EnclaveCiphertextV1 {
        self.seal_input(
            request_id,
            input_handle_key,
            type_tag_for_handle_type(HandleType::Suint256),
            plaintext,
        )
    }

    /// Test-only helper: seal an `sbool` value into an
    /// [`EnclaveCiphertextV1`] bound to `(request_id, input_handle_key)` under
    /// this runtime's configured AAD.
    pub fn seal_sbool_input(
        &self,
        request_id: RequestId,
        input_handle_key: HandleKey,
        value: bool,
    ) -> EnclaveCiphertextV1 {
        self.seal_input(
            request_id,
            input_handle_key,
            type_tag_for_handle_type(HandleType::Sbool),
            bool_to_payload(value),
        )
    }

    /// Test-only helper: unseal a [`SystemCiphertextV1`] produced by
    /// [`EnclaveRuntime::execute`]. Returns `None` if the envelope does not
    /// belong to this runtime (wrong AAD shape, wrong key id, or wrong
    /// ciphertext length) or its AAD's `type_tag` is not `suint256`.
    pub fn unseal_suint256_output(&self, ciphertext: &SystemCiphertextV1) -> Option<[u8; 32]> {
        self.unseal_output(ciphertext, type_tag_for_handle_type(HandleType::Suint256))
    }

    /// Test-only helper: unseal a [`SystemCiphertextV1`] produced by
    /// [`EnclaveRuntime::execute`] whose output AAD binds the `sbool`
    /// type tag. Returns `None` if the envelope does not belong to this
    /// runtime or its `type_tag` is not `sbool`.
    pub fn unseal_sbool_output(&self, ciphertext: &SystemCiphertextV1) -> Option<bool> {
        let payload =
            self.unseal_output(ciphertext, type_tag_for_handle_type(HandleType::Sbool))?;
        Some(payload_to_bool(payload))
    }

    fn seal_input(
        &self,
        request_id: RequestId,
        input_handle_key: HandleKey,
        type_tag: &str,
        plaintext: [u8; 32],
    ) -> EnclaveCiphertextV1 {
        let aad = self.build_enclave_aad(request_id, input_handle_key, type_tag);
        let aad_bytes = aad.encode();
        let sealed = seal_payload(&self.config.sealing_secret, &aad_bytes, plaintext);
        EnclaveCiphertextV1 {
            version: ENVELOPE_VERSION,
            aad: aad_bytes,
            wrapped_key: sealed.wrapped_key,
            ciphertext: sealed.ciphertext,
        }
    }

    fn unseal_output(
        &self,
        ciphertext: &SystemCiphertextV1,
        expected_type_tag: &str,
    ) -> Option<[u8; 32]> {
        let aad = SystemHandleAadV1::decode(&ciphertext.aad).ok()?;
        if aad.version != AAD_VERSION
            || aad.chain_id != self.config.chain_id
            || aad.domain_id != self.config.domain_id
            || aad.type_tag != expected_type_tag
            || aad.key_id != self.config.system_key_id
        {
            return None;
        }
        unseal_payload(
            &self.config.sealing_secret,
            &ciphertext.aad,
            &ciphertext.ciphertext,
        )
    }

    fn build_enclave_aad(
        &self,
        request_id: RequestId,
        input_handle_key: HandleKey,
        type_tag: &str,
    ) -> EnclaveAadV1 {
        EnclaveAadV1 {
            version: AAD_VERSION,
            chain_id: self.config.chain_id,
            domain_id: self.config.domain_id,
            request_id,
            handle_id: AadHandleId(input_handle_key.handle_id.0),
            type_tag: type_tag.to_string(),
            attestation_digest: self.config.attestation_digest,
            key_id: self.config.enclave_key_id,
        }
    }

    fn verify_task_attestation(&self, task: &ResolutionTask) -> Result<(), EnclaveExecutionError> {
        if task.attestation_digest == self.config.attestation_digest {
            Ok(())
        } else {
            Err(EnclaveExecutionError::AttestationVerificationFailure {
                expected: self.config.attestation_digest,
                actual: task.attestation_digest,
            })
        }
    }

    fn verify_input_aad(
        &self,
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
        if aad.chain_id != self.config.chain_id {
            return Err(input_aad_error(input_index, InputAadField::ChainId));
        }
        if aad.domain_id != self.config.domain_id {
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
        if aad.attestation_digest != self.config.attestation_digest {
            return Err(input_aad_error(
                input_index,
                InputAadField::AttestationDigest,
            ));
        }
        if aad.key_id != self.config.enclave_key_id {
            return Err(input_aad_error(input_index, InputAadField::KeyId));
        }
        Ok(())
    }

    fn unseal_input(&self, ciphertext: &EnclaveCiphertextV1) -> Option<[u8; 32]> {
        unseal_payload(
            &self.config.sealing_secret,
            &ciphertext.aad,
            &ciphertext.ciphertext,
        )
    }

    fn seal_output(&self, task: &ResolutionTask, plaintext: [u8; 32]) -> SystemCiphertextV1 {
        let type_tag = type_tag_for_handle_type(task.output_handle_type);
        let aad = SystemHandleAadV1 {
            version: AAD_VERSION,
            chain_id: self.config.chain_id,
            domain_id: self.config.domain_id,
            handle_id: AadHandleId(task.output_handle_key.handle_id.0),
            type_tag: type_tag.to_string(),
            key_id: self.config.system_key_id,
        };
        let aad_bytes = aad.encode();
        let sealed = seal_payload(&self.config.sealing_secret, &aad_bytes, plaintext);
        SystemCiphertextV1 {
            version: ENVELOPE_VERSION,
            aad: aad_bytes,
            wrapped_key: sealed.wrapped_key,
            ciphertext: sealed.ciphertext,
        }
    }
}

impl EnclaveRuntime for LocalEnclaveRuntime {
    fn execute(
        &self,
        task: &ResolutionTask,
    ) -> Result<EnclaveExecutionOutcome, EnclaveExecutionError> {
        task.validate_input_count()?;
        self.verify_task_attestation(task)?;

        let evaluator = SupportedOperation::for_task(task)?;
        evaluator.check_arity(task)?;

        let input_type_tags = evaluator.input_type_tags();
        let mut plaintexts: Vec<[u8; 32]> = Vec::with_capacity(task.input_ciphertexts.len());
        for (input_index, ((handle_key, ciphertext), expected_type_tag)) in task
            .input_handle_keys
            .iter()
            .zip(task.input_ciphertexts.iter())
            .zip(input_type_tags.iter())
            .enumerate()
        {
            self.verify_input_aad(task, input_index, handle_key, ciphertext, expected_type_tag)?;
            let plaintext = self
                .unseal_input(ciphertext)
                .ok_or_else(|| input_aad_error(input_index, InputAadField::Decode))?;
            plaintexts.push(plaintext);
        }

        let result = evaluator.evaluate(&plaintexts);
        let system_ciphertext = self.seal_output(task, result);
        let receipt = task.materialization_receipt();
        Ok(EnclaveExecutionOutcome {
            system_ciphertext,
            receipt,
        })
    }
}
