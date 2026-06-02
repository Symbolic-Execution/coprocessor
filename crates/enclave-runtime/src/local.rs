//! Local, in-process Enclave runtime for deterministic integration testing.
//!
//! [`LocalEnclaveRuntime`] implements the host-facing [`EnclaveRuntime`] trait
//! while doing real work inside the boundary: it verifies the
//! [`EnclaveAadV1`] of each input ciphertext, unwraps the test-only sealed
//! payload, evaluates a narrow `suint256` operation path, and re-seals the
//! result as a [`SystemCiphertextV1`] bound to a [`SystemHandleAadV1`]. The
//! host-visible outputs are the encrypted envelope and the
//! [`EnclaveMaterializationReceipt`]; plaintext Private Values never cross the
//! trait surface.
//!
//! The sealing scheme is deliberately tiny and NOT cryptographic — it is a
//! deterministic, AAD-bound keystream sufficient for tests to assert the
//! boundary plumbing without standing up a real Enclave. Production runtimes
//! (Nitro or otherwise) implement the same trait against attested key material
//! and authenticated encryption.

use coprocessor_ciphertext_binding::{
    AttestationDigest, DomainId, EnclaveAadV1, EnclaveCiphertextV1, HandleId as AadHandleId, KeyId,
    RequestId, SystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_handle_graph_core::{HandleKey, HandleType, OperationCode};

use crate::{EnclaveExecutionError, EnclaveExecutionOutcome, EnclaveRuntime, ResolutionTask};

/// Type tag the Coordinator and MPC use for the initial `suint256` Handle
/// type. The local Enclave only accepts inputs whose AAD binds this tag.
const SUINT256_TYPE_TAG: &str = "suint256";

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

/// The specific AAD field whose verification failed. The variant is safe to
/// surface to the host: it names the failed check without exposing AAD bytes,
/// plaintext, or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputAadField {
    /// The bytes did not decode as a canonical [`EnclaveAadV1`].
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
    /// `type_tag` does not match the operation's expected input type.
    TypeTag,
    /// `attestation_digest` does not match this runtime's configured
    /// Enclave key attestation.
    AttestationDigest,
    /// `key_id` does not match this runtime's configured Enclave key id.
    KeyId,
}

/// The local Enclave runtime. Construct with [`LocalEnclaveRuntime::new`] and
/// drive through the [`EnclaveRuntime`] trait the host uses.
///
/// Sealing helpers ([`LocalEnclaveRuntime::seal_suint256_input`] and
/// [`LocalEnclaveRuntime::unseal_suint256_output`]) are provided so tests can
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
        let aad = self.build_enclave_aad(request_id, input_handle_key);
        let aad_bytes = aad.encode();
        let sealed = seal_payload(&self.config.sealing_secret, &aad_bytes, plaintext);
        EnclaveCiphertextV1 {
            version: ENVELOPE_VERSION,
            aad: aad_bytes,
            wrapped_key: sealed.wrapped_key,
            ciphertext: sealed.ciphertext,
        }
    }

    /// Test-only helper: unseal a [`SystemCiphertextV1`] produced by
    /// [`EnclaveRuntime::execute`]. Returns `None` if the envelope does not
    /// belong to this runtime (wrong AAD shape, wrong key id, or wrong
    /// ciphertext length). Test fixtures use this to verify the operation
    /// result without leaking plaintext to host-facing assertions.
    pub fn unseal_suint256_output(&self, ciphertext: &SystemCiphertextV1) -> Option<[u8; 32]> {
        let aad = SystemHandleAadV1::decode(&ciphertext.aad).ok()?;
        if aad.version != AAD_VERSION
            || aad.chain_id != self.config.chain_id
            || aad.domain_id != self.config.domain_id
            || aad.type_tag != SUINT256_TYPE_TAG
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
    ) -> EnclaveAadV1 {
        EnclaveAadV1 {
            version: AAD_VERSION,
            chain_id: self.config.chain_id,
            domain_id: self.config.domain_id,
            request_id,
            handle_id: AadHandleId(input_handle_key.handle_id.0),
            type_tag: SUINT256_TYPE_TAG.to_string(),
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
        if aad.type_tag != SUINT256_TYPE_TAG {
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
        let aad = SystemHandleAadV1 {
            version: AAD_VERSION,
            chain_id: self.config.chain_id,
            domain_id: self.config.domain_id,
            handle_id: AadHandleId(task.output_handle_key.handle_id.0),
            type_tag: SUINT256_TYPE_TAG.to_string(),
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

        if task.output_handle_type != HandleType::Suint256 {
            return Err(EnclaveExecutionError::OperationNotSupported(
                task.operation_code,
            ));
        }

        let evaluator = SupportedOperation::from_code(task.operation_code).ok_or(
            EnclaveExecutionError::OperationNotSupported(task.operation_code),
        )?;
        evaluator.check_arity(task)?;

        let mut plaintexts: Vec<[u8; 32]> = Vec::with_capacity(task.input_ciphertexts.len());
        for (input_index, (handle_key, ciphertext)) in task
            .input_handle_keys
            .iter()
            .zip(task.input_ciphertexts.iter())
            .enumerate()
        {
            self.verify_input_aad(task, input_index, handle_key, ciphertext)?;
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

fn input_aad_error(input_index: usize, field: InputAadField) -> EnclaveExecutionError {
    EnclaveExecutionError::InputAadVerificationFailed { input_index, field }
}

struct SealedPayload {
    wrapped_key: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn seal_payload(secret: &[u8; 32], aad: &[u8], plaintext: [u8; 32]) -> SealedPayload {
    let keystream = derive_keystream_32(secret, aad);
    SealedPayload {
        wrapped_key: derive_wrapped_key(secret, aad),
        ciphertext: xor32(&plaintext, &keystream).to_vec(),
    }
}

fn unseal_payload(secret: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Option<[u8; 32]> {
    let payload: [u8; 32] = ciphertext.try_into().ok()?;
    let keystream = derive_keystream_32(secret, aad);
    Some(xor32(&payload, &keystream))
}

/// Operations the local Enclave evaluates. The local Enclave intentionally
/// implements a narrow path; anything outside it surfaces as
/// [`EnclaveExecutionError::OperationNotSupported`].
enum SupportedOperation {
    Add,
}

impl SupportedOperation {
    fn from_code(code: OperationCode) -> Option<Self> {
        match code {
            OperationCode::Add => Some(SupportedOperation::Add),
            _ => None,
        }
    }

    fn arity(&self) -> usize {
        match self {
            SupportedOperation::Add => 2,
        }
    }

    fn check_arity(&self, task: &ResolutionTask) -> Result<(), EnclaveExecutionError> {
        let expected = self.arity();
        let actual = task.input_handle_keys.len();
        if actual == expected {
            Ok(())
        } else {
            Err(EnclaveExecutionError::InputCountMismatch {
                handle_key_count: actual,
                ciphertext_count: task.input_ciphertexts.len(),
            })
        }
    }

    fn evaluate(&self, inputs: &[[u8; 32]]) -> [u8; 32] {
        match self {
            SupportedOperation::Add => add_suint256(&inputs[0], &inputs[1]),
        }
    }
}

/// Wrapping big-endian 256-bit add. Matches the spec's `suint256` semantics:
/// 2^256 modular addition with no overflow signalling.
fn add_suint256(lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let sum = lhs[i] as u16 + rhs[i] as u16 + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    out
}

/// Tiny mixing PRG (FNV-1a + a SplitMix64-style finalizer) keyed by the
/// sealing secret and the AAD bytes. NOT cryptographic. Produces a 32-byte
/// keystream that differs whenever the AAD differs, so each sealed payload is
/// bound to its own AAD.
fn derive_keystream_32(secret: &[u8; 32], aad: &[u8]) -> [u8; 32] {
    let mut state: u64 = 0xcbf29ce4_84222325;
    for &b in secret.iter().chain(aad.iter()) {
        state ^= b as u64;
        state = state.wrapping_mul(0x0000_0100_0000_01B3);
    }
    let mut out = [0u8; 32];
    for slot in &mut out {
        state ^= state >> 30;
        state = state.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        state ^= state >> 27;
        state = state.wrapping_mul(0x94D0_49BB_1331_11EB);
        state ^= state >> 31;
        *slot = state as u8;
    }
    out
}

/// Symbolic wrapped-DEK bytes, deterministic per AAD. The Enclave does not
/// use these for unsealing — the keystream is derived directly from the
/// sealing secret and the AAD — but a real MPC-wrapped DEK is non-empty and
/// AAD-bound, and we mirror that here so envelopes look structurally real.
fn derive_wrapped_key(secret: &[u8; 32], aad: &[u8]) -> Vec<u8> {
    let mut state: u64 = 0;
    for &b in secret.iter().chain(aad.iter()) {
        state = state.rotate_left(7) ^ b as u64;
        state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    let mut out = vec![0u8; 16];
    for chunk in out.chunks_exact_mut(8) {
        state ^= state >> 33;
        state = state.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        chunk.copy_from_slice(&state.to_be_bytes());
    }
    out
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}
