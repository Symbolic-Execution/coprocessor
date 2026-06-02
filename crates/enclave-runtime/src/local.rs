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

use std::cmp::Ordering;

use coprocessor_ciphertext_binding::{
    AttestationDigest, DomainId, EnclaveAadV1, EnclaveCiphertextV1, HandleId as AadHandleId, KeyId,
    RequestId, SystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_handle_graph_core::{HandleKey, HandleType, OperationCode};

use crate::{EnclaveExecutionError, EnclaveExecutionOutcome, EnclaveRuntime, ResolutionTask};

/// Type tag the Coordinator and MPC use for the initial `suint256` Handle
/// type.
const SUINT256_TYPE_TAG: &str = "suint256";

/// Type tag the Coordinator and MPC use for the initial `sbool` Handle type.
const SBOOL_TYPE_TAG: &str = "sbool";

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
    /// `type_tag` does not match the operation's expected input type at this
    /// position.
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

fn input_aad_error(input_index: usize, field: InputAadField) -> EnclaveExecutionError {
    EnclaveExecutionError::InputAadVerificationFailed { input_index, field }
}

const fn type_tag_for_handle_type(handle_type: HandleType) -> &'static str {
    match handle_type {
        HandleType::Suint256 => SUINT256_TYPE_TAG,
        HandleType::Sbool => SBOOL_TYPE_TAG,
    }
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

/// Operations the local Enclave evaluates. Covers the full initial
/// OperationCode and HandleType surface: `suint256` arithmetic
/// (`Add`/`Sub`), comparison (`Eq`/`Lt`/`Lte`/`Gt`/`Gte`), `sbool` logic
/// (`And`/`Or`/`Not`), and the private conditional `Select` for both
/// `suint256` and `sbool` branches. Any other OperationCode or
/// OperationCode/output-type pair surfaces as
/// [`EnclaveExecutionError::OperationNotSupported`].
enum SupportedOperation {
    Add,
    Sub,
    Eq,
    Lt,
    Lte,
    Gt,
    Gte,
    And,
    Or,
    Not,
    SelectSuint256,
    SelectSbool,
}

impl SupportedOperation {
    fn for_task(task: &ResolutionTask) -> Result<Self, EnclaveExecutionError> {
        let supported = match (task.operation_code, task.output_handle_type) {
            (OperationCode::Add, HandleType::Suint256) => SupportedOperation::Add,
            (OperationCode::Sub, HandleType::Suint256) => SupportedOperation::Sub,
            (OperationCode::Eq, HandleType::Sbool) => SupportedOperation::Eq,
            (OperationCode::Lt, HandleType::Sbool) => SupportedOperation::Lt,
            (OperationCode::Lte, HandleType::Sbool) => SupportedOperation::Lte,
            (OperationCode::Gt, HandleType::Sbool) => SupportedOperation::Gt,
            (OperationCode::Gte, HandleType::Sbool) => SupportedOperation::Gte,
            (OperationCode::And, HandleType::Sbool) => SupportedOperation::And,
            (OperationCode::Or, HandleType::Sbool) => SupportedOperation::Or,
            (OperationCode::Not, HandleType::Sbool) => SupportedOperation::Not,
            (OperationCode::Select, HandleType::Suint256) => SupportedOperation::SelectSuint256,
            (OperationCode::Select, HandleType::Sbool) => SupportedOperation::SelectSbool,
            _ => {
                return Err(EnclaveExecutionError::OperationNotSupported(
                    task.operation_code,
                ))
            }
        };
        Ok(supported)
    }

    fn arity(&self) -> usize {
        match self {
            SupportedOperation::Not => 1,
            SupportedOperation::Add
            | SupportedOperation::Sub
            | SupportedOperation::Eq
            | SupportedOperation::Lt
            | SupportedOperation::Lte
            | SupportedOperation::Gt
            | SupportedOperation::Gte
            | SupportedOperation::And
            | SupportedOperation::Or => 2,
            SupportedOperation::SelectSuint256 | SupportedOperation::SelectSbool => 3,
        }
    }

    /// Ordered input HandleType tags expected by this operation. Position is
    /// semantic: for `Select`, the tags are `(predicate sbool, when_true,
    /// when_false)`.
    fn input_type_tags(&self) -> &'static [&'static str] {
        match self {
            SupportedOperation::Add
            | SupportedOperation::Sub
            | SupportedOperation::Eq
            | SupportedOperation::Lt
            | SupportedOperation::Lte
            | SupportedOperation::Gt
            | SupportedOperation::Gte => &[SUINT256_TYPE_TAG, SUINT256_TYPE_TAG],
            SupportedOperation::And | SupportedOperation::Or => &[SBOOL_TYPE_TAG, SBOOL_TYPE_TAG],
            SupportedOperation::Not => &[SBOOL_TYPE_TAG],
            SupportedOperation::SelectSuint256 => {
                &[SBOOL_TYPE_TAG, SUINT256_TYPE_TAG, SUINT256_TYPE_TAG]
            }
            SupportedOperation::SelectSbool => &[SBOOL_TYPE_TAG, SBOOL_TYPE_TAG, SBOOL_TYPE_TAG],
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
            SupportedOperation::Sub => sub_suint256(&inputs[0], &inputs[1]),
            SupportedOperation::Eq => bool_to_payload(inputs[0] == inputs[1]),
            SupportedOperation::Lt => {
                bool_to_payload(cmp_be_u256(&inputs[0], &inputs[1]) == Ordering::Less)
            }
            SupportedOperation::Lte => bool_to_payload(matches!(
                cmp_be_u256(&inputs[0], &inputs[1]),
                Ordering::Less | Ordering::Equal,
            )),
            SupportedOperation::Gt => {
                bool_to_payload(cmp_be_u256(&inputs[0], &inputs[1]) == Ordering::Greater)
            }
            SupportedOperation::Gte => bool_to_payload(matches!(
                cmp_be_u256(&inputs[0], &inputs[1]),
                Ordering::Greater | Ordering::Equal,
            )),
            SupportedOperation::And => {
                bool_to_payload(payload_to_bool(inputs[0]) && payload_to_bool(inputs[1]))
            }
            SupportedOperation::Or => {
                bool_to_payload(payload_to_bool(inputs[0]) || payload_to_bool(inputs[1]))
            }
            SupportedOperation::Not => bool_to_payload(!payload_to_bool(inputs[0])),
            SupportedOperation::SelectSuint256 | SupportedOperation::SelectSbool => {
                if payload_to_bool(inputs[0]) {
                    inputs[1]
                } else {
                    inputs[2]
                }
            }
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

/// Wrapping big-endian 256-bit subtract. Matches the spec's `suint256`
/// semantics: 2^256 modular subtraction with no underflow signalling.
fn sub_suint256(lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = lhs[i] as i16 - rhs[i] as i16 - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    out
}

/// Big-endian unsigned 256-bit comparison.
fn cmp_be_u256(lhs: &[u8; 32], rhs: &[u8; 32]) -> Ordering {
    lhs.cmp(rhs)
}

/// Encode an sbool plaintext as a 32-byte payload: 31 leading zero bytes plus
/// a single `0x00` (false) or `0x01` (true) trailing byte. The local Enclave
/// uses this shape so sbool and suint256 share the same sealing path while
/// keeping the AAD `type_tag` as the authoritative type discriminator.
fn bool_to_payload(value: bool) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = u8::from(value);
    out
}

/// Decode an sbool plaintext from a 32-byte payload. Any non-zero byte means
/// true; this is deliberately lenient so producers that pad the encoding
/// differently still round-trip predictably.
fn payload_to_bool(payload: [u8; 32]) -> bool {
    payload.iter().any(|&b| b != 0)
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
/// use these for unsealing; the keystream is derived directly from the
/// sealing secret and the AAD, but a real MPC-wrapped DEK is non-empty and
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
