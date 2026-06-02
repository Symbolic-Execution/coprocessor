//! Runtime-neutral Enclave boundary used by the Coprocessor Host.
//!
//! The Coprocessor Host schedules Resolution Tasks for Derived Handles whose
//! ordered input Handles are Ready (see
//! [`coprocessor_handle_graph_core::HandleGraphCore::resolution_readiness`]).
//! For each task it asks an [`EnclaveRuntime`] to perform Enclave Execution
//! and returns an [`EnclaveExecutionOutcome`] containing the encrypted
//! [`SystemCiphertextV1`] result and a structured Materialization Receipt.
//!
//! The trait does not commit to any runtime (Nitro, simulator, or otherwise).
//! It only describes what the host needs from the boundary:
//!
//! - inputs are [`EnclaveCiphertextV1`] values that MPC already transformed
//!   for the attested Enclave key,
//! - outputs are [`SystemCiphertextV1`] payloads plus an
//!   [`EnclaveMaterializationReceipt`] of non-secret evidence,
//! - errors are domain-shaped and never carry plaintext or key material.
//!
//! Plaintext Private Values never cross this interface. The host receives
//! ciphertext envelopes and receipt metadata only.

pub use coprocessor_ciphertext_binding::{
    AttestationDigest, EnclaveCiphertextV1, RequestId, SystemCiphertextV1,
};
pub use coprocessor_handle_graph_core::{HandleKey, HandleType, OperationCode};

/// One host-scheduled Resolution Task: everything an [`EnclaveRuntime`] needs
/// to perform Enclave Execution for a single Derived Handle.
///
/// `input_ciphertexts` are the MPC-transformed inputs, paired by index with
/// `input_handle_keys`. For `Select`, the inputs stay in predicate,
/// when-true, when-false order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionTask {
    pub request_id: RequestId,
    pub attestation_digest: AttestationDigest,
    pub output_handle_key: HandleKey,
    pub operation_code: OperationCode,
    pub output_handle_type: HandleType,
    pub input_handle_keys: Vec<HandleKey>,
    pub input_ciphertexts: Vec<EnclaveCiphertextV1>,
}

impl ResolutionTask {
    fn validate_input_count(&self) -> Result<(), EnclaveExecutionError> {
        let handle_key_count = self.input_handle_keys.len();
        let ciphertext_count = self.input_ciphertexts.len();

        if handle_key_count == ciphertext_count {
            Ok(())
        } else {
            Err(EnclaveExecutionError::InputCountMismatch {
                handle_key_count,
                ciphertext_count,
            })
        }
    }

    fn materialization_receipt(&self) -> EnclaveMaterializationReceipt {
        EnclaveMaterializationReceipt {
            operation_code: self.operation_code,
            output_handle_key: self.output_handle_key,
            input_handle_keys: self.input_handle_keys.clone(),
            attestation_digest: self.attestation_digest,
        }
    }
}

/// Materialization Receipt for a Derived Handle that became Ready because
/// Enclave Execution succeeded. It carries non-secret evidence the host can
/// persist alongside the [`SystemCiphertextV1`] result: the OperationCode the
/// Enclave evaluated, the output Handle Key it produced, the ordered input
/// Handle Keys it consumed, and the attestation digest of the Enclave key MPC
/// authorized for the To-Enclave Transformation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnclaveMaterializationReceipt {
    pub operation_code: OperationCode,
    pub output_handle_key: HandleKey,
    pub input_handle_keys: Vec<HandleKey>,
    pub attestation_digest: AttestationDigest,
}

/// The successful result of one Enclave Execution: the encrypted result
/// envelope plus the Materialization Receipt the host binds to the Derived
/// Handle Record when it transitions to Ready.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnclaveExecutionOutcome {
    pub system_ciphertext: SystemCiphertextV1,
    pub receipt: EnclaveMaterializationReceipt,
}

/// Domain-shaped failures the runtime-neutral boundary may return.
///
/// Every variant is safe to surface to the Coprocessor Host: it carries
/// Handle Keys, counts, OperationCodes, and attestation digests, but never
/// plaintext, wrapped keys, or ciphertext bytes. The host maps these to the
/// `EnclaveExecutionFailure` Failed category when it cannot recover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnclaveExecutionError {
    /// MPC bound a different Enclave key than the runtime was configured to
    /// accept. Reported with the expected and actual attestation digests so
    /// the host can correlate logs without inspecting key material.
    AttestationVerificationFailure {
        expected: AttestationDigest,
        actual: AttestationDigest,
    },
    /// The task's ordered Handle Keys and input ciphertexts disagree on
    /// length. The runtime cannot guess the pairing.
    InputCountMismatch {
        handle_key_count: usize,
        ciphertext_count: usize,
    },
    /// The runtime does not implement this OperationCode. The host treats
    /// this as a permanent failure for the affected Derived Handle.
    OperationNotSupported(OperationCode),
    /// A transient backend condition (queue full, attestation refresh in
    /// progress, etc.). Hosts may retry while their retry policy still allows
    /// it; the Handle remains Pending in that window.
    BackendUnavailable,
}

/// The host-facing Enclave boundary. Implementations evaluate one
/// [`ResolutionTask`] inside an attested Enclave and return either a
/// [`EnclaveExecutionOutcome`] or a domain-shaped [`EnclaveExecutionError`].
///
/// Implementations must never return plaintext Private Values across this
/// interface. The encrypted [`SystemCiphertextV1`] result and the
/// [`EnclaveMaterializationReceipt`] are the only outputs.
pub trait EnclaveRuntime {
    fn execute(
        &self,
        task: &ResolutionTask,
    ) -> Result<EnclaveExecutionOutcome, EnclaveExecutionError>;
}

/// In-memory [`EnclaveRuntime`] implementation suitable for tests and for
/// host code that wants to drive the boundary without standing up a real
/// Enclave. The fake never decrypts anything: it derives a deterministic
/// pseudo-ciphertext fingerprint from the input envelopes so callers can
/// verify the encrypted result is wired through end-to-end without ever
/// inspecting plaintext.
pub struct FakeEnclaveRuntime {
    expected_attestation: Option<AttestationDigest>,
}

impl FakeEnclaveRuntime {
    /// A fake that accepts whatever attestation digest the task carries. Use
    /// this when the test is exercising other parts of the contract.
    pub fn deterministic() -> Self {
        Self {
            expected_attestation: None,
        }
    }

    /// A fake that rejects any task whose attestation digest does not match
    /// `expected`, surfacing
    /// [`EnclaveExecutionError::AttestationVerificationFailure`].
    pub fn with_expected_attestation(expected: AttestationDigest) -> Self {
        Self {
            expected_attestation: Some(expected),
        }
    }
}

impl EnclaveRuntime for FakeEnclaveRuntime {
    fn execute(
        &self,
        task: &ResolutionTask,
    ) -> Result<EnclaveExecutionOutcome, EnclaveExecutionError> {
        task.validate_input_count()?;
        self.verify_attestation(task.attestation_digest)?;

        let system_ciphertext = synth_system_ciphertext(task);
        let receipt = task.materialization_receipt();
        Ok(EnclaveExecutionOutcome {
            system_ciphertext,
            receipt,
        })
    }
}

impl FakeEnclaveRuntime {
    fn verify_attestation(&self, actual: AttestationDigest) -> Result<(), EnclaveExecutionError> {
        match self.expected_attestation {
            Some(expected) if expected != actual => {
                Err(EnclaveExecutionError::AttestationVerificationFailure { expected, actual })
            }
            _ => Ok(()),
        }
    }
}

const FAKE_SYSTEM_CIPHERTEXT_VERSION: u8 = 1;
const FAKE_AAD_PREFIX: &[u8] = b"fake-enclave-runtime/aad:";
const FAKE_WRAPPED_KEY_PREFIX: &[u8] = b"fake-enclave-runtime/wrapped:";
const FAKE_CIPHERTEXT_PREFIX: &[u8] = b"fake-enclave-runtime/result:";

/// Build a fingerprint [`SystemCiphertextV1`] from a task. The bytes are
/// deterministic and depend on the request id, output Handle Key,
/// OperationCode, and the AAD and ciphertext bytes of each input, so different
/// tasks produce different fingerprints. They are *not* a real encryption;
/// they only let tests assert the boundary plumbing wires inputs through to
/// the host-visible result without ever holding plaintext.
fn synth_system_ciphertext(task: &ResolutionTask) -> SystemCiphertextV1 {
    let mut aad = FAKE_AAD_PREFIX.to_vec();
    aad.extend_from_slice(&task.request_id.0);
    aad.extend_from_slice(&task.output_handle_key.handle_id.0);

    let mut wrapped_key = FAKE_WRAPPED_KEY_PREFIX.to_vec();
    wrapped_key.extend_from_slice(&task.attestation_digest.0);

    let mut ciphertext = FAKE_CIPHERTEXT_PREFIX.to_vec();
    ciphertext.push(op_code_byte(task.operation_code));
    for input in &task.input_ciphertexts {
        ciphertext.extend_from_slice(&input.aad);
        ciphertext.extend_from_slice(&input.ciphertext);
    }
    ciphertext.extend_from_slice(&task.output_handle_key.handle_id.0);

    SystemCiphertextV1 {
        version: FAKE_SYSTEM_CIPHERTEXT_VERSION,
        aad,
        wrapped_key,
        ciphertext,
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
