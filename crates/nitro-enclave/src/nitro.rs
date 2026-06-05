//! AWS Nitro Enclave production-target adapter.
//!
//! The [`NitroEnclaveAdapter`] implements the runtime-neutral
//! [`EnclaveAttestationSource`] trait by talking to a Nitro Security Module
//! (NSM) through the [`NitroAttestationDocSource`] seam. Splitting the
//! transport behind a trait keeps the adapter testable: integration tests
//! feed a fake document source with fake attestation material and assert the
//! adapter applies its checks and error mapping correctly without booting a
//! Nitro VM.
//!
//! What the adapter checks before producing
//! [`EnclaveAttestationMaterial`]:
//!
//! - the configured [`NitroAdapterConfig`] is internally consistent (the
//!   expected Enclave public-key byte count is non-zero, and the approved
//!   Enclave Measurement is non-zero);
//! - the document's PCR0 equals the approved Enclave Measurement;
//! - the document's embedded Enclave public key has the expected byte count
//!   for the configured MPC suite;
//! - the document carries non-empty attestation evidence the host can
//!   forward to MPC.
//!
//! Nitro-specific concerns - the PCR0 field, the byte-count expectation
//! driven by the chosen MPC suite, and the NSM transport - all live inside
//! this module. Callers receive only the runtime-neutral
//! [`EnclaveAttestationMaterial`] and [`EnclaveAttestationError`] surface
//! exported from the crate root.

use coprocessor_ciphertext_binding::AttestationDigest;
use thiserror::Error;

use crate::{EnclaveAttestationError, EnclaveAttestationMaterial, EnclaveAttestationSource};

/// Configuration for the [`NitroEnclaveAdapter`]. Nitro-specific knobs - the
/// approved PCR0 (the Enclave Measurement MPC will accept) and the expected
/// Enclave public-key byte count (driven by the chosen MPC suite) - stay
/// inside the adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NitroAdapterConfig {
    /// Approved PCR0 / Enclave Measurement. Attestation documents whose
    /// PCR0 differs are rejected with
    /// [`EnclaveAttestationError::MeasurementMismatch`].
    pub approved_enclave_measurement: AttestationDigest,
    /// Expected byte count of the Enclave public key, driven by the chosen
    /// MPC suite (for example, 48 bytes for `bls12-381-g1`). Documents whose
    /// embedded public key has a different length are rejected with
    /// [`EnclaveAttestationError::MalformedAttestation`].
    pub expected_public_key_len: usize,
}

impl NitroAdapterConfig {
    /// Validate the configuration before the adapter is constructed. Surfaces
    /// the first failing rule as
    /// [`EnclaveAttestationError::InvalidConfiguration`] so production
    /// wiring fails fast on misconfiguration without ever fetching an
    /// attestation document.
    pub fn validate(&self) -> Result<(), EnclaveAttestationError> {
        if self.expected_public_key_len == 0 {
            return Err(EnclaveAttestationError::InvalidConfiguration {
                detail: "expected_public_key_len must be greater than zero".to_string(),
            });
        }
        if self.approved_enclave_measurement.0.iter().all(|&b| b == 0) {
            return Err(EnclaveAttestationError::InvalidConfiguration {
                detail: "approved_enclave_measurement must not be all zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Parsed Nitro attestation document fields the adapter needs to check and
/// forward. Implementations of [`NitroAttestationDocSource`] are responsible
/// for parsing the raw NSM payload into this shape; the adapter treats
/// `document_bytes` as opaque attestation evidence and only reads `pcr0`
/// and `enclave_public_key` for validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NitroAttestationDoc {
    /// PCR0 carried by the attestation document. The adapter compares it
    /// against [`NitroAdapterConfig::approved_enclave_measurement`].
    pub pcr0: AttestationDigest,
    /// Enclave public key embedded in the attestation document.
    pub enclave_public_key: Vec<u8>,
    /// Canonical attestation-document bytes (the NSM COSE_Sign1 payload).
    /// The adapter does not parse or sign-verify these; it forwards them to
    /// MPC as the opaque `attestation` field of the To-Enclave
    /// Transformation request.
    pub document_bytes: Vec<u8>,
}

/// Failures the NSM transport itself may return before the adapter sees a
/// usable document. Separate from [`EnclaveAttestationError`] so the
/// transport implementation does not need to know how the adapter maps each
/// case onto the runtime-neutral error surface.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum NitroSourceError {
    /// The NSM endpoint was unreachable or returned a transient error.
    #[error("NSM endpoint unavailable: {detail}")]
    Unavailable { detail: String },
    /// The NSM endpoint replied but the document could not be parsed as a
    /// usable [`NitroAttestationDoc`].
    #[error("malformed NSM attestation document: {detail}")]
    Malformed { detail: String },
}

/// Seam for talking to a Nitro Security Module. Implementations carry their
/// own transport (the `/dev/nsm` device, an in-process simulator, etc.);
/// this trait only commits to producing a parsed [`NitroAttestationDoc`] or
/// a [`NitroSourceError`].
pub trait NitroAttestationDocSource {
    fn fetch_attestation_doc(&self) -> Result<NitroAttestationDoc, NitroSourceError>;
}

/// AWS Nitro Enclave production-target adapter. Construct with
/// [`NitroEnclaveAdapter::new`], which validates the supplied
/// [`NitroAdapterConfig`], then drive through the runtime-neutral
/// [`EnclaveAttestationSource`] trait the Coprocessor Host uses.
pub struct NitroEnclaveAdapter<S> {
    config: NitroAdapterConfig,
    source: S,
}

impl<S> NitroEnclaveAdapter<S>
where
    S: NitroAttestationDocSource,
{
    /// Construct a Nitro adapter. Validates the configuration up front so
    /// misconfigured deployments fail before any NSM round trip. Returns
    /// [`EnclaveAttestationError::InvalidConfiguration`] if the
    /// configuration is internally inconsistent.
    pub fn new(config: NitroAdapterConfig, source: S) -> Result<Self, EnclaveAttestationError> {
        config.validate()?;
        Ok(Self { config, source })
    }
}

impl<S> EnclaveAttestationSource for NitroEnclaveAdapter<S>
where
    S: NitroAttestationDocSource,
{
    fn current_attestation_material(
        &self,
    ) -> Result<EnclaveAttestationMaterial, EnclaveAttestationError> {
        let doc = self
            .source
            .fetch_attestation_doc()
            .map_err(map_source_error)?;

        if doc.pcr0 != self.config.approved_enclave_measurement {
            return Err(EnclaveAttestationError::MeasurementMismatch {
                expected: self.config.approved_enclave_measurement,
                actual: doc.pcr0,
            });
        }

        if doc.enclave_public_key.len() != self.config.expected_public_key_len {
            return Err(EnclaveAttestationError::MalformedAttestation {
                detail: format!(
                    "expected enclave public key length {}, got {}",
                    self.config.expected_public_key_len,
                    doc.enclave_public_key.len()
                ),
            });
        }

        if doc.document_bytes.is_empty() {
            return Err(EnclaveAttestationError::MalformedAttestation {
                detail: "attestation document bytes were empty".to_string(),
            });
        }

        Ok(EnclaveAttestationMaterial {
            enclave_public_key: doc.enclave_public_key,
            enclave_measurement: doc.pcr0,
            attestation: doc.document_bytes,
        })
    }
}

fn map_source_error(error: NitroSourceError) -> EnclaveAttestationError {
    match error {
        NitroSourceError::Unavailable { detail } => {
            EnclaveAttestationError::BackendUnavailable { detail }
        }
        NitroSourceError::Malformed { detail } => {
            EnclaveAttestationError::MalformedAttestation { detail }
        }
    }
}
