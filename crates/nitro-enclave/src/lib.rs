//! Runtime-neutral Enclave key and attestation seam used by the Coprocessor
//! Host, together with an AWS Nitro production-target adapter.
//!
//! The Coprocessor Host populates each
//! `ToEnclaveTransformationRequest` it sends to MPC with three pieces of
//! evidence about the Enclave the Resolution Task targets:
//!
//! - the Enclave public key MPC will wrap the input ciphertext to,
//! - the Enclave Measurement MPC will check the attestation against, and
//! - the Attestation evidence that binds the key to that Measurement.
//!
//! This crate owns the host-facing boundary for obtaining that material:
//!
//! 1. [`EnclaveAttestationMaterial`] is the runtime-neutral value object the
//!    host forwards to the MPC client. It carries the three spec fields and
//!    nothing Nitro-specific.
//! 2. [`EnclaveAttestationSource`] is the host-facing seam. Implementations
//!    decide where the material comes from (a Nitro Security Module, a
//!    pre-provisioned local fixture, etc.).
//! 3. [`NitroEnclaveAdapter`] is the production-target implementation for AWS
//!    Nitro Enclaves. It talks to a [`NitroAttestationDocSource`] seam (so
//!    tests can replace the NSM transport with a fake), checks the document's
//!    PCR0 against the configured approved Enclave Measurement, and emits the
//!    runtime-neutral material the host forwards to MPC.
//! 4. [`LocalEnclaveAttestationSource`] is the local-test substitute that
//!    serves pre-baked material so ordinary Sandcastle runs (and unit tests
//!    across the workspace) do not need a real Nitro NSM.
//!
//! Privacy: every error variant in [`EnclaveAttestationError`] and
//! [`NitroSourceError`] carries only non-secret diagnostic context (counts,
//! short text descriptions, the configured and observed measurement digests).
//! Attestation document bytes, the Enclave public key, and the wrapped key
//! material are never embedded in errors, so logging an error never leaks
//! attestation evidence or key bytes.

pub use coprocessor_ciphertext_binding::AttestationDigest;

mod local;
mod nitro;

pub use local::{LocalEnclaveAttestationConfig, LocalEnclaveAttestationSource};
pub use nitro::{
    NitroAdapterConfig, NitroAttestationDoc, NitroAttestationDocSource, NitroEnclaveAdapter,
    NitroSourceError,
};

/// Runtime-neutral material the Coprocessor Host forwards to MPC when
/// requesting a To-Enclave Transformation.
///
/// `enclave_public_key` and `attestation` are opaque byte payloads the host
/// must forward but never inspect. `enclave_measurement` is the Enclave
/// Measurement that MPC checks the attestation against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnclaveAttestationMaterial {
    pub enclave_public_key: Vec<u8>,
    pub enclave_measurement: AttestationDigest,
    pub attestation: Vec<u8>,
}

/// Domain-shaped failures the runtime-neutral attestation boundary surfaces
/// to the host. Mapped from runtime-specific errors by each adapter so the
/// host sees a stable variant set regardless of which Enclave backend is in
/// use.
///
/// No variant embeds attestation document bytes, the Enclave public key, or
/// any other secret-adjacent payload; only counts and short diagnostic
/// descriptions appear.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnclaveAttestationError {
    /// The attestation backend was unreachable or returned a transient
    /// error. Hosts may retry while their retry policy allows it.
    BackendUnavailable { detail: String },
    /// The attestation backend replied, but the document could not be
    /// validated as a well-formed attestation. `detail` is non-secret
    /// diagnostic context (for example, the expected and observed public-key
    /// byte counts).
    MalformedAttestation { detail: String },
    /// The Enclave Measurement carried by the attestation does not match the
    /// approved Enclave Measurement the adapter is configured to accept.
    /// Reported with the expected and actual digests so the host can
    /// correlate logs without inspecting attestation document bytes.
    MeasurementMismatch {
        expected: AttestationDigest,
        actual: AttestationDigest,
    },
    /// The adapter was constructed with configuration that fails its own
    /// validation rules (zero-length public-key expectation, all-zero
    /// approved Enclave Measurement, etc.). The detail describes which rule
    /// failed without exposing the bad value.
    InvalidConfiguration { detail: String },
}

/// Host-facing seam for obtaining Enclave attestation material. The
/// Coprocessor Host calls
/// [`current_attestation_material`](EnclaveAttestationSource::current_attestation_material)
/// every time it needs to build a To-Enclave Transformation request.
///
/// Implementations decide whether the material is freshly attested by a
/// Nitro Security Module, served from a pre-baked local fixture, or supplied
/// by some other backend. The trait commits only to the runtime-neutral
/// material shape and error surface.
pub trait EnclaveAttestationSource {
    fn current_attestation_material(
        &self,
    ) -> Result<EnclaveAttestationMaterial, EnclaveAttestationError>;
}
