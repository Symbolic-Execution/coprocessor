//! Local Enclave attestation substitute for ordinary Sandcastle runs and
//! tests.
//!
//! [`LocalEnclaveAttestationSource`] is the host-facing seam's stand-in for
//! deployments without a real Nitro Security Module: integration tests,
//! local developer loops, and Sandcastle runs that exercise the broader
//! Coprocessor pipeline without targeting AWS. It implements the same
//! runtime-neutral [`EnclaveAttestationSource`] trait the
//! [`crate::NitroEnclaveAdapter`] does, so host code remains identical
//! across the two.
//!
//! The substitute serves pre-baked, deterministic material; it does not
//! perform any cryptography and must never be used as the production
//! attestation source.

use crate::{
    AttestationDigest, EnclaveAttestationError, EnclaveAttestationMaterial,
    EnclaveAttestationSource,
};

/// Configuration for [`LocalEnclaveAttestationSource`]: the pre-baked
/// material the host receives every time it asks for attestation evidence.
/// The byte payloads are forwarded verbatim, so test fixtures can mirror
/// whatever shape the rest of the workspace expects (for example a 48-byte
/// BLS12-381 public key and a 96-byte sealed attestation blob).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalEnclaveAttestationConfig {
    pub enclave_public_key: Vec<u8>,
    pub enclave_measurement: AttestationDigest,
    pub attestation: Vec<u8>,
}

/// In-memory [`EnclaveAttestationSource`] used when no real Nitro NSM is
/// available. Construct with [`LocalEnclaveAttestationSource::new`] and
/// drive through the trait the host uses.
pub struct LocalEnclaveAttestationSource {
    config: LocalEnclaveAttestationConfig,
}

impl LocalEnclaveAttestationSource {
    pub fn new(config: LocalEnclaveAttestationConfig) -> Self {
        Self { config }
    }
}

impl EnclaveAttestationSource for LocalEnclaveAttestationSource {
    fn current_attestation_material(
        &self,
    ) -> Result<EnclaveAttestationMaterial, EnclaveAttestationError> {
        Ok(EnclaveAttestationMaterial {
            enclave_public_key: self.config.enclave_public_key.clone(),
            enclave_measurement: self.config.enclave_measurement,
            attestation: self.config.attestation.clone(),
        })
    }
}
