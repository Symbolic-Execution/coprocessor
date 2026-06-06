/// MPC public configuration and expectation value objects.
pub use coprocessor_ciphertext_binding::{AttestationDigest, DomainId, KeyId};
pub use coprocessor_handle_graph_core::ChainId;

use super::compat::MpcConfigIncompatibility;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct X25519PublicKey(pub [u8; 32]);

/// Reader key algorithm advertised by the MPC public configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReaderKeyAlgorithm {
    X25519,
}

impl ReaderKeyAlgorithm {
    /// Lowercase wire name carried in the JSON `reader_key_algorithm` field.
    pub fn wire_name(self) -> &'static str {
        match self {
            ReaderKeyAlgorithm::X25519 => "X25519",
        }
    }

    /// Parse a wire name back into a known algorithm. Unknown names surface
    /// as [`super::error::MpcConfigParseError::UnknownReaderKeyAlgorithm`]
    /// one level up.
    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "X25519" => Some(ReaderKeyAlgorithm::X25519),
            _ => None,
        }
    }
}

/// Ciphertext suite advertised by the MPC public configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CiphertextSuite {
    HpkeX25519HkdfSha256Aes256Gcm,
}

impl CiphertextSuite {
    /// Wire name carried in the JSON `ciphertext_suite` field.
    pub fn wire_name(self) -> &'static str {
        match self {
            CiphertextSuite::HpkeX25519HkdfSha256Aes256Gcm => {
                "HpkeX25519HkdfSha256Aes256Gcm"
            }
        }
    }

    /// Parse a wire name back into a known suite. Unknown names surface as
    /// [`super::error::MpcConfigParseError::UnknownCiphertextSuite`] one
    /// level up.
    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "HpkeX25519HkdfSha256Aes256Gcm" => Some(CiphertextSuite::HpkeX25519HkdfSha256Aes256Gcm),
            _ => None,
        }
    }
}

/// MPC public configuration the Coprocessor consumes as control-plane data.
///
/// Each field corresponds to one spec-defined identity the Coprocessor must
/// preserve when calling MPC or checking Enclave Measurement. The
/// `hpke_public_key` is parsed as fixed-width lower-hex bytes. Callers that
/// need a trusted configuration should construct it through
/// [`super::source::load_mpc_public_config`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MpcPublicConfig {
    pub chain_id: ChainId,
    pub domain_id: DomainId,
    pub key_id: KeyId,
    pub hpke_public_key: X25519PublicKey,
    pub reader_key_algorithm: ReaderKeyAlgorithm,
    pub ciphertext_suite: CiphertextSuite,
    pub approved_enclave_measurement: AttestationDigest,
}

impl MpcPublicConfig {
    /// Check the loaded MPC configuration against what the Coprocessor
    /// expects. Returns the first mismatch as an
    /// [`MpcConfigIncompatibility`] in the order the host checks them
    /// (chain, domain, reader-key algorithm, ciphertext suite) so the
    /// failing dimension is stable across runs.
    pub fn check_compatibility(
        &self,
        expectations: &MpcConfigExpectations,
    ) -> Result<(), MpcConfigIncompatibility> {
        if self.chain_id != expectations.chain_id {
            return Err(MpcConfigIncompatibility::ChainIdMismatch {
                expected: expectations.chain_id,
                actual: self.chain_id,
            });
        }
        if self.domain_id != expectations.domain_id {
            return Err(MpcConfigIncompatibility::DomainIdMismatch {
                expected: expectations.domain_id,
                actual: self.domain_id,
            });
        }
        if self.reader_key_algorithm != expectations.reader_key_algorithm {
            return Err(MpcConfigIncompatibility::ReaderKeyAlgorithmMismatch {
                expected: expectations.reader_key_algorithm,
                actual: self.reader_key_algorithm,
            });
        }
        if self.ciphertext_suite != expectations.ciphertext_suite {
            return Err(MpcConfigIncompatibility::CiphertextSuiteMismatch {
                expected: expectations.ciphertext_suite,
                actual: self.ciphertext_suite,
            });
        }
        Ok(())
    }
}

/// What the Coprocessor expects from a loaded MPC public configuration. The
/// host populates this from its own configured chain, domain, and expected
/// control-plane algorithms before the first config load.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MpcConfigExpectations {
    pub chain_id: ChainId,
    pub domain_id: DomainId,
    pub reader_key_algorithm: ReaderKeyAlgorithm,
    pub ciphertext_suite: CiphertextSuite,
}
