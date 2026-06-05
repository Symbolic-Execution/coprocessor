/// MPC suite, public configuration, and expectation value objects.

pub use coprocessor_ciphertext_binding::{AttestationDigest, DomainId, KeyId};
pub use coprocessor_handle_graph_core::ChainId;

use super::compat::MpcConfigIncompatibility;

/// A spec-named cryptographic suite carried in the MPC public configuration.
///
/// The suite identifies both the threshold scheme MPC runs and the wire
/// shape of [`MpcPublicConfig::public_key`]. Adding a new suite means
/// picking a discriminant, its wire name, and its public-key byte length.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MpcSuite {
    /// BLS12-381 G1 compressed public keys, 48 bytes.
    Bls12_381G1,
}

impl MpcSuite {
    /// Expected byte length of a public key under this suite.
    pub fn public_key_len(self) -> usize {
        match self {
            MpcSuite::Bls12_381G1 => 48,
        }
    }

    /// Lowercase wire name carried in the JSON `suite` field.
    pub fn wire_name(self) -> &'static str {
        match self {
            MpcSuite::Bls12_381G1 => "bls12-381-g1",
        }
    }

    /// Parse a wire name back into a known suite. Unknown names surface as
    /// [`super::error::MpcConfigParseError::UnknownSuite`] one level up.
    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "bls12-381-g1" => Some(MpcSuite::Bls12_381G1),
            _ => None,
        }
    }
}

/// MPC public configuration the Coprocessor consumes as control-plane data.
///
/// Each field corresponds to one spec-defined identity the Coprocessor must
/// preserve when calling MPC or checking Enclave Measurement. The
/// `public_key` is parsed as lower-hex bytes; callers that need a trusted
/// configuration should construct it through
/// [`super::source::load_mpc_public_config`], which checks the public-key
/// length against [`MpcSuite::public_key_len`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MpcPublicConfig {
    pub chain_id: ChainId,
    pub domain_id: DomainId,
    pub active_key_id: KeyId,
    pub suite: MpcSuite,
    pub public_key: Vec<u8>,
    pub approved_enclave_measurement: AttestationDigest,
}

impl MpcPublicConfig {
    /// Check the loaded MPC configuration against what the Coprocessor
    /// expects. Returns the first mismatch as an
    /// [`MpcConfigIncompatibility`] in the order the host checks them
    /// (chain, domain, suite, public-key shape) so the failing dimension is
    /// stable across runs.
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
        if self.suite != expectations.suite {
            return Err(MpcConfigIncompatibility::SuiteMismatch {
                expected: expectations.suite,
                actual: self.suite,
            });
        }
        let expected_bytes = self.suite.public_key_len();
        if self.public_key.len() != expected_bytes {
            return Err(MpcConfigIncompatibility::PublicKeyShape {
                suite: self.suite,
                expected_bytes,
                actual_bytes: self.public_key.len(),
            });
        }
        Ok(())
    }
}

/// What the Coprocessor expects from a loaded MPC public configuration. The
/// host populates this from its own configured chain, domain, and chosen
/// suite before the first config load.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MpcConfigExpectations {
    pub chain_id: ChainId,
    pub domain_id: DomainId,
    pub suite: MpcSuite,
}
