//! MPC public configuration for Coprocessor use.
//!
//! The Coprocessor needs the MPC public control-plane configuration before it
//! can schedule plaintext materialization, ask MPC for To-Enclave
//! Transformations, or check Enclave Measurements. This crate owns three
//! concerns:
//!
//! 1. The [`MpcPublicConfig`] value object — the DomainId, ChainId, active
//!    KeyId, public key bytes, cryptographic [`MpcSuite`], and approved
//!    Enclave Measurement that the host must trust before it does any of
//!    that work.
//! 2. Parsing the spec-shaped JSON payload the MPC endpoint serves.
//! 3. Validating the parsed config against the Coprocessor's
//!    [`MpcConfigExpectations`] (chain, domain, suite, public-key shape) so
//!    incompatible configuration is rejected before work is scheduled.
//!
//! The MPC endpoint itself is an [`MpcConfigSource`] seam. Tests provide a
//! fake; later slices wire an HTTP-backed implementation when the host
//! runtime is chosen. Backend availability failures and malformed or
//! incompatible payloads surface as distinct [`MpcConfigLoadError`]
//! variants so a retry loop can treat them differently.
//!
//! All errors carry only non-secret diagnostic context (field names,
//! expected vs actual byte counts, suite identifiers). No public-key bytes,
//! key material, or plaintext appear in error values.

pub use coprocessor_ciphertext_binding::{AttestationDigest, DomainId, KeyId};
pub use coprocessor_handle_graph_core::ChainId;
pub use coprocessor_transport_json::{HexDecodeError, JsonParseError};

use thiserror::Error;

use coprocessor_transport_json::{decode_hex_lower, decode_hex_lower_variable, parse_object};

const DOMAIN_ID_LEN: usize = 32;
const KEY_ID_LEN: usize = 32;
const ATTESTATION_DIGEST_LEN: usize = 32;

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
    /// [`MpcConfigParseError::UnknownSuite`] one level up.
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
/// configuration should construct it through [`load_mpc_public_config`], which
/// checks the public-key length against [`MpcSuite::public_key_len`].
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

/// One configuration dimension the loaded MPC public configuration did not
/// match. Distinct from parse errors and backend availability errors so the
/// host can refuse to schedule work and surface the mismatch without
/// retrying.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MpcConfigIncompatibility {
    #[error("chain_id mismatch: expected {expected:?}, actual {actual:?}")]
    ChainIdMismatch {
        expected: ChainId,
        actual: ChainId,
    },
    /// DomainId carries [u8; 32] — display only a category label, no bytes.
    #[error("domain_id mismatch")]
    DomainIdMismatch {
        expected: DomainId,
        actual: DomainId,
    },
    #[error("suite mismatch: expected {expected:?}, actual {actual:?}")]
    SuiteMismatch {
        expected: MpcSuite,
        actual: MpcSuite,
    },
    #[error("public key shape mismatch for suite {suite:?}: expected {expected_bytes} bytes, actual {actual_bytes} bytes")]
    PublicKeyShape {
        suite: MpcSuite,
        expected_bytes: usize,
        actual_bytes: usize,
    },
}

/// Errors raised while parsing the JSON payload served by an MPC endpoint
/// into an [`MpcPublicConfig`]. All variants describe wire-shape problems
/// before any compatibility check runs, so callers can distinguish "the
/// payload was not a valid MPC config" from "the payload was valid but
/// disagreed with our expectations".
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MpcConfigParseError {
    /// The JSON document was malformed or did not have the expected shape.
    #[error(transparent)]
    Json(#[from] JsonParseError),
    /// A hex-encoded field could not be decoded into bytes.
    /// `#[from]` is on this variant; `InvalidPublicKey` shares the same source
    /// type and is constructed explicitly.
    #[error(transparent)]
    Hex(#[from] HexDecodeError),
    /// The `suite` field carried a value that does not name a known
    /// [`MpcSuite`].
    #[error("unknown MPC suite name")]
    UnknownSuite,
    /// The `public_key` field was not canonical lower `0x`-prefixed hex.
    /// Constructed explicitly (not via `From`) because `HexDecodeError` is
    /// already the `#[from]` source of the `Hex` variant above.
    #[error("invalid public key hex")]
    InvalidPublicKey(#[source] HexDecodeError),
}

/// Reason an [`MpcConfigSource`] could not produce a payload. Reserved for
/// transient backend failures the host can retry under a backoff policy.
/// Implementations that hit the endpoint and read a malformed body should
/// return the body bytes from [`MpcConfigSource::fetch`] and let parsing
/// surface the shape failure as [`MpcConfigLoadError::Malformed`].
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MpcSourceError {
    /// The MPC endpoint was unreachable or returned a transient error.
    /// `detail` is a non-secret transport diagnostic (e.g. OS error string).
    #[error("MPC endpoint unavailable: {detail}")]
    Unavailable { detail: String },
}

/// Combined error type for [`load_mpc_public_config`]. Backend availability
/// failures, malformed payloads, and incompatible payloads are deliberately
/// kept as separate variants so the host can map each to its own behavior:
/// retry, alert, or refuse-to-start.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MpcConfigLoadError {
    /// The MPC endpoint could not be reached. Transient.
    /// `detail` is a non-secret transport diagnostic.
    #[error("MPC endpoint unavailable: {detail}")]
    Unavailable { detail: String },
    /// The endpoint replied but the payload was not a valid MPC public
    /// configuration document.
    #[error("malformed MPC configuration")]
    Malformed(#[from] MpcConfigParseError),
    /// The payload parsed but did not match the Coprocessor's expectations.
    #[error("incompatible MPC configuration")]
    Incompatible(#[from] MpcConfigIncompatibility),
}

/// Source seam for the MPC public configuration. Implementations carry
/// their own endpoint addressing, transport, and authentication; this
/// trait only commits to the wire payload contract: a JSON text document
/// matching [`parse_mpc_public_config`], or an [`MpcSourceError`].
pub trait MpcConfigSource {
    fn fetch(&self) -> Result<String, MpcSourceError>;
}

/// Load and validate the MPC public configuration the Coprocessor will
/// trust for plaintext materialization, To-Enclave Transformation, and
/// Enclave Measurement checks.
///
/// The function delegates fetching to the [`MpcConfigSource`] seam, parses
/// the returned JSON, and runs compatibility checks against the supplied
/// [`MpcConfigExpectations`]. Each failure stage produces its own
/// [`MpcConfigLoadError`] variant.
pub fn load_mpc_public_config(
    source: &dyn MpcConfigSource,
    expectations: &MpcConfigExpectations,
) -> Result<MpcPublicConfig, MpcConfigLoadError> {
    let payload = source.fetch().map_err(map_source_error)?;
    let config = parse_mpc_public_config(&payload)?;
    config.check_compatibility(expectations)?;
    Ok(config)
}

/// Parse the JSON payload served by an MPC endpoint into an
/// [`MpcPublicConfig`]. Surfaces the first wire-shape failure encountered;
/// compatibility checks are deliberately not part of parsing.
pub fn parse_mpc_public_config(text: &str) -> Result<MpcPublicConfig, MpcConfigParseError> {
    let mut object = parse_object(text)?;
    let chain_id = object.take_uint("chain_id")?;
    let domain_id_hex = object.take_string("domain_id")?;
    let active_key_id_hex = object.take_string("active_key_id")?;
    let suite_text = object.take_string("suite")?;
    let public_key_hex = object.take_string("public_key")?;
    let approved_enclave_measurement_hex = object.take_string("approved_enclave_measurement")?;
    object.finish()?;

    let domain_id_bytes = decode_hex_lower(&domain_id_hex, "domain_id", DOMAIN_ID_LEN)?;
    let active_key_id_bytes = decode_hex_lower(&active_key_id_hex, "active_key_id", KEY_ID_LEN)?;
    let approved_enclave_measurement_bytes = decode_hex_lower(
        &approved_enclave_measurement_hex,
        "approved_enclave_measurement",
        ATTESTATION_DIGEST_LEN,
    )?;

    let suite = MpcSuite::from_wire_name(&suite_text).ok_or(MpcConfigParseError::UnknownSuite)?;
    let public_key = decode_hex_lower_variable(&public_key_hex, "public_key")
        .map_err(MpcConfigParseError::InvalidPublicKey)?;

    Ok(MpcPublicConfig {
        chain_id: ChainId(chain_id),
        domain_id: DomainId(to_fixed::<DOMAIN_ID_LEN>(domain_id_bytes)),
        active_key_id: KeyId(to_fixed::<KEY_ID_LEN>(active_key_id_bytes)),
        suite,
        public_key,
        approved_enclave_measurement: AttestationDigest(to_fixed::<ATTESTATION_DIGEST_LEN>(
            approved_enclave_measurement_bytes,
        )),
    })
}

fn map_source_error(error: MpcSourceError) -> MpcConfigLoadError {
    match error {
        MpcSourceError::Unavailable { detail } => MpcConfigLoadError::Unavailable { detail },
    }
}

fn to_fixed<const N: usize>(bytes: Vec<u8>) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}
