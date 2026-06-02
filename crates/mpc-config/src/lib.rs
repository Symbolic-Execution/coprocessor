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

use coprocessor_transport_json::{decode_hex_lower, parse_object};

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
/// `public_key` byte length always matches [`MpcSuite::public_key_len`] for
/// the value carried in `suite`; construction through
/// [`parse_mpc_public_config`] enforces that invariant.
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MpcConfigIncompatibility {
    ChainIdMismatch {
        expected: ChainId,
        actual: ChainId,
    },
    DomainIdMismatch {
        expected: DomainId,
        actual: DomainId,
    },
    SuiteMismatch {
        expected: MpcSuite,
        actual: MpcSuite,
    },
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MpcConfigParseError {
    /// The JSON document was malformed or did not have the expected shape.
    Json(JsonParseError),
    /// A hex-encoded field could not be decoded into bytes.
    Hex(HexDecodeError),
    /// The `suite` field carried a value that does not name a known
    /// [`MpcSuite`].
    UnknownSuite,
    /// The `public_key` field's hex was well-formed but its byte length
    /// could not be parsed (odd hex length, missing prefix, etc.).
    InvalidPublicKey(HexDecodeError),
}

impl From<JsonParseError> for MpcConfigParseError {
    fn from(value: JsonParseError) -> Self {
        Self::Json(value)
    }
}

impl From<HexDecodeError> for MpcConfigParseError {
    fn from(value: HexDecodeError) -> Self {
        Self::Hex(value)
    }
}

/// Reason an [`MpcConfigSource`] could not produce a payload. Reserved for
/// transient backend failures the host can retry under a backoff policy.
/// Implementations that hit the endpoint and read a malformed body should
/// return the body bytes from [`MpcConfigSource::fetch`] and let parsing
/// surface the shape failure as [`MpcConfigLoadError::Malformed`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MpcSourceError {
    /// The MPC endpoint was unreachable or returned a transient error.
    Unavailable { detail: String },
}

/// Combined error type for [`load_mpc_public_config`]. Backend availability
/// failures, malformed payloads, and incompatible payloads are deliberately
/// kept as separate variants so the host can map each to its own behavior:
/// retry, alert, or refuse-to-start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MpcConfigLoadError {
    /// The MPC endpoint could not be reached. Transient.
    Unavailable { detail: String },
    /// The endpoint replied but the payload was not a valid MPC public
    /// configuration document.
    Malformed(MpcConfigParseError),
    /// The payload parsed but did not match the Coprocessor's expectations.
    Incompatible(MpcConfigIncompatibility),
}

impl From<MpcConfigParseError> for MpcConfigLoadError {
    fn from(value: MpcConfigParseError) -> Self {
        Self::Malformed(value)
    }
}

impl From<MpcConfigIncompatibility> for MpcConfigLoadError {
    fn from(value: MpcConfigIncompatibility) -> Self {
        Self::Incompatible(value)
    }
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
    let public_key = decode_hex_var_length(&public_key_hex, "public_key")
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

fn decode_hex_var_length(text: &str, field: &'static str) -> Result<Vec<u8>, HexDecodeError> {
    const PREFIX: &str = "0x";
    let payload = text
        .strip_prefix(PREFIX)
        .ok_or(HexDecodeError::MissingPrefix { field })?;
    if payload.len() % 2 != 0 {
        return Err(HexDecodeError::OddLength {
            field,
            actual_chars: payload.len(),
        });
    }
    let mut bytes = Vec::with_capacity(payload.len() / 2);
    for pair in payload.as_bytes().chunks_exact(2) {
        let hi = nibble_value(field, pair[0])?;
        let lo = nibble_value(field, pair[1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn nibble_value(field: &'static str, byte: u8) -> Result<u8, HexDecodeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Err(HexDecodeError::UppercaseDigit { field }),
        _ => Err(HexDecodeError::InvalidDigit { field }),
    }
}
