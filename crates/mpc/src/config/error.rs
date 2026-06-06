/// MPC configuration parse errors, source errors, and load errors.
use thiserror::Error;

use coprocessor_wire_codec::{HexDecodeError, JsonParseError};

use super::compat::MpcConfigIncompatibility;

/// Errors raised while parsing the JSON payload served by an MPC endpoint
/// into an [`super::config::MpcPublicConfig`]. All variants describe wire-shape
/// problems before any compatibility check runs, so callers can distinguish
/// "the payload was not a valid MPC config" from "the payload was valid but
/// disagreed with our expectations".
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MpcConfigParseError {
    /// The JSON document was malformed or did not have the expected shape.
    #[error(transparent)]
    Json(#[from] JsonParseError),
    /// A hex-encoded field could not be decoded into bytes.
    /// `#[from]` is on this variant; `InvalidHpkePublicKey` shares the same
    /// source type and is constructed explicitly.
    #[error(transparent)]
    Hex(#[from] HexDecodeError),
    /// The `reader_key_algorithm` field carried a value that does not name a
    /// known [`super::config::ReaderKeyAlgorithm`].
    #[error("unknown reader key algorithm")]
    UnknownReaderKeyAlgorithm,
    /// The `ciphertext_suite` field carried a value that does not name a
    /// known [`super::config::CiphertextSuite`].
    #[error("unknown ciphertext suite")]
    UnknownCiphertextSuite,
    /// The `hpke_public_key` field was not canonical lower `0x`-prefixed
    /// fixed-width hex.
    /// Constructed explicitly (not via `From`) because `HexDecodeError` is
    /// already the `#[from]` source of the `Hex` variant above.
    #[error("invalid hpke public key hex")]
    InvalidHpkePublicKey(#[source] HexDecodeError),
}

/// Reason an [`super::source::MpcConfigSource`] could not produce a payload.
/// Reserved for transient backend failures the host can retry under a backoff
/// policy. Implementations that hit the endpoint and read a malformed body
/// should return the body bytes from
/// [`super::source::MpcConfigSource::fetch`] and let parsing surface the
/// shape failure as [`MpcConfigLoadError::Malformed`].
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MpcSourceError {
    /// The MPC endpoint was unreachable or returned a transient error.
    /// `detail` is a non-secret transport diagnostic (e.g. OS error string).
    #[error("MPC endpoint unavailable: {detail}")]
    Unavailable { detail: String },
}

/// Combined error type for [`super::source::load_mpc_public_config`]. Backend
/// availability failures, malformed payloads, and incompatible payloads are
/// deliberately kept as separate variants so the host can map each to its own
/// behavior: retry, alert, or refuse-to-start.
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
