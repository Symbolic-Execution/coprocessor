//! Canonical RFC 4648 base64 codec for the ciphertext envelope transport.
//!
//! Encoding emits the standard alphabet with `=` padding. Decoding rejects any
//! non-canonical form: characters outside the alphabet (including the URL-safe
//! variant), unpadded inputs, padding in the wrong column, or non-zero unused
//! bits in the final group. The error type is intentionally coarse — the
//! caller only needs to know the payload was malformed, not which byte.
//!
//! The implementation delegates to the `base64` crate with an explicit
//! canonical configuration so the rejection invariants do not depend on a
//! pre-built engine's defaults.

use base64::{
    alphabet,
    engine::{
        general_purpose::{GeneralPurpose, GeneralPurposeConfig},
        DecodePaddingMode,
    },
    Engine as _,
};
use thiserror::Error;

const CANONICAL_STANDARD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
        .with_decode_allow_trailing_bits(false),
);

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Base64DecodeError {
    #[error("invalid base64 character")]
    InvalidCharacter,
    #[error("invalid base64 length")]
    InvalidLength,
    #[error("invalid base64 padding")]
    InvalidPadding,
    #[error("non-zero tail bits in base64")]
    NonZeroTail,
}

pub fn encode_into(out: &mut String, bytes: &[u8]) {
    CANONICAL_STANDARD.encode_string(bytes, out);
}

pub fn decode(text: &str) -> Result<Vec<u8>, Base64DecodeError> {
    // The base64 crate returns InvalidPadding for non-multiple-of-4 lengths
    // with RequireCanonical mode; pre-check to keep our InvalidLength variant
    // as the canonical rejection for that specific malformation.
    if text.len() % 4 != 0 {
        return Err(Base64DecodeError::InvalidLength);
    }
    CANONICAL_STANDARD.decode(text).map_err(map_decode_error)
}

fn map_decode_error(err: base64::DecodeError) -> Base64DecodeError {
    match err {
        // A `=` byte in a non-padding position is a padding error; any other
        // invalid byte is an alphabet rejection.
        base64::DecodeError::InvalidByte(_, b'=') => Base64DecodeError::InvalidPadding,
        base64::DecodeError::InvalidByte(_, _) => Base64DecodeError::InvalidCharacter,
        base64::DecodeError::InvalidLength(_) => Base64DecodeError::InvalidLength,
        // Non-zero unused bits in the final symbol.
        base64::DecodeError::InvalidLastSymbol(_, _) => Base64DecodeError::NonZeroTail,
        // Padding structure is wrong (e.g. wrong number of `=` chars).
        base64::DecodeError::InvalidPadding => Base64DecodeError::InvalidPadding,
    }
}
