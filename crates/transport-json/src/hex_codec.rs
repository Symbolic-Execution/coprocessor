//! Lowercase `0x`-prefixed hex codec for fixed-length byte strings.
//!
//! Decoding rejects any deviation from the canonical wire form: missing prefix,
//! uppercase digits, odd hex length, non-hex characters, or wrong byte length.
//! Each error carries the field name so the parent decoder can surface the
//! failure without inspecting the offending text.

use thiserror::Error;

const PREFIX: &str = "0x";

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HexDecodeError {
    #[error("missing 0x prefix in {field}")]
    MissingPrefix {
        field: &'static str,
    },
    #[error("odd hex length in {field}: {actual_chars} hex chars")]
    OddLength {
        field: &'static str,
        actual_chars: usize,
    },
    #[error("uppercase hex digit in {field}")]
    UppercaseDigit {
        field: &'static str,
    },
    #[error("invalid hex digit in {field}")]
    InvalidDigit {
        field: &'static str,
    },
    #[error("wrong byte length in {field}: expected {expected}, actual {actual}")]
    WrongByteLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}

pub fn encode_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str(PREFIX);
    for byte in bytes {
        out.push(nibble_to_lower(byte >> 4));
        out.push(nibble_to_lower(byte & 0x0f));
    }
    out
}

pub fn decode_lower(
    text: &str,
    field: &'static str,
    expected_bytes: usize,
) -> Result<Vec<u8>, HexDecodeError> {
    let bytes = decode_lower_variable(text, field)?;
    if bytes.len() != expected_bytes {
        return Err(HexDecodeError::WrongByteLength {
            field,
            expected: expected_bytes,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

/// Decode canonical lowercase `0x`-prefixed hex without enforcing a byte
/// length. Callers that own a variable-length field should validate shape
/// after decoding.
pub fn decode_lower_variable(text: &str, field: &'static str) -> Result<Vec<u8>, HexDecodeError> {
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

fn nibble_to_lower(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("4-bit nibble"),
    }
}

fn nibble_value(field: &'static str, byte: u8) -> Result<u8, HexDecodeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Err(HexDecodeError::UppercaseDigit { field }),
        _ => Err(HexDecodeError::InvalidDigit { field }),
    }
}
