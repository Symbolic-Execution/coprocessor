//! Lowercase `0x`-prefixed hex codec for fixed-length byte strings.
//!
//! Decoding rejects any deviation from the canonical wire form: missing prefix,
//! uppercase digits, odd hex length, non-hex characters, or wrong byte length.
//! Each error carries the field name so the parent decoder can surface the
//! failure without inspecting the offending text.

const PREFIX: &str = "0x";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HexDecodeError {
    MissingPrefix {
        field: &'static str,
    },
    OddLength {
        field: &'static str,
        actual_chars: usize,
    },
    UppercaseDigit {
        field: &'static str,
    },
    InvalidDigit {
        field: &'static str,
    },
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
    let mut chars = payload.bytes();
    while let Some(hi) = chars.next() {
        let lo = chars.next().expect("checked even length above");
        bytes.push((nibble_value(field, hi)? << 4) | nibble_value(field, lo)?);
    }
    if bytes.len() != expected_bytes {
        return Err(HexDecodeError::WrongByteLength {
            field,
            expected: expected_bytes,
            actual: bytes.len(),
        });
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
