//! Canonical RFC 4648 base64 codec for the ciphertext envelope transport.
//!
//! Encoding emits the standard alphabet with `=` padding. Decoding rejects any
//! non-canonical form: characters outside the alphabet (including the URL-safe
//! variant), unpadded inputs, padding in the wrong column, or non-zero unused
//! bits in the final group. The error type is intentionally coarse — the
//! caller only needs to know the payload was malformed, not which byte.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Base64DecodeError {
    InvalidCharacter,
    InvalidLength,
    InvalidPadding,
    NonZeroTail,
}

pub fn encode_into(out: &mut String, bytes: &[u8]) {
    let chunks = bytes.chunks_exact(3);
    let remainder = chunks.remainder();
    for chunk in chunks {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 6) as usize & 0x3f] as char);
        out.push(ALPHABET[n as usize & 0x3f] as char);
    }
    match remainder.len() {
        0 => {}
        1 => {
            let n = u32::from(remainder[0]) << 16;
            out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
            out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = (u32::from(remainder[0]) << 16) | (u32::from(remainder[1]) << 8);
            out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
            out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
            out.push(ALPHABET[(n >> 6) as usize & 0x3f] as char);
            out.push('=');
        }
        _ => unreachable!("chunks_exact remainder is < 3"),
    }
}

pub fn decode(text: &str) -> Result<Vec<u8>, Base64DecodeError> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(Base64DecodeError::InvalidLength);
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let pad = match (bytes[bytes.len() - 2], bytes[bytes.len() - 1]) {
        (b'=', b'=') => 2,
        (_, b'=') => 1,
        _ => 0,
    };
    let payload_chars = bytes.len() - pad;
    let mut out = Vec::with_capacity(payload_chars * 3 / 4);

    let groups = bytes.len() / 4;
    for group_index in 0..groups {
        let group = &bytes[group_index * 4..group_index * 4 + 4];
        let is_last = group_index == groups - 1;
        let group_pad = if is_last { pad } else { 0 };

        // `=` is never valid in a non-final group and never valid before the
        // padding column in the final group; surface that as `InvalidPadding`
        // rather than letting the alphabet check map it to `InvalidCharacter`.
        if !is_last && pad_in_group(group) {
            return Err(Base64DecodeError::InvalidPadding);
        }
        if group[..4 - group_pad].iter().any(|b| *b == b'=') {
            return Err(Base64DecodeError::InvalidPadding);
        }

        let mut acc: u32 = 0;
        for (offset, byte) in group.iter().take(4 - group_pad).enumerate() {
            acc |= u32::from(decode_alphabet_char(*byte)?) << (18 - offset * 6);
        }
        for byte in &group[4 - group_pad..] {
            if *byte != b'=' {
                return Err(Base64DecodeError::InvalidPadding);
            }
        }

        match group_pad {
            0 => {
                out.push((acc >> 16) as u8);
                out.push((acc >> 8) as u8);
                out.push(acc as u8);
            }
            1 => {
                out.push((acc >> 16) as u8);
                out.push((acc >> 8) as u8);
                if (acc as u8) != 0 {
                    return Err(Base64DecodeError::NonZeroTail);
                }
            }
            2 => {
                out.push((acc >> 16) as u8);
                if ((acc >> 8) as u8) != 0 || (acc as u8) != 0 {
                    return Err(Base64DecodeError::NonZeroTail);
                }
            }
            _ => unreachable!("pad is 0..=2"),
        }
    }

    Ok(out)
}

fn decode_alphabet_char(byte: u8) -> Result<u8, Base64DecodeError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Base64DecodeError::InvalidCharacter),
    }
}

fn pad_in_group(group: &[u8]) -> bool {
    group.iter().any(|b| *b == b'=')
}
