/// Minimal canonical CBOR primitives — write helpers plus a strict-mode
/// reader that rejects non-shortest-form encodings.
///
/// Only the subset the AAD and envelope specs need is implemented here.
/// See `docs/cbor-spike-decision.md` for why a third-party CBOR crate
/// was not adopted.
pub(crate) const MAJOR_UINT: u8 = 0;
pub(crate) const MAJOR_BYTE_STRING: u8 = 2;
pub(crate) const MAJOR_TEXT_STRING: u8 = 3;
pub(crate) const MAJOR_ARRAY: u8 = 4;

/// Error from the low-level CBOR reader. Callers map these to domain errors.
#[derive(Clone, Copy, Debug)]
pub(crate) enum CborReadError {
    /// Unexpected end-of-input or unsupported additional-info value.
    Malformed,
    /// A valid CBOR item encoded with a non-shortest-form argument.
    NonCanonical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CborHeader {
    pub(crate) major: u8,
    pub(crate) argument: u64,
}

pub(crate) fn write_unsigned_integer(out: &mut Vec<u8>, value: u64) {
    write_cbor_header(out, MAJOR_UINT, value);
}

pub(crate) fn write_array_header(out: &mut Vec<u8>, len: usize) {
    write_cbor_header(out, MAJOR_ARRAY, len as u64);
}

pub(crate) fn write_byte_string(out: &mut Vec<u8>, bytes: &[u8]) {
    write_cbor_header(out, MAJOR_BYTE_STRING, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub(crate) fn write_text_string(out: &mut Vec<u8>, text: &str) {
    write_cbor_header(out, MAJOR_TEXT_STRING, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

fn write_cbor_header(out: &mut Vec<u8>, major: u8, value: u64) {
    let head = major << 5;
    if value <= 23 {
        out.push(head | value as u8);
    } else if value <= u8::MAX as u64 {
        out.push(head | 24);
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(head | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(head | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(head | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_byte(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos.checked_add(n)? > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(slice)
    }

    /// Read one CBOR header, rejecting non-shortest-form argument encodings.
    /// Returns `Malformed` on EOF or unsupported additional-info values,
    /// `NonCanonical` when the argument uses a longer encoding than necessary.
    pub(crate) fn read_header(&mut self) -> Result<CborHeader, CborReadError> {
        let initial = self.read_byte().ok_or(CborReadError::Malformed)?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        let (arg, min_value) = match info {
            0..=23 => (info as u64, 0),
            24 => (
                self.read_byte().ok_or(CborReadError::Malformed)? as u64,
                24,
            ),
            25 => {
                let b = self.take(2).ok_or(CborReadError::Malformed)?;
                (u16::from_be_bytes([b[0], b[1]]) as u64, 1 << 8)
            }
            26 => {
                let b = self.take(4).ok_or(CborReadError::Malformed)?;
                (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, 1 << 16)
            }
            27 => {
                let b = self.take(8).ok_or(CborReadError::Malformed)?;
                (
                    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                    1 << 32,
                )
            }
            _ => return Err(CborReadError::Malformed),
        };
        if arg < min_value {
            return Err(CborReadError::NonCanonical);
        }
        Ok(CborHeader {
            major,
            argument: arg,
        })
    }
}
