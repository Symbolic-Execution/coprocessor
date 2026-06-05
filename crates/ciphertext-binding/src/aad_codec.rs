//! Shared AAD prefix, field-reader, and write helpers.

use super::aad::AadDecodeError;
use super::cbor::{
    write_array_header, write_unsigned_integer, CborReadError, Reader, MAJOR_ARRAY,
    MAJOR_BYTE_STRING, MAJOR_TEXT_STRING, MAJOR_UINT,
};
use super::identifiers::AadKind;

pub(crate) struct Prefix {
    pub(crate) array_len: usize,
    pub(crate) version: u8,
    pub(crate) kind: AadKind,
}

pub(crate) fn decode_with_prefix<T>(
    bytes: &[u8],
    expected_kind: Option<AadKind>,
    decode_body: impl FnOnce(&mut Reader<'_>, Prefix) -> Result<T, AadDecodeError>,
) -> Result<T, AadDecodeError> {
    let mut reader = Reader::new(bytes);
    let prefix = decode_prefix(&mut reader)?;
    if let Some(expected) = expected_kind {
        require_kind(expected, prefix.kind)?;
    }
    check_array_length(prefix.kind, prefix.array_len)?;
    let value = decode_body(&mut reader, prefix)?;
    ensure_consumed(&reader)?;
    Ok(value)
}

fn decode_prefix(reader: &mut Reader) -> Result<Prefix, AadDecodeError> {
    let array_header = reader.read_header().map_err(map_cbor_read_error)?;
    if array_header.major != MAJOR_ARRAY {
        return Err(AadDecodeError::Malformed);
    }
    let array_len =
        usize::try_from(array_header.argument).map_err(|_| AadDecodeError::Malformed)?;

    let version_header = reader.read_header().map_err(map_cbor_read_error)?;
    if version_header.major != MAJOR_UINT {
        return Err(AadDecodeError::Malformed);
    }
    let version = u8::try_from(version_header.argument)
        .map_err(|_| AadDecodeError::VersionOverflow(version_header.argument))?;

    let kind_header = reader.read_header().map_err(map_cbor_read_error)?;
    if kind_header.major != MAJOR_UINT {
        return Err(AadDecodeError::Malformed);
    }
    let kind = AadKind::from_discriminant(kind_header.argument)
        .ok_or(AadDecodeError::UnknownKind(kind_header.argument))?;

    Ok(Prefix {
        array_len,
        version,
        kind,
    })
}

fn require_kind(expected: AadKind, actual: AadKind) -> Result<(), AadDecodeError> {
    if expected == actual {
        Ok(())
    } else {
        Err(AadDecodeError::WrongKind { expected, actual })
    }
}

fn check_array_length(kind: AadKind, actual: usize) -> Result<(), AadDecodeError> {
    let expected = kind.array_length();
    if actual != expected {
        Err(AadDecodeError::WrongLength {
            kind,
            expected,
            actual,
        })
    } else {
        Ok(())
    }
}

fn ensure_consumed(reader: &Reader) -> Result<(), AadDecodeError> {
    if reader.done() {
        Ok(())
    } else {
        Err(AadDecodeError::TrailingBytes)
    }
}

pub(crate) fn read_uint_field(
    reader: &mut Reader,
    kind: AadKind,
    field: &'static str,
) -> Result<u64, AadDecodeError> {
    let header = reader.read_header().map_err(map_cbor_read_error)?;
    if header.major != MAJOR_UINT {
        return Err(AadDecodeError::WrongFieldType {
            kind,
            field,
            expected: "unsigned integer",
        });
    }
    Ok(header.argument)
}

pub(crate) fn read_fixed_bytes<const N: usize>(
    reader: &mut Reader,
    kind: AadKind,
    field: &'static str,
) -> Result<[u8; N], AadDecodeError> {
    let header = reader.read_header().map_err(map_cbor_read_error)?;
    if header.major != MAJOR_BYTE_STRING {
        return Err(AadDecodeError::WrongFieldType {
            kind,
            field,
            expected: "byte string",
        });
    }
    let actual = usize::try_from(header.argument).map_err(|_| AadDecodeError::Malformed)?;
    if actual != N {
        return Err(AadDecodeError::WrongByteStringLength {
            kind,
            field,
            expected: N,
            actual,
        });
    }
    let payload = reader.take(N).ok_or(AadDecodeError::Malformed)?;
    let mut out = [0u8; N];
    out.copy_from_slice(payload);
    Ok(out)
}

pub(crate) fn read_text_string(
    reader: &mut Reader,
    kind: AadKind,
    field: &'static str,
) -> Result<String, AadDecodeError> {
    let header = reader.read_header().map_err(map_cbor_read_error)?;
    if header.major != MAJOR_TEXT_STRING {
        return Err(AadDecodeError::WrongFieldType {
            kind,
            field,
            expected: "text string",
        });
    }
    let len = usize::try_from(header.argument).map_err(|_| AadDecodeError::Malformed)?;
    let payload = reader.take(len).ok_or(AadDecodeError::Malformed)?;
    let text =
        std::str::from_utf8(payload).map_err(|_| AadDecodeError::InvalidUtf8 { kind, field })?;
    Ok(text.to_string())
}

pub(crate) fn encode_aad(
    kind: AadKind,
    version: u8,
    write_body: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let mut out = Vec::new();
    write_aad_prefix(&mut out, kind, version);
    write_body(&mut out);
    out
}

fn write_aad_prefix(out: &mut Vec<u8>, kind: AadKind, version: u8) {
    write_array_header(out, kind.array_length());
    write_unsigned_integer(out, version as u64);
    write_unsigned_integer(out, kind.discriminant());
}

fn map_cbor_read_error(e: CborReadError) -> AadDecodeError {
    match e {
        CborReadError::Malformed => AadDecodeError::Malformed,
        CborReadError::NonCanonical => AadDecodeError::NonCanonicalEncoding,
    }
}
