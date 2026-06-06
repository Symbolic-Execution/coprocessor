/// Ciphertext envelope types, decode errors, and encode/decode logic for
/// the three spec-defined envelopes: System, Enclave, and Reader.
use thiserror::Error;

use super::aad::{AadDecodeError, CiphertextBindingAad};
use super::cbor::{write_array_header, write_byte_string, write_unsigned_integer};
use super::cbor::{CborReadError, Reader, MAJOR_ARRAY, MAJOR_BYTE_STRING, MAJOR_UINT};
use super::identifiers::{AadKind, EnvelopeKind, KeyId};

const ENVELOPE_ARRAY_LENGTH: usize = 4;
const CANONICAL_SYSTEM_CIPHERTEXT_ARRAY_LENGTH: usize = 6;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EnvelopeDecodeError {
    #[error("malformed {envelope:?} envelope")]
    Malformed { envelope: EnvelopeKind },
    #[error("non-canonical {envelope:?} envelope encoding")]
    NonCanonicalEncoding { envelope: EnvelopeKind },
    #[error("trailing bytes in {envelope:?} envelope")]
    TrailingBytes { envelope: EnvelopeKind },
    #[error("wrong {envelope:?} envelope length: expected {expected}, actual {actual}")]
    WrongLength {
        envelope: EnvelopeKind,
        expected: usize,
        actual: usize,
    },
    #[error("wrong field type in {envelope:?} envelope: field {field} expected {expected}")]
    WrongFieldType {
        envelope: EnvelopeKind,
        field: &'static str,
        expected: &'static str,
    },
    #[error("version overflow in {envelope:?} envelope")]
    VersionOverflow { envelope: EnvelopeKind, value: u64 },
    #[error("AAD binding mismatch in {envelope:?} envelope: unexpected {actual:?} AAD")]
    AadBindingMismatch {
        envelope: EnvelopeKind,
        actual: AadKind,
    },
    #[error("AAD decode error in {envelope:?} envelope")]
    AadDecode {
        envelope: EnvelopeKind,
        #[source]
        error: AadDecodeError,
    },
}

impl EnvelopeDecodeError {
    pub fn envelope(&self) -> EnvelopeKind {
        match self {
            EnvelopeDecodeError::Malformed { envelope }
            | EnvelopeDecodeError::NonCanonicalEncoding { envelope }
            | EnvelopeDecodeError::TrailingBytes { envelope }
            | EnvelopeDecodeError::WrongLength { envelope, .. }
            | EnvelopeDecodeError::WrongFieldType { envelope, .. }
            | EnvelopeDecodeError::VersionOverflow { envelope, .. }
            | EnvelopeDecodeError::AadBindingMismatch { envelope, .. }
            | EnvelopeDecodeError::AadDecode { envelope, .. } => *envelope,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemCiphertextV1 {
    pub version: u8,
    pub aad: Vec<u8>,
    pub wrapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Canonical-CBOR `SystemCiphertextV1` matching the public spec shape used by
/// `sym-client`, `mpc`, `coordinator`, and the on-chain `HandleImportedV1`
/// event surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalSystemCiphertextV1 {
    pub key_id: KeyId,
    pub enc: Vec<u8>,
    pub wrapped_key: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnclaveCiphertextV1 {
    pub version: u8,
    pub aad: Vec<u8>,
    pub wrapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReaderCiphertextV1 {
    pub version: u8,
    pub aad: Vec<u8>,
    pub wrapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl SystemCiphertextV1 {
    pub fn encode(&self) -> Vec<u8> {
        encode_envelope(self.version, &self.aad, &self.wrapped_key, &self.ciphertext)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeDecodeError> {
        let DecodedEnvelope {
            version,
            aad,
            wrapped_key,
            ciphertext,
        } = decode_envelope(bytes, EnvelopeKind::System)?;
        Ok(Self {
            version,
            aad,
            wrapped_key,
            ciphertext,
        })
    }
}

impl CanonicalSystemCiphertextV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_array_header(&mut out, CANONICAL_SYSTEM_CIPHERTEXT_ARRAY_LENGTH);
        write_byte_string(&mut out, &self.key_id.0);
        write_byte_string(&mut out, &self.enc);
        write_byte_string(&mut out, &self.wrapped_key);
        write_byte_string(&mut out, &self.nonce);
        write_byte_string(&mut out, &self.ciphertext);
        write_byte_string(&mut out, &self.aad);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeDecodeError> {
        let envelope = EnvelopeKind::System;
        let mut reader = Reader::new(bytes);
        let array_len = read_array_header(&mut reader, envelope)?;
        if array_len != CANONICAL_SYSTEM_CIPHERTEXT_ARRAY_LENGTH {
            return Err(EnvelopeDecodeError::WrongLength {
                envelope,
                expected: CANONICAL_SYSTEM_CIPHERTEXT_ARRAY_LENGTH,
                actual: array_len,
            });
        }
        let key_id = KeyId(read_fixed_byte_string::<32>(&mut reader, envelope, "key_id")?);
        let enc = read_envelope_byte_string(&mut reader, envelope, "enc")?;
        let wrapped_key = read_envelope_byte_string(&mut reader, envelope, "wrapped_key")?;
        let nonce = read_fixed_byte_string::<12>(&mut reader, envelope, "nonce")?;
        let ciphertext = read_envelope_byte_string(&mut reader, envelope, "ciphertext")?;
        let aad = read_envelope_byte_string(&mut reader, envelope, "aad")?;
        if !reader.done() {
            return Err(EnvelopeDecodeError::TrailingBytes { envelope });
        }
        bind_aad_to_envelope(envelope, &aad)?;
        Ok(Self {
            key_id,
            enc,
            wrapped_key,
            nonce,
            ciphertext,
            aad,
        })
    }
}

impl EnclaveCiphertextV1 {
    pub fn encode(&self) -> Vec<u8> {
        encode_envelope(self.version, &self.aad, &self.wrapped_key, &self.ciphertext)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeDecodeError> {
        let DecodedEnvelope {
            version,
            aad,
            wrapped_key,
            ciphertext,
        } = decode_envelope(bytes, EnvelopeKind::Enclave)?;
        Ok(Self {
            version,
            aad,
            wrapped_key,
            ciphertext,
        })
    }
}

impl ReaderCiphertextV1 {
    pub fn encode(&self) -> Vec<u8> {
        encode_envelope(self.version, &self.aad, &self.wrapped_key, &self.ciphertext)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeDecodeError> {
        let DecodedEnvelope {
            version,
            aad,
            wrapped_key,
            ciphertext,
        } = decode_envelope(bytes, EnvelopeKind::Reader)?;
        Ok(Self {
            version,
            aad,
            wrapped_key,
            ciphertext,
        })
    }
}

struct DecodedEnvelope {
    version: u8,
    aad: Vec<u8>,
    wrapped_key: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn encode_envelope(version: u8, aad: &[u8], wrapped_key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_array_header(&mut out, ENVELOPE_ARRAY_LENGTH);
    write_unsigned_integer(&mut out, version as u64);
    write_byte_string(&mut out, aad);
    write_byte_string(&mut out, wrapped_key);
    write_byte_string(&mut out, ciphertext);
    out
}

fn decode_envelope(
    bytes: &[u8],
    envelope: EnvelopeKind,
) -> Result<DecodedEnvelope, EnvelopeDecodeError> {
    let mut reader = Reader::new(bytes);
    let array_len = read_array_header(&mut reader, envelope)?;
    if array_len != ENVELOPE_ARRAY_LENGTH {
        return Err(EnvelopeDecodeError::WrongLength {
            envelope,
            expected: ENVELOPE_ARRAY_LENGTH,
            actual: array_len,
        });
    }
    let version = read_envelope_version(&mut reader, envelope)?;
    let aad = read_envelope_byte_string(&mut reader, envelope, "aad")?;
    let wrapped_key = read_envelope_byte_string(&mut reader, envelope, "wrapped_key")?;
    let ciphertext = read_envelope_byte_string(&mut reader, envelope, "ciphertext")?;
    if !reader.done() {
        return Err(EnvelopeDecodeError::TrailingBytes { envelope });
    }
    bind_aad_to_envelope(envelope, &aad)?;
    Ok(DecodedEnvelope {
        version,
        aad,
        wrapped_key,
        ciphertext,
    })
}

fn read_envelope_header(
    reader: &mut Reader,
    envelope: EnvelopeKind,
) -> Result<super::cbor::CborHeader, EnvelopeDecodeError> {
    reader
        .read_header()
        .map_err(|err| map_header_error(envelope, err))
}

fn read_array_header(
    reader: &mut Reader,
    envelope: EnvelopeKind,
) -> Result<usize, EnvelopeDecodeError> {
    let header = read_envelope_header(reader, envelope)?;
    if header.major != MAJOR_ARRAY {
        return Err(EnvelopeDecodeError::WrongFieldType {
            envelope,
            field: envelope.name(),
            expected: "array",
        });
    }
    usize::try_from(header.argument).map_err(|_| EnvelopeDecodeError::Malformed { envelope })
}

fn read_envelope_version(
    reader: &mut Reader,
    envelope: EnvelopeKind,
) -> Result<u8, EnvelopeDecodeError> {
    let header = read_envelope_header(reader, envelope)?;
    if header.major != MAJOR_UINT {
        return Err(EnvelopeDecodeError::WrongFieldType {
            envelope,
            field: "version",
            expected: "unsigned integer",
        });
    }
    u8::try_from(header.argument).map_err(|_| EnvelopeDecodeError::VersionOverflow {
        envelope,
        value: header.argument,
    })
}

fn read_envelope_byte_string(
    reader: &mut Reader,
    envelope: EnvelopeKind,
    field: &'static str,
) -> Result<Vec<u8>, EnvelopeDecodeError> {
    let header = read_envelope_header(reader, envelope)?;
    if header.major != MAJOR_BYTE_STRING {
        return Err(EnvelopeDecodeError::WrongFieldType {
            envelope,
            field,
            expected: "byte string",
        });
    }
    let len = usize::try_from(header.argument)
        .map_err(|_| EnvelopeDecodeError::Malformed { envelope })?;
    let payload = reader
        .take(len)
        .ok_or(EnvelopeDecodeError::Malformed { envelope })?;
    Ok(payload.to_vec())
}

fn read_fixed_byte_string<const N: usize>(
    reader: &mut Reader,
    envelope: EnvelopeKind,
    field: &'static str,
) -> Result<[u8; N], EnvelopeDecodeError> {
    let bytes = read_envelope_byte_string(reader, envelope, field)?;
    bytes
        .try_into()
        .map_err(|_| EnvelopeDecodeError::Malformed { envelope })
}

fn bind_aad_to_envelope(
    envelope: EnvelopeKind,
    aad_bytes: &[u8],
) -> Result<(), EnvelopeDecodeError> {
    let aad = CiphertextBindingAad::decode(aad_bytes)
        .map_err(|error| EnvelopeDecodeError::AadDecode { envelope, error })?;
    let kind = aad.kind();
    if !envelope.aad_matches(kind) {
        return Err(EnvelopeDecodeError::AadBindingMismatch {
            envelope,
            actual: kind,
        });
    }
    Ok(())
}

fn map_header_error(envelope: EnvelopeKind, err: CborReadError) -> EnvelopeDecodeError {
    match err {
        CborReadError::Malformed => EnvelopeDecodeError::Malformed { envelope },
        CborReadError::NonCanonical => EnvelopeDecodeError::NonCanonicalEncoding { envelope },
    }
}
