/// AAD value types, decode errors, and encode/decode logic for the four
/// spec-defined AAD kinds: SystemInput, SystemHandle, Enclave, and Reader.

use thiserror::Error;

use super::cbor::{
    CborReadError, Reader, MAJOR_ARRAY, MAJOR_BYTE_STRING, MAJOR_TEXT_STRING, MAJOR_UINT,
};
use super::cbor::{write_array_header, write_byte_string, write_text_string, write_unsigned_integer};
use super::identifiers::{
    AadKind, AttestationDigest, ContractAddress, DomainId, HandleId, KeyId, ReaderId, RequestId,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AadDecodeError {
    #[error("malformed AAD encoding")]
    Malformed,
    #[error("non-canonical AAD encoding")]
    NonCanonicalEncoding,
    #[error("trailing bytes in AAD")]
    TrailingBytes,
    #[error("unknown AAD kind")]
    UnknownKind(u64),
    #[error("wrong AAD kind: expected {expected:?}, actual {actual:?}")]
    WrongKind { expected: AadKind, actual: AadKind },
    #[error("wrong AAD length for {kind:?}: expected {expected}, actual {actual}")]
    WrongLength {
        kind: AadKind,
        expected: usize,
        actual: usize,
    },
    #[error("wrong field type for {kind:?}.{field}: expected {expected}")]
    WrongFieldType {
        kind: AadKind,
        field: &'static str,
        expected: &'static str,
    },
    #[error("wrong byte string length for {kind:?}.{field}: expected {expected}, actual {actual}")]
    WrongByteStringLength {
        kind: AadKind,
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid UTF-8 in {kind:?}.{field}")]
    InvalidUtf8 { kind: AadKind, field: &'static str },
    #[error("version overflow in AAD")]
    VersionOverflow(u64),
}

fn map_cbor_read_error(e: CborReadError) -> AadDecodeError {
    match e {
        CborReadError::Malformed => AadDecodeError::Malformed,
        CborReadError::NonCanonical => AadDecodeError::NonCanonicalEncoding,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemInputAadV1 {
    pub version: u8,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub contract: ContractAddress,
    pub type_tag: String,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemHandleAadV1 {
    pub version: u8,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub handle_id: HandleId,
    pub type_tag: String,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnclaveAadV1 {
    pub version: u8,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub request_id: RequestId,
    pub handle_id: HandleId,
    pub type_tag: String,
    pub attestation_digest: AttestationDigest,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReaderAadV1 {
    pub version: u8,
    pub chain_id: u64,
    pub domain_id: DomainId,
    pub request_id: RequestId,
    pub handle_id: HandleId,
    pub reader_id: ReaderId,
    pub type_tag: String,
    pub key_id: KeyId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CiphertextBindingAad {
    SystemInput(SystemInputAadV1),
    SystemHandle(SystemHandleAadV1),
    Enclave(EnclaveAadV1),
    Reader(ReaderAadV1),
}

impl From<SystemInputAadV1> for CiphertextBindingAad {
    fn from(value: SystemInputAadV1) -> Self {
        CiphertextBindingAad::SystemInput(value)
    }
}

impl From<SystemHandleAadV1> for CiphertextBindingAad {
    fn from(value: SystemHandleAadV1) -> Self {
        CiphertextBindingAad::SystemHandle(value)
    }
}

impl From<EnclaveAadV1> for CiphertextBindingAad {
    fn from(value: EnclaveAadV1) -> Self {
        CiphertextBindingAad::Enclave(value)
    }
}

impl From<ReaderAadV1> for CiphertextBindingAad {
    fn from(value: ReaderAadV1) -> Self {
        CiphertextBindingAad::Reader(value)
    }
}

impl CiphertextBindingAad {
    pub fn kind(&self) -> AadKind {
        match self {
            CiphertextBindingAad::SystemInput(_) => AadKind::SystemInput,
            CiphertextBindingAad::SystemHandle(_) => AadKind::SystemHandle,
            CiphertextBindingAad::Enclave(_) => AadKind::Enclave,
            CiphertextBindingAad::Reader(_) => AadKind::Reader,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            CiphertextBindingAad::SystemInput(a) => a.encode(),
            CiphertextBindingAad::SystemHandle(a) => a.encode(),
            CiphertextBindingAad::Enclave(a) => a.encode(),
            CiphertextBindingAad::Reader(a) => a.encode(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AadDecodeError> {
        decode_with_prefix(bytes, None, |reader, prefix| {
            let aad = match prefix.kind {
                AadKind::SystemInput => CiphertextBindingAad::SystemInput(
                    decode_system_input_body(reader, prefix.version)?,
                ),
                AadKind::SystemHandle => CiphertextBindingAad::SystemHandle(
                    decode_system_handle_body(reader, prefix.version)?,
                ),
                AadKind::Enclave => {
                    CiphertextBindingAad::Enclave(decode_enclave_body(reader, prefix.version)?)
                }
                AadKind::Reader => {
                    CiphertextBindingAad::Reader(decode_reader_body(reader, prefix.version)?)
                }
            };
            Ok(aad)
        })
    }
}

impl SystemInputAadV1 {
    pub fn encode(&self) -> Vec<u8> {
        encode_aad(AadKind::SystemInput, self.version, |out| {
            write_unsigned_integer(out, self.chain_id);
            write_byte_string(out, &self.domain_id.0);
            write_byte_string(out, &self.contract.0);
            write_text_string(out, &self.type_tag);
            write_byte_string(out, &self.key_id.0);
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AadDecodeError> {
        decode_with_prefix(bytes, Some(AadKind::SystemInput), |reader, prefix| {
            decode_system_input_body(reader, prefix.version)
        })
    }
}

impl SystemHandleAadV1 {
    pub fn encode(&self) -> Vec<u8> {
        encode_aad(AadKind::SystemHandle, self.version, |out| {
            write_unsigned_integer(out, self.chain_id);
            write_byte_string(out, &self.domain_id.0);
            write_byte_string(out, &self.handle_id.0);
            write_text_string(out, &self.type_tag);
            write_byte_string(out, &self.key_id.0);
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AadDecodeError> {
        decode_with_prefix(bytes, Some(AadKind::SystemHandle), |reader, prefix| {
            decode_system_handle_body(reader, prefix.version)
        })
    }
}

impl EnclaveAadV1 {
    pub fn encode(&self) -> Vec<u8> {
        encode_aad(AadKind::Enclave, self.version, |out| {
            write_unsigned_integer(out, self.chain_id);
            write_byte_string(out, &self.domain_id.0);
            write_byte_string(out, &self.request_id.0);
            write_byte_string(out, &self.handle_id.0);
            write_text_string(out, &self.type_tag);
            write_byte_string(out, &self.attestation_digest.0);
            write_byte_string(out, &self.key_id.0);
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AadDecodeError> {
        decode_with_prefix(bytes, Some(AadKind::Enclave), |reader, prefix| {
            decode_enclave_body(reader, prefix.version)
        })
    }
}

impl ReaderAadV1 {
    pub fn encode(&self) -> Vec<u8> {
        encode_aad(AadKind::Reader, self.version, |out| {
            write_unsigned_integer(out, self.chain_id);
            write_byte_string(out, &self.domain_id.0);
            write_byte_string(out, &self.request_id.0);
            write_byte_string(out, &self.handle_id.0);
            write_byte_string(out, &self.reader_id.0);
            write_text_string(out, &self.type_tag);
            write_byte_string(out, &self.key_id.0);
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AadDecodeError> {
        decode_with_prefix(bytes, Some(AadKind::Reader), |reader, prefix| {
            decode_reader_body(reader, prefix.version)
        })
    }
}

// ---------------------------------------------------------------------------
// Body decoders
// ---------------------------------------------------------------------------

fn decode_system_input_body(
    reader: &mut Reader,
    version: u8,
) -> Result<SystemInputAadV1, AadDecodeError> {
    let kind = AadKind::SystemInput;
    let chain_id = read_uint_field(reader, kind, "chain_id")?;
    let domain_id = DomainId(read_fixed_bytes(reader, kind, "domain_id")?);
    let contract = ContractAddress(read_fixed_bytes::<20>(reader, kind, "contract")?);
    let type_tag = read_text_string(reader, kind, "type_tag")?;
    let key_id = KeyId(read_fixed_bytes(reader, kind, "key_id")?);
    Ok(SystemInputAadV1 {
        version,
        chain_id,
        domain_id,
        contract,
        type_tag,
        key_id,
    })
}

fn decode_system_handle_body(
    reader: &mut Reader,
    version: u8,
) -> Result<SystemHandleAadV1, AadDecodeError> {
    let kind = AadKind::SystemHandle;
    let chain_id = read_uint_field(reader, kind, "chain_id")?;
    let domain_id = DomainId(read_fixed_bytes(reader, kind, "domain_id")?);
    let handle_id = HandleId(read_fixed_bytes(reader, kind, "handle_id")?);
    let type_tag = read_text_string(reader, kind, "type_tag")?;
    let key_id = KeyId(read_fixed_bytes(reader, kind, "key_id")?);
    Ok(SystemHandleAadV1 {
        version,
        chain_id,
        domain_id,
        handle_id,
        type_tag,
        key_id,
    })
}

fn decode_enclave_body(reader: &mut Reader, version: u8) -> Result<EnclaveAadV1, AadDecodeError> {
    let kind = AadKind::Enclave;
    let chain_id = read_uint_field(reader, kind, "chain_id")?;
    let domain_id = DomainId(read_fixed_bytes(reader, kind, "domain_id")?);
    let request_id = RequestId(read_fixed_bytes(reader, kind, "request_id")?);
    let handle_id = HandleId(read_fixed_bytes(reader, kind, "handle_id")?);
    let type_tag = read_text_string(reader, kind, "type_tag")?;
    let attestation_digest =
        AttestationDigest(read_fixed_bytes(reader, kind, "attestation_digest")?);
    let key_id = KeyId(read_fixed_bytes(reader, kind, "key_id")?);
    Ok(EnclaveAadV1 {
        version,
        chain_id,
        domain_id,
        request_id,
        handle_id,
        type_tag,
        attestation_digest,
        key_id,
    })
}

fn decode_reader_body(reader: &mut Reader, version: u8) -> Result<ReaderAadV1, AadDecodeError> {
    let kind = AadKind::Reader;
    let chain_id = read_uint_field(reader, kind, "chain_id")?;
    let domain_id = DomainId(read_fixed_bytes(reader, kind, "domain_id")?);
    let request_id = RequestId(read_fixed_bytes(reader, kind, "request_id")?);
    let handle_id = HandleId(read_fixed_bytes(reader, kind, "handle_id")?);
    let reader_id = ReaderId(read_fixed_bytes(reader, kind, "reader_id")?);
    let type_tag = read_text_string(reader, kind, "type_tag")?;
    let key_id = KeyId(read_fixed_bytes(reader, kind, "key_id")?);
    Ok(ReaderAadV1 {
        version,
        chain_id,
        domain_id,
        request_id,
        handle_id,
        reader_id,
        type_tag,
        key_id,
    })
}

// ---------------------------------------------------------------------------
// AAD prefix encode/decode shared by every kind
// ---------------------------------------------------------------------------

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

pub(crate) fn decode_prefix(reader: &mut Reader) -> Result<Prefix, AadDecodeError> {
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

// ---------------------------------------------------------------------------
// Field readers
// ---------------------------------------------------------------------------

fn read_uint_field(
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

fn read_fixed_bytes<const N: usize>(
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

fn read_text_string(
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

// ---------------------------------------------------------------------------
// AAD-level CBOR write helpers
// ---------------------------------------------------------------------------

fn write_aad_prefix(out: &mut Vec<u8>, kind: AadKind, version: u8) {
    write_array_header(out, kind.array_length());
    write_unsigned_integer(out, version as u64);
    write_unsigned_integer(out, kind.discriminant());
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
