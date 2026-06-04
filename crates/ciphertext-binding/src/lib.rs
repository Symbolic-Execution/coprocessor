//! Canonical Ciphertext Binding AAD codecs for the Coprocessor / MPC / Enclave
//! boundary.
//!
//! Each AAD kind encodes to a fixed-order canonical CBOR array (never a map),
//! starting with the version byte and an integer kind discriminant. Decoders
//! surface domain-shaped, non-secret errors so callers can map them to API
//! responses without leaking ciphertext or key material.
//!
//! # CBOR implementation
//!
//! The minimal CBOR reader/writer at the bottom of this file is intentional.
//! A spike (issue #84) evaluated `minicbor` as a replacement and found that
//! it does not reject non-canonical (non-shortest-form) integer and length
//! encodings on decode, requiring a hand-written guard that reproduces the
//! existing `read_header` check. The manual implementation was retained.
//! See the repository-level `docs/cbor-spike-decision.md` for the full
//! rationale.

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DomainId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContractAddress(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HandleId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReaderId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AttestationDigest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AadKind {
    SystemInput,
    SystemHandle,
    Enclave,
    Reader,
}

impl AadKind {
    fn discriminant(self) -> u64 {
        match self {
            AadKind::SystemInput => 1,
            AadKind::SystemHandle => 2,
            AadKind::Enclave => 3,
            AadKind::Reader => 4,
        }
    }

    fn from_discriminant(value: u64) -> Option<Self> {
        Some(match value {
            1 => AadKind::SystemInput,
            2 => AadKind::SystemHandle,
            3 => AadKind::Enclave,
            4 => AadKind::Reader,
            _ => return None,
        })
    }

    fn array_length(self) -> usize {
        match self {
            AadKind::SystemInput | AadKind::SystemHandle => 7,
            AadKind::Enclave | AadKind::Reader => 9,
        }
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

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AadDecodeError {
    #[error("malformed AAD")]
    Malformed,
    #[error("non-canonical AAD encoding")]
    NonCanonicalEncoding,
    #[error("trailing bytes after AAD payload")]
    TrailingBytes,
    #[error("unknown AAD kind discriminant {0}")]
    UnknownKind(u64),
    #[error("wrong AAD kind: expected {expected:?}, actual {actual:?}")]
    WrongKind { expected: AadKind, actual: AadKind },
    #[error("wrong AAD length for {kind:?}: expected {expected}, actual {actual}")]
    WrongLength {
        kind: AadKind,
        expected: usize,
        actual: usize,
    },
    #[error("wrong field type in {kind:?} for {field}: expected {expected}")]
    WrongFieldType {
        kind: AadKind,
        field: &'static str,
        expected: &'static str,
    },
    #[error(
        "wrong byte-string length in {kind:?} for {field}: expected {expected}, actual {actual}"
    )]
    WrongByteStringLength {
        kind: AadKind,
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid utf-8 in {kind:?} for {field}")]
    InvalidUtf8 { kind: AadKind, field: &'static str },
    #[error("AAD version overflow: {0}")]
    VersionOverflow(u64),
}

/// Kind discriminant for the three spec-defined ciphertext envelopes that wrap
/// AAD and opaque cryptographic payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeKind {
    System,
    Enclave,
    Reader,
}

impl EnvelopeKind {
    fn name(self) -> &'static str {
        match self {
            EnvelopeKind::System => "SystemCiphertextV1",
            EnvelopeKind::Enclave => "EnclaveCiphertextV1",
            EnvelopeKind::Reader => "ReaderCiphertextV1",
        }
    }

    fn aad_matches(self, kind: AadKind) -> bool {
        match self {
            EnvelopeKind::System => {
                matches!(kind, AadKind::SystemInput | AadKind::SystemHandle)
            }
            EnvelopeKind::Enclave => matches!(kind, AadKind::Enclave),
            EnvelopeKind::Reader => matches!(kind, AadKind::Reader),
        }
    }
}

const ENVELOPE_ARRAY_LENGTH: usize = 4;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum EnvelopeDecodeError {
    #[error("malformed {envelope:?} envelope")]
    Malformed { envelope: EnvelopeKind },
    #[error("non-canonical encoding in {envelope:?} envelope")]
    NonCanonicalEncoding { envelope: EnvelopeKind },
    #[error("trailing bytes after {envelope:?} envelope")]
    TrailingBytes { envelope: EnvelopeKind },
    #[error("wrong {envelope:?} envelope length: expected {expected}, actual {actual}")]
    WrongLength {
        envelope: EnvelopeKind,
        expected: usize,
        actual: usize,
    },
    #[error("wrong field type in {envelope:?} for {field}: expected {expected}")]
    WrongFieldType {
        envelope: EnvelopeKind,
        field: &'static str,
        expected: &'static str,
    },
    #[error("version overflow in {envelope:?} envelope: {value}")]
    VersionOverflow { envelope: EnvelopeKind, value: u64 },
    #[error("AAD binding mismatch in {envelope:?} envelope: actual {actual:?}")]
    AadBindingMismatch {
        envelope: EnvelopeKind,
        actual: AadKind,
    },
    #[error("failed to decode AAD for {envelope:?} envelope: {error}")]
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
// CBOR prefix handling shared by every kind
// ---------------------------------------------------------------------------

struct Prefix {
    array_len: usize,
    version: u8,
    kind: AadKind,
}

fn decode_with_prefix<T>(
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
    let array_header = reader.read_header()?;
    if array_header.major != MAJOR_ARRAY {
        return Err(AadDecodeError::Malformed);
    }
    let array_len =
        usize::try_from(array_header.argument).map_err(|_| AadDecodeError::Malformed)?;
    let version_header = reader.read_header()?;
    if version_header.major != MAJOR_UINT {
        return Err(AadDecodeError::Malformed);
    }
    let version = u8::try_from(version_header.argument)
        .map_err(|_| AadDecodeError::VersionOverflow(version_header.argument))?;
    let kind_header = reader.read_header()?;
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
    let header = reader.read_header()?;
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
    let header = reader.read_header()?;
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
    let header = reader.read_header()?;
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
// Minimal CBOR primitives — only the subset the AAD spec needs.
// ---------------------------------------------------------------------------

const MAJOR_UINT: u8 = 0;
const MAJOR_BYTE_STRING: u8 = 2;
const MAJOR_TEXT_STRING: u8 = 3;
const MAJOR_ARRAY: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CborHeader {
    major: u8,
    argument: u64,
}

fn write_aad_prefix(out: &mut Vec<u8>, kind: AadKind, version: u8) {
    write_array_header(out, kind.array_length());
    write_unsigned_integer(out, version as u64);
    write_unsigned_integer(out, kind.discriminant());
}

fn encode_aad(kind: AadKind, version: u8, write_body: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::new();
    write_aad_prefix(&mut out, kind, version);
    write_body(&mut out);
    out
}

fn write_unsigned_integer(out: &mut Vec<u8>, value: u64) {
    write_cbor_header(out, MAJOR_UINT, value);
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

fn write_array_header(out: &mut Vec<u8>, len: usize) {
    write_cbor_header(out, MAJOR_ARRAY, len as u64);
}

fn write_byte_string(out: &mut Vec<u8>, bytes: &[u8]) {
    write_cbor_header(out, MAJOR_BYTE_STRING, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn write_text_string(out: &mut Vec<u8>, text: &str) {
    write_cbor_header(out, MAJOR_TEXT_STRING, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_byte(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos.checked_add(n)? > self.buf.len() {
            return None;
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(slice)
    }

    fn read_header(&mut self) -> Result<CborHeader, AadDecodeError> {
        let initial = self.read_byte().ok_or(AadDecodeError::Malformed)?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        let (arg, min_value) = match info {
            0..=23 => (info as u64, 0),
            24 => (
                self.read_byte().ok_or(AadDecodeError::Malformed)? as u64,
                24,
            ),
            25 => {
                let b = self.take(2).ok_or(AadDecodeError::Malformed)?;
                (u16::from_be_bytes([b[0], b[1]]) as u64, 1 << 8)
            }
            26 => {
                let b = self.take(4).ok_or(AadDecodeError::Malformed)?;
                (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, 1 << 16)
            }
            27 => {
                let b = self.take(8).ok_or(AadDecodeError::Malformed)?;
                (
                    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                    1 << 32,
                )
            }
            _ => return Err(AadDecodeError::Malformed),
        };
        if arg < min_value {
            return Err(AadDecodeError::NonCanonicalEncoding);
        }
        Ok(CborHeader {
            major,
            argument: arg,
        })
    }
}

// ---------------------------------------------------------------------------
// Ciphertext envelopes
//
// Each envelope is a canonical CBOR array of exactly four elements:
//
//   [ version: uint(u8), aad: bstr, wrapped_key: bstr, ciphertext: bstr ]
//
// `wrapped_key` and `ciphertext` are opaque bytes: the host never inspects
// them. `aad` is the canonical CBOR encoding of the matching AAD kind for the
// envelope, so the decoder can bind AAD bytes to the right envelope without
// re-deriving them. Per-envelope `decode` checks the embedded AAD kind matches.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemCiphertextV1 {
    pub version: u8,
    pub aad: Vec<u8>,
    pub wrapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
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
) -> Result<CborHeader, EnvelopeDecodeError> {
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

fn map_header_error(envelope: EnvelopeKind, err: AadDecodeError) -> EnvelopeDecodeError {
    match err {
        AadDecodeError::Malformed => EnvelopeDecodeError::Malformed { envelope },
        AadDecodeError::NonCanonicalEncoding => {
            EnvelopeDecodeError::NonCanonicalEncoding { envelope }
        }
        other => EnvelopeDecodeError::AadDecode {
            envelope,
            error: other,
        },
    }
}
