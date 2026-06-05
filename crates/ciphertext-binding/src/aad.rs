//! AAD value types, decode errors, and encode/decode logic for the four
//! spec-defined AAD kinds: SystemInput, SystemHandle, Enclave, and Reader.

use thiserror::Error;

use super::aad_body::{
    decode_enclave_body, decode_reader_body, decode_system_handle_body, decode_system_input_body,
};
use super::aad_codec::{decode_with_prefix, encode_aad};
use super::cbor::{write_byte_string, write_text_string, write_unsigned_integer};
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
