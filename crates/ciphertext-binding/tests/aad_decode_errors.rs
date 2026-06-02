//! Decoder error coverage: wrong kind, wrong length, wrong field type, and
//! malformed payloads must surface as non-secret domain errors for every AAD
//! kind.

use coprocessor_ciphertext_binding::{
    AadDecodeError, AadKind, AttestationDigest, CiphertextBindingAad, ContractAddress, DomainId,
    EnclaveAadV1, HandleId, KeyId, ReaderAadV1, ReaderId, RequestId, SystemHandleAadV1,
    SystemInputAadV1,
};

const DIRECT_ARRAY_HEADER: u8 = 0x80;
const BYTE_STRING_32_HEADER_LEN: usize = 2;
const BYTE_STRING_32_FIELD_LEN: usize = BYTE_STRING_32_HEADER_LEN + 32;
const PREFIX_LEN: usize = 4;

fn fill(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn set_short_array_len(bytes: &mut [u8], len: u8) {
    bytes[0] = DIRECT_ARRAY_HEADER | len;
}

fn remove_final_bytes32_field(bytes: &mut Vec<u8>) {
    bytes.truncate(bytes.len() - BYTE_STRING_32_FIELD_LEN);
}

fn append_extra_uint_zero(bytes: &mut Vec<u8>) {
    set_short_array_len(bytes, 10);
    bytes.push(0x00);
}

fn sample_system_input() -> SystemInputAadV1 {
    SystemInputAadV1 {
        version: 1,
        chain_id: 1,
        domain_id: DomainId(fill(0xA1)),
        contract: ContractAddress([0xC2; 20]),
        type_tag: "suint256".to_string(),
        key_id: KeyId(fill(0x10)),
    }
}

fn sample_system_handle() -> SystemHandleAadV1 {
    SystemHandleAadV1 {
        version: 1,
        chain_id: 1,
        domain_id: DomainId(fill(0xA1)),
        handle_id: HandleId(fill(0xB3)),
        type_tag: "sbool".to_string(),
        key_id: KeyId(fill(0x10)),
    }
}

fn sample_enclave() -> EnclaveAadV1 {
    EnclaveAadV1 {
        version: 1,
        chain_id: 1,
        domain_id: DomainId(fill(0xA1)),
        request_id: RequestId(fill(0x70)),
        handle_id: HandleId(fill(0xB3)),
        type_tag: "suint256".to_string(),
        attestation_digest: AttestationDigest(fill(0xEE)),
        key_id: KeyId(fill(0x10)),
    }
}

fn sample_reader() -> ReaderAadV1 {
    ReaderAadV1 {
        version: 1,
        chain_id: 1,
        domain_id: DomainId(fill(0xA1)),
        request_id: RequestId(fill(0x70)),
        handle_id: HandleId(fill(0xB3)),
        reader_id: ReaderId(fill(0x40)),
        type_tag: "sbool".to_string(),
        key_id: KeyId(fill(0x10)),
    }
}

#[test]
fn system_input_decoder_rejects_other_kinds() {
    let bytes = sample_system_handle().encode();
    let err = SystemInputAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongKind {
            expected: AadKind::SystemInput,
            actual: AadKind::SystemHandle
        }
    );
}

#[test]
fn system_handle_decoder_rejects_other_kinds() {
    let bytes = sample_system_input().encode();
    let err = SystemHandleAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongKind {
            expected: AadKind::SystemHandle,
            actual: AadKind::SystemInput
        }
    );
}

#[test]
fn enclave_decoder_rejects_other_kinds() {
    let bytes = sample_reader().encode();
    let err = EnclaveAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongKind {
            expected: AadKind::Enclave,
            actual: AadKind::Reader
        }
    );
}

#[test]
fn reader_decoder_rejects_other_kinds() {
    let bytes = sample_enclave().encode();
    let err = ReaderAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongKind {
            expected: AadKind::Reader,
            actual: AadKind::Enclave
        }
    );
}

#[test]
fn unknown_kind_discriminant_surfaces_unknown_kind_error() {
    // Hand-build an array with kind=42 (not a valid AadKind).
    // [array(7), uint(1), uint(42), uint(1), bytes32, bytes20, text("x"), bytes32]
    let mut bytes = vec![0x87, 0x01, 0x18, 42, 0x01];
    bytes.push(0x58);
    bytes.push(32);
    bytes.extend_from_slice(&[0; 32]);
    bytes.push(0x54);
    bytes.extend_from_slice(&[0; 20]);
    bytes.push(0x61);
    bytes.push(b'x');
    bytes.push(0x58);
    bytes.push(32);
    bytes.extend_from_slice(&[0; 32]);
    let err = CiphertextBindingAad::decode(&bytes).unwrap_err();
    assert_eq!(err, AadDecodeError::UnknownKind(42));
}

#[test]
fn wrong_array_length_surfaces_wrong_length_error_for_each_kind() {
    let mut bytes = sample_system_input().encode();
    remove_final_bytes32_field(&mut bytes);
    set_short_array_len(&mut bytes, 6);
    let err = SystemInputAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongLength {
            kind: AadKind::SystemInput,
            expected: 7,
            actual: 6,
        }
    );

    let mut bytes = sample_system_handle().encode();
    remove_final_bytes32_field(&mut bytes);
    set_short_array_len(&mut bytes, 6);
    let err = SystemHandleAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongLength {
            kind: AadKind::SystemHandle,
            expected: 7,
            actual: 6,
        }
    );

    let mut bytes = sample_enclave().encode();
    append_extra_uint_zero(&mut bytes);
    let err = EnclaveAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongLength {
            kind: AadKind::Enclave,
            expected: 9,
            actual: 10,
        }
    );

    let mut bytes = sample_reader().encode();
    append_extra_uint_zero(&mut bytes);
    let err = ReaderAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongLength {
            kind: AadKind::Reader,
            expected: 9,
            actual: 10,
        }
    );
}

#[test]
fn wrong_field_type_surfaces_wrong_field_type_error() {
    let mut bytes = sample_system_input().encode();
    let chain_id_offset = PREFIX_LEN - 1;
    assert_eq!(
        bytes[chain_id_offset], 0x01,
        "test setup expects chain_id encoded as 0x01"
    );
    bytes[chain_id_offset] = 0x60;
    let err = SystemInputAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongFieldType {
            kind: AadKind::SystemInput,
            field: "chain_id",
            expected: "unsigned integer",
        }
    );
}

#[test]
fn wrong_byte_string_length_surfaces_specific_error() {
    let mut bytes = sample_system_handle().encode();
    let domain_id_header_offset = PREFIX_LEN;
    let domain_id_len_offset = domain_id_header_offset + 1;
    let removed_payload_byte_offset = domain_id_len_offset + 1 + 31;
    assert_eq!(bytes[domain_id_header_offset], 0x58);
    assert_eq!(bytes[domain_id_len_offset], 32);
    bytes[domain_id_len_offset] = 31;
    bytes.remove(removed_payload_byte_offset);
    let err = SystemHandleAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongByteStringLength {
            kind: AadKind::SystemHandle,
            field: "domain_id",
            expected: 32,
            actual: 31,
        }
    );
}

#[test]
fn truncated_payload_surfaces_malformed_error() {
    let bytes = sample_enclave().encode();
    let truncated = &bytes[..bytes.len() - 5];
    let err = EnclaveAadV1::decode(truncated).unwrap_err();
    assert_eq!(err, AadDecodeError::Malformed);
}

#[test]
fn empty_input_surfaces_malformed_error() {
    let err = CiphertextBindingAad::decode(&[]).unwrap_err();
    assert_eq!(err, AadDecodeError::Malformed);
}

#[test]
fn trailing_bytes_after_array_are_rejected() {
    let mut bytes = sample_reader().encode();
    bytes.push(0x00);
    let err = ReaderAadV1::decode(&bytes).unwrap_err();
    assert_eq!(err, AadDecodeError::TrailingBytes);
}

#[test]
fn non_array_top_level_is_rejected_as_malformed() {
    // Hand-encode an unsigned integer (major type 0) at the top level.
    let bytes = vec![0x01];
    let err = CiphertextBindingAad::decode(&bytes).unwrap_err();
    assert_eq!(err, AadDecodeError::Malformed);
}

#[test]
fn invalid_utf8_in_type_tag_surfaces_invalid_utf8_error() {
    let mut bytes = sample_system_handle().encode();
    let type_tag_head_offset = PREFIX_LEN + BYTE_STRING_32_FIELD_LEN + BYTE_STRING_32_FIELD_LEN;
    assert_eq!(bytes[type_tag_head_offset], 0x65);
    let payload_start = type_tag_head_offset + 1;
    bytes[payload_start..payload_start + 5].copy_from_slice(&[0xff, 0xfe, 0xfd, 0xfc, 0xfb]);
    let err = SystemHandleAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::InvalidUtf8 {
            kind: AadKind::SystemHandle,
            field: "type_tag",
        }
    );
}

#[test]
fn non_canonical_uint_encoding_is_rejected() {
    let original = sample_system_input().encode();
    let mut bytes = Vec::with_capacity(original.len() + 1);
    bytes.push(original[0]);
    bytes.extend_from_slice(&[0x18, 0x01]);
    bytes.extend_from_slice(&original[2..]);
    let err = SystemInputAadV1::decode(&bytes).unwrap_err();
    assert_eq!(err, AadDecodeError::NonCanonicalEncoding);
}

#[test]
fn non_canonical_byte_string_length_is_rejected() {
    let original = sample_system_handle().encode();
    let domain_id_header_offset = PREFIX_LEN;
    let domain_id_len_offset = domain_id_header_offset + 1;
    assert_eq!(original[domain_id_header_offset], 0x58);
    assert_eq!(original[domain_id_len_offset], 32);
    let mut bytes = Vec::with_capacity(original.len() + 1);
    bytes.extend_from_slice(&original[..domain_id_header_offset]);
    bytes.extend_from_slice(&[0x59, 0x00, 0x20]);
    bytes.extend_from_slice(&original[domain_id_len_offset + 1..]);
    let err = SystemHandleAadV1::decode(&bytes).unwrap_err();
    assert_eq!(err, AadDecodeError::NonCanonicalEncoding);
}

#[test]
fn version_overflow_when_value_exceeds_u8_is_rejected() {
    // Hand-build a SystemInput shape with version = 256 (overflows u8).
    // [arr(7), uint(256), uint(1), uint(1), bstr32, bstr20, tstr0, bstr32]
    let mut bytes = vec![0x87, 0x19, 0x01, 0x00, 0x01, 0x01];
    bytes.push(0x58);
    bytes.push(32);
    bytes.extend_from_slice(&[0; 32]);
    bytes.push(0x54);
    bytes.extend_from_slice(&[0; 20]);
    bytes.push(0x60);
    bytes.push(0x58);
    bytes.push(32);
    bytes.extend_from_slice(&[0; 32]);
    let err = CiphertextBindingAad::decode(&bytes).unwrap_err();
    assert_eq!(err, AadDecodeError::VersionOverflow(256));
}
