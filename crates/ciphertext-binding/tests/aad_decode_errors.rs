//! Decoder error coverage: wrong kind, wrong length, wrong field type, and
//! malformed payloads must surface as non-secret domain errors for every AAD
//! kind.

use coprocessor_ciphertext_binding::{
    AadDecodeError, AadKind, AttestationDigest, CiphertextBindingAad, ContractAddress, DomainId,
    EnclaveAadV1, HandleId, KeyId, ReaderAadV1, ReaderId, RequestId, SystemHandleAadV1,
    SystemInputAadV1,
};

fn fill(byte: u8) -> [u8; 32] {
    [byte; 32]
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
    // SystemInput should be 7. Truncate to 6 by stripping the final key_id
    // and shortening the array header from 0x87 to 0x86.
    let mut bytes = sample_system_input().encode();
    // The last field is a 32-byte byte string preceded by `0x58 32`. Drop 34 bytes.
    let new_len = bytes.len() - 34;
    bytes.truncate(new_len);
    bytes[0] = 0x80 | 6;
    let err = SystemInputAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongLength {
            kind: AadKind::SystemInput,
            expected: 7,
            actual: 6,
        }
    );

    // Enclave should be 9. Extend to 10 by appending an extra uint(0) and
    // bumping the array header from 0x89 to 0x8a.
    let mut bytes = sample_enclave().encode();
    bytes[0] = 0x80 | 10;
    bytes.push(0x00);
    let err = EnclaveAadV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        AadDecodeError::WrongLength {
            kind: AadKind::Enclave,
            expected: 9,
            actual: 10,
        }
    );
}

#[test]
fn wrong_field_type_surfaces_wrong_field_type_error() {
    // SystemInputAadV1 layout:
    // [arr(7), version(uint), kind(uint), chain_id(uint), domain_id(bstr32),
    //  contract(bstr20), type_tag(tstr), key_id(bstr32)]
    // Corrupt chain_id by replacing the small-uint byte 0x01 with a text-string
    // header for "" (0x60). The kind byte still says SystemInput, so the field
    // typing error surfaces as WrongFieldType for `chain_id`.
    let mut bytes = sample_system_input().encode();
    // bytes[0]=arr header, bytes[1]=version uint, bytes[2]=kind uint,
    // bytes[3]=chain_id uint. Overwrite that single chain_id byte (sample uses
    // chain_id=1, which encodes as 0x01) with 0x60 (text string of length 0).
    assert_eq!(
        bytes[3], 0x01,
        "test setup expects chain_id encoded as 0x01"
    );
    bytes[3] = 0x60;
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
    // Replace the 32-byte domain_id with a 31-byte byte string.
    // SystemHandle layout puts domain_id right after chain_id (uint 0x01).
    let mut bytes = sample_system_handle().encode();
    // domain_id starts at offset 4 (arr, version, kind, chain_id each 1 byte).
    // Original head: 0x58, 32, then 32 bytes. Replace length byte 32 with 31
    // and drop one byte from the tail of the 32-byte payload.
    assert_eq!(bytes[4], 0x58);
    assert_eq!(bytes[5], 32);
    bytes[5] = 31;
    bytes.remove(6 + 31);
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
    // SystemHandle layout: arr, version, kind, chain_id, domain_id(34 bytes),
    // handle_id(34 bytes), type_tag(tstr), key_id(34 bytes).
    let mut bytes = sample_system_handle().encode();
    // Locate the type_tag head. After arr+ver+kind+chain (4 bytes), domain_id
    // takes 2+32=34 bytes, handle_id takes 34 bytes. So type_tag head is at
    // offset 4+34+34 = 72.
    let type_tag_head_offset = 1 + 1 + 1 + 1 + 34 + 34;
    // Original sample uses "sbool" (5 bytes). Text string head for length 5 is
    // 0x65 (major 3 | 5). Replace the 5-byte payload with invalid UTF-8.
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
    // Shortest form for version=1 is the immediate byte 0x01.
    // Encoding it as a 1-byte extension (0x18 0x01) is a valid CBOR uint but
    // not deterministic per RFC 8949 §4.2.1. A canonical codec must reject it.
    // Take the SystemInput sample and rewrite the version byte 0x01 (offset 1)
    // as 0x18 0x01, shifting the rest of the payload down by one byte.
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
    // 32-byte payloads use 1-byte length extension (0x58, 32). Re-encoding
    // the length as a 2-byte extension (0x59, 0x00, 0x20) inflates the header
    // without changing semantics, so the canonical decoder must reject it.
    let original = sample_system_handle().encode();
    // domain_id starts at offset 4: 0x58, 32, then 32 payload bytes.
    assert_eq!(original[4], 0x58);
    assert_eq!(original[5], 32);
    let mut bytes = Vec::with_capacity(original.len() + 1);
    bytes.extend_from_slice(&original[..4]);
    bytes.extend_from_slice(&[0x59, 0x00, 0x20]);
    bytes.extend_from_slice(&original[6..]);
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
