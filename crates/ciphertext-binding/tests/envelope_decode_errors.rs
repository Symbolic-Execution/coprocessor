//! Decoder error coverage for ciphertext envelopes: wrong array length, wrong
//! field type, malformed payloads, version overflow, trailing bytes, and AAD
//! binding mismatches must surface as non-secret domain errors that name only
//! the envelope kind and field — never the opaque payload bytes.

use coprocessor_ciphertext_binding::{
    AadKind, AttestationDigest, ContractAddress, DomainId, EnclaveAadV1, EnclaveCiphertextV1,
    EnvelopeDecodeError, EnvelopeKind, HandleId, KeyId, ReaderAadV1, ReaderCiphertextV1, ReaderId,
    RequestId, SystemCiphertextV1, SystemHandleAadV1, SystemInputAadV1,
};

const DIRECT_ARRAY_HEADER: u8 = 0x80;

fn fill(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn sample_system_input_aad() -> SystemInputAadV1 {
    SystemInputAadV1 {
        version: 1,
        chain_id: 1,
        domain_id: DomainId(fill(0xA1)),
        contract: ContractAddress([0xC2; 20]),
        type_tag: "suint256".to_string(),
        key_id: KeyId(fill(0x10)),
    }
}

fn sample_system_handle_aad() -> SystemHandleAadV1 {
    SystemHandleAadV1 {
        version: 1,
        chain_id: 1,
        domain_id: DomainId(fill(0xA1)),
        handle_id: HandleId(fill(0xB3)),
        type_tag: "sbool".to_string(),
        key_id: KeyId(fill(0x10)),
    }
}

fn sample_enclave_aad() -> EnclaveAadV1 {
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

fn sample_reader_aad() -> ReaderAadV1 {
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

fn sample_system_envelope() -> SystemCiphertextV1 {
    SystemCiphertextV1 {
        version: 1,
        aad: sample_system_input_aad().encode(),
        wrapped_key: vec![0x01, 0x02, 0x03],
        ciphertext: vec![0xAA, 0xBB, 0xCC],
    }
}

fn sample_enclave_envelope() -> EnclaveCiphertextV1 {
    EnclaveCiphertextV1 {
        version: 1,
        aad: sample_enclave_aad().encode(),
        wrapped_key: vec![0x01, 0x02, 0x03],
        ciphertext: vec![0xAA, 0xBB, 0xCC],
    }
}

fn sample_reader_envelope() -> ReaderCiphertextV1 {
    ReaderCiphertextV1 {
        version: 1,
        aad: sample_reader_aad().encode(),
        wrapped_key: vec![0x01, 0x02, 0x03],
        ciphertext: vec![0xAA, 0xBB, 0xCC],
    }
}

#[test]
fn empty_input_is_rejected_as_malformed_for_each_envelope() {
    assert_eq!(
        SystemCiphertextV1::decode(&[]).unwrap_err(),
        EnvelopeDecodeError::Malformed {
            envelope: EnvelopeKind::System,
        },
    );
    assert_eq!(
        EnclaveCiphertextV1::decode(&[]).unwrap_err(),
        EnvelopeDecodeError::Malformed {
            envelope: EnvelopeKind::Enclave,
        },
    );
    assert_eq!(
        ReaderCiphertextV1::decode(&[]).unwrap_err(),
        EnvelopeDecodeError::Malformed {
            envelope: EnvelopeKind::Reader,
        },
    );
}

#[test]
fn non_array_top_level_is_rejected() {
    // CBOR uint(1) at top-level — major type 0, not 4.
    let bytes = vec![0x01];
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::WrongFieldType {
            envelope: EnvelopeKind::System,
            field: "SystemCiphertextV1",
            expected: "array",
        }
    );
}

#[test]
fn wrong_array_length_surfaces_wrong_length_error_for_each_envelope() {
    let mut bytes = sample_system_envelope().encode();
    bytes[0] = DIRECT_ARRAY_HEADER | 3;
    bytes.truncate(bytes.len() - sample_system_envelope().ciphertext.len() - 1);
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::WrongLength {
            envelope: EnvelopeKind::System,
            expected: 4,
            actual: 3,
        }
    );

    let mut bytes = sample_enclave_envelope().encode();
    bytes[0] = DIRECT_ARRAY_HEADER | 5;
    bytes.push(0x00);
    let err = EnclaveCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::WrongLength {
            envelope: EnvelopeKind::Enclave,
            expected: 4,
            actual: 5,
        }
    );

    let mut bytes = sample_reader_envelope().encode();
    bytes[0] = DIRECT_ARRAY_HEADER | 5;
    bytes.push(0x00);
    let err = ReaderCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::WrongLength {
            envelope: EnvelopeKind::Reader,
            expected: 4,
            actual: 5,
        }
    );
}

#[test]
fn version_field_must_be_unsigned_integer() {
    let mut bytes = sample_system_envelope().encode();
    // Position 1 is the version uint; replace 0x01 with 0x60 (empty text string).
    assert_eq!(bytes[1], 0x01);
    bytes[1] = 0x60;
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::WrongFieldType {
            envelope: EnvelopeKind::System,
            field: "version",
            expected: "unsigned integer",
        }
    );
}

#[test]
fn version_overflow_when_value_exceeds_u8_is_rejected() {
    // Hand-build a System envelope with version = 256 (overflows u8).
    // [arr(4), uint(256), bstr(empty), bstr(empty), bstr(empty)]
    let bytes = vec![
        DIRECT_ARRAY_HEADER | 4,
        0x19,
        0x01,
        0x00,
        0x40,
        0x40,
        0x40,
    ];
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::VersionOverflow {
            envelope: EnvelopeKind::System,
            value: 256,
        }
    );
}

#[test]
fn aad_field_must_be_byte_string() {
    let mut bytes = sample_system_envelope().encode();
    // Position 2 is the AAD header; rewrite to a uint header to break the type.
    assert_eq!(bytes[2] >> 5, 2, "AAD field should start as a byte string");
    bytes[2] = 0x00;
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::WrongFieldType {
            envelope: EnvelopeKind::System,
            field: "aad",
            expected: "byte string",
        }
    );
}

#[test]
fn truncated_byte_string_payload_surfaces_malformed_error() {
    let bytes = sample_enclave_envelope().encode();
    let truncated = &bytes[..bytes.len() - 1];
    let err = EnclaveCiphertextV1::decode(truncated).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::Malformed {
            envelope: EnvelopeKind::Enclave,
        }
    );
}

#[test]
fn trailing_bytes_after_envelope_array_are_rejected() {
    let mut bytes = sample_reader_envelope().encode();
    bytes.push(0x00);
    let err = ReaderCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::TrailingBytes {
            envelope: EnvelopeKind::Reader,
        }
    );
}

#[test]
fn non_canonical_array_length_is_rejected() {
    // 4-element array encoded with the 1-byte-extended form (0x98 0x04 ...) is
    // non-canonical since the shortest form is 0x84.
    let canonical = sample_system_envelope().encode();
    let mut bytes = Vec::with_capacity(canonical.len() + 1);
    bytes.push(0x98);
    bytes.push(0x04);
    bytes.extend_from_slice(&canonical[1..]);
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::NonCanonicalEncoding {
            envelope: EnvelopeKind::System,
        }
    );
}

#[test]
fn system_envelope_rejects_enclave_aad() {
    let envelope = SystemCiphertextV1 {
        version: 1,
        aad: sample_enclave_aad().encode(),
        wrapped_key: vec![0x00],
        ciphertext: vec![0x00],
    };
    let bytes = envelope.encode();
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::AadBindingMismatch {
            envelope: EnvelopeKind::System,
            actual: AadKind::Enclave,
        }
    );
}

#[test]
fn system_envelope_rejects_reader_aad() {
    let envelope = SystemCiphertextV1 {
        version: 1,
        aad: sample_reader_aad().encode(),
        wrapped_key: vec![0x00],
        ciphertext: vec![0x00],
    };
    let bytes = envelope.encode();
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::AadBindingMismatch {
            envelope: EnvelopeKind::System,
            actual: AadKind::Reader,
        }
    );
}

#[test]
fn enclave_envelope_rejects_system_handle_aad() {
    let envelope = EnclaveCiphertextV1 {
        version: 1,
        aad: sample_system_handle_aad().encode(),
        wrapped_key: vec![0x00],
        ciphertext: vec![0x00],
    };
    let bytes = envelope.encode();
    let err = EnclaveCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::AadBindingMismatch {
            envelope: EnvelopeKind::Enclave,
            actual: AadKind::SystemHandle,
        }
    );
}

#[test]
fn reader_envelope_rejects_enclave_aad() {
    let envelope = ReaderCiphertextV1 {
        version: 1,
        aad: sample_enclave_aad().encode(),
        wrapped_key: vec![0x00],
        ciphertext: vec![0x00],
    };
    let bytes = envelope.encode();
    let err = ReaderCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::AadBindingMismatch {
            envelope: EnvelopeKind::Reader,
            actual: AadKind::Enclave,
        }
    );
}

#[test]
fn malformed_aad_bytes_surface_aad_decode_error() {
    // AAD bytes that don't parse as any AAD kind: a non-array CBOR value.
    let envelope = SystemCiphertextV1 {
        version: 1,
        aad: vec![0x01],
        wrapped_key: vec![0x00],
        ciphertext: vec![0x00],
    };
    let bytes = envelope.encode();
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    match err {
        EnvelopeDecodeError::AadDecode {
            envelope: env,
            error: _,
        } => {
            assert_eq!(env, EnvelopeKind::System);
        }
        other => panic!("expected AadDecode error, got {other:?}"),
    }
}

#[test]
fn envelope_error_strings_do_not_contain_payload_bytes() {
    // Adversarial check: the formatted error for a malformed envelope must not
    // surface the opaque payload bytes the envelope was trying to carry.
    let secret = b"PLAINTEXT_LOOKING_PAYLOAD_DO_NOT_LEAK".to_vec();
    let envelope = SystemCiphertextV1 {
        version: 1,
        aad: sample_enclave_aad().encode(),
        wrapped_key: secret.clone(),
        ciphertext: secret.clone(),
    };
    let bytes = envelope.encode();
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    let rendered = format!("{err:?}");
    let needle = std::str::from_utf8(&secret).unwrap();
    assert!(
        !rendered.contains(needle),
        "envelope error must not include payload bytes, got: {rendered}",
    );
}
