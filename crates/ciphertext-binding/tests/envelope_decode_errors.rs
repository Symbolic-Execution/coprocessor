//! Decoder error coverage for ciphertext envelopes: wrong array length, wrong
//! field type, malformed payloads, version overflow, trailing bytes, and AAD
//! binding mismatches must surface as non-secret domain errors that name only
//! the envelope kind and field - never the opaque payload bytes.

use coprocessor_ciphertext_binding::{
    AadKind, EnclaveCiphertextV1, EnvelopeDecodeError, EnvelopeKind, ReaderCiphertextV1,
    SystemCiphertextV1,
};

mod common;

use common::{
    sample_enclave_aad, sample_enclave_envelope, sample_reader_aad, sample_reader_envelope,
    sample_system_envelope, sample_system_handle_aad, DIRECT_ARRAY_HEADER,
};

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
    // CBOR uint(1) at top-level: major type 0, not 4.
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
            expected: 6,
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
fn key_id_field_must_be_byte_string() {
    let mut bytes = sample_system_envelope().encode();
    bytes[1] = 0x00;
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::WrongFieldType {
            envelope: EnvelopeKind::System,
            field: "key_id",
            expected: "byte string",
        }
    );
}

#[test]
fn key_id_wrong_length_is_rejected() {
    let mut bytes = sample_system_envelope().encode();
    bytes[1] = 0x41;
    bytes[2] = 0x99;
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::Malformed {
            envelope: EnvelopeKind::System,
        }
    );
}

#[test]
fn aad_field_must_be_byte_string() {
    let envelope = sample_system_envelope();
    let mut bytes = envelope.encode();
    let aad_offset = 1
        + cbor_bstr_header_len(32)
        + 32
        + cbor_bstr_header_len(envelope.enc.len())
        + envelope.enc.len()
        + cbor_bstr_header_len(envelope.wrapped_key.len())
        + envelope.wrapped_key.len()
        + cbor_bstr_header_len(envelope.nonce.len())
        + envelope.nonce.len()
        + cbor_bstr_header_len(envelope.ciphertext.len())
        + envelope.ciphertext.len();
    assert_eq!(
        bytes[aad_offset] >> 5,
        2,
        "AAD field should start as a byte string"
    );
    bytes[aad_offset] = 0x00;
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

fn cbor_bstr_header_len(len: usize) -> usize {
    if len <= 23 {
        1
    } else if u8::try_from(len).is_ok() {
        2
    } else if u16::try_from(len).is_ok() {
        3
    } else if u32::try_from(len).is_ok() {
        5
    } else {
        9
    }
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
    // 6-element array encoded with the 1-byte-extended form (0x98 0x06 ...) is
    // non-canonical since the shortest form is 0x86.
    let canonical = sample_system_envelope().encode();
    let mut bytes = Vec::with_capacity(canonical.len() + 1);
    bytes.push(0x98);
    bytes.push(0x06);
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
        key_id: common::sample_system_input_aad().key_id,
        enc: vec![0xAA; 32],
        wrapped_key: vec![0x00],
        nonce: [0x11; 12],
        ciphertext: vec![0x00],
        aad: sample_enclave_aad().encode(),
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
        key_id: common::sample_system_input_aad().key_id,
        enc: vec![0xBB; 32],
        wrapped_key: vec![0x00],
        nonce: [0x22; 12],
        ciphertext: vec![0x00],
        aad: sample_reader_aad().encode(),
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
        key_id: common::sample_system_input_aad().key_id,
        enc: vec![0xCC; 32],
        wrapped_key: vec![0x00],
        nonce: [0x33; 12],
        ciphertext: vec![0x00],
        aad: vec![0x01],
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
        key_id: common::sample_system_input_aad().key_id,
        enc: vec![0xDD; 32],
        wrapped_key: secret.clone(),
        nonce: [0x44; 12],
        ciphertext: secret.clone(),
        aad: sample_enclave_aad().encode(),
    };
    let bytes = envelope.encode();
    let err = SystemCiphertextV1::decode(&bytes).unwrap_err();
    let rendered = format!("{err:?}");
    let needle = std::str::from_utf8(&secret).unwrap();
    assert!(
        !rendered.contains(needle),
        "envelope error must not include payload bytes, got: {rendered}",
    );

    let display_rendered = format!("{err}");
    assert!(
        !display_rendered.contains(needle),
        "envelope error display must not include payload bytes, got: {display_rendered}",
    );
}
