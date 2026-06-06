//! Round-trip each spec-defined ciphertext envelope through the JSON transport.
//! Encoding emits a JSON string carrying base64-encoded canonical CBOR bytes;
//! decoding reconstructs the original envelope and validates it against the
//! same rules the binary codec enforces.

use coprocessor_ciphertext_binding::SystemCiphertextV1;
use coprocessor_wire_codec::{
    decode_enclave_ciphertext, decode_reader_ciphertext, decode_system_ciphertext,
    encode_enclave_ciphertext, encode_reader_ciphertext, encode_system_ciphertext,
    CiphertextJsonError,
};

mod common;

use common::{sample_enclave_envelope, sample_reader_envelope, sample_system_envelope};

#[test]
fn system_ciphertext_round_trips_through_json_preserving_every_field() {
    let envelope = sample_system_envelope();
    let json = encode_system_ciphertext(&envelope);
    let decoded = decode_system_ciphertext(&json).expect("decode");
    assert_eq!(decoded, envelope);
}

#[test]
fn enclave_ciphertext_round_trips_through_json_preserving_every_field() {
    let envelope = sample_enclave_envelope();
    let json = encode_enclave_ciphertext(&envelope);
    let decoded = decode_enclave_ciphertext(&json).expect("decode");
    assert_eq!(decoded, envelope);
}

#[test]
fn reader_ciphertext_round_trips_through_json_preserving_every_field() {
    let envelope = sample_reader_envelope();
    let json = encode_reader_ciphertext(&envelope);
    let decoded = decode_reader_ciphertext(&json).expect("decode");
    assert_eq!(decoded, envelope);
}

#[test]
fn encoded_envelope_is_a_quoted_base64_string() {
    let json = encode_system_ciphertext(&sample_system_envelope());
    assert!(json.starts_with('"'));
    assert!(json.ends_with('"'));
    let payload = &json[1..json.len() - 1];
    for byte in payload.bytes() {
        assert!(
            matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'='),
            "JSON envelope payload must be base64; saw byte 0x{byte:02x}",
        );
    }
}

#[test]
fn empty_payload_envelope_round_trips() {
    // Wrap an empty wrapped_key + empty ciphertext to cover the zero-byte case.
    let sample = sample_system_envelope();
    let envelope = SystemCiphertextV1 {
        key_id: sample.key_id,
        enc: Vec::new(),
        wrapped_key: Vec::new(),
        nonce: [0u8; 12],
        ciphertext: Vec::new(),
        aad: sample.aad,
    };
    let json = encode_system_ciphertext(&envelope);
    let decoded = decode_system_ciphertext(&json).expect("decode");
    assert_eq!(decoded, envelope);
}

#[test]
fn invalid_json_string_is_rejected_as_json_error() {
    let err = decode_system_ciphertext("not-a-json-string").unwrap_err();
    assert!(matches!(err, CiphertextJsonError::Json(_)));
}

#[test]
fn non_base64_string_is_rejected_as_base64_error() {
    let err = decode_system_ciphertext("\"$$$$\"").unwrap_err();
    assert!(matches!(err, CiphertextJsonError::Base64(_)));
}

#[test]
fn base64_payload_that_is_not_a_valid_envelope_is_rejected_as_envelope_error() {
    // "AAAA" is valid base64 for [0x00, 0x00, 0x00] - not a valid CBOR
    // envelope.
    let err = decode_system_ciphertext("\"AAAA\"").unwrap_err();
    assert!(matches!(err, CiphertextJsonError::Envelope(_)));
}

#[test]
fn system_envelope_payload_decoded_as_enclave_fails_with_envelope_error() {
    let json = encode_system_ciphertext(&sample_system_envelope());
    let err = decode_enclave_ciphertext(&json).unwrap_err();
    assert!(matches!(err, CiphertextJsonError::Envelope(_)));
}

#[test]
fn enclave_envelope_payload_decoded_as_reader_fails_with_envelope_error() {
    let json = encode_enclave_ciphertext(&sample_enclave_envelope());
    let err = decode_reader_ciphertext(&json).unwrap_err();
    assert!(matches!(err, CiphertextJsonError::Envelope(_)));
}

#[test]
fn whitespace_around_envelope_json_value_is_accepted() {
    let envelope = sample_system_envelope();
    let raw = encode_system_ciphertext(&envelope);
    let padded = format!("   \n  {raw}\n  ");
    let decoded = decode_system_ciphertext(&padded).expect("decode");
    assert_eq!(decoded, envelope);
}

#[test]
fn trailing_content_after_envelope_string_is_rejected() {
    let envelope = sample_system_envelope();
    let json = format!("{} junk", encode_system_ciphertext(&envelope));
    let err = decode_system_ciphertext(&json).unwrap_err();
    assert!(matches!(err, CiphertextJsonError::Json(_)));
}
