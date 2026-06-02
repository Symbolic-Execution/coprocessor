//! Stable parse error coverage for the JSON transport surface. Every malformed
//! input class — bad hex, bad JSON shape, bad base64 — surfaces a specific
//! error variant that an API layer can map to a fixed error code. Tests in
//! this file exist to lock down the error shape, not to round-trip values.

use coprocessor_transport_json::{
    decode_chain_event_ref, decode_system_ciphertext, Base64DecodeError, CiphertextJsonError,
    HexDecodeError, HexIdentifier, JsonParseError, RequestIdHex,
};

#[test]
fn hex_missing_prefix_uses_field_name() {
    let err = RequestIdHex::from_hex(&"a".repeat(64)).unwrap_err();
    assert!(matches!(
        err,
        HexDecodeError::MissingPrefix {
            field: "request_id"
        }
    ));
}

#[test]
fn base64_with_padding_in_the_middle_is_rejected() {
    let err = decode_system_ciphertext("\"AB=DEFGH\"").unwrap_err();
    assert!(matches!(
        err,
        CiphertextJsonError::Base64(Base64DecodeError::InvalidPadding)
    ));
}

#[test]
fn base64_with_url_safe_alphabet_is_rejected_as_canonical_only() {
    // `-` and `_` are the URL-safe alphabet replacements for `+` and `/`.
    // Canonical base64 requires the standard alphabet, so URL-safe input
    // surfaces as `InvalidCharacter`.
    let err = decode_system_ciphertext("\"AB-DEF__\"").unwrap_err();
    assert!(matches!(
        err,
        CiphertextJsonError::Base64(Base64DecodeError::InvalidCharacter)
    ));
}

#[test]
fn base64_length_not_multiple_of_four_is_rejected() {
    let err = decode_system_ciphertext("\"AAA\"").unwrap_err();
    assert!(matches!(
        err,
        CiphertextJsonError::Base64(Base64DecodeError::InvalidLength)
    ));
}

#[test]
fn base64_with_non_zero_tail_bits_is_rejected() {
    // `AAAB` decodes to a 3-byte sequence ending in 0x01; padding it to 2-pad
    // forces unused tail bits to be non-zero.
    let err = decode_system_ciphertext("\"AB==\"").unwrap_err();
    assert!(matches!(
        err,
        CiphertextJsonError::Base64(Base64DecodeError::NonZeroTail)
    ));
}

#[test]
fn empty_string_envelope_is_rejected_as_envelope_error() {
    // Empty string is a valid JSON string and valid (empty) base64, so the
    // failure surfaces as an envelope decode error.
    let err = decode_system_ciphertext("\"\"").unwrap_err();
    assert!(matches!(err, CiphertextJsonError::Envelope(_)));
}

#[test]
fn chain_event_ref_with_unterminated_string_is_rejected() {
    let json = "{\"chain_id\":1,\"block_number\":1,\"block_hash\":\"unterminated";
    let err = decode_chain_event_ref(json).unwrap_err();
    assert!(matches!(err, JsonParseError::UnexpectedEndOfInput { .. }));
}

#[test]
fn chain_event_ref_with_unclosed_object_is_rejected() {
    let json = "{";
    let err = decode_chain_event_ref(json).unwrap_err();
    assert!(matches!(err, JsonParseError::UnexpectedEndOfInput { .. }));
}

#[test]
fn chain_event_ref_with_missing_colon_between_key_and_value_is_rejected() {
    let json = "{\"chain_id\" 1}";
    let err = decode_chain_event_ref(json).unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::UnexpectedToken { expected: "':'" }
    ));
}
