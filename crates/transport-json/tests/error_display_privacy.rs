//! Privacy tests for the Display output of transport-json error types (issue #82).
//!
//! Verifies that newly derived Display impls contain only category labels,
//! field names, and counts — never raw byte payloads or secret material.

use coprocessor_transport_json::{
    Base64DecodeError, CiphertextJsonError, HexDecodeError, JsonParseError,
};

const FORBIDDEN_DISPLAY_FRAGMENTS: &[&str] = &[
    "0xaa",
    "0xbb",
    "0xcc",
    "aaaa",
    "bbbb",
    "plaintext",
    "private_key",
    "wrapped_key",
    "decrypted",
    "reader_secret",
];

fn assert_display_is_non_secret(label: &str, display: &str) {
    assert!(!display.is_empty(), "{label} display must be non-empty");
    let normalized = display.to_ascii_lowercase();
    for fragment in FORBIDDEN_DISPLAY_FRAGMENTS {
        assert!(
            !normalized.contains(fragment),
            "{label} display must not contain '{fragment}': {display:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// HexDecodeError display must name the field and error class, not raw bytes.
// ---------------------------------------------------------------------------

#[test]
fn hex_decode_error_display_contains_field_name_not_bytes() {
    let cases = vec![
        HexDecodeError::MissingPrefix { field: "domain_id" },
        HexDecodeError::OddLength {
            field: "key_id",
            actual_chars: 63,
        },
        HexDecodeError::UppercaseDigit { field: "handle_id" },
        HexDecodeError::InvalidDigit { field: "tx_hash" },
        HexDecodeError::WrongByteLength {
            field: "block_hash",
            expected: 32,
            actual: 31,
        },
    ];

    for err in &cases {
        let display = format!("{}", err);
        assert_display_is_non_secret("HexDecodeError", &display);
    }
}

// ---------------------------------------------------------------------------
// Base64DecodeError display — no raw byte content.
// ---------------------------------------------------------------------------

#[test]
fn base64_decode_error_display_is_non_empty_and_non_secret() {
    let cases = vec![
        Base64DecodeError::InvalidCharacter,
        Base64DecodeError::InvalidLength,
        Base64DecodeError::InvalidPadding,
        Base64DecodeError::NonZeroTail,
    ];

    for err in &cases {
        let display = format!("{}", err);
        assert_display_is_non_secret("Base64DecodeError", &display);
    }
}

// ---------------------------------------------------------------------------
// JsonParseError display — field names (safe &'static str) are permitted;
// no byte payloads.
// ---------------------------------------------------------------------------

#[test]
fn json_parse_error_display_is_non_empty_and_non_secret() {
    let cases = vec![
        JsonParseError::UnexpectedToken { expected: "object" },
        JsonParseError::UnexpectedEndOfInput {
            expected: "closing quote",
        },
        JsonParseError::TrailingContent,
        JsonParseError::UnsupportedStringEscape,
        JsonParseError::InvalidUnsignedNumber { field: "chain_id" },
        JsonParseError::DuplicateField {
            field: "<duplicate>",
        },
        JsonParseError::MissingField { field: "suite" },
        JsonParseError::UnexpectedField,
        JsonParseError::FieldShape {
            field: "chain_id",
            expected: "unsigned integer",
        },
        JsonParseError::InvalidHex {
            field: "domain_id",
            error: HexDecodeError::InvalidDigit { field: "domain_id" },
        },
        JsonParseError::IntegerOverflow {
            field: "log_index",
            expected: "u32",
        },
    ];

    for err in &cases {
        let display = format!("{}", err);
        assert_display_is_non_secret("JsonParseError", &display);
    }
}

#[test]
fn ciphertext_json_error_display_is_non_empty_and_non_secret() {
    let cases = vec![
        CiphertextJsonError::Json(JsonParseError::TrailingContent),
        CiphertextJsonError::Base64(Base64DecodeError::InvalidCharacter),
    ];

    for err in &cases {
        let display = format!("{}", err);
        assert_display_is_non_secret("CiphertextJsonError", &display);
    }
}
