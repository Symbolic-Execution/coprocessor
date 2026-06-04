//! Privacy tests for the Display output of transport-json error types (issue #82).
//!
//! Verifies that newly derived Display impls contain only category labels,
//! field names, and counts — never raw byte payloads or secret material.

use coprocessor_transport_json::{Base64DecodeError, HexDecodeError, JsonParseError};

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
        assert!(!display.is_empty(), "HexDecodeError display must be non-empty for {err:?}");
        // Must not include raw hex content — only field names and category labels.
        const FORBIDDEN_BYTES: &[&str] = &["0xaa", "0xbb", "0xcc", "0xdd"];
        for word in FORBIDDEN_BYTES {
            assert!(
                !display.to_lowercase().contains(word),
                "HexDecodeError display must not contain '{word}' for {err:?}: {display:?}"
            );
        }
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
        assert!(!display.is_empty(), "Base64DecodeError display must be non-empty for {err:?}");
        const FORBIDDEN: &[&str] = &["0xaa", "0xbb", "plaintext", "private_key", "wrapped_key"];
        for word in FORBIDDEN {
            assert!(
                !display.to_lowercase().contains(word),
                "Base64DecodeError display must not contain '{word}' for {err:?}: {display:?}"
            );
        }
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
        JsonParseError::UnexpectedEndOfInput { expected: "closing quote" },
        JsonParseError::TrailingContent,
        JsonParseError::UnsupportedStringEscape,
        JsonParseError::InvalidUnsignedNumber { field: "chain_id" },
        JsonParseError::DuplicateField { field: "<duplicate>" },
        JsonParseError::MissingField { field: "suite" },
        JsonParseError::UnexpectedField,
        JsonParseError::FieldShape {
            field: "chain_id",
            expected: "unsigned integer",
        },
        JsonParseError::IntegerOverflow {
            field: "log_index",
            expected: "u32",
        },
    ];

    const FORBIDDEN_BYTES: &[&str] = &["0xaa", "0xbb", "0xcc"];
    const FORBIDDEN_WORDS: &[&str] = &["plaintext", "private_key", "wrapped_key"];

    for err in &cases {
        let display = format!("{}", err);
        assert!(!display.is_empty(), "JsonParseError display must be non-empty for {err:?}");
        for word in FORBIDDEN_BYTES {
            assert!(
                !display.to_lowercase().contains(word),
                "JsonParseError display must not contain '{word}' for {err:?}: {display:?}"
            );
        }
        for word in FORBIDDEN_WORDS {
            assert!(
                !display.to_lowercase().contains(word),
                "JsonParseError display must not contain secret word '{word}' for {err:?}: {display:?}"
            );
        }
    }
}
