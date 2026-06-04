//! Privacy tests for the Display output of newly derived error types (issue #82).
//!
//! Asserts that formatting error variants that carry byte-array fields (DomainId,
//! KeyId, AttestationDigest, public-key bytes) does NOT include the raw byte
//! values — only category labels and field names reach the formatted string.

use coprocessor_ciphertext_binding::DomainId;
use coprocessor_handle_graph_core::ChainId;
use coprocessor_mpc_config::{
    HexDecodeError, JsonParseError, MpcConfigIncompatibility, MpcConfigLoadError,
    MpcConfigParseError, MpcSourceError,
};

// ---------------------------------------------------------------------------
// MpcConfigIncompatibility::DomainIdMismatch must not leak byte content
// ---------------------------------------------------------------------------

#[test]
fn domain_id_mismatch_display_contains_no_raw_bytes() {
    let err = MpcConfigIncompatibility::DomainIdMismatch {
        expected: DomainId([0xAA; 32]),
        actual: DomainId([0xBB; 32]),
    };
    let display = format!("{}", err);
    // Category label must be present, bytes must not be.
    assert!(
        !display.is_empty(),
        "DomainIdMismatch display must be non-empty"
    );
    assert!(
        !display.to_lowercase().contains("aa"),
        "DomainIdMismatch display must not contain raw 0xAA bytes: {display:?}"
    );
    assert!(
        !display.to_lowercase().contains("bb"),
        "DomainIdMismatch display must not contain raw 0xBB bytes: {display:?}"
    );
}

// ---------------------------------------------------------------------------
// MpcSourceError::Unavailable may include the detail string (non-secret)
// but must not include raw byte patterns from fixture seeds.
// ---------------------------------------------------------------------------

#[test]
fn mpc_source_unavailable_display_includes_detail_not_bytes() {
    let err = MpcSourceError::Unavailable {
        detail: "connection refused".to_string(),
    };
    let display = format!("{}", err);
    assert!(
        display.contains("connection refused"),
        "Unavailable display must include the detail string: {display:?}"
    );
    // Non-secret transport diagnostics are permitted; raw byte seeds are not.
    assert!(
        !display.to_lowercase().contains("0xaa"),
        "Unavailable display must not contain hex byte pattern: {display:?}"
    );
}

// ---------------------------------------------------------------------------
// MpcConfigParseError::InvalidPublicKey must not include raw hex content
// from the offending bytes — only the category label.
// ---------------------------------------------------------------------------

#[test]
fn invalid_public_key_display_is_category_label_only() {
    let hex_err = HexDecodeError::InvalidDigit {
        field: "public_key",
    };
    let err = MpcConfigParseError::InvalidPublicKey(hex_err);
    let display = format!("{}", err);
    assert!(
        !display.is_empty(),
        "InvalidPublicKey display must be non-empty"
    );
    // Must not include raw byte content — only field names and category labels.
    const FORBIDDEN: &[&str] = &["0xaa", "0xbb", "plaintext", "private_key", "wrapped_key"];
    for word in FORBIDDEN {
        assert!(
            !display.to_lowercase().contains(word),
            "InvalidPublicKey display must not contain '{word}': {display:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// MpcConfigLoadError variants must not surface secret material.
// ---------------------------------------------------------------------------

#[test]
fn load_error_display_variants_are_non_secret() {
    let cases: Vec<(&str, MpcConfigLoadError)> = vec![
        (
            "Malformed(Json)",
            MpcConfigLoadError::Malformed(MpcConfigParseError::Json(
                JsonParseError::MissingField { field: "suite" },
            )),
        ),
        (
            "Incompatible(DomainIdMismatch)",
            MpcConfigLoadError::Incompatible(MpcConfigIncompatibility::DomainIdMismatch {
                expected: DomainId([0xCC; 32]),
                actual: DomainId([0xDD; 32]),
            }),
        ),
        (
            "Unavailable",
            MpcConfigLoadError::Unavailable {
                detail: "timed out".to_string(),
            },
        ),
    ];

    const FORBIDDEN_BYTES: &[&str] = &["0xaa", "0xbb", "0xcc", "0xdd", "cccc", "dddd"];
    const FORBIDDEN_WORDS: &[&str] = &["plaintext", "private_key", "wrapped_key", "decrypted"];

    for (label, err) in cases {
        let display = format!("{}", err);
        assert!(
            !display.is_empty(),
            "{label} display must be non-empty, got empty string"
        );
        for word in FORBIDDEN_BYTES {
            assert!(
                !display.to_lowercase().contains(word),
                "{label} display must not contain byte pattern '{word}': {display:?}"
            );
        }
        for word in FORBIDDEN_WORDS {
            assert!(
                !display.to_lowercase().contains(word),
                "{label} display must not contain secret word '{word}': {display:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// MpcConfigIncompatibility variants with safe fields are still non-empty.
// ---------------------------------------------------------------------------

#[test]
fn chain_id_mismatch_display_is_non_empty_and_non_secret() {
    let err = MpcConfigIncompatibility::ChainIdMismatch {
        expected: ChainId(1),
        actual: ChainId(999),
    };
    let display = format!("{}", err);
    assert!(!display.is_empty(), "ChainIdMismatch display must be non-empty");
    // ChainId contains u64 — numbers are allowed; raw byte seeds are not.
    assert!(
        !display.to_lowercase().contains("0xaa"),
        "ChainIdMismatch display must not contain hex byte seeds: {display:?}"
    );
}
