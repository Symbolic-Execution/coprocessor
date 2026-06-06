//! Privacy tests for the Display output of newly derived error types (issue #82).
//!
//! Asserts that formatting error variants that carry byte-array fields (DomainId,
//! KeyId, AttestationDigest, public-key bytes) does NOT include the raw byte
//! values — only category labels and field names reach the formatted string.

use coprocessor_ciphertext_binding::DomainId;
use coprocessor_handle_graph_core::ChainId;
use coprocessor_mpc::{
    parse_mpc_public_config, HexDecodeError, JsonParseError, MpcConfigIncompatibility,
    MpcConfigLoadError, MpcConfigParseError, MpcConfigSourceError,
    CiphertextSuite, ReaderKeyAlgorithm,
};

const FORBIDDEN_DISPLAY_FRAGMENTS: &[&str] = &[
    "0xaa",
    "0xbb",
    "0xcc",
    "0xdd",
    "aaaa",
    "bbbb",
    "cccc",
    "dddd",
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
// MpcConfigSourceError::Unavailable may include the detail string (non-secret)
// but must not include raw byte patterns from fixture seeds.
// ---------------------------------------------------------------------------

#[test]
fn mpc_source_unavailable_display_includes_detail_not_bytes() {
    let err = MpcConfigSourceError::Unavailable {
        detail: "connection refused".to_string(),
    };
    let display = format!("{}", err);
    assert!(
        display.contains("connection refused"),
        "Unavailable display must include the detail string: {display:?}"
    );
    assert_display_is_non_secret("MpcConfigSourceError::Unavailable", &display);
}

// ---------------------------------------------------------------------------
// MpcConfigParseError::InvalidHpkePublicKey must not include raw hex content
// from the offending bytes — only the category label.
// ---------------------------------------------------------------------------

#[test]
fn invalid_hpke_public_key_display_is_category_label_only() {
    let hex_err = HexDecodeError::InvalidDigit {
        field: "hpke_public_key",
    };
    let err = MpcConfigParseError::InvalidHpkePublicKey(hex_err);
    let display = format!("{}", err);
    assert_display_is_non_secret("MpcConfigParseError::InvalidHpkePublicKey", &display);
}

#[test]
fn parse_error_display_variants_are_non_secret() {
    let cases = vec![
        MpcConfigParseError::Json(JsonParseError::MissingField {
            field: "ciphertext_suite",
        }),
        MpcConfigParseError::Hex(HexDecodeError::WrongByteLength {
            field: "domain_id",
            expected: 32,
            actual: 31,
        }),
        MpcConfigParseError::UnknownCiphertextSuite,
        MpcConfigParseError::InvalidHpkePublicKey(HexDecodeError::InvalidDigit {
            field: "hpke_public_key",
        }),
    ];

    for err in &cases {
        let display = format!("{}", err);
        assert_display_is_non_secret("MpcConfigParseError", &display);
    }
}

#[test]
fn serde_parse_error_debug_does_not_expose_raw_input_fragments() {
    let secret_value_payload = format!(
        r#"{{"chain_id":"PAYLOAD_SECRET_42","domain_id":"{}","key_id":"{}","hpke_public_key":"{}","reader_key_algorithm":"X25519","ciphertext_suite":"HpkeX25519HkdfSha256Aes256Gcm","approved_enclave_measurement":"{}"}}"#,
        hex_bytes(0x11, 32),
        hex_bytes(0x22, 32),
        hex_bytes(0x44, 32),
        hex_bytes(0x33, 32),
    );
    let err = parse_mpc_public_config(&secret_value_payload).unwrap_err();
    let debug = format!("{:?}", err);
    assert!(
        !debug.contains("PAYLOAD_SECRET_42"),
        "serde parse error must not expose field content: {debug}",
    );

    let secret_field_payload = format!(
        r#"{{"chain_id":1,"domain_id":"{}","key_id":"{}","hpke_public_key":"{}","reader_key_algorithm":"X25519","ciphertext_suite":"HpkeX25519HkdfSha256Aes256Gcm","approved_enclave_measurement":"{}","PAYLOAD_SECRET_FIELD":0}}"#,
        hex_bytes(0x11, 32),
        hex_bytes(0x22, 32),
        hex_bytes(0x44, 32),
        hex_bytes(0x33, 32),
    );
    let err = parse_mpc_public_config(&secret_field_payload).unwrap_err();
    let debug = format!("{:?}", err);
    assert!(
        !debug.contains("PAYLOAD_SECRET_FIELD"),
        "serde parse error must not expose unexpected field names: {debug}",
    );
}

fn hex_bytes(byte: u8, len: usize) -> String {
    let mut out = String::from("0x");
    for _ in 0..len {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
                JsonParseError::MissingField {
                    field: "ciphertext_suite",
                },
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

    for (label, err) in cases {
        let display = format!("{}", err);
        assert_display_is_non_secret(label, &display);
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
    assert_display_is_non_secret("ChainIdMismatch", &display);
}

#[test]
fn reader_key_algorithm_mismatch_display_is_non_secret() {
    let err = MpcConfigIncompatibility::ReaderKeyAlgorithmMismatch {
        expected: ReaderKeyAlgorithm::X25519,
        actual: ReaderKeyAlgorithm::X25519,
    };
    let display = format!("{}", err);
    assert_display_is_non_secret("ReaderKeyAlgorithmMismatch", &display);
}

#[test]
fn ciphertext_suite_mismatch_display_is_non_secret() {
    let err = MpcConfigIncompatibility::CiphertextSuiteMismatch {
        expected: CiphertextSuite::HpkeX25519HkdfSha256Aes256Gcm,
        actual: CiphertextSuite::HpkeX25519HkdfSha256Aes256Gcm,
    };
    let display = format!("{}", err);
    assert_display_is_non_secret("CiphertextSuiteMismatch", &display);
}
