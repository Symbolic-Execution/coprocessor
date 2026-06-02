//! Behavior tests for [`load_mpc_public_config`].
//!
//! These tests exercise the public crate entry point — fetching from an
//! [`MpcConfigSource`], parsing the JSON payload, and validating against the
//! Coprocessor's expectations. The three acceptance-criteria failure modes
//! (success, incompatible, transient unavailable) each have a dedicated
//! test; finer-grained parse and compatibility failures are covered under
//! the dimension they belong to.

mod common;

use coprocessor_mpc_config::{
    load_mpc_public_config, parse_mpc_public_config, ChainId, DomainId, HexDecodeError,
    JsonParseError, MpcConfigIncompatibility, MpcConfigLoadError, MpcConfigParseError, MpcSuite,
};

use common::{
    build_json, hex32, hex_bytes, matching_expectations, valid_config_json, FlakyOnceSource,
    JsonValue, StubSource, UnavailableSource, TEST_ENCLAVE_MEASUREMENT, TEST_KEY_ID,
};

#[test]
fn load_succeeds_when_payload_matches_expectations() {
    let source = StubSource::new(valid_config_json());

    let config = load_mpc_public_config(&source, &matching_expectations()).unwrap();

    assert_eq!(config.chain_id, ChainId(1));
    assert_eq!(config.domain_id, DomainId([0x11; 32]));
    assert_eq!(config.active_key_id, TEST_KEY_ID);
    assert_eq!(config.suite, MpcSuite::Bls12_381G1);
    assert_eq!(
        config.public_key.len(),
        MpcSuite::Bls12_381G1.public_key_len()
    );
    assert!(config.public_key.iter().all(|byte| *byte == 0x44));
    assert_eq!(
        config.approved_enclave_measurement,
        TEST_ENCLAVE_MEASUREMENT
    );
}

#[test]
fn chain_id_mismatch_surfaces_incompatible_load_error() {
    let payload = build_json(&[
        ("chain_id", JsonValue::Uint(999)),
        ("domain_id", JsonValue::Str(&hex32(0x11))),
        ("active_key_id", JsonValue::Str(&hex32(0x22))),
        ("suite", JsonValue::Str("bls12-381-g1")),
        ("public_key", JsonValue::Str(&hex_bytes(0x44, 48))),
        ("approved_enclave_measurement", JsonValue::Str(&hex32(0x33))),
    ]);
    let source = StubSource::new(payload);

    let err = load_mpc_public_config(&source, &matching_expectations()).unwrap_err();

    assert!(matches!(
        err,
        MpcConfigLoadError::Incompatible(MpcConfigIncompatibility::ChainIdMismatch {
            expected: ChainId(1),
            actual: ChainId(999),
        })
    ));
}

#[test]
fn domain_id_mismatch_surfaces_incompatible_load_error() {
    let payload = build_json(&[
        ("chain_id", JsonValue::Uint(1)),
        ("domain_id", JsonValue::Str(&hex32(0xAA))),
        ("active_key_id", JsonValue::Str(&hex32(0x22))),
        ("suite", JsonValue::Str("bls12-381-g1")),
        ("public_key", JsonValue::Str(&hex_bytes(0x44, 48))),
        ("approved_enclave_measurement", JsonValue::Str(&hex32(0x33))),
    ]);
    let source = StubSource::new(payload);

    let err = load_mpc_public_config(&source, &matching_expectations()).unwrap_err();

    assert!(matches!(
        err,
        MpcConfigLoadError::Incompatible(MpcConfigIncompatibility::DomainIdMismatch { .. })
    ));
}

#[test]
fn unknown_suite_in_payload_is_parse_error_not_compatibility_error() {
    let payload = build_json(&[
        ("chain_id", JsonValue::Uint(1)),
        ("domain_id", JsonValue::Str(&hex32(0x11))),
        ("active_key_id", JsonValue::Str(&hex32(0x22))),
        ("suite", JsonValue::Str("not-a-real-suite")),
        ("public_key", JsonValue::Str(&hex_bytes(0x44, 48))),
        ("approved_enclave_measurement", JsonValue::Str(&hex32(0x33))),
    ]);
    let source = StubSource::new(payload);

    let err = load_mpc_public_config(&source, &matching_expectations()).unwrap_err();

    assert!(matches!(
        err,
        MpcConfigLoadError::Malformed(MpcConfigParseError::UnknownSuite)
    ));
}

#[test]
fn public_key_byte_length_off_by_one_is_key_shape_mismatch() {
    let short_key = hex_bytes(0x44, 47);
    let payload = build_json(&[
        ("chain_id", JsonValue::Uint(1)),
        ("domain_id", JsonValue::Str(&hex32(0x11))),
        ("active_key_id", JsonValue::Str(&hex32(0x22))),
        ("suite", JsonValue::Str("bls12-381-g1")),
        ("public_key", JsonValue::Str(&short_key)),
        ("approved_enclave_measurement", JsonValue::Str(&hex32(0x33))),
    ]);
    let source = StubSource::new(payload);

    let err = load_mpc_public_config(&source, &matching_expectations()).unwrap_err();

    assert!(matches!(
        err,
        MpcConfigLoadError::Incompatible(MpcConfigIncompatibility::PublicKeyShape {
            suite: MpcSuite::Bls12_381G1,
            expected_bytes: 48,
            actual_bytes: 47,
        })
    ));
}

#[test]
fn transient_availability_failure_surfaces_unavailable_load_error() {
    let source = UnavailableSource {
        detail: "connection reset by peer",
    };

    let err = load_mpc_public_config(&source, &matching_expectations()).unwrap_err();

    match err {
        MpcConfigLoadError::Unavailable { detail } => {
            assert_eq!(detail, "connection reset by peer");
        }
        other => panic!("expected Unavailable, got {:?}", other),
    }
}

#[test]
fn unavailable_failure_is_distinct_from_malformed_and_incompatible() {
    // Spec requirement: backend availability failures are distinguishable
    // from malformed or incompatible configuration. This test asserts the
    // discriminator behavior explicitly so a future refactor that collapses
    // these into a single error variant breaks here.
    let unavailable = load_mpc_public_config(
        &UnavailableSource { detail: "boom" },
        &matching_expectations(),
    )
    .unwrap_err();
    assert!(matches!(
        unavailable,
        MpcConfigLoadError::Unavailable { .. }
    ));

    let malformed_payload =
        build_json(&[("chain_id", JsonValue::Str("not-a-number-but-a-string"))]);
    let malformed = load_mpc_public_config(
        &StubSource::new(malformed_payload),
        &matching_expectations(),
    )
    .unwrap_err();
    assert!(matches!(malformed, MpcConfigLoadError::Malformed(_)));

    let incompatible_payload = build_json(&[
        ("chain_id", JsonValue::Uint(2)),
        ("domain_id", JsonValue::Str(&hex32(0x11))),
        ("active_key_id", JsonValue::Str(&hex32(0x22))),
        ("suite", JsonValue::Str("bls12-381-g1")),
        ("public_key", JsonValue::Str(&hex_bytes(0x44, 48))),
        ("approved_enclave_measurement", JsonValue::Str(&hex32(0x33))),
    ]);
    let incompatible = load_mpc_public_config(
        &StubSource::new(incompatible_payload),
        &matching_expectations(),
    )
    .unwrap_err();
    assert!(matches!(incompatible, MpcConfigLoadError::Incompatible(_)));
}

#[test]
fn second_load_after_transient_failure_succeeds() {
    // A retry policy that calls the loader twice should be able to recover
    // from a transient availability failure because Unavailable is its own
    // load-error variant.
    let source = FlakyOnceSource::new(valid_config_json());
    let expectations = matching_expectations();

    let first = load_mpc_public_config(&source, &expectations).unwrap_err();
    assert!(matches!(first, MpcConfigLoadError::Unavailable { .. }));

    let second = load_mpc_public_config(&source, &expectations).unwrap();
    assert_eq!(second.suite, MpcSuite::Bls12_381G1);
}

#[test]
fn parse_rejects_missing_field() {
    let payload = build_json(&[
        ("chain_id", JsonValue::Uint(1)),
        ("domain_id", JsonValue::Str(&hex32(0x11))),
        ("active_key_id", JsonValue::Str(&hex32(0x22))),
        ("suite", JsonValue::Str("bls12-381-g1")),
        ("public_key", JsonValue::Str(&hex_bytes(0x44, 48))),
    ]);

    let err = parse_mpc_public_config(&payload).unwrap_err();

    assert!(matches!(
        err,
        MpcConfigParseError::Json(JsonParseError::MissingField {
            field: "approved_enclave_measurement"
        })
    ));
}

#[test]
fn parse_rejects_unexpected_extra_field() {
    let payload = build_json(&[
        ("chain_id", JsonValue::Uint(1)),
        ("domain_id", JsonValue::Str(&hex32(0x11))),
        ("active_key_id", JsonValue::Str(&hex32(0x22))),
        ("suite", JsonValue::Str("bls12-381-g1")),
        ("public_key", JsonValue::Str(&hex_bytes(0x44, 48))),
        ("approved_enclave_measurement", JsonValue::Str(&hex32(0x33))),
        ("rogue_field", JsonValue::Uint(0)),
    ]);

    let err = parse_mpc_public_config(&payload).unwrap_err();

    assert!(matches!(
        err,
        MpcConfigParseError::Json(JsonParseError::UnexpectedField)
    ));
}

#[test]
fn parse_rejects_invalid_hex_digit_in_domain_id() {
    let bad_domain = "0x".to_string() + &"zz".repeat(32);
    let payload = build_json(&[
        ("chain_id", JsonValue::Uint(1)),
        ("domain_id", JsonValue::Str(&bad_domain)),
        ("active_key_id", JsonValue::Str(&hex32(0x22))),
        ("suite", JsonValue::Str("bls12-381-g1")),
        ("public_key", JsonValue::Str(&hex_bytes(0x44, 48))),
        ("approved_enclave_measurement", JsonValue::Str(&hex32(0x33))),
    ]);

    let err = parse_mpc_public_config(&payload).unwrap_err();

    assert!(matches!(
        err,
        MpcConfigParseError::Hex(HexDecodeError::InvalidDigit { field: "domain_id" })
    ));
}

#[test]
fn parse_rejects_public_key_with_odd_hex_length() {
    let odd_key = "0x".to_string() + &"4".repeat(95);
    let payload = build_json(&[
        ("chain_id", JsonValue::Uint(1)),
        ("domain_id", JsonValue::Str(&hex32(0x11))),
        ("active_key_id", JsonValue::Str(&hex32(0x22))),
        ("suite", JsonValue::Str("bls12-381-g1")),
        ("public_key", JsonValue::Str(&odd_key)),
        ("approved_enclave_measurement", JsonValue::Str(&hex32(0x33))),
    ]);

    let err = parse_mpc_public_config(&payload).unwrap_err();

    assert!(matches!(
        err,
        MpcConfigParseError::InvalidPublicKey(HexDecodeError::OddLength {
            field: "public_key",
            ..
        })
    ));
}
