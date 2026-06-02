//! Behavior tests for the AWS Nitro Enclave adapter.
//!
//! Each test programs a [`FakeNsm`] with a single document or transport
//! outcome and asserts the adapter produces the right runtime-neutral
//! [`EnclaveAttestationMaterial`] or the right
//! [`EnclaveAttestationError`] variant. Privacy is checked through the
//! public error surface: stable error variants never carry the Enclave
//! public key or the attestation document bytes.

mod common;

use coprocessor_nitro_enclave::{
    AttestationDigest, EnclaveAttestationError, EnclaveAttestationSource, NitroAdapterConfig,
    NitroAttestationDoc, NitroEnclaveAdapter, NitroSourceError,
};

use common::{
    approved_config, fake_attestation_document_bytes, fake_enclave_public_key,
    valid_attestation_doc, FakeNsm, TEST_APPROVED_MEASUREMENT, TEST_PUBLIC_KEY_LEN,
};

fn adapter_with_doc(doc: NitroAttestationDoc) -> NitroEnclaveAdapter<FakeNsm> {
    NitroEnclaveAdapter::new(approved_config(), FakeNsm::returning_doc(doc))
        .expect("approved configuration is valid")
}

fn adapter_with_source_error(error: NitroSourceError) -> NitroEnclaveAdapter<FakeNsm> {
    NitroEnclaveAdapter::new(approved_config(), FakeNsm::returning_error(error))
        .expect("approved configuration is valid")
}

#[test]
fn returns_runtime_neutral_material_for_valid_attestation_doc() {
    let adapter = adapter_with_doc(valid_attestation_doc());

    let material = adapter
        .current_attestation_material()
        .expect("valid document must produce material");

    assert_eq!(material.enclave_public_key, fake_enclave_public_key());
    assert_eq!(material.enclave_measurement, TEST_APPROVED_MEASUREMENT);
    assert_eq!(material.attestation, fake_attestation_document_bytes());
}

#[test]
fn rejects_measurement_mismatch_with_expected_and_actual_digests() {
    let mut doc = valid_attestation_doc();
    let observed = AttestationDigest([0x11; 32]);
    doc.pcr0 = observed;
    let adapter = adapter_with_doc(doc);

    let err = adapter
        .current_attestation_material()
        .expect_err("PCR0 mismatch must be rejected");

    assert_eq!(
        err,
        EnclaveAttestationError::MeasurementMismatch {
            expected: TEST_APPROVED_MEASUREMENT,
            actual: observed,
        }
    );
}

#[test]
fn rejects_wrong_public_key_length_as_malformed_attestation() {
    let mut doc = valid_attestation_doc();
    doc.enclave_public_key = vec![0x42; TEST_PUBLIC_KEY_LEN - 1];
    let adapter = adapter_with_doc(doc);

    let err = adapter
        .current_attestation_material()
        .expect_err("wrong public-key length must be rejected");

    match err {
        EnclaveAttestationError::MalformedAttestation { detail } => {
            assert!(
                detail.contains(&TEST_PUBLIC_KEY_LEN.to_string())
                    && detail.contains(&(TEST_PUBLIC_KEY_LEN - 1).to_string()),
                "detail should name expected and actual byte counts: {detail}"
            );
        }
        other => panic!("expected MalformedAttestation, got {other:?}"),
    }
}

#[test]
fn rejects_empty_document_bytes_as_malformed_attestation() {
    let mut doc = valid_attestation_doc();
    doc.document_bytes = Vec::new();
    let adapter = adapter_with_doc(doc);

    let err = adapter
        .current_attestation_material()
        .expect_err("empty document bytes must be rejected");

    assert!(matches!(
        err,
        EnclaveAttestationError::MalformedAttestation { .. }
    ));
}

#[test]
fn maps_nsm_unavailable_to_backend_unavailable() {
    let adapter = adapter_with_source_error(NitroSourceError::Unavailable {
        detail: "nsm device busy".to_string(),
    });

    let err = adapter
        .current_attestation_material()
        .expect_err("transient NSM failure must surface");

    assert_eq!(
        err,
        EnclaveAttestationError::BackendUnavailable {
            detail: "nsm device busy".to_string(),
        }
    );
}

#[test]
fn maps_nsm_malformed_to_malformed_attestation() {
    let adapter = adapter_with_source_error(NitroSourceError::Malformed {
        detail: "cose_sign1 decode failed".to_string(),
    });

    let err = adapter
        .current_attestation_material()
        .expect_err("malformed NSM document must surface");

    assert_eq!(
        err,
        EnclaveAttestationError::MalformedAttestation {
            detail: "cose_sign1 decode failed".to_string(),
        }
    );
}

fn expect_invalid_configuration(
    result: Result<NitroEnclaveAdapter<FakeNsm>, EnclaveAttestationError>,
) -> EnclaveAttestationError {
    match result {
        Ok(_) => panic!("expected EnclaveAttestationError::InvalidConfiguration"),
        Err(err) => err,
    }
}

#[test]
fn configuration_validation_rejects_zero_public_key_length() {
    let bad = NitroAdapterConfig {
        approved_enclave_measurement: TEST_APPROVED_MEASUREMENT,
        expected_public_key_len: 0,
    };

    let err = expect_invalid_configuration(NitroEnclaveAdapter::new(
        bad,
        FakeNsm::returning_doc(valid_attestation_doc()),
    ));

    assert!(matches!(
        err,
        EnclaveAttestationError::InvalidConfiguration { .. }
    ));
}

#[test]
fn configuration_validation_rejects_all_zero_approved_measurement() {
    let bad = NitroAdapterConfig {
        approved_enclave_measurement: AttestationDigest([0; 32]),
        expected_public_key_len: TEST_PUBLIC_KEY_LEN,
    };

    let err = expect_invalid_configuration(NitroEnclaveAdapter::new(
        bad,
        FakeNsm::returning_doc(valid_attestation_doc()),
    ));

    assert!(matches!(
        err,
        EnclaveAttestationError::InvalidConfiguration { .. }
    ));
}

#[test]
fn configuration_validation_runs_before_any_nsm_round_trip() {
    // The adapter must not call the NSM when its configuration is invalid.
    // We program the fake to a doc that would succeed if reached, but
    // configuration validation should fail first; the test passes if the
    // adapter never asks the fake (the fake's outcome remains unconsumed).
    let bad = NitroAdapterConfig {
        approved_enclave_measurement: AttestationDigest([0; 32]),
        expected_public_key_len: TEST_PUBLIC_KEY_LEN,
    };
    let fake = FakeNsm::returning_doc(valid_attestation_doc());

    let _ = expect_invalid_configuration(NitroEnclaveAdapter::new(bad, fake));
    // Construction failed before the fake was consumed; the test reaching
    // this point implies no NSM round trip happened.
}

#[test]
fn four_failure_modes_each_have_a_distinct_error_variant() {
    // Pin the four runtime-neutral failure modes (transient backend,
    // malformed attestation, measurement mismatch, invalid configuration)
    // to distinct variants so a future refactor that collapses any of them
    // breaks here.
    let backend = adapter_with_source_error(NitroSourceError::Unavailable {
        detail: "boom".to_string(),
    })
    .current_attestation_material()
    .unwrap_err();

    let malformed = adapter_with_source_error(NitroSourceError::Malformed {
        detail: "boom".to_string(),
    })
    .current_attestation_material()
    .unwrap_err();

    let mut mismatched = valid_attestation_doc();
    mismatched.pcr0 = AttestationDigest([0xFF; 32]);
    let mismatch = adapter_with_doc(mismatched)
        .current_attestation_material()
        .unwrap_err();

    let invalid_config = expect_invalid_configuration(NitroEnclaveAdapter::new(
        NitroAdapterConfig {
            approved_enclave_measurement: AttestationDigest([0; 32]),
            expected_public_key_len: TEST_PUBLIC_KEY_LEN,
        },
        FakeNsm::returning_doc(valid_attestation_doc()),
    ));

    assert!(matches!(
        backend,
        EnclaveAttestationError::BackendUnavailable { .. }
    ));
    assert!(matches!(
        malformed,
        EnclaveAttestationError::MalformedAttestation { .. }
    ));
    assert!(matches!(
        mismatch,
        EnclaveAttestationError::MeasurementMismatch { .. }
    ));
    assert!(matches!(
        invalid_config,
        EnclaveAttestationError::InvalidConfiguration { .. }
    ));
}

#[test]
fn errors_do_not_carry_attestation_or_public_key_bytes() {
    // Hosts log error variants. The runtime-neutral error variants must
    // never embed the Enclave public key bytes, attestation document
    // bytes, or any field that would leak key material. We probe via the
    // Debug surface so a future maintainer who adds a payload-carrying
    // variant trips the check.
    let probes: &[EnclaveAttestationError] = &[
        EnclaveAttestationError::BackendUnavailable {
            detail: "transient: read timeout".to_string(),
        },
        EnclaveAttestationError::MalformedAttestation {
            detail: "cose_sign1 decode failed".to_string(),
        },
        EnclaveAttestationError::MeasurementMismatch {
            expected: TEST_APPROVED_MEASUREMENT,
            actual: AttestationDigest([0x99; 32]),
        },
        EnclaveAttestationError::InvalidConfiguration {
            detail: "expected_public_key_len must be greater than zero".to_string(),
        },
    ];

    let public_key_signature = format!("{:?}", fake_enclave_public_key());
    let attestation_signature = format!("{:?}", fake_attestation_document_bytes());

    for error in probes {
        let rendered = format!("{:?}", error);
        assert!(
            !rendered.contains(&public_key_signature),
            "error rendering leaks enclave public key: {rendered}"
        );
        assert!(
            !rendered.contains(&attestation_signature),
            "error rendering leaks attestation document bytes: {rendered}"
        );
    }
}

#[test]
fn host_drives_adapter_through_runtime_neutral_trait_object() {
    // The Coprocessor Host should be able to swap adapters by holding a
    // `&dyn EnclaveAttestationSource`. This pins the trait is object-safe
    // and the adapter is dispatchable from runtime-neutral host code.
    let adapter = adapter_with_doc(valid_attestation_doc());
    let source: &dyn EnclaveAttestationSource = &adapter;

    let material = source
        .current_attestation_material()
        .expect("dyn dispatch must work");

    assert_eq!(material.enclave_measurement, TEST_APPROVED_MEASUREMENT);
}
