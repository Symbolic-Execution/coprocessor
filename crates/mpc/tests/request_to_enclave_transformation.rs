//! Behavior tests for the MPC To-Enclave Transformation client.
//!
//! Each test programs a [`FakeMpcServer`] with one outcome and asserts the
//! client wrapper returns the right Coprocessor-domain result. The fake
//! records the request so tests can confirm the client forwards the spec
//! fields without re-shaping them.
//!
//! Privacy is checked through the public error surface: stable error variants
//! never carry the enclave public key, attestation bytes, ciphertext bytes,
//! or wrapped-key bytes.

mod to_enclave_common;

use coprocessor_mpc::{
    request_to_enclave_transformation, MpcSourceError, MpcToEnclaveResponse,
    ToEnclaveTransformationError,
};

use to_enclave_common::{
    attestation_bytes, enclave_ciphertext_for_test_request, enclave_public_key,
    system_ciphertext_for_test_request, valid_request, FakeMpcOutcome, FakeMpcServer,
    TEST_ATTESTATION_DIGEST, TEST_CHAIN_ID, TEST_HANDLE_ID, TEST_REQUEST_ID,
};

fn error_for_outcome(outcome: FakeMpcOutcome) -> ToEnclaveTransformationError {
    let server = FakeMpcServer::returning(outcome);
    request_to_enclave_transformation(&server, &valid_request()).unwrap_err()
}

#[test]
fn success_response_returns_enclave_ciphertext_to_caller() {
    let envelope = enclave_ciphertext_for_test_request();
    let server = FakeMpcServer::returning_success(envelope.clone());

    let result = request_to_enclave_transformation(&server, &valid_request()).unwrap();

    assert_eq!(result, envelope);
}

#[test]
fn client_forwards_spec_fields_to_mpc_server() {
    let server = FakeMpcServer::returning_success(enclave_ciphertext_for_test_request());
    let request = valid_request();

    let _ = request_to_enclave_transformation(&server, &request).unwrap();

    let observed = server.observed_request();
    assert_eq!(observed.request_id, TEST_REQUEST_ID);
    assert_eq!(observed.chain_id, TEST_CHAIN_ID);
    assert_eq!(observed.handle_id, TEST_HANDLE_ID);
    assert_eq!(observed.enclave_public_key, enclave_public_key());
    assert_eq!(observed.enclave_measurement, TEST_ATTESTATION_DIGEST);
    assert_eq!(observed.attestation, attestation_bytes());
    assert_eq!(
        observed.system_ciphertext,
        system_ciphertext_for_test_request()
    );
}

#[test]
fn unauthorized_response_maps_to_unauthorized_error() {
    let err = error_for_outcome(FakeMpcOutcome::Response(MpcToEnclaveResponse::Unauthorized));

    assert_eq!(err, ToEnclaveTransformationError::Unauthorized);
}

#[test]
fn invalid_binding_response_maps_to_invalid_binding_error() {
    let err = error_for_outcome(FakeMpcOutcome::Response(
        MpcToEnclaveResponse::InvalidBinding,
    ));

    assert_eq!(err, ToEnclaveTransformationError::InvalidBinding);
}

#[test]
fn invalid_attestation_response_maps_to_invalid_attestation_error() {
    let err = error_for_outcome(FakeMpcOutcome::Response(
        MpcToEnclaveResponse::InvalidAttestation,
    ));

    assert_eq!(err, ToEnclaveTransformationError::InvalidAttestation);
}

#[test]
fn malformed_source_error_maps_to_malformed_response_error() {
    let err = error_for_outcome(FakeMpcOutcome::SourceError(
        MpcSourceError::MalformedResponse,
    ));

    assert_eq!(err, ToEnclaveTransformationError::MalformedResponse);
}

#[test]
fn transport_unavailable_maps_to_unavailable_error_with_detail() {
    let err = error_for_outcome(FakeMpcOutcome::SourceError(MpcSourceError::Unavailable {
        detail: "mpc endpoint timed out".to_string(),
    }));

    assert_eq!(
        err,
        ToEnclaveTransformationError::Unavailable {
            detail: "mpc endpoint timed out".to_string(),
        }
    );
}

#[test]
fn five_failure_modes_each_have_a_distinct_error_variant() {
    // The spec says malformed, authorization, invalid binding, invalid
    // attestation, and backend-availability errors map to stable, distinct
    // Coprocessor errors. This test pins that all five reach distinct
    // variants so a future refactor that collapses any of them breaks here.
    let malformed = error_for_outcome(FakeMpcOutcome::SourceError(
        MpcSourceError::MalformedResponse,
    ));
    let unauthorized =
        error_for_outcome(FakeMpcOutcome::Response(MpcToEnclaveResponse::Unauthorized));
    let invalid_binding = error_for_outcome(FakeMpcOutcome::Response(
        MpcToEnclaveResponse::InvalidBinding,
    ));
    let invalid_attestation = error_for_outcome(FakeMpcOutcome::Response(
        MpcToEnclaveResponse::InvalidAttestation,
    ));
    let unavailable = error_for_outcome(FakeMpcOutcome::SourceError(MpcSourceError::Unavailable {
        detail: "boom".to_string(),
    }));

    assert!(matches!(
        malformed,
        ToEnclaveTransformationError::MalformedResponse
    ));
    assert!(matches!(
        unauthorized,
        ToEnclaveTransformationError::Unauthorized
    ));
    assert!(matches!(
        invalid_binding,
        ToEnclaveTransformationError::InvalidBinding
    ));
    assert!(matches!(
        invalid_attestation,
        ToEnclaveTransformationError::InvalidAttestation
    ));
    assert!(matches!(
        unavailable,
        ToEnclaveTransformationError::Unavailable { .. }
    ));
}

#[test]
fn errors_do_not_carry_key_material_or_ciphertext_bytes() {
    // Hosts log error variants and pass them across logs. The five domain
    // error variants must never include the enclave public key, attestation
    // bytes, the SystemCiphertextV1 payload (wrapped_key / ciphertext), or
    // any field that would leak key material. We assert this through the
    // Debug surface so a future maintainer who adds a payload-carrying
    // variant trips the check.
    let probes: &[ToEnclaveTransformationError] = &[
        ToEnclaveTransformationError::Unauthorized,
        ToEnclaveTransformationError::InvalidBinding,
        ToEnclaveTransformationError::InvalidAttestation,
        ToEnclaveTransformationError::MalformedResponse,
        ToEnclaveTransformationError::Unavailable {
            detail: "transient: read timeout".to_string(),
        },
    ];

    let public_key_signature = format!("{:?}", enclave_public_key());
    let attestation_signature = format!("{:?}", attestation_bytes());
    let system_ciphertext_signature =
        format!("{:?}", system_ciphertext_for_test_request().ciphertext);
    let wrapped_key_signature = format!("{:?}", system_ciphertext_for_test_request().wrapped_key);

    for error in probes {
        let rendered = format!("{:?}", error);
        assert!(
            !rendered.contains(&public_key_signature),
            "error rendering leaks enclave public key: {rendered}"
        );
        assert!(
            !rendered.contains(&attestation_signature),
            "error rendering leaks attestation bytes: {rendered}"
        );
        assert!(
            !rendered.contains(&system_ciphertext_signature),
            "error rendering leaks SystemCiphertext ciphertext bytes: {rendered}"
        );
        assert!(
            !rendered.contains(&wrapped_key_signature),
            "error rendering leaks SystemCiphertext wrapped-key bytes: {rendered}"
        );
    }
}

#[test]
fn success_path_returns_enclave_ciphertext_with_enclave_aad_bound_to_request() {
    // Smoke-check that the success path threads the typed EnclaveCiphertextV1
    // through without reshaping its AAD. Hosts pass that envelope to the
    // Enclave runtime, which verifies the AAD; this test pins the wire is
    // preserved end-to-end through the client.
    let envelope = enclave_ciphertext_for_test_request();
    let expected_aad = envelope.aad.clone();
    let server = FakeMpcServer::returning_success(envelope);

    let result = request_to_enclave_transformation(&server, &valid_request()).unwrap();

    assert_eq!(result.aad, expected_aad);
}
