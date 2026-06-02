//! Behavior tests for the local attestation substitute used by ordinary
//! Sandcastle runs and tests that do not boot a Nitro VM.

mod common;

use coprocessor_nitro_enclave::{
    EnclaveAttestationSource, LocalEnclaveAttestationConfig, LocalEnclaveAttestationSource,
};

use common::{fake_attestation_document_bytes, fake_enclave_public_key, TEST_APPROVED_MEASUREMENT};

fn local_config() -> LocalEnclaveAttestationConfig {
    LocalEnclaveAttestationConfig {
        enclave_public_key: fake_enclave_public_key(),
        enclave_measurement: TEST_APPROVED_MEASUREMENT,
        attestation: fake_attestation_document_bytes(),
    }
}

#[test]
fn local_substitute_serves_prebaked_material_through_runtime_neutral_trait() {
    let source = LocalEnclaveAttestationSource::new(local_config());
    let trait_view: &dyn EnclaveAttestationSource = &source;

    let material = trait_view
        .current_attestation_material()
        .expect("local substitute must always succeed");

    assert_eq!(material.enclave_public_key, fake_enclave_public_key());
    assert_eq!(material.enclave_measurement, TEST_APPROVED_MEASUREMENT);
    assert_eq!(material.attestation, fake_attestation_document_bytes());
}

#[test]
fn local_substitute_returns_consistent_material_across_calls() {
    // Sandcastle runs may ask the substitute repeatedly. Each call must
    // return the same pre-baked material so downstream code that hashes or
    // compares attestation evidence stays stable.
    let source = LocalEnclaveAttestationSource::new(local_config());

    let first = source.current_attestation_material().unwrap();
    let second = source.current_attestation_material().unwrap();

    assert_eq!(first, second);
}
