//! Round-trip every Ciphertext Binding AAD kind through canonical CBOR and
//! back. Encoding produces a fixed-order CBOR array, decoding reconstructs the
//! exact same domain value, and the cross-kind dispatcher returns the right
//! variant.

use coprocessor_ciphertext_binding::{
    AadKind, AttestationDigest, CiphertextBindingAad, ContractAddress, DomainId, EnclaveAadV1,
    HandleId, KeyId, ReaderAadV1, ReaderId, RequestId, SystemHandleAadV1, SystemInputAadV1,
};

fn fill(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn sample_system_input() -> SystemInputAadV1 {
    SystemInputAadV1 {
        version: 1,
        chain_id: 11155111,
        domain_id: DomainId(fill(0xAA)),
        contract: ContractAddress([0xCC; 20]),
        type_tag: "suint256".to_string(),
        key_id: KeyId(fill(0x11)),
    }
}

fn sample_system_handle() -> SystemHandleAadV1 {
    SystemHandleAadV1 {
        version: 1,
        chain_id: 11155111,
        domain_id: DomainId(fill(0xAA)),
        handle_id: HandleId(fill(0xBB)),
        type_tag: "sbool".to_string(),
        key_id: KeyId(fill(0x11)),
    }
}

fn sample_enclave() -> EnclaveAadV1 {
    EnclaveAadV1 {
        version: 1,
        chain_id: 11155111,
        domain_id: DomainId(fill(0xAA)),
        request_id: RequestId(fill(0x77)),
        handle_id: HandleId(fill(0xBB)),
        type_tag: "suint256".to_string(),
        attestation_digest: AttestationDigest(fill(0xEE)),
        key_id: KeyId(fill(0x11)),
    }
}

fn sample_reader() -> ReaderAadV1 {
    ReaderAadV1 {
        version: 1,
        chain_id: 11155111,
        domain_id: DomainId(fill(0xAA)),
        request_id: RequestId(fill(0x77)),
        handle_id: HandleId(fill(0xBB)),
        reader_id: ReaderId(fill(0x44)),
        type_tag: "sbool".to_string(),
        key_id: KeyId(fill(0x11)),
    }
}

#[test]
fn system_input_round_trip_preserves_every_field() {
    let aad = sample_system_input();
    let bytes = aad.encode();
    let decoded = SystemInputAadV1::decode(&bytes).expect("decode");
    assert_eq!(decoded, aad);
}

#[test]
fn system_handle_round_trip_preserves_every_field() {
    let aad = sample_system_handle();
    let bytes = aad.encode();
    let decoded = SystemHandleAadV1::decode(&bytes).expect("decode");
    assert_eq!(decoded, aad);
}

#[test]
fn enclave_round_trip_preserves_every_field() {
    let aad = sample_enclave();
    let bytes = aad.encode();
    let decoded = EnclaveAadV1::decode(&bytes).expect("decode");
    assert_eq!(decoded, aad);
}

#[test]
fn reader_round_trip_preserves_every_field() {
    let aad = sample_reader();
    let bytes = aad.encode();
    let decoded = ReaderAadV1::decode(&bytes).expect("decode");
    assert_eq!(decoded, aad);
}

#[test]
fn dispatcher_returns_matching_variant_for_each_kind() {
    let cases: Vec<(CiphertextBindingAad, AadKind)> = vec![
        (sample_system_input().into(), AadKind::SystemInput),
        (sample_system_handle().into(), AadKind::SystemHandle),
        (sample_enclave().into(), AadKind::Enclave),
        (sample_reader().into(), AadKind::Reader),
    ];
    for (aad, expected_kind) in cases {
        let bytes = aad.encode();
        let decoded = CiphertextBindingAad::decode(&bytes).expect("dispatcher decode");
        assert_eq!(decoded.kind(), expected_kind);
        assert_eq!(decoded, aad);
    }
}

#[test]
fn encoded_payload_is_a_definite_length_cbor_array_not_a_map() {
    // CBOR major type 4 (array) has initial byte 0x80..=0x9b. Major type 5 (map)
    // is 0xa0..=0xbb. The spec forbids map encoding for AAD.
    for bytes in [
        sample_system_input().encode(),
        sample_system_handle().encode(),
        sample_enclave().encode(),
        sample_reader().encode(),
    ] {
        let initial = bytes[0];
        let major = initial >> 5;
        assert_eq!(
            major, 4,
            "AAD must encode as CBOR array (major type 4), got major {major} for initial byte 0x{initial:02x}",
        );
    }
}

#[test]
fn encoded_arrays_use_fixed_lengths_per_spec() {
    // Spec: SystemInput=7, SystemHandle=7, Enclave=9, Reader=9 elements.
    // For arrays of length 0..=23, the initial byte is 0x80 | len.
    assert_eq!(sample_system_input().encode()[0], 0x80 | 7);
    assert_eq!(sample_system_handle().encode()[0], 0x80 | 7);
    assert_eq!(sample_enclave().encode()[0], 0x80 | 9);
    assert_eq!(sample_reader().encode()[0], 0x80 | 9);
}
