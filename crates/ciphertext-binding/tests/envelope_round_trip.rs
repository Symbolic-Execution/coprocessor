//! Round-trip every Ciphertext Envelope kind through canonical CBOR. Each
//! envelope encodes as a fixed-shape CBOR array; decoding reconstructs the
//! exact same domain value and validates that the embedded AAD bytes bind to
//! a matching `AadKind` for the envelope.

use coprocessor_ciphertext_binding::{
    AttestationDigest, ContractAddress, DomainId, EnclaveAadV1, EnclaveCiphertextV1, HandleId,
    KeyId, ReaderAadV1, ReaderCiphertextV1, ReaderId, RequestId, SystemCiphertextV1,
    SystemHandleAadV1, SystemInputAadV1,
};

fn fill(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn sample_system_input_aad() -> SystemInputAadV1 {
    SystemInputAadV1 {
        version: 1,
        chain_id: 11155111,
        domain_id: DomainId(fill(0xAA)),
        contract: ContractAddress([0xCC; 20]),
        type_tag: "suint256".to_string(),
        key_id: KeyId(fill(0x11)),
    }
}

fn sample_system_handle_aad() -> SystemHandleAadV1 {
    SystemHandleAadV1 {
        version: 1,
        chain_id: 11155111,
        domain_id: DomainId(fill(0xAA)),
        handle_id: HandleId(fill(0xBB)),
        type_tag: "sbool".to_string(),
        key_id: KeyId(fill(0x11)),
    }
}

fn sample_enclave_aad() -> EnclaveAadV1 {
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

fn sample_reader_aad() -> ReaderAadV1 {
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
fn system_ciphertext_round_trip_with_system_input_aad_preserves_every_field() {
    let envelope = SystemCiphertextV1 {
        version: 1,
        aad: sample_system_input_aad().encode(),
        wrapped_key: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        ciphertext: vec![0xAA, 0xBB, 0xCC, 0xDD],
    };
    let bytes = envelope.encode();
    let decoded = SystemCiphertextV1::decode(&bytes).expect("decode");
    assert_eq!(decoded, envelope);
}

#[test]
fn system_ciphertext_round_trip_with_system_handle_aad_preserves_every_field() {
    let envelope = SystemCiphertextV1 {
        version: 1,
        aad: sample_system_handle_aad().encode(),
        wrapped_key: vec![0x10; 64],
        ciphertext: vec![0x20; 128],
    };
    let bytes = envelope.encode();
    let decoded = SystemCiphertextV1::decode(&bytes).expect("decode");
    assert_eq!(decoded, envelope);
}

#[test]
fn enclave_ciphertext_round_trip_preserves_every_field() {
    let envelope = EnclaveCiphertextV1 {
        version: 1,
        aad: sample_enclave_aad().encode(),
        wrapped_key: vec![0x55; 96],
        ciphertext: vec![0x66; 200],
    };
    let bytes = envelope.encode();
    let decoded = EnclaveCiphertextV1::decode(&bytes).expect("decode");
    assert_eq!(decoded, envelope);
}

#[test]
fn reader_ciphertext_round_trip_preserves_every_field() {
    let envelope = ReaderCiphertextV1 {
        version: 1,
        aad: sample_reader_aad().encode(),
        wrapped_key: vec![0x77; 80],
        ciphertext: vec![0x88; 256],
    };
    let bytes = envelope.encode();
    let decoded = ReaderCiphertextV1::decode(&bytes).expect("decode");
    assert_eq!(decoded, envelope);
}

#[test]
fn each_envelope_encodes_as_a_definite_length_cbor_array() {
    let system = SystemCiphertextV1 {
        version: 1,
        aad: sample_system_input_aad().encode(),
        wrapped_key: vec![0; 8],
        ciphertext: vec![0; 16],
    }
    .encode();
    let enclave = EnclaveCiphertextV1 {
        version: 1,
        aad: sample_enclave_aad().encode(),
        wrapped_key: vec![0; 8],
        ciphertext: vec![0; 16],
    }
    .encode();
    let reader = ReaderCiphertextV1 {
        version: 1,
        aad: sample_reader_aad().encode(),
        wrapped_key: vec![0; 8],
        ciphertext: vec![0; 16],
    }
    .encode();
    for bytes in [system, enclave, reader] {
        let initial = bytes[0];
        let major = initial >> 5;
        assert_eq!(
            major, 4,
            "envelope must encode as CBOR array (major type 4), got major {major} for initial byte 0x{initial:02x}",
        );
        assert_eq!(
            initial & 0x1f,
            4,
            "envelope must be a 4-element definite-length array; got initial byte 0x{initial:02x}",
        );
    }
}

#[test]
fn empty_wrapped_key_and_ciphertext_round_trip() {
    let envelope = SystemCiphertextV1 {
        version: 1,
        aad: sample_system_input_aad().encode(),
        wrapped_key: Vec::new(),
        ciphertext: Vec::new(),
    };
    let bytes = envelope.encode();
    let decoded = SystemCiphertextV1::decode(&bytes).expect("decode");
    assert_eq!(decoded, envelope);
}
