//! Round-trip every Ciphertext Envelope kind through canonical CBOR. Each
//! envelope encodes as a fixed-shape CBOR array; decoding reconstructs the
//! exact same domain value and validates that the embedded AAD bytes bind to
//! a matching `AadKind` for the envelope.

use coprocessor_ciphertext_binding::{EnclaveCiphertextV1, ReaderCiphertextV1, SystemCiphertextV1};

mod common;

use common::{
    sample_enclave_aad, sample_reader_aad, sample_system_handle_aad, sample_system_input_aad,
};

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
