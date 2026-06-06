#![allow(dead_code)]

use coprocessor_ciphertext_binding::{
    AttestationDigest, ContractAddress, DomainId, EnclaveAadV1, EnclaveCiphertextV1, HandleId,
    KeyId, ReaderAadV1, ReaderCiphertextV1, ReaderId, RequestId, SystemCiphertextV1,
    SystemHandleAadV1, SystemInputAadV1,
};

pub const DIRECT_ARRAY_HEADER: u8 = 0x80;

fn fill(byte: u8) -> [u8; 32] {
    [byte; 32]
}

pub fn sample_system_input_aad() -> SystemInputAadV1 {
    SystemInputAadV1 {
        version: 1,
        chain_id: 11155111,
        domain_id: DomainId(fill(0xAA)),
        contract: ContractAddress([0xCC; 20]),
        type_tag: "suint256".to_string(),
        key_id: KeyId(fill(0x11)),
    }
}

pub fn sample_system_handle_aad() -> SystemHandleAadV1 {
    SystemHandleAadV1 {
        version: 1,
        chain_id: 11155111,
        domain_id: DomainId(fill(0xAA)),
        handle_id: HandleId(fill(0xBB)),
        type_tag: "sbool".to_string(),
        key_id: KeyId(fill(0x11)),
    }
}

pub fn sample_enclave_aad() -> EnclaveAadV1 {
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

pub fn sample_reader_aad() -> ReaderAadV1 {
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

pub fn sample_system_envelope() -> SystemCiphertextV1 {
    SystemCiphertextV1 {
        key_id: KeyId(fill(0x11)),
        enc: vec![0x99; 32],
        wrapped_key: vec![0x01, 0x02, 0x03],
        nonce: [0x77; 12],
        ciphertext: vec![0xAA, 0xBB, 0xCC],
        aad: sample_system_input_aad().encode(),
    }
}

pub fn sample_enclave_envelope() -> EnclaveCiphertextV1 {
    EnclaveCiphertextV1 {
        version: 1,
        aad: sample_enclave_aad().encode(),
        wrapped_key: vec![0x01, 0x02, 0x03],
        ciphertext: vec![0xAA, 0xBB, 0xCC],
    }
}

pub fn sample_reader_envelope() -> ReaderCiphertextV1 {
    ReaderCiphertextV1 {
        version: 1,
        aad: sample_reader_aad().encode(),
        wrapped_key: vec![0x01, 0x02, 0x03],
        ciphertext: vec![0xAA, 0xBB, 0xCC],
    }
}
