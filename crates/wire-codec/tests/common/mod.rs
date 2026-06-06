#![allow(dead_code)]

use coprocessor_ciphertext_binding::{
    AttestationDigest as BindingAttestationDigest, ContractAddress as BindingContractAddress,
    DomainId as BindingDomainId, EnclaveAadV1, EnclaveCiphertextV1, HandleId as BindingHandleId,
    KeyId, ReaderAadV1, ReaderCiphertextV1, ReaderId, RequestId, SystemCiphertextV1,
    SystemHandleAadV1, SystemInputAadV1,
};
use coprocessor_handle_graph_core::{ChainEventRef, ChainId};

pub fn fill_32(byte: u8) -> [u8; 32] {
    [byte; 32]
}

pub fn fill_20(byte: u8) -> [u8; 20] {
    [byte; 20]
}

pub fn sample_chain_event_ref() -> ChainEventRef {
    ChainEventRef {
        chain_id: ChainId(11_155_111),
        block_number: 18_000_001,
        block_hash: fill_32(0x12),
        tx_hash: fill_32(0x34),
        log_index: 7,
    }
}

pub fn sample_system_input_aad() -> SystemInputAadV1 {
    SystemInputAadV1 {
        version: 1,
        chain_id: 11_155_111,
        domain_id: BindingDomainId(fill_32(0xAA)),
        contract: BindingContractAddress(fill_20(0xCC)),
        type_tag: "suint256".to_string(),
        key_id: KeyId(fill_32(0x11)),
    }
}

pub fn sample_system_handle_aad() -> SystemHandleAadV1 {
    SystemHandleAadV1 {
        version: 1,
        chain_id: 11_155_111,
        domain_id: BindingDomainId(fill_32(0xAA)),
        handle_id: BindingHandleId(fill_32(0xBB)),
        type_tag: "sbool".to_string(),
        key_id: KeyId(fill_32(0x11)),
    }
}

pub fn sample_enclave_aad() -> EnclaveAadV1 {
    EnclaveAadV1 {
        version: 1,
        chain_id: 11_155_111,
        domain_id: BindingDomainId(fill_32(0xAA)),
        request_id: RequestId(fill_32(0x77)),
        handle_id: BindingHandleId(fill_32(0xBB)),
        type_tag: "suint256".to_string(),
        attestation_digest: BindingAttestationDigest(fill_32(0xEE)),
        key_id: KeyId(fill_32(0x11)),
    }
}

pub fn sample_reader_aad() -> ReaderAadV1 {
    ReaderAadV1 {
        version: 1,
        chain_id: 11_155_111,
        domain_id: BindingDomainId(fill_32(0xAA)),
        request_id: RequestId(fill_32(0x77)),
        handle_id: BindingHandleId(fill_32(0xBB)),
        reader_id: ReaderId(fill_32(0x44)),
        type_tag: "sbool".to_string(),
        key_id: KeyId(fill_32(0x11)),
    }
}

pub fn sample_system_envelope() -> SystemCiphertextV1 {
    SystemCiphertextV1 {
        key_id: KeyId(fill_32(0x11)),
        enc: vec![0x66; 32],
        wrapped_key: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        nonce: [0x77; 12],
        ciphertext: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20, 0x30],
        aad: sample_system_input_aad().encode(),
    }
}

pub fn sample_enclave_envelope() -> EnclaveCiphertextV1 {
    EnclaveCiphertextV1 {
        version: 1,
        aad: sample_enclave_aad().encode(),
        wrapped_key: vec![0x10; 32],
        ciphertext: vec![0x20; 48],
    }
}

pub fn sample_reader_envelope() -> ReaderCiphertextV1 {
    ReaderCiphertextV1 {
        version: 1,
        aad: sample_reader_aad().encode(),
        wrapped_key: vec![0x77; 16],
        ciphertext: vec![0x88; 64],
    }
}
