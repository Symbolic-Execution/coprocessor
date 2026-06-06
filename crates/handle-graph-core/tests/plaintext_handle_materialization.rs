//! Verify that Plaintext Handle ingestion materializes a real
//! `SystemCiphertextV1` envelope bound to a `SystemHandleAadV1`, and that the
//! Public Plaintext Value is not retained as the handle payload.

use coprocessor_ciphertext_binding::{
    self as cbinding, SystemCiphertextV1 as EnvelopeSystemCiphertextV1, SystemHandleAadV1,
};
use coprocessor_handle_graph_core::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DomainId, HandleGraphCore, HandleId,
    HandleKey, HandleState, HandleType, PlaintextHandle, PlaintextMaterializer,
    PublicPlaintextValue,
};

const ACTIVE_KEY_ID: [u8; 32] = [0xAB; 32];
const AAD_VERSION: u8 = 1;
const DOMAIN_SEED: u8 = 9;
const CONTRACT_SEED: u8 = 7;

#[test]
fn materialized_suint256_plaintext_binds_system_handle_aad_v1() {
    let mut core = build_core();
    let handle_key = handle_key(1, 42);
    let event_ref = chain_event_ref(1, 10, 3);

    let _ = core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Suint256,
        PublicPlaintextValue(vec![0xAB, 0xCD]),
    ));

    let (envelope, aad) = decode_ready_envelope(&core, &handle_key);

    assert_eq!(envelope.key_id.0, ACTIVE_KEY_ID);
    assert_eq!(aad.version, AAD_VERSION);
    assert_eq!(aad.chain_id, 1);
    assert_eq!(aad.domain_id.0, bytes32(DOMAIN_SEED));
    assert_eq!(aad.handle_id.0, bytes32(42));
    assert_eq!(aad.type_tag, "suint256");
    assert_eq!(aad.key_id.0, ACTIVE_KEY_ID);
}

#[test]
fn materialized_sbool_plaintext_binds_system_handle_aad_v1() {
    let mut core = build_core();
    let handle_key = handle_key(1, 100);
    let event_ref = chain_event_ref(1, 10, 5);

    let _ = core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Sbool,
        PublicPlaintextValue(vec![0x01]),
    ));

    let (envelope, aad) = decode_ready_envelope(&core, &handle_key);

    assert_eq!(envelope.key_id.0, ACTIVE_KEY_ID);
    assert_eq!(aad.type_tag, "sbool");
    assert_eq!(aad.chain_id, 1);
    assert_eq!(aad.domain_id.0, bytes32(DOMAIN_SEED));
    assert_eq!(aad.handle_id.0, bytes32(100));
    assert_eq!(aad.key_id.0, ACTIVE_KEY_ID);
}

#[test]
fn materialized_envelope_carries_no_public_plaintext_bytes() {
    let mut core = build_core();
    let handle_key = handle_key(1, 42);
    let event_ref = chain_event_ref(1, 10, 3);
    let raw_public_value = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let _ = core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Suint256,
        PublicPlaintextValue(raw_public_value.clone()),
    ));

    let (envelope, _aad) = decode_ready_envelope(&core, &handle_key);

    // The host must not persist the Public Plaintext Value as the handle
    // payload. The envelope's ciphertext slot is reserved for MPC-bound or
    // Enclave-bound bytes, never the raw plaintext that arrived in the event.
    assert!(
        !contains_subsequence(&envelope.ciphertext, &raw_public_value),
        "envelope.ciphertext must not contain the raw Public Plaintext Value bytes"
    );
    assert!(
        !contains_subsequence(&envelope.wrapped_key, &raw_public_value),
        "envelope.wrapped_key must not contain the raw Public Plaintext Value bytes"
    );
    let stored = match &core.canonical_handle(&handle_key).unwrap().state {
        HandleState::Ready {
            system_ciphertext, ..
        } => system_ciphertext.0.clone(),
        other => panic!("expected Ready, got {:?}", other),
    };
    assert!(
        !contains_subsequence(&stored, &raw_public_value),
        "persisted SystemCiphertextV1 bytes must not contain the raw Public Plaintext Value"
    );
}

#[test]
fn materialized_handle_state_carries_non_empty_receipt() {
    let mut core = build_core();
    let handle_key = handle_key(1, 7);
    let event_ref = chain_event_ref(1, 10, 1);

    let _ = core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Suint256,
        PublicPlaintextValue(vec![1, 2, 3]),
    ));

    let record = core.canonical_handle(&handle_key).unwrap();
    match &record.state {
        HandleState::Ready {
            materialization_receipt,
            ..
        } => {
            assert!(
                !materialization_receipt.0.is_empty(),
                "Materialization Receipt must be present and non-empty"
            );
        }
        other => panic!("expected Ready, got {:?}", other),
    }
}

#[test]
fn system_ciphertext_decode_rejects_non_system_handle_aad_kind() {
    let mut core = build_core();
    let handle_key = handle_key(1, 42);
    let event_ref = chain_event_ref(1, 10, 3);

    let _ = core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Suint256,
        PublicPlaintextValue(vec![0xAB, 0xCD]),
    ));

    let (_envelope, aad) = decode_ready_envelope(&core, &handle_key);

    // The AAD encodes "suint256". A consumer that expects "sbool" must
    // detect the mismatch.
    let expected_sbool_type_tag = "sbool";
    assert_ne!(aad.type_tag, expected_sbool_type_tag);

    // A wrong AAD kind must not silently bind to a SystemCiphertextV1
    // envelope.
    let wrong_aad = cbinding::EnclaveAadV1 {
        version: AAD_VERSION,
        chain_id: aad.chain_id,
        domain_id: aad.domain_id,
        request_id: cbinding::RequestId([0; 32]),
        handle_id: aad.handle_id,
        type_tag: aad.type_tag.clone(),
        attestation_digest: cbinding::AttestationDigest([0; 32]),
        key_id: aad.key_id,
    };
    let wrong_envelope = EnvelopeSystemCiphertextV1 {
        key_id: cbinding::KeyId(ACTIVE_KEY_ID),
        enc: vec![0x01; 32],
        wrapped_key: Vec::new(),
        nonce: [0u8; 12],
        ciphertext: Vec::new(),
        aad: wrong_aad.encode(),
    };
    let bytes = wrong_envelope.encode();
    let err = EnvelopeSystemCiphertextV1::decode(&bytes)
        .expect_err("envelope decode must reject AAD kind that does not bind SystemCiphertextV1");
    assert!(matches!(
        err,
        cbinding::EnvelopeDecodeError::AadBindingMismatch { .. }
    ));
}

#[test]
fn materialized_aad_chain_id_tracks_the_handle_key_chain_id() {
    let mut core = build_core();
    let handle_key = handle_key(99, 42);
    let event_ref = chain_event_ref(99, 11, 4);

    let _ = core.apply_chain_event(plaintext_handle_event(
        handle_key,
        event_ref,
        HandleType::Suint256,
        PublicPlaintextValue(vec![0x01]),
    ));

    let (_envelope, aad) = decode_ready_envelope(&core, &handle_key);
    assert_eq!(aad.chain_id, 99);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn build_core() -> HandleGraphCore {
    HandleGraphCore::with_plaintext_materializer(PlaintextMaterializer::new(cbinding::KeyId(
        ACTIVE_KEY_ID,
    )))
}

fn decode_ready_envelope(
    core: &HandleGraphCore,
    handle_key: &HandleKey,
) -> (EnvelopeSystemCiphertextV1, SystemHandleAadV1) {
    let record = core
        .canonical_handle(handle_key)
        .expect("handle should be present");
    let bytes = match &record.state {
        HandleState::Ready {
            system_ciphertext, ..
        } => system_ciphertext.0.clone(),
        other => panic!("expected Ready, got {:?}", other),
    };
    let envelope =
        EnvelopeSystemCiphertextV1::decode(&bytes).expect("SystemCiphertextV1 must decode");
    let aad =
        SystemHandleAadV1::decode(&envelope.aad).expect("AAD bytes must decode as SystemHandle");
    (envelope, aad)
}

fn plaintext_handle_event(
    handle_key: HandleKey,
    event_ref: ChainEventRef,
    handle_type: HandleType,
    public_value: PublicPlaintextValue,
) -> ChainEvent {
    ChainEvent::PlaintextHandle(PlaintextHandle {
        domain_id: DomainId(bytes32(DOMAIN_SEED)),
        handle_key,
        handle_type,
        public_value,
        event_ref,
    })
}

fn handle_key(chain_id: u64, handle_seed: u8) -> HandleKey {
    HandleKey {
        chain_id: ChainId(chain_id),
        contract_address: ContractAddress([CONTRACT_SEED; 20]),
        handle_id: HandleId(bytes32(handle_seed)),
    }
}

fn chain_event_ref(chain_id: u64, block_number: u64, log_index: u32) -> ChainEventRef {
    ChainEventRef {
        chain_id: ChainId(chain_id),
        block_number,
        block_hash: bytes32(11),
        tx_hash: bytes32(12),
        log_index,
    }
}

fn bytes32(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
