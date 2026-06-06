use coprocessor_ciphertext_binding::{
    CanonicalSystemCiphertextV1, EnvelopeDecodeError, EnvelopeKind, KeyId, SystemHandleAadV1,
};

#[test]
fn canonical_system_ciphertext_round_trips_through_cbor() {
    let ciphertext = sample_ciphertext();
    let bytes = ciphertext.encode();
    let decoded = CanonicalSystemCiphertextV1::decode(&bytes).expect("decode");
    assert_eq!(decoded, ciphertext);
}

#[test]
fn canonical_system_ciphertext_rejects_wrong_top_level_length() {
    let mut bytes = sample_ciphertext().encode();
    bytes[0] = 0x85;
    let err = CanonicalSystemCiphertextV1::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        EnvelopeDecodeError::WrongLength {
            envelope: EnvelopeKind::System,
            expected: 6,
            actual: 5,
        }
    );
}

#[test]
fn canonical_system_ciphertext_rejects_non_system_aad() {
    let mut ciphertext = sample_ciphertext();
    ciphertext.aad = vec![0x01, 0x02, 0x03];
    let err = CanonicalSystemCiphertextV1::decode(&ciphertext.encode()).unwrap_err();
    assert!(matches!(
        err,
        EnvelopeDecodeError::AadDecode {
            envelope: EnvelopeKind::System,
            ..
        }
    ));
}

fn sample_ciphertext() -> CanonicalSystemCiphertextV1 {
    let aad = SystemHandleAadV1 {
        version: 1,
        chain_id: 1,
        domain_id: coprocessor_ciphertext_binding::DomainId([0x11; 32]),
        handle_id: coprocessor_ciphertext_binding::HandleId([0x22; 32]),
        type_tag: "suint256".to_string(),
        key_id: KeyId([0x33; 32]),
    }
    .encode();

    CanonicalSystemCiphertextV1 {
        key_id: KeyId([0x33; 32]),
        enc: vec![0x44; 48],
        wrapped_key: vec![0x55; 32],
        nonce: [0x66; 12],
        ciphertext: vec![0x77; 96],
        aad,
    }
}
