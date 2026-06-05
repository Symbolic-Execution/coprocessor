//! Hex round-trip for every Coprocessor identifier that crosses the JSON
//! boundary. Each identifier encodes to lowercase `0x`-prefixed hex of fixed
//! width and decodes back to the same bytes; encoding mismatches surface as
//! [`HexDecodeError`] variants without leaking the offending text.

use coprocessor_ciphertext_binding::{
    AttestationDigest as BindingAttestationDigest, ContractAddress as BindingContractAddress,
    DomainId as BindingDomainId, HandleId as BindingHandleId, KeyId, ReaderId, RequestId,
};
use coprocessor_handle_graph_core::{
    ContractAddress as CoreContractAddress, DomainId as CoreDomainId, HandleId as CoreHandleId,
};
use coprocessor_wire_codec::{
    AttestationDigestHex, BlockHashHex, ContractAddressHex, DomainIdHex, HandleIdHex,
    HexDecodeError, HexIdentifier, KeyIdHex, ReaderIdHex, RequestIdHex, TxHashHex,
};

mod common;

use common::{fill_20, fill_32};

#[test]
fn handle_id_round_trips_through_lowercase_hex() {
    let id = HandleIdHex(fill_32(0xAB));
    let hex = id.to_hex();
    assert_eq!(hex.len(), 2 + 64);
    assert!(hex.starts_with("0x"));
    assert!(hex.bytes().skip(2).all(|b| b == b'a' || b == b'b'));
    let decoded = HandleIdHex::from_hex(&hex).expect("decode");
    assert_eq!(decoded, id);
}

#[test]
fn contract_address_round_trips_at_twenty_bytes() {
    let address = ContractAddressHex(fill_20(0xC1));
    let hex = address.to_hex();
    assert_eq!(hex.len(), 2 + 40);
    let decoded = ContractAddressHex::from_hex(&hex).expect("decode");
    assert_eq!(decoded, address);
}

#[test]
fn every_thirty_two_byte_identifier_round_trips() {
    let domain = DomainIdHex(fill_32(0x01));
    let request = RequestIdHex(fill_32(0x02));
    let reader = ReaderIdHex(fill_32(0x03));
    let key = KeyIdHex(fill_32(0x04));
    let attestation = AttestationDigestHex(fill_32(0x05));
    let block_hash = BlockHashHex(fill_32(0x06));
    let tx_hash = TxHashHex(fill_32(0x07));

    assert_eq!(DomainIdHex::from_hex(&domain.to_hex()).unwrap(), domain);
    assert_eq!(RequestIdHex::from_hex(&request.to_hex()).unwrap(), request);
    assert_eq!(ReaderIdHex::from_hex(&reader.to_hex()).unwrap(), reader);
    assert_eq!(KeyIdHex::from_hex(&key.to_hex()).unwrap(), key);
    assert_eq!(
        AttestationDigestHex::from_hex(&attestation.to_hex()).unwrap(),
        attestation
    );
    assert_eq!(
        BlockHashHex::from_hex(&block_hash.to_hex()).unwrap(),
        block_hash
    );
    assert_eq!(TxHashHex::from_hex(&tx_hash.to_hex()).unwrap(), tx_hash);
}

#[test]
fn encoded_hex_uses_only_lowercase_digits() {
    let id = HandleIdHex([0xAB; 32]);
    let hex = id.to_hex();
    for byte in hex.bytes().skip(2) {
        assert!(
            matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
            "byte 0x{byte:02x} must be a lowercase hex digit",
        );
    }
}

#[test]
fn missing_prefix_is_rejected() {
    let raw = "cccccccccccccccccccccccccccccccccccccccc";
    let err = ContractAddressHex::from_hex(raw).unwrap_err();
    assert!(matches!(
        err,
        HexDecodeError::MissingPrefix {
            field: "contract_address"
        }
    ));
}

#[test]
fn uppercase_digits_are_rejected_for_canonicality() {
    let raw = "0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD";
    let err = HandleIdHex::from_hex(raw).unwrap_err();
    assert!(matches!(
        err,
        HexDecodeError::UppercaseDigit { field: "handle_id" }
    ));
}

#[test]
fn non_hex_digit_in_payload_is_rejected() {
    let mut raw = String::from("0x");
    raw.push_str(&"a".repeat(63));
    raw.push('z');
    let err = HandleIdHex::from_hex(&raw).unwrap_err();
    assert!(matches!(
        err,
        HexDecodeError::InvalidDigit { field: "handle_id" }
    ));
}

#[test]
fn odd_number_of_hex_digits_is_rejected() {
    let raw = String::from("0xabc");
    let err = HandleIdHex::from_hex(&raw).unwrap_err();
    assert!(matches!(
        err,
        HexDecodeError::OddLength {
            field: "handle_id",
            actual_chars: 3,
        }
    ));
}

#[test]
fn wrong_byte_length_for_identifier_is_rejected() {
    // 30 bytes instead of 32 for a HandleId.
    let raw = format!("0x{}", "a".repeat(60));
    let err = HandleIdHex::from_hex(&raw).unwrap_err();
    assert!(matches!(
        err,
        HexDecodeError::WrongByteLength {
            field: "handle_id",
            expected: 32,
            actual: 30,
        }
    ));
}

#[test]
fn conversions_to_and_from_underlying_handle_graph_types_preserve_bytes() {
    let core_handle = CoreHandleId(fill_32(0x42));
    let hex: HandleIdHex = core_handle.into();
    let round_trip: CoreHandleId = hex.into();
    assert_eq!(round_trip, core_handle);

    let core_address = CoreContractAddress(fill_20(0x42));
    let hex: ContractAddressHex = core_address.into();
    let round_trip: CoreContractAddress = hex.into();
    assert_eq!(round_trip, core_address);

    let core_domain = CoreDomainId(fill_32(0x42));
    let hex: DomainIdHex = core_domain.into();
    let round_trip: CoreDomainId = hex.into();
    assert_eq!(round_trip, core_domain);
}

#[test]
fn conversions_to_and_from_binding_identifier_types_preserve_bytes() {
    let binding_handle = BindingHandleId(fill_32(0x99));
    let hex: HandleIdHex = binding_handle.into();
    let round_trip: BindingHandleId = hex.into();
    assert_eq!(round_trip, binding_handle);

    let binding_address = BindingContractAddress(fill_20(0x99));
    let hex: ContractAddressHex = binding_address.into();
    let round_trip: BindingContractAddress = hex.into();
    assert_eq!(round_trip, binding_address);

    let binding_domain = BindingDomainId(fill_32(0x99));
    let hex: DomainIdHex = binding_domain.into();
    let round_trip: BindingDomainId = hex.into();
    assert_eq!(round_trip, binding_domain);

    let request = RequestId(fill_32(0x99));
    let hex: RequestIdHex = request.into();
    let round_trip: RequestId = hex.into();
    assert_eq!(round_trip, request);

    let reader = ReaderId(fill_32(0x99));
    let hex: ReaderIdHex = reader.into();
    let round_trip: ReaderId = hex.into();
    assert_eq!(round_trip, reader);

    let key = KeyId(fill_32(0x99));
    let hex: KeyIdHex = key.into();
    let round_trip: KeyId = hex.into();
    assert_eq!(round_trip, key);

    let attestation = BindingAttestationDigest(fill_32(0x99));
    let hex: AttestationDigestHex = attestation.into();
    let round_trip: BindingAttestationDigest = hex.into();
    assert_eq!(round_trip, attestation);
}
