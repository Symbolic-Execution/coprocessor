//! Round-trip [`ChainEventRef`] through JSON and verify every field-level
//! decode failure surfaces a stable [`JsonParseError`] variant. The encoded
//! object has lowercase hex for the two `bytes32` fields and plain integers
//! for the three numeric fields.

use coprocessor_handle_graph_core::{ChainEventRef, ChainId};
use coprocessor_transport_json::{
    decode_chain_event_ref, encode_chain_event_ref, HexDecodeError, JsonParseError,
};

mod common;

use common::{fill_32, sample_chain_event_ref};

#[test]
fn chain_event_ref_round_trips_through_json_preserving_every_field() {
    let value = sample_chain_event_ref();
    let json = encode_chain_event_ref(&value);
    let decoded = decode_chain_event_ref(&json).expect("decode");
    assert_eq!(decoded, value);
}

#[test]
fn encoded_chain_event_ref_uses_lowercase_hex_for_bytes32_fields() {
    let json = encode_chain_event_ref(&sample_chain_event_ref());
    assert!(json.contains(
        "\"block_hash\":\"0x1212121212121212121212121212121212121212121212121212121212121212\""
    ));
    assert!(json.contains(
        "\"tx_hash\":\"0x3434343434343434343434343434343434343434343434343434343434343434\""
    ));
}

#[test]
fn encoded_chain_event_ref_emits_unsigned_integer_for_numeric_fields() {
    let json = encode_chain_event_ref(&sample_chain_event_ref());
    assert!(json.contains("\"chain_id\":11155111"));
    assert!(json.contains("\"block_number\":18000001"));
    assert!(json.contains("\"log_index\":7"));
}

#[test]
fn fields_in_any_order_decode_into_the_same_chain_event_ref() {
    let baseline = sample_chain_event_ref();
    let reordered = format!(
        "{{\"log_index\":{},\"tx_hash\":\"{}\",\"block_hash\":\"{}\",\"block_number\":{},\"chain_id\":{}}}",
        baseline.log_index,
        hex(&baseline.tx_hash),
        hex(&baseline.block_hash),
        baseline.block_number,
        baseline.chain_id.0,
    );
    let decoded = decode_chain_event_ref(&reordered).expect("decode");
    assert_eq!(decoded, baseline);
}

#[test]
fn whitespace_and_pretty_printing_are_accepted() {
    let baseline = sample_chain_event_ref();
    let pretty = format!(
        "{{\n  \"chain_id\": {},\n  \"block_number\": {},\n  \"block_hash\": \"{}\",\n  \"tx_hash\": \"{}\",\n  \"log_index\": {}\n}}",
        baseline.chain_id.0,
        baseline.block_number,
        hex(&baseline.block_hash),
        hex(&baseline.tx_hash),
        baseline.log_index,
    );
    let decoded = decode_chain_event_ref(&pretty).expect("decode");
    assert_eq!(decoded, baseline);
}

#[test]
fn empty_input_is_rejected_with_unexpected_end_of_input() {
    let err = decode_chain_event_ref("").unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::UnexpectedEndOfInput { expected: "object" }
    ));
}

#[test]
fn top_level_array_is_rejected_with_unexpected_token() {
    let err = decode_chain_event_ref("[]").unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::UnexpectedToken { expected: "object" }
    ));
}

#[test]
fn missing_field_is_rejected_with_specific_field_name() {
    let json = "{\"chain_id\":1,\"block_number\":2,\"block_hash\":\"0x00\",\"tx_hash\":\"0x00\"}";
    let err = decode_chain_event_ref(json).unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::MissingField { field: "log_index" }
    ));
}

#[test]
fn unexpected_extra_field_is_rejected() {
    let baseline = sample_chain_event_ref();
    let json = format!(
        "{{\"chain_id\":{},\"block_number\":{},\"block_hash\":\"{}\",\"tx_hash\":\"{}\",\"log_index\":{},\"extra\":1}}",
        baseline.chain_id.0,
        baseline.block_number,
        hex(&baseline.block_hash),
        hex(&baseline.tx_hash),
        baseline.log_index,
    );
    let err = decode_chain_event_ref(&json).unwrap_err();
    assert!(matches!(err, JsonParseError::UnexpectedField));
}

#[test]
fn wrong_field_shape_is_rejected_with_expected_kind() {
    let json = "{\"chain_id\":\"not-a-number\",\"block_number\":1,\"block_hash\":\"0x00\",\"tx_hash\":\"0x00\",\"log_index\":1}";
    let err = decode_chain_event_ref(json).unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::FieldShape {
            field: "chain_id",
            expected: "unsigned integer",
        }
    ));
}

#[test]
fn malformed_bytes32_field_surfaces_invalid_hex_error_with_field_name() {
    let baseline = sample_chain_event_ref();
    // Replace block_hash with a hex value that is one byte too short.
    let json = format!(
        "{{\"chain_id\":{},\"block_number\":{},\"block_hash\":\"0x{}\",\"tx_hash\":\"{}\",\"log_index\":{}}}",
        baseline.chain_id.0,
        baseline.block_number,
        "ab".repeat(31),
        hex(&baseline.tx_hash),
        baseline.log_index,
    );
    let err = decode_chain_event_ref(&json).unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::InvalidHex {
            field: "block_hash",
            error: HexDecodeError::WrongByteLength {
                field: "block_hash",
                expected: 32,
                actual: 31,
            },
        }
    ));
}

#[test]
fn log_index_overflow_is_rejected_with_integer_overflow() {
    let baseline = sample_chain_event_ref();
    let json = format!(
        "{{\"chain_id\":{},\"block_number\":{},\"block_hash\":\"{}\",\"tx_hash\":\"{}\",\"log_index\":{}}}",
        baseline.chain_id.0,
        baseline.block_number,
        hex(&baseline.block_hash),
        hex(&baseline.tx_hash),
        u64::from(u32::MAX) + 1,
    );
    let err = decode_chain_event_ref(&json).unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::IntegerOverflow {
            field: "log_index",
            expected: "u32",
        }
    ));
}

#[test]
fn maximum_u64_chain_id_round_trips() {
    let value = ChainEventRef {
        chain_id: ChainId(u64::MAX),
        block_number: u64::MAX,
        block_hash: fill_32(0xFF),
        tx_hash: fill_32(0xFF),
        log_index: u32::MAX,
    };
    let json = encode_chain_event_ref(&value);
    let decoded = decode_chain_event_ref(&json).expect("decode");
    assert_eq!(decoded, value);
}

#[test]
fn signed_or_decimal_number_is_rejected_with_invalid_unsigned_number() {
    // serde_json parses -1 as a valid JSON Number, so rejection happens at
    // the u64 conversion step rather than at the field-shape level.
    let json = "{\"chain_id\":-1,\"block_number\":1,\"block_hash\":\"0x00\",\"tx_hash\":\"0x00\",\"log_index\":1}";
    let err = decode_chain_event_ref(json).unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::InvalidUnsignedNumber { field: "chain_id" }
    ));
}

#[test]
fn leading_zero_number_is_rejected() {
    // serde_json rejects leading zeros at the JSON syntax level (per the JSON
    // spec), so the error surfaces as UnexpectedToken rather than the
    // field-specific InvalidUnsignedNumber the hand-rolled parser produced.
    let json = "{\"chain_id\":01,\"block_number\":1,\"block_hash\":\"0x00\",\"tx_hash\":\"0x00\",\"log_index\":1}";
    let err = decode_chain_event_ref(json).unwrap_err();
    assert!(matches!(err, JsonParseError::UnexpectedToken { .. }));
}

#[test]
fn trailing_content_after_object_is_rejected() {
    let baseline = sample_chain_event_ref();
    let json = format!("{}, garbage", encode_chain_event_ref(&baseline));
    let err = decode_chain_event_ref(&json).unwrap_err();
    assert!(matches!(err, JsonParseError::TrailingContent));
}

#[test]
fn duplicate_field_uses_last_value_serde_standard_behavior() {
    // serde_json uses last-wins for duplicate keys (serde-standard behavior).
    // The hand-rolled parser previously rejected duplicates with DuplicateField.
    // Behavior change: duplicate fields no longer produce an error; the second
    // occurrence wins, so the decoded chain_id is the second value.
    let baseline = sample_chain_event_ref();
    let different_chain_id = baseline.chain_id.0 + 1;
    let json = format!(
        "{{\"chain_id\":{},\"chain_id\":{},\"block_number\":{},\"block_hash\":\"{}\",\"tx_hash\":\"{}\",\"log_index\":{}}}",
        baseline.chain_id.0,
        different_chain_id,
        baseline.block_number,
        hex(&baseline.block_hash),
        hex(&baseline.tx_hash),
        baseline.log_index,
    );
    let decoded = decode_chain_event_ref(&json).expect("serde last-wins decode");
    assert_eq!(decoded.chain_id.0, different_chain_id);
}

#[test]
fn escape_sequence_in_hex_field_is_rejected_as_invalid_hex() {
    // serde_json decodes   to the null character, so the field value
    // "0x\u{0}" passes JSON parsing but fails hex validation. The error
    // surfaces as InvalidHex rather than UnsupportedStringEscape (a
    // hand-rolled-parser-specific variant).
    let json = "{\"chain_id\":1,\"block_number\":1,\"block_hash\":\"0x\\u0000\",\"tx_hash\":\"0x00\",\"log_index\":1}";
    let err = decode_chain_event_ref(json).unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::InvalidHex {
            field: "block_hash",
            ..
        }
    ));
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::from("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
