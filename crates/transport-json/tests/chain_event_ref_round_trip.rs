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
fn top_level_string_with_escape_is_rejected_as_wrong_shape() {
    let err = decode_chain_event_ref("\"not\\u002dan\\u002dobject\"").unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::UnexpectedToken { expected: "object" }
    ));
}

#[test]
fn missing_field_is_rejected_with_specific_field_name() {
    let baseline = sample_chain_event_ref();
    let json = format!(
        "{{\"chain_id\":1,\"block_number\":2,\"block_hash\":\"{}\",\"tx_hash\":\"{}\"}}",
        hex(&baseline.block_hash),
        hex(&baseline.tx_hash),
    );
    let err = decode_chain_event_ref(&json).unwrap_err();
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
fn bytes32_field_with_wrong_shape_keeps_field_specific_error() {
    let baseline = sample_chain_event_ref();
    let json = format!(
        "{{\"chain_id\":{},\"block_number\":{},\"block_hash\":1,\"tx_hash\":\"{}\",\"log_index\":{}}}",
        baseline.chain_id.0,
        baseline.block_number,
        hex(&baseline.tx_hash),
        baseline.log_index,
    );
    let err = decode_chain_event_ref(&json).unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::FieldShape {
            field: "block_hash",
            expected: "string",
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
fn trailing_escaped_string_after_object_is_rejected_as_trailing_content() {
    let baseline = sample_chain_event_ref();
    let json = format!(
        "{} \"trailing\\u002dcontent\"",
        encode_chain_event_ref(&baseline)
    );
    let err = decode_chain_event_ref(&json).unwrap_err();
    assert!(matches!(err, JsonParseError::TrailingContent));
}

#[test]
fn duplicate_field_uses_serde_struct_behavior_without_duplicate_field_variant() {
    // Serde's struct deserializer rejects duplicate keys. The transport no
    // longer exposes the hand-rolled DuplicateField variant on this path.
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
    let err = decode_chain_event_ref(&json).unwrap_err();
    assert!(matches!(
        err,
        JsonParseError::UnexpectedToken {
            expected: "unique field"
        }
    ));
}

#[test]
fn escape_sequence_in_hex_field_is_rejected_before_hex_validation() {
    let baseline = sample_chain_event_ref();
    let escaped_valid_hex = format!("0x\\u0061{}", "a".repeat(63));
    let json = format!(
        "{{\"chain_id\":{},\"block_number\":{},\"block_hash\":\"{}\",\"tx_hash\":\"{}\",\"log_index\":{}}}",
        baseline.chain_id.0,
        baseline.block_number,
        escaped_valid_hex,
        hex(&baseline.tx_hash),
        baseline.log_index,
    );
    let err = decode_chain_event_ref(&json).unwrap_err();
    assert!(matches!(err, JsonParseError::UnsupportedStringEscape));
}

#[test]
fn escape_sequence_in_object_key_is_rejected() {
    let baseline = sample_chain_event_ref();
    let json = format!(
        "{{\"chain\\u005fid\":{},\"block_number\":{},\"block_hash\":\"{}\",\"tx_hash\":\"{}\",\"log_index\":{}}}",
        baseline.chain_id.0,
        baseline.block_number,
        hex(&baseline.block_hash),
        hex(&baseline.tx_hash),
        baseline.log_index,
    );
    let err = decode_chain_event_ref(&json).unwrap_err();
    assert!(matches!(err, JsonParseError::UnsupportedStringEscape));
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::from("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
