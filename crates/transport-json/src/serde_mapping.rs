/// Sanitized serde error mapping and marker helpers for JSON transport.
///
/// The serde_json error message is intentionally discarded or inspected
/// only to classify the failure category; raw message text is never
/// forwarded to error values so offending input fragments (tokens, field
/// values) cannot leak.

use super::hex_codec::HexDecodeError;
use super::json_codec::JsonParseError;

pub(super) const SERDE_ERROR_PREFIX: &str = "__transport_json_error__:";

pub(super) fn field_shape_marker(field: &'static str, expected: &'static str) -> String {
    format!(
        "{SERDE_ERROR_PREFIX}field_shape:{field}:{}",
        marker_expected(expected)
    )
}

pub(super) fn invalid_unsigned_marker(field: &'static str) -> String {
    format!("{SERDE_ERROR_PREFIX}invalid_unsigned:{field}")
}

pub(super) fn integer_overflow_marker(field: &'static str, expected: &'static str) -> String {
    format!("{SERDE_ERROR_PREFIX}integer_overflow:{field}:{expected}")
}

pub(super) fn hex_error_marker(error: HexDecodeError) -> String {
    match error {
        HexDecodeError::MissingPrefix { field } => {
            format!("{SERDE_ERROR_PREFIX}hex:missing_prefix:{field}")
        }
        HexDecodeError::OddLength {
            field,
            actual_chars,
        } => format!("{SERDE_ERROR_PREFIX}hex:odd_length:{field}:{actual_chars}"),
        HexDecodeError::UppercaseDigit { field } => {
            format!("{SERDE_ERROR_PREFIX}hex:uppercase_digit:{field}")
        }
        HexDecodeError::InvalidDigit { field } => {
            format!("{SERDE_ERROR_PREFIX}hex:invalid_digit:{field}")
        }
        HexDecodeError::WrongByteLength {
            field,
            expected,
            actual,
        } => format!("{SERDE_ERROR_PREFIX}hex:wrong_byte_length:{field}:{expected}:{actual}"),
    }
}

fn marker_expected(expected: &'static str) -> &'static str {
    match expected {
        "unsigned integer" => "unsigned_integer",
        "string" => "string",
        other => other,
    }
}

fn unmarker_expected(expected: &str) -> &'static str {
    match expected {
        "unsigned_integer" => "unsigned integer",
        "string" => "string",
        _ => "value",
    }
}

pub(super) fn map_serde_json_to_parse_error(err: serde_json::Error) -> JsonParseError {
    let message = err.to_string();
    if let Some(error) = marker_to_parse_error(&message) {
        return error;
    }
    if let Some(field) = missing_field_from_serde_error(&message) {
        return JsonParseError::MissingField { field };
    }
    if message.starts_with("unknown field") {
        return JsonParseError::UnexpectedField;
    }
    if message.starts_with("duplicate field") {
        return JsonParseError::UnexpectedToken {
            expected: "unique field",
        };
    }
    if err.is_data() {
        return JsonParseError::UnexpectedToken { expected: "object" };
    }
    if err.is_eof() {
        JsonParseError::UnexpectedEndOfInput { expected: "object" }
    } else {
        JsonParseError::UnexpectedToken {
            expected: "valid JSON",
        }
    }
}

fn marker_to_parse_error(message: &str) -> Option<JsonParseError> {
    let marker = serde_error_marker(message)?;
    let parts: Vec<&str> = marker.split(':').collect();
    match parts.as_slice() {
        ["field_shape", field, expected] => Some(JsonParseError::FieldShape {
            field: known_field(field)?,
            expected: unmarker_expected(expected),
        }),
        ["invalid_unsigned", field] => Some(JsonParseError::InvalidUnsignedNumber {
            field: known_field(field)?,
        }),
        ["integer_overflow", field, expected] => Some(JsonParseError::IntegerOverflow {
            field: known_field(field)?,
            expected: match *expected {
                "u32" => "u32",
                _ => "integer",
            },
        }),
        ["hex", "missing_prefix", field] => {
            let field = known_field(field)?;
            Some(JsonParseError::InvalidHex {
                field,
                error: HexDecodeError::MissingPrefix { field },
            })
        }
        ["hex", "odd_length", field, actual_chars] => {
            let field = known_field(field)?;
            Some(JsonParseError::InvalidHex {
                field,
                error: HexDecodeError::OddLength {
                    field,
                    actual_chars: actual_chars.parse().ok()?,
                },
            })
        }
        ["hex", "uppercase_digit", field] => {
            let field = known_field(field)?;
            Some(JsonParseError::InvalidHex {
                field,
                error: HexDecodeError::UppercaseDigit { field },
            })
        }
        ["hex", "invalid_digit", field] => {
            let field = known_field(field)?;
            Some(JsonParseError::InvalidHex {
                field,
                error: HexDecodeError::InvalidDigit { field },
            })
        }
        ["hex", "wrong_byte_length", field, expected, actual] => {
            let field = known_field(field)?;
            Some(JsonParseError::InvalidHex {
                field,
                error: HexDecodeError::WrongByteLength {
                    field,
                    expected: expected.parse().ok()?,
                    actual: actual.parse().ok()?,
                },
            })
        }
        _ => None,
    }
}

fn serde_error_marker(message: &str) -> Option<&str> {
    if let Some(marker) = message.strip_prefix(SERDE_ERROR_PREFIX) {
        return Some(marker.split_whitespace().next().unwrap_or_default());
    }

    if !message.starts_with("invalid type:") {
        return None;
    }

    let expected_marker = format!("expected {SERDE_ERROR_PREFIX}");
    let start = message.find(&expected_marker)?;
    let marker = &message[start + expected_marker.len()..];
    Some(marker.split_whitespace().next().unwrap_or_default())
}

pub(super) fn missing_field_from_serde_error(message: &str) -> Option<&'static str> {
    known_fields()
        .iter()
        .copied()
        .find(|field| message.starts_with(&format!("missing field `{field}`")))
}

pub(super) fn known_field(field: &str) -> Option<&'static str> {
    known_fields().iter().copied().find(|known| *known == field)
}

pub(super) fn known_fields() -> &'static [&'static str] {
    &[
        "chain_id",
        "block_number",
        "block_hash",
        "tx_hash",
        "log_index",
        "handle_id",
        "contract_address",
        "domain_id",
        "request_id",
        "reader_id",
        "key_id",
        "attestation_digest",
    ]
}
