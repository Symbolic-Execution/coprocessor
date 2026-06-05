/// Sanitized serde error mapping for MPC config JSON parsing.
///
/// Serde_json error messages are inspected only to classify the failure
/// category; raw message text is never forwarded to error values so offending
/// input fragments (e.g. a public-key string) cannot leak.
use coprocessor_transport_json::JsonParseError;

use super::error::MpcConfigParseError;

pub(super) const MPC_SERDE_ERROR_PREFIX: &str = "__mpc_config_json_error__:";

pub(super) fn map_serde_json_to_mpc_parse_error(err: serde_json::Error) -> MpcConfigParseError {
    let message = err.to_string();
    if let Some(error) = marker_to_mpc_json_error(&message) {
        return MpcConfigParseError::Json(error);
    }
    if let Some(field) = extract_missing_mpc_field(&message) {
        return MpcConfigParseError::Json(JsonParseError::MissingField { field });
    }
    if message.starts_with("unknown field") {
        return MpcConfigParseError::Json(JsonParseError::UnexpectedField);
    }
    if message.starts_with("duplicate field") {
        return MpcConfigParseError::Json(JsonParseError::UnexpectedToken {
            expected: "unique field",
        });
    }
    if message.starts_with("trailing characters") {
        return MpcConfigParseError::Json(JsonParseError::TrailingContent);
    }
    if err.is_eof() {
        return MpcConfigParseError::Json(JsonParseError::UnexpectedEndOfInput {
            expected: "object",
        });
    }
    MpcConfigParseError::Json(JsonParseError::UnexpectedToken { expected: "object" })
}

pub(super) fn field_shape_marker(field: &'static str, expected: &'static str) -> String {
    format!(
        "{MPC_SERDE_ERROR_PREFIX}field_shape:{field}:{}",
        marker_expected(expected)
    )
}

pub(super) fn invalid_unsigned_marker(field: &'static str) -> String {
    format!("{MPC_SERDE_ERROR_PREFIX}invalid_unsigned:{field}")
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

fn marker_to_mpc_json_error(message: &str) -> Option<JsonParseError> {
    let marker = serde_error_marker(message)?;
    let parts: Vec<&str> = marker.split(':').collect();
    match parts.as_slice() {
        ["field_shape", field, expected] => Some(JsonParseError::FieldShape {
            field: known_mpc_field(field)?,
            expected: unmarker_expected(expected),
        }),
        ["invalid_unsigned", field] => Some(JsonParseError::InvalidUnsignedNumber {
            field: known_mpc_field(field)?,
        }),
        _ => None,
    }
}

fn serde_error_marker(message: &str) -> Option<&str> {
    if let Some(marker) = message.strip_prefix(MPC_SERDE_ERROR_PREFIX) {
        return Some(marker.split_whitespace().next().unwrap_or_default());
    }

    if !message.starts_with("invalid type:") {
        return None;
    }

    let expected_marker = format!("expected {MPC_SERDE_ERROR_PREFIX}");
    let start = message.find(&expected_marker)?;
    let marker = &message[start + expected_marker.len()..];
    Some(marker.split_whitespace().next().unwrap_or_default())
}

/// Scan the known MPC config field names against a serde_json missing-field
/// error message. Returns the static field name when matched, or `None` if
/// the message does not name a known field (prevents user-content leakage).
pub(super) fn extract_missing_mpc_field(message: &str) -> Option<&'static str> {
    known_mpc_fields()
        .iter()
        .copied()
        .find(|field| message.starts_with(&format!("missing field `{field}`")))
}

pub(super) fn known_mpc_field(field: &str) -> Option<&'static str> {
    known_mpc_fields()
        .iter()
        .copied()
        .find(|known| *known == field)
}

pub(super) fn known_mpc_fields() -> &'static [&'static str] {
    &[
        "chain_id",
        "domain_id",
        "active_key_id",
        "suite",
        "public_key",
        "approved_enclave_measurement",
    ]
}
