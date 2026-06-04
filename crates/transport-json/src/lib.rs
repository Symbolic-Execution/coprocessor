//! JSON transport encoders and decoders for Coprocessor-facing payload shapes.
//!
//! Binary identifiers (`HandleId`, `ContractAddress`, `DomainId`, `RequestId`,
//! `ReaderId`, `KeyId`, `AttestationDigest`, and the `bytes32` fields inside
//! [`ChainEventRefJson`]) round-trip through lowercase `0x`-prefixed hex. The
//! three ciphertext envelopes (`SystemCiphertextV1`, `EnclaveCiphertextV1`,
//! `ReaderCiphertextV1`) round-trip as base64-encoded canonical CBOR bytes
//! produced by [`coprocessor_ciphertext_binding`], so the binary format on the
//! wire is owned by the ciphertext-binding spec rather than reinvented here.
//!
//! Decoders only ever produce non-secret diagnostic errors. Errors name the
//! field that failed and the expected shape, but never include payload bytes,
//! key material, or plaintext.

use coprocessor_ciphertext_binding::{
    AttestationDigest as BindingAttestationDigest, ContractAddress as BindingContractAddress,
    DomainId as BindingDomainId, EnclaveCiphertextV1, EnvelopeDecodeError,
    HandleId as BindingHandleId, KeyId, ReaderCiphertextV1, ReaderId, RequestId,
    SystemCiphertextV1,
};
use coprocessor_handle_graph_core::{
    ChainEventRef, ChainId, ContractAddress as CoreContractAddress, DomainId as CoreDomainId,
    HandleId as CoreHandleId,
};
use serde::{
    de::{self, Error as DeError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;
use std::marker::PhantomData;

mod base64_codec;
mod hex_codec;
mod json_codec;

pub use hex_codec::{
    decode_lower as decode_hex_lower, decode_lower_variable as decode_hex_lower_variable,
    HexDecodeError,
};
pub use json_codec::{parse_object, JsonObject, JsonParseError};

// ---------------------------------------------------------------------------
// Hex round-trip for fixed-byte identifiers
//
// Every Coprocessor-facing identifier carried as a byte string crosses the JSON
// boundary as a lowercase `0x`-prefixed hex string of the right fixed length.
// One trait keeps the wire shape identical across the eight identifier types
// without forcing callers to remember each one's byte width.
// ---------------------------------------------------------------------------

/// A fixed-length binary identifier that travels across the JSON boundary as a
/// lowercase `0x`-prefixed hex string. The trait exists so the per-type hex
/// codec is one line per identifier — adding a new identifier means picking
/// `LEN` and naming the type.
pub trait HexIdentifier: Sized {
    const LEN: usize;
    const FIELD: &'static str;

    fn to_bytes(&self) -> &[u8];
    fn from_bytes(bytes: Vec<u8>) -> Self;

    fn to_hex(&self) -> String {
        hex_codec::encode_lower(self.to_bytes())
    }

    fn from_hex(text: &str) -> Result<Self, HexDecodeError> {
        let bytes = hex_codec::decode_lower(text, Self::FIELD, Self::LEN)?;
        Ok(Self::from_bytes(bytes))
    }
}

macro_rules! hex_identifier {
    ($wrapper:ident, $inner:ty, $len:expr, $field:expr) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $wrapper(pub $inner);

        impl HexIdentifier for $wrapper {
            const LEN: usize = $len;
            const FIELD: &'static str = $field;

            fn to_bytes(&self) -> &[u8] {
                &self.0
            }

            fn from_bytes(bytes: Vec<u8>) -> Self {
                let mut out = [0u8; $len];
                out.copy_from_slice(&bytes);
                Self(out)
            }
        }

        impl Serialize for $wrapper {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $wrapper {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_str(HexIdentifierVisitor::<Self>::new())
            }
        }
    };
}

hex_identifier!(HandleIdHex, [u8; 32], 32, "handle_id");
hex_identifier!(ContractAddressHex, [u8; 20], 20, "contract_address");
hex_identifier!(DomainIdHex, [u8; 32], 32, "domain_id");
hex_identifier!(RequestIdHex, [u8; 32], 32, "request_id");
hex_identifier!(ReaderIdHex, [u8; 32], 32, "reader_id");
hex_identifier!(KeyIdHex, [u8; 32], 32, "key_id");
hex_identifier!(AttestationDigestHex, [u8; 32], 32, "attestation_digest");
hex_identifier!(BlockHashHex, [u8; 32], 32, "block_hash");
hex_identifier!(TxHashHex, [u8; 32], 32, "tx_hash");

// Conversions to/from the underlying domain types so callers do not have to
// re-type the bytes when crossing the JSON boundary.

macro_rules! hex_identifier_conversion {
    ($domain:ty, $wrapper:ty) => {
        impl From<$domain> for $wrapper {
            fn from(value: $domain) -> Self {
                Self(value.0)
            }
        }

        impl From<$wrapper> for $domain {
            fn from(value: $wrapper) -> Self {
                Self(value.0)
            }
        }
    };
}

hex_identifier_conversion!(CoreHandleId, HandleIdHex);
hex_identifier_conversion!(BindingHandleId, HandleIdHex);
hex_identifier_conversion!(CoreContractAddress, ContractAddressHex);
hex_identifier_conversion!(BindingContractAddress, ContractAddressHex);
hex_identifier_conversion!(CoreDomainId, DomainIdHex);
hex_identifier_conversion!(BindingDomainId, DomainIdHex);
hex_identifier_conversion!(RequestId, RequestIdHex);
hex_identifier_conversion!(ReaderId, ReaderIdHex);
hex_identifier_conversion!(KeyId, KeyIdHex);
hex_identifier_conversion!(BindingAttestationDigest, AttestationDigestHex);

struct HexIdentifierVisitor<T> {
    _marker: PhantomData<T>,
}

impl<T> HexIdentifierVisitor<T> {
    fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<T> Visitor<'_> for HexIdentifierVisitor<T>
where
    T: HexIdentifier,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&field_shape_marker(T::FIELD, "string"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        T::from_hex(value).map_err(|error| E::custom(hex_error_marker(error)))
    }
}

// ---------------------------------------------------------------------------
// ChainEventRef JSON object
//
// ChainEventRef is the only composite identifier in this slice. It encodes as a
// flat JSON object with the five spec fields; bytes32 fields use the hex
// identifier round-trip, and the integer fields use JSON numbers within u64 /
// u32 range.
//
// Encoding and decoding use an internal serde DTO so the transport boundary is
// isolated from the domain model. Serde errors are translated into sanitized
// JsonParseError variants; serde_json's Display/Debug text is never exposed to
// callers because it can echo input fragments.
//
// Duplicate field behavior: ChainEventRef now follows serde's struct
// deserializer, which rejects duplicates as a generic JSON shape error rather
// than the old bespoke DuplicateField variant. The DuplicateField variant
// remains in JsonParseError because parse_object (used by mpc-config) still
// produces it.
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChainEventRefDto {
    #[serde(deserialize_with = "deserialize_chain_id")]
    chain_id: u64,
    #[serde(deserialize_with = "deserialize_block_number")]
    block_number: u64,
    block_hash: BlockHashHex,
    tx_hash: TxHashHex,
    #[serde(deserialize_with = "deserialize_log_index")]
    log_index: u32,
}

impl From<&ChainEventRef> for ChainEventRefDto {
    fn from(value: &ChainEventRef) -> Self {
        Self {
            chain_id: value.chain_id.0,
            block_number: value.block_number,
            block_hash: BlockHashHex(value.block_hash),
            tx_hash: TxHashHex(value.tx_hash),
            log_index: value.log_index,
        }
    }
}

impl From<ChainEventRefDto> for ChainEventRef {
    fn from(value: ChainEventRefDto) -> Self {
        Self {
            chain_id: ChainId(value.chain_id),
            block_number: value.block_number,
            block_hash: value.block_hash.0,
            tx_hash: value.tx_hash.0,
            log_index: value.log_index,
        }
    }
}

pub fn encode_chain_event_ref(value: &ChainEventRef) -> String {
    serde_json::to_string(&ChainEventRefDto::from(value))
        .expect("ChainEventRef DTO serialization is infallible")
}

pub fn decode_chain_event_ref(text: &str) -> Result<ChainEventRef, JsonParseError> {
    reject_json_string_escape_in_top_level_object(text)?;
    let mut de = serde_json::Deserializer::from_str(text);
    let value: ChainEventRefDto =
        serde::de::Deserialize::deserialize(&mut de).map_err(map_serde_json_to_parse_error)?;
    de.end().map_err(|_| JsonParseError::TrailingContent)?;
    Ok(value.into())
}

fn reject_json_string_escape_in_top_level_object(text: &str) -> Result<(), JsonParseError> {
    let Some(start) = first_non_whitespace(text) else {
        return Ok(());
    };
    if text.as_bytes()[start] != b'{' {
        return Ok(());
    }

    reject_json_string_escape_until_top_level_close(text, start)
}

fn reject_json_string_escape_in_top_level_string(text: &str) -> Result<(), JsonParseError> {
    let Some(start) = first_non_whitespace(text) else {
        return Ok(());
    };
    if text.as_bytes()[start] != b'"' {
        return Ok(());
    }

    let mut escaped = false;
    for byte in text.bytes().skip(start + 1) {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => return Err(JsonParseError::UnsupportedStringEscape),
            b'"' => return Ok(()),
            _ => {}
        }
    }
    Ok(())
}

fn first_non_whitespace(text: &str) -> Option<usize> {
    text.bytes()
        .position(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
}

fn reject_json_string_escape_until_top_level_close(
    text: &str,
    start: usize,
) -> Result<(), JsonParseError> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut reject_current_string = false;
    let mut escaped = false;
    let mut index = start;

    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else {
                match byte {
                    b'\\' if reject_current_string => {
                        return Err(JsonParseError::UnsupportedStringEscape);
                    }
                    b'\\' => escaped = true,
                    b'"' => {
                        in_string = false;
                        reject_current_string = false;
                    }
                    _ => {}
                }
            }
            index += 1;
            continue;
        }

        match byte {
            b'"' => {
                in_string = true;
                reject_current_string = depth == 1;
            }
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(());
                }
            }
            _ => {}
        }
        index += 1;
    }
    Ok(())
}

/// Map a serde_json parse error to a sanitized [`JsonParseError`] variant.
/// The serde_json error message is intentionally discarded — it can echo
/// input fragments (offending tokens, field values) which would violate the
/// transport's sanitized-error guarantee.
fn map_serde_json_to_parse_error(err: serde_json::Error) -> JsonParseError {
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

fn deserialize_chain_id<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_u64_field(deserializer, "chain_id")
}

fn deserialize_block_number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_u64_field(deserializer, "block_number")
}

fn deserialize_log_index<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_u64_field(deserializer, "log_index")?;
    u32::try_from(value).map_err(|_| D::Error::custom(integer_overflow_marker("log_index", "u32")))
}

fn deserialize_u64_field<'de, D>(deserializer: D, field: &'static str) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| D::Error::custom(invalid_unsigned_marker(field))),
        _ => Err(D::Error::custom(field_shape_marker(
            field,
            "unsigned integer",
        ))),
    }
}

const SERDE_ERROR_PREFIX: &str = "__transport_json_error__:";

fn field_shape_marker(field: &'static str, expected: &'static str) -> String {
    format!(
        "{SERDE_ERROR_PREFIX}field_shape:{field}:{}",
        marker_expected(expected)
    )
}

fn invalid_unsigned_marker(field: &'static str) -> String {
    format!("{SERDE_ERROR_PREFIX}invalid_unsigned:{field}")
}

fn integer_overflow_marker(field: &'static str, expected: &'static str) -> String {
    format!("{SERDE_ERROR_PREFIX}integer_overflow:{field}:{expected}")
}

fn hex_error_marker(error: HexDecodeError) -> String {
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

fn missing_field_from_serde_error(message: &str) -> Option<&'static str> {
    known_fields()
        .iter()
        .copied()
        .find(|field| message.starts_with(&format!("missing field `{field}`")))
}

fn known_field(field: &str) -> Option<&'static str> {
    known_fields().iter().copied().find(|known| *known == field)
}

fn known_fields() -> &'static [&'static str] {
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

// ---------------------------------------------------------------------------
// Ciphertext envelope JSON transport
//
// On the wire, each envelope is a JSON string carrying base64-encoded canonical
// CBOR bytes. The CBOR bytes themselves are produced and validated by
// `coprocessor-ciphertext-binding` so this crate never re-derives the binary
// envelope layout. Decode failure paths map both base64 errors and envelope
// errors into [`CiphertextJsonError`].
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
pub enum CiphertextJsonError {
    /// The JSON value did not parse as a single quoted string.
    #[error(transparent)]
    Json(#[from] JsonParseError),
    /// The base64 payload was not valid canonical base64.
    #[error(transparent)]
    Base64(#[from] base64_codec::Base64DecodeError),
    /// The decoded CBOR envelope was malformed or carried mismatched AAD.
    #[error(transparent)]
    Envelope(#[from] EnvelopeDecodeError),
}

pub use base64_codec::Base64DecodeError;

pub fn encode_system_ciphertext(envelope: &SystemCiphertextV1) -> String {
    encode_envelope_as_json_string(&envelope.encode())
}

pub fn encode_enclave_ciphertext(envelope: &EnclaveCiphertextV1) -> String {
    encode_envelope_as_json_string(&envelope.encode())
}

pub fn encode_reader_ciphertext(envelope: &ReaderCiphertextV1) -> String {
    encode_envelope_as_json_string(&envelope.encode())
}

pub fn decode_system_ciphertext(text: &str) -> Result<SystemCiphertextV1, CiphertextJsonError> {
    let bytes = decode_envelope_bytes(text)?;
    Ok(SystemCiphertextV1::decode(&bytes)?)
}

pub fn decode_enclave_ciphertext(text: &str) -> Result<EnclaveCiphertextV1, CiphertextJsonError> {
    let bytes = decode_envelope_bytes(text)?;
    Ok(EnclaveCiphertextV1::decode(&bytes)?)
}

pub fn decode_reader_ciphertext(text: &str) -> Result<ReaderCiphertextV1, CiphertextJsonError> {
    let bytes = decode_envelope_bytes(text)?;
    Ok(ReaderCiphertextV1::decode(&bytes)?)
}

fn encode_envelope_as_json_string(envelope_bytes: &[u8]) -> String {
    let mut out = String::with_capacity(envelope_bytes.len() * 4 / 3 + 2);
    out.push('"');
    base64_codec::encode_into(&mut out, envelope_bytes);
    out.push('"');
    out
}

fn decode_envelope_bytes(text: &str) -> Result<Vec<u8>, CiphertextJsonError> {
    // Use serde_json to extract the JSON string value. The Deserializer is
    // used directly so trailing-content failures map to Json(TrailingContent)
    // rather than being swallowed by a combined parse-and-end call.
    // The serde_json error message is discarded — it can contain the offending
    // token, which for base64/ciphertext fields would leak payload bytes.
    reject_json_string_escape_in_top_level_string(text)?;
    let mut de = serde_json::Deserializer::from_str(text);
    let base64_text: String = serde::de::Deserialize::deserialize(&mut de).map_err(|_| {
        CiphertextJsonError::Json(JsonParseError::UnexpectedToken { expected: "string" })
    })?;
    de.end()
        .map_err(|_| CiphertextJsonError::Json(JsonParseError::TrailingContent))?;
    let bytes = base64_codec::decode(&base64_text)?;
    Ok(bytes)
}
