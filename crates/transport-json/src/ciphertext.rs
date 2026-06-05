/// Ciphertext envelope JSON transport: encode/decode System, Enclave,
/// and Reader ciphertext envelopes as base64-encoded canonical CBOR JSON
/// strings.

use coprocessor_ciphertext_binding::{EnclaveCiphertextV1, EnvelopeDecodeError, ReaderCiphertextV1, SystemCiphertextV1};

use super::base64_codec;
use super::json_codec::JsonParseError;
use super::string_escape::reject_json_string_escape_in_top_level_string;

pub use base64_codec::Base64DecodeError;

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

pub(super) fn encode_envelope_as_json_string(envelope_bytes: &[u8]) -> String {
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
