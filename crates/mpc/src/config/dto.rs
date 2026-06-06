/// Wire-shaped serde DTO for the MPC public configuration JSON payload,
/// plus the parse function and per-field deserializers.
use serde::{de::Error as DeError, Deserialize, Deserializer};

use coprocessor_wire_codec::decode_hex_lower;

use super::config::{
    AttestationDigest, ChainId, CiphertextSuite, DomainId, KeyId, MpcPublicConfig,
    ReaderKeyAlgorithm, X25519PublicKey,
};
use super::error::MpcConfigParseError;
use super::serde_mapping::{
    field_shape_marker, invalid_unsigned_marker, map_serde_json_to_mpc_parse_error,
};
use super::validation::to_fixed;

const DOMAIN_ID_LEN: usize = 32;
const KEY_ID_LEN: usize = 32;
const HPKE_PUBLIC_KEY_LEN: usize = 32;
const ATTESTATION_DIGEST_LEN: usize = 32;

/// Wire-shaped serde DTO for the MPC public configuration JSON payload.
/// All hex fields are kept as `String` so hex validation is delegated to the
/// transport codec after parsing; this keeps the malformed-vs-incompatible
/// split entirely in `load_mpc_public_config`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MpcPublicConfigDto {
    #[serde(deserialize_with = "deserialize_chain_id")]
    pub(super) chain_id: u64,
    #[serde(deserialize_with = "deserialize_domain_id")]
    pub(super) domain_id: String,
    #[serde(deserialize_with = "deserialize_key_id")]
    pub(super) key_id: String,
    #[serde(deserialize_with = "deserialize_hpke_public_key")]
    pub(super) hpke_public_key: String,
    #[serde(deserialize_with = "deserialize_reader_key_algorithm")]
    pub(super) reader_key_algorithm: String,
    #[serde(deserialize_with = "deserialize_ciphertext_suite")]
    pub(super) ciphertext_suite: String,
    #[serde(deserialize_with = "deserialize_approved_enclave_measurement")]
    pub(super) approved_enclave_measurement: String,
}

/// Parse the JSON payload served by an MPC endpoint into an
/// [`MpcPublicConfig`]. Surfaces the first wire-shape failure encountered;
/// compatibility checks are deliberately not part of parsing.
pub fn parse_mpc_public_config(text: &str) -> Result<MpcPublicConfig, MpcConfigParseError> {
    reject_json_string_escape_in_top_level_object(text)?;
    let dto: MpcPublicConfigDto =
        serde_json::from_str(text).map_err(map_serde_json_to_mpc_parse_error)?;

    let domain_id_bytes = decode_hex_lower(&dto.domain_id, "domain_id", DOMAIN_ID_LEN)?;
    let key_id_bytes = decode_hex_lower(&dto.key_id, "key_id", KEY_ID_LEN)?;
    let hpke_public_key_bytes = decode_hex_lower(
        &dto.hpke_public_key,
        "hpke_public_key",
        HPKE_PUBLIC_KEY_LEN,
    )
    .map_err(MpcConfigParseError::InvalidHpkePublicKey)?;
    let approved_enclave_measurement_bytes = decode_hex_lower(
        &dto.approved_enclave_measurement,
        "approved_enclave_measurement",
        ATTESTATION_DIGEST_LEN,
    )?;
    let reader_key_algorithm = ReaderKeyAlgorithm::from_wire_name(&dto.reader_key_algorithm)
        .ok_or(MpcConfigParseError::UnknownReaderKeyAlgorithm)?;
    let ciphertext_suite = CiphertextSuite::from_wire_name(&dto.ciphertext_suite)
        .ok_or(MpcConfigParseError::UnknownCiphertextSuite)?;

    Ok(MpcPublicConfig {
        chain_id: ChainId(dto.chain_id),
        domain_id: DomainId(to_fixed::<DOMAIN_ID_LEN>(domain_id_bytes)),
        key_id: KeyId(to_fixed::<KEY_ID_LEN>(key_id_bytes)),
        hpke_public_key: X25519PublicKey(to_fixed::<HPKE_PUBLIC_KEY_LEN>(hpke_public_key_bytes)),
        reader_key_algorithm,
        ciphertext_suite,
        approved_enclave_measurement: AttestationDigest(to_fixed::<ATTESTATION_DIGEST_LEN>(
            approved_enclave_measurement_bytes,
        )),
    })
}

fn reject_json_string_escape_in_top_level_object(
    text: &str,
) -> Result<(), coprocessor_wire_codec::JsonParseError> {
    let Some(start) = first_non_whitespace(text) else {
        return Ok(());
    };
    if text.as_bytes()[start] != b'{' {
        return Ok(());
    }

    let mut depth = 1usize;
    let mut in_string = false;
    let mut reject_current_string = false;
    let mut escaped = false;
    for byte in text.bytes().skip(start + 1) {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' if reject_current_string => {
                    return Err(coprocessor_wire_codec::JsonParseError::UnsupportedStringEscape);
                }
                b'\\' => escaped = true,
                b'"' => {
                    in_string = false;
                    reject_current_string = false;
                }
                _ => {}
            }
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
    }

    Ok(())
}

fn first_non_whitespace(text: &str) -> Option<usize> {
    text.bytes()
        .position(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
}

fn deserialize_chain_id<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| D::Error::custom(invalid_unsigned_marker("chain_id"))),
        _ => Err(D::Error::custom(field_shape_marker(
            "chain_id",
            "unsigned integer",
        ))),
    }
}

fn deserialize_domain_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_field(deserializer, "domain_id")
}

fn deserialize_key_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_field(deserializer, "key_id")
}

fn deserialize_hpke_public_key<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_field(deserializer, "hpke_public_key")
}

fn deserialize_reader_key_algorithm<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_field(deserializer, "reader_key_algorithm")
}

fn deserialize_ciphertext_suite<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_field(deserializer, "ciphertext_suite")
}

fn deserialize_approved_enclave_measurement<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_string_field(deserializer, "approved_enclave_measurement")
}

fn deserialize_string_field<'de, D>(
    deserializer: D,
    field: &'static str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::String(value) => Ok(value),
        _ => Err(D::Error::custom(field_shape_marker(field, "string"))),
    }
}
