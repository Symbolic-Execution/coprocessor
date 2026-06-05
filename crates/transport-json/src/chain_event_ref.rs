/// ChainEventRef JSON encoding and decoding.
use coprocessor_handle_graph_core::{ChainEventRef, ChainId};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};

use super::hex_identifier::{BlockHashHex, TxHashHex};
use super::json_codec::JsonParseError;
use super::serde_mapping::{
    field_shape_marker, integer_overflow_marker, invalid_unsigned_marker,
    map_serde_json_to_parse_error,
};
use super::string_escape::reject_json_string_escape_in_top_level_object;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChainEventRefDto {
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
