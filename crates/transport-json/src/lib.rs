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

// ---------------------------------------------------------------------------
// ChainEventRef JSON object
//
// ChainEventRef is the only composite identifier in this slice. It encodes as a
// flat JSON object with the five spec fields; bytes32 fields use the hex
// identifier round-trip, and the integer fields use JSON numbers within u64 /
// u32 range.
// ---------------------------------------------------------------------------

pub fn encode_chain_event_ref(value: &ChainEventRef) -> String {
    let block_hash = BlockHashHex(value.block_hash).to_hex();
    let tx_hash = TxHashHex(value.tx_hash).to_hex();
    let mut out = String::new();
    json_codec::write_object_open(&mut out);
    json_codec::write_uint_field(&mut out, "chain_id", value.chain_id.0, false);
    json_codec::write_uint_field(&mut out, "block_number", value.block_number, true);
    json_codec::write_string_field(&mut out, "block_hash", &block_hash, true);
    json_codec::write_string_field(&mut out, "tx_hash", &tx_hash, true);
    json_codec::write_uint_field(&mut out, "log_index", u64::from(value.log_index), true);
    json_codec::write_object_close(&mut out);
    out
}

pub fn decode_chain_event_ref(text: &str) -> Result<ChainEventRef, JsonParseError> {
    let mut object = json_codec::parse_object(text)?;
    let chain_id = object.take_uint("chain_id")?;
    let block_number = object.take_uint("block_number")?;
    let block_hash_hex = object.take_string("block_hash")?;
    let tx_hash_hex = object.take_string("tx_hash")?;
    let log_index = object.take_uint("log_index")?;
    object.finish()?;

    let block_hash =
        BlockHashHex::from_hex(&block_hash_hex).map_err(|error| JsonParseError::InvalidHex {
            field: "block_hash",
            error,
        })?;
    let tx_hash =
        TxHashHex::from_hex(&tx_hash_hex).map_err(|error| JsonParseError::InvalidHex {
            field: "tx_hash",
            error,
        })?;
    let log_index = u32::try_from(log_index).map_err(|_| JsonParseError::IntegerOverflow {
        field: "log_index",
        expected: "u32",
    })?;

    Ok(ChainEventRef {
        chain_id: ChainId(chain_id),
        block_number,
        block_hash: block_hash.0,
        tx_hash: tx_hash.0,
        log_index,
    })
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
    let base64_text = json_codec::parse_string(text)?;
    let bytes = base64_codec::decode(&base64_text)?;
    Ok(bytes)
}
