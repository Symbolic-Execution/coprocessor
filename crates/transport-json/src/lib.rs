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

mod base64_codec;
mod hex_codec;
mod json_codec;

mod chain_event_ref;
mod ciphertext;
mod hex_identifier;
mod serde_mapping;
mod string_escape;

pub use hex_codec::{
    decode_lower as decode_hex_lower, decode_lower_variable as decode_hex_lower_variable,
    HexDecodeError,
};
pub use json_codec::{parse_object, JsonObject, JsonParseError};

pub use hex_identifier::{
    AttestationDigestHex, BlockHashHex, ContractAddressHex, DomainIdHex, HandleIdHex,
    HexIdentifier, KeyIdHex, ReaderIdHex, RequestIdHex, TxHashHex,
};

pub use chain_event_ref::{decode_chain_event_ref, encode_chain_event_ref};

pub use ciphertext::{
    decode_enclave_ciphertext, decode_reader_ciphertext, decode_system_ciphertext,
    encode_enclave_ciphertext, encode_reader_ciphertext, encode_system_ciphertext,
    Base64DecodeError, CiphertextJsonError,
};
