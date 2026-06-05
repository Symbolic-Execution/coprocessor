/// HexIdentifier trait, visitor, macro, and all identifier newtype types
/// for JSON transport.
use coprocessor_ciphertext_binding::{
    AttestationDigest as BindingAttestationDigest, ContractAddress as BindingContractAddress,
    DomainId as BindingDomainId, HandleId as BindingHandleId, KeyId, ReaderId, RequestId,
};
use coprocessor_handle_graph_core::{
    ContractAddress as CoreContractAddress, DomainId as CoreDomainId, HandleId as CoreHandleId,
};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;
use std::marker::PhantomData;

use super::hex_codec;
use super::serde_mapping::{field_shape_marker, hex_error_marker};
pub use hex_codec::HexDecodeError;

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

pub(super) struct HexIdentifierVisitor<T> {
    _marker: PhantomData<T>,
}

impl<T> HexIdentifierVisitor<T> {
    pub(super) fn new() -> Self {
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
