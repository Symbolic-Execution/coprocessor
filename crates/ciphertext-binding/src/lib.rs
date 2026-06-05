//! Canonical Ciphertext Binding AAD codecs for the Coprocessor / MPC / Enclave
//! boundary.
//!
//! Each AAD kind encodes to a fixed-order canonical CBOR array (never a map),
//! starting with the version byte and an integer kind discriminant. Decoders
//! surface domain-shaped, non-secret errors so callers can map them to API
//! responses without leaking ciphertext or key material.
//!
//! # CBOR implementation
//!
//! The minimal CBOR reader/writer is in the private `cbor` module.
//! A spike (issue #84) evaluated `minicbor` as a replacement and found that
//! it does not reject non-canonical (non-shortest-form) integer and length
//! encodings on decode, requiring a hand-written guard that reproduces the
//! existing `read_header` check. The manual implementation was retained.
//! See the repository-level `docs/cbor-spike-decision.md` for the full
//! rationale.

mod aad;
mod aad_body;
mod aad_codec;
mod cbor;
mod envelope;
mod identifiers;

pub use identifiers::{
    AadKind, AttestationDigest, ContractAddress, DomainId, EnvelopeKind, HandleId, KeyId, ReaderId,
    RequestId,
};

pub use aad::{
    AadDecodeError, CiphertextBindingAad, EnclaveAadV1, ReaderAadV1, SystemHandleAadV1,
    SystemInputAadV1,
};

pub use envelope::{
    EnclaveCiphertextV1, EnvelopeDecodeError, ReaderCiphertextV1, SystemCiphertextV1,
};
