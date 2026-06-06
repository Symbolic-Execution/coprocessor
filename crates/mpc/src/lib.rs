//! MPC-facing concerns for the Coprocessor: public configuration loading and
//! To-Enclave Transformation client.
//!
//! Two internal modules keep the concepts separate:
//!
//! - [`config`] owns [`MpcPublicConfig`], its JSON parse function, the
//!   [`MpcConfigSource`] seam, the compatibility check, and all associated
//!   error types.
//! - [`to_enclave`] owns [`ToEnclaveTransformationRequest`], the
//!   [`MpcToEnclaveSource`] seam, and the transformation function.
//!
//! The public surface of both modules is re-exported here so callers
//! use `coprocessor_mpc::{...}` without knowing the internal structure.
//!
//! Note: the previous config and To-Enclave crates both exported an
//! `MpcSourceError` type for different seam contracts. The root
//! `MpcSourceError` resolves to the To-Enclave one, which is the runtime path
//! used by the host. The config source error is re-exported as
//! [`MpcConfigSourceError`].

mod config;
mod to_enclave;

pub use config::{
    load_mpc_public_config, parse_mpc_public_config, AttestationDigest, ChainId, DomainId,
    HexDecodeError, JsonParseError, KeyId, MpcConfigExpectations, MpcConfigIncompatibility,
    MpcConfigLoadError, MpcConfigParseError, MpcConfigSource, MpcPublicConfig,
    MpcSourceError as MpcConfigSourceError, CiphertextSuite, ReaderKeyAlgorithm, X25519PublicKey,
};

pub use to_enclave::{
    request_to_enclave_transformation, EnclaveCiphertextV1, HandleId, MpcSourceError,
    MpcToEnclaveResponse, MpcToEnclaveSource, RequestId, SystemCiphertextV1,
    ToEnclaveTransformationError, ToEnclaveTransformationRequest,
};
