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
//! The full public surface of both modules is re-exported here so callers
//! use `coprocessor_mpc::{...}` without knowing the internal structure.
//!
//! Note: both modules define an `MpcSourceError` type for their respective
//! seam contracts. `coprocessor_mpc::MpcSourceError` resolves to the
//! To-Enclave one (the type the host interacts with at runtime). The config
//! source error is available as `coprocessor_mpc::config::MpcSourceError`.

pub mod config;
pub mod to_enclave;

pub use config::{
    load_mpc_public_config, parse_mpc_public_config, AttestationDigest, ChainId, DomainId,
    HexDecodeError, JsonParseError, KeyId, MpcConfigExpectations, MpcConfigIncompatibility,
    MpcConfigLoadError, MpcConfigParseError, MpcConfigSource, MpcPublicConfig, MpcSuite,
};

pub use to_enclave::{
    request_to_enclave_transformation, EnclaveCiphertextV1, HandleId, MpcSourceError,
    MpcToEnclaveResponse, MpcToEnclaveSource, RequestId, SystemCiphertextV1,
    ToEnclaveTransformationError, ToEnclaveTransformationRequest,
};
