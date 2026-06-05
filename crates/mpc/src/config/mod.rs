//! MPC public configuration for Coprocessor use.
//!
//! The Coprocessor needs the MPC public control-plane configuration before it
//! can schedule plaintext materialization, ask MPC for To-Enclave
//! Transformations, or check Enclave Measurements. This module owns three
//! concerns:
//!
//! 1. The [`MpcPublicConfig`] value object — the DomainId, ChainId, active
//!    KeyId, public key bytes, cryptographic [`MpcSuite`], and approved
//!    Enclave Measurement that the host must trust before it does any of
//!    that work.
//! 2. Parsing the spec-shaped JSON payload the MPC endpoint serves.
//! 3. Validating the parsed config against the Coprocessor's
//!    [`MpcConfigExpectations`] (chain, domain, suite, public-key shape) so
//!    incompatible configuration is rejected before work is scheduled.
//!
//! The MPC endpoint itself is an [`MpcConfigSource`] seam. Tests provide a
//! fake; later slices wire an HTTP-backed implementation when the host
//! runtime is chosen. Backend availability failures and malformed or
//! incompatible payloads surface as distinct [`MpcConfigLoadError`]
//! variants so a retry loop can treat them differently.
//!
//! All errors carry only non-secret diagnostic context (field names,
//! expected vs actual byte counts, suite identifiers). No public-key bytes,
//! key material, or plaintext appear in error values.

mod compat;
mod config;
mod dto;
mod error;
mod serde_mapping;
mod source;
mod validation;

pub use coprocessor_wire_codec::{HexDecodeError, JsonParseError};

pub use compat::MpcConfigIncompatibility;
pub use config::{AttestationDigest, ChainId, DomainId, KeyId};
pub use config::{MpcConfigExpectations, MpcPublicConfig, MpcSuite};
pub use dto::parse_mpc_public_config;
pub use error::{MpcConfigLoadError, MpcConfigParseError, MpcSourceError};
pub use source::{load_mpc_public_config, MpcConfigSource};
