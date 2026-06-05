/// MPC config source seam and the load function that drives it.
use super::config::{MpcConfigExpectations, MpcPublicConfig};
use super::dto::parse_mpc_public_config;
use super::error::{MpcConfigLoadError, MpcSourceError};

/// Source seam for the MPC public configuration. Implementations carry
/// their own endpoint addressing, transport, and authentication; this
/// trait only commits to the wire payload contract: a JSON text document
/// matching [`parse_mpc_public_config`], or an [`MpcSourceError`].
pub trait MpcConfigSource {
    fn fetch(&self) -> Result<String, MpcSourceError>;
}

/// Load and validate the MPC public configuration the Coprocessor will
/// trust for plaintext materialization, To-Enclave Transformation, and
/// Enclave Measurement checks.
///
/// The function delegates fetching to the [`MpcConfigSource`] seam, parses
/// the returned JSON, and runs compatibility checks against the supplied
/// [`MpcConfigExpectations`]. Each failure stage produces its own
/// [`MpcConfigLoadError`] variant.
pub fn load_mpc_public_config(
    source: &dyn MpcConfigSource,
    expectations: &MpcConfigExpectations,
) -> Result<MpcPublicConfig, MpcConfigLoadError> {
    let payload = source.fetch().map_err(map_source_error)?;
    let config = parse_mpc_public_config(&payload)?;
    config.check_compatibility(expectations)?;
    Ok(config)
}

pub(super) fn map_source_error(error: MpcSourceError) -> MpcConfigLoadError {
    match error {
        MpcSourceError::Unavailable { detail } => MpcConfigLoadError::Unavailable { detail },
    }
}
