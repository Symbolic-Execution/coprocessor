/// Lifecycle phases, readiness signal, and host start errors.
use thiserror::Error;

use super::config::HostConfigError;
use super::dependency::DependencyName;

/// Lifecycle phase of the Coprocessor Host. Transitions are linear:
/// `NotStarted` -> `Running` -> `ShutDown`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    NotStarted,
    Running,
    ShutDown,
}

/// Readiness signal exposed by the host. Distinguishes a host that has merely
/// loaded configuration from one that has every named dependency wired and
/// reachable. The Coordinator should treat anything other than
/// [`Readiness::Ready`] as not-yet-serving.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Readiness {
    /// The host has not been started, so no configuration has been loaded and
    /// no dependencies have been polled.
    NotStarted,
    /// Configuration is loaded and valid, but at least one named dependency is
    /// still `Unavailable`. The `unavailable` list is sorted and deduplicated.
    ConfigurationLoaded { unavailable: Vec<DependencyName> },
    /// Configuration is loaded and every named dependency reports available.
    Ready,
    /// The host completed a clean shutdown. Readiness reads after shutdown
    /// must not be confused with `NotStarted`.
    ShutDown,
}

/// Reasons [`super::CoprocessorHost::start`] can fail.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum HostStartError {
    #[error(transparent)]
    InvalidConfig(#[from] HostConfigError),
    #[error("host is already shut down")]
    AlreadyShutDown,
    /// The Nitro adapter configuration is internally inconsistent. Surfaces
    /// [`coprocessor_nitro_enclave::EnclaveAttestationError::InvalidConfiguration`]
    /// from the factory ([`super::config::HostConfig::build_nitro_attestation_source`]).
    #[error(transparent)]
    InvalidEnclaveAttestationConfig(#[from] coprocessor_nitro_enclave::EnclaveAttestationError),
    /// The wrong factory was called for the selected attestation mode (e.g.
    /// `build_nitro_attestation_source` on a Local config, or
    /// `build_local_attestation_source` on a Nitro config).
    #[error("enclave attestation mode mismatch")]
    EnclaveAttestationModeMismatch,
}
