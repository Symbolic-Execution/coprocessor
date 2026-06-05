/// Host configuration, retry policy, and enclave attestation source
/// construction.
use coprocessor_nitro_enclave::{
    EnclaveAttestationSource, LocalEnclaveAttestationConfig, LocalEnclaveAttestationSource,
    NitroAdapterConfig, NitroAttestationDocSource, NitroEnclaveAdapter,
};
use thiserror::Error;

use super::chain_ingestion::ChainView;
use super::lifecycle::HostStartError;

/// Retry policy for resolution failures. Controls how many times the host
/// attempts a Resolution Task before declaring the Derived Handle Failed.
/// Uses a deterministic attempt counter — no clock, no randomness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Maximum number of attempts (including the first). When a backend
    /// returns a transient error and `attempts_used >= max_attempts` the
    /// failure is treated as terminal. Must be at least 1.
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 3 }
    }
}

/// Config-driven selection of the Enclave attestation source. Local mode serves
/// pre-baked material for tests and local development; Nitro mode wires the
/// AWS Nitro Enclave adapter backed by an injectable [`NitroAttestationDocSource`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnclaveAttestationConfig {
    /// Pre-baked, deterministic attestation material. Delegates to
    /// [`LocalEnclaveAttestationSource`]. Use for local development and
    /// in-process tests; never use in production.
    Local(LocalEnclaveAttestationConfig),
    /// AWS Nitro Enclave production adapter. Delegates to
    /// [`NitroEnclaveAdapter`] backed by an injectable [`NitroAttestationDocSource`].
    Nitro(NitroAdapterConfig),
}

/// Configuration loaded by the Coprocessor Host before startup. The shape is
/// deliberately minimal in this scaffold: the runtime/stack decision (issue
/// #18) will extend this with endpoints, persistence, and credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostConfig {
    /// Human-readable label for the deployment, used in logs and health output.
    pub deployment_label: String,
    /// Confirmation view from which Chain Event Ingestion pulls. Defaults to
    /// [`ChainView::Safe`]; deployments that require stricter confirmation
    /// can choose [`ChainView::Finalized`].
    pub chain_view: ChainView,
    /// Retry policy applied when MPC or Enclave backend returns a transient
    /// failure. The handle stays Pending while attempts remain; on budget
    /// exhaustion the handle transitions to Failed.
    pub retry_policy: RetryPolicy,
    /// Enclave attestation source selection. Defaults to `Local` in
    /// [`Self::for_local_development`]; production deployments use
    /// [`EnclaveAttestationConfig::Nitro`] and wire a real
    /// [`NitroAttestationDocSource`] at startup via
    /// [`Self::build_nitro_attestation_source`].
    pub enclave_attestation: EnclaveAttestationConfig,
}

impl HostConfig {
    /// Configuration suitable for local development and the in-process tests
    /// that drive this crate. It never reaches MPC, the Enclave, or a chain
    /// RPC, and never reads credentials from the environment.
    pub fn for_local_development() -> Self {
        Self {
            deployment_label: "local-development".to_string(),
            chain_view: ChainView::default(),
            retry_policy: RetryPolicy::default(),
            enclave_attestation: EnclaveAttestationConfig::Local(LocalEnclaveAttestationConfig {
                enclave_public_key: vec![0x44; 48],
                enclave_measurement: coprocessor_nitro_enclave::AttestationDigest([0x42; 32]),
                attestation: vec![0x55; 96],
            }),
        }
    }

    /// Configuration for production AWS Nitro Enclave mode.
    ///
    /// `enclave_measurement` is the approved PCR0 MPC checks attestations
    /// against. `expected_public_key_len` is the byte-count expectation driven
    /// by the chosen MPC suite (e.g. 48 for `bls12-381-g1`).
    ///
    /// Wire the `NitroAttestationDocSource` at startup via
    /// [`Self::build_nitro_attestation_source`].
    pub fn for_production_nitro(
        enclave_measurement: coprocessor_nitro_enclave::AttestationDigest,
        expected_public_key_len: usize,
    ) -> Self {
        Self {
            deployment_label: "production-nitro".to_string(),
            chain_view: ChainView::default(),
            retry_policy: RetryPolicy::default(),
            enclave_attestation: EnclaveAttestationConfig::Nitro(NitroAdapterConfig {
                approved_enclave_measurement: enclave_measurement,
                expected_public_key_len,
            }),
        }
    }

    /// Build a [`LocalEnclaveAttestationSource`] from the config's local
    /// attestation material. Returns
    /// [`HostStartError::EnclaveAttestationModeMismatch`] if the config uses
    /// Nitro mode.
    pub fn build_local_attestation_source(
        &self,
    ) -> Result<Box<dyn EnclaveAttestationSource>, HostStartError> {
        match &self.enclave_attestation {
            EnclaveAttestationConfig::Local(cfg) => {
                Ok(Box::new(LocalEnclaveAttestationSource::new(cfg.clone())))
            }
            EnclaveAttestationConfig::Nitro(_) => {
                Err(HostStartError::EnclaveAttestationModeMismatch)
            }
        }
    }

    /// Build a [`NitroEnclaveAdapter`] backed by `doc_source`. The
    /// `doc_source` is the injectable [`NitroAttestationDocSource`]: use a
    /// fake in tests and a real NSM transport in production.
    ///
    /// Returns [`HostStartError::EnclaveAttestationModeMismatch`] if the
    /// config uses Local mode. Returns
    /// [`HostStartError::InvalidEnclaveAttestationConfig`] if the Nitro
    /// config fails [`NitroAdapterConfig::validate`].
    pub fn build_nitro_attestation_source<S: NitroAttestationDocSource + 'static>(
        &self,
        doc_source: S,
    ) -> Result<Box<dyn EnclaveAttestationSource>, HostStartError> {
        match &self.enclave_attestation {
            EnclaveAttestationConfig::Nitro(cfg) => {
                NitroEnclaveAdapter::new(cfg.clone(), doc_source)
                    .map(|adapter| Box::new(adapter) as Box<dyn EnclaveAttestationSource>)
                    .map_err(HostStartError::InvalidEnclaveAttestationConfig)
            }
            EnclaveAttestationConfig::Local(_) => {
                Err(HostStartError::EnclaveAttestationModeMismatch)
            }
        }
    }

    pub(super) fn validate(&self) -> Result<(), HostConfigError> {
        if self.deployment_label.trim().is_empty() {
            return Err(HostConfigError::EmptyDeploymentLabel);
        }
        if self.retry_policy.max_attempts == 0 {
            return Err(HostConfigError::RetryPolicyRequiresAttempt);
        }
        if let EnclaveAttestationConfig::Nitro(cfg) = &self.enclave_attestation {
            cfg.validate().map_err(|e| {
                let detail = match e {
                    coprocessor_nitro_enclave::EnclaveAttestationError::InvalidConfiguration {
                        detail,
                    } => detail,
                    other => format!("unexpected validation error: {other:?}"),
                };
                HostConfigError::InvalidEnclaveAttestationConfig { detail }
            })?;
        }
        Ok(())
    }
}

impl Default for HostConfig {
    fn default() -> Self {
        Self::for_local_development()
    }
}

/// Reasons configuration validation can fail before the host starts. Failure
/// keeps the host in [`super::lifecycle::LifecycleState::NotStarted`].
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum HostConfigError {
    #[error("deployment label must not be empty")]
    EmptyDeploymentLabel,
    #[error("retry policy requires at least one attempt")]
    RetryPolicyRequiresAttempt,
    /// Nitro adapter configuration failed its own validation rules.
    /// `detail` is the non-secret description of the failing rule.
    #[error("invalid Enclave attestation config: {detail}")]
    InvalidEnclaveAttestationConfig { detail: String },
}
