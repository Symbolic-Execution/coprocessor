/// Host configuration, retry policy, and enclave attestation source
/// construction.
use coprocessor_handle_graph_core::PlaintextMaterializer;
use coprocessor_mpc::{
    AttestationDigest as MpcAttestationDigest, ChainId as MpcChainId,
    CiphertextSuite as MpcCiphertextSuite, DomainId as MpcDomainId, KeyId as MpcKeyId,
    MpcConfigExpectations, MpcPublicConfig, ReaderKeyAlgorithm as MpcReaderKeyAlgorithm,
    X25519PublicKey,
};
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

const DEFAULT_MPC_CHAIN_ID: MpcChainId = MpcChainId(1);
const DEFAULT_MPC_DOMAIN_ID: MpcDomainId = MpcDomainId([0x11; 32]);
const DEFAULT_MPC_KEY_ID: MpcKeyId = MpcKeyId([0x22; 32]);
const DEFAULT_MPC_HPKE_PUBLIC_KEY: X25519PublicKey = X25519PublicKey([0x66; 32]);

/// Host-owned view of the MPC control-plane identity it expects to use.
///
/// `public_config` is the currently trusted MPC public configuration; the
/// host uses its active `key_id` for Plaintext Handle materialization and its
/// approved Enclave Measurement when checking that local/Nitro attestation
/// configuration is internally consistent. `expectations` is the compatibility
/// contract a future config-loader slice must preserve when reloading the MPC
/// endpoint's published JSON.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostMpcConfig {
    pub public_config: MpcPublicConfig,
    pub expectations: MpcConfigExpectations,
}

impl HostMpcConfig {
    fn scaffold(approved_enclave_measurement: MpcAttestationDigest) -> Self {
        let public_config = MpcPublicConfig {
            chain_id: DEFAULT_MPC_CHAIN_ID,
            domain_id: DEFAULT_MPC_DOMAIN_ID,
            key_id: DEFAULT_MPC_KEY_ID,
            hpke_public_key: DEFAULT_MPC_HPKE_PUBLIC_KEY,
            reader_key_algorithm: MpcReaderKeyAlgorithm::X25519,
            ciphertext_suite: MpcCiphertextSuite::HpkeX25519HkdfSha256Aes256Gcm,
            approved_enclave_measurement,
        };
        let expectations = MpcConfigExpectations {
            chain_id: public_config.chain_id,
            domain_id: public_config.domain_id,
            reader_key_algorithm: public_config.reader_key_algorithm,
            ciphertext_suite: public_config.ciphertext_suite,
        };
        Self {
            public_config,
            expectations,
        }
    }

    fn validate(&self) -> Result<(), HostConfigError> {
        self.public_config
            .check_compatibility(&self.expectations)
            .map_err(
                |incompatibility| HostConfigError::IncompatibleMpcPublicConfig {
                    detail: incompatibility.to_string(),
                },
            )
    }

    fn plaintext_materializer(&self) -> PlaintextMaterializer {
        PlaintextMaterializer::new(self.public_config.key_id)
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
    /// Trusted MPC control-plane configuration plus the compatibility contract
    /// the host expects future loads to satisfy. The active `key_id` here
    /// drives Plaintext Handle materialization from the moment the host is
    /// constructed.
    pub mpc: HostMpcConfig,
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
        let approved_enclave_measurement = MpcAttestationDigest([0x42; 32]);
        Self {
            deployment_label: "local-development".to_string(),
            chain_view: ChainView::default(),
            retry_policy: RetryPolicy::default(),
            mpc: HostMpcConfig::scaffold(approved_enclave_measurement),
            enclave_attestation: EnclaveAttestationConfig::Local(LocalEnclaveAttestationConfig {
                enclave_public_key: vec![0x44; 48],
                enclave_measurement: coprocessor_nitro_enclave::AttestationDigest(
                    approved_enclave_measurement.0,
                ),
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
            mpc: HostMpcConfig::scaffold(MpcAttestationDigest(enclave_measurement.0)),
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

    pub(super) fn plaintext_materializer(&self) -> PlaintextMaterializer {
        self.mpc.plaintext_materializer()
    }

    pub(super) fn validate(&self) -> Result<(), HostConfigError> {
        if self.deployment_label.trim().is_empty() {
            return Err(HostConfigError::EmptyDeploymentLabel);
        }
        if self.retry_policy.max_attempts == 0 {
            return Err(HostConfigError::RetryPolicyRequiresAttempt);
        }
        self.mpc.validate()?;
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
        let configured_measurement = self.mpc.public_config.approved_enclave_measurement;
        let attestation_measurement = match &self.enclave_attestation {
            EnclaveAttestationConfig::Local(cfg) => MpcAttestationDigest(cfg.enclave_measurement.0),
            EnclaveAttestationConfig::Nitro(cfg) => {
                MpcAttestationDigest(cfg.approved_enclave_measurement.0)
            }
        };
        if configured_measurement != attestation_measurement {
            return Err(HostConfigError::MpcEnclaveMeasurementMismatch {
                mpc_measurement: configured_measurement,
                enclave_measurement: attestation_measurement,
            });
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
    #[error("incompatible MPC public config: {detail}")]
    IncompatibleMpcPublicConfig { detail: String },
    /// Nitro adapter configuration failed its own validation rules.
    /// `detail` is the non-secret description of the failing rule.
    #[error("invalid Enclave attestation config: {detail}")]
    InvalidEnclaveAttestationConfig { detail: String },
    #[error(
        "MPC approved measurement {mpc_measurement:?} does not match Enclave measurement {enclave_measurement:?}"
    )]
    MpcEnclaveMeasurementMismatch {
        mpc_measurement: MpcAttestationDigest,
        enclave_measurement: MpcAttestationDigest,
    },
}
