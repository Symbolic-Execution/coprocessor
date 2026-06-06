/// Host construction and restore-from-persistence entry points.
use std::collections::BTreeSet;

use coprocessor_handle_graph_core::{HandleGraphCore, HandlePersistence, PlaintextMaterializer};

use super::{
    CoprocessorHost, HostConfig, HostConfigError, LifecycleState, ResolutionIntents,
    ResolutionTaskClaims,
};

impl CoprocessorHost {
    /// Validate `config` without starting the host. Useful for smoke-checks
    /// that want to fail fast before doing any work.
    pub fn validate_config(config: &HostConfig) -> Result<(), HostConfigError> {
        config.validate()
    }

    /// Construct a host in the [`LifecycleState::NotStarted`] phase.
    ///
    /// The owned [`HandleGraphCore`] is seeded with a
    /// [`PlaintextMaterializer`] bound to the host's trusted active MPC key
    /// id, so Plaintext Handle ingestion never falls back to the all-zero
    /// default materializer.
    pub fn new(config: HostConfig) -> Self {
        let handle_graph_core =
            HandleGraphCore::with_plaintext_materializer(config.plaintext_materializer());
        Self::from_handle_graph_core(config, handle_graph_core)
    }

    /// Construct a host whose [`HandleGraphCore`] is restored from
    /// `persistence`. The restored graph includes Handle Records, consumed
    /// Chain Event refs, and tombstone state, so host reads, ingestion replay,
    /// and Resolution Readiness observe the same graph state as before the
    /// restart.
    ///
    /// The restored host returns in [`LifecycleState::NotStarted`]; callers
    /// must still invoke [`Self::start`] before the host serves traffic, so
    /// configuration validation and dependency wiring follow the same path as
    /// a fresh boot.
    ///
    /// The restored Handle Graph is re-seeded with a
    /// [`PlaintextMaterializer`] bound to the host's configured active MPC key
    /// id, so post-restart Plaintext Handle ingestion keeps producing real
    /// `SystemCiphertextV1` envelopes without any extra caller wiring.
    pub fn restore_from_persistence<P: HandlePersistence>(
        config: HostConfig,
        persistence: &P,
    ) -> Self {
        let handle_graph_core = HandleGraphCore::restore_from_persistence_with_materializer(
            persistence,
            config.plaintext_materializer(),
        );
        Self::from_handle_graph_core(config, handle_graph_core)
    }

    /// Same as [`Self::restore_from_persistence`], but binds the supplied
    /// `plaintext_materializer` so post-restart Plaintext Handle ingestion
    /// keeps producing real `SystemCiphertextV1` envelopes bound to the host's
    /// active MPC key id.
    pub fn restore_from_persistence_with_materializer<P: HandlePersistence>(
        config: HostConfig,
        persistence: &P,
        plaintext_materializer: PlaintextMaterializer,
    ) -> Self {
        Self::from_handle_graph_core(
            config,
            HandleGraphCore::restore_from_persistence_with_materializer(
                persistence,
                plaintext_materializer,
            ),
        )
    }

    fn from_handle_graph_core(config: HostConfig, handle_graph_core: HandleGraphCore) -> Self {
        Self {
            config,
            handle_graph_core,
            lifecycle: LifecycleState::NotStarted,
            available_dependencies: BTreeSet::new(),
            resolution_intents: ResolutionIntents::default(),
            resolution_claims: ResolutionTaskClaims::default(),
        }
    }
}
