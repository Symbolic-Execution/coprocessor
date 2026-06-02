//! Coprocessor Host runtime scaffold.
//!
//! This crate is the non-private orchestration side of the Coprocessor. It
//! owns the [`HandleGraphCore`], loads validated configuration, and exposes a
//! lifecycle plus a readiness signal that distinguishes a configuration-loaded
//! host from a host whose external dependencies (`symVM` event surface, MPC,
//! Enclave) are still unwired or unreachable.
//!
//! Scope of this scaffold: no chain RPC, no MPC client, no Enclave runtime,
//! no HTTP server. Those seams are named through [`DependencyName`] so each
//! future slice can flip a dependency from `Unavailable` to `Available` without
//! reshaping the [`Readiness`] surface.

use std::collections::BTreeSet;

use coprocessor_handle_graph_core::{HandleGraphCore, HandleKey};

mod internal_api;

pub use internal_api::{HandleStateFailureCategory, HandleStateView};

mod chain_ingestion;

pub use chain_ingestion::{ChainEventSource, ChainView, ChainViewPoll, IngestionReport};

mod resolution_intent;

use resolution_intent::ResolutionIntents;
pub use resolution_intent::{RequestId, ResolutionIntent};

const ALL_DEPENDENCIES: [DependencyName; 3] = [
    DependencyName::SymVmEventSurface,
    DependencyName::Mpc,
    DependencyName::Enclave,
];

/// Named dependencies that the Coprocessor Host requires before it can serve
/// resolution work. Each variant marks a seam that future slices will wire.
/// Until a seam is wired, the host reports it as `Unavailable` in [`Readiness`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DependencyName {
    /// Chain Event Ingestion from the `symVM` Event Surface.
    SymVmEventSurface,
    /// MPC threshold-key custody and ciphertext transformation.
    Mpc,
    /// Private computation Enclave runtime.
    Enclave,
}

impl DependencyName {
    /// Every dependency the host runtime currently models. The set is closed:
    /// adding a dependency means extending [`DependencyName`] and surfacing the
    /// seam in the readiness contract.
    pub fn all() -> [DependencyName; 3] {
        ALL_DEPENDENCIES
    }
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
}

impl HostConfig {
    /// Configuration suitable for local development and the in-process tests
    /// that drive this crate. It never reaches MPC, the Enclave, or a chain
    /// RPC, and never reads credentials from the environment.
    pub fn for_local_development() -> Self {
        Self {
            deployment_label: "local-development".to_string(),
            chain_view: ChainView::default(),
        }
    }

    fn validate(&self) -> Result<(), HostConfigError> {
        if self.deployment_label.trim().is_empty() {
            return Err(HostConfigError::EmptyDeploymentLabel);
        }
        Ok(())
    }
}

/// Reasons configuration validation can fail before the host starts. Failure
/// keeps the host in [`LifecycleState::NotStarted`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostConfigError {
    EmptyDeploymentLabel,
}

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

/// Coprocessor Host runtime. Owns the in-memory [`HandleGraphCore`] and the
/// availability state of every named dependency. This scaffold does not spawn
/// background tasks; future slices that introduce an async runtime, chain
/// event ingestion, scheduler, or HTTP server will hang off the same handle.
pub struct CoprocessorHost {
    config: HostConfig,
    handle_graph_core: HandleGraphCore,
    lifecycle: LifecycleState,
    /// Set of dependencies currently reachable. The complement against
    /// [`DependencyName::all`] is the `Unavailable` list reported in readiness.
    available_dependencies: BTreeSet<DependencyName>,
    /// Per-Handle-Key resolution intent registry. Populated by
    /// [`Self::resolve_handle`] whenever a Handle Resolution Request lands on
    /// a Pending Derived Handle; repeated requests collapse onto the same
    /// intent so the future Resolution Scheduler sees one piece of work per
    /// Handle.
    resolution_intents: ResolutionIntents,
}

impl CoprocessorHost {
    /// Validate `config` without starting the host. Useful for smoke-checks
    /// that want to fail fast before doing any work.
    pub fn validate_config(config: &HostConfig) -> Result<(), HostConfigError> {
        config.validate()
    }

    /// Construct a host in the [`LifecycleState::NotStarted`] phase.
    pub fn new(config: HostConfig) -> Self {
        Self {
            config,
            handle_graph_core: HandleGraphCore::new(),
            lifecycle: LifecycleState::NotStarted,
            available_dependencies: BTreeSet::new(),
            resolution_intents: ResolutionIntents::default(),
        }
    }

    /// Validate configuration and transition into [`LifecycleState::Running`].
    /// Idempotent: calling `start` on a running host is a no-op. Calling it
    /// on a shut-down host is an error.
    pub fn start(&mut self) -> Result<(), HostStartError> {
        match self.lifecycle {
            LifecycleState::Running => Ok(()),
            LifecycleState::ShutDown => Err(HostStartError::AlreadyShutDown),
            LifecycleState::NotStarted => {
                self.config
                    .validate()
                    .map_err(HostStartError::InvalidConfig)?;
                self.lifecycle = LifecycleState::Running;
                Ok(())
            }
        }
    }

    /// Transition into [`LifecycleState::ShutDown`]. Idempotent. After
    /// shutdown the Handle Graph Core is still readable for audit but the
    /// host reports [`Readiness::ShutDown`].
    pub fn shutdown(&mut self) {
        self.lifecycle = LifecycleState::ShutDown;
    }

    /// Current lifecycle phase.
    pub fn lifecycle(&self) -> LifecycleState {
        self.lifecycle
    }

    /// Readiness signal derived from lifecycle phase and dependency
    /// availability. The Coordinator-facing health/readiness endpoint should
    /// wrap this value.
    pub fn readiness(&self) -> Readiness {
        match self.lifecycle {
            LifecycleState::NotStarted => Readiness::NotStarted,
            LifecycleState::ShutDown => Readiness::ShutDown,
            LifecycleState::Running => {
                let unavailable = self.unavailable_dependencies();
                if unavailable.is_empty() {
                    Readiness::Ready
                } else {
                    Readiness::ConfigurationLoaded { unavailable }
                }
            }
        }
    }

    /// Mark a named dependency as reachable. Reserved for the slices that
    /// wire chain, MPC, and Enclave seams; calling it from a test simulates
    /// that wiring without pulling in those subsystems.
    pub fn mark_dependency_available(&mut self, dep: DependencyName) {
        self.available_dependencies.insert(dep);
    }

    /// Mark a named dependency as unreachable. Used when a previously
    /// available dependency becomes degraded (e.g. RPC outage).
    pub fn mark_dependency_unavailable(&mut self, dep: DependencyName) {
        self.available_dependencies.remove(&dep);
    }

    /// Borrow the owned [`HandleGraphCore`]. Coordinator-facing reads should
    /// go through a dedicated API in a later slice; this borrow exists so the
    /// scaffold can prove ownership without exposing mutability broadly.
    pub fn handle_graph_core(&self) -> &HandleGraphCore {
        &self.handle_graph_core
    }

    /// Mutable borrow of the [`HandleGraphCore`]. Used by Chain Event
    /// Ingestion in a later slice; tests use it to drive ingestion against the
    /// host-owned core rather than a free-standing one.
    pub fn handle_graph_core_mut(&mut self) -> &mut HandleGraphCore {
        &mut self.handle_graph_core
    }

    /// Read-only access to the loaded configuration.
    pub fn config(&self) -> &HostConfig {
        &self.config
    }

    /// Internal Coordinator API: GET Handle State.
    ///
    /// Returns the Coordinator-facing [`HandleStateView`] for `handle_key`.
    /// Unknown Handle Keys and tombstoned Handle Records both resolve to
    /// [`HandleStateView::Unknown`]; known Canonical Handle Records project to
    /// `Pending`, `Ready { .. }`, or `Failed { category }` according to their
    /// Handle State. Lifecycle does not gate this read; callers that need
    /// the host to be Running must check [`Self::readiness`] first.
    pub fn get_handle_state(&self, handle_key: &HandleKey) -> HandleStateView {
        self.project_handle_state(handle_key)
    }

    /// Internal Coordinator API: Resolve Handle Request.
    ///
    /// Returns the same [`HandleStateView`] projection as
    /// [`Self::get_handle_state`] for already-known Canonical Handle Records,
    /// and additionally attaches `request_id` to the resolution intent for
    /// `handle_key` when the projected view is [`HandleStateView::Pending`].
    /// `RequestId` identifies the request flow only; the Handle Graph lookup
    /// key is `handle_key`, so repeated requests for the same Pending Derived
    /// Handle collapse onto a single [`ResolutionIntent`] regardless of how
    /// many distinct `RequestId`s have attached.
    ///
    /// Ready, Failed, and Unknown projections do not register a resolution
    /// intent: the first two already carry their stable current state, and an
    /// unknown or tombstoned Handle Key has no record for the Resolution
    /// Scheduler to attach to. Chain Event Ingestion remains the only source
    /// of Handle Records, so this call cannot move Handle Graph state by
    /// itself even when a new resolution intent is registered.
    pub fn resolve_handle(
        &mut self,
        request_id: RequestId,
        handle_key: &HandleKey,
    ) -> HandleStateView {
        let view = self.project_handle_state(handle_key);
        if matches!(view, HandleStateView::Pending) {
            self.resolution_intents.attach(*handle_key, request_id);
        }
        view
    }

    /// Snapshot of the resolution intent for `handle_key`, or `None` if no
    /// Handle Resolution Request has attached to it. The returned
    /// `attached_request_ids` list is sorted and deduplicated.
    pub fn pending_resolution_intent(&self, handle_key: &HandleKey) -> Option<ResolutionIntent> {
        self.resolution_intents.intent(handle_key)
    }

    /// Number of distinct Handle Keys that currently carry a resolution
    /// intent. Repeated `RequestId`s for the same Handle Key do not inflate
    /// this count.
    pub fn pending_resolution_intent_count(&self) -> usize {
        self.resolution_intents.intent_count()
    }

    fn project_handle_state(&self, handle_key: &HandleKey) -> HandleStateView {
        internal_api::project_canonical(self.handle_graph_core.canonical_handle(handle_key))
    }

    fn unavailable_dependencies(&self) -> Vec<DependencyName> {
        DependencyName::all()
            .into_iter()
            .filter(|dep| !self.available_dependencies.contains(dep))
            .collect()
    }
}

/// Reasons [`CoprocessorHost::start`] can fail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostStartError {
    InvalidConfig(HostConfigError),
    AlreadyShutDown,
}
