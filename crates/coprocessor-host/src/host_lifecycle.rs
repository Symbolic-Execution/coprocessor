/// Host lifecycle, readiness, dependency availability, and basic accessors.
use coprocessor_handle_graph_core::HandleGraphCore;

use super::{
    CoprocessorHost, DependencyName, HostConfig, HostStartError, LifecycleState, Readiness,
};

impl CoprocessorHost {
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

    fn unavailable_dependencies(&self) -> Vec<DependencyName> {
        DependencyName::all()
            .into_iter()
            .filter(|dep| !self.available_dependencies.contains(dep))
            .collect()
    }
}
