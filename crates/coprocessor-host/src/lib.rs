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

use coprocessor_handle_graph_core::HandleGraphCore;

mod derived_receipt;
mod internal_api;

pub use derived_receipt::DerivedHandleReceiptView;
pub use internal_api::{HandleStateFailureCategory, HandleStateView};

mod chain_ingestion;

pub use chain_ingestion::{ChainEventSource, ChainView, ChainViewPoll, IngestionReport};

mod resolution_intent;

use resolution_intent::ResolutionIntents;
pub use resolution_intent::{RequestId, ResolutionIntent};

mod resolution_scheduler;

pub use resolution_scheduler::ResolutionTask;
use resolution_scheduler::ResolutionTaskClaims;

mod to_enclave_transformation;

pub use to_enclave_transformation::{
    transform_resolution_task_inputs, TransformResolutionInputsError,
};

mod resolve_enclave;

mod dependency;
pub use dependency::DependencyName;

mod config;
pub use config::{
    EnclaveAttestationConfig, HostConfig, HostConfigError, HostMpcConfig, RetryPolicy,
};

mod lifecycle;
pub use lifecycle::{HostStartError, LifecycleState, Readiness};

mod construction;
mod host_lifecycle;
mod resolution;

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
    /// Handle Resolution Request attachments grouped by Handle Key.
    resolution_intents: ResolutionIntents,
    /// Resolution Scheduler claims grouped by Handle Key. A claim records
    /// that the scheduler has dispatched a Resolution Task for a Pending
    /// Derived Handle so duplicate scheduler ticks do not re-dispatch it.
    resolution_claims: ResolutionTaskClaims,
}
