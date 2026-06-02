//! Chain Event Ingestion for the Coprocessor Host.
//!
//! Wires the host to a [`ChainEventSource`] — the seam that pulls decoded
//! Chain Events from the `symVM` Event Surface at a chosen [`ChainView`] — and
//! drives a single ingestion pass:
//!
//! 1. Poll the source at the host's configured Chain View.
//! 2. Sort the returned events into canonical log order:
//!    `(chain_id, block_number, log_index)`. EVM log indices are unique within
//!    a block and increase with transaction order, so this sort is the
//!    canonical confirmation order even across multiple transactions in the
//!    same block.
//! 3. Apply each event to the owned [`HandleGraphCore`]. The core dedupes by
//!    [`ChainEventRef`], so re-polling an already-consumed event is a no-op.
//!
//! The seam intentionally does no chain RPC, no decoding, and no AAD or
//! attestation checks. Production sources will implement [`ChainEventSource`]
//! against a real chain client; tests substitute a fake.

use coprocessor_handle_graph_core::{ChainEvent, ChainEventRef, IngestionOutcome};

use crate::CoprocessorHost;

/// The confirmation view of the `symVM` Event Surface from which the host
/// consumes Chain Events. The default is [`ChainView::Safe`]; deployments
/// that require stricter confirmation can choose [`ChainView::Finalized`].
///
/// The host never converts between views: a single deployment is bound to
/// one view at start, and a stricter view does not retroactively re-confirm
/// earlier events.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ChainView {
    #[default]
    Safe,
    Finalized,
}

/// Pull-based seam onto the `symVM` Event Surface. Each call returns the
/// batch of decoded Chain Events whose confirmation status is at least as
/// strong as `view`. The source is expected to:
///
/// - return only events confirmed at or above the requested view;
/// - not filter by [`ChainEventRef`] — the host owns idempotency;
/// - not reorder for canonical order — the host sorts.
///
/// An empty return means there is no new work at this view right now; it is
/// not an error.
pub trait ChainEventSource {
    fn poll_events(&mut self, view: ChainView) -> Vec<ChainEvent>;
}

/// Per-pass ingestion accounting. Each pulled Chain Event lands in exactly
/// one of the three counters, mirroring the three [`IngestionOutcome`]
/// variants produced by the Handle Graph Core.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IngestionReport {
    /// New canonical Handle Records created on this pass.
    pub recorded: usize,
    /// Chain Events whose [`ChainEventRef`] was already consumed, so no
    /// further work was done.
    pub idempotent: usize,
    /// Chain Events that named a Handle Key already bound to a canonical
    /// Handle Record. The first canonical record is preserved; the rejected
    /// record is surfaced to the host but not stored.
    pub duplicates_rejected: usize,
}

impl IngestionReport {
    fn record_outcome(&mut self, outcome: IngestionOutcome) {
        match outcome {
            IngestionOutcome::Recorded(_) => self.recorded += 1,
            IngestionOutcome::Idempotent => self.idempotent += 1,
            IngestionOutcome::DuplicateHandleKeyRejected(_) => self.duplicates_rejected += 1,
        }
    }
}

impl CoprocessorHost {
    /// Drive a single Chain Event Ingestion pass: poll `source` at the host's
    /// configured [`ChainView`], canonically order the returned events, and
    /// apply each to the owned [`HandleGraphCore`].
    ///
    /// Returns an [`IngestionReport`] summarizing the pass. Repeated calls
    /// with already-consumed events are idempotent because the Handle Graph
    /// Core dedupes by [`ChainEventRef`].
    pub fn ingest_chain_events<S: ChainEventSource>(&mut self, source: &mut S) -> IngestionReport {
        let view = self.config().chain_view;
        let mut events = source.poll_events(view);
        sort_canonical(&mut events);

        let mut report = IngestionReport::default();
        for event in events {
            let outcome = self.handle_graph_core_mut().apply_chain_event(event);
            report.record_outcome(outcome);
        }
        report
    }
}

/// Sorts events into canonical log order: `(chain_id, block_number,
/// log_index)`. EVM log indices are unique within a block and increase with
/// transaction order, so this key is the canonical confirmation order even
/// across multiple transactions in the same block.
fn sort_canonical(events: &mut [ChainEvent]) {
    events.sort_by_key(canonical_sort_key);
}

fn canonical_sort_key(event: &ChainEvent) -> (u64, u64, u32) {
    let event_ref = chain_event_ref(event);
    (
        event_ref.chain_id.0,
        event_ref.block_number,
        event_ref.log_index,
    )
}

fn chain_event_ref(event: &ChainEvent) -> ChainEventRef {
    match event {
        ChainEvent::ImportedHandle(e) => e.event_ref,
        ChainEvent::PlaintextHandle(e) => e.event_ref,
        ChainEvent::DerivedHandleOperation(e) => e.event_ref,
    }
}
