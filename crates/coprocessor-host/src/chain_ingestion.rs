//! Chain Event Ingestion for the Coprocessor Host.
//!
//! This module owns the pull boundary between the host and a decoded `symVM`
//! Event Surface source. A single ingestion pass:
//!
//! 1. Poll the source at the host's configured Chain View. The poll yields
//!    both new Chain Events and the [`ChainEventRef`]s of previously consumed
//!    events that have left the chosen Chain View (e.g. dropped by a reorg).
//! 2. Apply Orphan Discard for the orphaned event refs, tombstoning the
//!    matching Handle Records and cascading through Handle Lineage.
//! 3. Sort the returned events into canonical log order.
//! 4. Apply each event to the owned [`HandleGraphCore`]. The core dedupes by
//!    [`ChainEventRef`], so re-polling an already-consumed event is a no-op.
//!
//! Orphan Discard is applied before the new events: a reorg-style poll that
//! carries both the orphan ref and replacement events arrives in one batch,
//! and discarding first means the cascade is computed against the pre-replay
//! Handle Graph state.
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

/// Single poll result from a [`ChainEventSource`]. Carries both the new
/// Chain Events confirmed at or above the requested [`ChainView`] and the
/// [`ChainEventRef`]s of previously consumed events that no longer belong to
/// the chosen Chain View. The source owns canonicality tracking; the host
/// just applies what the source reports.
///
/// An empty struct (no events, no orphans) means there is no new work at this
/// view right now; it is not an error.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChainViewPoll {
    /// New Chain Events confirmed at or above the requested view. The host
    /// sorts these into canonical log order before applying them.
    pub events: Vec<ChainEvent>,
    /// [`ChainEventRef`]s of previously consumed events whose blocks have
    /// left the chosen Chain View (e.g. via a reorg). The host applies Orphan
    /// Discard for each ref, tombstoning the matching Handle Records and
    /// cascading through Handle Lineage. Unknown or never-consumed refs are
    /// no-ops.
    pub orphaned_event_refs: Vec<ChainEventRef>,
}

/// Pull-based seam onto the `symVM` Event Surface. Each call returns a
/// [`ChainViewPoll`] describing both new events and orphaned-event refs. The
/// source is expected to:
///
/// - return only events confirmed at or above the requested view;
/// - not filter by [`ChainEventRef`] for events — the host owns idempotency;
/// - not reorder events for canonical order — the host sorts;
/// - report orphan refs for previously surfaced events whose blocks have left
///   the chosen view, including repeated reorg signals (the host's Orphan
///   Discard is idempotent).
pub trait ChainEventSource {
    fn poll(&mut self, view: ChainView) -> ChainViewPoll;
}

/// Per-pass ingestion accounting. Each pulled Chain Event lands in exactly
/// one of the three event counters, mirroring the three [`IngestionOutcome`]
/// variants produced by the Handle Graph Core. The two tombstone counters
/// summarize Orphan Discard for the same pass.
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
    /// Handle Records tombstoned because the source flagged their
    /// [`ChainEventRef`] as orphaned by the chosen Chain View.
    pub directly_tombstoned: usize,
    /// Handle Records tombstoned because their Handle Lineage depends on a
    /// directly-tombstoned record (possibly transitively). A record is
    /// counted at most once across `directly_tombstoned` and
    /// `cascade_tombstoned` on a given pass.
    pub cascade_tombstoned: usize,
}

impl IngestionReport {
    fn count_outcome(&mut self, outcome: IngestionOutcome) {
        match outcome {
            IngestionOutcome::Recorded(_) => self.recorded += 1,
            IngestionOutcome::Idempotent => self.idempotent += 1,
            IngestionOutcome::DuplicateHandleKeyRejected(_) => self.duplicates_rejected += 1,
        }
    }
}

impl CoprocessorHost {
    /// Drive a single Chain Event Ingestion pass: poll `source` at the host's
    /// configured [`ChainView`], apply Orphan Discard for orphaned event refs,
    /// canonically order the returned events, and apply each to the owned
    /// [`HandleGraphCore`].
    ///
    /// Returns an [`IngestionReport`] summarizing the pass. Repeated calls
    /// with already-consumed events are idempotent because the Handle Graph
    /// Core dedupes by [`ChainEventRef`]; repeated orphan refs are idempotent
    /// because Orphan Discard skips already-tombstoned records.
    pub fn ingest_chain_events<S: ChainEventSource>(&mut self, source: &mut S) -> IngestionReport {
        let view = self.config().chain_view;
        let ChainViewPoll {
            mut events,
            orphaned_event_refs,
        } = source.poll(view);

        let mut report = IngestionReport::default();

        let discard = self
            .handle_graph_core_mut()
            .apply_orphan_discard(&orphaned_event_refs);
        report.directly_tombstoned = discard.directly_tombstoned.len();
        report.cascade_tombstoned = discard.cascade_tombstoned.len();

        sort_by_canonical_log_order(&mut events);
        for event in events {
            let outcome = self.handle_graph_core_mut().apply_chain_event(event);
            report.count_outcome(outcome);
        }
        report
    }
}

/// Sorts events into canonical log order: `(chain_id, block_number,
/// log_index)`. EVM log indices are unique within a block and increase with
/// transaction order, so this key is the canonical confirmation order even
/// across multiple transactions in the same block.
fn sort_by_canonical_log_order(events: &mut [ChainEvent]) {
    events.sort_by_key(canonical_log_order_key);
}

fn canonical_log_order_key(event: &ChainEvent) -> (u64, u64, u32) {
    let ChainEventRef {
        chain_id,
        block_number,
        log_index,
        ..
    } = chain_event_ref(event);
    (chain_id.0, block_number, log_index)
}

fn chain_event_ref(event: &ChainEvent) -> ChainEventRef {
    match event {
        ChainEvent::ImportedHandle(e) => e.event_ref,
        ChainEvent::PlaintextHandle(e) => e.event_ref,
        ChainEvent::DerivedHandleOperation(e) => e.event_ref,
    }
}
