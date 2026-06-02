//! Durable storage for canonical Handle Records and consumed Chain Event refs.
//!
//! The [`HandlePersistence`] trait is the domain-facing seam for persisting
//! the Coprocessor Host's Handle Graph state. It hides whether the backing
//! store is in-process, an embedded KV, or a relational database; callers
//! work in terms of [`HandleRecord`] and [`ChainEventRef`].
//!
//! [`HandleGraphCore`](crate::HandleGraphCore) writes through this seam during
//! ingestion and orphan discard, and rehydrates from it after process restart
//! via [`HandleGraphCore::restore_from_persistence`](
//! crate::HandleGraphCore::restore_from_persistence). The trait does not
//! enforce ordering between record writes and event-ref writes: when both
//! happen for the same event, the Host writes the record first so a partial
//! crash can be recovered without losing the canonical record.
//!
//! Per ADR 0004 only durable state belongs here: canonical Handle Records
//! (with their state-specific payloads — [`SystemCiphertextV1`](
//! crate::SystemCiphertextV1) and [`MaterializationReceipt`](
//! crate::MaterializationReceipt) for Ready; [`FailureReason`](
//! crate::FailureReason) for Failed) and consumed [`ChainEventRef`] values.
//! Plaintext Private Values, raw Attestation documents, and
//! EnclaveCiphertextV1 must not flow through this trait.

use std::collections::{HashMap, HashSet};

use crate::{ChainEventRef, HandleKey, HandleRecord};

/// Domain-facing persistence interface for the Coprocessor Host's Handle
/// Graph state.
///
/// Behavior contract:
///
/// - [`put_handle_record`](Self::put_handle_record) is upsert by
///   [`HandleKey`]: re-persisting the same key replaces the prior record. The
///   Host re-puts a record when its tombstone flag flips during Orphan
///   Discard; implementations must overwrite rather than merge.
/// - [`record_consumed_event`](Self::record_consumed_event) is idempotent by
///   [`ChainEventRef`]; the same reference re-recorded is a no-op.
/// - Implementations must surface every previously written record from
///   [`handle_records`](Self::handle_records) and every previously recorded
///   event ref from [`consumed_events`](Self::consumed_events) so that
///   `HandleGraphCore::restore_from_persistence` can reconstruct the prior
///   in-process state exactly.
///
/// The trait is intentionally synchronous and infallible: it is the seam an
/// in-process store, an embedded KV, or a future RPC store can sit behind,
/// but it is not itself an RPC surface. Async or fallible backends should
/// wrap their failure modes at a layer above this trait so the
/// `HandleGraphCore` interface stays focused on lineage and ingestion rather
/// than IO error handling.
pub trait HandlePersistence {
    /// Upserts a canonical Handle Record. Used during ingestion (Pending,
    /// Ready, or Failed canonical records) and during Orphan Discard (to
    /// persist the flipped `is_tombstoned` flag).
    fn put_handle_record(&mut self, record: HandleRecord);

    /// Looks up a previously persisted Handle Record by Handle Key, including
    /// tombstoned records. This mirrors the audit/debug semantics of
    /// [`HandleGraphCore::handle_record_for_audit`](
    /// crate::HandleGraphCore::handle_record_for_audit): persistence does
    /// not hide tombstoned records, since canonical/tombstoned filtering is
    /// the Handle Graph's responsibility.
    fn handle_record(&self, handle_key: &HandleKey) -> Option<HandleRecord>;

    /// Returns every persisted Handle Record. Used by
    /// [`HandleGraphCore::restore_from_persistence`](
    /// crate::HandleGraphCore::restore_from_persistence) to rebuild the
    /// in-process record map after restart. Order is unspecified.
    fn handle_records(&self) -> Vec<HandleRecord>;

    /// Marks a Chain Event as consumed. Idempotent: the same reference
    /// recorded twice has the same effect as recording it once.
    fn record_consumed_event(&mut self, event_ref: ChainEventRef);

    /// Returns true when the given Chain Event has previously been marked
    /// consumed.
    fn is_consumed_event(&self, event_ref: &ChainEventRef) -> bool;

    /// Returns every previously recorded Chain Event reference. Used by
    /// `HandleGraphCore::restore_from_persistence` so that ingestion replay
    /// after restart remains idempotent by ChainEventRef.
    fn consumed_events(&self) -> Vec<ChainEventRef>;
}

/// In-process backing for [`HandlePersistence`]. This is the default backend
/// the workspace ships until the durable persistence store decision (issue
/// #18) lands; tests and any local-only deployment use it directly.
///
/// The store does not persist across process restart on its own. Tests
/// exercise restart semantics by handing the same instance to a freshly
/// constructed [`HandleGraphCore`](crate::HandleGraphCore) via
/// [`HandleGraphCore::restore_from_persistence`](
/// crate::HandleGraphCore::restore_from_persistence), which is the same
/// rehydration path a durable backend will use.
#[derive(Clone, Debug, Default)]
pub struct InMemoryHandlePersistence {
    records: HashMap<HandleKey, HandleRecord>,
    consumed_events: HashSet<ChainEventRef>,
}

impl InMemoryHandlePersistence {
    pub fn new() -> Self {
        Self::default()
    }
}

impl HandlePersistence for InMemoryHandlePersistence {
    fn put_handle_record(&mut self, record: HandleRecord) {
        self.records.insert(record.handle_key, record);
    }

    fn handle_record(&self, handle_key: &HandleKey) -> Option<HandleRecord> {
        self.records.get(handle_key).cloned()
    }

    fn handle_records(&self) -> Vec<HandleRecord> {
        self.records.values().cloned().collect()
    }

    fn record_consumed_event(&mut self, event_ref: ChainEventRef) {
        self.consumed_events.insert(event_ref);
    }

    fn is_consumed_event(&self, event_ref: &ChainEventRef) -> bool {
        self.consumed_events.contains(event_ref)
    }

    fn consumed_events(&self) -> Vec<ChainEventRef> {
        self.consumed_events.iter().copied().collect()
    }
}
