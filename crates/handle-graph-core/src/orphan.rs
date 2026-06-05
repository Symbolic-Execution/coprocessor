/// Orphan Discard behavior: tombstone records and cascade through lineage.

use std::collections::HashSet;

use super::persistence::HandlePersistence;
use super::types::{ChainEventRef, HandleKey, HandleLineage, HandleRecord, OrphanDiscardOutcome};
use super::HandleGraphCore;

impl HandleGraphCore {
    /// Applies a manually supplied set of canonicality changes by tombstoning
    /// every Handle Record whose `event_ref` matches one of
    /// `orphaned_event_refs`, then cascades the tombstone through Handle
    /// Lineage: any Derived Handle whose inputs include a tombstoned record is
    /// itself tombstoned, transitively. Cascade applies even when the
    /// downstream Derived Handle's own `event_ref` is still canonical.
    ///
    /// Tombstoning is not a `Failed` Handle State and never deletes records;
    /// the underlying `event_ref` and `state` remain available through
    /// [`HandleGraphCore::handle_record_for_audit`]. Tombstoned records are
    /// excluded from [`HandleGraphCore::canonical_handle`] and from
    /// [`HandleGraphCore::resolution_readiness`].
    pub fn apply_orphan_discard(
        &mut self,
        orphaned_event_refs: &[ChainEventRef],
    ) -> OrphanDiscardOutcome {
        let orphaned: HashSet<ChainEventRef> = orphaned_event_refs.iter().copied().collect();

        let directly_tombstoned: Vec<HandleKey> = self
            .records
            .iter()
            .filter(|(_, record)| !record.is_tombstoned && orphaned.contains(&record.event_ref))
            .map(|(key, _)| *key)
            .collect();
        self.mark_tombstoned(&directly_tombstoned);

        let mut cascade_tombstoned: Vec<HandleKey> = Vec::new();
        loop {
            let newly_tombstoned: Vec<HandleKey> = self
                .records
                .iter()
                .filter(|(_, record)| self.depends_on_tombstoned_input(record))
                .map(|(key, _)| *key)
                .collect();
            if newly_tombstoned.is_empty() {
                break;
            }
            self.mark_tombstoned(&newly_tombstoned);
            cascade_tombstoned.extend(newly_tombstoned);
        }

        OrphanDiscardOutcome {
            directly_tombstoned,
            cascade_tombstoned,
        }
    }

    /// Applies an Orphan Discard and mirrors every flipped Handle Record into
    /// `persistence`. Returns the same [`OrphanDiscardOutcome`] as
    /// [`HandleGraphCore::apply_orphan_discard`].
    ///
    /// The tombstone flag is the only field that changes during Orphan
    /// Discard, but the whole record is re-put so the persistence backend
    /// does not need a separate "update flag" operation. Cascade-tombstoned
    /// records are written in addition to directly-tombstoned ones so a
    /// restart restores the full cascade rather than the discard root only.
    pub fn apply_orphan_discard_with_persistence<P: HandlePersistence>(
        &mut self,
        orphaned_event_refs: &[ChainEventRef],
        persistence: &mut P,
    ) -> OrphanDiscardOutcome {
        let outcome = self.apply_orphan_discard(orphaned_event_refs);
        for key in outcome
            .directly_tombstoned
            .iter()
            .chain(outcome.cascade_tombstoned.iter())
        {
            if let Some(record) = self.records.get(key) {
                persistence.put_handle_record(record.clone());
            }
        }
        outcome
    }

    /// Marks every record in `keys` as tombstoned. Keys with no matching
    /// record are silently skipped.
    fn mark_tombstoned(&mut self, keys: &[HandleKey]) {
        for key in keys {
            if let Some(record) = self.records.get_mut(key) {
                record.is_tombstoned = true;
            }
        }
    }

    /// True when `record` is itself still canonical but has at least one
    /// tombstoned input handle in its lineage. The cascade pass tombstones
    /// every such record.
    fn depends_on_tombstoned_input(&self, record: &HandleRecord) -> bool {
        if record.is_tombstoned {
            return false;
        }
        let HandleLineage::Derived {
            ref input_handle_keys,
            ..
        } = record.lineage
        else {
            return false;
        };
        input_handle_keys.iter().any(|input_key| {
            self.records
                .get(input_key)
                .is_some_and(|input_record| input_record.is_tombstoned)
        })
    }
}
