/// Handle Graph ingestion: apply_chain_event and related methods,
/// including persistence-write-through variants and restore-from-persistence.
use std::collections::{HashMap, HashSet};

use super::operations::{validate_arity, validate_operation_types};
use super::persistence::HandlePersistence;
use super::plaintext_materialization::PlaintextMaterializer;
use super::types::{
    ChainEvent, ChainEventRef, DerivedHandleOperation, FailureReason, HandleKey, HandleLineage,
    HandleRecord, HandleState, HandleType, ImportedHandle, IngestionOutcome, LineageViolation,
    MaterializationReceipt, PlaintextHandle,
};
use super::HandleGraphCore;

impl HandleGraphCore {
    pub fn apply_chain_event(&mut self, event: ChainEvent) -> IngestionOutcome {
        let event_ref = event.event_ref();
        if !self.consumed_events.insert(event_ref) {
            return IngestionOutcome::Idempotent;
        }

        match event {
            ChainEvent::ImportedHandle(imported) => self.apply_imported(imported),
            ChainEvent::PlaintextHandle(plaintext) => self.apply_plaintext(plaintext),
            ChainEvent::DerivedHandleOperation(op) => self.apply_derived(op),
        }
    }

    /// Applies a Chain Event and mirrors the resulting durable state into
    /// `persistence`. Returns the same [`IngestionOutcome`] as
    /// [`HandleGraphCore::apply_chain_event`].
    ///
    /// Persistence ordering: when a canonical record is created, the record is
    /// written first, then the Chain Event is marked consumed. A crash between
    /// the two leaves the next restart with the record present and the event
    /// not-yet-consumed; the next replay of the same event surfaces
    /// [`IngestionOutcome::DuplicateHandleKeyRejected`] for the second attempt,
    /// preserving the first canonical record. A canonical rejected duplicate
    /// is intentionally not persisted — only the consumed event ref is — so
    /// the store reflects exactly the records the Handle Graph retains.
    pub fn apply_chain_event_with_persistence<P: HandlePersistence>(
        &mut self,
        event: ChainEvent,
        persistence: &mut P,
    ) -> IngestionOutcome {
        let outcome = self.apply_chain_event(event);
        let consumed_event_ref = match &outcome {
            IngestionOutcome::Recorded(record) => {
                persistence.put_handle_record(record.clone());
                Some(record.event_ref)
            }
            IngestionOutcome::DuplicateHandleKeyRejected(rejected) => Some(rejected.event_ref),
            IngestionOutcome::Idempotent => None,
        };
        if let Some(event_ref) = consumed_event_ref {
            persistence.record_consumed_event(event_ref);
        }
        outcome
    }

    /// Rebuilds a [`HandleGraphCore`] from a previously written
    /// [`HandlePersistence`]. After restart this is the entry point that
    /// re-seeds the in-process record map and the consumed-event set, so
    /// ingestion replay remains idempotent by [`ChainEventRef`] and canonical
    /// reads return the same Handle Records observed before the restart.
    ///
    /// The restored graph uses [`PlaintextMaterializer::default`]; callers
    /// that subsequently ingest Plaintext Handle events should construct the
    /// graph with
    /// [`HandleGraphCore::restore_from_persistence_with_materializer`]
    /// so the materializer carries the host's active MPC key id.
    pub fn restore_from_persistence<P: HandlePersistence>(persistence: &P) -> Self {
        Self::restore_from_persistence_with_materializer(
            persistence,
            PlaintextMaterializer::default(),
        )
    }

    /// Same as [`HandleGraphCore::restore_from_persistence`], but binds the
    /// supplied `plaintext_materializer` so post-restart Plaintext Handle
    /// ingestion keeps producing real `SystemCiphertextV1` envelopes bound to
    /// the host's active MPC key id.
    pub fn restore_from_persistence_with_materializer<P: HandlePersistence>(
        persistence: &P,
        plaintext_materializer: PlaintextMaterializer,
    ) -> Self {
        let records: HashMap<HandleKey, HandleRecord> = persistence
            .handle_records()
            .into_iter()
            .map(|record| (record.handle_key, record))
            .collect();
        let consumed_events: HashSet<ChainEventRef> =
            persistence.consumed_events().into_iter().collect();
        Self {
            records,
            consumed_events,
            plaintext_materializer,
        }
    }

    pub(super) fn apply_imported(&mut self, imported: ImportedHandle) -> IngestionOutcome {
        if let Some(outcome) = self.duplicate_rejection(
            imported.domain_id,
            imported.handle_key,
            imported.handle_type,
            imported.event_ref,
            HandleLineage::Source,
        ) {
            return outcome;
        }

        let record = HandleRecord {
            domain_id: imported.domain_id,
            handle_key: imported.handle_key,
            handle_type: imported.handle_type,
            state: HandleState::Ready {
                system_ciphertext: imported.system_ciphertext,
                // Imported handles carry no materialization receipt in the
                // spec ABI; the submitted SystemCiphertextV1 is the ready
                // source value. The receipt is empty per the spec.
                materialization_receipt: MaterializationReceipt(Vec::new()),
            },
            event_ref: imported.event_ref,
            is_canonical: true,
            lineage: HandleLineage::Source,
            is_tombstoned: false,
        };
        self.records.insert(imported.handle_key, record.clone());
        IngestionOutcome::Recorded(record)
    }

    pub(super) fn apply_plaintext(&mut self, plaintext: PlaintextHandle) -> IngestionOutcome {
        use super::plaintext_materialization::MaterializedPlaintextHandle;

        if let Some(outcome) = self.duplicate_rejection(
            plaintext.domain_id,
            plaintext.handle_key,
            plaintext.handle_type,
            plaintext.event_ref,
            HandleLineage::Source,
        ) {
            return outcome;
        }

        let MaterializedPlaintextHandle {
            system_ciphertext,
            materialization_receipt,
        } = self.plaintext_materializer.materialize(&plaintext);
        let record = HandleRecord {
            domain_id: plaintext.domain_id,
            handle_key: plaintext.handle_key,
            handle_type: plaintext.handle_type,
            state: HandleState::Ready {
                system_ciphertext,
                materialization_receipt,
            },
            event_ref: plaintext.event_ref,
            is_canonical: true,
            lineage: HandleLineage::Source,
            is_tombstoned: false,
        };
        self.records.insert(plaintext.handle_key, record.clone());
        IngestionOutcome::Recorded(record)
    }

    pub(super) fn apply_derived(&mut self, op: DerivedHandleOperation) -> IngestionOutcome {
        let lineage = HandleLineage::Derived {
            operation_code: op.operation_code,
            input_handle_keys: op.input_handle_keys.clone(),
        };

        // A duplicate handle key never overwrites the canonical record; the
        // rejected record is returned to the caller but not stored.
        if let Some(outcome) = self.duplicate_rejection(
            op.domain_id,
            op.handle_key,
            op.output_handle_type,
            op.event_ref,
            lineage.clone(),
        ) {
            return outcome;
        }

        // A failed derivation is still recorded under its handle key, so a
        // valid derivation lands as Pending and any violation lands as Failed.
        let state = match self.validate_derived(&op) {
            Ok(()) => HandleState::Pending,
            Err(reason) => HandleState::Failed { reason },
        };
        let record = HandleRecord {
            domain_id: op.domain_id,
            handle_key: op.handle_key,
            handle_type: op.output_handle_type,
            state,
            event_ref: op.event_ref,
            is_canonical: true,
            lineage,
            is_tombstoned: false,
        };
        self.records.insert(op.handle_key, record.clone());
        IngestionOutcome::Recorded(record)
    }

    pub(super) fn duplicate_rejection(
        &self,
        domain_id: super::types::DomainId,
        handle_key: HandleKey,
        handle_type: HandleType,
        event_ref: ChainEventRef,
        lineage: HandleLineage,
    ) -> Option<IngestionOutcome> {
        self.records.get(&handle_key).map(|existing| {
            IngestionOutcome::DuplicateHandleKeyRejected(HandleRecord {
                domain_id,
                handle_key,
                handle_type,
                state: HandleState::Failed {
                    reason: FailureReason::LineageViolation(LineageViolation::DuplicateHandleKey {
                        existing_event_ref: existing.event_ref,
                    }),
                },
                event_ref,
                is_canonical: true,
                lineage,
                is_tombstoned: false,
            })
        })
    }

    /// Validates a derived operation against its inputs, in order: arity, then
    /// that every input is a known handle in the same domain, then the
    /// per-operation input and output type rules.
    pub(super) fn validate_derived(
        &self,
        op: &DerivedHandleOperation,
    ) -> Result<(), FailureReason> {
        validate_arity(op.operation_code, op.input_handle_keys.len())
            .map_err(FailureReason::OperationViolation)?;

        let input_types = op
            .input_handle_keys
            .iter()
            .map(|input_key| {
                self.records
                    .get(input_key)
                    .filter(|record| record.domain_id == op.domain_id)
                    .map(|record| record.handle_type)
                    .ok_or(LineageViolation::UnknownInputHandle {
                        input_handle_key: *input_key,
                    })
            })
            .collect::<Result<Vec<HandleType>, _>>()
            .map_err(FailureReason::LineageViolation)?;

        validate_operation_types(op.operation_code, &input_types, op.output_handle_type)
            .map_err(FailureReason::OperationViolation)?;

        Ok(())
    }
}
