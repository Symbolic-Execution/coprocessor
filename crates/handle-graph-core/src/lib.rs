use std::collections::{HashMap, HashSet};

pub mod persistence;

pub use persistence::{HandlePersistence, InMemoryHandlePersistence};

mod chain_log_decoder;
mod plaintext_materialization;

pub use chain_log_decoder::{
    decode_chain_log, ChainLog, ChainLogDecodeError, HANDLE_FROM_PLAINTEXT_V1_SIGNATURE,
    HANDLE_IMPORTED_V1_SIGNATURE, OPERATION_REQUESTED_V1_SIGNATURE,
};
pub use plaintext_materialization::{
    type_tag_for_handle_type, MaterializedPlaintextHandle, PlaintextMaterializer, SBOOL_TYPE_TAG,
    SUINT256_TYPE_TAG,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChainId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContractAddress(pub [u8; 20]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DomainId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HandleId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HandleKey {
    pub chain_id: ChainId,
    pub contract_address: ContractAddress,
    pub handle_id: HandleId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleType {
    Suint256,
    Sbool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationCode {
    Add,
    Sub,
    Eq,
    Lt,
    Lte,
    Gt,
    Gte,
    And,
    Or,
    Not,
    Select,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemCiphertextV1(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationReceipt(pub Vec<u8>);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChainEventRef {
    pub chain_id: ChainId,
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub tx_hash: [u8; 32],
    pub log_index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandleState {
    Pending,
    Ready {
        system_ciphertext: SystemCiphertextV1,
        materialization_receipt: MaterializationReceipt,
    },
    Failed {
        reason: FailureReason,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureReason {
    LineageViolation(LineageViolation),
    OperationViolation(OperationViolation),
    /// Terminal failure during MPC To-Enclave Transformation. `reason` is
    /// non-secret: it names the failure category and input position only,
    /// never ciphertext bytes, wrapped keys, or plaintext.
    MpcTransformationFailure { reason: String },
    /// Terminal failure during Enclave Execution. `reason` is non-secret:
    /// it names the failure category and affected input index only.
    EnclaveExecutionFailure { reason: String },
    /// Terminal failure during core materialization. Indicates an
    /// orchestration bug (the Handle was not Pending or not Derived).
    /// `reason` is non-secret.
    MaterializationFailure { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineageViolation {
    DuplicateHandleKey { existing_event_ref: ChainEventRef },
    UnknownInputHandle { input_handle_key: HandleKey },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationViolation {
    WrongArity {
        operation_code: OperationCode,
        expected: usize,
        actual: usize,
    },
    WrongInputHandleType {
        input_index: usize,
        expected: HandleType,
        actual: HandleType,
    },
    WrongOutputHandleType {
        expected: HandleType,
        actual: HandleType,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandleLineage {
    Source,
    Derived {
        operation_code: OperationCode,
        input_handle_keys: Vec<HandleKey>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandleRecord {
    pub domain_id: DomainId,
    pub handle_key: HandleKey,
    pub handle_type: HandleType,
    pub state: HandleState,
    pub event_ref: ChainEventRef,
    pub is_canonical: bool,
    pub lineage: HandleLineage,
    /// Set to `true` by [`HandleGraphCore::apply_orphan_discard`] when the
    /// record (or one of its lineage ancestors) was discarded. Tombstoned
    /// records are retained for audit and continue to expose their original
    /// `event_ref` and `state`, but are hidden from canonical queries and
    /// Resolution Readiness. Tombstoning is not a `Failed` Handle State.
    pub is_tombstoned: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChainEvent {
    ImportedHandle(ImportedHandle),
    PlaintextHandle(PlaintextHandle),
    DerivedHandleOperation(DerivedHandleOperation),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedHandle {
    pub domain_id: DomainId,
    pub handle_key: HandleKey,
    pub handle_type: HandleType,
    pub system_ciphertext: SystemCiphertextV1,
    pub materialization_receipt: MaterializationReceipt,
    pub event_ref: ChainEventRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicPlaintextValue(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaintextHandle {
    pub domain_id: DomainId,
    pub handle_key: HandleKey,
    pub handle_type: HandleType,
    pub public_value: PublicPlaintextValue,
    pub event_ref: ChainEventRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedHandleOperation {
    pub domain_id: DomainId,
    pub handle_key: HandleKey,
    pub operation_code: OperationCode,
    pub output_handle_type: HandleType,
    pub input_handle_keys: Vec<HandleKey>,
    pub event_ref: ChainEventRef,
}

#[must_use = "an IngestionOutcome may surface a rejected Failed record that callers must observe"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IngestionOutcome {
    Recorded(HandleRecord),
    Idempotent,
    DuplicateHandleKeyRejected(HandleRecord),
}

/// Result of [`HandleGraphCore::apply_orphan_discard`]. Reports the Handle
/// Keys tombstoned directly because their `event_ref` was supplied, and the
/// Handle Keys tombstoned through Handle Lineage cascade. A key appears in
/// at most one of the two lists.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OrphanDiscardOutcome {
    pub directly_tombstoned: Vec<HandleKey>,
    pub cascade_tombstoned: Vec<HandleKey>,
}

/// Typed rejection reasons for [`HandleGraphCore::materialize_derived_handle`].
/// Every variant is safe to surface to the Coprocessor Host: none embed
/// ciphertext bytes, wrapped keys, or plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterializeDerivedError {
    /// No Handle Record exists for the given Handle Key.
    UnknownHandle,
    /// The Handle Record exists but has been tombstoned by Orphan Discard.
    Tombstoned,
    /// The Handle Record's lineage is Source, not Derived. Only Derived
    /// Handles can be materialized through Enclave Execution.
    NotDerived,
    /// The Handle Record is not in the Pending state (already Ready or Failed).
    NotPending,
}

/// Typed rejection reasons for [`HandleGraphCore::fail_derived_handle`].
/// Mirrors [`MaterializeDerivedError`]: only a Pending, canonical, Derived,
/// non-tombstoned handle may transition to Failed. Every variant is safe to
/// surface to the Coprocessor Host: none embed ciphertext, wrapped keys, or
/// plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailDerivedError {
    /// No Handle Record exists for the given Handle Key.
    UnknownHandle,
    /// The Handle Record exists but has been tombstoned by Orphan Discard.
    Tombstoned,
    /// The Handle Record's lineage is Source, not Derived.
    NotDerived,
    /// The Handle Record is not in the Pending state (already Ready or Failed).
    NotPending,
}

/// Snapshot of a Pending Derived Handle whose ordered input Handles are all
/// canonical and Ready. Carries everything a future Resolution Scheduler needs
/// to build a Resolution Task without re-walking the graph: the target Handle
/// Key, its OperationCode and output HandleType, and the ordered input Handle
/// Keys paired by index with the ready input `SystemCiphertextV1` values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionReadiness {
    pub handle_key: HandleKey,
    pub operation_code: OperationCode,
    pub output_handle_type: HandleType,
    pub input_handle_keys: Vec<HandleKey>,
    pub input_system_ciphertexts: Vec<SystemCiphertextV1>,
}

#[derive(Default)]
pub struct HandleGraphCore {
    records: HashMap<HandleKey, HandleRecord>,
    consumed_events: HashSet<ChainEventRef>,
    plaintext_materializer: PlaintextMaterializer,
}

impl HandleGraphCore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a [`HandleGraphCore`] that materializes Plaintext Handles
    /// through `plaintext_materializer`. The host populates the materializer
    /// from the MPC public configuration's active `key_id` before any
    /// Plaintext Handle ingestion happens, so every Ready Plaintext Handle
    /// carries an AAD bound to the currently-active MPC key.
    pub fn with_plaintext_materializer(plaintext_materializer: PlaintextMaterializer) -> Self {
        Self {
            records: HashMap::new(),
            consumed_events: HashSet::new(),
            plaintext_materializer,
        }
    }

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
    /// graph with [`HandleGraphCore::restore_from_persistence_with_materializer`]
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
        let consumed_events = persistence.consumed_events().into_iter().collect();
        Self {
            records,
            consumed_events,
            plaintext_materializer,
        }
    }

    /// Returns the canonical Handle Record for `handle_key`. Tombstoned
    /// records (see [`HandleGraphCore::apply_orphan_discard`]) and
    /// non-canonical records are hidden from this query and appear unknown to
    /// normal API behavior.
    pub fn canonical_handle(&self, handle_key: &HandleKey) -> Option<&HandleRecord> {
        self.records
            .get(handle_key)
            .filter(|record| record.is_canonical && !record.is_tombstoned)
    }

    /// Returns any retained Handle Record, including tombstoned records. This
    /// is the audit/debug path: it lets operators inspect the preserved
    /// `event_ref`, `state`, and lineage of records hidden from canonical
    /// reads. It is not part of the Internal Coordinator API surface.
    pub fn handle_record_for_audit(&self, handle_key: &HandleKey) -> Option<&HandleRecord> {
        self.records.get(handle_key)
    }

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

    /// Reports every canonical Pending Derived Handle whose ordered inputs are
    /// all canonical and Ready. Results carry the input `SystemCiphertextV1`
    /// values in the same order as the input Handle Keys; Select inputs stay
    /// in predicate, when-true, when-false order. Failed Derived Handles and
    /// Derived Handles with any non-Ready or non-canonical input are excluded.
    /// This slice only reports readiness — it does not build Resolution Tasks
    /// and does not perform Resolution.
    pub fn resolution_readiness(&self) -> Vec<ResolutionReadiness> {
        self.records
            .values()
            .filter_map(|record| self.readiness_for(record))
            .collect()
    }

    /// Transition a Pending Derived Handle Record to Ready by binding the
    /// supplied `system_ciphertext` and `materialization_receipt`. This is the
    /// only path from Pending to Ready for Derived Handles; the invariant is
    /// enforced here and nowhere else.
    ///
    /// Returns the updated [`HandleRecord`] on success. Returns a typed
    /// [`MaterializeDerivedError`] when the handle key has no canonical record,
    /// is tombstoned, is not Derived-lineage, or is not in the Pending state.
    /// On error the record is left unchanged.
    pub fn materialize_derived_handle(
        &mut self,
        handle_key: &HandleKey,
        system_ciphertext: SystemCiphertextV1,
        materialization_receipt: MaterializationReceipt,
    ) -> Result<HandleRecord, MaterializeDerivedError> {
        let record = self
            .records
            .get_mut(handle_key)
            .ok_or(MaterializeDerivedError::UnknownHandle)?;

        if record.is_tombstoned {
            return Err(MaterializeDerivedError::Tombstoned);
        }

        if !record.is_canonical {
            return Err(MaterializeDerivedError::UnknownHandle);
        }

        if !matches!(record.lineage, HandleLineage::Derived { .. }) {
            return Err(MaterializeDerivedError::NotDerived);
        }

        if record.state != HandleState::Pending {
            return Err(MaterializeDerivedError::NotPending);
        }

        record.state = HandleState::Ready {
            system_ciphertext,
            materialization_receipt,
        };

        Ok(record.clone())
    }

    /// Same as [`HandleGraphCore::materialize_derived_handle`] but mirrors the
    /// updated Ready record into `persistence` on success. Follows the same
    /// write-through pattern as [`HandleGraphCore::apply_chain_event_with_persistence`].
    pub fn materialize_derived_handle_with_persistence<P: HandlePersistence>(
        &mut self,
        handle_key: &HandleKey,
        system_ciphertext: SystemCiphertextV1,
        materialization_receipt: MaterializationReceipt,
        persistence: &mut P,
    ) -> Result<HandleRecord, MaterializeDerivedError> {
        let record = self.materialize_derived_handle(
            handle_key,
            system_ciphertext,
            materialization_receipt,
        )?;
        persistence.put_handle_record(record.clone());
        Ok(record)
    }

    /// Transition a Pending Derived Handle Record to Failed by binding the
    /// supplied `reason`. This is the only path from Pending to Failed for
    /// terminal resolution errors; the invariant is enforced here.
    ///
    /// Returns the updated [`HandleRecord`] on success. Returns a typed
    /// [`FailDerivedError`] when the handle key has no canonical record, is
    /// tombstoned, is not Derived-lineage, or is not in the Pending state.
    /// On error the record is left unchanged.
    ///
    /// The `reason` must be non-secret: callers must sanitize backend error
    /// detail before constructing it (no ciphertext bytes, wrapped keys,
    /// reader secrets, enclave private keys, or decrypted payloads).
    pub fn fail_derived_handle(
        &mut self,
        handle_key: &HandleKey,
        reason: FailureReason,
    ) -> Result<HandleRecord, FailDerivedError> {
        let record = self
            .records
            .get_mut(handle_key)
            .ok_or(FailDerivedError::UnknownHandle)?;

        if record.is_tombstoned {
            return Err(FailDerivedError::Tombstoned);
        }

        if !record.is_canonical {
            return Err(FailDerivedError::UnknownHandle);
        }

        if !matches!(record.lineage, HandleLineage::Derived { .. }) {
            return Err(FailDerivedError::NotDerived);
        }

        if record.state != HandleState::Pending {
            return Err(FailDerivedError::NotPending);
        }

        record.state = HandleState::Failed { reason };

        Ok(record.clone())
    }

    /// Same as [`HandleGraphCore::fail_derived_handle`] but mirrors the
    /// updated Failed record into `persistence` on success. Follows the same
    /// write-through pattern as [`HandleGraphCore::apply_chain_event_with_persistence`].
    pub fn fail_derived_handle_with_persistence<P: HandlePersistence>(
        &mut self,
        handle_key: &HandleKey,
        reason: FailureReason,
        persistence: &mut P,
    ) -> Result<HandleRecord, FailDerivedError> {
        let record = self.fail_derived_handle(handle_key, reason)?;
        persistence.put_handle_record(record.clone());
        Ok(record)
    }

    fn readiness_for(&self, record: &HandleRecord) -> Option<ResolutionReadiness> {
        if record.is_tombstoned || !record.is_canonical || record.state != HandleState::Pending {
            return None;
        }
        let HandleLineage::Derived {
            operation_code,
            ref input_handle_keys,
        } = record.lineage
        else {
            return None;
        };
        let mut input_system_ciphertexts = Vec::with_capacity(input_handle_keys.len());
        for input_key in input_handle_keys {
            let input_record = self.records.get(input_key)?;
            if input_record.is_tombstoned || !input_record.is_canonical {
                return None;
            }
            let HandleState::Ready {
                ref system_ciphertext,
                ..
            } = input_record.state
            else {
                return None;
            };
            input_system_ciphertexts.push(system_ciphertext.clone());
        }
        Some(ResolutionReadiness {
            handle_key: record.handle_key,
            operation_code,
            output_handle_type: record.handle_type,
            input_handle_keys: input_handle_keys.clone(),
            input_system_ciphertexts,
        })
    }

    fn apply_imported(&mut self, imported: ImportedHandle) -> IngestionOutcome {
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
                materialization_receipt: imported.materialization_receipt,
            },
            event_ref: imported.event_ref,
            is_canonical: true,
            lineage: HandleLineage::Source,
            is_tombstoned: false,
        };
        self.records.insert(imported.handle_key, record.clone());
        IngestionOutcome::Recorded(record)
    }

    fn apply_plaintext(&mut self, plaintext: PlaintextHandle) -> IngestionOutcome {
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

    fn apply_derived(&mut self, op: DerivedHandleOperation) -> IngestionOutcome {
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

        // A failed derivation is still recorded under its handle key, so a valid
        // derivation lands as Pending and any violation lands as Failed.
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

    fn duplicate_rejection(
        &self,
        domain_id: DomainId,
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
    fn validate_derived(&self, op: &DerivedHandleOperation) -> Result<(), FailureReason> {
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

impl ChainEvent {
    fn event_ref(&self) -> ChainEventRef {
        match self {
            ChainEvent::ImportedHandle(imported) => imported.event_ref,
            ChainEvent::PlaintextHandle(plaintext) => plaintext.event_ref,
            ChainEvent::DerivedHandleOperation(op) => op.event_ref,
        }
    }
}

fn expected_arity(op: OperationCode) -> usize {
    match op {
        OperationCode::Add
        | OperationCode::Sub
        | OperationCode::Eq
        | OperationCode::Lt
        | OperationCode::Lte
        | OperationCode::Gt
        | OperationCode::Gte
        | OperationCode::And
        | OperationCode::Or => 2,
        OperationCode::Not => 1,
        OperationCode::Select => 3,
    }
}

fn validate_arity(op: OperationCode, actual: usize) -> Result<(), OperationViolation> {
    let expected = expected_arity(op);
    if actual == expected {
        Ok(())
    } else {
        Err(OperationViolation::WrongArity {
            operation_code: op,
            expected,
            actual,
        })
    }
}

/// Checks input and output types for `op`. Callers must validate arity first:
/// the `Select` arm indexes `inputs[0..=2]` directly, relying on that guarantee.
fn validate_operation_types(
    op: OperationCode,
    inputs: &[HandleType],
    output_type: HandleType,
) -> Result<(), OperationViolation> {
    match op {
        OperationCode::Add | OperationCode::Sub => {
            require_each_input(inputs, HandleType::Suint256)?;
            require_output(output_type, HandleType::Suint256)
        }
        OperationCode::Eq
        | OperationCode::Lt
        | OperationCode::Lte
        | OperationCode::Gt
        | OperationCode::Gte => {
            require_each_input(inputs, HandleType::Suint256)?;
            require_output(output_type, HandleType::Sbool)
        }
        OperationCode::And | OperationCode::Or => {
            require_each_input(inputs, HandleType::Sbool)?;
            require_output(output_type, HandleType::Sbool)
        }
        OperationCode::Not => {
            require_each_input(inputs, HandleType::Sbool)?;
            require_output(output_type, HandleType::Sbool)
        }
        OperationCode::Select => {
            // inputs are (predicate, when_true, when_false): the predicate is
            // sbool, both branches must share a type, and the output matches it.
            require_input_at(inputs, 0, HandleType::Sbool)?;
            require_input_at(inputs, 2, inputs[1])?;
            require_output(output_type, inputs[1])
        }
    }
}

fn require_each_input(
    inputs: &[HandleType],
    expected: HandleType,
) -> Result<(), OperationViolation> {
    for (index, actual) in inputs.iter().enumerate() {
        if *actual != expected {
            return Err(OperationViolation::WrongInputHandleType {
                input_index: index,
                expected,
                actual: *actual,
            });
        }
    }
    Ok(())
}

fn require_input_at(
    inputs: &[HandleType],
    index: usize,
    expected: HandleType,
) -> Result<(), OperationViolation> {
    if inputs[index] != expected {
        return Err(OperationViolation::WrongInputHandleType {
            input_index: index,
            expected,
            actual: inputs[index],
        });
    }
    Ok(())
}

fn require_output(actual: HandleType, expected: HandleType) -> Result<(), OperationViolation> {
    if actual == expected {
        Ok(())
    } else {
        Err(OperationViolation::WrongOutputHandleType { expected, actual })
    }
}
