/// Canonical and audit queries, resolution readiness, and constructors
/// for HandleGraphCore.
use super::plaintext_materialization::PlaintextMaterializer;
use super::types::{HandleKey, HandleLineage, HandleRecord, HandleState, ResolutionReadiness};
use super::HandleGraphCore;

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
            records: std::collections::HashMap::new(),
            consumed_events: std::collections::HashSet::new(),
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

    pub(super) fn readiness_for(&self, record: &HandleRecord) -> Option<ResolutionReadiness> {
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
}
