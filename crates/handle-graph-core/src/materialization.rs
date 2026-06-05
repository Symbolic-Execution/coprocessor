/// Materialization and failure transitions for Derived Handle Records.
use super::persistence::HandlePersistence;
use super::types::{
    FailDerivedError, FailureReason, HandleKey, HandleLineage, HandleRecord, HandleState,
    MaterializationReceipt, MaterializeDerivedError, SystemCiphertextV1,
};
use super::HandleGraphCore;

impl HandleGraphCore {
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
    /// write-through pattern as
    /// [`HandleGraphCore::apply_chain_event_with_persistence`].
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
    /// write-through pattern as
    /// [`HandleGraphCore::apply_chain_event_with_persistence`].
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
}
