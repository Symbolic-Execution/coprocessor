/// Domain value types, Handle State, Chain Event types, and failure/rejection
/// enums for the Handle Graph Core.

use thiserror::Error;

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
    MpcTransformationFailure {
        reason: String,
    },
    /// Terminal failure during Enclave Execution. `reason` is non-secret:
    /// it names the failure category and affected input index only.
    EnclaveExecutionFailure {
        reason: String,
    },
    /// Terminal failure during core materialization. Indicates an
    /// orchestration bug (the Handle was not Pending or not Derived).
    /// `reason` is non-secret.
    MaterializationFailure {
        reason: String,
    },
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
    /// Set to `true` by [`super::HandleGraphCore::apply_orphan_discard`] when
    /// the record (or one of its lineage ancestors) was discarded. Tombstoned
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

/// Result of [`super::HandleGraphCore::apply_orphan_discard`]. Reports the
/// Handle Keys tombstoned directly because their `event_ref` was supplied,
/// and the Handle Keys tombstoned through Handle Lineage cascade. A key
/// appears in at most one of the two lists.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OrphanDiscardOutcome {
    pub directly_tombstoned: Vec<HandleKey>,
    pub cascade_tombstoned: Vec<HandleKey>,
}

/// Typed rejection reasons for
/// [`super::HandleGraphCore::materialize_derived_handle`].
/// Every variant is safe to surface to the Coprocessor Host: none embed
/// ciphertext bytes, wrapped keys, or plaintext.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum MaterializeDerivedError {
    #[error("unknown handle")]
    UnknownHandle,
    #[error("tombstoned handle")]
    Tombstoned,
    #[error("handle is not derived")]
    NotDerived,
    #[error("handle is not pending")]
    NotPending,
}

/// Typed rejection reasons for [`super::HandleGraphCore::fail_derived_handle`].
/// Mirrors [`MaterializeDerivedError`]: only a Pending, canonical, Derived,
/// non-tombstoned handle may transition to Failed. Every variant is safe to
/// surface to the Coprocessor Host: none embed ciphertext, wrapped keys, or
/// plaintext.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum FailDerivedError {
    #[error("unknown handle")]
    UnknownHandle,
    #[error("tombstoned handle")]
    Tombstoned,
    #[error("handle is not derived")]
    NotDerived,
    #[error("handle is not pending")]
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

impl ChainEvent {
    pub(super) fn event_ref(&self) -> ChainEventRef {
        match self {
            ChainEvent::ImportedHandle(imported) => imported.event_ref,
            ChainEvent::PlaintextHandle(plaintext) => plaintext.event_ref,
            ChainEvent::DerivedHandleOperation(op) => op.event_ref,
        }
    }
}
