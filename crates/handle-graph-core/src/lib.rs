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

mod types;
pub use types::{
    ChainEvent, ChainEventRef, ChainId, ContractAddress, DerivedHandleOperation, DomainId,
    FailDerivedError, FailureReason, HandleId, HandleKey, HandleLineage, HandleRecord, HandleState,
    HandleType, ImportedHandle, IngestionOutcome, LineageViolation, MaterializationReceipt,
    MaterializeDerivedError, OperationCode, OperationViolation, OrphanDiscardOutcome,
    PlaintextHandle, PublicPlaintextValue, ResolutionReadiness, SystemCiphertextV1,
};

mod operations;
mod ingestion;
mod query;
mod orphan;
mod materialization;

#[derive(Default)]
pub struct HandleGraphCore {
    records: HashMap<HandleKey, HandleRecord>,
    consumed_events: HashSet<ChainEventRef>,
    plaintext_materializer: PlaintextMaterializer,
}
