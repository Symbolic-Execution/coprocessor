/// MPC configuration compatibility check results.
use thiserror::Error;

use super::config::{ChainId, CiphertextSuite, DomainId, ReaderKeyAlgorithm};

/// One configuration dimension the loaded MPC public configuration did not
/// match. Distinct from parse errors and backend availability errors so the
/// host can refuse to schedule work and surface the mismatch without
/// retrying.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MpcConfigIncompatibility {
    #[error("chain_id mismatch: expected {expected:?}, actual {actual:?}")]
    ChainIdMismatch { expected: ChainId, actual: ChainId },
    /// DomainId carries [u8; 32] — display only a category label, no bytes.
    #[error("domain_id mismatch")]
    DomainIdMismatch {
        expected: DomainId,
        actual: DomainId,
    },
    #[error("reader_key_algorithm mismatch: expected {expected:?}, actual {actual:?}")]
    ReaderKeyAlgorithmMismatch {
        expected: ReaderKeyAlgorithm,
        actual: ReaderKeyAlgorithm,
    },
    #[error("ciphertext_suite mismatch: expected {expected:?}, actual {actual:?}")]
    CiphertextSuiteMismatch {
        expected: CiphertextSuite,
        actual: CiphertextSuite,
    },
}
