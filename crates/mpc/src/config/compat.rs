/// MPC configuration compatibility check results.
use thiserror::Error;

use super::config::{ChainId, DomainId, MpcSuite};

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
    #[error("suite mismatch: expected {expected:?}, actual {actual:?}")]
    SuiteMismatch {
        expected: MpcSuite,
        actual: MpcSuite,
    },
    #[error("public key shape mismatch for suite {suite:?}: expected {expected_bytes} bytes, actual {actual_bytes} bytes")]
    PublicKeyShape {
        suite: MpcSuite,
        expected_bytes: usize,
        actual_bytes: usize,
    },
}
