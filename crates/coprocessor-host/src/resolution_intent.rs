//! Handle Resolution Request dedup: per-Handle-Key resolution intents.
//!
//! A Handle Resolution Request carries a [`RequestId`] that identifies the
//! request flow only — never the Handle Graph lookup key. Multiple requests
//! that name the same Pending Derived Handle collapse onto a single
//! [`ResolutionIntent`] keyed by Handle Key, so the future Resolution Scheduler
//! observes one piece of work per Handle regardless of how many callers asked.
//!
//! The intent registry is intentionally orthogonal to the Handle Graph: it
//! records request-flow attachments only, never Handle State. Source Handles
//! are already Ready at ingestion time and Failed Derived Handles never become
//! schedulable, so this slice only registers intents for `HandleStateView::
//! Pending` projections.

use std::collections::{BTreeSet, HashMap};

use coprocessor_handle_graph_core::HandleKey;

/// Identifier of a particular request flow (Handle Resolution Request,
/// To-Enclave Transformation, ...). It does not identify a Handle: every
/// canonical Handle lookup goes through [`HandleKey`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId(pub [u8; 32]);

/// Coordinator-facing snapshot of the resolution intent that has accumulated
/// for a single Pending Derived Handle. `attached_request_ids` is sorted and
/// deduplicated: a repeated `RequestId` for the same Handle Key appears once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionIntent {
    pub handle_key: HandleKey,
    pub attached_request_ids: Vec<RequestId>,
}

/// Per-Handle-Key resolution intent registry.
///
/// The internal map is keyed by Handle Key only — the `RequestId` is request
/// flow metadata, never a lookup key. A repeated `attach` for the same
/// `(handle_key, request_id)` is idempotent; distinct `RequestId`s for the
/// same Handle Key collapse into the same intent.
#[derive(Default)]
pub(crate) struct ResolutionIntents {
    by_handle_key: HashMap<HandleKey, BTreeSet<RequestId>>,
}

impl ResolutionIntents {
    pub(crate) fn attach(&mut self, handle_key: HandleKey, request_id: RequestId) {
        self.by_handle_key
            .entry(handle_key)
            .or_default()
            .insert(request_id);
    }

    pub(crate) fn intent(&self, handle_key: &HandleKey) -> Option<ResolutionIntent> {
        self.by_handle_key
            .get(handle_key)
            .map(|attached| ResolutionIntent {
                handle_key: *handle_key,
                attached_request_ids: attached.iter().copied().collect(),
            })
    }

    pub(crate) fn intent_count(&self) -> usize {
        self.by_handle_key.len()
    }
}
