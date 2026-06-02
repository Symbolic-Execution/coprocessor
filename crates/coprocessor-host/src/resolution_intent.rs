//! Per-Handle-Key Handle Resolution Request intents.
//!
//! A Handle Resolution Request carries a [`RequestId`] that identifies the
//! request flow, not the Handle Graph lookup key. Requests for the same Pending
//! Derived Handle share one [`ResolutionIntent`], so the future Resolution
//! Scheduler observes one piece of work per Handle.

use std::collections::{BTreeSet, HashMap};

use coprocessor_handle_graph_core::HandleKey;

/// Identifier of a request flow. It never identifies a Handle; canonical Handle
/// lookup always goes through [`HandleKey`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId(pub [u8; 32]);

/// Snapshot of the resolution intent accumulated for one Pending Derived
/// Handle. `attached_request_ids` is sorted and deduplicated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionIntent {
    pub handle_key: HandleKey,
    pub attached_request_ids: Vec<RequestId>,
}

/// Per-Handle-Key resolution intent registry.
///
/// Keyed by Handle Key only. Repeated attachments for the same
/// `(handle_key, request_id)` are idempotent; distinct `RequestId`s for the
/// same Handle Key remain attached to one intent.
#[derive(Default)]
pub(crate) struct ResolutionIntents {
    request_ids_by_handle_key: HashMap<HandleKey, BTreeSet<RequestId>>,
}

impl ResolutionIntents {
    pub(crate) fn attach(&mut self, handle_key: HandleKey, request_id: RequestId) {
        self.request_ids_by_handle_key
            .entry(handle_key)
            .or_default()
            .insert(request_id);
    }

    pub(crate) fn intent(&self, handle_key: &HandleKey) -> Option<ResolutionIntent> {
        self.request_ids_by_handle_key
            .get(handle_key)
            .map(|request_ids| ResolutionIntent {
                handle_key: *handle_key,
                attached_request_ids: request_ids.iter().copied().collect(),
            })
    }

    pub(crate) fn len(&self) -> usize {
        self.request_ids_by_handle_key.len()
    }
}
