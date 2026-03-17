//! Session-wide mutable state.

use codex_protocol::models::PermissionProfile;
use codex_protocol::models::ResponseItem;
use std::collections::HashMap;
use std::collections::HashSet;
use tokio::task::JoinHandle;

use crate::codex::DeferredCollabEnqueueError;
use crate::codex::PreviousTurnSettings;
use crate::codex::SessionConfiguration;
use crate::context_manager::ContextManager;
use crate::error::Result as CodexResult;
use crate::protocol::RateLimitSnapshot;
use crate::protocol::TokenUsage;
use crate::protocol::TokenUsageInfo;
use crate::sandboxing::merge_permission_profiles;
use crate::tasks::RegularTask;
use crate::truncate::TruncationPolicy;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::protocol::TurnContextItem;
use tracing::warn;

const DEFERRED_COLLAB_ITEMS_MAX: usize = 8192;
const DEFERRED_COLLAB_BYTES_MAX: usize = 64 * 1024 * 1024;

/// Persistent, session-scoped state previously stored directly on `Session`.
pub(crate) struct SessionState {
    pub(crate) session_configuration: SessionConfiguration,
    pub(crate) history: ContextManager,
    pub(crate) latest_rate_limits: Option<RateLimitSnapshot>,
    pub(crate) server_reasoning_included: bool,
    pub(crate) dependency_env: HashMap<String, String>,
    pub(crate) mcp_dependency_prompted: HashSet<String>,
    /// Settings used by the latest regular user turn, used for turn-to-turn
    /// model/realtime handling on subsequent regular turns (including full-context
    /// reinjection after resume or `/compact`).
    previous_turn_settings: Option<PreviousTurnSettings>,
    /// Latest completed proposed plan text emitted as `TurnItem::Plan`.
    latest_proposed_plan_text: Option<String>,
    /// Startup regular task pre-created during session initialization.
    pub(crate) startup_regular_task: Option<JoinHandle<CodexResult<RegularTask>>>,
    pub(crate) active_connector_selection: HashSet<String>,
    pub(crate) pending_session_start_source: Option<codex_hooks::SessionStartSource>,
    granted_permissions: Option<PermissionProfile>,
    post_interrupt_collab_hold_armed: bool,
    deferred_collab_items: Vec<ResponseInputItem>,
    deferred_collab_items_bytes: usize,
    post_turn_agent_items: Vec<ResponseInputItem>,
    post_turn_agent_items_bytes: usize,
    post_turn_agent_flush_pending: bool,
}

impl SessionState {
    /// Create a new session state mirroring previous `State::default()` semantics.
    pub(crate) fn new(session_configuration: SessionConfiguration) -> Self {
        let history = ContextManager::new();
        Self {
            session_configuration,
            history,
            latest_rate_limits: None,
            server_reasoning_included: false,
            dependency_env: HashMap::new(),
            mcp_dependency_prompted: HashSet::new(),
            previous_turn_settings: None,
            latest_proposed_plan_text: None,
            startup_regular_task: None,
            active_connector_selection: HashSet::new(),
            pending_session_start_source: None,
            granted_permissions: None,
            post_interrupt_collab_hold_armed: false,
            deferred_collab_items: Vec::new(),
            deferred_collab_items_bytes: 0,
            post_turn_agent_items: Vec::new(),
            post_turn_agent_items_bytes: 0,
            post_turn_agent_flush_pending: false,
        }
    }

    // History helpers
    pub(crate) fn record_items<I>(&mut self, items: I, policy: TruncationPolicy)
    where
        I: IntoIterator,
        I::Item: std::ops::Deref<Target = ResponseItem>,
    {
        self.history.record_items(items, policy);
    }

    pub(crate) fn previous_turn_settings(&self) -> Option<PreviousTurnSettings> {
        self.previous_turn_settings.clone()
    }
    pub(crate) fn set_previous_turn_settings(
        &mut self,
        previous_turn_settings: Option<PreviousTurnSettings>,
    ) {
        self.previous_turn_settings = previous_turn_settings;
    }

    pub(crate) fn latest_proposed_plan_text(&self) -> Option<String> {
        self.latest_proposed_plan_text.clone()
    }

    pub(crate) fn set_latest_proposed_plan_text(&mut self, plan_text: Option<String>) {
        self.latest_proposed_plan_text = plan_text;
    }

    pub(crate) fn clone_history(&self) -> ContextManager {
        self.history.clone()
    }

    pub(crate) fn replace_history(
        &mut self,
        items: Vec<ResponseItem>,
        reference_context_item: Option<TurnContextItem>,
    ) {
        self.history.replace(items);
        self.history
            .set_reference_context_item(reference_context_item);
    }

    pub(crate) fn set_token_info(&mut self, info: Option<TokenUsageInfo>) {
        self.history.set_token_info(info);
    }

    pub(crate) fn set_reference_context_item(&mut self, item: Option<TurnContextItem>) {
        self.history.set_reference_context_item(item);
    }

    pub(crate) fn reference_context_item(&self) -> Option<TurnContextItem> {
        self.history.reference_context_item()
    }

    // Token/rate limit helpers
    pub(crate) fn update_token_info_from_usage(
        &mut self,
        usage: &TokenUsage,
        model_context_window: Option<i64>,
    ) {
        self.history.update_token_info(usage, model_context_window);
    }

    pub(crate) fn token_info(&self) -> Option<TokenUsageInfo> {
        self.history.token_info()
    }

    pub(crate) fn set_rate_limits(&mut self, snapshot: RateLimitSnapshot) {
        self.latest_rate_limits = Some(merge_rate_limit_fields(
            self.latest_rate_limits.as_ref(),
            snapshot,
        ));
    }

    pub(crate) fn token_info_and_rate_limits(
        &self,
    ) -> (Option<TokenUsageInfo>, Option<RateLimitSnapshot>) {
        (self.token_info(), self.latest_rate_limits.clone())
    }

    pub(crate) fn set_token_usage_full(&mut self, context_window: i64) {
        self.history.set_token_usage_full(context_window);
    }

    pub(crate) fn get_total_token_usage(&self, server_reasoning_included: bool) -> i64 {
        self.history
            .get_total_token_usage(server_reasoning_included)
    }

    pub(crate) fn set_server_reasoning_included(&mut self, included: bool) {
        self.server_reasoning_included = included;
    }

    pub(crate) fn server_reasoning_included(&self) -> bool {
        self.server_reasoning_included
    }

    pub(crate) fn record_mcp_dependency_prompted<I>(&mut self, names: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.mcp_dependency_prompted.extend(names);
    }

    pub(crate) fn mcp_dependency_prompted(&self) -> HashSet<String> {
        self.mcp_dependency_prompted.clone()
    }

    pub(crate) fn set_dependency_env(&mut self, values: HashMap<String, String>) {
        for (key, value) in values {
            self.dependency_env.insert(key, value);
        }
    }

    pub(crate) fn dependency_env(&self) -> HashMap<String, String> {
        self.dependency_env.clone()
    }

    pub(crate) fn set_startup_regular_task(&mut self, task: JoinHandle<CodexResult<RegularTask>>) {
        self.startup_regular_task = Some(task);
    }

    pub(crate) fn take_startup_regular_task(
        &mut self,
    ) -> Option<JoinHandle<CodexResult<RegularTask>>> {
        self.startup_regular_task.take()
    }

    // Adds connector IDs to the active set and returns the merged selection.
    pub(crate) fn merge_connector_selection<I>(&mut self, connector_ids: I) -> HashSet<String>
    where
        I: IntoIterator<Item = String>,
    {
        self.active_connector_selection.extend(connector_ids);
        self.active_connector_selection.clone()
    }

    // Returns the current connector selection tracked on session state.
    pub(crate) fn get_connector_selection(&self) -> HashSet<String> {
        self.active_connector_selection.clone()
    }

    // Removes all currently tracked connector selections.
    pub(crate) fn clear_connector_selection(&mut self) {
        self.active_connector_selection.clear();
    }

    pub(crate) fn arm_post_interrupt_collab_hold(&mut self) -> bool {
        let was_armed = self.post_interrupt_collab_hold_armed;
        self.post_interrupt_collab_hold_armed = true;
        !was_armed
    }

    pub(crate) fn post_interrupt_collab_hold_armed(&self) -> bool {
        self.post_interrupt_collab_hold_armed
    }

    pub(crate) fn clear_post_interrupt_collab_hold_if_no_deferred_items(&mut self) -> bool {
        if self.deferred_collab_items.is_empty() {
            self.post_interrupt_collab_hold_armed = false;
            true
        } else {
            false
        }
    }

    pub(crate) fn enqueue_deferred_collab_items(
        &mut self,
        items: Vec<ResponseInputItem>,
    ) -> Result<(), DeferredCollabEnqueueError> {
        if items.is_empty() {
            return Ok(());
        }

        let existing_items = self.deferred_collab_items.len();
        let incoming_items = items.len();
        if existing_items.saturating_add(incoming_items) > DEFERRED_COLLAB_ITEMS_MAX {
            return Err(DeferredCollabEnqueueError::TooManyItems {
                existing_items,
                incoming_items,
                max_items: DEFERRED_COLLAB_ITEMS_MAX,
            });
        }

        let incoming_bytes = match serialized_response_input_items_bytes(&items) {
            Ok(bytes) => bytes,
            Err(err) => {
                return Err(DeferredCollabEnqueueError::Serialization {
                    message: err.to_string(),
                });
            }
        };
        if self
            .deferred_collab_items_bytes
            .saturating_add(incoming_bytes)
            > DEFERRED_COLLAB_BYTES_MAX
        {
            return Err(DeferredCollabEnqueueError::TooManyBytes {
                existing_bytes: self.deferred_collab_items_bytes,
                incoming_bytes,
                max_bytes: DEFERRED_COLLAB_BYTES_MAX,
            });
        }

        self.deferred_collab_items.extend(items);
        self.deferred_collab_items_bytes += incoming_bytes;
        Ok(())
    }

    pub(crate) fn take_deferred_collab_items(&mut self) -> Vec<ResponseInputItem> {
        if self.deferred_collab_items.is_empty() {
            return Vec::with_capacity(0);
        }

        self.deferred_collab_items_bytes = 0;
        std::mem::take(&mut self.deferred_collab_items)
    }

    pub(crate) fn restore_deferred_collab_items(&mut self, items: Vec<ResponseInputItem>) {
        if items.is_empty() {
            return;
        }

        let mut restored_items = items;
        restored_items.append(&mut self.deferred_collab_items);

        let initial_count = restored_items.len();
        if initial_count > DEFERRED_COLLAB_ITEMS_MAX {
            let dropped_items = initial_count - DEFERRED_COLLAB_ITEMS_MAX;
            restored_items.truncate(DEFERRED_COLLAB_ITEMS_MAX);
            warn!(
                dropped_items,
                kept_items = restored_items.len(),
                max_items = DEFERRED_COLLAB_ITEMS_MAX,
                "trimmed deferred collab items during restore to enforce item cap"
            );
        }

        let mut total_bytes = 0usize;
        let mut keep_prefix_len = restored_items.len();
        for (idx, item) in restored_items.iter().enumerate() {
            let item_bytes = match serde_json::to_vec(item).map(|serialized| serialized.len()) {
                Ok(bytes) => bytes,
                Err(err) => {
                    keep_prefix_len = idx;
                    warn!(
                        dropped_items = restored_items.len().saturating_sub(idx),
                        error = %err,
                        "dropping deferred collab items during restore due to serialization failure"
                    );
                    break;
                }
            };

            if total_bytes.saturating_add(item_bytes) > DEFERRED_COLLAB_BYTES_MAX {
                keep_prefix_len = idx;
                warn!(
                    dropped_items = restored_items.len().saturating_sub(idx),
                    kept_items = idx,
                    kept_bytes = total_bytes,
                    max_bytes = DEFERRED_COLLAB_BYTES_MAX,
                    "trimmed deferred collab items during restore to enforce byte cap"
                );
                break;
            }

            total_bytes += item_bytes;
        }

        restored_items.truncate(keep_prefix_len);
        self.deferred_collab_items = restored_items;
        self.deferred_collab_items_bytes = total_bytes;
    }

    pub(crate) fn deferred_collab_stats(&self) -> (usize, usize) {
        (
            self.deferred_collab_items.len(),
            self.deferred_collab_items_bytes,
        )
    }

    pub(crate) fn enqueue_post_turn_agent_items(
        &mut self,
        items: Vec<ResponseInputItem>,
    ) -> Result<(), DeferredCollabEnqueueError> {
        if items.is_empty() {
            return Ok(());
        }

        let existing_items = self.post_turn_agent_items.len();
        let incoming_items = items.len();
        if existing_items.saturating_add(incoming_items) > DEFERRED_COLLAB_ITEMS_MAX {
            return Err(DeferredCollabEnqueueError::TooManyItems {
                existing_items,
                incoming_items,
                max_items: DEFERRED_COLLAB_ITEMS_MAX,
            });
        }

        let incoming_bytes = match serialized_response_input_items_bytes(&items) {
            Ok(bytes) => bytes,
            Err(err) => {
                return Err(DeferredCollabEnqueueError::Serialization {
                    message: err.to_string(),
                });
            }
        };
        if self
            .post_turn_agent_items_bytes
            .saturating_add(incoming_bytes)
            > DEFERRED_COLLAB_BYTES_MAX
        {
            return Err(DeferredCollabEnqueueError::TooManyBytes {
                existing_bytes: self.post_turn_agent_items_bytes,
                incoming_bytes,
                max_bytes: DEFERRED_COLLAB_BYTES_MAX,
            });
        }

        self.post_turn_agent_items.extend(items);
        self.post_turn_agent_items_bytes += incoming_bytes;
        Ok(())
    }

    pub(crate) fn take_post_turn_agent_items(&mut self) -> Vec<ResponseInputItem> {
        if self.post_turn_agent_items.is_empty() {
            self.post_turn_agent_flush_pending = false;
            return Vec::with_capacity(0);
        }

        self.post_turn_agent_items_bytes = 0;
        self.post_turn_agent_flush_pending = false;
        std::mem::take(&mut self.post_turn_agent_items)
    }

    pub(crate) fn arm_post_turn_agent_flush_if_items(&mut self) -> bool {
        self.post_turn_agent_flush_pending = !self.post_turn_agent_items.is_empty();
        self.post_turn_agent_flush_pending
    }

    pub(crate) fn post_turn_agent_flush_pending(&self) -> bool {
        self.post_turn_agent_flush_pending
    }

    pub(crate) fn clear_post_turn_agent_items(&mut self) {
        self.post_turn_agent_items.clear();
        self.post_turn_agent_items_bytes = 0;
        self.post_turn_agent_flush_pending = false;
    }

    #[cfg(test)]
    pub(crate) fn post_turn_agent_stats(&self) -> (usize, usize, bool) {
        (
            self.post_turn_agent_items.len(),
            self.post_turn_agent_items_bytes,
            self.post_turn_agent_flush_pending,
        )
    }

    pub(crate) fn set_pending_session_start_source(
        &mut self,
        value: Option<codex_hooks::SessionStartSource>,
    ) {
        self.pending_session_start_source = value;
    }

    pub(crate) fn take_pending_session_start_source(
        &mut self,
    ) -> Option<codex_hooks::SessionStartSource> {
        self.pending_session_start_source.take()
    }

    pub(crate) fn record_granted_permissions(&mut self, permissions: PermissionProfile) {
        self.granted_permissions =
            merge_permission_profiles(self.granted_permissions.as_ref(), Some(&permissions));
    }

    pub(crate) fn granted_permissions(&self) -> Option<PermissionProfile> {
        self.granted_permissions.clone()
    }
}

fn serialized_response_input_items_bytes(
    items: &[ResponseInputItem],
) -> Result<usize, serde_json::Error> {
    items.iter().try_fold(0usize, |acc, item| {
        serde_json::to_vec(item).map(|serialized| acc.saturating_add(serialized.len()))
    })
}

// Sometimes new snapshots don't include credits or plan information.
// Preserve those from the previous snapshot when missing. For `limit_id`, treat
// missing values as the default `"codex"` bucket.
fn merge_rate_limit_fields(
    previous: Option<&RateLimitSnapshot>,
    mut snapshot: RateLimitSnapshot,
) -> RateLimitSnapshot {
    if snapshot.limit_id.is_none() {
        snapshot.limit_id = Some("codex".to_string());
    }
    if snapshot.credits.is_none() {
        snapshot.credits = previous.and_then(|prior| prior.credits.clone());
    }
    if snapshot.plan_type.is_none() {
        snapshot.plan_type = previous.and_then(|prior| prior.plan_type);
    }
    snapshot
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
