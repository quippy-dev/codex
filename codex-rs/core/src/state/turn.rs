//! Turn-scoped state and active turn metadata scaffolding.

use indexmap::IndexMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use codex_protocol::dynamic_tools::DynamicToolResponse;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::request_permissions::RequestPermissionsResponse;
use codex_protocol::request_user_input::RequestUserInputResponse;
use codex_rmcp_client::ElicitationResponse;
use rmcp::model::RequestId;
use tokio::sync::oneshot;

use crate::codex::TurnContext;
use crate::protocol::ReviewDecision;
use crate::protocol::TokenUsage;
use crate::sandboxing::merge_permission_profiles;
use crate::tasks::SessionTask;
use codex_protocol::models::PermissionProfile;

/// Metadata about the currently running turn.
pub(crate) struct ActiveTurn {
    pub(crate) current_turn_context: Option<Arc<TurnContext>>,
    pub(crate) tasks: IndexMap<String, RunningTask>,
    pub(crate) turn_state: Arc<Mutex<TurnState>>,
}

impl Default for ActiveTurn {
    fn default() -> Self {
        Self {
            current_turn_context: None,
            tasks: IndexMap::new(),
            turn_state: Arc::new(Mutex::new(TurnState::default())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskKind {
    Regular,
    Review,
    Compact,
}

pub(crate) struct RunningTask {
    pub(crate) done: Arc<Notify>,
    pub(crate) kind: TaskKind,
    pub(crate) task: Arc<dyn SessionTask>,
    pub(crate) cancellation_token: CancellationToken,
    pub(crate) handle: Arc<AbortOnDropHandle<()>>,
    pub(crate) initial_turn_context: Arc<TurnContext>,
    // Timer recorded when the task drops to capture the full turn duration.
    pub(crate) _timer: Option<codex_otel::Timer>,
}

impl ActiveTurn {
    pub(crate) fn add_task(&mut self, task: RunningTask) {
        self.current_turn_context = Some(Arc::clone(&task.initial_turn_context));
        let sub_id = task.initial_turn_context.sub_id.clone();
        self.tasks.insert(sub_id, task);
    }

    pub(crate) fn remove_task(&mut self, sub_id: &str) -> bool {
        self.tasks.swap_remove(sub_id);
        self.tasks.is_empty()
    }

    pub(crate) fn drain_tasks(&mut self) -> Vec<RunningTask> {
        self.tasks.drain(..).map(|(_, task)| task).collect()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PendingInputItem {
    pub(crate) item: ResponseInputItem,
    pub(crate) raw_response_item_emitted_live: bool,
}

impl PendingInputItem {
    pub(crate) fn queued(item: ResponseInputItem) -> Self {
        Self {
            item,
            raw_response_item_emitted_live: false,
        }
    }

    pub(crate) fn live_emitted(item: ResponseInputItem) -> Self {
        Self {
            item,
            raw_response_item_emitted_live: true,
        }
    }
}

/// Mutable state for a single turn.
#[derive(Default)]
pub(crate) struct TurnState {
    pending_approvals: HashMap<String, PendingApproval>,
    pending_request_permissions: HashMap<String, oneshot::Sender<RequestPermissionsResponse>>,
    pending_user_input: HashMap<String, oneshot::Sender<RequestUserInputResponse>>,
    pending_elicitations: HashMap<(String, RequestId), oneshot::Sender<ElicitationResponse>>,
    pending_dynamic_tools: HashMap<String, oneshot::Sender<DynamicToolResponse>>,
    pending_input: Vec<PendingInputItem>,
    live_emitted_agent_inbox_messages: HashSet<(String, String)>,
    sampling_completed: bool,
    granted_permissions: Option<PermissionProfile>,
    pub(crate) tool_calls: u64,
    pub(crate) token_usage_at_turn_start: TokenUsage,
}

pub(crate) struct PendingApproval {
    pub(crate) tx: oneshot::Sender<ReviewDecision>,
    pub(crate) turn_id: String,
}

impl TurnState {
    pub(crate) fn insert_pending_approval(
        &mut self,
        key: String,
        approval: PendingApproval,
    ) -> Option<PendingApproval> {
        self.pending_approvals.insert(key, approval)
    }

    pub(crate) fn pending_approval_turn_id(&self, key: &str) -> Option<&str> {
        self.pending_approvals
            .get(key)
            .map(|approval| approval.turn_id.as_str())
    }

    pub(crate) fn remove_pending_approval(&mut self, key: &str) -> Option<PendingApproval> {
        self.pending_approvals.remove(key)
    }

    pub(crate) fn clear_pending(&mut self) {
        self.pending_approvals.clear();
        self.pending_request_permissions.clear();
        self.pending_user_input.clear();
        self.pending_elicitations.clear();
        self.pending_dynamic_tools.clear();
        self.pending_input.clear();
        self.live_emitted_agent_inbox_messages.clear();
    }

    pub(crate) fn insert_pending_request_permissions(
        &mut self,
        key: String,
        tx: oneshot::Sender<RequestPermissionsResponse>,
    ) -> Option<oneshot::Sender<RequestPermissionsResponse>> {
        self.pending_request_permissions.insert(key, tx)
    }

    pub(crate) fn remove_pending_request_permissions(
        &mut self,
        key: &str,
    ) -> Option<oneshot::Sender<RequestPermissionsResponse>> {
        self.pending_request_permissions.remove(key)
    }

    pub(crate) fn insert_pending_user_input(
        &mut self,
        key: String,
        tx: oneshot::Sender<RequestUserInputResponse>,
    ) -> Option<oneshot::Sender<RequestUserInputResponse>> {
        self.pending_user_input.insert(key, tx)
    }

    pub(crate) fn remove_pending_user_input(
        &mut self,
        key: &str,
    ) -> Option<oneshot::Sender<RequestUserInputResponse>> {
        self.pending_user_input.remove(key)
    }

    pub(crate) fn insert_pending_elicitation(
        &mut self,
        server_name: String,
        request_id: RequestId,
        tx: oneshot::Sender<ElicitationResponse>,
    ) -> Option<oneshot::Sender<ElicitationResponse>> {
        self.pending_elicitations
            .insert((server_name, request_id), tx)
    }

    pub(crate) fn remove_pending_elicitation(
        &mut self,
        server_name: &str,
        request_id: &RequestId,
    ) -> Option<oneshot::Sender<ElicitationResponse>> {
        self.pending_elicitations
            .remove(&(server_name.to_string(), request_id.clone()))
    }

    pub(crate) fn insert_pending_dynamic_tool(
        &mut self,
        key: String,
        tx: oneshot::Sender<DynamicToolResponse>,
    ) -> Option<oneshot::Sender<DynamicToolResponse>> {
        self.pending_dynamic_tools.insert(key, tx)
    }

    pub(crate) fn remove_pending_dynamic_tool(
        &mut self,
        key: &str,
    ) -> Option<oneshot::Sender<DynamicToolResponse>> {
        self.pending_dynamic_tools.remove(key)
    }

    pub(crate) fn push_pending_input(&mut self, input: ResponseInputItem) {
        self.pending_input.push(PendingInputItem::queued(input));
    }

    pub(crate) fn push_live_emitted_pending_input(&mut self, input: ResponseInputItem) {
        self.pending_input
            .push(PendingInputItem::live_emitted(input));
    }

    pub(crate) fn record_live_emitted_agent_inbox_message(
        &mut self,
        canonical_sender: String,
        message: String,
    ) {
        self.live_emitted_agent_inbox_messages
            .insert((canonical_sender, message));
    }

    pub(crate) fn has_live_emitted_agent_inbox_message(
        &self,
        canonical_sender: &str,
        message: &str,
    ) -> bool {
        self.live_emitted_agent_inbox_messages
            .contains(&(canonical_sender.to_string(), message.to_string()))
    }

    pub(crate) fn mark_sampling_completed(&mut self) {
        self.sampling_completed = true;
    }

    pub(crate) fn sampling_completed(&self) -> bool {
        self.sampling_completed
    }

    #[cfg(test)]
    pub(crate) fn prepend_pending_input(&mut self, mut input: Vec<ResponseInputItem>) {
        if input.is_empty() {
            return;
        }

        let pending_input = input.drain(..).map(PendingInputItem::queued).collect();
        self.prepend_pending_input_entries(pending_input);
    }

    pub(crate) fn prepend_pending_input_entries(&mut self, mut input: Vec<PendingInputItem>) {
        if input.is_empty() {
            return;
        }

        input.append(&mut self.pending_input);
        self.pending_input = input;
    }

    pub(crate) fn take_pending_input(&mut self) -> Vec<ResponseInputItem> {
        self.take_pending_input_entries()
            .into_iter()
            .map(|pending| pending.item)
            .collect()
    }

    pub(crate) fn take_pending_input_entries(&mut self) -> Vec<PendingInputItem> {
        if self.pending_input.is_empty() {
            Vec::with_capacity(0)
        } else {
            let mut ret = Vec::new();
            std::mem::swap(&mut ret, &mut self.pending_input);
            ret
        }
    }

    pub(crate) fn has_pending_input(&self) -> bool {
        !self.pending_input.is_empty()
    }

    pub(crate) fn record_granted_permissions(&mut self, permissions: PermissionProfile) {
        self.granted_permissions =
            merge_permission_profiles(self.granted_permissions.as_ref(), Some(&permissions));
    }

    pub(crate) fn granted_permissions(&self) -> Option<PermissionProfile> {
        self.granted_permissions.clone()
    }
}

impl ActiveTurn {
    /// Clear any pending approvals and input buffered for the current turn.
    pub(crate) async fn clear_pending(&self) {
        let mut ts = self.turn_state.lock().await;
        ts.clear_pending();
    }
}
