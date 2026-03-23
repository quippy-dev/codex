use super::agent_delivery::completed_message_for_agent_fallback;
#[cfg(test)]
use super::inbox_delivery::build_agent_inbox_items;
use super::progress_cache::AgentProgressCache;
use super::watchdog::RemovedWatchdog;
use super::watchdog::WatchdogManager;
use super::watchdog::WatchdogRegistration;
use crate::AuthManager;
use crate::agent::AgentProgressSnapshot;
use crate::agent::AgentStatus;
use crate::agent::guards::Guards;
use crate::agent::guards::SpawnReservation;
use crate::agent::role::DEFAULT_ROLE_NAME;
use crate::agent::role::resolve_role_config;
use crate::agent::status::is_final;
use crate::codex_thread::ThreadConfigSnapshot;
use crate::config::Config;
#[cfg(test)]
use crate::config::types::CollabInboxDeliveryRole;
use crate::error::CodexErr;
use crate::error::Result as CodexResult;
use crate::find_archived_thread_path_by_id_str;
use crate::find_thread_path_by_id_str;
use crate::rollout::RolloutRecorder;
use crate::session_prefix::format_subagent_context_line;
use crate::session_prefix::format_subagent_notification_message;
use crate::shell_snapshot::ShellSnapshot;
use crate::state_db;
use crate::thread_manager::ThreadManagerState;
use codex_features::Feature;
use codex_protocol::ThreadId;
#[cfg(test)]
use codex_protocol::models::ContentItem;
use codex_protocol::models::FunctionCallOutputPayload;
#[cfg(test)]
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
#[cfg(test)]
use codex_protocol::protocol::AGENT_INBOX_KIND;
#[cfg(test)]
use codex_protocol::protocol::AgentInboxPayload;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ForkReferenceItem;
use codex_protocol::protocol::InitialHistory;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::RolloutItem;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::protocol::TokenUsage;
use codex_protocol::user_input::UserInput;
use codex_state::DirectionalThreadSpawnEdgeStatus;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
#[cfg(test)]
use std::future::Future;
#[cfg(test)]
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Weak;
use tokio::sync::Mutex;
use tokio::sync::watch;
use tracing::warn;

#[path = "control_lifecycle.rs"]
mod control_lifecycle;
#[path = "control_query.rs"]
mod control_query;
#[path = "control_spawn.rs"]
mod control_spawn;

const AGENT_NAMES: &str = include_str!("agent_names.txt");
const FORKED_SPAWN_AGENT_OUTPUT_MESSAGE: &str = "You are the newly spawned agent. The prior conversation history was forked from your parent agent. Treat the next user message as your new task, and use the forked history only as background context.";

#[derive(Clone, Debug, Default)]
pub(crate) struct SpawnAgentOptions {
    pub(crate) fork_parent_spawn_call_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LateAgentDeliveryMode {
    QueuePostTurn,
    LiveOnlyAfterSamplingComplete,
}

fn default_agent_nickname_list() -> Vec<&'static str> {
    AGENT_NAMES
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
}

fn agent_nickname_candidates(
    config: &crate::config::Config,
    role_name: Option<&str>,
) -> Vec<String> {
    let role_name = role_name.unwrap_or(DEFAULT_ROLE_NAME);
    if let Some(candidates) =
        resolve_role_config(config, role_name).and_then(|role| role.nickname_candidates.clone())
    {
        return candidates;
    }

    default_agent_nickname_list()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
}

/// Control-plane handle for multi-agent operations.
/// `AgentControl` is held by each session (via `SessionServices`). It provides capability to
/// spawn new agents and the inter-agent communication layer.
/// An `AgentControl` instance is shared per "user session" which means the same `AgentControl`
/// is used for every sub-agent spawned by Codex. By doing so, we make sure the guards are
/// scoped to a user session.
#[derive(Clone)]
pub(crate) struct AgentControl {
    /// Weak handle back to the global thread registry/state.
    /// This is `Weak` to avoid reference cycles and shadow persistence of the form
    /// `ThreadManagerState -> CodexThread -> Session -> SessionServices -> ThreadManagerState`.
    manager: Weak<ThreadManagerState>,
    pub(super) guards: Arc<Guards>,
    watchdogs: Arc<WatchdogManager>,
    watchdog_compactions_in_progress: Arc<Mutex<HashSet<ThreadId>>>,
    progress_cache: Arc<AgentProgressCache>,
}

#[derive(Debug, Clone)]
pub(crate) struct AgentListing {
    pub(crate) thread_id: ThreadId,
    pub(crate) parent_thread_id: Option<ThreadId>,
    pub(crate) status: AgentStatus,
    pub(crate) depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WatchdogParentCompactionResult {
    NotWatchdogHelper,
    ParentBusy {
        parent_thread_id: ThreadId,
    },
    AlreadyInProgress {
        parent_thread_id: ThreadId,
    },
    Submitted {
        parent_thread_id: ThreadId,
        submission_id: String,
    },
}

impl Default for AgentControl {
    fn default() -> Self {
        let manager = Weak::new();
        let guards = Arc::new(Guards::default());
        let watchdogs = WatchdogManager::new(manager.clone(), Arc::clone(&guards));
        Self::from_parts(manager, guards, watchdogs)
    }
}

impl AgentControl {
    /// Construct a new `AgentControl` that can spawn/message agents via the given manager state.
    pub(crate) fn new(manager: Weak<ThreadManagerState>) -> Self {
        let guards = Arc::new(Guards::default());
        let watchdogs = WatchdogManager::new(manager.clone(), Arc::clone(&guards));
        watchdogs.start();
        Self::from_parts(manager, guards, watchdogs)
    }

    pub(crate) fn from_parts(
        manager: Weak<ThreadManagerState>,
        guards: Arc<Guards>,
        watchdogs: Arc<WatchdogManager>,
    ) -> Self {
        Self {
            manager,
            guards,
            watchdogs,
            watchdog_compactions_in_progress: Arc::new(Mutex::new(HashSet::new())),
            progress_cache: Arc::new(AgentProgressCache::default()),
        }
    }

    pub(crate) async fn record_prompt_preview(&self, thread_id: ThreadId, prompt: &str) {
        self.progress_cache
            .record_prompt_preview(thread_id, prompt)
            .await;
    }

    pub(crate) async fn observe_progress_event(&self, thread_id: ThreadId, event: &EventMsg) {
        self.progress_cache.observe_event(thread_id, event).await;
    }

    pub(crate) async fn progress_snapshots(
        &self,
        thread_ids: &[ThreadId],
    ) -> HashMap<ThreadId, AgentProgressSnapshot> {
        self.progress_cache.snapshots(thread_ids).await
    }

    pub(crate) fn upgrade(&self) -> CodexResult<Arc<ThreadManagerState>> {
        self.manager
            .upgrade()
            .ok_or_else(|| CodexErr::UnsupportedOperation("thread manager dropped".to_string()))
    }
}

fn thread_spawn_parent_thread_id(session_source: &SessionSource) -> Option<ThreadId> {
    match session_source {
        SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id, ..
        }) => Some(*parent_thread_id),
        _ => None,
    }
}

fn thread_spawn_depth(session_source: &SessionSource) -> Option<i32> {
    match session_source {
        SessionSource::SubAgent(SubAgentSource::ThreadSpawn { depth, .. }) => Some(*depth),
        _ => None,
    }
}

fn replayed_parent_auth_file(
    session_meta: &codex_protocol::protocol::SessionMeta,
) -> Option<std::path::PathBuf> {
    let auth_file = session_meta.auth_file.as_ref()?;
    Some(if auth_file.is_absolute() {
        auth_file.clone()
    } else {
        session_meta.cwd.join(auth_file)
    })
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
