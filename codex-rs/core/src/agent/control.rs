use super::agent_delivery::completed_message_for_agent_fallback;
use super::agent_delivery::log_deferred_agent_enqueue_error;
use super::agent_delivery::log_post_turn_agent_enqueue_error;
use super::agent_delivery::should_defer_agent_delivery;
use super::agent_delivery::should_queue_agent_delivery_until_turn_end;
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
use crate::features::Feature;
use crate::find_archived_thread_path_by_id_str;
use crate::find_thread_path_by_id_str;
use crate::rollout::RolloutRecorder;
use crate::session_prefix::format_subagent_context_line;
use crate::session_prefix::format_subagent_notification_message;
use crate::shell_snapshot::ShellSnapshot;
use crate::state_db;
use crate::thread_manager::ThreadManagerState;
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
use uuid::Uuid;

const AGENT_NAMES: &str = include_str!("agent_names.txt");
const FORKED_SPAWN_AGENT_OUTPUT_MESSAGE: &str = "You are the newly spawned agent. The prior conversation history was forked from your parent agent. Treat the next user message as your new task, and use the forked history only as background context.";

#[derive(Clone, Debug, Default)]
pub(crate) struct SpawnAgentOptions {
    pub(crate) fork_parent_spawn_call_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LateAgentDeliveryMode {
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
    guards: Arc<Guards>,
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

    /// Spawn a new agent thread and submit the initial prompt.
    pub(crate) async fn spawn_agent(
        &self,
        config: Config,
        items: Vec<UserInput>,
        session_source: Option<SessionSource>,
    ) -> CodexResult<ThreadId> {
        self.spawn_agent_with_options(config, items, session_source, SpawnAgentOptions::default())
            .await
    }

    pub(crate) async fn spawn_agent_with_options(
        &self,
        config: crate::config::Config,
        items: Vec<UserInput>,
        session_source: Option<SessionSource>,
        options: SpawnAgentOptions,
    ) -> CodexResult<ThreadId> {
        let state = self.upgrade()?;
        let mut reservation = self
            .reserve_spawn_slot_with_reconcile(&state, config.agent_max_threads)
            .await?;
        let inherited_shell_snapshot = self
            .inherited_shell_snapshot_for_source(&state, session_source.as_ref())
            .await;
        let session_source =
            self.maybe_reserve_thread_spawn_identity(&config, &mut reservation, session_source)?;
        let inherited_exec_policy = self
            .inherited_exec_policy_for_source(&state, session_source.as_ref(), &config)
            .await;
        let notification_source = session_source.clone();
        let auth_manager = self
            .auth_manager_for_source(&config, &state, session_source.as_ref())
            .await;

        // The same `AgentControl` is sent to spawn the thread.
        let new_thread = match session_source {
            Some(session_source) => {
                if let Some(call_id) = options.fork_parent_spawn_call_id.as_ref() {
                    let SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                        parent_thread_id,
                        ..
                    }) = session_source.clone()
                    else {
                        return Err(CodexErr::Fatal(
                            "spawn_agent fork requires a thread-spawn session source".to_string(),
                        ));
                    };
                    let parent_thread = state.get_thread(parent_thread_id).await.ok();
                    if let Some(parent_thread) = parent_thread.as_ref() {
                        // `record_conversation_items` only queues rollout writes asynchronously.
                        // Flush/materialize the live parent before snapshotting JSONL for a fork.
                        parent_thread
                            .codex
                            .session
                            .ensure_rollout_materialized()
                            .await;
                        parent_thread.codex.session.flush_rollout().await;
                    }
                    let rollout_path = parent_thread
                        .as_ref()
                        .and_then(|parent_thread| parent_thread.rollout_path())
                        .or(find_thread_path_by_id_str(
                            config.codex_home.as_path(),
                            &parent_thread_id.to_string(),
                        )
                        .await?)
                        .ok_or_else(|| {
                            CodexErr::Fatal(format!(
                                "parent thread rollout unavailable for fork: {parent_thread_id}"
                            ))
                        })?;
                    let mut forked_rollout_items: Vec<RolloutItem> =
                        RolloutRecorder::get_rollout_history(&rollout_path)
                            .await?
                            .get_rollout_items();
                    if forked_rollout_items
                        .iter()
                        .any(|item| matches!(item, RolloutItem::ForkReference(_)))
                    {
                        forked_rollout_items =
                            crate::rollout::truncation::materialize_rollout_items_for_replay(
                                config.codex_home.as_path(),
                                &forked_rollout_items,
                            )
                            .await;
                    }
                    forked_rollout_items.push(RolloutItem::ForkReference(ForkReferenceItem {
                        rollout_path: rollout_path.clone(),
                        nth_user_message: usize::MAX,
                    }));
                    let mut output = FunctionCallOutputPayload::from_text(
                        FORKED_SPAWN_AGENT_OUTPUT_MESSAGE.to_string(),
                    );
                    output.success = Some(true);
                    forked_rollout_items.push(RolloutItem::ResponseItem(
                        ResponseItem::FunctionCallOutput {
                            call_id: call_id.clone(),
                            output,
                        },
                    ));
                    let initial_history = InitialHistory::Forked(forked_rollout_items);
                    state
                        .spawn_thread_from_history_with_source(
                            config,
                            initial_history,
                            auth_manager,
                            self.clone(),
                            session_source,
                            /*persist_extended_history*/ false,
                            inherited_shell_snapshot,
                            inherited_exec_policy,
                        )
                        .await?
                } else {
                    state
                        .spawn_new_thread_with_source(
                            config,
                            auth_manager,
                            self.clone(),
                            session_source,
                            /*persist_extended_history*/ false,
                            /*metrics_service_name*/ None,
                            inherited_shell_snapshot,
                            inherited_exec_policy,
                        )
                        .await?
                }
            }
            None => state.spawn_new_thread(config, self.clone()).await?,
        };
        reservation.commit(new_thread.thread_id);

        // Notify a new thread has been created. This notification will be processed by clients
        // to subscribe or drain this newly created thread.
        // TODO(jif) add helper for drain
        state.notify_thread_created(new_thread.thread_id);
        self.persist_thread_spawn_edge_for_source(
            new_thread.thread.as_ref(),
            new_thread.thread_id,
            notification_source.as_ref(),
        )
        .await;
        self.submit_initial_input_or_cleanup(&state, new_thread.thread_id, items)
            .await?;
        self.maybe_start_completion_watcher(new_thread.thread_id, notification_source);
        Ok(new_thread.thread_id)
    }

    /// Spawn a new agent thread but do not submit an initial prompt.
    ///
    /// This is used for watchdog handles, which should not run a model turn on
    /// their own. The watchdog manager will fork helpers from the owner thread
    /// when the owner becomes idle.
    pub(crate) async fn spawn_agent_handle(
        &self,
        config: Config,
        session_source: Option<SessionSource>,
    ) -> CodexResult<ThreadId> {
        let state = self.upgrade()?;
        let mut reservation = self
            .reserve_spawn_slot_with_reconcile(&state, config.agent_max_threads)
            .await?;
        let session_source =
            self.maybe_reserve_thread_spawn_identity(&config, &mut reservation, session_source)?;
        let notification_source = session_source.clone();
        let inherited_shell_snapshot = self
            .inherited_shell_snapshot_for_source(&state, session_source.as_ref())
            .await;
        let inherited_exec_policy = self
            .inherited_exec_policy_for_source(&state, session_source.as_ref(), &config)
            .await;
        let auth_manager = self
            .auth_manager_for_source(&config, &state, session_source.as_ref())
            .await;

        let new_thread = match session_source {
            Some(session_source) => {
                state
                    .spawn_new_thread_with_source(
                        config,
                        auth_manager,
                        self.clone(),
                        session_source,
                        false,
                        None,
                        inherited_shell_snapshot,
                        inherited_exec_policy,
                    )
                    .await?
            }
            None => state.spawn_new_thread(config, self.clone()).await?,
        };
        reservation.commit(new_thread.thread_id);

        // Notify a new thread has been created. This notification will be processed by clients
        // to subscribe or drain this newly created thread.
        state.notify_thread_created(new_thread.thread_id);
        self.persist_thread_spawn_edge_for_source(
            new_thread.thread.as_ref(),
            new_thread.thread_id,
            notification_source.as_ref(),
        )
        .await;

        Ok(new_thread.thread_id)
    }

    /// Fork an existing agent thread and submit a prompt to the fork.
    pub(crate) async fn fork_agent(
        &self,
        config: Config,
        items: Vec<UserInput>,
        parent_thread_id: ThreadId,
        nth_user_message: usize,
        session_source: SessionSource,
    ) -> CodexResult<ThreadId> {
        let state = self.upgrade()?;
        let mut reservation = self
            .reserve_spawn_slot_with_reconcile(&state, config.agent_max_threads)
            .await?;
        let session_source =
            self.reserve_thread_spawn_identity(&config, &mut reservation, session_source)?;
        let notification_source = Some(session_source.clone());
        let inherited_shell_snapshot = self
            .inherited_shell_snapshot_for_source(&state, Some(&session_source))
            .await;
        let inherited_exec_policy = self
            .inherited_exec_policy_for_source(&state, Some(&session_source), &config)
            .await;
        let auth_manager = self
            .auth_manager_for_parent_thread(&config, &state, parent_thread_id)
            .await;

        let live_rollout_path = match state.get_thread(parent_thread_id).await {
            Ok(parent_thread) => {
                parent_thread.flush_rollout().await;
                parent_thread.rollout_path()
            }
            Err(CodexErr::ThreadNotFound(_)) => None,
            Err(err) => return Err(err),
        };
        let rollout_path = match live_rollout_path {
            Some(path) => path,
            None => find_thread_path_by_id_str(
                config.codex_home.as_path(),
                &parent_thread_id.to_string(),
            )
            .await?
            .ok_or_else(|| {
                CodexErr::UnsupportedOperation(format!(
                    "rollout history unavailable for thread {parent_thread_id}"
                ))
            })?,
        };

        let new_thread = state
            .fork_thread_with_source(
                nth_user_message,
                config,
                auth_manager,
                self.clone(),
                false,
                rollout_path,
                session_source,
                inherited_shell_snapshot,
                inherited_exec_policy,
                None,
            )
            .await?;
        reservation.commit(new_thread.thread_id);
        state.notify_thread_created(new_thread.thread_id);
        self.persist_thread_spawn_edge_for_source(
            new_thread.thread.as_ref(),
            new_thread.thread_id,
            notification_source.as_ref(),
        )
        .await;
        self.submit_initial_input_or_cleanup(&state, new_thread.thread_id, items)
            .await?;
        self.maybe_start_completion_watcher(new_thread.thread_id, notification_source);

        Ok(new_thread.thread_id)
    }

    /// Resume an existing agent thread from a recorded rollout file.
    pub(crate) async fn resume_agent_from_rollout(
        &self,
        config: Config,
        thread_id: ThreadId,
        session_source: SessionSource,
    ) -> CodexResult<ThreadId> {
        let root_depth = thread_spawn_depth(&session_source).unwrap_or(0);
        let resumed_thread_id = self
            .resume_single_agent_from_rollout(config.clone(), thread_id, session_source)
            .await?;
        let state = self.upgrade()?;
        let Ok(resumed_thread) = state.get_thread(resumed_thread_id).await else {
            return Ok(resumed_thread_id);
        };
        let Some(state_db_ctx) = resumed_thread.state_db() else {
            return Ok(resumed_thread_id);
        };

        let mut resume_queue = VecDeque::from([(thread_id, root_depth)]);
        while let Some((parent_thread_id, parent_depth)) = resume_queue.pop_front() {
            let child_ids = match state_db_ctx
                .list_thread_spawn_children_with_status(
                    parent_thread_id,
                    DirectionalThreadSpawnEdgeStatus::Open,
                )
                .await
            {
                Ok(child_ids) => child_ids,
                Err(err) => {
                    warn!(
                        "failed to load persisted thread-spawn children for {parent_thread_id}: {err}"
                    );
                    continue;
                }
            };

            for child_thread_id in child_ids {
                let child_depth = parent_depth + 1;
                let child_resumed = if state.get_thread(child_thread_id).await.is_ok() {
                    true
                } else {
                    let child_session_source =
                        SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                            parent_thread_id,
                            depth: child_depth,
                            agent_nickname: None,
                            agent_role: None,
                        });
                    match self
                        .resume_single_agent_from_rollout(
                            config.clone(),
                            child_thread_id,
                            child_session_source,
                        )
                        .await
                    {
                        Ok(_) => true,
                        Err(err) => {
                            warn!("failed to resume descendant thread {child_thread_id}: {err}");
                            false
                        }
                    }
                };
                if child_resumed {
                    resume_queue.push_back((child_thread_id, child_depth));
                }
            }
        }

        Ok(resumed_thread_id)
    }

    async fn resume_single_agent_from_rollout(
        &self,
        mut config: crate::config::Config,
        thread_id: ThreadId,
        session_source: SessionSource,
    ) -> CodexResult<ThreadId> {
        if let SessionSource::SubAgent(SubAgentSource::ThreadSpawn { depth, .. }) = &session_source
            && *depth >= config.agent_max_depth
        {
            let _ = config.features.disable(Feature::SpawnCsv);
            let _ = config.features.disable(Feature::Collab);
        }
        let state = self.upgrade()?;
        let mut reservation = self
            .reserve_spawn_slot_with_reconcile(&state, config.agent_max_threads)
            .await?;
        let session_source = match session_source {
            SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth,
                agent_nickname,
                agent_role,
            }) => {
                // Collab resume callers rebuild a placeholder ThreadSpawn source. Rehydrate the
                // stored nickname/role from sqlite when available, then prefer any explicit
                // values already present on the session source.
                let (stored_agent_nickname, stored_agent_role) =
                    if let Some(state_db_ctx) = state_db::get_state_db(&config).await {
                        match state_db_ctx.get_thread(thread_id).await {
                            Ok(Some(metadata)) => (metadata.agent_nickname, metadata.agent_role),
                            Ok(None) | Err(_) => (None, None),
                        }
                    } else {
                        (None, None)
                    };
                let resumed_agent_role = agent_role.or(stored_agent_role);
                let resumed_agent_nickname = agent_nickname.or(stored_agent_nickname);
                let reserved_agent_nickname = resumed_agent_nickname
                    .as_deref()
                    .map(|agent_nickname| {
                        let candidate_names =
                            agent_nickname_candidates(&config, resumed_agent_role.as_deref());
                        let candidate_name_refs: Vec<&str> =
                            candidate_names.iter().map(String::as_str).collect();
                        reservation.reserve_agent_nickname_with_preference(
                            &candidate_name_refs,
                            Some(agent_nickname),
                        )
                    })
                    .transpose()?;
                SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth,
                    agent_nickname: reserved_agent_nickname,
                    agent_role: resumed_agent_role,
                })
            }
            other => other,
        };
        let notification_source = session_source.clone();
        let inherited_shell_snapshot = self
            .inherited_shell_snapshot_for_source(&state, Some(&session_source))
            .await;
        let inherited_exec_policy = self
            .inherited_exec_policy_for_source(&state, Some(&session_source), &config)
            .await;
        let auth_manager = self
            .auth_manager_for_source(&config, &state, Some(&session_source))
            .await;
        let rollout_path =
            match find_thread_path_by_id_str(config.codex_home.as_path(), &thread_id.to_string())
                .await?
            {
                Some(rollout_path) => rollout_path,
                None => find_archived_thread_path_by_id_str(
                    config.codex_home.as_path(),
                    &thread_id.to_string(),
                )
                .await?
                .ok_or_else(|| CodexErr::ThreadNotFound(thread_id))?,
            };

        let resumed_thread = state
            .resume_thread_from_rollout_with_source(
                config,
                rollout_path,
                auth_manager,
                self.clone(),
                session_source,
                inherited_shell_snapshot,
                inherited_exec_policy,
            )
            .await?;
        reservation.commit(resumed_thread.thread_id);
        // Resumed threads are re-registered in-memory and need the same listener
        // attachment path as freshly spawned threads.
        state.notify_thread_created(resumed_thread.thread_id);
        self.maybe_start_completion_watcher(
            resumed_thread.thread_id,
            Some(notification_source.clone()),
        );
        self.persist_thread_spawn_edge_for_source(
            resumed_thread.thread.as_ref(),
            resumed_thread.thread_id,
            Some(&notification_source),
        )
        .await;

        Ok(resumed_thread.thread_id)
    }

    /// Send a `user` prompt to an existing agent thread.
    pub(crate) async fn send_prompt(
        &self,
        agent_id: ThreadId,
        prompt: String,
    ) -> CodexResult<String> {
        self.send_input(
            agent_id,
            vec![UserInput::Text {
                text: prompt,
                text_elements: Vec::new(),
            }],
        )
        .await
    }

    /// Send rich user input items to an existing agent thread.
    pub(crate) async fn send_input(
        &self,
        agent_id: ThreadId,
        items: Vec<UserInput>,
    ) -> CodexResult<String> {
        let state = self.upgrade()?;
        let result = state
            .send_op(
                agent_id,
                Op::UserInput {
                    items,
                    final_output_json_schema: None,
                },
            )
            .await;
        if matches!(result, Err(CodexErr::InternalAgentDied)) {
            let _ = state.remove_thread(&agent_id).await;
            self.guards.release_spawned_thread(agent_id);
        }
        result
    }

    async fn note_watchdog_delivery_if_needed(
        &self,
        sender_thread_id: ThreadId,
        sender_is_watchdog_helper_for_receiver: bool,
    ) {
        if sender_is_watchdog_helper_for_receiver {
            let _ = self
                .mark_watchdog_idle_episode_satisfied_for_helper(sender_thread_id)
                .await;
        }
    }

    pub(crate) async fn drop_pending_input(&self, agent_id: ThreadId) -> CodexResult<bool> {
        let state = self.upgrade()?;
        let thread = state.get_thread(agent_id).await?;
        Ok(thread.codex.session.drop_pending_input().await)
    }

    pub(crate) fn was_spawned_thread(&self, agent_id: ThreadId) -> bool {
        self.guards.was_spawned_thread(agent_id)
    }

    /// Send a prompt to an existing agent thread using the configured collab inbox delivery role.
    pub(crate) async fn send_agent_message(
        &self,
        agent_id: ThreadId,
        sender_thread_id: ThreadId,
        message: String,
    ) -> CodexResult<String> {
        self.send_agent_message_inner(
            agent_id,
            sender_thread_id,
            message,
            true,
            LateAgentDeliveryMode::QueuePostTurn,
            #[cfg(test)]
            None,
        )
        .await
    }

    async fn send_agent_message_inner(
        &self,
        agent_id: ThreadId,
        sender_thread_id: ThreadId,
        message: String,
        record_live_sender_message_for_completion_dedupe: bool,
        late_delivery_mode: LateAgentDeliveryMode,
        #[cfg(test)] before_live_inject: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
    ) -> CodexResult<String> {
        let state = self.upgrade()?;
        let thread = state.get_thread(agent_id).await?;
        let snapshot = thread.config_snapshot().await;
        let (sender_agent_nickname, sender_agent_role) = self
            .get_agent_nickname_and_role(sender_thread_id)
            .await
            .unwrap_or((None, None));

        if matches!(snapshot.session_source, SessionSource::SubAgent(_)) {
            return self.send_prompt(agent_id, message).await;
        }

        let receiver_has_active_turn = thread.has_active_turn().await;
        let post_turn_agent_flush_pending =
            thread.codex.session.post_turn_agent_flush_pending().await;
        let post_interrupt_collab_hold_armed = thread
            .codex
            .session
            .post_interrupt_collab_hold_armed()
            .await;
        let sender_is_watchdog_helper_for_receiver = self
            .watchdog_owner_for_active_helper(sender_thread_id)
            .await
            == Some(agent_id);
        if should_queue_agent_delivery_until_turn_end(post_turn_agent_flush_pending) {
            let queued_items = build_agent_inbox_items(
                snapshot.collab_inbox_delivery_role,
                sender_thread_id,
                sender_agent_nickname.clone(),
                sender_agent_role.clone(),
                message.clone(),
                false,
            )?;
            match thread
                .codex
                .session
                .enqueue_post_turn_agent_items(queued_items)
                .await
            {
                Ok(()) => {
                    self.note_watchdog_delivery_if_needed(
                        sender_thread_id,
                        sender_is_watchdog_helper_for_receiver,
                    )
                    .await;
                    return Ok(Uuid::now_v7().to_string());
                }
                Err(err) => log_post_turn_agent_enqueue_error(agent_id, sender_thread_id, err),
            }
        }
        if receiver_has_active_turn {
            #[cfg(test)]
            if let Some(before_live_inject) = before_live_inject {
                before_live_inject.await;
            }
            let live_items = build_agent_inbox_items(
                snapshot.collab_inbox_delivery_role,
                sender_thread_id,
                sender_agent_nickname.clone(),
                sender_agent_role.clone(),
                message.clone(),
                false,
            )?;
            match thread.codex.session.inject_response_items(live_items).await {
                Ok(()) => {
                    if record_live_sender_message_for_completion_dedupe {
                        self.record_live_forwarded_agent_message(sender_thread_id, &message)
                            .await;
                    }
                    self.note_watchdog_delivery_if_needed(
                        sender_thread_id,
                        sender_is_watchdog_helper_for_receiver,
                    )
                    .await;
                    return Ok(Uuid::now_v7().to_string());
                }
                Err(late_items) => {
                    let post_interrupt_collab_hold_armed = thread
                        .codex
                        .session
                        .post_interrupt_collab_hold_armed()
                        .await;
                    let should_defer_late_items = should_defer_agent_delivery(
                        false,
                        post_interrupt_collab_hold_armed,
                        sender_is_watchdog_helper_for_receiver,
                    );
                    if should_defer_late_items {
                        match thread
                            .codex
                            .session
                            .enqueue_deferred_collab_items(late_items)
                            .await
                        {
                            Ok(()) => {
                                self.note_watchdog_delivery_if_needed(
                                    sender_thread_id,
                                    sender_is_watchdog_helper_for_receiver,
                                )
                                .await;
                                return Ok(Uuid::now_v7().to_string());
                            }
                            Err(err) => {
                                log_deferred_agent_enqueue_error(agent_id, sender_thread_id, err)
                            }
                        }
                    } else if late_delivery_mode
                        == LateAgentDeliveryMode::LiveOnlyAfterSamplingComplete
                        && let Some(turn_context) =
                            thread.codex.session.current_active_turn_context().await
                    {
                        let sender_thread_id_text = sender_thread_id.to_string();
                        if thread
                            .codex
                            .session
                            .active_turn_has_live_emitted_agent_inbox_message(
                                sender_thread_id_text.as_str(),
                                &message,
                            )
                            .await
                        {
                            return Ok(Uuid::now_v7().to_string());
                        }
                        let live_response_items = late_items
                            .into_iter()
                            .map(ResponseItem::from)
                            .collect::<Vec<_>>();
                        thread
                            .codex
                            .session
                            .record_conversation_items(turn_context.as_ref(), &live_response_items)
                            .await;
                        if record_live_sender_message_for_completion_dedupe {
                            self.record_live_forwarded_agent_message(sender_thread_id, &message)
                                .await;
                        }
                        self.note_watchdog_delivery_if_needed(
                            sender_thread_id,
                            sender_is_watchdog_helper_for_receiver,
                        )
                        .await;
                        return Ok(Uuid::now_v7().to_string());
                    } else {
                        match thread
                            .codex
                            .session
                            .enqueue_post_turn_agent_items(late_items)
                            .await
                        {
                            Ok(()) => {
                                if thread
                                    .codex
                                    .session
                                    .arm_post_turn_agent_flush_if_items()
                                    .await
                                {
                                    if thread.has_active_turn().await {
                                        self.note_watchdog_delivery_if_needed(
                                            sender_thread_id,
                                            sender_is_watchdog_helper_for_receiver,
                                        )
                                        .await;
                                        return Ok(Uuid::now_v7().to_string());
                                    }
                                    if let Err(err) = state
                                        .send_op(
                                            agent_id,
                                            Op::InjectResponseItems { items: Vec::new() },
                                        )
                                        .await
                                    {
                                        warn!(
                                            receiver_thread_id = %agent_id,
                                            sender_thread_id = %sender_thread_id,
                                            "failed to submit post-turn agent items after late active-turn inject miss: {err}"
                                        );
                                        thread.codex.session.clear_post_turn_agent_items().await;
                                    } else {
                                        self.note_watchdog_delivery_if_needed(
                                            sender_thread_id,
                                            sender_is_watchdog_helper_for_receiver,
                                        )
                                        .await;
                                        return Ok(Uuid::now_v7().to_string());
                                    }
                                } else {
                                    self.note_watchdog_delivery_if_needed(
                                        sender_thread_id,
                                        sender_is_watchdog_helper_for_receiver,
                                    )
                                    .await;
                                    return Ok(Uuid::now_v7().to_string());
                                }
                            }
                            Err(err) => {
                                log_post_turn_agent_enqueue_error(agent_id, sender_thread_id, err)
                            }
                        }
                    }
                }
            }
        }
        if should_defer_agent_delivery(
            receiver_has_active_turn,
            post_interrupt_collab_hold_armed,
            sender_is_watchdog_helper_for_receiver,
        ) {
            let deferred_items = build_agent_inbox_items(
                snapshot.collab_inbox_delivery_role,
                sender_thread_id,
                sender_agent_nickname.clone(),
                sender_agent_role.clone(),
                message.clone(),
                false,
            )?;
            match thread
                .codex
                .session
                .enqueue_deferred_collab_items(deferred_items)
                .await
            {
                Ok(()) => {
                    self.note_watchdog_delivery_if_needed(
                        sender_thread_id,
                        sender_is_watchdog_helper_for_receiver,
                    )
                    .await;
                    return Ok(Uuid::now_v7().to_string());
                }
                Err(err) => log_deferred_agent_enqueue_error(agent_id, sender_thread_id, err),
            }
        }

        let items = build_agent_inbox_items(
            snapshot.collab_inbox_delivery_role,
            sender_thread_id,
            sender_agent_nickname,
            sender_agent_role,
            message.clone(),
            false,
        )?;
        let submission_id = state
            .send_op(agent_id, Op::InjectResponseItems { items })
            .await?;
        self.note_watchdog_delivery_if_needed(
            sender_thread_id,
            sender_is_watchdog_helper_for_receiver,
        )
        .await;
        Ok(submission_id)
    }

    /// Interrupt the current task for an existing agent thread.
    pub(crate) async fn interrupt_agent(&self, agent_id: ThreadId) -> CodexResult<String> {
        let state = self.upgrade()?;
        state.send_op(agent_id, Op::Interrupt).await
    }

    /// Submit a shutdown request to an existing agent thread and any live descendants.
    pub(crate) async fn shutdown_agent(&self, agent_id: ThreadId) -> CodexResult<String> {
        let state = self.upgrade()?;
        let mut descendants = self.collect_descendants(&state, agent_id).await;
        descendants.reverse();
        for descendant_id in descendants {
            match self.shutdown_single_live_agent(&state, descendant_id).await {
                Ok(_) | Err(CodexErr::ThreadNotFound(_)) | Err(CodexErr::InternalAgentDied) => {}
                Err(err) => return Err(err),
            }
        }
        self.shutdown_single_live_agent(&state, agent_id).await
    }

    /// Submit a shutdown request for a live agent without marking it explicitly closed in
    /// persisted spawn-edge state.
    pub(crate) async fn shutdown_live_agent(&self, agent_id: ThreadId) -> CodexResult<String> {
        let state = self.upgrade()?;
        self.shutdown_single_live_agent(&state, agent_id).await
    }

    /// Mark `agent_id` as explicitly closed in persisted spawn-edge state, then shut down the
    /// agent and any live descendants reached from the in-memory tree.
    pub(crate) async fn close_agent(&self, agent_id: ThreadId) -> CodexResult<String> {
        let state = self.upgrade()?;
        if let Ok(thread) = state.get_thread(agent_id).await
            && let Some(state_db_ctx) = thread.state_db()
            && let Err(err) = state_db_ctx
                .set_thread_spawn_edge_status(agent_id, DirectionalThreadSpawnEdgeStatus::Closed)
                .await
        {
            warn!("failed to persist thread-spawn edge status for {agent_id}: {err}");
        }
        self.shutdown_agent_tree(agent_id).await
    }

    /// Shut down `agent_id` and any live descendants reachable from the in-memory spawn tree.
    async fn shutdown_agent_tree(&self, agent_id: ThreadId) -> CodexResult<String> {
        let descendant_ids = self.live_thread_spawn_descendants(agent_id).await?;
        let result = self.shutdown_live_agent(agent_id).await;
        for descendant_id in descendant_ids {
            match self.shutdown_live_agent(descendant_id).await {
                Ok(_) | Err(CodexErr::ThreadNotFound(_)) | Err(CodexErr::InternalAgentDied) => {}
                Err(err) => return Err(err),
            }
        }
        result
    }

    async fn shutdown_single_live_agent(
        &self,
        state: &Arc<ThreadManagerState>,
        agent_id: ThreadId,
    ) -> CodexResult<String> {
        if let Some(removed_watchdog) = self.watchdogs.unregister(agent_id).await
            && let Some(helper_id) = removed_watchdog.active_helper_id
        {
            if let Ok(owner_thread) = state.get_thread(removed_watchdog.owner_thread_id).await
                && !is_final(&owner_thread.agent_status().await)
            {
                self.watchdogs
                    .preserve_helper_owner_for_completion_fallback(
                        helper_id,
                        removed_watchdog.owner_thread_id,
                    )
                    .await;
            }
            let _ = state.send_op(helper_id, Op::Shutdown {}).await;
            let _ = state.remove_thread(&helper_id).await;
            self.guards.release_spawned_thread(helper_id);
        }

        let result = if let Ok(thread) = state.get_thread(agent_id).await {
            thread.codex.session.ensure_rollout_materialized().await;
            thread.codex.session.flush_rollout().await;
            if matches!(thread.agent_status().await, AgentStatus::Shutdown) {
                Ok(String::new())
            } else {
                state.send_op(agent_id, Op::Shutdown {}).await
            }
        } else {
            state.send_op(agent_id, Op::Shutdown {}).await
        };
        let _ = state.remove_thread(&agent_id).await;
        self.guards.release_spawned_thread(agent_id);
        result
    }

    /// Fetch the last known status for `agent_id`, returning `NotFound` when unavailable.
    pub(crate) async fn get_status(&self, agent_id: ThreadId) -> AgentStatus {
        let Ok(state) = self.upgrade() else {
            // No agent available if upgrade fails.
            return AgentStatus::NotFound;
        };
        let Ok(thread) = state.get_thread(agent_id).await else {
            return AgentStatus::NotFound;
        };
        thread.agent_status().await
    }

    pub(crate) async fn get_agent_nickname_and_role(
        &self,
        agent_id: ThreadId,
    ) -> Option<(Option<String>, Option<String>)> {
        let Ok(state) = self.upgrade() else {
            return None;
        };
        let Ok(thread) = state.get_thread(agent_id).await else {
            return None;
        };
        let session_source = thread.config_snapshot().await.session_source;
        Some((
            session_source.get_nickname(),
            session_source.get_agent_role(),
        ))
    }

    pub(crate) async fn resolve_root_thread_id(&self, thread_id: ThreadId) -> ThreadId {
        let Ok(state) = self.upgrade() else {
            return thread_id;
        };
        let mut root_thread_id = thread_id;
        let mut visited = HashSet::new();
        while visited.insert(root_thread_id) {
            let Ok(thread) = state.get_thread(root_thread_id).await else {
                break;
            };
            let snapshot = thread.config_snapshot().await;
            let SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id, ..
            }) = snapshot.session_source
            else {
                break;
            };
            if parent_thread_id == root_thread_id {
                break;
            }
            root_thread_id = parent_thread_id;
        }
        root_thread_id
    }

    #[allow(dead_code)]
    pub(crate) async fn get_agent_config_snapshot(
        &self,
        agent_id: ThreadId,
    ) -> Option<ThreadConfigSnapshot> {
        let Ok(state) = self.upgrade() else {
            return None;
        };
        let Ok(thread) = state.get_thread(agent_id).await else {
            return None;
        };
        Some(thread.config_snapshot().await)
    }

    /// Subscribe to status updates for `agent_id`, yielding the latest value and changes.
    pub(crate) async fn subscribe_status(
        &self,
        agent_id: ThreadId,
    ) -> CodexResult<watch::Receiver<AgentStatus>> {
        let state = self.upgrade()?;
        let thread = state.get_thread(agent_id).await?;
        Ok(thread.subscribe_status())
    }

    pub(crate) async fn get_total_token_usage(&self, agent_id: ThreadId) -> Option<TokenUsage> {
        let Ok(state) = self.upgrade() else {
            return None;
        };
        let Ok(thread) = state.get_thread(agent_id).await else {
            return None;
        };
        thread.total_token_usage().await
    }

    pub(crate) async fn format_environment_context_subagents(
        &self,
        parent_thread_id: ThreadId,
    ) -> String {
        let Ok(agents) = self.open_thread_spawn_children(parent_thread_id).await else {
            return String::new();
        };

        agents
            .into_iter()
            .map(|(thread_id, nickname)| {
                format_subagent_context_line(&thread_id.to_string(), nickname.as_deref())
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Starts a detached watcher for sub-agents spawned from another thread.
    ///
    /// This is only enabled for `SubAgentSource::ThreadSpawn`, where a parent thread exists and
    /// can receive completion notifications.
    fn maybe_start_completion_watcher(
        &self,
        child_thread_id: ThreadId,
        session_source: Option<SessionSource>,
    ) {
        let Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id, ..
        })) = session_source
        else {
            return;
        };
        let control = self.clone();
        tokio::spawn(async move {
            let status = match control.subscribe_status(child_thread_id).await {
                Ok(mut status_rx) => {
                    let mut status = status_rx.borrow().clone();
                    while !is_final(&status) {
                        if status_rx.changed().await.is_err() {
                            status = control.get_status(child_thread_id).await;
                            break;
                        }
                        status = status_rx.borrow().clone();
                    }
                    status
                }
                Err(_) => control.get_status(child_thread_id).await,
            };
            if !is_final(&status) {
                return;
            }

            let Ok(state) = control.upgrade() else {
                return;
            };
            let Ok(parent_thread) = state.get_thread(parent_thread_id).await else {
                return;
            };
            let parent_is_root_thread = !matches!(
                parent_thread.config_snapshot().await.session_source,
                SessionSource::SubAgent(_)
            );
            let child_is_watchdog_helper_for_parent = control
                .watchdog_owner_for_active_helper(child_thread_id)
                .await
                == Some(parent_thread_id);

            if parent_is_root_thread {
                let child_used_agent_send_input =
                    if let Ok(child_thread) = state.get_thread(child_thread_id).await {
                        child_thread
                            .codex
                            .session
                            .last_completed_turn_used_agent_send_input()
                    } else {
                        false
                    };
                let child_completed_message_already_forwarded = match &status {
                    AgentStatus::Completed(Some(message)) if !message.trim().is_empty() => {
                        if let Ok(child_thread) = state.get_thread(child_thread_id).await {
                            child_thread
                                .codex
                                .session
                                .last_completed_turn_live_forwarded_agent_message(message)
                                .await
                        } else {
                            false
                        }
                    }
                    _ => false,
                };
                if let Some(message) = completed_message_for_agent_fallback(
                    &status,
                    child_used_agent_send_input,
                    child_completed_message_already_forwarded,
                    child_is_watchdog_helper_for_parent,
                ) {
                    match control
                        .send_agent_message_inner(
                            parent_thread_id,
                            child_thread_id,
                            message,
                            false,
                            if child_is_watchdog_helper_for_parent {
                                LateAgentDeliveryMode::QueuePostTurn
                            } else {
                                LateAgentDeliveryMode::LiveOnlyAfterSamplingComplete
                            },
                            #[cfg(test)]
                            None,
                        )
                        .await
                    {
                        Ok(_) => {
                            if child_is_watchdog_helper_for_parent {
                                control
                                    .mark_watchdog_idle_episode_satisfied_for_helper(
                                        child_thread_id,
                                    )
                                    .await;
                            }
                        }
                        Err(err) => {
                            warn!(
                                child_thread_id = %child_thread_id,
                                parent_thread_id = %parent_thread_id,
                                "subagent completion fallback forward failed: {err}"
                            );
                        }
                    }
                }
            }
            parent_thread
                .inject_user_message_without_turn(format_subagent_notification_message(
                    &child_thread_id.to_string(),
                    &status,
                ))
                .await;
            control
                .watchdogs
                .clear_preserved_helper_owner(child_thread_id)
                .await;
        });
    }

    async fn record_live_forwarded_agent_message(&self, sender_thread_id: ThreadId, message: &str) {
        if let Ok(state) = self.upgrade()
            && let Ok(sender_thread) = state.get_thread(sender_thread_id).await
        {
            sender_thread
                .codex
                .session
                .record_turn_live_forwarded_agent_message(message)
                .await;
        }
    }

    pub(crate) async fn watchdog_targets(&self, agent_ids: &[ThreadId]) -> HashSet<ThreadId> {
        self.watchdogs.registered_targets(agent_ids).await
    }

    pub(crate) async fn register_watchdog(
        &self,
        registration: WatchdogRegistration,
    ) -> CodexResult<Vec<RemovedWatchdog>> {
        self.watchdogs.register(registration).await
    }

    pub(crate) async fn unregister_watchdog(
        &self,
        target_thread_id: ThreadId,
    ) -> Option<RemovedWatchdog> {
        self.watchdogs.unregister(target_thread_id).await
    }

    pub(crate) async fn unregister_watchdogs_for_owner(
        &self,
        owner_thread_id: ThreadId,
    ) -> Vec<RemovedWatchdog> {
        self.watchdogs.take_for_owner(owner_thread_id).await
    }

    pub(crate) async fn compact_parent_for_watchdog_helper(
        &self,
        helper_thread_id: ThreadId,
    ) -> CodexResult<WatchdogParentCompactionResult> {
        self.compact_parent_for_watchdog_helper_inner(
            helper_thread_id,
            #[cfg(test)]
            None,
        )
        .await
    }

    async fn compact_parent_for_watchdog_helper_inner(
        &self,
        helper_thread_id: ThreadId,
        #[cfg(test)] before_submit_recheck: Option<
            Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
        >,
    ) -> CodexResult<WatchdogParentCompactionResult> {
        let Some(parent_thread_id) = self
            .watchdogs
            .owner_for_active_helper(helper_thread_id)
            .await
        else {
            return Ok(WatchdogParentCompactionResult::NotWatchdogHelper);
        };
        let state = self.upgrade()?;
        let parent_thread = state.get_thread(parent_thread_id).await?;
        let parent_has_active_turn = parent_thread.has_active_turn().await;

        #[cfg(test)]
        if let Some(before_submit_recheck) = before_submit_recheck {
            before_submit_recheck.await;
        }

        {
            let mut compacting = self.watchdog_compactions_in_progress.lock().await;
            if compacting.contains(&parent_thread_id) {
                return Ok(WatchdogParentCompactionResult::AlreadyInProgress { parent_thread_id });
            }
            if parent_has_active_turn {
                return Ok(WatchdogParentCompactionResult::ParentBusy { parent_thread_id });
            }
            compacting.insert(parent_thread_id);
        }

        if parent_thread.has_active_turn().await {
            let mut compacting = self.watchdog_compactions_in_progress.lock().await;
            compacting.remove(&parent_thread_id);
            return Ok(WatchdogParentCompactionResult::ParentBusy { parent_thread_id });
        }

        match state.send_op(parent_thread_id, Op::Compact).await {
            Ok(submission_id) => Ok(WatchdogParentCompactionResult::Submitted {
                parent_thread_id,
                submission_id,
            }),
            Err(err) => {
                let mut compacting = self.watchdog_compactions_in_progress.lock().await;
                compacting.remove(&parent_thread_id);
                Err(err)
            }
        }
    }

    pub(crate) async fn finish_watchdog_parent_compaction(&self, parent_thread_id: ThreadId) {
        let mut compacting = self.watchdog_compactions_in_progress.lock().await;
        compacting.remove(&parent_thread_id);
    }

    pub(crate) async fn watchdog_parent_compaction_in_progress(
        &self,
        parent_thread_id: ThreadId,
    ) -> bool {
        let compacting = self.watchdog_compactions_in_progress.lock().await;
        compacting.contains(&parent_thread_id)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn run_watchdogs_once_for_tests(&self) {
        self.watchdogs.run_once().await;
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn force_watchdog_due_for_tests(&self, target_thread_id: ThreadId) {
        self.watchdogs.force_due_for_tests(target_thread_id).await;
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn set_watchdog_active_helper_for_tests(
        &self,
        target_thread_id: ThreadId,
        helper_thread_id: ThreadId,
    ) {
        self.watchdogs
            .set_active_helper_for_tests(target_thread_id, helper_thread_id)
            .await;
    }

    #[cfg(test)]
    pub(crate) async fn mark_watchdog_parent_compaction_in_progress_for_tests(
        &self,
        parent_thread_id: ThreadId,
    ) {
        let mut compacting = self.watchdog_compactions_in_progress.lock().await;
        compacting.insert(parent_thread_id);
    }

    pub(crate) async fn watchdog_owner_for_active_helper(
        &self,
        helper_thread_id: ThreadId,
    ) -> Option<ThreadId> {
        self.watchdogs
            .owner_for_active_helper(helper_thread_id)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn watchdog_active_helper_for_tests(
        &self,
        target_thread_id: ThreadId,
    ) -> Option<ThreadId> {
        self.watchdogs
            .active_helper_for_target(target_thread_id)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn watchdog_idle_episode_satisfied_for_tests(
        &self,
        target_thread_id: ThreadId,
    ) -> Option<bool> {
        self.watchdogs
            .idle_episode_satisfied_for_target(target_thread_id)
            .await
    }

    pub(crate) async fn mark_watchdog_idle_episode_satisfied_for_helper(
        &self,
        helper_thread_id: ThreadId,
    ) -> bool {
        self.watchdogs
            .mark_idle_episode_satisfied_for_helper(helper_thread_id)
            .await
    }

    pub(crate) async fn list_agents(
        &self,
        owner_thread_id: ThreadId,
        recursive: bool,
        all: bool,
    ) -> CodexResult<Vec<AgentListing>> {
        let state = self.upgrade()?;
        let threads = state.list_threads().await;

        let mut parent_by_thread: HashMap<ThreadId, Option<ThreadId>> =
            HashMap::with_capacity(threads.len());
        let mut status_by_thread: HashMap<ThreadId, AgentStatus> =
            HashMap::with_capacity(threads.len());
        let mut depth_by_thread: HashMap<ThreadId, usize> = HashMap::with_capacity(threads.len());

        for (thread_id, thread) in &threads {
            let snapshot = thread.config_snapshot().await;
            let (parent_thread_id, depth) = match snapshot.session_source {
                SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth,
                    ..
                }) => (
                    Some(parent_thread_id),
                    usize::try_from(depth).unwrap_or_default(),
                ),
                _ => (None, 0),
            };
            parent_by_thread.insert(*thread_id, parent_thread_id);
            status_by_thread.insert(*thread_id, thread.agent_status().await);
            depth_by_thread.insert(*thread_id, depth);
        }

        let mut children_by_parent: HashMap<ThreadId, Vec<ThreadId>> = HashMap::new();
        for (thread_id, parent_thread_id) in &parent_by_thread {
            if let Some(parent_thread_id) = parent_thread_id {
                children_by_parent
                    .entry(*parent_thread_id)
                    .or_default()
                    .push(*thread_id);
            }
        }

        for children in children_by_parent.values_mut() {
            children.sort_by_key(ToString::to_string);
        }

        let mut listings = Vec::new();
        if all {
            let mut thread_ids = self.guards.tracked_thread_ids();
            thread_ids.sort_by_key(ToString::to_string);
            for thread_id in thread_ids {
                listings.push(AgentListing {
                    thread_id,
                    parent_thread_id: parent_by_thread.get(&thread_id).copied().flatten(),
                    status: status_by_thread
                        .get(&thread_id)
                        .cloned()
                        .unwrap_or(AgentStatus::NotFound),
                    depth: depth_by_thread.get(&thread_id).copied().unwrap_or_default(),
                });
            }
            return Ok(listings);
        }

        let mut queue: VecDeque<(ThreadId, usize)> = VecDeque::new();
        if let Some(children) = children_by_parent.get(&owner_thread_id) {
            for child in children {
                queue.push_back((*child, 1));
            }
        }

        while let Some((thread_id, depth)) = queue.pop_front() {
            listings.push(AgentListing {
                thread_id,
                parent_thread_id: parent_by_thread.get(&thread_id).copied().flatten(),
                status: status_by_thread
                    .get(&thread_id)
                    .cloned()
                    .unwrap_or(AgentStatus::NotFound),
                depth,
            });

            if recursive && let Some(children) = children_by_parent.get(&thread_id) {
                for child in children {
                    queue.push_back((*child, depth + 1));
                }
            }
        }

        Ok(listings)
    }

    fn upgrade(&self) -> CodexResult<Arc<ThreadManagerState>> {
        self.manager
            .upgrade()
            .ok_or_else(|| CodexErr::UnsupportedOperation("thread manager dropped".to_string()))
    }

    async fn submit_initial_input_or_cleanup(
        &self,
        state: &ThreadManagerState,
        thread_id: ThreadId,
        items: Vec<UserInput>,
    ) -> CodexResult<()> {
        if let Err(err) = self.send_input(thread_id, items).await {
            let _ = state.send_op(thread_id, Op::Shutdown {}).await;
            let _ = state.remove_thread(&thread_id).await;
            self.guards.release_spawned_thread(thread_id);
            return Err(err);
        }
        Ok(())
    }

    async fn reserve_spawn_slot_with_reconcile(
        &self,
        state: &ThreadManagerState,
        max_threads: Option<usize>,
    ) -> CodexResult<crate::agent::guards::SpawnReservation> {
        self.reconcile_stale_guard_slots(state).await;
        let first_attempt = self.guards.reserve_spawn_slot(max_threads);
        match first_attempt {
            Ok(reservation) => return Ok(reservation),
            Err(CodexErr::AgentLimitReached { .. }) => {}
            Err(err) => return Err(err),
        }

        self.reconcile_stale_guard_slots(state).await;
        let second_attempt = self.guards.reserve_spawn_slot(max_threads);
        if let Err(CodexErr::AgentLimitReached { max_threads }) = second_attempt.as_ref() {
            let live_thread_ids = state
                .list_threads()
                .await
                .into_iter()
                .map(|(thread_id, _)| thread_id)
                .collect::<HashSet<_>>();
            let snapshot = self.guards.thread_cap_snapshot();
            let stale_tracked = snapshot
                .tracked_thread_ids
                .iter()
                .filter(|thread_id| !live_thread_ids.contains(thread_id))
                .count();
            warn!(
                max_threads,
                guard_total_count = snapshot.total_count,
                guard_tracked_count = snapshot.tracked_count,
                guard_in_flight_reservations = snapshot.in_flight_reservations,
                live_thread_count = live_thread_ids.len(),
                stale_tracked_count = stale_tracked,
                tracked_thread_ids = ?snapshot.tracked_thread_ids,
                live_thread_ids = ?live_thread_ids,
                "agent thread cap reached after stale-slot reconciliation"
            );
        }
        second_attempt
    }

    async fn reconcile_stale_guard_slots(&self, state: &ThreadManagerState) {
        let live_thread_ids: HashSet<ThreadId> = state
            .list_threads()
            .await
            .into_iter()
            .map(|(thread_id, _)| thread_id)
            .collect();
        for tracked_thread_id in self.guards.tracked_thread_ids() {
            if !live_thread_ids.contains(&tracked_thread_id) {
                self.guards.release_spawned_thread(tracked_thread_id);
            }
        }
    }

    async fn collect_descendants(
        &self,
        state: &ThreadManagerState,
        owner_thread_id: ThreadId,
    ) -> Vec<ThreadId> {
        let threads = state.list_threads().await;
        let mut children_by_parent: HashMap<ThreadId, Vec<ThreadId>> = HashMap::new();
        for (thread_id, thread) in &threads {
            let snapshot = thread.config_snapshot().await;
            if let SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id, ..
            }) = snapshot.session_source
            {
                children_by_parent
                    .entry(parent_thread_id)
                    .or_default()
                    .push(*thread_id);
            }
        }

        for children in children_by_parent.values_mut() {
            children.sort_by_key(ToString::to_string);
        }

        let mut descendants = Vec::new();
        let mut queue = VecDeque::new();
        if let Some(children) = children_by_parent.get(&owner_thread_id) {
            for child in children {
                queue.push_back(*child);
            }
        }

        while let Some(thread_id) = queue.pop_front() {
            descendants.push(thread_id);
            if let Some(children) = children_by_parent.get(&thread_id) {
                for child in children {
                    queue.push_back(*child);
                }
            }
        }

        descendants
    }

    fn reserve_thread_spawn_identity(
        &self,
        config: &Config,
        reservation: &mut SpawnReservation,
        session_source: SessionSource,
    ) -> CodexResult<SessionSource> {
        match session_source {
            SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth,
                agent_nickname,
                agent_role,
            }) => {
                let candidate_names = agent_nickname_candidates(config, agent_role.as_deref());
                let candidate_name_refs: Vec<&str> =
                    candidate_names.iter().map(String::as_str).collect();
                let agent_nickname = reservation.reserve_agent_nickname_with_preference(
                    &candidate_name_refs,
                    agent_nickname.as_deref(),
                )?;
                Ok(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth,
                    agent_nickname: Some(agent_nickname),
                    agent_role,
                }))
            }
            other => Ok(other),
        }
    }

    fn maybe_reserve_thread_spawn_identity(
        &self,
        config: &Config,
        reservation: &mut SpawnReservation,
        session_source: Option<SessionSource>,
    ) -> CodexResult<Option<SessionSource>> {
        session_source
            .map(|source| self.reserve_thread_spawn_identity(config, reservation, source))
            .transpose()
    }

    async fn inherited_shell_snapshot_for_source(
        &self,
        state: &Arc<ThreadManagerState>,
        session_source: Option<&SessionSource>,
    ) -> Option<Arc<ShellSnapshot>> {
        let Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id, ..
        })) = session_source
        else {
            return None;
        };

        let parent_thread = state.get_thread(*parent_thread_id).await.ok()?;
        parent_thread.codex.session.user_shell().shell_snapshot()
    }

    async fn auth_manager_for_source(
        &self,
        config: &Config,
        state: &Arc<ThreadManagerState>,
        session_source: Option<&SessionSource>,
    ) -> Arc<AuthManager> {
        let Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id, ..
        })) = session_source
        else {
            return state.default_auth_manager();
        };

        self.auth_manager_for_parent_thread(config, state, *parent_thread_id)
            .await
    }

    async fn auth_manager_for_parent_thread(
        &self,
        config: &Config,
        state: &Arc<ThreadManagerState>,
        parent_thread_id: ThreadId,
    ) -> Arc<AuthManager> {
        let default_auth_manager = state.default_auth_manager();
        match state.get_thread(parent_thread_id).await {
            Ok(parent_thread) => Arc::clone(&parent_thread.codex.session.services.auth_manager),
            Err(_) => self
                .auth_manager_from_parent_rollout(
                    config,
                    parent_thread_id,
                    default_auth_manager.enable_codex_api_key_env(),
                )
                .await
                .unwrap_or(default_auth_manager),
        }
    }

    async fn auth_manager_from_parent_rollout(
        &self,
        config: &Config,
        parent_thread_id: ThreadId,
        enable_codex_api_key_env: bool,
    ) -> Option<Arc<AuthManager>> {
        let rollout_path = match find_thread_path_by_id_str(
            config.codex_home.as_path(),
            &parent_thread_id.to_string(),
        )
        .await
        .ok()?
        {
            Some(rollout_path) => rollout_path,
            None => find_archived_thread_path_by_id_str(
                config.codex_home.as_path(),
                &parent_thread_id.to_string(),
            )
            .await
            .ok()??,
        };
        let session_meta = crate::rollout::list::read_session_meta_line(&rollout_path)
            .await
            .ok()?;
        let auth_file = replayed_parent_auth_file(&session_meta.meta)?;
        AuthManager::shared_with_auth_file(
            config.codex_home.clone(),
            enable_codex_api_key_env,
            config.cli_auth_credentials_store_mode,
            Some(auth_file),
        )
        .ok()
    }

    async fn inherited_exec_policy_for_source(
        &self,
        state: &Arc<ThreadManagerState>,
        session_source: Option<&SessionSource>,
        child_config: &crate::config::Config,
    ) -> Option<Arc<crate::exec_policy::ExecPolicyManager>> {
        let Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id, ..
        })) = session_source
        else {
            return None;
        };

        let parent_thread = state.get_thread(*parent_thread_id).await.ok()?;
        let parent_config = parent_thread.codex.session.get_config().await;
        if !crate::exec_policy::child_uses_parent_exec_policy(&parent_config, child_config) {
            return None;
        }

        Some(Arc::clone(
            &parent_thread.codex.session.services.exec_policy,
        ))
    }

    async fn open_thread_spawn_children(
        &self,
        parent_thread_id: ThreadId,
    ) -> CodexResult<Vec<(ThreadId, Option<String>)>> {
        let mut children_by_parent = self.live_thread_spawn_children().await?;
        Ok(children_by_parent
            .remove(&parent_thread_id)
            .unwrap_or_default())
    }

    async fn live_thread_spawn_children(
        &self,
    ) -> CodexResult<HashMap<ThreadId, Vec<(ThreadId, Option<String>)>>> {
        let state = self.upgrade()?;
        let mut children_by_parent = HashMap::<ThreadId, Vec<(ThreadId, Option<String>)>>::new();

        for thread_id in state.list_thread_ids().await {
            let Ok(thread) = state.get_thread(thread_id).await else {
                continue;
            };
            let snapshot = thread.config_snapshot().await;
            let Some(parent_thread_id) = thread_spawn_parent_thread_id(&snapshot.session_source)
            else {
                continue;
            };
            children_by_parent
                .entry(parent_thread_id)
                .or_default()
                .push((thread_id, snapshot.session_source.get_nickname()));
        }

        for children in children_by_parent.values_mut() {
            children.sort_by_key(|left| left.0.to_string());
        }

        Ok(children_by_parent)
    }

    async fn persist_thread_spawn_edge_for_source(
        &self,
        thread: &crate::CodexThread,
        child_thread_id: ThreadId,
        session_source: Option<&SessionSource>,
    ) {
        let Some(parent_thread_id) = session_source.and_then(thread_spawn_parent_thread_id) else {
            return;
        };
        let Some(state_db_ctx) = thread.state_db() else {
            return;
        };
        if let Err(err) = state_db_ctx
            .upsert_thread_spawn_edge(
                parent_thread_id,
                child_thread_id,
                DirectionalThreadSpawnEdgeStatus::Open,
            )
            .await
        {
            warn!("failed to persist thread-spawn edge: {err}");
        }
    }

    async fn live_thread_spawn_descendants(
        &self,
        root_thread_id: ThreadId,
    ) -> CodexResult<Vec<ThreadId>> {
        let mut children_by_parent = self.live_thread_spawn_children().await?;
        let mut descendants = Vec::new();
        let mut stack = children_by_parent
            .remove(&root_thread_id)
            .unwrap_or_default()
            .into_iter()
            .map(|(child_thread_id, _)| child_thread_id)
            .rev()
            .collect::<Vec<_>>();

        while let Some(thread_id) = stack.pop() {
            descendants.push(thread_id);
            if let Some(children) = children_by_parent.remove(&thread_id) {
                for (child_thread_id, _) in children.into_iter().rev() {
                    stack.push(child_thread_id);
                }
            }
        }

        Ok(descendants)
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
