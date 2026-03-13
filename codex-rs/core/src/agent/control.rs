use super::agent_delivery::completed_message_for_agent_fallback;
use super::agent_delivery::log_deferred_agent_enqueue_error;
use super::agent_delivery::log_post_turn_agent_enqueue_error;
use super::agent_delivery::should_defer_agent_delivery;
use super::agent_delivery::should_queue_agent_delivery_until_turn_end;
use super::inbox_delivery::build_agent_inbox_items;
use super::watchdog::RemovedWatchdog;
use super::watchdog::WatchdogManager;
use super::watchdog::WatchdogRegistration;
use crate::AuthManager;
use crate::agent::AgentStatus;
use crate::agent::guards::Guards;
use crate::agent::guards::SpawnReservation;
use crate::agent::role::DEFAULT_ROLE_NAME;
use crate::agent::role::resolve_role_config;
use crate::agent::status::is_final;
use crate::config::Config;
#[cfg(test)]
use crate::config::types::CollabInboxDeliveryRole;
use crate::error::CodexErr;
use crate::error::Result as CodexResult;
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
use codex_protocol::protocol::ForkReferenceItem;
use codex_protocol::protocol::InitialHistory;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::RolloutItem;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::protocol::TokenUsage;
use codex_protocol::user_input::UserInput;
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
        }
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
                    let mut forked_rollout_items =
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
                            false,
                            inherited_shell_snapshot,
                        )
                        .await?
                } else {
                    state
                        .spawn_new_thread_with_source(
                            config,
                            auth_manager,
                            self.clone(),
                            session_source,
                            false,
                            None,
                            inherited_shell_snapshot,
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
        let inherited_shell_snapshot = self
            .inherited_shell_snapshot_for_source(&state, session_source.as_ref())
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
                    )
                    .await?
            }
            None => state.spawn_new_thread(config, self.clone()).await?,
        };
        reservation.commit(new_thread.thread_id);

        // Notify a new thread has been created. This notification will be processed by clients
        // to subscribe or drain this newly created thread.
        state.notify_thread_created(new_thread.thread_id);

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
            )
            .await?;
        reservation.commit(new_thread.thread_id);
        state.notify_thread_created(new_thread.thread_id);
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
        let notification_source = Some(session_source.clone());
        let inherited_shell_snapshot = self
            .inherited_shell_snapshot_for_source(&state, Some(&session_source))
            .await;
        let auth_manager = self
            .auth_manager_for_source(&config, &state, Some(&session_source))
            .await;
        let rollout_path =
            find_thread_path_by_id_str(config.codex_home.as_path(), &thread_id.to_string())
                .await?
                .ok_or(CodexErr::ThreadNotFound(thread_id))?;

        let resumed_thread = state
            .resume_thread_from_rollout_with_source(
                config,
                rollout_path,
                auth_manager,
                self.clone(),
                session_source,
                inherited_shell_snapshot,
            )
            .await?;
        reservation.commit(resumed_thread.thread_id);
        // Resumed threads are re-registered in-memory and need the same listener
        // attachment path as freshly spawned threads.
        state.notify_thread_created(resumed_thread.thread_id);
        self.maybe_start_completion_watcher(resumed_thread.thread_id, notification_source);

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
        record_sender_message_for_completion_dedupe: bool,
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
                    if record_sender_message_for_completion_dedupe {
                        self.record_forwarded_agent_message(sender_thread_id, &message)
                            .await;
                    }
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
                    if record_sender_message_for_completion_dedupe {
                        self.record_forwarded_agent_message(sender_thread_id, &message)
                            .await;
                    }
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
                                if record_sender_message_for_completion_dedupe {
                                    self.record_forwarded_agent_message(sender_thread_id, &message)
                                        .await;
                                }
                                return Ok(Uuid::now_v7().to_string());
                            }
                            Err(err) => {
                                log_deferred_agent_enqueue_error(agent_id, sender_thread_id, err)
                            }
                        }
                    } else {
                        match thread
                            .codex
                            .session
                            .enqueue_post_turn_agent_items(late_items)
                            .await
                        {
                            Ok(()) => {
                                if record_sender_message_for_completion_dedupe {
                                    self.record_forwarded_agent_message(sender_thread_id, &message)
                                        .await;
                                }
                                if thread
                                    .codex
                                    .session
                                    .arm_post_turn_agent_flush_if_items()
                                    .await
                                {
                                    if thread.has_active_turn().await {
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
                                        return Ok(Uuid::now_v7().to_string());
                                    }
                                } else {
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
                    if record_sender_message_for_completion_dedupe {
                        self.record_forwarded_agent_message(sender_thread_id, &message)
                            .await;
                    }
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
        if record_sender_message_for_completion_dedupe {
            self.record_forwarded_agent_message(sender_thread_id, &message)
                .await;
        }
        Ok(submission_id)
    }

    /// Interrupt the current task for an existing agent thread.
    pub(crate) async fn interrupt_agent(&self, agent_id: ThreadId) -> CodexResult<String> {
        let state = self.upgrade()?;
        state.send_op(agent_id, Op::Interrupt).await
    }

    /// Submit a shutdown request to an existing agent thread.
    pub(crate) async fn shutdown_agent(&self, agent_id: ThreadId) -> CodexResult<String> {
        let state = self.upgrade()?;
        let mut descendants = self.collect_descendants(&state, agent_id).await;
        descendants.reverse();
        for descendant_id in descendants {
            if let Some(removed_watchdog) = self.watchdogs.unregister(descendant_id).await
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
            let _ = state.send_op(descendant_id, Op::Shutdown {}).await;
            let _ = state.remove_thread(&descendant_id).await;
            self.guards.release_spawned_thread(descendant_id);
        }
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
        let result = state.send_op(agent_id, Op::Shutdown {}).await;
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
        let Ok(state) = self.upgrade() else {
            return String::new();
        };

        let mut agents = Vec::new();
        for thread_id in state.list_thread_ids().await {
            let Ok(thread) = state.get_thread(thread_id).await else {
                continue;
            };
            let snapshot = thread.config_snapshot().await;
            let SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: agent_parent_thread_id,
                agent_nickname,
                ..
            }) = snapshot.session_source
            else {
                continue;
            };
            if agent_parent_thread_id != parent_thread_id {
                continue;
            }
            agents.push(format_subagent_context_line(
                &thread_id.to_string(),
                agent_nickname.as_deref(),
            ));
        }
        agents.sort();
        agents.join("\n")
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
                let child_completed_message_already_forwarded = match &status {
                    AgentStatus::Completed(Some(message)) if !message.trim().is_empty() => {
                        if let Ok(child_thread) = state.get_thread(child_thread_id).await {
                            child_thread
                                .codex
                                .session
                                .last_completed_turn_forwarded_agent_message(message)
                                .await
                        } else {
                            false
                        }
                    }
                    _ => false,
                };
                if let Some(message) = completed_message_for_agent_fallback(
                    &status,
                    child_completed_message_already_forwarded,
                    child_is_watchdog_helper_for_parent,
                ) && let Err(err) = control
                    .send_agent_message_inner(
                        parent_thread_id,
                        child_thread_id,
                        message,
                        false,
                        #[cfg(test)]
                        None,
                    )
                    .await
                {
                    warn!(
                        child_thread_id = %child_thread_id,
                        parent_thread_id = %parent_thread_id,
                        "subagent completion fallback forward failed: {err}"
                    );
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

    async fn record_forwarded_agent_message(&self, sender_thread_id: ThreadId, message: &str) {
        if let Ok(state) = self.upgrade()
            && let Ok(sender_thread) = state.get_thread(sender_thread_id).await
        {
            sender_thread
                .codex
                .session
                .record_turn_forwarded_agent_message(message)
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
        let rollout_path =
            find_thread_path_by_id_str(config.codex_home.as_path(), &parent_thread_id.to_string())
                .await
                .ok()??;
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
mod tests {
    use super::*;
    use crate::AuthManager;
    use crate::CodexAuth;
    use crate::CodexThread;
    use crate::ThreadManager;
    use crate::agent::agent_status_from_event;
    use crate::auth::AuthCredentialsStoreMode;
    use crate::config::AgentRoleConfig;
    use crate::config::Config;
    use crate::config::ConfigBuilder;
    use crate::contextual_user_message::SUBAGENT_NOTIFICATION_OPEN_TAG;
    use crate::tasks::CompactTask;
    use crate::tasks::SessionTask;
    use crate::tasks::SessionTaskContext;

    use assert_matches::assert_matches;
    use codex_protocol::config_types::ModeKind;
    use codex_protocol::models::ResponseItem;
    use codex_protocol::protocol::ErrorEvent;
    use codex_protocol::protocol::EventMsg;
    use codex_protocol::protocol::RawResponseItemEvent;
    use codex_protocol::protocol::TurnAbortReason;
    use codex_protocol::protocol::TurnAbortedEvent;
    use codex_protocol::protocol::TurnCompleteEvent;
    use codex_protocol::protocol::TurnStartedEvent;
    use pretty_assertions::assert_eq;
    use serial_test::serial;
    use std::env;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::time::timeout;
    use toml::Value as TomlValue;

    #[derive(Clone, Copy)]
    struct WaitForCancellationTask;

    #[async_trait::async_trait]
    impl SessionTask for WaitForCancellationTask {
        fn kind(&self) -> crate::state::TaskKind {
            crate::state::TaskKind::Regular
        }

        fn span_name(&self) -> &'static str {
            "session_task.wait_for_cancellation"
        }

        async fn run(
            self: Arc<Self>,
            _session: Arc<SessionTaskContext>,
            _ctx: Arc<crate::codex::TurnContext>,
            _input: Vec<UserInput>,
            cancellation_token: tokio_util::sync::CancellationToken,
        ) -> Option<String> {
            cancellation_token.cancelled().await;
            None
        }
    }

    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = env::var(key).ok();
            unsafe { env::set_var(key, value) };
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(original) = self.original.take() {
                unsafe { env::set_var(self.key, original) };
            } else {
                unsafe { env::remove_var(self.key) };
            }
        }
    }

    async fn test_config_with_cli_overrides(
        cli_overrides: Vec<(String, TomlValue)>,
    ) -> (TempDir, Config) {
        let home = TempDir::new().expect("create temp dir");
        let config = ConfigBuilder::default()
            .codex_home(home.path().to_path_buf())
            .cli_overrides(cli_overrides)
            .build()
            .await
            .expect("load default test config");
        (home, config)
    }

    async fn test_config() -> (TempDir, Config) {
        test_config_with_cli_overrides(Vec::new()).await
    }

    fn text_input(text: &str) -> Vec<UserInput> {
        vec![UserInput::Text {
            text: text.to_string(),
            text_elements: Vec::new(),
        }]
    }

    fn thread_spawn_source(parent_thread_id: ThreadId) -> SessionSource {
        SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth: 1,
            agent_nickname: None,
            agent_role: None,
        })
    }

    fn history_contains_text(history_items: &[ResponseItem], needle: &str) -> bool {
        history_items.iter().any(|item| match item {
            ResponseItem::Message { content, .. } => {
                content.iter().any(|content_item| match content_item {
                    ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                        text.contains(needle)
                    }
                    ContentItem::InputImage { .. } => false,
                })
            }
            ResponseItem::FunctionCallOutput { output, .. } => output
                .text_content()
                .is_some_and(|text| text.contains(needle)),
            _ => false,
        })
    }

    fn count_history_text(history_items: &[ResponseItem], needle: &str) -> usize {
        history_items
            .iter()
            .filter(|item| match item {
                ResponseItem::Message { content, .. } => {
                    content.iter().any(|content_item| match content_item {
                        ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                            text.contains(needle)
                        }
                        ContentItem::InputImage { .. } => false,
                    })
                }
                ResponseItem::FunctionCallOutput { output, .. } => output
                    .text_content()
                    .is_some_and(|text| text.contains(needle)),
                _ => false,
            })
            .count()
    }

    fn has_subagent_notification(history_items: &[ResponseItem]) -> bool {
        history_items.iter().any(|item| {
            let ResponseItem::Message { role, content, .. } = item else {
                return false;
            };
            if role != "user" {
                return false;
            }
            content.iter().any(|content_item| match content_item {
                ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                    text.contains(SUBAGENT_NOTIFICATION_OPEN_TAG)
                }
                ContentItem::InputImage { .. } => false,
            })
        })
    }

    async fn wait_for_subagent_notification(parent_thread: &Arc<CodexThread>) -> bool {
        let wait = async {
            loop {
                let history_items = parent_thread
                    .codex
                    .session
                    .clone_history()
                    .await
                    .raw_items()
                    .to_vec();
                if has_subagent_notification(&history_items) {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), wait)
            .await
            .is_ok()
    }

    async fn wait_for_history_text(parent_thread: &Arc<CodexThread>, needle: &str) -> bool {
        let wait = async {
            loop {
                let history_items = parent_thread
                    .codex
                    .session
                    .clone_history()
                    .await
                    .raw_items()
                    .to_vec();
                if history_contains_text(&history_items, needle) {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), wait)
            .await
            .is_ok()
    }

    async fn wait_for_raw_response_text(thread: &Arc<CodexThread>, needle: &str) -> bool {
        let wait = async {
            loop {
                let event = thread
                    .next_event()
                    .await
                    .expect("event should be available");
                if let EventMsg::RawResponseItem(RawResponseItemEvent { item }) = event.msg
                    && history_contains_text(&[item], needle)
                {
                    return true;
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), wait)
            .await
            .is_ok()
    }

    fn auth_manager_with_auth_file(
        config: &Config,
        root: &TempDir,
        label: &str,
    ) -> Arc<AuthManager> {
        AuthManager::shared_with_auth_file(
            config.codex_home.clone(),
            false,
            AuthCredentialsStoreMode::File,
            Some(root.path().join(label).join("auth.json")),
        )
        .expect("auth manager with override auth file")
    }

    struct AgentControlHarness {
        _home: TempDir,
        config: Config,
        manager: ThreadManager,
        control: AgentControl,
    }

    impl AgentControlHarness {
        async fn new() -> Self {
            let (home, config) = test_config().await;
            let manager = ThreadManager::with_models_provider_and_home_for_tests(
                CodexAuth::from_api_key("dummy"),
                config.model_provider.clone(),
                config.codex_home.clone(),
            );
            let control = manager.agent_control();
            Self {
                _home: home,
                config,
                manager,
                control,
            }
        }

        async fn start_thread(&self) -> (ThreadId, Arc<CodexThread>) {
            let new_thread = self
                .manager
                .start_thread(self.config.clone())
                .await
                .expect("start thread");
            (new_thread.thread_id, new_thread.thread)
        }

        async fn start_thread_with_auth_manager(
            &self,
            auth_manager: Arc<AuthManager>,
        ) -> (ThreadId, Arc<CodexThread>) {
            let new_thread = self
                .manager
                .resume_thread_with_history(
                    self.config.clone(),
                    InitialHistory::New,
                    auth_manager,
                    false,
                )
                .await
                .expect("start thread");
            (new_thread.thread_id, new_thread.thread)
        }

        async fn arm_post_interrupt_hold(&self, thread: &Arc<CodexThread>) {
            {
                let mut active = thread.codex.session.active_turn.lock().await;
                *active = Some(crate::state::ActiveTurn::default());
            }
            thread.codex.session.interrupt_task().await;
        }
    }

    #[tokio::test]
    async fn send_input_errors_when_manager_dropped() {
        let control = AgentControl::default();
        let err = control
            .send_input(
                ThreadId::new(),
                vec![UserInput::Text {
                    text: "hello".to_string(),
                    text_elements: Vec::new(),
                }],
            )
            .await
            .expect_err("send_input should fail without a manager");
        assert_eq!(
            err.to_string(),
            "unsupported operation: thread manager dropped"
        );
    }

    #[tokio::test]
    async fn drop_pending_input_clears_buffered_items() {
        let harness = AgentControlHarness::new().await;
        let (agent_id, thread) = harness.start_thread().await;

        {
            let mut active = thread.codex.session.active_turn.lock().await;
            *active = Some(crate::state::ActiveTurn::default());
        }

        thread
            .codex
            .session
            .inject_response_items(vec![ResponseInputItem::Message {
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "queued".to_string(),
                }],
            }])
            .await
            .expect("inject pending input");

        let dropped = harness
            .control
            .drop_pending_input(agent_id)
            .await
            .expect("drop pending input should succeed");
        assert_eq!(dropped, true);
        assert_eq!(thread.codex.session.has_pending_input().await, false);

        let _ = harness.control.shutdown_agent(agent_id).await;
    }

    #[tokio::test]
    async fn get_status_returns_not_found_without_manager() {
        let control = AgentControl::default();
        let got = control.get_status(ThreadId::new()).await;
        assert_eq!(got, AgentStatus::NotFound);
    }

    #[tokio::test]
    async fn on_event_updates_status_from_task_started() {
        let status = agent_status_from_event(&EventMsg::TurnStarted(TurnStartedEvent {
            turn_id: "turn-1".to_string(),
            model_context_window: None,
            collaboration_mode_kind: ModeKind::Default,
        }));
        assert_eq!(status, Some(AgentStatus::Running));
    }

    #[tokio::test]
    async fn on_event_updates_status_from_task_complete() {
        let status = agent_status_from_event(&EventMsg::TurnComplete(TurnCompleteEvent {
            turn_id: "turn-1".to_string(),
            last_agent_message: Some("done".to_string()),
        }));
        let expected = AgentStatus::Completed(Some("done".to_string()));
        assert_eq!(status, Some(expected));
    }

    #[tokio::test]
    async fn on_event_updates_status_from_error() {
        let status = agent_status_from_event(&EventMsg::Error(ErrorEvent {
            message: "boom".to_string(),
            codex_error_info: None,
        }));

        let expected = AgentStatus::Errored("boom".to_string());
        assert_eq!(status, Some(expected));
    }

    #[tokio::test]
    async fn on_event_updates_status_from_turn_aborted() {
        let status = agent_status_from_event(&EventMsg::TurnAborted(TurnAbortedEvent {
            turn_id: Some("turn-1".to_string()),
            reason: TurnAbortReason::Interrupted,
        }));

        let expected = AgentStatus::Interrupted;
        assert_eq!(status, Some(expected));
    }

    #[tokio::test]
    async fn interrupted_status_is_not_final() {
        assert_eq!(is_final(&AgentStatus::Interrupted), false);
    }

    #[tokio::test]
    async fn on_event_updates_status_from_shutdown_complete() {
        let status = agent_status_from_event(&EventMsg::ShutdownComplete);
        assert_eq!(status, Some(AgentStatus::Shutdown));
    }

    #[tokio::test]
    async fn spawn_agent_errors_when_manager_dropped() {
        let control = AgentControl::default();
        let (_home, config) = test_config().await;
        let err = control
            .spawn_agent(config, text_input("hello"), None)
            .await
            .expect_err("spawn_agent should fail without a manager");
        assert_eq!(
            err.to_string(),
            "unsupported operation: thread manager dropped"
        );
    }

    #[tokio::test]
    async fn resume_agent_errors_when_manager_dropped() {
        let control = AgentControl::default();
        let (_home, config) = test_config().await;
        let err = control
            .resume_agent_from_rollout(config, ThreadId::new(), SessionSource::Exec)
            .await
            .expect_err("resume_agent should fail without a manager");
        assert_eq!(
            err.to_string(),
            "unsupported operation: thread manager dropped"
        );
    }

    #[tokio::test]
    async fn send_input_errors_when_thread_missing() {
        let harness = AgentControlHarness::new().await;
        let thread_id = ThreadId::new();
        let err = harness
            .control
            .send_input(
                thread_id,
                vec![UserInput::Text {
                    text: "hello".to_string(),
                    text_elements: Vec::new(),
                }],
            )
            .await
            .expect_err("send_input should fail for missing thread");
        assert_matches!(err, CodexErr::ThreadNotFound(id) if id == thread_id);
    }

    #[tokio::test]
    async fn get_status_returns_not_found_for_missing_thread() {
        let harness = AgentControlHarness::new().await;
        let status = harness.control.get_status(ThreadId::new()).await;
        assert_eq!(status, AgentStatus::NotFound);
    }

    #[tokio::test]
    async fn get_status_returns_pending_init_for_new_thread() {
        let harness = AgentControlHarness::new().await;
        let (thread_id, _) = harness.start_thread().await;
        let status = harness.control.get_status(thread_id).await;
        assert_eq!(status, AgentStatus::PendingInit);
    }

    #[tokio::test]
    async fn subscribe_status_errors_for_missing_thread() {
        let harness = AgentControlHarness::new().await;
        let thread_id = ThreadId::new();
        let err = harness
            .control
            .subscribe_status(thread_id)
            .await
            .expect_err("subscribe_status should fail for missing thread");
        assert_matches!(err, CodexErr::ThreadNotFound(id) if id == thread_id);
    }

    #[tokio::test]
    async fn subscribe_status_updates_on_shutdown() {
        let harness = AgentControlHarness::new().await;
        let (thread_id, thread) = harness.start_thread().await;
        let mut status_rx = harness
            .control
            .subscribe_status(thread_id)
            .await
            .expect("subscribe_status should succeed");
        assert_eq!(status_rx.borrow().clone(), AgentStatus::PendingInit);

        let _ = thread
            .submit(Op::Shutdown {})
            .await
            .expect("shutdown should submit");

        let _ = status_rx.changed().await;
        assert_eq!(status_rx.borrow().clone(), AgentStatus::Shutdown);
    }

    #[tokio::test]
    async fn send_input_submits_user_message() {
        let harness = AgentControlHarness::new().await;
        let (thread_id, _thread) = harness.start_thread().await;

        let submission_id = harness
            .control
            .send_input(
                thread_id,
                vec![UserInput::Text {
                    text: "hello from tests".to_string(),
                    text_elements: Vec::new(),
                }],
            )
            .await
            .expect("send_input should succeed");
        assert!(!submission_id.is_empty());
        let expected = (
            thread_id,
            Op::UserInput {
                items: vec![UserInput::Text {
                    text: "hello from tests".to_string(),
                    text_elements: Vec::new(),
                }],
                final_output_json_schema: None,
            },
        );
        let captured = harness
            .manager
            .captured_ops()
            .into_iter()
            .find(|entry| *entry == expected);
        assert_eq!(captured, Some(expected));
    }

    #[tokio::test]
    async fn send_agent_message_to_idle_thread_avoids_empty_user_bootstrap() {
        let harness = AgentControlHarness::new().await;
        let (receiver_thread_id, _thread) = harness.start_thread().await;
        let sender_thread_id = ThreadId::new();

        let submission_id = harness
            .control
            .send_agent_message(
                receiver_thread_id,
                sender_thread_id,
                "watchdog update".to_string(),
            )
            .await
            .expect("send_agent_message should succeed");
        assert!(!submission_id.is_empty());

        let captured = harness
            .manager
            .captured_ops()
            .into_iter()
            .find(|(thread_id, op)| {
                *thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
            })
            .expect("expected injected collab inbox op");

        let Op::InjectResponseItems { items } = captured.1 else {
            unreachable!("matched above");
        };
        assert_eq!(items.len(), 1);
        match &items[0] {
            ResponseInputItem::FunctionCallOutput { output, .. } => {
                let output_text = output
                    .body
                    .to_text()
                    .expect("payload should convert to text");
                let payload: AgentInboxPayload =
                    serde_json::from_str(&output_text).expect("payload should be valid json");
                assert_eq!(payload.sender_thread_id, sender_thread_id);
                assert_eq!(payload.message, "watchdog update");
            }
            other => panic!("expected collab function call output, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_agent_message_to_active_root_thread_injects_immediately() {
        let harness = AgentControlHarness::new().await;
        let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
        let sender_thread_id = ThreadId::new();

        let turn_context = receiver_thread
            .codex
            .session
            .new_default_turn_with_sub_id("active-root-turn".to_string())
            .await;
        receiver_thread
            .codex
            .session
            .spawn_task(
                Arc::clone(&turn_context),
                text_input("active root turn"),
                WaitForCancellationTask,
            )
            .await;
        assert!(receiver_thread.has_active_turn().await);

        let submission_id = harness
            .control
            .send_agent_message(
                receiver_thread_id,
                sender_thread_id,
                "same-turn update".to_string(),
            )
            .await
            .expect("send_agent_message should inject into the active root turn");
        assert!(!submission_id.is_empty());

        let (queued_items, queued_bytes, flush_pending) =
            receiver_thread.codex.session.post_turn_agent_stats().await;
        assert_eq!(queued_items, 0);
        assert_eq!(queued_bytes, 0);
        assert_eq!(flush_pending, false);
        let injected_items = receiver_thread.codex.session.get_pending_input().await;
        assert_eq!(injected_items.len(), 1);
        assert!(
            harness
                .manager
                .captured_ops()
                .into_iter()
                .all(|(thread_id, op)| {
                    thread_id != receiver_thread_id || !matches!(op, Op::InjectResponseItems { .. })
                })
        );

        receiver_thread
            .codex
            .session
            .abort_all_tasks(TurnAbortReason::Interrupted)
            .await;
        assert_eq!(
            receiver_thread
                .codex
                .session
                .post_turn_agent_stats()
                .await
                .0,
            0
        );
        let _ = harness.control.shutdown_agent(receiver_thread_id).await;
    }

    #[tokio::test]
    async fn send_agent_message_late_active_turn_miss_queues_post_turn_flush() {
        let harness = AgentControlHarness::new().await;
        let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
        let sender_thread_id = ThreadId::new();

        let turn_context = receiver_thread
            .codex
            .session
            .new_default_turn_with_sub_id("late-active-root-turn".to_string())
            .await;
        receiver_thread
            .codex
            .session
            .spawn_task(
                Arc::clone(&turn_context),
                text_input("active root turn"),
                WaitForCancellationTask,
            )
            .await;
        assert!(receiver_thread.has_active_turn().await);

        let receiver_session = Arc::clone(&receiver_thread.codex.session);
        let submission_id = harness
            .control
            .send_agent_message_inner(
                receiver_thread_id,
                sender_thread_id,
                "late same-turn update".to_string(),
                true,
                Some(Box::pin(async move {
                    receiver_session
                        .abort_all_tasks(TurnAbortReason::Replaced)
                        .await;
                })),
            )
            .await
            .expect("send_agent_message should recover a late active-turn miss");
        assert!(!submission_id.is_empty());

        let inject_ops: Vec<Op> = harness
            .manager
            .captured_ops()
            .into_iter()
            .filter_map(|(thread_id, op)| (thread_id == receiver_thread_id).then_some(op))
            .filter(|op| matches!(op, Op::InjectResponseItems { .. }))
            .collect();
        assert_eq!(inject_ops.len(), 1);
        match &inject_ops[0] {
            Op::InjectResponseItems { items } => {
                assert!(items.is_empty(), "late miss should arm an empty flush op");
            }
            other => panic!("expected inject response items op, got {other:?}"),
        }

        receiver_thread
            .codex
            .session
            .clear_post_turn_agent_items()
            .await;
        let _ = harness.control.shutdown_agent(receiver_thread_id).await;
    }

    #[tokio::test]
    async fn send_agent_message_after_sampling_completed_queues_post_turn_flush() {
        let harness = AgentControlHarness::new().await;
        let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
        let sender_thread_id = ThreadId::new();

        let turn_context = receiver_thread
            .codex
            .session
            .new_default_turn_with_sub_id("sampling-completed-turn".to_string())
            .await;
        receiver_thread
            .codex
            .session
            .spawn_task(
                Arc::clone(&turn_context),
                text_input("active root turn"),
                WaitForCancellationTask,
            )
            .await;
        assert!(receiver_thread.has_active_turn().await);

        let receiver_session = Arc::clone(&receiver_thread.codex.session);
        let submission_id = harness
            .control
            .send_agent_message_inner(
                receiver_thread_id,
                sender_thread_id,
                "late completed update".to_string(),
                true,
                Some(Box::pin(async move {
                    receiver_session.mark_active_turn_sampling_completed().await;
                })),
            )
            .await
            .expect("send_agent_message should queue after sampling completed");
        assert!(!submission_id.is_empty());

        let (queued_items, queued_bytes, flush_pending) =
            receiver_thread.codex.session.post_turn_agent_stats().await;
        assert_eq!(queued_items, 1);
        assert!(queued_bytes > 0);
        assert!(flush_pending);
        assert!(
            receiver_thread
                .codex
                .session
                .get_pending_input()
                .await
                .is_empty()
        );

        let inject_ops: Vec<Op> = harness
            .manager
            .captured_ops()
            .into_iter()
            .filter_map(|(thread_id, op)| (thread_id == receiver_thread_id).then_some(op))
            .filter(|op| matches!(op, Op::InjectResponseItems { .. }))
            .collect();
        assert!(inject_ops.is_empty());

        receiver_thread
            .codex
            .session
            .clear_post_turn_agent_items()
            .await;
        let _ = harness.control.shutdown_agent(receiver_thread_id).await;
    }

    #[tokio::test]
    async fn send_agent_message_late_interrupt_miss_preserves_post_interrupt_hold() {
        let harness = AgentControlHarness::new().await;
        let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
        let sender_thread_id = ThreadId::new();

        let turn_context = receiver_thread
            .codex
            .session
            .new_default_turn_with_sub_id("late-interrupt-turn".to_string())
            .await;
        receiver_thread
            .codex
            .session
            .spawn_task(
                Arc::clone(&turn_context),
                text_input("active root turn"),
                WaitForCancellationTask,
            )
            .await;
        assert!(receiver_thread.has_active_turn().await);

        let receiver_session = Arc::clone(&receiver_thread.codex.session);
        let submission_id = harness
            .control
            .send_agent_message_inner(
                receiver_thread_id,
                sender_thread_id,
                "late interrupt update".to_string(),
                true,
                Some(Box::pin(async move {
                    receiver_session.interrupt_task().await;
                })),
            )
            .await
            .expect("send_agent_message should defer after late interrupt miss");
        assert!(!submission_id.is_empty());

        let (deferred_items, deferred_bytes) =
            receiver_thread.codex.session.deferred_collab_stats().await;
        assert_eq!(deferred_items, 1);
        assert!(deferred_bytes > 0);
        let (queued_items, queued_bytes, flush_pending) =
            receiver_thread.codex.session.post_turn_agent_stats().await;
        assert_eq!((queued_items, queued_bytes, flush_pending), (0, 0, false));
        assert!(
            receiver_thread
                .codex
                .session
                .post_interrupt_collab_hold_armed()
                .await
        );
        let injected = harness
            .manager
            .captured_ops()
            .into_iter()
            .any(|(thread_id, op)| {
                thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
            });
        assert!(!injected);

        let _ = receiver_thread
            .codex
            .session
            .take_deferred_collab_items()
            .await;
        let _ = harness.control.shutdown_agent(receiver_thread_id).await;
    }

    #[tokio::test]
    async fn send_agent_message_keeps_turn_boundary_replies_in_same_post_turn_queue() {
        let harness = AgentControlHarness::new().await;
        let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
        let first_sender = ThreadId::new();
        let second_sender = ThreadId::new();
        let queued_items = build_agent_inbox_items(
            CollabInboxDeliveryRole::Tool,
            first_sender,
            None,
            None,
            "queued before boundary".to_string(),
            false,
        )
        .expect("build queued items");
        receiver_thread
            .codex
            .session
            .enqueue_post_turn_agent_items(queued_items)
            .await
            .expect("seed boundary queue");
        assert!(
            receiver_thread
                .codex
                .session
                .arm_post_turn_agent_flush_if_items()
                .await
        );

        harness
            .control
            .send_agent_message(
                receiver_thread_id,
                second_sender,
                "queued during boundary flush".to_string(),
            )
            .await
            .expect("second send should join the same queue");

        let (queued_items, queued_bytes, flush_pending) =
            receiver_thread.codex.session.post_turn_agent_stats().await;
        assert_eq!(queued_items, 2);
        assert!(queued_bytes > 0);
        assert_eq!(flush_pending, true);

        let injected = harness
            .manager
            .captured_ops()
            .into_iter()
            .any(|(thread_id, op)| {
                thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
            });
        assert_eq!(injected, false);

        receiver_thread
            .codex
            .session
            .clear_post_turn_agent_items()
            .await;
        let _ = harness.control.shutdown_agent(receiver_thread_id).await;
    }

    #[tokio::test]
    async fn send_agent_message_defers_when_post_interrupt_hold_is_armed() {
        let harness = AgentControlHarness::new().await;
        let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
        harness.arm_post_interrupt_hold(&receiver_thread).await;

        let submission_id = harness
            .control
            .send_agent_message(
                receiver_thread_id,
                ThreadId::new(),
                "deferred update".to_string(),
            )
            .await
            .expect("send_agent_message should defer while hold is armed");
        assert!(!submission_id.is_empty());

        let (deferred_items, deferred_bytes) =
            receiver_thread.codex.session.deferred_collab_stats().await;
        assert_eq!(deferred_items, 1);
        assert!(deferred_bytes > 0);

        let injected = harness
            .manager
            .captured_ops()
            .into_iter()
            .any(|(thread_id, op)| {
                thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
            });
        assert_eq!(injected, false);

        let _ = harness.control.shutdown_agent(receiver_thread_id).await;
    }

    #[tokio::test]
    async fn send_agent_message_watchdog_helper_bypasses_deferral() {
        let harness = AgentControlHarness::new().await;
        let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
        harness.arm_post_interrupt_hold(&receiver_thread).await;

        let watchdog_handle_id = harness
            .control
            .spawn_agent_handle(
                harness.config.clone(),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: receiver_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
            )
            .await
            .expect("spawn watchdog handle");
        harness
            .control
            .register_watchdog(WatchdogRegistration {
                owner_thread_id: receiver_thread_id,
                target_thread_id: watchdog_handle_id,
                child_depth: 1,
                interval_s: 30,
                prompt: "watchdog".to_string(),
                config: harness.config.clone(),
            })
            .await
            .expect("register watchdog");

        let helper_id = harness
            .control
            .spawn_agent_handle(
                harness.config.clone(),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: receiver_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
            )
            .await
            .expect("spawn helper");
        harness
            .control
            .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_id)
            .await;

        let submission_id = harness
            .control
            .send_agent_message(receiver_thread_id, helper_id, "watchdog bypass".to_string())
            .await
            .expect("watchdog helper should bypass deferred collab queue");
        assert!(!submission_id.is_empty());

        let (deferred_items, _deferred_bytes) =
            receiver_thread.codex.session.deferred_collab_stats().await;
        assert_eq!(deferred_items, 0);

        let injected = harness
            .manager
            .captured_ops()
            .into_iter()
            .any(|(thread_id, op)| {
                thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
            });
        assert_eq!(injected, true);

        let _ = harness.control.shutdown_agent(watchdog_handle_id).await;
        let _ = harness.control.shutdown_agent(receiver_thread_id).await;
    }

    #[tokio::test]
    async fn root_watchdog_helper_shutdown_without_send_input_wakes_owner() {
        let harness = AgentControlHarness::new().await;
        let (owner_thread_id, owner_thread) = harness.start_thread().await;
        let watchdog_handle_id = harness
            .control
            .spawn_agent_handle(
                harness.config.clone(),
                Some(thread_spawn_source(owner_thread_id)),
            )
            .await
            .expect("watchdog handle should spawn");
        let helper_thread_id = harness
            .control
            .spawn_agent(
                harness.config.clone(),
                text_input("check in"),
                Some(thread_spawn_source(owner_thread_id)),
            )
            .await
            .expect("watchdog helper should spawn");
        let removed = harness
            .control
            .register_watchdog(WatchdogRegistration {
                owner_thread_id,
                target_thread_id: watchdog_handle_id,
                child_depth: 1,
                interval_s: 1,
                prompt: "check in".to_string(),
                config: harness.config.clone(),
            })
            .await
            .expect("watchdog registration should succeed");
        assert_eq!(removed, Vec::<RemovedWatchdog>::new());
        harness
            .control
            .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
            .await;

        let _ = harness
            .control
            .shutdown_agent(helper_thread_id)
            .await
            .expect("helper shutdown should submit");
        timeout(Duration::from_secs(10), async {
            loop {
                if matches!(
                    harness.control.get_status(helper_thread_id).await,
                    AgentStatus::Shutdown | AgentStatus::NotFound
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("helper should reach shutdown");
        assert_eq!(
            wait_for_history_text(&owner_thread, "before calling send_input").await,
            true
        );
        harness
            .control
            .force_watchdog_due_for_tests(watchdog_handle_id)
            .await;
        harness.control.run_watchdogs_once_for_tests().await;
        tokio::task::yield_now().await;
        let owner_history = owner_thread
            .codex
            .session
            .clone_history()
            .await
            .raw_items()
            .to_vec();
        assert_eq!(
            count_history_text(&owner_history, "before calling send_input"),
            1
        );
    }

    #[tokio::test]
    async fn root_watchdog_helper_shutdown_without_send_input_survives_handle_shutdown() {
        let harness = AgentControlHarness::new().await;
        let (owner_thread_id, owner_thread) = harness.start_thread().await;
        let watchdog_handle_id = harness
            .control
            .spawn_agent_handle(
                harness.config.clone(),
                Some(thread_spawn_source(owner_thread_id)),
            )
            .await
            .expect("watchdog handle should spawn");
        let helper_thread_id = harness
            .control
            .spawn_agent(
                harness.config.clone(),
                text_input("check in"),
                Some(thread_spawn_source(owner_thread_id)),
            )
            .await
            .expect("watchdog helper should spawn");
        let removed = harness
            .control
            .register_watchdog(WatchdogRegistration {
                owner_thread_id,
                target_thread_id: watchdog_handle_id,
                child_depth: 1,
                interval_s: 1,
                prompt: "check in".to_string(),
                config: harness.config.clone(),
            })
            .await
            .expect("watchdog registration should succeed");
        assert_eq!(removed, Vec::<RemovedWatchdog>::new());
        harness
            .control
            .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
            .await;

        let _ = harness
            .control
            .shutdown_agent(helper_thread_id)
            .await
            .expect("helper shutdown should submit");
        timeout(Duration::from_secs(10), async {
            loop {
                if matches!(
                    harness.control.get_status(helper_thread_id).await,
                    AgentStatus::Shutdown | AgentStatus::NotFound
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("helper should reach shutdown");
        tokio::task::yield_now().await;

        let _ = harness
            .control
            .shutdown_agent(watchdog_handle_id)
            .await
            .expect("watchdog handle shutdown should submit");

        assert_eq!(
            wait_for_history_text(&owner_thread, "before calling send_input").await,
            true
        );
    }

    #[tokio::test]
    async fn send_agent_message_overflow_fails_open_with_immediate_inject() {
        const DEFERRED_COLLAB_ITEMS_MAX: usize = 8192;

        let harness = AgentControlHarness::new().await;
        let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
        harness.arm_post_interrupt_hold(&receiver_thread).await;
        let sender_thread_id = ThreadId::new();

        let seeded_items = (0..DEFERRED_COLLAB_ITEMS_MAX)
            .map(|idx| ResponseInputItem::Message {
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: format!("seed-{idx}"),
                }],
            })
            .collect::<Vec<_>>();
        receiver_thread
            .codex
            .session
            .enqueue_deferred_collab_items(seeded_items)
            .await
            .expect("seed deferred collab items");
        let (queued_before, _queued_before_bytes) =
            receiver_thread.codex.session.deferred_collab_stats().await;
        assert_eq!(queued_before, DEFERRED_COLLAB_ITEMS_MAX);

        let overflow_submission_id = harness
            .control
            .send_agent_message(receiver_thread_id, sender_thread_id, "overflow".to_string())
            .await
            .expect("overflow should fail open and inject");
        assert!(!overflow_submission_id.is_empty());

        let (queued_after, _queued_after_bytes) =
            receiver_thread.codex.session.deferred_collab_stats().await;
        assert_eq!(queued_after, DEFERRED_COLLAB_ITEMS_MAX);

        let injected_ops = harness
            .manager
            .captured_ops()
            .into_iter()
            .filter(|(thread_id, op)| {
                *thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
            })
            .collect::<Vec<_>>();
        assert_eq!(injected_ops.len(), 1);

        let Op::InjectResponseItems { items } = &injected_ops[0].1 else {
            unreachable!("filtered to inject ops");
        };
        assert_eq!(items.len(), 1);
        assert_matches!(&items[0], ResponseInputItem::FunctionCallOutput { .. });

        let _ = harness.control.shutdown_agent(receiver_thread_id).await;
    }

    #[tokio::test]
    async fn spawn_agent_creates_thread_and_sends_prompt() {
        let harness = AgentControlHarness::new().await;
        let thread_id = harness
            .control
            .spawn_agent(harness.config.clone(), text_input("spawned"), None)
            .await
            .expect("spawn_agent should succeed");
        let _thread = harness
            .manager
            .get_thread(thread_id)
            .await
            .expect("thread should be registered");
        let expected = (
            thread_id,
            Op::UserInput {
                items: vec![UserInput::Text {
                    text: "spawned".to_string(),
                    text_elements: Vec::new(),
                }],
                final_output_json_schema: None,
            },
        );
        let captured = harness
            .manager
            .captured_ops()
            .into_iter()
            .find(|entry| *entry == expected);
        assert_eq!(captured, Some(expected));
    }

    #[tokio::test]
    async fn fork_agent_falls_back_to_rollout_on_disk_when_parent_missing_in_memory() {
        let harness = AgentControlHarness::new().await;
        let (parent_thread_id, parent_thread) = harness.start_thread().await;
        parent_thread
            .inject_user_message_without_turn("parent seed context".to_string())
            .await;
        parent_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        parent_thread.codex.session.flush_rollout().await;
        let _ = harness.manager.remove_thread(&parent_thread_id).await;

        let thread_id = harness
            .control
            .fork_agent(
                harness.config.clone(),
                text_input("forked"),
                parent_thread_id,
                usize::MAX,
                SessionSource::Exec,
            )
            .await
            .expect("fork_agent should fall back to rollout on disk");
        let thread = harness
            .manager
            .get_thread(thread_id)
            .await
            .expect("thread should be registered");
        let history = thread.codex.session.clone_history().await;
        assert!(history_contains_text(
            history.raw_items(),
            "parent seed context"
        ));

        let expected = (
            thread_id,
            Op::UserInput {
                items: vec![UserInput::Text {
                    text: "forked".to_string(),
                    text_elements: Vec::new(),
                }],
                final_output_json_schema: None,
            },
        );
        let captured = harness
            .manager
            .captured_ops()
            .into_iter()
            .find(|entry| *entry == expected);
        assert_eq!(captured, Some(expected));
    }

    #[tokio::test]
    async fn fork_agent_errors_when_parent_missing_from_memory_and_rollout() {
        let harness = AgentControlHarness::new().await;
        let parent_thread_id = ThreadId::new();

        let err = harness
            .control
            .fork_agent(
                harness.config.clone(),
                text_input("forked"),
                parent_thread_id,
                0,
                SessionSource::Exec,
            )
            .await
            .expect_err("fork_agent should fail when parent rollout is unavailable");
        assert_matches!(
            err,
            CodexErr::UnsupportedOperation(message)
                if message == format!("rollout history unavailable for thread {parent_thread_id}")
        );
    }

    #[tokio::test]
    async fn spawn_agent_can_fork_parent_thread_history() {
        let harness = AgentControlHarness::new().await;
        let (parent_thread_id, parent_thread) = harness.start_thread().await;
        parent_thread
            .inject_user_message_without_turn("parent seed context".to_string())
            .await;
        let turn_context = parent_thread.codex.session.new_default_turn().await;
        let parent_spawn_call_id = "spawn-call-history".to_string();
        let parent_spawn_call = ResponseItem::FunctionCall {
            id: None,
            name: "spawn_agent".to_string(),
            namespace: None,
            arguments: "{}".to_string(),
            call_id: parent_spawn_call_id.clone(),
        };
        parent_thread
            .codex
            .session
            .record_conversation_items(turn_context.as_ref(), &[parent_spawn_call])
            .await;
        parent_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        parent_thread.codex.session.flush_rollout().await;

        let child_thread_id = harness
            .control
            .spawn_agent_with_options(
                harness.config.clone(),
                text_input("child task"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
                SpawnAgentOptions {
                    fork_parent_spawn_call_id: Some(parent_spawn_call_id),
                },
            )
            .await
            .expect("forked spawn should succeed");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        assert_ne!(child_thread_id, parent_thread_id);
        let history = child_thread.codex.session.clone_history().await;
        assert!(history_contains_text(
            history.raw_items(),
            "parent seed context"
        ));

        let expected = (
            child_thread_id,
            Op::UserInput {
                items: vec![UserInput::Text {
                    text: "child task".to_string(),
                    text_elements: Vec::new(),
                }],
                final_output_json_schema: None,
            },
        );
        let captured = harness
            .manager
            .captured_ops()
            .into_iter()
            .find(|entry| *entry == expected);
        assert_eq!(captured, Some(expected));

        let _ = harness
            .control
            .shutdown_agent(child_thread_id)
            .await
            .expect("child shutdown should submit");
        let _ = parent_thread
            .submit(Op::Shutdown {})
            .await
            .expect("parent shutdown should submit");
    }

    #[tokio::test]
    async fn spawn_agent_fork_injects_output_for_parent_spawn_call() {
        let harness = AgentControlHarness::new().await;
        let (parent_thread_id, parent_thread) = harness.start_thread().await;
        let turn_context = parent_thread.codex.session.new_default_turn().await;
        let parent_spawn_call_id = "spawn-call-1".to_string();
        let parent_spawn_call = ResponseItem::FunctionCall {
            id: None,
            name: "spawn_agent".to_string(),
            namespace: None,
            arguments: "{}".to_string(),
            call_id: parent_spawn_call_id.clone(),
        };
        parent_thread
            .codex
            .session
            .record_conversation_items(turn_context.as_ref(), &[parent_spawn_call])
            .await;
        parent_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        parent_thread.codex.session.flush_rollout().await;

        let child_thread_id = harness
            .control
            .spawn_agent_with_options(
                harness.config.clone(),
                text_input("child task"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
                SpawnAgentOptions {
                    fork_parent_spawn_call_id: Some(parent_spawn_call_id.clone()),
                },
            )
            .await
            .expect("forked spawn should succeed");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        let history = child_thread.codex.session.clone_history().await;
        let injected_output = history.raw_items().iter().find_map(|item| match item {
            ResponseItem::FunctionCallOutput { call_id, output }
                if call_id == &parent_spawn_call_id =>
            {
                Some(output)
            }
            _ => None,
        });
        let injected_output =
            injected_output.expect("forked child should contain synthetic tool output");
        assert_eq!(
            injected_output.text_content(),
            Some(FORKED_SPAWN_AGENT_OUTPUT_MESSAGE)
        );
        assert_eq!(injected_output.success, Some(true));

        let _ = harness
            .control
            .shutdown_agent(child_thread_id)
            .await
            .expect("child shutdown should submit");
        let _ = parent_thread
            .submit(Op::Shutdown {})
            .await
            .expect("parent shutdown should submit");
    }

    #[tokio::test]
    async fn spawn_agent_fork_flushes_parent_rollout_before_loading_history() {
        let harness = AgentControlHarness::new().await;
        let (parent_thread_id, parent_thread) = harness.start_thread().await;
        let turn_context = parent_thread.codex.session.new_default_turn().await;
        let parent_spawn_call_id = "spawn-call-unflushed".to_string();
        let parent_spawn_call = ResponseItem::FunctionCall {
            id: None,
            name: "spawn_agent".to_string(),
            namespace: None,
            arguments: "{}".to_string(),
            call_id: parent_spawn_call_id.clone(),
        };
        parent_thread
            .codex
            .session
            .record_conversation_items(turn_context.as_ref(), &[parent_spawn_call])
            .await;

        let child_thread_id = harness
            .control
            .spawn_agent_with_options(
                harness.config.clone(),
                text_input("child task"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
                SpawnAgentOptions {
                    fork_parent_spawn_call_id: Some(parent_spawn_call_id.clone()),
                },
            )
            .await
            .expect("forked spawn should flush parent rollout before loading history");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        let history = child_thread.codex.session.clone_history().await;

        let mut parent_call_index = None;
        let mut injected_output_index = None;
        for (idx, item) in history.raw_items().iter().enumerate() {
            match item {
                ResponseItem::FunctionCall { call_id, .. } if call_id == &parent_spawn_call_id => {
                    parent_call_index = Some(idx);
                }
                ResponseItem::FunctionCallOutput { call_id, .. }
                    if call_id == &parent_spawn_call_id =>
                {
                    injected_output_index = Some(idx);
                }
                _ => {}
            }
        }

        let parent_call_index =
            parent_call_index.expect("forked child should include the parent spawn_agent call");
        let injected_output_index = injected_output_index
            .expect("forked child should include synthetic output for the parent spawn_agent call");
        assert!(parent_call_index < injected_output_index);

        let _ = harness
            .control
            .shutdown_agent(child_thread_id)
            .await
            .expect("child shutdown should submit");
        let _ = parent_thread
            .submit(Op::Shutdown {})
            .await
            .expect("parent shutdown should submit");
    }

    #[tokio::test]
    async fn spawn_agent_fork_persists_fork_reference_instead_of_parent_history() {
        let harness = AgentControlHarness::new().await;
        let (parent_thread_id, parent_thread) = harness.start_thread().await;
        parent_thread
            .inject_user_message_without_turn("parent seed context".to_string())
            .await;
        let turn_context = parent_thread.codex.session.new_default_turn().await;
        let parent_spawn_call_id = "spawn-call-dedup".to_string();
        let parent_spawn_call = ResponseItem::FunctionCall {
            id: None,
            name: "spawn_agent".to_string(),
            namespace: None,
            arguments: "{}".to_string(),
            call_id: parent_spawn_call_id.clone(),
        };
        parent_thread
            .codex
            .session
            .record_conversation_items(turn_context.as_ref(), &[parent_spawn_call])
            .await;
        parent_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        parent_thread.codex.session.flush_rollout().await;
        let parent_rollout_path = parent_thread
            .rollout_path()
            .expect("parent rollout path should be available");

        let child_thread_id = harness
            .control
            .spawn_agent_with_options(
                harness.config.clone(),
                text_input("child task"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
                SpawnAgentOptions {
                    fork_parent_spawn_call_id: Some(parent_spawn_call_id),
                },
            )
            .await
            .expect("forked spawn should succeed");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        let child_rollout_path = child_thread
            .rollout_path()
            .expect("child rollout path should be available");
        let InitialHistory::Resumed(resumed) =
            RolloutRecorder::get_rollout_history(child_rollout_path.as_path())
                .await
                .expect("child rollout should load")
        else {
            panic!("child rollout should include session metadata");
        };

        assert!(
            resumed.history.iter().any(|item| {
                matches!(
                    item,
                    RolloutItem::ForkReference(ForkReferenceItem {
                        rollout_path,
                        nth_user_message,
                    }) if rollout_path == &parent_rollout_path && *nth_user_message == usize::MAX
                )
            }),
            "child rollout should persist a fork reference to the parent rollout"
        );

        let raw_response_items: Vec<ResponseItem> = resumed
            .history
            .iter()
            .filter_map(|item| match item {
                RolloutItem::ResponseItem(response_item) => Some(response_item.clone()),
                RolloutItem::SessionMeta(_)
                | RolloutItem::ForkReference(_)
                | RolloutItem::Compacted(_)
                | RolloutItem::TurnContext(_)
                | RolloutItem::EventMsg(_) => None,
            })
            .collect();
        assert!(
            !history_contains_text(&raw_response_items, "parent seed context"),
            "child rollout should not duplicate the parent's raw transcript"
        );

        let history = child_thread.codex.session.clone_history().await;
        assert!(history_contains_text(
            history.raw_items(),
            "parent seed context"
        ));

        let _ = harness
            .control
            .shutdown_agent(child_thread_id)
            .await
            .expect("child shutdown should submit");
        let _ = parent_thread
            .submit(Op::Shutdown {})
            .await
            .expect("parent shutdown should submit");
    }

    #[tokio::test]
    async fn spawn_agent_respects_max_threads_limit() {
        let max_threads = 1usize;
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(max_threads as i64),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();

        let _ = manager
            .start_thread(config.clone())
            .await
            .expect("start thread");

        let first_agent_id = control
            .spawn_agent(config.clone(), text_input("hello"), None)
            .await
            .expect("spawn_agent should succeed");

        let err = control
            .spawn_agent(config, text_input("hello again"), None)
            .await
            .expect_err("spawn_agent should respect max threads");
        let CodexErr::AgentLimitReached {
            max_threads: seen_max_threads,
        } = err
        else {
            panic!("expected CodexErr::AgentLimitReached");
        };
        assert_eq!(seen_max_threads, max_threads);

        let _ = control
            .shutdown_agent(first_agent_id)
            .await
            .expect("shutdown agent");
    }

    #[tokio::test]
    async fn spawn_agent_releases_slot_after_shutdown() {
        let max_threads = 1usize;
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(max_threads as i64),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();

        let first_agent_id = control
            .spawn_agent(config.clone(), text_input("hello"), None)
            .await
            .expect("spawn_agent should succeed");
        let _ = control
            .shutdown_agent(first_agent_id)
            .await
            .expect("shutdown agent");

        let second_agent_id = control
            .spawn_agent(config.clone(), text_input("hello again"), None)
            .await
            .expect("spawn_agent should succeed after shutdown");
        let _ = control
            .shutdown_agent(second_agent_id)
            .await
            .expect("shutdown agent");
    }

    #[tokio::test]
    async fn spawn_agent_reconciles_stale_guard_slots() {
        let max_threads = 1usize;
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(max_threads as i64),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();

        let stale_agent_id = control
            .spawn_agent(config.clone(), text_input("stale"), None)
            .await
            .expect("spawn stale agent");
        let _ = manager.remove_thread(&stale_agent_id).await;

        let replacement_agent_id = control
            .spawn_agent(config.clone(), text_input("replacement"), None)
            .await
            .expect("spawn should reconcile stale guard slot");

        let _ = control
            .shutdown_agent(replacement_agent_id)
            .await
            .expect("shutdown replacement agent");
    }

    #[tokio::test]
    async fn submit_initial_input_cleanup_releases_guard_slot_after_send_error() {
        let max_threads = 1usize;
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(max_threads as i64),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();

        let missing_thread_id = ThreadId::new();
        let reservation = control
            .guards
            .reserve_spawn_slot(Some(max_threads))
            .expect("reserve slot");
        reservation.commit(missing_thread_id);

        let state = control.upgrade().expect("thread manager state");
        let err = control
            .submit_initial_input_or_cleanup(&state, missing_thread_id, text_input("hello"))
            .await
            .expect_err("send_input should fail for missing thread");
        assert_matches!(err, CodexErr::ThreadNotFound(id) if id == missing_thread_id);

        let replacement = control
            .spawn_agent(config, text_input("replacement"), None)
            .await
            .expect("slot should be released after cleanup");
        let _ = control.shutdown_agent(replacement).await;
    }

    #[tokio::test]
    async fn shutdown_agent_releases_descendant_slots() {
        let max_threads = 2usize;
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(max_threads as i64),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();

        let root_thread_id = ThreadId::new();
        let first_agent_id = control
            .spawn_agent(
                config.clone(),
                text_input("first"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: root_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
            )
            .await
            .expect("spawn first agent");
        let _second_agent_id = control
            .spawn_agent(
                config.clone(),
                text_input("second"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: first_agent_id,
                    depth: 2,
                    agent_nickname: None,
                    agent_role: None,
                })),
            )
            .await
            .expect("spawn descendant agent");

        let _ = control
            .shutdown_agent(first_agent_id)
            .await
            .expect("shutdown should close subtree");

        let replacement_a = control
            .spawn_agent(config.clone(), text_input("replacement-a"), None)
            .await
            .expect("first replacement spawn should succeed");
        let replacement_b = control
            .spawn_agent(config.clone(), text_input("replacement-b"), None)
            .await
            .expect("second replacement spawn should succeed after subtree shutdown");

        let _ = control
            .shutdown_agent(replacement_a)
            .await
            .expect("shutdown replacement_a");
        let _ = control
            .shutdown_agent(replacement_b)
            .await
            .expect("shutdown replacement_b");
    }

    #[tokio::test]
    async fn shutdown_watchdog_handle_releases_active_helper_slot() {
        let max_threads = 2usize;
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(max_threads as i64),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();
        let owner_thread = manager
            .start_thread(config.clone())
            .await
            .expect("start owner thread");
        let owner_thread_id = owner_thread.thread_id;

        let watchdog_handle_id = control
            .spawn_agent_handle(
                config.clone(),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: owner_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
            )
            .await
            .expect("spawn watchdog handle");
        control
            .register_watchdog(WatchdogRegistration {
                owner_thread_id,
                target_thread_id: watchdog_handle_id,
                child_depth: 1,
                interval_s: 30,
                prompt: "watchdog".to_string(),
                config: config.clone(),
            })
            .await
            .expect("register watchdog");

        let helper_id = control
            .spawn_agent(
                config.clone(),
                text_input("helper"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: owner_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
            )
            .await
            .expect("spawn helper");
        control
            .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_id)
            .await;

        let _ = control
            .shutdown_agent(watchdog_handle_id)
            .await
            .expect("shutdown watchdog handle");
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if matches!(control.get_status(helper_id).await, AgentStatus::NotFound) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("watchdog helper should be cleaned up before replacement spawns");

        let replacement_a = control
            .spawn_agent(config.clone(), text_input("replacement-a"), None)
            .await
            .expect("first replacement spawn should succeed");
        let replacement_b = control
            .spawn_agent(config.clone(), text_input("replacement-b"), None)
            .await
            .expect("second replacement spawn should succeed");

        let _ = control
            .shutdown_agent(replacement_a)
            .await
            .expect("shutdown replacement_a");
        let _ = control
            .shutdown_agent(replacement_b)
            .await
            .expect("shutdown replacement_b");
        let _ = control.shutdown_agent(owner_thread_id).await;
    }

    #[tokio::test]
    async fn watchdog_run_once_cleans_up_final_helper_thread() {
        let (_home, config) = test_config().await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();

        let owner_thread = manager
            .start_thread(config.clone())
            .await
            .expect("start owner thread");
        let owner_thread_id = owner_thread.thread_id;
        let watchdog_handle_id = control
            .spawn_agent_handle(
                config.clone(),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: owner_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
            )
            .await
            .expect("spawn watchdog handle");
        control
            .register_watchdog(WatchdogRegistration {
                owner_thread_id,
                target_thread_id: watchdog_handle_id,
                child_depth: 1,
                interval_s: 30,
                prompt: "watchdog".to_string(),
                config: config.clone(),
            })
            .await
            .expect("register watchdog");

        let helper_id = control
            .spawn_agent_handle(
                config,
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: owner_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
            )
            .await
            .expect("spawn helper");
        control
            .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_id)
            .await;
        control
            .force_watchdog_due_for_tests(watchdog_handle_id)
            .await;
        let helper_thread = manager
            .get_thread(helper_id)
            .await
            .expect("helper thread should exist");
        let mut helper_status_rx = helper_thread.subscribe_status();
        let _ = helper_thread.submit(Op::Shutdown {}).await;
        if !crate::agent::status::is_final(&helper_status_rx.borrow()) {
            let _ = helper_status_rx.changed().await;
        }

        control.run_watchdogs_once_for_tests().await;

        let helper_after = manager.get_thread(helper_id).await;
        assert!(matches!(helper_after, Err(CodexErr::ThreadNotFound(id)) if id == helper_id));
        let _ = control.shutdown_agent(watchdog_handle_id).await;
        let _ = control.shutdown_agent(owner_thread_id).await;
    }

    #[tokio::test]
    async fn watchdog_run_once_cleans_up_active_helper_when_owner_missing() {
        let max_threads = 2usize;
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(max_threads as i64),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();

        let owner_thread = manager
            .start_thread(config.clone())
            .await
            .expect("start owner thread");
        let owner_thread_id = owner_thread.thread_id;
        let watchdog_handle_id = control
            .spawn_agent_handle(
                config.clone(),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: owner_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
            )
            .await
            .expect("spawn watchdog handle");
        control
            .register_watchdog(WatchdogRegistration {
                owner_thread_id,
                target_thread_id: watchdog_handle_id,
                child_depth: 1,
                interval_s: 30,
                prompt: "watchdog".to_string(),
                config: config.clone(),
            })
            .await
            .expect("register watchdog");

        let helper_id = control
            .spawn_agent(
                config.clone(),
                text_input("helper"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: owner_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
            )
            .await
            .expect("spawn helper");
        control
            .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_id)
            .await;

        let _ = manager.remove_thread(&owner_thread_id).await;

        control.run_watchdogs_once_for_tests().await;

        let helper_after = manager.get_thread(helper_id).await;
        assert!(matches!(helper_after, Err(CodexErr::ThreadNotFound(id)) if id == helper_id));

        let replacement = control
            .spawn_agent(config, text_input("replacement"), None)
            .await
            .expect("replacement spawn should succeed after helper cleanup");
        let _ = control.shutdown_agent(replacement).await;
        let _ = control.shutdown_agent(watchdog_handle_id).await;
    }

    #[tokio::test]
    async fn run_watchdogs_once_cleans_up_handle_and_helper_after_owner_shutdown() {
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(2),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();
        let owner_thread = manager
            .start_thread(config.clone())
            .await
            .expect("start owner thread");
        let owner_thread_id = owner_thread.thread_id;
        let watchdog_handle_id = control
            .spawn_agent_handle(config.clone(), Some(thread_spawn_source(owner_thread_id)))
            .await
            .expect("watchdog handle should spawn");
        let helper_thread_id = control
            .spawn_agent_handle(config.clone(), Some(thread_spawn_source(owner_thread_id)))
            .await
            .expect("watchdog helper should spawn");
        let removed = control
            .register_watchdog(WatchdogRegistration {
                owner_thread_id,
                target_thread_id: watchdog_handle_id,
                child_depth: 1,
                interval_s: 1,
                prompt: "check in".to_string(),
                config: config.clone(),
            })
            .await
            .expect("watchdog registration should succeed");
        assert_eq!(removed, Vec::<RemovedWatchdog>::new());
        control
            .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
            .await;
        assert_eq!(
            control
                .watchdog_owner_for_active_helper(helper_thread_id)
                .await,
            Some(owner_thread_id)
        );
        let tracked_before = control.guards.tracked_thread_ids();
        assert!(tracked_before.contains(&watchdog_handle_id));
        assert!(tracked_before.contains(&helper_thread_id));

        let mut owner_status_rx = control
            .subscribe_status(owner_thread_id)
            .await
            .expect("owner status subscription should succeed");
        let _ = owner_thread
            .thread
            .submit(Op::Shutdown {})
            .await
            .expect("owner shutdown should submit");
        timeout(Duration::from_secs(2), async {
            loop {
                if matches!(owner_status_rx.borrow().clone(), AgentStatus::Shutdown) {
                    break;
                }
                owner_status_rx
                    .changed()
                    .await
                    .expect("owner status should reach shutdown");
            }
        })
        .await
        .expect("owner should reach shutdown");

        control.run_watchdogs_once_for_tests().await;

        assert_eq!(
            control.get_status(watchdog_handle_id).await,
            AgentStatus::NotFound
        );
        assert_eq!(
            control.get_status(helper_thread_id).await,
            AgentStatus::NotFound
        );
        assert_eq!(
            control
                .watchdog_owner_for_active_helper(helper_thread_id)
                .await,
            None
        );
        let tracked_after = control.guards.tracked_thread_ids();
        assert!(!tracked_after.contains(&watchdog_handle_id));
        assert!(!tracked_after.contains(&helper_thread_id));

        let replacement_thread_id = control
            .spawn_agent_handle(config.clone(), None)
            .await
            .expect("cleanup should release watchdog helper slots");
        let ops = manager.captured_ops();
        assert!(
            ops.iter()
                .any(|(thread_id, op)| *thread_id == watchdog_handle_id
                    && matches!(op, Op::Shutdown))
        );
        assert!(
            ops.iter()
                .any(|(thread_id, op)| *thread_id == helper_thread_id && matches!(op, Op::Shutdown))
        );

        let _ = control
            .shutdown_agent(replacement_thread_id)
            .await
            .expect("replacement thread shutdown should submit");
    }

    #[tokio::test]
    async fn compact_parent_for_watchdog_helper_blocks_until_finish_hook() {
        let harness = AgentControlHarness::new().await;
        let (owner_thread_id, _owner_thread) = harness.start_thread().await;
        let watchdog_handle_id = harness
            .control
            .spawn_agent_handle(
                harness.config.clone(),
                Some(thread_spawn_source(owner_thread_id)),
            )
            .await
            .expect("watchdog handle should spawn");
        let helper_thread_id = harness
            .control
            .spawn_agent_handle(
                harness.config.clone(),
                Some(thread_spawn_source(owner_thread_id)),
            )
            .await
            .expect("watchdog helper should spawn");
        let removed = harness
            .control
            .register_watchdog(WatchdogRegistration {
                owner_thread_id,
                target_thread_id: watchdog_handle_id,
                child_depth: 1,
                interval_s: 1,
                prompt: "compact if needed".to_string(),
                config: harness.config.clone(),
            })
            .await
            .expect("watchdog registration should succeed");
        assert_eq!(removed, Vec::<RemovedWatchdog>::new());
        harness
            .control
            .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
            .await;

        let result = harness
            .control
            .compact_parent_for_watchdog_helper(helper_thread_id)
            .await
            .expect("first compact request should submit");
        let submission_id = match result {
            WatchdogParentCompactionResult::Submitted {
                parent_thread_id,
                submission_id,
            } => {
                assert_eq!(parent_thread_id, owner_thread_id);
                submission_id
            }
            other => panic!("expected submitted compaction result, got {other:?}"),
        };
        assert!(!submission_id.is_empty());
        assert_eq!(
            harness
                .manager
                .captured_ops()
                .iter()
                .filter(|(thread_id, op)| *thread_id == owner_thread_id && matches!(op, Op::Compact))
                .count(),
            1
        );

        let result = harness
            .control
            .compact_parent_for_watchdog_helper(helper_thread_id)
            .await
            .expect("duplicate compact should be blocked");
        assert_eq!(
            result,
            WatchdogParentCompactionResult::AlreadyInProgress {
                parent_thread_id: owner_thread_id
            }
        );

        harness
            .control
            .finish_watchdog_parent_compaction(owner_thread_id)
            .await;

        let result = harness
            .control
            .compact_parent_for_watchdog_helper(helper_thread_id)
            .await
            .expect("completed compact should unblock later requests");
        let resubmitted_id = match result {
            WatchdogParentCompactionResult::Submitted {
                parent_thread_id,
                submission_id,
            } => {
                assert_eq!(parent_thread_id, owner_thread_id);
                submission_id
            }
            other => panic!("expected submitted compaction result after finish, got {other:?}"),
        };
        assert!(!resubmitted_id.is_empty());
        assert_eq!(
            harness
                .manager
                .captured_ops()
                .iter()
                .filter(|(thread_id, op)| *thread_id == owner_thread_id && matches!(op, Op::Compact))
                .count(),
            2
        );

        let _ = harness
            .control
            .shutdown_agent(watchdog_handle_id)
            .await
            .expect("watchdog handle shutdown should submit");
        let _ = harness
            .control
            .shutdown_agent(owner_thread_id)
            .await
            .expect("owner shutdown should submit");
    }

    #[tokio::test]
    async fn compact_parent_for_watchdog_helper_rechecks_parent_idleness_before_submitting() {
        let harness = AgentControlHarness::new().await;
        let (owner_thread_id, owner_thread) = harness.start_thread().await;
        let watchdog_handle_id = harness
            .control
            .spawn_agent_handle(
                harness.config.clone(),
                Some(thread_spawn_source(owner_thread_id)),
            )
            .await
            .expect("watchdog handle should spawn");
        let helper_thread_id = harness
            .control
            .spawn_agent_handle(
                harness.config.clone(),
                Some(thread_spawn_source(owner_thread_id)),
            )
            .await
            .expect("watchdog helper should spawn");
        let removed = harness
            .control
            .register_watchdog(WatchdogRegistration {
                owner_thread_id,
                target_thread_id: watchdog_handle_id,
                child_depth: 1,
                interval_s: 1,
                prompt: "compact if needed".to_string(),
                config: harness.config.clone(),
            })
            .await
            .expect("watchdog registration should succeed");
        assert_eq!(removed, Vec::<RemovedWatchdog>::new());
        harness
            .control
            .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
            .await;

        let owner_session = Arc::clone(&owner_thread.codex.session);
        let result = harness
            .control
            .compact_parent_for_watchdog_helper_inner(
                helper_thread_id,
                Some(Box::pin(async move {
                    let mut active_turn = owner_session.active_turn.lock().await;
                    *active_turn = Some(crate::state::ActiveTurn::default());
                })),
            )
            .await
            .expect("recheck should return a busy result");
        assert_eq!(
            result,
            WatchdogParentCompactionResult::ParentBusy {
                parent_thread_id: owner_thread_id
            }
        );
        assert_eq!(
            harness
                .manager
                .captured_ops()
                .iter()
                .filter(|(thread_id, op)| *thread_id == owner_thread_id && matches!(op, Op::Compact))
                .count(),
            0
        );

        {
            let mut active_turn = owner_thread.codex.session.active_turn.lock().await;
            *active_turn = None;
        }

        let result = harness
            .control
            .compact_parent_for_watchdog_helper(helper_thread_id)
            .await
            .expect("recheck cleanup should allow a later submit");
        let submission_id = match result {
            WatchdogParentCompactionResult::Submitted {
                parent_thread_id,
                submission_id,
            } => {
                assert_eq!(parent_thread_id, owner_thread_id);
                submission_id
            }
            other => {
                panic!("expected submitted compaction result after parent idles, got {other:?}")
            }
        };
        assert!(!submission_id.is_empty());
        assert_eq!(
            harness
                .manager
                .captured_ops()
                .iter()
                .filter(|(thread_id, op)| *thread_id == owner_thread_id && matches!(op, Op::Compact))
                .count(),
            1
        );

        let _ = harness
            .control
            .shutdown_agent(watchdog_handle_id)
            .await
            .expect("watchdog handle shutdown should submit");
        let _ = harness
            .control
            .shutdown_agent(owner_thread_id)
            .await
            .expect("owner shutdown should submit");
    }

    #[tokio::test]
    async fn compact_handler_rechecks_watchdog_parent_idleness_at_execution_time() {
        let harness = AgentControlHarness::new().await;
        let (owner_thread_id, owner_thread) = harness.start_thread().await;

        harness
            .control
            .mark_watchdog_parent_compaction_in_progress_for_tests(owner_thread_id)
            .await;

        {
            let mut active_turn = owner_thread.codex.session.active_turn.lock().await;
            *active_turn = Some(crate::state::ActiveTurn::default());
        }

        owner_thread
            .submit(Op::Compact)
            .await
            .expect("compact submit should succeed");

        timeout(Duration::from_secs(2), async {
            loop {
                if !harness
                    .control
                    .watchdog_parent_compaction_in_progress(owner_thread_id)
                    .await
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("watchdog compaction marker should be cleared");

        assert!(
            owner_thread.has_active_turn().await,
            "execution-time recheck must not replace an active parent turn"
        );

        {
            let mut active_turn = owner_thread.codex.session.active_turn.lock().await;
            *active_turn = None;
        }

        let _ = harness
            .control
            .shutdown_agent(owner_thread_id)
            .await
            .expect("owner shutdown should submit");
    }

    #[tokio::test]
    async fn queued_watchdog_compact_skips_execution_when_parent_became_active() {
        let harness = AgentControlHarness::new().await;
        let (owner_thread_id, owner_thread) = harness.start_thread().await;
        let owner_control = owner_thread.codex.session.services.agent_control.clone();

        owner_control
            .mark_watchdog_parent_compaction_in_progress_for_tests(owner_thread_id)
            .await;

        {
            let mut active_turn = owner_thread.codex.session.active_turn.lock().await;
            *active_turn = Some(crate::state::ActiveTurn::default());
        }

        assert!(
            crate::codex::skip_watchdog_parent_compact_if_parent_busy(&owner_thread.codex.session)
                .await,
            "execution-time watchdog compaction recheck should skip when the parent is active"
        );

        let active_turn = owner_thread.codex.session.active_turn.lock().await;
        let active_turn = active_turn
            .as_ref()
            .expect("queued watchdog compact must not replace the active turn");
        assert!(
            active_turn.tasks.is_empty(),
            "queued watchdog compact should not spawn a replacement task"
        );
        assert!(
            !owner_control
                .watchdog_parent_compaction_in_progress(owner_thread_id)
                .await,
            "execution-time recheck should clear the in-progress marker"
        );

        let _ = owner_control
            .shutdown_agent(owner_thread_id)
            .await
            .expect("owner shutdown should submit");
    }

    #[tokio::test]
    async fn compact_parent_for_watchdog_helper_unblocks_after_compact_abort_cleanup() {
        let harness = AgentControlHarness::new().await;
        let (owner_thread_id, owner_thread) = harness.start_thread().await;
        let owner_control = owner_thread.codex.session.services.agent_control.clone();
        let watchdog_handle_id = owner_control
            .spawn_agent_handle(
                harness.config.clone(),
                Some(thread_spawn_source(owner_thread_id)),
            )
            .await
            .expect("watchdog handle should spawn");
        let helper_thread_id = owner_control
            .spawn_agent_handle(
                harness.config.clone(),
                Some(thread_spawn_source(owner_thread_id)),
            )
            .await
            .expect("watchdog helper should spawn");
        let removed = owner_control
            .register_watchdog(WatchdogRegistration {
                owner_thread_id,
                target_thread_id: watchdog_handle_id,
                child_depth: 1,
                interval_s: 1,
                prompt: "compact if needed".to_string(),
                config: harness.config.clone(),
            })
            .await
            .expect("watchdog registration should succeed");
        assert_eq!(removed, Vec::<RemovedWatchdog>::new());
        owner_control
            .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
            .await;

        let result = owner_control
            .compact_parent_for_watchdog_helper(helper_thread_id)
            .await
            .expect("first compact request should submit");
        let submission_id = match result {
            WatchdogParentCompactionResult::Submitted {
                parent_thread_id,
                submission_id,
            } => {
                assert_eq!(parent_thread_id, owner_thread_id);
                submission_id
            }
            other => panic!("expected submitted compaction result, got {other:?}"),
        };
        assert!(!submission_id.is_empty());

        let result = owner_control
            .compact_parent_for_watchdog_helper(helper_thread_id)
            .await
            .expect("duplicate compact should be blocked");
        assert_eq!(
            result,
            WatchdogParentCompactionResult::AlreadyInProgress {
                parent_thread_id: owner_thread_id
            }
        );

        Arc::new(CompactTask)
            .abort(
                Arc::new(SessionTaskContext::new(Arc::clone(
                    &owner_thread.codex.session,
                ))),
                owner_thread.codex.session.new_default_turn().await,
            )
            .await;

        let result = owner_control
            .compact_parent_for_watchdog_helper(helper_thread_id)
            .await
            .expect("abort cleanup should unblock later requests");
        let resubmitted_id = match result {
            WatchdogParentCompactionResult::Submitted {
                parent_thread_id,
                submission_id,
            } => {
                assert_eq!(parent_thread_id, owner_thread_id);
                submission_id
            }
            other => panic!("expected submitted compaction result after abort, got {other:?}"),
        };
        assert!(!resubmitted_id.is_empty());
    }

    #[tokio::test]
    async fn list_agents_all_includes_tracked_not_found_threads() {
        let max_threads = 1usize;
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(max_threads as i64),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();

        let orphaned_agent_id = control
            .spawn_agent(config.clone(), text_input("orphan"), None)
            .await
            .expect("spawn orphaned agent");
        let _ = manager.remove_thread(&orphaned_agent_id).await;

        let listings = control
            .list_agents(ThreadId::new(), true, true)
            .await
            .expect("list all agents");
        let listing = listings
            .into_iter()
            .find(|entry| entry.thread_id == orphaned_agent_id)
            .expect("orphaned tracked agent should be listed");
        assert_eq!(listing.status, AgentStatus::NotFound);
        assert_eq!(listing.depth, 0);

        let _ = control.shutdown_agent(orphaned_agent_id).await;

        let replacement = control
            .spawn_agent(config, text_input("replacement"), None)
            .await
            .expect("replacement spawn should succeed after cleanup");
        let _ = control.shutdown_agent(replacement).await;
    }

    #[tokio::test]
    async fn list_agents_all_excludes_live_manager_threads_when_untracked() {
        let (_home, config) = test_config().await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();

        let agent_id = control
            .spawn_agent(config, text_input("live thread"), None)
            .await
            .expect("spawn live thread");
        control.guards.release_spawned_thread(agent_id);

        let listings = control
            .list_agents(ThreadId::new(), true, true)
            .await
            .expect("list all agents");
        let listing = listings
            .into_iter()
            .find(|entry| entry.thread_id == agent_id);
        assert!(listing.is_none());

        let _ = control.shutdown_agent(agent_id).await;
    }

    #[tokio::test]
    async fn spawn_agent_limit_shared_across_clones() {
        let max_threads = 1usize;
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(max_threads as i64),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();
        let cloned = control.clone();

        let first_agent_id = cloned
            .spawn_agent(config.clone(), text_input("hello"), None)
            .await
            .expect("spawn_agent should succeed");

        let err = control
            .spawn_agent(config, text_input("hello again"), None)
            .await
            .expect_err("spawn_agent should respect shared guard");
        let CodexErr::AgentLimitReached { max_threads } = err else {
            panic!("expected CodexErr::AgentLimitReached");
        };
        assert_eq!(max_threads, 1);

        let _ = control
            .shutdown_agent(first_agent_id)
            .await
            .expect("shutdown agent");
    }

    #[test]
    fn build_agent_inbox_items_tool_role_emits_function_call_and_output() {
        let sender_thread_id = ThreadId::new();
        let message = "ping".to_string();

        let items = build_agent_inbox_items(
            CollabInboxDeliveryRole::Tool,
            sender_thread_id,
            Some("Atlas".to_string()),
            Some("worker".to_string()),
            message,
            false,
        )
        .expect("tool role should build inbox items");

        assert_eq!(items.len(), 1);

        let _call_id = match &items[0] {
            ResponseInputItem::FunctionCallOutput { call_id, output } => {
                let call_id = call_id.clone();
                let output_text = output
                    .body
                    .to_text()
                    .expect("payload should convert to text");
                let payload: AgentInboxPayload =
                    serde_json::from_str(&output_text).expect("payload should be valid json");
                assert!(payload.injected);
                assert_eq!(payload.kind, AGENT_INBOX_KIND);
                assert_eq!(payload.sender_thread_id, sender_thread_id);
                assert_eq!(payload.sender_agent_nickname.as_deref(), Some("Atlas"));
                assert_eq!(payload.sender_agent_role.as_deref(), Some("worker"));
                assert_eq!(payload.message, "ping");
                call_id
            }
            other => panic!("expected function call output item, got {other:?}"),
        };
    }

    #[tokio::test]
    async fn resume_agent_respects_max_threads_limit() {
        let max_threads = 1usize;
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(max_threads as i64),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();

        let resumable_id = control
            .spawn_agent(config.clone(), text_input("hello"), None)
            .await
            .expect("spawn_agent should succeed");
        let resumable_thread = manager
            .get_thread(resumable_id)
            .await
            .expect("resumable thread should exist");
        resumable_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        resumable_thread.flush_rollout().await;
        let _ = control
            .shutdown_agent(resumable_id)
            .await
            .expect("shutdown resumable thread");

        let active_id = control
            .spawn_agent(config.clone(), text_input("occupy"), None)
            .await
            .expect("spawn_agent should succeed for active slot");

        let err = control
            .resume_agent_from_rollout(config, resumable_id, SessionSource::Exec)
            .await
            .expect_err("resume should respect max threads");
        let CodexErr::AgentLimitReached {
            max_threads: seen_max_threads,
        } = err
        else {
            panic!("expected CodexErr::AgentLimitReached");
        };
        assert_eq!(seen_max_threads, max_threads);

        let _ = control
            .shutdown_agent(active_id)
            .await
            .expect("shutdown active thread");
    }

    #[tokio::test]
    async fn resume_agent_releases_slot_after_resume_failure() {
        let max_threads = 1usize;
        let (_home, config) = test_config_with_cli_overrides(vec![(
            "agents.max_threads".to_string(),
            TomlValue::Integer(max_threads as i64),
        )])
        .await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();

        let _ = control
            .resume_agent_from_rollout(config.clone(), ThreadId::new(), SessionSource::Exec)
            .await
            .expect_err("resume should fail for missing rollout");

        let resumed_id = control
            .spawn_agent(config, text_input("hello"), None)
            .await
            .expect("spawn should succeed after failed resume");
        let _ = control
            .shutdown_agent(resumed_id)
            .await
            .expect("shutdown resumed thread");
    }

    #[tokio::test]
    async fn spawn_child_completion_notifies_parent_history() {
        let harness = AgentControlHarness::new().await;
        let (parent_thread_id, parent_thread) = harness.start_thread().await;

        let child_thread_id = harness
            .control
            .spawn_agent(
                harness.config.clone(),
                text_input("hello child"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                })),
            )
            .await
            .expect("child spawn should succeed");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should exist");
        let _ = child_thread
            .submit(Op::Shutdown {})
            .await
            .expect("child shutdown should submit");

        assert_eq!(wait_for_subagent_notification(&parent_thread).await, true);
    }

    #[tokio::test]
    async fn completion_watcher_forwards_terminal_message_live_to_active_root_parent() {
        let harness = AgentControlHarness::new().await;
        let (parent_thread_id, parent_thread) = harness.start_thread().await;
        let parent_turn = parent_thread
            .codex
            .session
            .new_default_turn_with_sub_id("parent-wait-turn".to_string())
            .await;
        parent_thread
            .codex
            .session
            .spawn_task(
                Arc::clone(&parent_turn),
                text_input("wait for child"),
                WaitForCancellationTask,
            )
            .await;

        let (child_thread_id, child_thread) = harness.start_thread().await;
        let child_turn = child_thread
            .codex
            .session
            .new_default_turn_with_sub_id("child-final-turn".to_string())
            .await;
        child_thread
            .codex
            .session
            .spawn_task(
                Arc::clone(&child_turn),
                text_input("child work"),
                WaitForCancellationTask,
            )
            .await;

        harness.control.maybe_start_completion_watcher(
            child_thread_id,
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            })),
        );

        child_thread
            .codex
            .session
            .on_task_finished(
                Arc::clone(&child_turn),
                Some("final explorer result".to_string()),
            )
            .await;

        assert!(
            wait_for_raw_response_text(&parent_thread, "final explorer result").await,
            "expected live fallback Agent message while parent wait turn is still active"
        );

        parent_thread
            .codex
            .session
            .abort_all_tasks(TurnAbortReason::Interrupted)
            .await;
    }

    #[tokio::test]
    async fn completion_watcher_forwards_distinct_terminal_message_after_progress_send_input() {
        let harness = AgentControlHarness::new().await;
        let (parent_thread_id, parent_thread) = harness.start_thread().await;
        let parent_turn = parent_thread
            .codex
            .session
            .new_default_turn_with_sub_id("parent-progress-wait-turn".to_string())
            .await;
        parent_thread
            .codex
            .session
            .spawn_task(
                Arc::clone(&parent_turn),
                text_input("wait for child"),
                WaitForCancellationTask,
            )
            .await;

        let (child_thread_id, child_thread) = harness.start_thread().await;
        let child_turn = child_thread
            .codex
            .session
            .new_default_turn_with_sub_id("child-progress-turn".to_string())
            .await;
        child_thread
            .codex
            .session
            .spawn_task(
                Arc::clone(&child_turn),
                text_input("child work"),
                WaitForCancellationTask,
            )
            .await;

        harness.control.maybe_start_completion_watcher(
            child_thread_id,
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            })),
        );

        child_thread.codex.session.mark_turn_used_agent_send_input();
        harness
            .control
            .send_agent_message(
                parent_thread_id,
                child_thread_id,
                "progress update".to_string(),
            )
            .await
            .expect("progress send_input should succeed");

        assert!(wait_for_raw_response_text(&parent_thread, "progress update").await);

        child_thread
            .codex
            .session
            .on_task_finished(
                Arc::clone(&child_turn),
                Some("final explorer result".to_string()),
            )
            .await;

        assert!(
            wait_for_raw_response_text(&parent_thread, "final explorer result").await,
            "expected final completion body to stay live even after earlier progress send_input"
        );

        parent_thread
            .codex
            .session
            .abort_all_tasks(TurnAbortReason::Interrupted)
            .await;
    }

    #[tokio::test]
    async fn completion_watcher_suppresses_duplicate_terminal_message_already_forwarded_live() {
        let harness = AgentControlHarness::new().await;
        let (parent_thread_id, parent_thread) = harness.start_thread().await;
        let parent_turn = parent_thread
            .codex
            .session
            .new_default_turn_with_sub_id("parent-dedupe-wait-turn".to_string())
            .await;
        parent_thread
            .codex
            .session
            .spawn_task(
                Arc::clone(&parent_turn),
                text_input("wait for child"),
                WaitForCancellationTask,
            )
            .await;

        let (child_thread_id, child_thread) = harness.start_thread().await;
        let child_turn = child_thread
            .codex
            .session
            .new_default_turn_with_sub_id("child-dedupe-turn".to_string())
            .await;
        child_thread
            .codex
            .session
            .spawn_task(
                Arc::clone(&child_turn),
                text_input("child work"),
                WaitForCancellationTask,
            )
            .await;

        harness.control.maybe_start_completion_watcher(
            child_thread_id,
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            })),
        );

        child_thread.codex.session.mark_turn_used_agent_send_input();
        harness
            .control
            .send_agent_message(
                parent_thread_id,
                child_thread_id,
                "same final message".to_string(),
            )
            .await
            .expect("initial send_input should succeed");

        assert!(wait_for_raw_response_text(&parent_thread, "same final message").await);

        child_thread
            .codex
            .session
            .on_task_finished(
                Arc::clone(&child_turn),
                Some("same final message".to_string()),
            )
            .await;

        let duplicate = tokio::time::timeout(std::time::Duration::from_millis(300), async {
            loop {
                let event = parent_thread
                    .next_event()
                    .await
                    .expect("event should be available");
                if matches!(
                    event.msg,
                    EventMsg::RawResponseItem(RawResponseItemEvent { item })
                        if history_contains_text(&[item.clone()], "same final message")
                ) {
                    return true;
                }
            }
        })
        .await
        .is_ok();
        assert_eq!(duplicate, false);

        parent_thread
            .codex
            .session
            .abort_all_tasks(TurnAbortReason::Interrupted)
            .await;
    }

    #[tokio::test]
    async fn completion_watcher_notifies_parent_when_child_is_missing() {
        let harness = AgentControlHarness::new().await;
        let (parent_thread_id, parent_thread) = harness.start_thread().await;
        let child_thread_id = ThreadId::new();

        harness.control.maybe_start_completion_watcher(
            child_thread_id,
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            })),
        );

        assert_eq!(wait_for_subagent_notification(&parent_thread).await, true);

        let history_items = parent_thread
            .codex
            .session
            .clone_history()
            .await
            .raw_items()
            .to_vec();
        assert_eq!(
            history_contains_text(
                &history_items,
                &format!("\"agent_id\":\"{child_thread_id}\"")
            ),
            true
        );
        assert_eq!(
            history_contains_text(&history_items, "\"status\":\"not_found\""),
            true
        );
    }

    #[tokio::test]
    async fn spawn_thread_subagent_gets_random_nickname_in_session_source() {
        let harness = AgentControlHarness::new().await;
        let (parent_thread_id, _parent_thread) = harness.start_thread().await;

        let child_thread_id = harness
            .control
            .spawn_agent(
                harness.config.clone(),
                text_input("hello child"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                })),
            )
            .await
            .expect("child spawn should succeed");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        let snapshot = child_thread.config_snapshot().await;

        let SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id: seen_parent_thread_id,
            depth,
            agent_nickname,
            agent_role,
        }) = snapshot.session_source
        else {
            panic!("expected thread-spawn sub-agent source");
        };
        assert_eq!(seen_parent_thread_id, parent_thread_id);
        assert_eq!(depth, 1);
        assert!(agent_nickname.is_some());
        assert_eq!(agent_role, Some("explorer".to_string()));
    }

    #[tokio::test]
    async fn spawn_agent_uses_parent_thread_auth_manager_when_parent_differs_from_manager_default()
    {
        let harness = AgentControlHarness::new().await;
        let parent_auth_manager =
            auth_manager_with_auth_file(&harness.config, &harness._home, "spawn-parent");
        let (parent_thread_id, parent_thread) = harness
            .start_thread_with_auth_manager(parent_auth_manager.clone())
            .await;

        let child_thread_id = harness
            .control
            .spawn_agent(
                harness.config.clone(),
                text_input("hello child"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                })),
            )
            .await
            .expect("child spawn should succeed");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        assert!(Arc::ptr_eq(
            &parent_thread.codex.session.services.auth_manager,
            &child_thread.codex.session.services.auth_manager,
        ));
        assert!(Arc::ptr_eq(
            &parent_auth_manager,
            &child_thread.codex.session.services.auth_manager,
        ));
    }

    #[tokio::test]
    async fn spawn_agent_fork_from_parent_history_uses_parent_thread_auth_manager() {
        let harness = AgentControlHarness::new().await;
        let parent_auth_manager =
            auth_manager_with_auth_file(&harness.config, &harness._home, "history-parent");
        let (parent_thread_id, parent_thread) = harness
            .start_thread_with_auth_manager(parent_auth_manager.clone())
            .await;
        let turn_context = parent_thread.codex.session.new_default_turn().await;
        let parent_spawn_call_id = "spawn-call-auth".to_string();
        let parent_spawn_call = ResponseItem::FunctionCall {
            id: None,
            name: "spawn_agent".to_string(),
            namespace: None,
            arguments: "{}".to_string(),
            call_id: parent_spawn_call_id.clone(),
        };
        parent_thread
            .codex
            .session
            .record_conversation_items(turn_context.as_ref(), &[parent_spawn_call])
            .await;
        parent_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        parent_thread.codex.session.flush_rollout().await;

        let child_thread_id = harness
            .control
            .spawn_agent_with_options(
                harness.config.clone(),
                text_input("child task"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: None,
                })),
                SpawnAgentOptions {
                    fork_parent_spawn_call_id: Some(parent_spawn_call_id),
                },
            )
            .await
            .expect("forked spawn should succeed");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        assert!(Arc::ptr_eq(
            &parent_thread.codex.session.services.auth_manager,
            &child_thread.codex.session.services.auth_manager,
        ));
        assert!(Arc::ptr_eq(
            &parent_auth_manager,
            &child_thread.codex.session.services.auth_manager,
        ));
    }

    #[tokio::test]
    async fn fork_agent_uses_parent_thread_auth_manager_when_parent_differs_from_manager_default() {
        let harness = AgentControlHarness::new().await;
        let parent_auth_manager =
            auth_manager_with_auth_file(&harness.config, &harness._home, "fork-parent");
        let (parent_thread_id, parent_thread) = harness
            .start_thread_with_auth_manager(parent_auth_manager.clone())
            .await;
        parent_thread
            .inject_user_message_without_turn("parent seed context".to_string())
            .await;
        parent_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        parent_thread.codex.session.flush_rollout().await;

        let child_thread_id = harness
            .control
            .fork_agent(
                harness.config.clone(),
                text_input("forked"),
                parent_thread_id,
                usize::MAX,
                SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                }),
            )
            .await
            .expect("fork_agent should succeed");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        assert!(Arc::ptr_eq(
            &parent_thread.codex.session.services.auth_manager,
            &child_thread.codex.session.services.auth_manager,
        ));
        assert!(Arc::ptr_eq(
            &parent_auth_manager,
            &child_thread.codex.session.services.auth_manager,
        ));
    }

    #[tokio::test]
    async fn fork_agent_uses_parent_thread_auth_file_from_rollout_when_parent_missing_in_memory() {
        let harness = AgentControlHarness::new().await;
        let parent_auth_manager =
            auth_manager_with_auth_file(&harness.config, &harness._home, "fork-parent-disk");
        let (parent_thread_id, parent_thread) = harness
            .start_thread_with_auth_manager(parent_auth_manager.clone())
            .await;
        parent_thread
            .inject_user_message_without_turn("parent seed context".to_string())
            .await;
        parent_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        parent_thread.codex.session.flush_rollout().await;
        let _ = harness.manager.remove_thread(&parent_thread_id).await;

        let child_thread_id = harness
            .control
            .fork_agent(
                harness.config.clone(),
                text_input("forked"),
                parent_thread_id,
                usize::MAX,
                SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                }),
            )
            .await
            .expect("fork_agent should succeed");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        assert_eq!(
            child_thread
                .codex
                .session
                .services
                .auth_manager
                .auth_file_override()
                .map(std::path::Path::to_path_buf),
            parent_auth_manager
                .auth_file_override()
                .map(std::path::Path::to_path_buf),
        );
    }

    #[tokio::test]
    #[serial(codex_api_key)]
    async fn fork_agent_uses_manager_default_auth_when_parent_rollout_has_no_auth_file() {
        let _guard = EnvVarGuard::set(crate::auth::CODEX_API_KEY_ENV_VAR, "sk-env-parent");
        let (home, config) = test_config().await;
        let default_auth_manager = AuthManager::shared(
            config.codex_home.clone(),
            true,
            AuthCredentialsStoreMode::File,
        );
        let manager = ThreadManager::new(
            &config,
            default_auth_manager.clone(),
            SessionSource::default(),
            crate::models_manager::collaboration_mode_presets::CollaborationModesConfig::default(),
        );
        let control = manager.agent_control();

        let parent_thread = manager
            .start_thread(config.clone())
            .await
            .expect("start parent thread");
        parent_thread
            .thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        parent_thread.thread.codex.session.flush_rollout().await;
        let _ = manager.remove_thread(&parent_thread.thread_id).await;

        let child_thread_id = control
            .fork_agent(
                config.clone(),
                text_input("forked"),
                parent_thread.thread_id,
                usize::MAX,
                SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: parent_thread.thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                }),
            )
            .await
            .expect("fork_agent should succeed");

        let child_thread = manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        assert!(Arc::ptr_eq(
            &default_auth_manager,
            &child_thread.codex.session.services.auth_manager,
        ));
        assert!(
            child_thread
                .codex
                .session
                .services
                .auth_manager
                .auth_cached()
                .is_some(),
            "child should retain env-backed auth through the default manager fallback"
        );

        let _ = control.shutdown_agent(child_thread_id).await;
        drop(home);
    }

    #[tokio::test]
    async fn spawn_thread_subagent_uses_role_specific_nickname_candidates() {
        let mut harness = AgentControlHarness::new().await;
        harness.config.agent_roles.insert(
            "researcher".to_string(),
            AgentRoleConfig {
                description: Some("Research role".to_string()),
                model: None,
                config_file: None,
                spawn_mode: None,
                nickname_candidates: Some(vec!["Atlas".to_string()]),
            },
        );
        let (parent_thread_id, _parent_thread) = harness.start_thread().await;

        let child_thread_id = harness
            .control
            .spawn_agent(
                harness.config.clone(),
                text_input("hello child"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("researcher".to_string()),
                })),
            )
            .await
            .expect("child spawn should succeed");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        let snapshot = child_thread.config_snapshot().await;

        let SessionSource::SubAgent(SubAgentSource::ThreadSpawn { agent_nickname, .. }) =
            snapshot.session_source
        else {
            panic!("expected thread-spawn sub-agent source");
        };
        assert_eq!(agent_nickname, Some("Atlas".to_string()));
    }

    #[tokio::test]
    async fn resume_thread_subagent_preserves_supplied_nickname_and_role() {
        let (_home, config) = test_config().await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();
        let harness = AgentControlHarness {
            _home,
            config,
            manager,
            control,
        };
        let (parent_thread_id, _parent_thread) = harness.start_thread().await;

        let child_thread_id = harness
            .control
            .spawn_agent(
                harness.config.clone(),
                text_input("hello child"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                })),
            )
            .await
            .expect("child spawn should succeed");

        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should exist");
        child_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        child_thread.flush_rollout().await;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let rollout_path = crate::find_thread_path_by_id_str(
                    harness.config.codex_home.as_path(),
                    &child_thread_id.to_string(),
                )
                .await
                .expect("rollout lookup should succeed");
                if rollout_path.is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("child thread rollout should be discoverable before shutdown");
        let original_snapshot = child_thread.config_snapshot().await;
        let original_nickname = original_snapshot
            .session_source
            .get_nickname()
            .expect("spawned sub-agent should have a nickname");

        let _ = harness
            .control
            .shutdown_agent(child_thread_id)
            .await
            .expect("child shutdown should submit");

        let resumed_thread_id = harness
            .control
            .resume_agent_from_rollout(
                harness.config.clone(),
                child_thread_id,
                SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: Some(original_nickname.clone()),
                    agent_role: Some("explorer".to_string()),
                }),
            )
            .await
            .expect("resume should succeed");
        assert_eq!(resumed_thread_id, child_thread_id);

        let resumed_snapshot = harness
            .manager
            .get_thread(resumed_thread_id)
            .await
            .expect("resumed child thread should exist")
            .config_snapshot()
            .await;
        let SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id: resumed_parent_thread_id,
            depth: resumed_depth,
            agent_nickname,
            agent_role,
        }) = resumed_snapshot.session_source
        else {
            panic!("expected resumed thread-spawn sub-agent source");
        };
        assert_eq!(resumed_parent_thread_id, parent_thread_id);
        assert_eq!(resumed_depth, 1);
        assert_eq!(agent_nickname, Some(original_nickname));
        assert_eq!(agent_role, Some("explorer".to_string()));
    }

    #[tokio::test]
    async fn resume_agent_uses_parent_thread_auth_manager_when_parent_differs_from_manager_default()
    {
        let harness = AgentControlHarness::new().await;
        let parent_auth_manager =
            auth_manager_with_auth_file(&harness.config, &harness._home, "resume-parent");
        let (parent_thread_id, parent_thread) = harness
            .start_thread_with_auth_manager(parent_auth_manager.clone())
            .await;
        let child_thread_id = harness
            .control
            .spawn_agent(
                harness.config.clone(),
                text_input("hello child"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                })),
            )
            .await
            .expect("child spawn should succeed");
        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should exist");
        child_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        child_thread.flush_rollout().await;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let rollout_path = crate::find_thread_path_by_id_str(
                    harness.config.codex_home.as_path(),
                    &child_thread_id.to_string(),
                )
                .await
                .expect("rollout lookup should succeed");
                if rollout_path.is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("resumable thread rollout should be discoverable before shutdown");
        let _ = harness
            .control
            .shutdown_agent(child_thread_id)
            .await
            .expect("shutdown child thread");

        let resumed_thread_id = harness
            .control
            .resume_agent_from_rollout(
                harness.config.clone(),
                child_thread_id,
                SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                }),
            )
            .await
            .expect("resume should succeed");

        let resumed_thread = harness
            .manager
            .get_thread(resumed_thread_id)
            .await
            .expect("resumed child thread should exist");
        assert!(Arc::ptr_eq(
            &parent_thread.codex.session.services.auth_manager,
            &resumed_thread.codex.session.services.auth_manager,
        ));
        assert!(Arc::ptr_eq(
            &parent_auth_manager,
            &resumed_thread.codex.session.services.auth_manager,
        ));
    }

    #[tokio::test]
    async fn resume_agent_uses_parent_thread_auth_file_from_rollout_when_parent_missing_in_memory()
    {
        let harness = AgentControlHarness::new().await;
        let parent_auth_manager =
            auth_manager_with_auth_file(&harness.config, &harness._home, "resume-parent-disk");
        let (parent_thread_id, parent_thread) = harness
            .start_thread_with_auth_manager(parent_auth_manager.clone())
            .await;
        parent_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        parent_thread.codex.session.flush_rollout().await;
        let child_thread_id = harness
            .control
            .spawn_agent(
                harness.config.clone(),
                text_input("hello child"),
                Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                })),
            )
            .await
            .expect("child spawn should succeed");
        let child_thread = harness
            .manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should exist");
        child_thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        child_thread.flush_rollout().await;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let rollout_path = crate::find_thread_path_by_id_str(
                    harness.config.codex_home.as_path(),
                    &child_thread_id.to_string(),
                )
                .await
                .expect("rollout lookup should succeed");
                if rollout_path.is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("resumable thread rollout should be discoverable before shutdown");
        let _ = harness
            .control
            .shutdown_agent(child_thread_id)
            .await
            .expect("shutdown child thread");
        let _ = harness.manager.remove_thread(&parent_thread_id).await;

        let resumed_thread_id = harness
            .control
            .resume_agent_from_rollout(
                harness.config.clone(),
                child_thread_id,
                SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                }),
            )
            .await
            .expect("resume should succeed");

        let resumed_thread = harness
            .manager
            .get_thread(resumed_thread_id)
            .await
            .expect("resumed child thread should exist");
        assert_eq!(
            resumed_thread
                .codex
                .session
                .services
                .auth_manager
                .auth_file_override()
                .map(std::path::Path::to_path_buf),
            parent_auth_manager
                .auth_file_override()
                .map(std::path::Path::to_path_buf),
        );
    }

    #[tokio::test]
    async fn fork_agent_rebases_relative_parent_auth_file_to_parent_session_cwd() {
        let (_home, mut config) = test_config().await;
        let parent_cwd = tempfile::tempdir().expect("parent cwd");
        config.cwd = parent_cwd.path().to_path_buf();
        let relative_auth_file = PathBuf::from("relative/auth.json");
        let parent_auth_manager = AuthManager::shared_with_auth_file(
            config.codex_home.clone(),
            false,
            AuthCredentialsStoreMode::File,
            Some(relative_auth_file.clone()),
        )
        .expect("relative auth manager");
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();
        let parent_thread = manager
            .resume_thread_with_history(
                config.clone(),
                InitialHistory::New,
                parent_auth_manager,
                false,
            )
            .await
            .expect("start parent thread");
        parent_thread
            .thread
            .codex
            .session
            .ensure_rollout_materialized()
            .await;
        parent_thread.thread.codex.session.flush_rollout().await;
        let _ = manager.remove_thread(&parent_thread.thread_id).await;

        let child_thread_id = control
            .fork_agent(
                config.clone(),
                text_input("forked"),
                parent_thread.thread_id,
                usize::MAX,
                SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id: parent_thread.thread_id,
                    depth: 1,
                    agent_nickname: None,
                    agent_role: Some("explorer".to_string()),
                }),
            )
            .await
            .expect("fork_agent should succeed");

        let child_thread = manager
            .get_thread(child_thread_id)
            .await
            .expect("child thread should be registered");
        assert_eq!(
            child_thread
                .codex
                .session
                .services
                .auth_manager
                .auth_file_override()
                .map(std::path::Path::to_path_buf),
            Some(parent_cwd.path().join(relative_auth_file)),
        );

        let _ = control.shutdown_agent(child_thread_id).await;
    }

    #[test]
    fn build_agent_inbox_items_tool_role_prepends_empty_user_message_when_requested() {
        let sender_thread_id = ThreadId::new();
        let message = "ping".to_string();

        let items = build_agent_inbox_items(
            CollabInboxDeliveryRole::Tool,
            sender_thread_id,
            None,
            None,
            message,
            true,
        )
        .expect("tool role should build inbox items");

        assert_eq!(items.len(), 2);
        match &items[0] {
            ResponseInputItem::Message { role, content } => {
                assert_eq!(role, "user");
                assert_eq!(
                    content,
                    &vec![ContentItem::InputText {
                        text: String::new()
                    }]
                );
            }
            other => panic!("expected prepended user message, got {other:?}"),
        }
        assert_matches!(&items[1], ResponseInputItem::FunctionCallOutput { .. });
    }

    #[test]
    fn build_agent_inbox_items_assistant_role_prepends_empty_user_message_when_requested() {
        let sender_thread_id = ThreadId::new();
        let message = "hello".to_string();

        let items = build_agent_inbox_items(
            CollabInboxDeliveryRole::Assistant,
            sender_thread_id,
            None,
            None,
            message,
            true,
        )
        .expect("assistant role should build inbox items");

        assert_eq!(items.len(), 2);
        match &items[0] {
            ResponseInputItem::Message { role, content } => {
                assert_eq!(role, "user");
                assert_eq!(
                    content,
                    &vec![ContentItem::InputText {
                        text: String::new()
                    }]
                );
            }
            other => panic!("expected prepended user message, got {other:?}"),
        }
        match &items[1] {
            ResponseInputItem::Message { role, .. } => assert_eq!(role, "assistant"),
            other => panic!("expected assistant message, got {other:?}"),
        }
    }

    #[test]
    fn build_agent_inbox_items_developer_role_prepends_empty_user_message_when_requested() {
        let sender_thread_id = ThreadId::new();
        let message = "hello".to_string();

        let items = build_agent_inbox_items(
            CollabInboxDeliveryRole::Developer,
            sender_thread_id,
            None,
            None,
            message,
            true,
        )
        .expect("developer role should build inbox items");

        assert_eq!(items.len(), 2);
        match &items[0] {
            ResponseInputItem::Message { role, content } => {
                assert_eq!(role, "user");
                assert_eq!(
                    content,
                    &vec![ContentItem::InputText {
                        text: String::new()
                    }]
                );
            }
            other => panic!("expected prepended user message, got {other:?}"),
        }
        match &items[1] {
            ResponseInputItem::Message { role, .. } => assert_eq!(role, "developer"),
            other => panic!("expected developer message, got {other:?}"),
        }
    }
}
