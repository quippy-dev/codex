use crate::agent::AgentStatus;
use crate::agent::WatchdogParentCompactionResult;
use crate::codex::Session;
use crate::codex::TurnContext;
use crate::config::Config;
use crate::error::CodexErr;
use crate::function_tool::FunctionCallError;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::handlers::parse_arguments;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;
use async_trait::async_trait;
use codex_features::Feature;
use codex_protocol::ThreadId;
use codex_protocol::models::BaseInstructions;
use codex_protocol::openai_models::ModelInfo;
use codex_protocol::openai_models::ModelPreset;
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::protocol::AgentSpawnMode;
use codex_protocol::protocol::CollabAgentInteractionBeginEvent;
use codex_protocol::protocol::CollabAgentInteractionEndEvent;
use codex_protocol::protocol::CollabAgentRef;
use codex_protocol::protocol::CollabAgentSpawnBeginEvent;
use codex_protocol::protocol::CollabAgentSpawnEndEvent;
use codex_protocol::protocol::CollabAgentStatusEntry;
use codex_protocol::protocol::CollabCloseBeginEvent;
use codex_protocol::protocol::CollabCloseEndEvent;
use codex_protocol::protocol::CollabCloseResult;
use codex_protocol::protocol::CollabResumeBeginEvent;
use codex_protocol::protocol::CollabResumeEndEvent;
use codex_protocol::protocol::CollabWaitingBeginEvent;
use codex_protocol::protocol::CollabWaitingEndEvent;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::user_input::UserInput;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::HashSet;

pub struct MultiAgentHandler;
pub(crate) struct SpawnAgentHandler;
pub(crate) struct SendInputHandler;
pub(crate) struct ResumeAgentHandler;
pub(crate) struct WaitAgentHandler;
pub(crate) struct CloseAgentHandler;

/// Minimum wait timeout to prevent tight polling loops from burning CPU.
pub(crate) const MIN_WAIT_TIMEOUT_MS: i64 = 10_000;
pub(crate) const DEFAULT_WAIT_TIMEOUT_MS: i64 = 30_000;
pub(crate) const MAX_WAIT_TIMEOUT_MS: i64 = 3600 * 1000;

#[derive(Debug, Deserialize)]
struct CloseAgentArgs {
    id: String,
}

#[async_trait]
impl ToolHandler for MultiAgentHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    fn matches_kind(&self, payload: &ToolPayload) -> bool {
        matches!(payload, ToolPayload::Function { .. })
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation {
            session,
            turn,
            tool_name,
            payload,
            call_id,
            ..
        } = invocation;

        let arguments = match payload {
            ToolPayload::Function { arguments } => arguments,
            _ => {
                return Err(FunctionCallError::RespondToModel(
                    "multi-agent handler received unsupported payload".to_string(),
                ));
            }
        };

        match tool_name.as_str() {
            "spawn_agent" => spawn::handle(session, turn, call_id, arguments).await,
            "send_input" => send_input::handle(session, turn, call_id, arguments).await,
            "resume_agent" => resume_agent::handle(session, turn, call_id, arguments).await,
            "compact_parent_context" if !turn.config.features.enabled(Feature::AgentWatchdog) => {
                Err(FunctionCallError::RespondToModel(
                    "watchdogs are disabled".to_string(),
                ))
            }
            "compact_parent_context" => {
                compact_parent_context::handle(session, turn, call_id, arguments).await
            }
            "list_agents" => list_agents::handle(session, turn, call_id, arguments).await,
            "peek_agents" => peek_agents::handle(session, turn, call_id, arguments).await,
            "wait" | "wait_agent" => wait::handle(session, turn, call_id, arguments).await,
            "close_agent" => close_agent::handle(session, turn, call_id, arguments).await,
            other => Err(FunctionCallError::RespondToModel(format!(
                "unsupported multi-agent tool {other}"
            ))),
        }
    }
}

fn function_arguments(payload: ToolPayload) -> Result<String, FunctionCallError> {
    match payload {
        ToolPayload::Function { arguments } => Ok(arguments),
        _ => Err(FunctionCallError::RespondToModel(
            "collab handler received unsupported payload".to_string(),
        )),
    }
}

macro_rules! impl_forwarding_handler {
    ($handler:ident, $call:path) => {
        #[async_trait]
        impl ToolHandler for $handler {
            type Output = FunctionToolOutput;

            fn kind(&self) -> ToolKind {
                ToolKind::Function
            }

            fn matches_kind(&self, payload: &ToolPayload) -> bool {
                matches!(payload, ToolPayload::Function { .. })
            }

            async fn handle(
                &self,
                invocation: ToolInvocation,
            ) -> Result<Self::Output, FunctionCallError> {
                let ToolInvocation {
                    session,
                    turn,
                    payload,
                    call_id,
                    ..
                } = invocation;
                let arguments = function_arguments(payload)?;
                $call(session, turn, call_id, arguments).await
            }
        }
    };
}

impl_forwarding_handler!(SpawnAgentHandler, spawn::handle);
impl_forwarding_handler!(SendInputHandler, send_input::handle);
impl_forwarding_handler!(ResumeAgentHandler, resume_agent::handle);
impl_forwarding_handler!(WaitAgentHandler, wait::handle);
impl_forwarding_handler!(CloseAgentHandler, close_agent::handle);

mod spawn {
    use super::*;
    use crate::agent::AgentControl;
    use crate::agent::WatchdogRegistration;
    use crate::agent::control::SpawnAgentOptions;
    use crate::agent::exceeds_thread_spawn_depth_limit;
    use crate::agent::next_thread_spawn_depth;
    use crate::agent::role::DEFAULT_ROLE_NAME;
    use crate::agent::role::apply_role_to_config;
    use crate::agent::role::default_spawn_mode_for_role;
    use crate::config::AgentRoleSpawnMode;
    use crate::config::Config;
    use codex_protocol::protocol::SessionSource;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tracing::info;

    #[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
    #[serde(rename_all = "snake_case")]
    enum SpawnMode {
        #[default]
        Spawn,
        Fork,
        Watchdog,
    }

    #[derive(Debug, Deserialize)]
    struct SpawnAgentArgs {
        message: Option<String>,
        items: Option<Vec<UserInput>>,
        agent_type: Option<String>,
        model: Option<String>,
        reasoning_effort: Option<ReasoningEffort>,
        interval_s: Option<i64>,
        #[serde(default)]
        fork_context: bool,
        #[serde(alias = "mode")]
        spawn_mode: Option<SpawnMode>,
    }

    #[derive(Debug, Serialize)]
    struct SpawnAgentResult {
        agent_id: String,
        nickname: Option<String>,
    }

    impl From<SpawnMode> for AgentSpawnMode {
        fn from(value: SpawnMode) -> Self {
            match value {
                SpawnMode::Spawn => AgentSpawnMode::Spawn,
                SpawnMode::Fork => AgentSpawnMode::Fork,
                SpawnMode::Watchdog => AgentSpawnMode::Watchdog,
            }
        }
    }

    pub async fn handle(
        session: Arc<Session>,
        turn: Arc<TurnContext>,
        call_id: String,
        arguments: String,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        let args: SpawnAgentArgs = parse_arguments(&arguments)?;
        if let Some(model) = args.model.as_deref()
            && model.trim().is_empty()
        {
            return Err(FunctionCallError::RespondToModel(
                "model must be non-empty when provided".to_string(),
            ));
        }
        let role_name = args
            .agent_type
            .as_deref()
            .map(str::trim)
            .filter(|role| !role.is_empty());
        let role_name_owned = role_name.map(str::to_string);
        let requested_model = args.model.clone();
        let requested_reasoning_effort = args.reasoning_effort;
        let default_spawn_mode = match default_spawn_mode_for_role(turn.config.as_ref(), role_name)
        {
            AgentRoleSpawnMode::Spawn => SpawnMode::Spawn,
            AgentRoleSpawnMode::Fork => SpawnMode::Fork,
        };
        let requested_spawn_mode = args.spawn_mode.unwrap_or(default_spawn_mode);
        let spawn_mode = if args.fork_context {
            match requested_spawn_mode {
                SpawnMode::Watchdog => {
                    return Err(FunctionCallError::RespondToModel(
                        "fork_context cannot be used with spawn_mode = \"watchdog\"".to_string(),
                    ));
                }
                _ => SpawnMode::Fork,
            }
        } else {
            requested_spawn_mode
        };
        let input_items = parse_multi_agent_input(args.message, args.items)?;
        let prompt = input_preview(&input_items);
        let session_source = turn.session_source.clone();
        let child_depth = next_thread_spawn_depth(&session_source);
        if matches!(spawn_mode, SpawnMode::Watchdog)
            && !turn.config.features.enabled(Feature::AgentWatchdog)
        {
            return Err(FunctionCallError::RespondToModel(
                "watchdogs are disabled".to_string(),
            ));
        }
        if matches!(spawn_mode, SpawnMode::Watchdog)
            && matches!(session_source, SessionSource::SubAgent(_))
        {
            return Err(FunctionCallError::RespondToModel(
                "watchdogs can only be spawned by root agents".to_string(),
            ));
        }
        let max_depth = turn.config.agent_max_depth;
        if exceeds_thread_spawn_depth_limit(child_depth, max_depth) {
            return Err(FunctionCallError::RespondToModel(format!(
                "agent depth limit reached: max depth is {max_depth}"
            )));
        }
        session
            .send_event(
                &turn,
                CollabAgentSpawnBeginEvent {
                    call_id: call_id.clone(),
                    sender_thread_id: session.conversation_id,
                    prompt: prompt.clone(),
                    model: args.model.clone().unwrap_or_default(),
                    reasoning_effort: args.reasoning_effort.unwrap_or_default(),
                }
                .into(),
            )
            .await;
        let config_strategy = match spawn_mode {
            SpawnMode::Spawn => SpawnConfigStrategy::ContextFreeSpawn,
            SpawnMode::Fork | SpawnMode::Watchdog => SpawnConfigStrategy::ForkLike,
        };
        let mut config = build_agent_spawn_config(
            &session.get_base_instructions().await,
            turn.as_ref(),
            child_depth,
            config_strategy,
        )?;
        apply_spawn_agent_model_overrides(
            &session,
            turn.as_ref(),
            &mut config,
            requested_model.as_deref(),
            requested_reasoning_effort,
        )
        .await?;
        apply_role_to_config(&mut config, role_name)
            .await
            .map_err(FunctionCallError::RespondToModel)?;
        revalidate_spawn_agent_model_reasoning(&session, turn.as_ref(), &config).await?;
        apply_spawn_agent_runtime_overrides(&mut config, turn.as_ref())?;
        apply_spawn_agent_overrides(&mut config, child_depth);
        let spawn_source = thread_spawn_source_with_metadata(
            session.conversation_id,
            child_depth,
            None,
            role_name_owned,
        );
        let agent_control = &session.services.agent_control;
        let result = match spawn_mode {
            SpawnMode::Spawn => {
                agent_control
                    .spawn_agent_with_options(
                        config,
                        input_items,
                        Some(spawn_source),
                        SpawnAgentOptions {
                            fork_parent_spawn_call_id: None,
                        },
                    )
                    .await
            }
            SpawnMode::Fork => {
                agent_control
                    .spawn_agent_with_options(
                        config,
                        input_items,
                        Some(spawn_source),
                        SpawnAgentOptions {
                            fork_parent_spawn_call_id: Some(call_id.clone()),
                        },
                    )
                    .await
            }
            SpawnMode::Watchdog => {
                let interval_s = watchdog_interval(&config, args.interval_s)?;
                spawn_watchdog(
                    agent_control,
                    config,
                    prompt.clone(),
                    session.conversation_id,
                    child_depth,
                    interval_s,
                    spawn_source,
                )
                .await
            }
        }
        .map_err(multi_agent_spawn_error);
        let (new_thread_id, status) = match &result {
            Ok(thread_id) => (
                Some(*thread_id),
                session.services.agent_control.get_status(*thread_id).await,
            ),
            Err(_) => (None, AgentStatus::NotFound),
        };
        let agent_snapshot = match new_thread_id {
            Some(thread_id) => {
                session
                    .services
                    .agent_control
                    .get_agent_config_snapshot(thread_id)
                    .await
            }
            None => None,
        };
        let (new_agent_nickname, new_agent_role) = match new_thread_id {
            Some(thread_id) => session
                .services
                .agent_control
                .get_agent_nickname_and_role(thread_id)
                .await
                .unwrap_or((None, None)),
            None => (None, None),
        };
        let effective_model = agent_snapshot
            .as_ref()
            .map(|snapshot| snapshot.model.clone())
            .unwrap_or_else(|| requested_model.clone().unwrap_or_default());
        let effective_reasoning_effort = agent_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.reasoning_effort)
            .unwrap_or(requested_reasoning_effort.unwrap_or_default());
        let nickname = new_agent_nickname.clone();
        session
            .send_event(
                &turn,
                CollabAgentSpawnEndEvent {
                    call_id,
                    sender_thread_id: session.conversation_id,
                    new_thread_id,
                    new_agent_nickname,
                    new_agent_role,
                    prompt: prompt.clone(),
                    model: effective_model,
                    reasoning_effort: effective_reasoning_effort,
                    spawn_mode: spawn_mode.into(),
                    status,
                }
                .into(),
            )
            .await;
        let new_thread_id = result?;
        session
            .services
            .agent_control
            .record_prompt_preview(new_thread_id, &prompt)
            .await;
        let role_tag = role_name.unwrap_or(DEFAULT_ROLE_NAME);
        turn.session_telemetry
            .counter("codex.multi_agent.spawn", 1, &[("role", role_tag)]);

        let content = serde_json::to_string(&SpawnAgentResult {
            agent_id: new_thread_id.to_string(),
            nickname,
        })
        .map_err(|err| {
            FunctionCallError::Fatal(format!("failed to serialize spawn_agent result: {err}"))
        })?;

        Ok(FunctionToolOutput::from_text(content, Some(true)))
    }

    fn watchdog_interval(
        config: &Config,
        interval_override_s: Option<i64>,
    ) -> Result<i64, FunctionCallError> {
        let interval = interval_override_s.unwrap_or(config.watchdog_interval_s);
        if interval <= 0 {
            return Err(FunctionCallError::RespondToModel(
                "interval_s must be greater than zero".to_string(),
            ));
        }
        Ok(interval)
    }

    async fn spawn_watchdog(
        agent_control: &AgentControl,
        config: Config,
        prompt: String,
        owner_thread_id: ThreadId,
        child_depth: i32,
        interval_s: i64,
        spawn_source: SessionSource,
    ) -> crate::error::Result<ThreadId> {
        let target_thread_id = agent_control
            .spawn_agent_handle(config.clone(), Some(spawn_source))
            .await?;
        let superseded_before_register = agent_control
            .unregister_watchdogs_for_owner(owner_thread_id)
            .await;
        shutdown_removed_watchdogs(agent_control, superseded_before_register).await;
        let registration = WatchdogRegistration {
            owner_thread_id,
            target_thread_id,
            child_depth,
            interval_s,
            prompt,
            config,
        };
        let superseded_after_register = match agent_control.register_watchdog(registration).await {
            Ok(superseded_after_register) => superseded_after_register,
            Err(err) => {
                let _ = agent_control.shutdown_agent(target_thread_id).await;
                return Err(err);
            }
        };
        shutdown_removed_watchdogs(agent_control, superseded_after_register).await;
        Ok(target_thread_id)
    }

    async fn shutdown_removed_watchdogs(
        agent_control: &AgentControl,
        removed_watchdogs: Vec<crate::agent::RemovedWatchdog>,
    ) {
        let mut to_shutdown = HashSet::new();
        for removed in removed_watchdogs {
            to_shutdown.insert(removed.target_thread_id);
            if let Some(helper_id) = removed.active_helper_id {
                to_shutdown.insert(helper_id);
            }
        }
        let mut thread_ids = to_shutdown.into_iter().collect::<Vec<_>>();
        thread_ids.sort_by_key(ToString::to_string);
        if !thread_ids.is_empty() {
            info!(
                removed_thread_count = thread_ids.len(),
                "cleaning up superseded watchdog threads"
            );
        }
        for thread_id in thread_ids {
            info!(thread_id = %thread_id, "shutting down superseded watchdog thread");
            let _ = agent_control.shutdown_agent(thread_id).await;
        }
    }
}

mod send_input {
    use super::*;
    use std::sync::Arc;

    #[derive(Debug, Deserialize)]
    struct SendInputArgs {
        id: Option<String>,
        message: Option<String>,
        items: Option<Vec<UserInput>>,
        #[serde(default)]
        interrupt: bool,
    }

    #[derive(Debug, Serialize)]
    struct SendInputResult {
        submission_id: String,
    }

    pub async fn handle(
        session: Arc<Session>,
        turn: Arc<TurnContext>,
        call_id: String,
        arguments: String,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        let args: SendInputArgs = parse_arguments(&arguments)?;
        let receiver_thread_id = match args.id.as_deref().map(str::trim) {
            Some(id) if !id.is_empty() && !matches!(id, "parent" | "root") => agent_id(id)?,
            _ => session.parent_thread_id().await.ok_or_else(|| {
                FunctionCallError::RespondToModel(
                    "send_input requires an id when no parent agent is available".to_string(),
                )
            })?,
        };
        let watchdog_targets = session
            .services
            .agent_control
            .watchdog_targets(&[receiver_thread_id])
            .await;
        if watchdog_targets.contains(&receiver_thread_id) {
            return Err(FunctionCallError::RespondToModel(
                "send_input cannot target watchdog handles. Send the message to the parent/root agent instead."
                    .to_string(),
            ));
        }
        let input_items = parse_multi_agent_input(args.message, args.items)?;
        let prompt = input_preview(&input_items);
        let (receiver_agent_nickname, receiver_agent_role) = session
            .services
            .agent_control
            .get_agent_nickname_and_role(receiver_thread_id)
            .await
            .unwrap_or((None, None));
        if args.interrupt {
            session
                .services
                .agent_control
                .interrupt_agent(receiver_thread_id)
                .await
                .map_err(|err| multi_agent_tool_error(receiver_thread_id, err))?;
            let _ = session
                .services
                .agent_control
                .drop_pending_input(receiver_thread_id)
                .await
                .map_err(|err| multi_agent_tool_error(receiver_thread_id, err))?;
        }
        session
            .send_event(
                &turn,
                CollabAgentInteractionBeginEvent {
                    call_id: call_id.clone(),
                    sender_thread_id: session.conversation_id,
                    receiver_thread_id,
                    prompt: prompt.clone(),
                }
                .into(),
            )
            .await;
        let result = if let Some(message) = single_text_input(&input_items) {
            session
                .services
                .agent_control
                .send_agent_message(receiver_thread_id, session.conversation_id, message)
                .await
                .map_err(|err| multi_agent_tool_error(receiver_thread_id, err))
        } else {
            session
                .services
                .agent_control
                .send_input(receiver_thread_id, input_items)
                .await
                .map_err(|err| multi_agent_tool_error(receiver_thread_id, err))
        };
        let status = session
            .services
            .agent_control
            .get_status(receiver_thread_id)
            .await;
        session
            .send_event(
                &turn,
                CollabAgentInteractionEndEvent {
                    call_id,
                    sender_thread_id: session.conversation_id,
                    receiver_thread_id,
                    receiver_agent_nickname,
                    receiver_agent_role,
                    prompt: prompt.clone(),
                    status,
                }
                .into(),
            )
            .await;
        let submission_id = result?;
        session
            .services
            .agent_control
            .record_prompt_preview(receiver_thread_id, &prompt)
            .await;
        if session
            .services
            .agent_control
            .watchdog_owner_for_active_helper(session.conversation_id)
            .await
            == Some(receiver_thread_id)
        {
            session
                .services
                .agent_control
                .mark_watchdog_idle_episode_satisfied_for_helper(session.conversation_id)
                .await;
        }
        session.mark_turn_used_agent_send_input();

        let content = serde_json::to_string(&SendInputResult { submission_id }).map_err(|err| {
            FunctionCallError::Fatal(format!("failed to serialize send_input result: {err}"))
        })?;

        Ok(FunctionToolOutput::from_text(content, Some(true)))
    }
}

mod resume_agent {
    use super::*;
    use crate::agent::exceeds_thread_spawn_depth_limit;
    use crate::agent::next_thread_spawn_depth;
    use crate::rollout::RolloutRecorder;
    use crate::rollout::find_thread_path_by_id_str;
    use std::sync::Arc;

    #[derive(Debug, Deserialize)]
    struct ResumeAgentArgs {
        id: String,
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub(super) struct ResumeAgentResult {
        pub(super) status: AgentStatus,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub(super) struct RecordedResumeContext {
        pub(super) developer_instructions: Option<Option<String>>,
        pub(super) model: Option<String>,
        pub(super) reasoning_effort: Option<Option<ReasoningEffort>>,
    }

    pub async fn handle(
        session: Arc<Session>,
        turn: Arc<TurnContext>,
        call_id: String,
        arguments: String,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        let args: ResumeAgentArgs = parse_arguments(&arguments)?;
        let receiver_thread_id = agent_id(&args.id)?;
        let child_depth = next_thread_spawn_depth(&turn.session_source);
        let max_depth = turn.config.agent_max_depth;
        if exceeds_thread_spawn_depth_limit(child_depth, max_depth) {
            return Err(FunctionCallError::RespondToModel(format!(
                "agent depth limit reached: max depth is {max_depth}"
            )));
        }

        let (receiver_agent_nickname, receiver_agent_role) = session
            .services
            .agent_control
            .get_agent_nickname_and_role(receiver_thread_id)
            .await
            .unwrap_or((None, None));
        let receiver_spawn_mode = watchdog_ref_spawn_mode(
            &session
                .services
                .agent_control
                .watchdog_targets(&[receiver_thread_id])
                .await,
            receiver_thread_id,
        );
        session
            .send_event(
                &turn,
                CollabResumeBeginEvent {
                    call_id: call_id.clone(),
                    sender_thread_id: session.conversation_id,
                    receiver_thread_id,
                    receiver_agent_nickname: receiver_agent_nickname.clone(),
                    receiver_agent_role: receiver_agent_role.clone(),
                    receiver_spawn_mode,
                }
                .into(),
            )
            .await;

        let mut status = session
            .services
            .agent_control
            .get_status(receiver_thread_id)
            .await;
        let error = if matches!(status, AgentStatus::NotFound) {
            match try_resume_closed_agent(&session, &turn, receiver_thread_id, child_depth).await {
                Ok(resumed_status) => {
                    status = resumed_status;
                    None
                }
                Err(err) => {
                    status = session
                        .services
                        .agent_control
                        .get_status(receiver_thread_id)
                        .await;
                    Some(err)
                }
            }
        } else {
            None
        };
        let (receiver_agent_nickname, receiver_agent_role) = session
            .services
            .agent_control
            .get_agent_nickname_and_role(receiver_thread_id)
            .await
            .unwrap_or((receiver_agent_nickname, receiver_agent_role));

        session
            .send_event(
                &turn,
                CollabResumeEndEvent {
                    call_id,
                    sender_thread_id: session.conversation_id,
                    receiver_thread_id,
                    receiver_agent_nickname,
                    receiver_agent_role,
                    receiver_spawn_mode,
                    status: status.clone(),
                }
                .into(),
            )
            .await;

        if let Some(err) = error {
            return Err(err);
        }
        turn.session_telemetry
            .counter("codex.multi_agent.resume", 1, &[]);

        let content = serde_json::to_string(&ResumeAgentResult { status }).map_err(|err| {
            FunctionCallError::Fatal(format!("failed to serialize resume_agent result: {err}"))
        })?;

        Ok(FunctionToolOutput::from_text(content, Some(true)))
    }

    async fn try_resume_closed_agent(
        session: &Arc<Session>,
        turn: &Arc<TurnContext>,
        receiver_thread_id: ThreadId,
        child_depth: i32,
    ) -> Result<AgentStatus, FunctionCallError> {
        let recorded_resume_context =
            load_recorded_resume_context(turn.as_ref(), receiver_thread_id).await?;
        let config =
            build_agent_resume_config(turn.as_ref(), child_depth, &recorded_resume_context)?;
        let (agent_nickname, agent_role) = match crate::state_db::get_state_db(&turn.config).await {
            Some(state_db_ctx) => match state_db_ctx.get_thread(receiver_thread_id).await {
                Ok(Some(metadata)) => (metadata.agent_nickname, metadata.agent_role),
                Ok(None) | Err(_) => (None, None),
            },
            None => (None, None),
        };
        let resumed_thread_id = session
            .services
            .agent_control
            .resume_agent_from_rollout(
                config,
                receiver_thread_id,
                thread_spawn_source_with_metadata(
                    session.conversation_id,
                    child_depth,
                    agent_nickname,
                    agent_role,
                ),
            )
            .await
            .map_err(|err| multi_agent_tool_error(receiver_thread_id, err))?;

        Ok(session
            .services
            .agent_control
            .get_status(resumed_thread_id)
            .await)
    }

    async fn load_recorded_resume_context(
        turn: &TurnContext,
        receiver_thread_id: ThreadId,
    ) -> Result<RecordedResumeContext, FunctionCallError> {
        let rollout_path = find_thread_path_by_id_str(
            turn.config.codex_home.as_path(),
            &receiver_thread_id.to_string(),
        )
        .await
        .map_err(|err| {
            FunctionCallError::RespondToModel(format!(
                "failed to inspect recorded agent {receiver_thread_id}: {err}"
            ))
        })?;
        let Some(rollout_path) = rollout_path else {
            return Ok(RecordedResumeContext::default());
        };
        let initial_history = RolloutRecorder::get_rollout_history(rollout_path.as_path())
            .await
            .map_err(|err| {
                FunctionCallError::RespondToModel(format!(
                    "failed to load recorded agent {receiver_thread_id}: {err}"
                ))
            })?;
        let developer_instructions = initial_history
            .get_rollout_items()
            .into_iter()
            .rev()
            .find_map(|item| match item {
                codex_protocol::protocol::RolloutItem::TurnContext(context) => {
                    Some(context.developer_instructions)
                }
                _ => None,
            })
            .or_else(|| {
                initial_history
                    .forked_from_id()
                    .map(|_| turn.developer_instructions.clone())
            });
        let model = initial_history
            .get_rollout_items()
            .into_iter()
            .rev()
            .find_map(|item| match item {
                codex_protocol::protocol::RolloutItem::TurnContext(context) => Some(context.model),
                _ => None,
            });
        let reasoning_effort = initial_history
            .get_rollout_items()
            .into_iter()
            .rev()
            .find_map(|item| match item {
                codex_protocol::protocol::RolloutItem::TurnContext(context) => Some(context.effort),
                _ => None,
            });
        Ok(RecordedResumeContext {
            developer_instructions,
            model,
            reasoning_effort,
        })
    }
}

mod compact_parent_context {
    use super::*;
    use std::sync::Arc;

    #[derive(Debug, Deserialize)]
    struct CompactParentContextArgs {
        reason: Option<String>,
        evidence: Option<String>,
    }

    #[derive(Debug, Serialize)]
    struct CompactParentContextResult {
        parent_id: String,
        submission_id: String,
    }

    pub async fn handle(
        session: Arc<Session>,
        _turn: Arc<TurnContext>,
        _call_id: String,
        arguments: String,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        let args: CompactParentContextArgs = parse_arguments(&arguments)?;
        let _reason = args.reason.and_then(|reason| {
            let trimmed = reason.trim();
            (!trimmed.is_empty()).then_some(trimmed.to_string())
        });
        let _evidence = args.evidence.and_then(|evidence| {
            let trimmed = evidence.trim();
            (!trimmed.is_empty()).then_some(trimmed.to_string())
        });

        let helper_thread_id = session.conversation_id;
        let result = session
            .services
            .agent_control
            .compact_parent_for_watchdog_helper(helper_thread_id)
            .await
            .map_err(|err| multi_agent_tool_error(helper_thread_id, err))?;

        let (parent_thread_id, submission_id) = match result {
            WatchdogParentCompactionResult::NotWatchdogHelper => {
                return Err(FunctionCallError::RespondToModel(
                    "compact_parent_context is only available to active watchdog helpers"
                        .to_string(),
                ));
            }
            WatchdogParentCompactionResult::ParentBusy { parent_thread_id } => {
                return Err(FunctionCallError::RespondToModel(format!(
                    "parent agent {parent_thread_id} has an active turn; compact_parent_context requires an idle parent"
                )));
            }
            WatchdogParentCompactionResult::AlreadyInProgress { parent_thread_id } => {
                return Err(FunctionCallError::RespondToModel(format!(
                    "parent agent {parent_thread_id} already has a compaction in progress"
                )));
            }
            WatchdogParentCompactionResult::Submitted {
                parent_thread_id,
                submission_id,
            } => (parent_thread_id, submission_id),
        };

        let content = serde_json::to_string(&CompactParentContextResult {
            parent_id: parent_thread_id.to_string(),
            submission_id,
        })
        .map_err(|err| {
            FunctionCallError::Fatal(format!(
                "failed to serialize compact_parent_context result: {err}"
            ))
        })?;

        Ok(FunctionToolOutput::from_text(content, Some(true)))
    }
}

mod list_agents {
    use super::*;
    use std::sync::Arc;

    #[derive(Debug, Deserialize)]
    struct ListAgentsArgs {
        id: Option<String>,
        #[serde(default = "default_recursive")]
        recursive: bool,
        #[serde(default)]
        all: bool,
    }

    #[derive(Debug, Serialize)]
    struct ListAgentsResult {
        agents: Vec<ListAgentEntry>,
    }

    #[derive(Debug, Serialize)]
    struct ListAgentEntry {
        id: String,
        parent_id: String,
        status: AgentStatus,
        depth: usize,
    }

    fn default_recursive() -> bool {
        true
    }

    pub async fn handle(
        session: Arc<Session>,
        _turn: Arc<TurnContext>,
        _call_id: String,
        arguments: String,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        let args: ListAgentsArgs = parse_arguments(&arguments)?;
        let owner_thread_id =
            resolve_owner_thread_id(session.as_ref(), args.id.as_deref().map(str::trim)).await?;

        let listings = session
            .services
            .agent_control
            .list_agents(owner_thread_id, args.recursive, args.all)
            .await
            .map_err(multi_agent_spawn_error)?;

        let agents = listings
            .into_iter()
            .map(|entry| ListAgentEntry {
                id: entry.thread_id.to_string(),
                parent_id: entry
                    .parent_thread_id
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                status: entry.status,
                depth: entry.depth,
            })
            .collect();

        let content = serde_json::to_string(&ListAgentsResult { agents }).map_err(|err| {
            FunctionCallError::Fatal(format!("failed to serialize list_agents result: {err}"))
        })?;

        Ok(FunctionToolOutput::from_text(content, Some(true)))
    }
}

mod peek_agents {
    use super::*;
    use crate::agent::AgentProgressSnapshot;
    use std::sync::Arc;

    const DEFAULT_PEEK_LIMIT: usize = 20;
    const MAX_PEEK_LIMIT: usize = 200;

    #[derive(Debug, Deserialize)]
    struct PeekAgentsArgs {
        id: Option<String>,
        #[serde(default = "default_recursive")]
        recursive: bool,
        cursor: Option<u64>,
        limit: Option<usize>,
    }

    #[derive(Debug, Serialize)]
    struct PeekAgentsResult {
        agents: Vec<PeekAgentEntry>,
        next_cursor: u64,
    }

    #[derive(Debug, Serialize)]
    struct PeekAgentEntry {
        id: String,
        parent_id: String,
        status: AgentStatus,
        depth: usize,
        cursor: u64,
        prompt_preview: Option<String>,
        reasoning_summary: Option<String>,
        latest_message_preview: Option<String>,
        terminal_summary: Option<String>,
    }

    fn default_recursive() -> bool {
        true
    }

    pub async fn handle(
        session: Arc<Session>,
        _turn: Arc<TurnContext>,
        _call_id: String,
        arguments: String,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        let args: PeekAgentsArgs = parse_arguments(&arguments)?;
        let owner_thread_id =
            resolve_owner_thread_id(session.as_ref(), args.id.as_deref().map(str::trim)).await?;
        let listings = session
            .services
            .agent_control
            .list_agents(owner_thread_id, args.recursive, /*all*/ false)
            .await
            .map_err(multi_agent_spawn_error)?;
        let thread_ids = listings
            .iter()
            .map(|entry| entry.thread_id)
            .collect::<Vec<_>>();
        let progress_by_thread = session
            .services
            .agent_control
            .progress_snapshots(&thread_ids)
            .await;
        let max_selected_cursor = progress_by_thread
            .values()
            .map(|snapshot| snapshot.cursor)
            .max()
            .unwrap_or_default();
        let cursor = args.cursor.unwrap_or_default();
        let limit = args
            .limit
            .unwrap_or(DEFAULT_PEEK_LIMIT)
            .clamp(1, MAX_PEEK_LIMIT);
        let incremental = args.cursor.is_some();

        let mut agents = listings
            .into_iter()
            .filter_map(|entry| {
                let progress = progress_by_thread.get(&entry.thread_id).cloned();
                let snapshot_cursor = progress
                    .as_ref()
                    .map(|snapshot| snapshot.cursor)
                    .unwrap_or_default();
                if incremental && snapshot_cursor <= cursor {
                    return None;
                }
                Some(build_peek_agent_entry(entry, progress))
            })
            .collect::<Vec<_>>();
        if incremental {
            agents.sort_by(|left, right| {
                left.cursor
                    .cmp(&right.cursor)
                    .then(left.id.cmp(&right.id))
                    .then(left.depth.cmp(&right.depth))
            });
        } else {
            agents.sort_by(|left, right| {
                right
                    .cursor
                    .cmp(&left.cursor)
                    .then(left.id.cmp(&right.id))
                    .then(left.depth.cmp(&right.depth))
            });
        }
        let truncated = agents.len() > limit;
        agents.truncate(limit);

        let next_cursor = if truncated {
            if incremental {
                agents
                    .last()
                    .map(|entry| entry.cursor)
                    .unwrap_or(max_selected_cursor.max(cursor))
            } else {
                max_selected_cursor.max(cursor)
            }
        } else {
            max_selected_cursor.max(cursor)
        };
        let content = serde_json::to_string(&PeekAgentsResult {
            agents,
            next_cursor,
        })
        .map_err(|err| {
            FunctionCallError::Fatal(format!("failed to serialize peek_agents result: {err}"))
        })?;

        Ok(FunctionToolOutput::from_text(content, Some(true)))
    }

    fn build_peek_agent_entry(
        listing: crate::agent::control::AgentListing,
        progress: Option<AgentProgressSnapshot>,
    ) -> PeekAgentEntry {
        let AgentProgressSnapshot {
            cursor,
            prompt_preview,
            reasoning_summary,
            latest_message_preview,
            terminal_summary,
        } = progress.unwrap_or_default();
        PeekAgentEntry {
            id: listing.thread_id.to_string(),
            parent_id: listing
                .parent_thread_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            status: listing.status,
            depth: listing.depth,
            cursor,
            prompt_preview,
            reasoning_summary,
            latest_message_preview,
            terminal_summary,
        }
    }
}

pub(crate) mod wait {
    use super::*;
    use crate::agent::status::is_final;
    use futures::FutureExt;
    use futures::StreamExt;
    use futures::stream::FuturesUnordered;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::watch::Receiver;
    use tokio::time::Instant;

    use tokio::time::timeout_at;

    #[derive(Debug, Deserialize)]
    struct WaitArgs {
        ids: Vec<String>,
        timeout_ms: Option<i64>,
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub(crate) struct WaitResult {
        pub(crate) status: HashMap<ThreadId, AgentStatus>,
        pub(crate) timed_out: bool,
    }

    #[cfg(test)]
    pub(crate) type WaitAgentResult = WaitResult;

    pub async fn handle(
        session: Arc<Session>,
        turn: Arc<TurnContext>,
        call_id: String,
        arguments: String,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        if let Some(owner_thread_id) = session
            .services
            .agent_control
            .watchdog_owner_for_active_helper(session.conversation_id)
            .await
        {
            return Err(FunctionCallError::RespondToModel(format!(
                "wait is not available to watchdog check-in agents. This thread is a one-shot watchdog check-in for owner {owner_thread_id}. Send the result to the parent/root agent with `send_input`. A successful watchdog handoff wakes the owner into a real follow-up turn. If you finish without `send_input`, runtime will forward your conclusory message to the owner as the mandatory fallback wake-up path. After a successful handoff, exit quietly and do not add extra completion narration."
            )));
        }
        let args: WaitArgs = parse_arguments(&arguments)?;
        if args.ids.is_empty() {
            return Err(FunctionCallError::RespondToModel(
                "ids must be non-empty".to_owned(),
            ));
        }
        let requested_thread_ids = args
            .ids
            .iter()
            .map(|id| agent_id(id))
            .collect::<Result<Vec<_>, _>>()?;
        let watchdog_target_ids = session
            .services
            .agent_control
            .watchdog_targets(&requested_thread_ids)
            .await;
        let event_receiver_thread_ids = requested_thread_ids.clone();
        let mut receiver_agents = Vec::with_capacity(event_receiver_thread_ids.len());
        for receiver_thread_id in &event_receiver_thread_ids {
            let (agent_nickname, agent_role) = session
                .services
                .agent_control
                .get_agent_nickname_and_role(*receiver_thread_id)
                .await
                .unwrap_or((None, None));
            receiver_agents.push(CollabAgentRef {
                thread_id: *receiver_thread_id,
                agent_nickname,
                agent_role,
                spawn_mode: watchdog_ref_spawn_mode(&watchdog_target_ids, *receiver_thread_id),
            });
        }
        let mut receiver_thread_ids = Vec::new();
        let mut watchdog_statuses = Vec::new();
        split_wait_ids(
            &session,
            requested_thread_ids,
            &watchdog_target_ids,
            &mut receiver_thread_ids,
            &mut watchdog_statuses,
        )
        .await;

        // Validate timeout.
        let timeout_ms = args.timeout_ms.unwrap_or(DEFAULT_WAIT_TIMEOUT_MS);
        let timeout_ms = match timeout_ms {
            ms if ms <= 0 => {
                return Err(FunctionCallError::RespondToModel(
                    "timeout_ms must be greater than zero".to_owned(),
                ));
            }
            ms => ms.clamp(MIN_WAIT_TIMEOUT_MS, MAX_WAIT_TIMEOUT_MS),
        };

        session
            .send_event(
                &turn,
                CollabWaitingBeginEvent {
                    sender_thread_id: session.conversation_id,
                    receiver_thread_ids: event_receiver_thread_ids,
                    receiver_agents: receiver_agents.clone(),
                    call_id: call_id.clone(),
                }
                .into(),
            )
            .await;

        if receiver_thread_ids.is_empty() {
            let statuses_map = watchdog_statuses.into_iter().collect::<HashMap<_, _>>();
            session
                .send_event(
                    &turn,
                    CollabWaitingEndEvent {
                        sender_thread_id: session.conversation_id,
                        call_id,
                        agent_statuses: build_wait_agent_statuses(&statuses_map, &receiver_agents),
                        statuses: statuses_map.clone(),
                    }
                    .into(),
                )
                .await;

            let content = serde_json::to_string(&WaitResult {
                status: statuses_map,
                timed_out: false,
            })
            .map_err(|err| {
                FunctionCallError::Fatal(format!("failed to serialize wait result: {err}"))
            })?;

            return Err(FunctionCallError::RespondToModel(format!(
                "wait cannot be used to wait for watchdog check-ins. You passed only watchdog handle ids. Watchdog check-ins happen only after the current turn ends and the owner thread is idle for at least the watchdog interval. Each idle stretch allows at most one successful watchdog handoff; failed runs may retry while the owner stays idle until one succeeds. `wait` on a watchdog handle is status-only and cannot confirm a new check-in. Do not poll with `wait`, `list_agents`, or shell `sleep`: the owner thread is still active during this turn, so those calls cannot make the watchdog fire. Do not call `wait` again on this watchdog handle in this turn. Continue the task now or end the turn so the watchdog can check in later. Current watchdog handle statuses: {content}"
            )));
        }

        let mut status_rxs = Vec::with_capacity(receiver_thread_ids.len());
        let mut initial_final_statuses = Vec::new();
        for id in &receiver_thread_ids {
            match session.services.agent_control.subscribe_status(*id).await {
                Ok(rx) => {
                    let status = rx.borrow().clone();
                    if let Some(final_status) =
                        observed_wait_final_status(&session, *id, status).await
                    {
                        initial_final_statuses.push((*id, final_status));
                    }
                    status_rxs.push((*id, rx));
                }
                Err(CodexErr::ThreadNotFound(_)) => {
                    initial_final_statuses.push((*id, AgentStatus::NotFound));
                }
                Err(err) => {
                    let mut statuses = HashMap::with_capacity(1 + watchdog_statuses.len());
                    statuses.insert(*id, session.services.agent_control.get_status(*id).await);
                    statuses.extend(watchdog_statuses.iter().cloned());
                    session
                        .send_event(
                            &turn,
                            CollabWaitingEndEvent {
                                sender_thread_id: session.conversation_id,
                                call_id: call_id.clone(),
                                agent_statuses: build_wait_agent_statuses(
                                    &statuses,
                                    &receiver_agents,
                                ),
                                statuses,
                            }
                            .into(),
                        )
                        .await;
                    return Err(multi_agent_tool_error(*id, err));
                }
            }
        }

        let statuses = if !initial_final_statuses.is_empty() {
            initial_final_statuses
        } else {
            // Wait for the first agent to reach a final status.
            let mut futures = FuturesUnordered::new();
            for (id, rx) in status_rxs.into_iter() {
                let session = session.clone();
                futures.push(wait_for_final_status(session, id, rx));
            }
            let mut results = Vec::new();
            let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
            loop {
                match timeout_at(deadline, futures.next()).await {
                    Ok(Some(Some(result))) => {
                        results.push(result);
                        break;
                    }
                    Ok(Some(None)) => continue,
                    Ok(None) | Err(_) => break,
                }
            }
            if !results.is_empty() {
                // Drain the unlikely last elements to prevent race.
                loop {
                    match futures.next().now_or_never() {
                        Some(Some(Some(result))) => results.push(result),
                        Some(Some(None)) => continue,
                        Some(None) | None => break,
                    }
                }
            }
            results
        };

        // Convert payload.
        let wait_timed_out = statuses.is_empty();
        let mut statuses_with_watchdogs = statuses;
        statuses_with_watchdogs.extend(watchdog_statuses);
        let statuses_map = statuses_with_watchdogs
            .into_iter()
            .collect::<HashMap<_, _>>();
        let agent_statuses = build_wait_agent_statuses(&statuses_map, &receiver_agents);
        let result = WaitResult {
            status: statuses_map.clone(),
            timed_out: wait_timed_out,
        };

        // Final event emission.
        session
            .send_event(
                &turn,
                CollabWaitingEndEvent {
                    sender_thread_id: session.conversation_id,
                    call_id,
                    agent_statuses,
                    statuses: statuses_map,
                }
                .into(),
            )
            .await;

        let content = serde_json::to_string(&result).map_err(|err| {
            FunctionCallError::Fatal(format!("failed to serialize wait result: {err}"))
        })?;

        Ok(FunctionToolOutput::from_text(content, None))
    }

    // Pub only for tests. Do not use.
    pub(super) async fn wait_for_final_status(
        session: Arc<Session>,
        thread_id: ThreadId,
        mut status_rx: Receiver<AgentStatus>,
    ) -> Option<(ThreadId, AgentStatus)> {
        let status = status_rx.borrow().clone();
        if let Some(final_status) = observed_wait_final_status(&session, thread_id, status).await {
            return Some((thread_id, final_status));
        }

        loop {
            if status_rx.changed().await.is_err() {
                let latest = session.services.agent_control.get_status(thread_id).await;
                return observed_wait_final_status(&session, thread_id, latest)
                    .await
                    .map(|final_status| (thread_id, final_status));
            }
            let status = status_rx.borrow().clone();
            if let Some(final_status) =
                observed_wait_final_status(&session, thread_id, status).await
            {
                return Some((thread_id, final_status));
            }
        }
    }

    async fn observed_wait_final_status(
        session: &Arc<Session>,
        thread_id: ThreadId,
        observed_status: AgentStatus,
    ) -> Option<AgentStatus> {
        let follow_up_status = if matches!(&observed_status, AgentStatus::Errored(reason) if reason == "Interrupted")
        {
            Some(session.services.agent_control.get_status(thread_id).await)
        } else {
            None
        };
        finalized_wait_status(observed_status, follow_up_status)
    }

    fn finalized_wait_status(
        observed_status: AgentStatus,
        follow_up_status: Option<AgentStatus>,
    ) -> Option<AgentStatus> {
        if !is_final(&observed_status) {
            return None;
        }
        if !matches!(&observed_status, AgentStatus::Errored(reason) if reason == "Interrupted") {
            return Some(observed_status);
        }

        let Some(follow_up_status) = follow_up_status else {
            return Some(observed_status);
        };
        if matches!(
            &follow_up_status,
            AgentStatus::PendingInit | AgentStatus::Running
        ) {
            return None;
        }

        Some(follow_up_status)
    }

    async fn split_wait_ids(
        session: &Arc<Session>,
        requested_thread_ids: Vec<ThreadId>,
        watchdog_target_ids: &HashSet<ThreadId>,
        receiver_thread_ids: &mut Vec<ThreadId>,
        watchdog_statuses: &mut Vec<(ThreadId, AgentStatus)>,
    ) {
        for thread_id in requested_thread_ids {
            if watchdog_target_ids.contains(&thread_id) {
                let status = session.services.agent_control.get_status(thread_id).await;
                watchdog_statuses.push((thread_id, status));
            } else {
                receiver_thread_ids.push(thread_id);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::finalized_wait_status;
        use codex_protocol::protocol::AgentStatus;
        use pretty_assertions::assert_eq;

        #[test]
        fn interrupted_follow_up_running_is_treated_as_non_final() {
            assert_eq!(
                finalized_wait_status(
                    AgentStatus::Errored("Interrupted".to_string()),
                    Some(AgentStatus::Running),
                ),
                None
            );
        }

        #[test]
        fn interrupted_follow_up_pending_init_is_treated_as_non_final() {
            assert_eq!(
                finalized_wait_status(
                    AgentStatus::Errored("Interrupted".to_string()),
                    Some(AgentStatus::PendingInit),
                ),
                None
            );
        }

        #[test]
        fn interrupted_follow_up_final_status_wins() {
            assert_eq!(
                finalized_wait_status(
                    AgentStatus::Errored("Interrupted".to_string()),
                    Some(AgentStatus::Shutdown),
                ),
                Some(AgentStatus::Shutdown)
            );
        }

        #[test]
        fn non_interrupted_error_is_unchanged() {
            assert_eq!(
                finalized_wait_status(
                    AgentStatus::Errored("boom".to_string()),
                    Some(AgentStatus::Running),
                ),
                Some(AgentStatus::Errored("boom".to_string()))
            );
        }
    }
}

fn build_wait_agent_statuses(
    statuses: &HashMap<ThreadId, AgentStatus>,
    receiver_agents: &[CollabAgentRef],
) -> Vec<CollabAgentStatusEntry> {
    if statuses.is_empty() {
        return Vec::new();
    }

    let mut entries = Vec::with_capacity(statuses.len());
    let mut seen = HashMap::with_capacity(receiver_agents.len());
    for receiver_agent in receiver_agents {
        seen.insert(receiver_agent.thread_id, ());
        if let Some(status) = statuses.get(&receiver_agent.thread_id) {
            entries.push(CollabAgentStatusEntry {
                thread_id: receiver_agent.thread_id,
                agent_nickname: receiver_agent.agent_nickname.clone(),
                agent_role: receiver_agent.agent_role.clone(),
                spawn_mode: receiver_agent.spawn_mode,
                status: status.clone(),
            });
        }
    }

    let mut extras = statuses
        .iter()
        .filter(|(thread_id, _)| !seen.contains_key(thread_id))
        .map(|(thread_id, status)| CollabAgentStatusEntry {
            thread_id: *thread_id,
            agent_nickname: None,
            agent_role: None,
            spawn_mode: None,
            status: status.clone(),
        })
        .collect::<Vec<_>>();
    extras.sort_by_key(|left| left.thread_id.to_string());
    entries.extend(extras);
    entries
}

fn watchdog_ref_spawn_mode(
    watchdog_target_ids: &HashSet<ThreadId>,
    receiver_thread_id: ThreadId,
) -> Option<AgentSpawnMode> {
    watchdog_target_ids
        .contains(&receiver_thread_id)
        .then_some(AgentSpawnMode::Watchdog)
}

async fn resolve_owner_thread_id(
    session: &Session,
    owner_alias: Option<&str>,
) -> Result<ThreadId, FunctionCallError> {
    match owner_alias {
        Some("parent") => Ok(session
            .parent_thread_id()
            .await
            .unwrap_or(session.conversation_id)),
        Some("root") => Ok(session
            .services
            .agent_control
            .resolve_root_thread_id(session.conversation_id)
            .await),
        Some(alias) if !alias.is_empty() && !matches!(alias, "self") => agent_id(alias),
        _ => Ok(session.conversation_id),
    }
}

pub mod close_agent {
    use super::*;
    use crate::rollout::find_thread_path_by_id_str;
    use std::sync::Arc;

    #[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    pub(super) enum CloseAgentOutcome {
        Closed,
        AlreadyClosed,
        NotFound,
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
    pub(super) struct CloseAgentResult {
        pub(super) status: AgentStatus,
        pub(super) close_result: CloseAgentOutcome,
    }

    fn not_found_outcome(was_known: bool) -> CloseAgentOutcome {
        if was_known {
            CloseAgentOutcome::AlreadyClosed
        } else {
            CloseAgentOutcome::NotFound
        }
    }

    fn event_close_result(outcome: CloseAgentOutcome) -> CollabCloseResult {
        match outcome {
            CloseAgentOutcome::Closed => CollabCloseResult::Closed,
            CloseAgentOutcome::AlreadyClosed => CollabCloseResult::AlreadyClosed,
            CloseAgentOutcome::NotFound => CollabCloseResult::NotFound,
        }
    }

    pub async fn handle(
        session: Arc<Session>,
        turn: Arc<TurnContext>,
        call_id: String,
        arguments: String,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        let args: CloseAgentArgs = parse_arguments(&arguments)?;
        let agent_id = agent_id(&args.id)?;
        let status_before = session.services.agent_control.get_status(agent_id).await;
        let (receiver_agent_nickname, receiver_agent_role) = session
            .services
            .agent_control
            .get_agent_nickname_and_role(agent_id)
            .await
            .unwrap_or((None, None));
        let receiver_spawn_mode = watchdog_ref_spawn_mode(
            &session
                .services
                .agent_control
                .watchdog_targets(&[agent_id])
                .await,
            agent_id,
        );
        let mut was_known = if matches!(status_before, AgentStatus::NotFound) {
            let listed = session
                .services
                .agent_control
                .list_agents(session.conversation_id, true, true)
                .await
                .map(|agents| agents.into_iter().any(|agent| agent.thread_id == agent_id))
                .unwrap_or(false);
            let spawned = session.services.agent_control.was_spawned_thread(agent_id);
            let recorded = find_thread_path_by_id_str(turn.config.codex_home.as_path(), &args.id)
                .await
                .map(|path| path.is_some())
                .unwrap_or(false);
            listed || spawned || recorded
        } else {
            true
        };
        session
            .send_event(
                &turn,
                CollabCloseBeginEvent {
                    call_id: call_id.clone(),
                    sender_thread_id: session.conversation_id,
                    receiver_thread_id: agent_id,
                }
                .into(),
            )
            .await;
        if let Err(err) = session
            .services
            .agent_control
            .subscribe_status(agent_id)
            .await
        {
            let removed_watchdog = session
                .services
                .agent_control
                .unregister_watchdog(agent_id)
                .await;
            if removed_watchdog.is_some() {
                was_known = true;
            }
            if let Some(helper_id) = removed_watchdog.and_then(|entry| entry.active_helper_id) {
                let _ = session
                    .services
                    .agent_control
                    .shutdown_agent(helper_id)
                    .await;
            }
            let _ = session
                .services
                .agent_control
                .shutdown_agent(agent_id)
                .await;
            let status = session.services.agent_control.get_status(agent_id).await;
            session
                .send_event(
                    &turn,
                    CollabCloseEndEvent {
                        call_id: call_id.clone(),
                        sender_thread_id: session.conversation_id,
                        receiver_thread_id: agent_id,
                        receiver_agent_nickname: receiver_agent_nickname.clone(),
                        receiver_agent_role: receiver_agent_role.clone(),
                        receiver_spawn_mode,
                        status: status.clone(),
                        close_result: event_close_result(not_found_outcome(was_known)),
                    }
                    .into(),
                )
                .await;
            return if matches!(err, CodexErr::ThreadNotFound(_)) {
                let content = serde_json::to_string(&CloseAgentResult {
                    status,
                    close_result: not_found_outcome(was_known),
                })
                .map_err(|serialize_err| {
                    FunctionCallError::Fatal(format!(
                        "failed to serialize close_agent result: {serialize_err}"
                    ))
                })?;

                Ok(FunctionToolOutput::from_text(content, Some(true)))
            } else {
                Err(multi_agent_tool_error(agent_id, err))
            };
        }
        let removed_watchdog = session
            .services
            .agent_control
            .unregister_watchdog(agent_id)
            .await;
        if removed_watchdog.is_some() {
            was_known = true;
        }
        if let Some(helper_id) = removed_watchdog.and_then(|entry| entry.active_helper_id) {
            let _ = session
                .services
                .agent_control
                .shutdown_agent(helper_id)
                .await;
        }
        let close_result = match session.services.agent_control.close_agent(agent_id).await {
            Ok(_) => Ok(CloseAgentOutcome::Closed),
            Err(CodexErr::ThreadNotFound(_)) | Err(CodexErr::InternalAgentDied) => {
                Ok(not_found_outcome(was_known))
            }
            Err(err) => Err(multi_agent_tool_error(agent_id, err)),
        };
        let status = match close_result {
            Ok(CloseAgentOutcome::Closed) => {
                session.services.agent_control.get_status(agent_id).await
            }
            Ok(CloseAgentOutcome::AlreadyClosed) | Ok(CloseAgentOutcome::NotFound) => {
                session.services.agent_control.get_status(agent_id).await
            }
            Err(_) => session.services.agent_control.get_status(agent_id).await,
        };
        let close_result = close_result?;
        session
            .send_event(
                &turn,
                CollabCloseEndEvent {
                    call_id,
                    sender_thread_id: session.conversation_id,
                    receiver_thread_id: agent_id,
                    receiver_agent_nickname,
                    receiver_agent_role,
                    receiver_spawn_mode,
                    status: status.clone(),
                    close_result: event_close_result(close_result),
                }
                .into(),
            )
            .await;

        let content = serde_json::to_string(&CloseAgentResult {
            status,
            close_result,
        })
        .map_err(|err| {
            FunctionCallError::Fatal(format!("failed to serialize close_agent result: {err}"))
        })?;

        Ok(FunctionToolOutput::from_text(content, Some(true)))
    }
}

fn agent_id(id: &str) -> Result<ThreadId, FunctionCallError> {
    ThreadId::from_string(id)
        .map_err(|e| FunctionCallError::RespondToModel(format!("invalid agent id {id}: {e:?}")))
}

fn multi_agent_spawn_error(err: CodexErr) -> FunctionCallError {
    match err {
        CodexErr::UnsupportedOperation(reason) if reason == "thread manager dropped" => {
            FunctionCallError::RespondToModel("multi-agent manager unavailable".to_string())
        }
        CodexErr::UnsupportedOperation(reason) => FunctionCallError::RespondToModel(reason),
        CodexErr::AgentLimitReached { max_threads } => FunctionCallError::RespondToModel(format!(
            "multi-agent spawn failed: agent thread limit reached (max {max_threads}). \
                 Close completed agents with close_agent (idempotent), or inspect tracked threads with \
                 list_agents(all=true)."
        )),
        err => FunctionCallError::RespondToModel(format!("multi-agent spawn failed: {err}")),
    }
}

fn multi_agent_tool_error(agent_id: ThreadId, err: CodexErr) -> FunctionCallError {
    match err {
        CodexErr::ThreadNotFound(id) => {
            FunctionCallError::RespondToModel(format!("agent with id {id} not found"))
        }
        CodexErr::InternalAgentDied => {
            FunctionCallError::RespondToModel(format!("agent with id {agent_id} is closed"))
        }
        CodexErr::UnsupportedOperation(_) => {
            FunctionCallError::RespondToModel("multi-agent manager unavailable".to_string())
        }
        err => FunctionCallError::RespondToModel(format!("multi-agent tool failed: {err}")),
    }
}

#[cfg(test)]
fn thread_spawn_source(parent_thread_id: ThreadId, depth: i32) -> SessionSource {
    thread_spawn_source_with_metadata(parent_thread_id, depth, None, None)
}

fn thread_spawn_source_with_metadata(
    parent_thread_id: ThreadId,
    depth: i32,
    agent_nickname: Option<String>,
    agent_role: Option<String>,
) -> SessionSource {
    SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id,
        depth,
        agent_path: None,
        agent_nickname,
        agent_role,
    })
}

fn parse_multi_agent_input(
    message: Option<String>,
    items: Option<Vec<UserInput>>,
) -> Result<Vec<UserInput>, FunctionCallError> {
    match (message, items) {
        (Some(_), Some(_)) => Err(FunctionCallError::RespondToModel(
            "Provide either message or items, but not both".to_string(),
        )),
        (None, None) => Err(FunctionCallError::RespondToModel(
            "Provide one of: message or items".to_string(),
        )),
        (Some(message), None) => {
            if message.trim().is_empty() {
                return Err(FunctionCallError::RespondToModel(
                    "Empty message can't be sent to an agent".to_string(),
                ));
            }
            Ok(vec![UserInput::Text {
                text: message,
                text_elements: Vec::new(),
            }])
        }
        (None, Some(items)) => {
            if items.is_empty() {
                return Err(FunctionCallError::RespondToModel(
                    "Items can't be empty".to_string(),
                ));
            }
            Ok(items)
        }
    }
}

fn input_preview(items: &[UserInput]) -> String {
    let parts: Vec<String> = items
        .iter()
        .map(|item| match item {
            UserInput::Text { text, .. } => text.clone(),
            UserInput::Image { .. } => "[image]".to_string(),
            UserInput::LocalImage { path } => format!("[local_image:{}]", path.display()),
            UserInput::Skill { name, path } => {
                format!("[skill:${name}]({})", path.display())
            }
            UserInput::Mention { name, path } => format!("[mention:${name}]({path})"),
            _ => "[input]".to_string(),
        })
        .collect();

    parts.join("\n")
}

fn single_text_input(items: &[UserInput]) -> Option<String> {
    match items {
        [UserInput::Text { text, .. }] => Some(text.clone()),
        _ => None,
    }
}

pub(crate) fn build_agent_spawn_config(
    base_instructions: &BaseInstructions,
    turn: &TurnContext,
    child_depth: i32,
    strategy: SpawnConfigStrategy,
) -> Result<Config, FunctionCallError> {
    let mut config = build_agent_shared_config(turn, child_depth)?;
    config.base_instructions = Some(base_instructions.text.clone());
    let base_config = turn.config.as_ref();
    match strategy {
        SpawnConfigStrategy::ContextFreeSpawn => {
            // Context-free subagents should use base config instructions.
            config.developer_instructions = base_config.developer_instructions.clone();
            // At or past max depth, a freshly spawned context-free child cannot expose
            // fanout tools for further descendants. Hide them at the capability boundary.
            if child_depth >= config.agent_max_depth {
                let _ = config.features.disable(Feature::SpawnCsv);
                let _ = config.features.disable(Feature::Collab);
            }
        }
        SpawnConfigStrategy::ForkLike => {
            // Fork/watchdog children should preserve turn-level developer context
            // to maximize prompt/cache parity with the parent thread.
            config.developer_instructions = turn.developer_instructions.clone();
        }
    }
    Ok(config)
}

fn build_agent_resume_config(
    turn: &TurnContext,
    child_depth: i32,
    recorded_resume_context: &resume_agent::RecordedResumeContext,
) -> Result<Config, FunctionCallError> {
    let mut config = build_agent_shared_config(turn, child_depth)?;
    // For resume, keep base instructions sourced from rollout/session metadata.
    config.base_instructions = None;
    if let Some(model) = recorded_resume_context.model.clone() {
        config.model = Some(model);
    }
    if let Some(reasoning_effort) = recorded_resume_context.reasoning_effort {
        config.model_reasoning_effort = reasoning_effort;
    }
    config.developer_instructions = match recorded_resume_context.developer_instructions.clone() {
        Some(developer_instructions) => developer_instructions,
        None => turn.config.developer_instructions.clone(),
    };
    apply_spawn_agent_runtime_overrides(&mut config, turn)?;
    apply_spawn_agent_overrides(&mut config, child_depth);
    Ok(config)
}

fn build_agent_shared_config(
    turn: &TurnContext,
    _child_depth: i32,
) -> Result<Config, FunctionCallError> {
    let base_config = turn.config.as_ref();
    let mut config = base_config.clone();
    config.model = Some(turn.model_info.slug.clone());
    config.model_provider = turn.provider.clone();
    config.model_reasoning_effort = turn.reasoning_effort;
    config.model_reasoning_summary = Some(turn.reasoning_summary);
    config.compact_prompt = turn.compact_prompt.clone();
    apply_spawn_agent_runtime_overrides(&mut config, turn)?;
    Ok(config)
}

fn apply_spawn_agent_runtime_overrides(
    config: &mut Config,
    turn: &TurnContext,
) -> Result<(), FunctionCallError> {
    config
        .permissions
        .approval_policy
        .set(turn.approval_policy.value())
        .map_err(|err| {
            FunctionCallError::RespondToModel(format!("approval_policy is invalid: {err}"))
        })?;
    config.permissions.shell_environment_policy = turn.shell_environment_policy.clone();
    config.codex_linux_sandbox_exe = turn.codex_linux_sandbox_exe.clone();
    config.cwd = turn.cwd.clone();
    config
        .permissions
        .sandbox_policy
        .set(turn.sandbox_policy.get().clone())
        .map_err(|err| {
            FunctionCallError::RespondToModel(format!("sandbox_policy is invalid: {err}"))
        })?;
    config.permissions.file_system_sandbox_policy = turn.file_system_sandbox_policy.clone();
    config.permissions.network_sandbox_policy = turn.network_sandbox_policy;
    Ok(())
}

fn apply_spawn_agent_overrides(config: &mut Config, child_depth: i32) {
    if child_depth >= config.agent_max_depth {
        let _ = config.features.disable(Feature::SpawnCsv);
        let _ = config.features.disable(Feature::Collab);
    }
}

async fn apply_spawn_agent_model_overrides(
    session: &Session,
    turn: &TurnContext,
    config: &mut Config,
    requested_model: Option<&str>,
    requested_reasoning_effort: Option<ReasoningEffort>,
) -> Result<(), FunctionCallError> {
    if let Some(model) = requested_model {
        let model_selection = resolve_spawn_agent_model_selection(session, config, model).await;
        let reasoning_effort =
            requested_reasoning_effort.or_else(|| model_selection.default_reasoning_effort());
        if let Some(reasoning_effort) = reasoning_effort {
            model_selection.validate_reasoning_effort(reasoning_effort)?;
        }
        config.model_provider_id = turn.config.model_provider_id.clone();
        config.model_provider = turn.provider.clone();
        config.model = Some(model_selection.model().to_string());
        config.model_reasoning_effort = reasoning_effort;
        return Ok(());
    }

    if let Some(reasoning_effort) = requested_reasoning_effort {
        validate_reasoning_effort_for_effective_model(session, turn, config, reasoning_effort)
            .await?;
        config.model_reasoning_effort = Some(reasoning_effort);
    }

    Ok(())
}

enum SpawnAgentModelSelection {
    Preset(ModelPreset),
    ModelInfo(ModelInfo),
}

impl SpawnAgentModelSelection {
    fn model(&self) -> &str {
        match self {
            Self::Preset(preset) => preset.model.as_str(),
            Self::ModelInfo(model_info) => model_info.slug.as_str(),
        }
    }

    fn default_reasoning_effort(&self) -> Option<ReasoningEffort> {
        match self {
            Self::Preset(preset) => Some(preset.default_reasoning_effort),
            Self::ModelInfo(model_info) => model_info.default_reasoning_level,
        }
    }

    fn validate_reasoning_effort(
        &self,
        reasoning_effort: ReasoningEffort,
    ) -> Result<(), FunctionCallError> {
        match self {
            Self::Preset(preset) => validate_reasoning_effort_for_preset(preset, reasoning_effort),
            Self::ModelInfo(model_info) => {
                validate_reasoning_effort_for_model_info(model_info, reasoning_effort)
            }
        }
    }
}

async fn resolve_spawn_agent_model_selection(
    session: &Session,
    config: &Config,
    model: &str,
) -> SpawnAgentModelSelection {
    if let Some(preset) = model_preset(session, model).await {
        return SpawnAgentModelSelection::Preset(preset);
    }
    let model_info = session
        .services
        .models_manager
        .get_model_info(model, config)
        .await;
    SpawnAgentModelSelection::ModelInfo(model_info)
}

async fn revalidate_spawn_agent_model_reasoning(
    session: &Session,
    turn: &TurnContext,
    config: &Config,
) -> Result<(), FunctionCallError> {
    if let Some(reasoning_effort) = config.model_reasoning_effort {
        validate_reasoning_effort_for_effective_model(session, turn, config, reasoning_effort)
            .await?;
    }
    Ok(())
}

async fn validate_reasoning_effort_for_effective_model(
    session: &Session,
    turn: &TurnContext,
    config: &Config,
    reasoning_effort: ReasoningEffort,
) -> Result<(), FunctionCallError> {
    let effective_model = config
        .model
        .clone()
        .unwrap_or_else(|| turn.model_info.slug.clone());
    if let Ok(preset) = visible_model_preset(session, effective_model.as_str()).await {
        return validate_reasoning_effort_for_preset(&preset, reasoning_effort);
    }
    let model_info = if effective_model == turn.model_info.slug {
        turn.model_info.clone()
    } else {
        session
            .services
            .models_manager
            .get_model_info(effective_model.as_str(), config)
            .await
    };
    validate_reasoning_effort_for_model_info(&model_info, reasoning_effort)
}

async fn visible_model_preset(
    session: &Session,
    model: &str,
) -> Result<ModelPreset, FunctionCallError> {
    let available_models = session
        .services
        .models_manager
        .list_models(crate::models_manager::manager::RefreshStrategy::Offline)
        .await;
    let visible_models = available_models
        .iter()
        .filter(|preset| preset.show_in_picker)
        .map(|preset| format!("`{}`", preset.model))
        .collect::<Vec<_>>()
        .join(", ");
    available_models
        .into_iter()
        .find(|preset| preset.show_in_picker && preset.model == model)
        .ok_or_else(|| {
            FunctionCallError::RespondToModel(format!(
                "spawn_agent model `{model}` is not available. Choose one of: {visible_models}"
            ))
        })
}

async fn model_preset(session: &Session, model: &str) -> Option<ModelPreset> {
    session
        .services
        .models_manager
        .list_models(crate::models_manager::manager::RefreshStrategy::Offline)
        .await
        .into_iter()
        .find(|preset| preset.model == model)
}

fn validate_reasoning_effort_for_preset(
    preset: &ModelPreset,
    reasoning_effort: ReasoningEffort,
) -> Result<(), FunctionCallError> {
    let supported_reasoning_efforts = preset
        .supported_reasoning_efforts
        .iter()
        .map(|effort| effort.effort)
        .collect::<Vec<_>>();
    validate_reasoning_effort(
        preset.model.as_str(),
        reasoning_effort,
        supported_reasoning_efforts.as_slice(),
    )
}

fn validate_reasoning_effort_for_model_info(
    model_info: &ModelInfo,
    reasoning_effort: ReasoningEffort,
) -> Result<(), FunctionCallError> {
    let supported_reasoning_efforts = model_info
        .supported_reasoning_levels
        .iter()
        .map(|effort| effort.effort)
        .collect::<Vec<_>>();
    validate_reasoning_effort(
        model_info.slug.as_str(),
        reasoning_effort,
        supported_reasoning_efforts.as_slice(),
    )
}

fn validate_reasoning_effort(
    model: &str,
    reasoning_effort: ReasoningEffort,
    supported_reasoning_efforts: &[ReasoningEffort],
) -> Result<(), FunctionCallError> {
    if supported_reasoning_efforts.contains(&reasoning_effort) {
        return Ok(());
    }

    let supported_reasoning = supported_reasoning_efforts
        .iter()
        .map(|effort| format!("`{effort}`"))
        .collect::<Vec<_>>()
        .join(", ");
    Err(FunctionCallError::RespondToModel(format!(
        "spawn_agent reasoning_effort `{reasoning_effort}` is not supported for model `{model}`. Choose one of: {supported_reasoning}"
    )))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpawnConfigStrategy {
    ContextFreeSpawn,
    ForkLike,
}

#[cfg(test)]
#[path = "multi_agents_tests.rs"]
mod tests;
