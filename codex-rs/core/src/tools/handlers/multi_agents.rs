use crate::agent::AgentStatus;
use crate::agent::WatchdogParentCompactionResult;
use crate::codex::Session;
use crate::codex::TurnContext;
use crate::config::Config;
use crate::error::CodexErr;
use crate::features::Feature;
use crate::function_tool::FunctionCallError;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::handlers::parse_arguments;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;
use async_trait::async_trait;
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
            "wait" => wait::handle(session, turn, call_id, arguments).await,
            "close_agent" => close_agent::handle(session, turn, call_id, arguments).await,
            other => Err(FunctionCallError::RespondToModel(format!(
                "unsupported multi-agent tool {other}"
            ))),
        }
    }
}

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
        let spawn_mode = args
            .spawn_mode
            .or_else(|| args.fork_context.then_some(SpawnMode::Fork))
            .unwrap_or(default_spawn_mode);
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
        apply_role_to_config(&mut config, role_name)
            .await
            .map_err(FunctionCallError::RespondToModel)?;
        if role_name.is_none() {
            apply_spawn_agent_model_overrides(
                &session,
                turn.as_ref(),
                &mut config,
                requested_model.as_deref(),
                requested_reasoning_effort,
            )
            .await?;
        }
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
        let (new_agent_nickname, new_agent_role) = match new_thread_id {
            Some(thread_id) => session
                .services
                .agent_control
                .get_agent_nickname_and_role(thread_id)
                .await
                .unwrap_or((None, None)),
            None => (None, None),
        };
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
                    prompt,
                    spawn_mode: spawn_mode.into(),
                    status,
                }
                .into(),
            )
            .await;
        let new_thread_id = result?;
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
                    prompt,
                    status,
                }
                .into(),
            )
            .await;
        let submission_id = result?;
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
        let owner_thread_id = match args.id.as_deref().map(str::trim) {
            Some(id) if !id.is_empty() && id == "parent" => session
                .parent_thread_id()
                .await
                .unwrap_or(session.conversation_id),
            Some(id) if !id.is_empty() && id == "root" => {
                session
                    .services
                    .agent_control
                    .resolve_root_thread_id(session.conversation_id)
                    .await
            }
            Some(id) if !id.is_empty() && !matches!(id, "self") => agent_id(id)?,
            _ => session.conversation_id,
        };

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
                "wait is not available to watchdog check-in agents. This thread is a one-shot watchdog check-in for owner {owner_thread_id}. Send the result to the parent/root agent with `send_input`. If you finish without `send_input`, runtime will forward your conclusory message to the owner as the mandatory fallback wake-up path. Exiting without either `send_input` or a final message is a bug; every watchdog check-in must wake the owner thread."
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
                "wait cannot be used to wait for watchdog check-ins. You passed only watchdog handle ids. Watchdog check-ins only happen after the current turn ends and the owner thread is idle for at least the watchdog interval. `wait` on a watchdog handle is status-only and cannot confirm a new check-in. Do not poll with `wait`, `list_agents`, or shell `sleep`: the owner thread is still active during this turn, so those calls cannot make the watchdog fire. Do not call `wait` again on this watchdog handle in this turn. Continue the task now or end the turn so the watchdog can check in later. Current watchdog handle statuses: {content}"
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
    extras.sort_by(|left, right| left.thread_id.to_string().cmp(&right.thread_id.to_string()));
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
        let close_result = match session
            .services
            .agent_control
            .shutdown_agent(agent_id)
            .await
        {
            Ok(_) => Ok(CloseAgentOutcome::Closed),
            Err(CodexErr::ThreadNotFound(_)) | Err(CodexErr::InternalAgentDied) => {
                Ok(not_found_outcome(was_known))
            }
            Err(err) => Err(multi_agent_tool_error(agent_id, err)),
        };
        let status = match close_result {
            Ok(CloseAgentOutcome::Closed) => status_before,
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
            // At max depth, a freshly spawned context-free child cannot spawn further descendants.
            // Hide multi-agent tools to match that capability boundary.
            if crate::agent::exceeds_thread_spawn_depth_limit(child_depth, config.agent_max_depth) {
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
    Ok(())
}

fn apply_spawn_agent_overrides(config: &mut Config, child_depth: i32) {
    if crate::agent::exceeds_thread_spawn_depth_limit(child_depth, config.agent_max_depth) {
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
        let preset = visible_model_preset(session, model).await?;
        let reasoning_effort =
            requested_reasoning_effort.unwrap_or(preset.default_reasoning_effort);
        validate_reasoning_effort_for_preset(&preset, reasoning_effort)?;
        config.model_provider_id = turn.config.model_provider_id.clone();
        config.model_provider = turn.provider.clone();
        config.model = Some(preset.model);
        config.model_reasoning_effort = Some(reasoning_effort);
        return Ok(());
    }

    if let Some(reasoning_effort) = requested_reasoning_effort {
        let effective_model = config
            .model
            .clone()
            .unwrap_or_else(|| turn.model_info.slug.clone());
        let model_info = if effective_model == turn.model_info.slug {
            turn.model_info.clone()
        } else {
            session
                .services
                .models_manager
                .get_model_info(effective_model.as_str(), config)
                .await
        };
        validate_reasoning_effort_for_model_info(&model_info, reasoning_effort)?;
        config.model_reasoning_effort = Some(reasoning_effort);
    }

    Ok(())
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
mod tests {
    use super::*;
    use crate::AuthManager;
    use crate::CodexAuth;
    use crate::ThreadManager;
    use crate::built_in_model_providers;
    use crate::codex::make_session_and_context;
    use crate::codex::make_session_and_context_with_rx;
    use crate::config::AgentRoleConfig;
    use crate::config::AgentRoleSpawnMode;
    use crate::config::types::ShellEnvironmentPolicy;
    use crate::features::Feature;
    use crate::function_tool::FunctionCallError;
    use crate::protocol::AskForApproval;
    use crate::protocol::ErrorEvent;
    use crate::protocol::Event;
    use crate::protocol::EventMsg;
    use crate::protocol::Op;
    use crate::protocol::SandboxPolicy;
    use crate::protocol::SessionSource;
    use crate::protocol::SubAgentSource;
    use crate::tools::context::FunctionToolOutput;
    use crate::turn_diff_tracker::TurnDiffTracker;
    use codex_protocol::ThreadId;
    use codex_protocol::models::ContentItem;
    use codex_protocol::models::ResponseItem;
    use codex_protocol::openai_models::ReasoningEffort;
    use codex_protocol::protocol::AgentSpawnMode;
    use codex_protocol::protocol::InitialHistory;
    use codex_protocol::protocol::RolloutItem;
    use codex_protocol::protocol::TurnContextItem;
    use pretty_assertions::assert_eq;
    use serde::Deserialize;
    use serde_json::json;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tokio::sync::watch;
    use tokio::time::timeout;

    fn invocation(
        session: Arc<crate::codex::Session>,
        turn: Arc<TurnContext>,
        tool_name: &str,
        payload: ToolPayload,
    ) -> ToolInvocation {
        ToolInvocation {
            session,
            turn,
            tracker: Arc::new(Mutex::new(TurnDiffTracker::default())),
            call_id: "call-1".to_string(),
            tool_name: tool_name.to_string(),
            payload,
        }
    }

    fn function_payload(args: serde_json::Value) -> ToolPayload {
        ToolPayload::Function {
            arguments: args.to_string(),
        }
    }

    #[derive(Debug, Deserialize)]
    struct SpawnAgentResultForTest {
        agent_id: String,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct ListAgentsResultForTest {
        agents: Vec<ListAgentEntryForTest>,
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct ListAgentEntryForTest {
        id: String,
        parent_id: String,
        status: AgentStatus,
        depth: usize,
    }

    async fn spawn_watchdog_for_test(
        session: Arc<crate::codex::Session>,
        turn: Arc<TurnContext>,
    ) -> ThreadId {
        let invocation = invocation(
            session,
            turn,
            "spawn_agent",
            function_payload(json!({
                "message": "watchdog check-in",
                "spawn_mode": "watchdog"
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("spawn_agent should succeed");
        let (content, _) = expect_text_output(output);
        let result: SpawnAgentResultForTest =
            serde_json::from_str(&content).expect("spawn result should be json");
        agent_id(&result.agent_id).expect("spawn result should contain a valid agent id")
    }

    fn thread_manager() -> ThreadManager {
        ThreadManager::with_models_provider_for_tests(
            CodexAuth::from_api_key("dummy"),
            built_in_model_providers()["openai"].clone(),
        )
    }

    async fn visible_models(session: &Session) -> Vec<ModelPreset> {
        session
            .services
            .models_manager
            .list_models(crate::models_manager::manager::RefreshStrategy::Offline)
            .await
            .into_iter()
            .filter(|preset| preset.show_in_picker)
            .collect()
    }

    fn expect_text_output(output: FunctionToolOutput) -> (String, Option<bool>) {
        (
            codex_protocol::models::function_call_output_content_items_to_text(&output.body)
                .unwrap_or_default(),
            output.success,
        )
    }

    #[tokio::test]
    async fn handler_rejects_non_function_payloads() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            ToolPayload::Custom {
                input: "hello".to_string(),
            },
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("payload should be rejected");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(
                "multi-agent handler received unsupported payload".to_string()
            )
        );
    }

    #[tokio::test]
    async fn handler_rejects_unknown_tool() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "unknown_tool",
            function_payload(json!({})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("tool should be rejected");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(
                "unsupported multi-agent tool unknown_tool".to_string()
            )
        );
    }

    #[tokio::test]
    async fn spawn_agent_rejects_empty_message() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({"message": "   "})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("empty message should be rejected");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(
                "Empty message can't be sent to an agent".to_string()
            )
        );
    }

    #[tokio::test]
    async fn spawn_agent_rejects_when_message_and_items_are_both_set() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "hello",
                "items": [{"type": "mention", "name": "drive", "path": "app://drive"}]
            })),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("message+items should be rejected");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(
                "Provide either message or items, but not both".to_string()
            )
        );
    }

    #[tokio::test]
    async fn spawn_agent_uses_explorer_role_and_sets_never_approval_policy() {
        #[derive(Debug, Deserialize)]
        struct SpawnAgentResult {
            agent_id: String,
            nickname: Option<String>,
        }

        let (mut session, mut turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let mut config = (*turn.config).clone();
        config
            .permissions
            .approval_policy
            .set(AskForApproval::OnRequest)
            .expect("approval policy should be set");
        turn.config = Arc::new(config);
        let expected_model = turn.model_info.slug.clone();

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "inspect this repo",
                "agent_type": "explorer"
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("spawn_agent should succeed");
        let (content, _) = expect_text_output(output);
        let result: SpawnAgentResult =
            serde_json::from_str(&content).expect("spawn_agent result should be json");
        let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
        assert!(
            result
                .nickname
                .as_deref()
                .is_some_and(|nickname| !nickname.is_empty())
        );
        let snapshot = manager
            .get_thread(agent_id)
            .await
            .expect("spawned agent thread should exist")
            .config_snapshot()
            .await;
        assert_eq!(snapshot.model, expected_model);
        assert_eq!(snapshot.approval_policy, AskForApproval::Never);
    }

    #[tokio::test]
    async fn spawn_agent_errors_when_manager_dropped() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({"message": "hello"})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("spawn should fail without a manager");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel("multi-agent manager unavailable".to_string())
        );
    }

    #[tokio::test]
    async fn spawn_agent_reapplies_runtime_sandbox_after_role_config() {
        fn pick_allowed_sandbox_policy(
            constraint: &crate::config::Constrained<SandboxPolicy>,
            base: SandboxPolicy,
        ) -> SandboxPolicy {
            let candidates = [
                SandboxPolicy::DangerFullAccess,
                SandboxPolicy::new_workspace_write_policy(),
                SandboxPolicy::new_read_only_policy(),
            ];
            candidates
                .into_iter()
                .find(|candidate| *candidate != base && constraint.can_set(candidate).is_ok())
                .unwrap_or(base)
        }

        #[derive(Debug, Deserialize)]
        struct SpawnAgentResult {
            agent_id: String,
            nickname: Option<String>,
        }

        let (mut session, mut turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let expected_sandbox = pick_allowed_sandbox_policy(
            &turn.config.permissions.sandbox_policy,
            turn.config.permissions.sandbox_policy.get().clone(),
        );
        turn.approval_policy
            .set(AskForApproval::OnRequest)
            .expect("approval policy should be set");
        turn.sandbox_policy
            .set(expected_sandbox.clone())
            .expect("sandbox policy should be set");
        assert_ne!(
            expected_sandbox,
            turn.config.permissions.sandbox_policy.get().clone(),
            "test requires a runtime sandbox override that differs from base config"
        );

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "await this command",
                "agent_type": "awaiter"
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("spawn_agent should succeed");
        let (content, _) = expect_text_output(output);
        let result: SpawnAgentResult =
            serde_json::from_str(&content).expect("spawn_agent result should be json");
        let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
        assert!(
            result
                .nickname
                .as_deref()
                .is_some_and(|nickname| !nickname.is_empty())
        );

        let snapshot = manager
            .get_thread(agent_id)
            .await
            .expect("spawned agent thread should exist")
            .config_snapshot()
            .await;
        assert_eq!(snapshot.sandbox_policy, expected_sandbox);
        assert_eq!(snapshot.approval_policy, AskForApproval::OnRequest);
    }

    #[tokio::test]
    async fn spawn_agent_rejects_when_depth_limit_exceeded() {
        let (mut session, mut turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let max_depth = turn.config.agent_max_depth;

        turn.session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id: session.conversation_id,
            depth: max_depth,
            agent_nickname: None,
            agent_role: None,
        });

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({"message": "hello"})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("spawn should fail when depth limit exceeded");
        };
        let FunctionCallError::RespondToModel(message) = err else {
            panic!("expected respond-to-model error");
        };
        assert!(message.contains("depth limit reached"));
    }

    #[tokio::test]
    async fn spawn_agent_allows_depth_up_to_configured_max_depth() {
        #[derive(Debug, Deserialize)]
        struct SpawnAgentResult {
            agent_id: String,
            nickname: Option<String>,
        }

        let (mut session, mut turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let current_max_depth = turn.config.agent_max_depth;

        let mut config = (*turn.config).clone();
        config.agent_max_depth = current_max_depth + 1;
        turn.config = Arc::new(config);
        turn.session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id: session.conversation_id,
            depth: current_max_depth,
            agent_nickname: None,
            agent_role: None,
        });

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({"message": "hello"})),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("spawn should succeed within configured depth");
        let (content, success) = expect_text_output(output);
        let result: SpawnAgentResult =
            serde_json::from_str(&content).expect("spawn_agent result should be json");
        assert!(!result.agent_id.is_empty());
        assert!(
            result
                .nickname
                .as_deref()
                .is_some_and(|nickname| !nickname.is_empty())
        );
        assert_eq!(success, Some(true));
    }

    #[tokio::test]
    async fn spawn_agent_accepts_watchdog_interval_override() {
        let (mut session, mut turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let mut config = (*turn.config).clone();
        let _ = config.features.enable(Feature::AgentWatchdog);
        turn.config = Arc::new(config);

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "watchdog check-in",
                "spawn_mode": "watchdog",
                "interval_s": 5
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("interval override should be accepted");
        let (_, success) = expect_text_output(output);
        assert_eq!(success, Some(true));
    }

    #[tokio::test]
    async fn spawn_agent_rejects_empty_model_override() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "inspect this repo",
                "model": "   "
            })),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("empty model override should be rejected");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel("model must be non-empty when provided".to_string())
        );
    }

    #[tokio::test]
    async fn spawn_agent_rejects_watchdog_from_subagent() {
        let (mut session, mut turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        turn.session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id: session.conversation_id,
            depth: 0,
            agent_nickname: None,
            agent_role: None,
        });

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "watchdog check-in",
                "spawn_mode": "watchdog"
            })),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("watchdog spawn should be rejected for subagents");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(
                "watchdogs can only be spawned by root agents".to_string()
            )
        );
    }

    #[tokio::test]
    async fn spawn_agent_rejects_watchdog_when_feature_disabled() {
        let (mut session, mut turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let mut config = (*turn.config).clone();
        let _ = config.features.disable(Feature::AgentWatchdog);
        turn.config = Arc::new(config);

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "watchdog check-in",
                "spawn_mode": "watchdog"
            })),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("watchdog spawn should be rejected when the feature is disabled");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel("watchdogs are disabled".to_string())
        );
    }

    #[tokio::test]
    async fn spawn_agent_role_model_beats_explicit_model_override() {
        #[derive(Debug, Deserialize)]
        struct SpawnAgentResult {
            agent_id: String,
        }

        let (mut session, mut turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        session.services.models_manager = manager.get_models_manager();
        let visible_models = visible_models(&session).await;
        let role_model = visible_models
            .iter()
            .find(|preset| {
                preset
                    .supported_reasoning_efforts
                    .iter()
                    .any(|effort| effort.effort == ReasoningEffort::High)
            })
            .expect("expected visible model with high reasoning support")
            .clone();
        let selected_model = visible_models
            .iter()
            .find(|preset| preset.model != role_model.model)
            .expect("expected second visible model")
            .clone();

        let role_dir = tempfile::tempdir().expect("temp dir");
        let role_path = role_dir.path().join("custom-role.toml");
        tokio::fs::write(
            &role_path,
            format!(
                "model = \"{}\"\nmodel_reasoning_effort = \"high\"\n",
                role_model.model
            ),
        )
        .await
        .expect("write role config");

        let mut config = (*turn.config).clone();
        config.agent_roles.insert(
            "custom".to_string(),
            AgentRoleConfig {
                description: None,
                model: None,
                config_file: Some(role_path),
                spawn_mode: None,
                nickname_candidates: None,
            },
        );
        turn.config = Arc::new(config);

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "inspect this repo",
                "agent_type": "custom",
                "model": selected_model.model,
                "reasoning_effort": "minimal"
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("spawn_agent should succeed");
        let (content, _) = expect_text_output(output);
        let result: SpawnAgentResult =
            serde_json::from_str(&content).expect("spawn_agent result should be json");
        let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
        let snapshot = manager
            .get_thread(agent_id)
            .await
            .expect("spawned agent thread should exist")
            .config_snapshot()
            .await;
        assert_eq!(snapshot.model, role_model.model);
        assert_eq!(snapshot.reasoning_effort, Some(ReasoningEffort::High));
    }

    #[tokio::test]
    async fn spawn_agent_omitted_spawn_mode_uses_role_default() {
        #[derive(Debug, Deserialize)]
        struct SpawnAgentResult {
            agent_id: String,
        }

        let (mut session, mut turn, rx) = make_session_and_context_with_rx().await;
        let manager = thread_manager();
        let owner_thread = manager
            .start_thread(turn.config.as_ref().clone())
            .await
            .expect("start owner thread");
        Arc::get_mut(&mut session)
            .expect("no extra session refs")
            .services
            .agent_control = manager.agent_control();
        Arc::get_mut(&mut session)
            .expect("no extra session refs")
            .conversation_id = owner_thread.thread_id;

        let mut config = (*turn.config).clone();
        config.agent_roles.insert(
            "custom".to_string(),
            AgentRoleConfig {
                description: Some("Fork by default".to_string()),
                model: None,
                config_file: None,
                spawn_mode: Some(AgentRoleSpawnMode::Fork),
                nickname_candidates: None,
            },
        );
        Arc::get_mut(&mut turn).expect("no extra turn refs").config = Arc::new(config);

        let invocation = invocation(
            session.clone(),
            turn.clone(),
            "spawn_agent",
            function_payload(json!({
                "message": "inspect this repo",
                "agent_type": "custom"
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("spawn_agent should succeed");
        let (content, _) = expect_text_output(output);
        let result: SpawnAgentResult =
            serde_json::from_str(&content).expect("spawn_agent result should be json");
        let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
        let spawn_event = timeout(Duration::from_secs(2), async {
            loop {
                let event = rx.recv().await.expect("collab event");
                if let EventMsg::CollabAgentSpawnEnd(event) = event.msg {
                    break event;
                }
            }
        })
        .await
        .expect("spawn end event should arrive");

        assert_eq!(spawn_event.spawn_mode, AgentSpawnMode::Fork);

        let _ = manager
            .agent_control()
            .shutdown_agent(agent_id)
            .await
            .expect("shutdown spawned agent");
        let _ = manager
            .agent_control()
            .shutdown_agent(owner_thread.thread_id)
            .await
            .expect("shutdown owner thread");
    }

    #[tokio::test]
    async fn spawn_agent_fork_context_defaults_spawn_mode_to_fork() {
        #[derive(Debug, Deserialize)]
        struct SpawnAgentResult {
            agent_id: String,
        }

        let (mut session, turn, rx) = make_session_and_context_with_rx().await;
        let manager = thread_manager();
        let owner_thread = manager
            .start_thread(turn.config.as_ref().clone())
            .await
            .expect("start owner thread");
        Arc::get_mut(&mut session)
            .expect("no extra session refs")
            .services
            .agent_control = manager.agent_control();
        Arc::get_mut(&mut session)
            .expect("no extra session refs")
            .conversation_id = owner_thread.thread_id;

        let invocation = invocation(
            session.clone(),
            turn.clone(),
            "spawn_agent",
            function_payload(json!({
                "message": "inspect this repo",
                "fork_context": true
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("spawn_agent should succeed");
        let (content, _) = expect_text_output(output);
        let result: SpawnAgentResult =
            serde_json::from_str(&content).expect("spawn_agent result should be json");
        let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
        let spawn_event = timeout(Duration::from_secs(2), async {
            loop {
                let event = rx.recv().await.expect("collab event");
                if let EventMsg::CollabAgentSpawnEnd(event) = event.msg {
                    break event;
                }
            }
        })
        .await
        .expect("spawn end event should arrive");

        assert_eq!(spawn_event.spawn_mode, AgentSpawnMode::Fork);

        let _ = manager
            .agent_control()
            .shutdown_agent(agent_id)
            .await
            .expect("shutdown spawned agent");
        let _ = manager
            .agent_control()
            .shutdown_agent(owner_thread.thread_id)
            .await
            .expect("shutdown owner thread");
    }

    #[tokio::test]
    async fn spawn_agent_applies_explicit_model_override() {
        #[derive(Debug, Deserialize)]
        struct SpawnAgentResult {
            agent_id: String,
            nickname: Option<String>,
        }

        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        session.services.models_manager = manager.get_models_manager();
        let visible_models = visible_models(&session).await;
        let selected_model = visible_models
            .iter()
            .find(|preset| preset.model != turn.model_info.slug)
            .unwrap_or_else(|| {
                panic!(
                    "expected visible model distinct from {}",
                    turn.model_info.slug
                )
            })
            .clone();

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "inspect this repo",
                "model": selected_model.model
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("spawn_agent should succeed");
        let (content, _) = expect_text_output(output);
        let result: SpawnAgentResult =
            serde_json::from_str(&content).expect("spawn_agent result should be json");
        assert!(
            result
                .nickname
                .as_deref()
                .is_some_and(|nickname| !nickname.is_empty())
        );
        let snapshot = manager
            .get_thread(agent_id(&result.agent_id).expect("agent_id should be valid"))
            .await
            .expect("spawned agent thread should exist")
            .config_snapshot()
            .await;
        assert_eq!(snapshot.model, selected_model.model);
        assert_eq!(
            snapshot.reasoning_effort,
            Some(selected_model.default_reasoning_effort)
        );
    }

    #[tokio::test]
    async fn spawn_agent_applies_explicit_reasoning_effort_override() {
        #[derive(Debug, Deserialize)]
        struct SpawnAgentResult {
            agent_id: String,
        }

        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        session.services.models_manager = manager.get_models_manager();
        let turn = if turn.model_info.supported_reasoning_levels.is_empty() {
            let selected_model = visible_models(&session)
                .await
                .into_iter()
                .find(|preset| !preset.supported_reasoning_efforts.is_empty())
                .expect("expected a visible model with reasoning support");
            turn.with_model(selected_model.model, &session.services.models_manager)
                .await
        } else {
            turn
        };
        let inherited_model = turn.model_info.slug.clone();
        let selected_effort = turn
            .model_info
            .supported_reasoning_levels
            .iter()
            .find(|preset| Some(preset.effort) != turn.reasoning_effort)
            .or_else(|| turn.model_info.supported_reasoning_levels.first())
            .map(|preset| preset.effort)
            .expect("expected at least one supported reasoning level");

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "inspect this repo",
                "reasoning_effort": selected_effort
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("spawn_agent should succeed");
        let (content, _) = expect_text_output(output);
        let result: SpawnAgentResult =
            serde_json::from_str(&content).expect("spawn_agent result should be json");
        let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
        let snapshot = manager
            .get_thread(agent_id)
            .await
            .expect("spawned agent thread should exist")
            .config_snapshot()
            .await;
        assert_eq!(snapshot.model, inherited_model);
        assert_eq!(snapshot.reasoning_effort, Some(selected_effort));
    }

    #[tokio::test]
    async fn spawn_agent_rejects_unknown_model_override() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        session.services.models_manager = manager.get_models_manager();
        let expected_visible_models = visible_models(&session)
            .await
            .into_iter()
            .map(|preset| format!("`{}`", preset.model))
            .collect::<Vec<_>>()
            .join(", ");

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "inspect this repo",
                "model": "definitely-not-a-real-model"
            })),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("unknown model should be rejected");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(format!(
                "spawn_agent model `definitely-not-a-real-model` is not available. Choose one of: {expected_visible_models}"
            ))
        );
    }

    #[tokio::test]
    async fn spawn_agent_rejects_unsupported_reasoning_effort_for_selected_model() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        session.services.models_manager = manager.get_models_manager();
        let candidate_efforts = [
            ReasoningEffort::None,
            ReasoningEffort::Minimal,
            ReasoningEffort::Low,
            ReasoningEffort::Medium,
            ReasoningEffort::High,
            ReasoningEffort::XHigh,
        ];
        let selected_model = visible_models(&session)
            .await
            .into_iter()
            .find(|preset| {
                candidate_efforts.iter().any(|candidate| {
                    !preset
                        .supported_reasoning_efforts
                        .iter()
                        .any(|effort| effort.effort == *candidate)
                })
            })
            .expect("expected a visible model without full reasoning coverage");
        let unsupported_effort = candidate_efforts
            .into_iter()
            .find(|candidate| {
                !selected_model
                    .supported_reasoning_efforts
                    .iter()
                    .any(|effort| effort.effort == *candidate)
            })
            .expect("expected unsupported effort");

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "spawn_agent",
            function_payload(json!({
                "message": "inspect this repo",
                "model": selected_model.model,
                "reasoning_effort": unsupported_effort,
            })),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("unsupported reasoning effort should be rejected");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(format!(
                "spawn_agent reasoning_effort `{unsupported_effort}` is not supported for model `{}`. Choose one of: {}",
                selected_model.model,
                selected_model
                    .supported_reasoning_efforts
                    .iter()
                    .map(|effort| format!("`{}`", effort.effort))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        );
    }

    #[tokio::test]
    async fn spawn_agent_watchdog_handle_uses_explicit_overrides() {
        #[derive(Debug, Deserialize)]
        struct SpawnAgentResult {
            agent_id: String,
        }

        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        session.services.models_manager = manager.get_models_manager();
        let selected_model = visible_models(&session)
            .await
            .into_iter()
            .find(|preset| !preset.supported_reasoning_efforts.is_empty())
            .expect("expected visible model with reasoning support");
        let requested_effort = selected_model
            .supported_reasoning_efforts
            .first()
            .map(|effort| effort.effort)
            .expect("expected reasoning effort");
        let mut config = (*turn.config).clone();
        let _ = config.features.enable(Feature::AgentWatchdog);
        session.services.agent_control = manager.agent_control();
        let turn = Arc::new(TurnContext {
            config: Arc::new(config),
            ..turn
        });

        let invocation = invocation(
            Arc::new(session),
            turn,
            "spawn_agent",
            function_payload(json!({
                "message": "watchdog check-in",
                "spawn_mode": "watchdog",
                "model": selected_model.model,
                "reasoning_effort": requested_effort
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("watchdog spawn should succeed");
        let (content, _) = expect_text_output(output);
        let result: SpawnAgentResult =
            serde_json::from_str(&content).expect("spawn_agent result should be json");
        let watchdog_id = agent_id(&result.agent_id).expect("agent_id should be valid");
        let snapshot = manager
            .get_thread(watchdog_id)
            .await
            .expect("watchdog handle should exist")
            .config_snapshot()
            .await;
        assert_eq!(snapshot.model, selected_model.model);
        assert_eq!(snapshot.reasoning_effort, Some(requested_effort));
    }

    #[tokio::test]
    async fn compact_parent_context_rejects_when_feature_disabled() {
        let (session, mut turn) = make_session_and_context().await;
        let mut config = (*turn.config).clone();
        let _ = config.features.disable(Feature::AgentWatchdog);
        turn.config = Arc::new(config);

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "compact_parent_context",
            function_payload(json!({})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("compact_parent_context should be rejected when the feature is disabled");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel("watchdogs are disabled".to_string())
        );
    }

    #[tokio::test]
    async fn send_input_rejects_empty_message() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "send_input",
            function_payload(json!({"id": ThreadId::new().to_string(), "message": ""})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("empty message should be rejected");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(
                "Empty message can't be sent to an agent".to_string()
            )
        );
    }

    #[tokio::test]
    async fn send_input_rejects_when_message_and_items_are_both_set() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "send_input",
            function_payload(json!({
                "id": ThreadId::new().to_string(),
                "message": "hello",
                "items": [{"type": "mention", "name": "drive", "path": "app://drive"}]
            })),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("message+items should be rejected");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(
                "Provide either message or items, but not both".to_string()
            )
        );
    }

    #[tokio::test]
    async fn send_input_rejects_invalid_id() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "send_input",
            function_payload(json!({"id": "not-a-uuid", "message": "hi"})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("invalid id should be rejected");
        };
        let FunctionCallError::RespondToModel(msg) = err else {
            panic!("expected respond-to-model error");
        };
        assert!(msg.starts_with("invalid agent id not-a-uuid:"));
    }

    #[tokio::test]
    async fn send_input_requires_id_without_parent_agent() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "send_input",
            function_payload(json!({"message": "hi"})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("missing id should be rejected without a parent agent");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(
                "send_input requires an id when no parent agent is available".to_string()
            )
        );
    }

    #[tokio::test]
    async fn send_input_reports_missing_agent() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let agent_id = ThreadId::new();
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "send_input",
            function_payload(json!({"id": agent_id.to_string(), "message": "hi"})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("missing agent should be reported");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(format!("agent with id {agent_id} not found"))
        );
    }

    #[tokio::test]
    async fn list_agents_root_alias_resolves_true_root_from_nested_subagents() {
        let (mut root_session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        root_session.services.agent_control = manager.agent_control();
        let root_thread_id = root_session.conversation_id;
        let child_id = manager
            .agent_control()
            .spawn_agent_handle(
                turn.config.as_ref().clone(),
                Some(thread_spawn_source(root_thread_id, 1)),
            )
            .await
            .expect("spawn child handle");
        let grandchild_id = manager
            .agent_control()
            .spawn_agent_handle(
                turn.config.as_ref().clone(),
                Some(thread_spawn_source(child_id, 2)),
            )
            .await
            .expect("spawn grandchild handle");
        let grandchild_session = manager
            .get_thread(grandchild_id)
            .await
            .expect("grandchild thread should exist")
            .codex
            .session
            .clone();
        let invocation = invocation(
            grandchild_session.clone(),
            Arc::new(turn),
            "list_agents",
            function_payload(json!({
                "id": "root",
                "recursive": true
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("list_agents should succeed");
        let (content, success) = expect_text_output(output);
        let result: ListAgentsResultForTest =
            serde_json::from_str(&content).expect("list_agents result should be json");
        let expected_child_status = manager.agent_control().get_status(child_id).await;
        let expected_grandchild_status = manager.agent_control().get_status(grandchild_id).await;
        assert_eq!(
            result,
            ListAgentsResultForTest {
                agents: vec![
                    ListAgentEntryForTest {
                        id: child_id.to_string(),
                        parent_id: root_thread_id.to_string(),
                        status: expected_child_status,
                        depth: 1,
                    },
                    ListAgentEntryForTest {
                        id: grandchild_id.to_string(),
                        parent_id: child_id.to_string(),
                        status: expected_grandchild_status,
                        depth: 2,
                    },
                ],
            }
        );
        assert_eq!(success, Some(true));

        let _ = grandchild_session
            .services
            .agent_control
            .shutdown_agent(child_id)
            .await;
    }

    #[tokio::test]
    async fn list_agents_parent_alias_targets_immediate_parent() {
        let (mut root_session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        root_session.services.agent_control = manager.agent_control();
        let root_thread_id = root_session.conversation_id;
        let child_id = manager
            .agent_control()
            .spawn_agent_handle(
                turn.config.as_ref().clone(),
                Some(thread_spawn_source(root_thread_id, 1)),
            )
            .await
            .expect("spawn child handle");
        let grandchild_id = manager
            .agent_control()
            .spawn_agent_handle(
                turn.config.as_ref().clone(),
                Some(thread_spawn_source(child_id, 2)),
            )
            .await
            .expect("spawn grandchild handle");
        let child_session = manager
            .get_thread(grandchild_id)
            .await
            .expect("grandchild thread should exist")
            .codex
            .session
            .clone();

        let invocation = invocation(
            child_session.clone(),
            Arc::new(turn),
            "list_agents",
            function_payload(json!({
                "id": "parent",
                "recursive": false
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("list_agents should succeed");
        let (content, success) = expect_text_output(output);
        let result: ListAgentsResultForTest =
            serde_json::from_str(&content).expect("list_agents result should be json");
        let expected_status = manager.agent_control().get_status(grandchild_id).await;
        assert_eq!(
            result,
            ListAgentsResultForTest {
                agents: vec![ListAgentEntryForTest {
                    id: grandchild_id.to_string(),
                    parent_id: child_id.to_string(),
                    status: expected_status,
                    depth: 1,
                }],
            }
        );
        assert_eq!(success, Some(true));

        let _ = child_session
            .services
            .agent_control
            .shutdown_agent(child_id)
            .await;
    }

    #[tokio::test]
    async fn send_input_interrupts_before_prompt() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let config = turn.config.as_ref().clone();
        let thread = manager.start_thread(config).await.expect("start thread");
        let agent_id = thread.thread_id;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "send_input",
            function_payload(json!({
                "id": agent_id.to_string(),
                "message": "hi",
                "interrupt": true
            })),
        );
        MultiAgentHandler
            .handle(invocation)
            .await
            .expect("send_input should succeed");

        let ops = manager.captured_ops();
        let ops_for_agent: Vec<&Op> = ops
            .iter()
            .filter_map(|(id, op)| (*id == agent_id).then_some(op))
            .collect();
        assert!(
            !ops_for_agent.is_empty(),
            "expected at least one op for the target agent"
        );
        assert!(matches!(ops_for_agent[0], Op::Interrupt));

        let _ = thread
            .thread
            .submit(Op::Shutdown {})
            .await
            .expect("shutdown should submit");
    }

    #[tokio::test]
    async fn send_input_parent_alias_uses_collab_inbox_delivery_for_text() {
        let (mut root_session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        root_session.services.agent_control = manager.agent_control();
        let root_thread = manager
            .start_thread(turn.config.as_ref().clone())
            .await
            .expect("start root thread");
        let child_id = manager
            .agent_control()
            .spawn_agent_handle(
                turn.config.as_ref().clone(),
                Some(thread_spawn_source(root_thread.thread_id, 1)),
            )
            .await
            .expect("spawn child handle");
        let child_session = manager
            .get_thread(child_id)
            .await
            .expect("child thread should exist")
            .codex
            .session
            .clone();

        let invocation = invocation(
            child_session.clone(),
            Arc::new(turn),
            "send_input",
            function_payload(json!({
                "id": "parent",
                "message": "watchdog check-in"
            })),
        );
        MultiAgentHandler
            .handle(invocation)
            .await
            .expect("send_input should succeed");

        let ops = manager.captured_ops();
        let parent_received_collab_inbox = ops.iter().any(|(id, op)| {
            *id == root_thread.thread_id && matches!(op, Op::InjectResponseItems { .. })
        });
        assert!(parent_received_collab_inbox);
        let parent_received_user_input = ops
            .iter()
            .any(|(id, op)| *id == root_thread.thread_id && matches!(op, Op::UserInput { .. }));
        assert!(!parent_received_user_input);

        let _ = child_session
            .services
            .agent_control
            .shutdown_agent(child_id)
            .await;
        let _ = child_session
            .services
            .agent_control
            .shutdown_agent(root_thread.thread_id)
            .await;
    }

    #[tokio::test]
    async fn send_input_rejects_watchdog_handle() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();

        let owner_thread = manager
            .start_thread(turn.config.as_ref().clone())
            .await
            .expect("start owner thread");
        session.conversation_id = owner_thread.thread_id;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;

        let invocation = invocation(
            session.clone(),
            turn.clone(),
            "send_input",
            function_payload(json!({
                "id": watchdog_id.to_string(),
                "message": "hi"
            })),
        );
        let result = MultiAgentHandler.handle(invocation).await;
        assert!(matches!(
            result,
            Err(FunctionCallError::RespondToModel(message))
                if message
                    == "send_input cannot target watchdog handles. Send the message to the parent/root agent instead."
        ));

        let _ = session
            .services
            .agent_control
            .shutdown_agent(watchdog_id)
            .await;
        let _ = session
            .services
            .agent_control
            .shutdown_agent(owner_thread.thread_id)
            .await;
    }

    #[tokio::test]
    async fn send_input_interrupt_rejects_watchdog_handle() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();

        let owner_thread = manager
            .start_thread(turn.config.as_ref().clone())
            .await
            .expect("start owner thread");
        session.conversation_id = owner_thread.thread_id;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;

        let invocation = invocation(
            session.clone(),
            turn.clone(),
            "send_input",
            function_payload(json!({
                "id": watchdog_id.to_string(),
                "message": "hi",
                "interrupt": true
            })),
        );
        let result = MultiAgentHandler.handle(invocation).await;
        assert!(matches!(
            result,
            Err(FunctionCallError::RespondToModel(message))
                if message
                    == "send_input cannot target watchdog handles. Send the message to the parent/root agent instead."
        ));

        let _ = session
            .services
            .agent_control
            .shutdown_agent(watchdog_id)
            .await;
        let _ = session
            .services
            .agent_control
            .shutdown_agent(owner_thread.thread_id)
            .await;
    }

    #[tokio::test]
    async fn send_input_accepts_structured_items() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let config = turn.config.as_ref().clone();
        let thread = manager.start_thread(config).await.expect("start thread");
        let agent_id = thread.thread_id;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "send_input",
            function_payload(json!({
                "id": agent_id.to_string(),
                "items": [
                    {"type": "mention", "name": "drive", "path": "app://google_drive"},
                    {"type": "text", "text": "read the folder"}
                ]
            })),
        );
        MultiAgentHandler
            .handle(invocation)
            .await
            .expect("send_input should succeed");

        let expected = Op::UserInput {
            items: vec![
                UserInput::Mention {
                    name: "drive".to_string(),
                    path: "app://google_drive".to_string(),
                },
                UserInput::Text {
                    text: "read the folder".to_string(),
                    text_elements: Vec::new(),
                },
            ],
            final_output_json_schema: None,
        };
        let captured = manager
            .captured_ops()
            .into_iter()
            .find(|(id, op)| *id == agent_id && *op == expected);
        assert_eq!(captured, Some((agent_id, expected)));

        let _ = thread
            .thread
            .submit(Op::Shutdown {})
            .await
            .expect("shutdown should submit");
    }

    #[tokio::test]
    async fn resume_agent_rejects_invalid_id() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "resume_agent",
            function_payload(json!({"id": "not-a-uuid"})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("invalid id should be rejected");
        };
        let FunctionCallError::RespondToModel(msg) = err else {
            panic!("expected respond-to-model error");
        };
        assert!(msg.starts_with("invalid agent id not-a-uuid:"));
    }

    #[tokio::test]
    async fn resume_agent_reports_missing_agent() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let agent_id = ThreadId::new();
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "resume_agent",
            function_payload(json!({"id": agent_id.to_string()})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("missing agent should be reported");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel(format!("agent with id {agent_id} not found"))
        );
    }

    #[tokio::test]
    async fn resume_agent_noops_for_active_agent() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let config = turn.config.as_ref().clone();
        let thread = manager.start_thread(config).await.expect("start thread");
        let agent_id = thread.thread_id;
        let status_before = manager.agent_control().get_status(agent_id).await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "resume_agent",
            function_payload(json!({"id": agent_id.to_string()})),
        );

        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("resume_agent should succeed");
        let (content, success) = expect_text_output(output);
        let result: resume_agent::ResumeAgentResult =
            serde_json::from_str(&content).expect("resume_agent result should be json");
        assert_eq!(result.status, status_before);
        assert_eq!(success, Some(true));

        let thread_ids = manager.list_thread_ids().await;
        assert_eq!(thread_ids, vec![agent_id]);

        let _ = thread
            .thread
            .submit(Op::Shutdown {})
            .await
            .expect("shutdown should submit");
    }

    #[tokio::test]
    async fn resume_agent_restores_closed_agent_and_accepts_send_input() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let config = turn.config.as_ref().clone();
        let thread = manager
            .resume_thread_with_history(
                config,
                InitialHistory::Forked(vec![RolloutItem::ResponseItem(ResponseItem::Message {
                    id: None,
                    role: "user".to_string(),
                    content: vec![ContentItem::InputText {
                        text: "materialized".to_string(),
                    }],
                    end_turn: None,
                    phase: None,
                })]),
                AuthManager::from_auth_for_testing(CodexAuth::from_api_key("dummy")),
                false,
            )
            .await
            .expect("start thread");
        let agent_id = thread.thread_id;
        let _ = manager
            .agent_control()
            .shutdown_agent(agent_id)
            .await
            .expect("shutdown agent");
        assert_eq!(
            manager.agent_control().get_status(agent_id).await,
            AgentStatus::NotFound
        );
        let session = Arc::new(session);
        let turn = Arc::new(turn);

        let resume_invocation = invocation(
            session.clone(),
            turn.clone(),
            "resume_agent",
            function_payload(json!({"id": agent_id.to_string()})),
        );
        let output = MultiAgentHandler
            .handle(resume_invocation)
            .await
            .expect("resume_agent should succeed");
        let (content, success) = expect_text_output(output);
        let result: resume_agent::ResumeAgentResult =
            serde_json::from_str(&content).expect("resume_agent result should be json");
        assert_ne!(result.status, AgentStatus::NotFound);
        assert_eq!(success, Some(true));

        let send_invocation = invocation(
            session,
            turn,
            "send_input",
            function_payload(json!({"id": agent_id.to_string(), "message": "hello"})),
        );
        let output = MultiAgentHandler
            .handle(send_invocation)
            .await
            .expect("send_input should succeed after resume");
        let (content, success) = expect_text_output(output);
        let result: serde_json::Value =
            serde_json::from_str(&content).expect("send_input result should be json");
        let submission_id = result
            .get("submission_id")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        assert!(!submission_id.is_empty());
        assert_eq!(success, Some(true));

        let _ = manager
            .agent_control()
            .shutdown_agent(agent_id)
            .await
            .expect("shutdown resumed agent");
    }

    #[tokio::test]
    async fn resume_agent_restores_closed_fork_agent_with_turn_developer_instructions() {
        let (mut session, mut turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let mut config = turn.config.as_ref().clone();
        config.developer_instructions = Some("base-dev".to_string());
        turn.developer_instructions = Some("turn-dev".to_string());
        turn.reasoning_effort = Some(ReasoningEffort::XHigh);
        turn.config = Arc::new(config.clone());
        let thread = manager
            .resume_thread_with_history(
                config,
                InitialHistory::Forked(vec![
                    RolloutItem::TurnContext(TurnContextItem {
                        turn_id: Some("turn-1".to_string()),
                        cwd: turn.cwd.clone(),
                        current_date: turn.current_date.clone(),
                        timezone: turn.timezone.clone(),
                        trace_id: None,
                        approval_policy: turn.approval_policy.value(),
                        sandbox_policy: turn.sandbox_policy.get().clone(),
                        network: None,
                        model: "gpt-5.1-codex-mini".to_string(),
                        personality: turn.personality,
                        collaboration_mode: Some(turn.collaboration_mode.clone()),
                        realtime_active: Some(turn.realtime_active),
                        effort: Some(ReasoningEffort::High),
                        summary: turn.reasoning_summary,
                        user_instructions: turn.user_instructions.clone(),
                        developer_instructions: turn.developer_instructions.clone(),
                        final_output_json_schema: turn.final_output_json_schema.clone(),
                        truncation_policy: Some(turn.truncation_policy.into()),
                    }),
                    RolloutItem::ResponseItem(ResponseItem::Message {
                        id: None,
                        role: "user".to_string(),
                        content: vec![ContentItem::InputText {
                            text: "materialized".to_string(),
                        }],
                        end_turn: None,
                        phase: None,
                    }),
                ]),
                AuthManager::from_auth_for_testing(CodexAuth::from_api_key("dummy")),
                false,
            )
            .await
            .expect("start thread");
        let agent_id = thread.thread_id;
        let _ = manager
            .agent_control()
            .shutdown_agent(agent_id)
            .await
            .expect("shutdown agent");
        assert_eq!(
            manager.agent_control().get_status(agent_id).await,
            AgentStatus::NotFound
        );
        let session = Arc::new(session);
        let turn = Arc::new(turn);

        let resume_invocation = invocation(
            session,
            turn.clone(),
            "resume_agent",
            function_payload(json!({"id": agent_id.to_string()})),
        );
        let output = MultiAgentHandler
            .handle(resume_invocation)
            .await
            .expect("resume_agent should succeed");
        let (content, success) = expect_text_output(output);
        let result: resume_agent::ResumeAgentResult =
            serde_json::from_str(&content).expect("resume_agent result should be json");
        assert_ne!(result.status, AgentStatus::NotFound);
        assert_eq!(success, Some(true));

        let resumed_thread = manager
            .get_thread(agent_id)
            .await
            .expect("resumed thread should be registered");
        let resumed_config = resumed_thread.codex.session.get_config().await;
        assert_eq!(resumed_config.model.as_deref(), Some("gpt-5.1-codex-mini"));
        assert_eq!(
            resumed_config.model_reasoning_effort,
            Some(ReasoningEffort::High)
        );
        assert_eq!(
            resumed_config.developer_instructions,
            turn.developer_instructions
        );

        let _ = manager
            .agent_control()
            .shutdown_agent(agent_id)
            .await
            .expect("shutdown resumed agent");
    }

    #[tokio::test]
    async fn resume_agent_rejects_when_depth_limit_exceeded() {
        let (mut session, mut turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let max_depth = turn.config.agent_max_depth;

        turn.session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id: session.conversation_id,
            depth: max_depth,
            agent_nickname: None,
            agent_role: None,
        });

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "resume_agent",
            function_payload(json!({"id": ThreadId::new().to_string()})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("resume should fail when depth limit exceeded");
        };
        let FunctionCallError::RespondToModel(message) = err else {
            panic!("expected respond-to-model error");
        };
        assert!(message.contains("depth limit reached"));
    }

    #[tokio::test]
    async fn wait_rejects_non_positive_timeout() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "wait",
            function_payload(json!({
                "ids": [ThreadId::new().to_string()],
                "timeout_ms": 0
            })),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("non-positive timeout should be rejected");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel("timeout_ms must be greater than zero".to_string())
        );
    }

    #[tokio::test]
    async fn wait_rejects_invalid_id() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "wait",
            function_payload(json!({"ids": ["invalid"]})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("invalid id should be rejected");
        };
        let FunctionCallError::RespondToModel(msg) = err else {
            panic!("expected respond-to-model error");
        };
        assert!(msg.starts_with("invalid agent id invalid:"));
    }

    #[tokio::test]
    async fn wait_rejects_empty_ids() {
        let (session, turn) = make_session_and_context().await;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "wait",
            function_payload(json!({"ids": []})),
        );
        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("empty ids should be rejected");
        };
        assert_eq!(
            err,
            FunctionCallError::RespondToModel("ids must be non-empty".to_string())
        );
    }

    #[tokio::test]
    async fn wait_returns_not_found_for_missing_agents() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let id_a = ThreadId::new();
        let id_b = ThreadId::new();
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "wait",
            function_payload(json!({
                "ids": [id_a.to_string(), id_b.to_string()],
                "timeout_ms": 1000
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("wait should succeed");
        let (content, success) = expect_text_output(output);
        let result: wait::WaitResult =
            serde_json::from_str(&content).expect("wait result should be json");
        assert_eq!(
            result,
            wait::WaitResult {
                status: HashMap::from([
                    (id_a, AgentStatus::NotFound),
                    (id_b, AgentStatus::NotFound),
                ]),
                timed_out: false
            }
        );
        assert_eq!(success, None);
    }

    #[tokio::test]
    async fn wait_times_out_when_status_is_not_final() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let config = turn.config.as_ref().clone();
        let thread = manager.start_thread(config).await.expect("start thread");
        let agent_id = thread.thread_id;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "wait",
            function_payload(json!({
                "ids": [agent_id.to_string()],
                "timeout_ms": MIN_WAIT_TIMEOUT_MS
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("wait should succeed");
        let (content, success) = expect_text_output(output);
        let result: wait::WaitResult =
            serde_json::from_str(&content).expect("wait result should be json");
        assert_eq!(
            result,
            wait::WaitResult {
                status: HashMap::new(),
                timed_out: true
            }
        );
        assert_eq!(success, None);

        let _ = thread
            .thread
            .submit(Op::Shutdown {})
            .await
            .expect("shutdown should submit");
    }

    #[tokio::test]
    async fn wait_rejects_watchdog_only_handles() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();

        let owner_thread = manager
            .start_thread(turn.config.as_ref().clone())
            .await
            .expect("start owner thread");
        session.conversation_id = owner_thread.thread_id;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;

        let invocation = invocation(
            session.clone(),
            turn,
            "wait",
            function_payload(json!({
                "ids": [watchdog_id.to_string()],
                "timeout_ms": 10
            })),
        );

        let wait_result = timeout(
            Duration::from_millis(250),
            MultiAgentHandler.handle(invocation),
        )
        .await
        .expect("wait should return immediately for watchdog handles");
        let Err(err) = wait_result else {
            panic!("watchdog-only wait should return a correction");
        };
        let FunctionCallError::RespondToModel(message) = err else {
            panic!("expected respond-to-model error");
        };
        assert!(message.contains("wait cannot be used to wait for watchdog check-ins"));
        assert!(message.contains("watchdog interval"));
        assert!(message.contains("Continue the task now or end the turn"));
        assert!(message.contains(&watchdog_id.to_string()));

        let _ = session
            .services
            .agent_control
            .shutdown_agent(watchdog_id)
            .await;
        let _ = session
            .services
            .agent_control
            .shutdown_agent(owner_thread.thread_id)
            .await;
    }

    #[tokio::test]
    async fn wait_rejects_active_watchdog_helper_sessions() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();

        let owner_thread = manager
            .start_thread(turn.config.as_ref().clone())
            .await
            .expect("start owner thread");
        session.conversation_id = owner_thread.thread_id;

        let mut session = Arc::new(session);
        let turn = Arc::new(turn);
        let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;
        let owner_thread_id = owner_thread.thread_id;

        let mut helper_config = turn.config.as_ref().clone();
        helper_config.ephemeral = true;
        let helper_id = session
            .services
            .agent_control
            .spawn_agent_handle(
                helper_config.clone(),
                Some(thread_spawn_source(owner_thread_id, 1)),
            )
            .await
            .expect("spawn helper handle");
        session
            .services
            .agent_control
            .set_watchdog_active_helper_for_tests(watchdog_id, helper_id)
            .await;

        Arc::get_mut(&mut session)
            .expect("no extra session refs")
            .conversation_id = helper_id;
        let (_, mut helper_turn) = make_session_and_context().await;
        helper_turn.session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id: owner_thread_id,
            depth: 1,
            agent_nickname: None,
            agent_role: None,
        });
        helper_turn.config = Arc::new(helper_config);
        let helper_turn = Arc::new(helper_turn);
        let invocation = invocation(
            session.clone(),
            helper_turn,
            "wait",
            function_payload(json!({
                "ids": [watchdog_id.to_string()]
            })),
        );

        let Err(err) = MultiAgentHandler.handle(invocation).await else {
            panic!("watchdog helper wait should be rejected");
        };
        let FunctionCallError::RespondToModel(message) = err else {
            panic!("expected model-visible correction");
        };
        assert!(message.contains("wait is not available to watchdog check-in agents"));
        assert!(message.contains("send_input"));

        let _ = session
            .services
            .agent_control
            .shutdown_agent(helper_id)
            .await;
        let _ = session
            .services
            .agent_control
            .shutdown_agent(watchdog_id)
            .await;
        let _ = session
            .services
            .agent_control
            .shutdown_agent(owner_thread_id)
            .await;
    }

    #[tokio::test]
    async fn wait_includes_watchdog_status_when_non_watchdog_is_final() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();

        let owner_thread = manager
            .start_thread(turn.config.as_ref().clone())
            .await
            .expect("start owner thread");
        session.conversation_id = owner_thread.thread_id;

        let worker_thread = manager
            .start_thread(turn.config.as_ref().clone())
            .await
            .expect("start worker thread");
        let worker_id = worker_thread.thread_id;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;

        let mut worker_status_rx = session
            .services
            .agent_control
            .subscribe_status(worker_id)
            .await
            .expect("subscribe should succeed");
        let _ = worker_thread
            .thread
            .submit(Op::Shutdown {})
            .await
            .expect("shutdown should submit");
        let _ = timeout(Duration::from_secs(1), worker_status_rx.changed())
            .await
            .expect("shutdown status should arrive");

        let invocation = invocation(
            session.clone(),
            turn,
            "wait",
            function_payload(json!({
                "ids": [watchdog_id.to_string(), worker_id.to_string()],
                "timeout_ms": 10
            })),
        );
        let output = timeout(
            Duration::from_millis(250),
            MultiAgentHandler.handle(invocation),
        )
        .await
        .expect("wait should return quickly when non-watchdog is already final")
        .expect("wait should succeed");

        let (content, success) = expect_text_output(output);
        let result: wait::WaitResult =
            serde_json::from_str(&content).expect("wait result should be json");
        let expected_watchdog_status = session.services.agent_control.get_status(watchdog_id).await;
        assert_eq!(
            result,
            wait::WaitResult {
                status: HashMap::from([
                    (watchdog_id, expected_watchdog_status),
                    (worker_id, AgentStatus::Shutdown),
                ]),
                timed_out: false
            }
        );
        assert_eq!(success, None);

        let _ = session
            .services
            .agent_control
            .shutdown_agent(watchdog_id)
            .await;
        let _ = session
            .services
            .agent_control
            .shutdown_agent(worker_id)
            .await;
        let _ = session
            .services
            .agent_control
            .shutdown_agent(owner_thread.thread_id)
            .await;
    }

    #[tokio::test]
    async fn wait_clamps_short_timeouts_to_minimum() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let config = turn.config.as_ref().clone();
        let thread = manager.start_thread(config).await.expect("start thread");
        let agent_id = thread.thread_id;
        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "wait",
            function_payload(json!({
                "ids": [agent_id.to_string()],
                "timeout_ms": 10
            })),
        );

        let early = timeout(
            Duration::from_millis(50),
            MultiAgentHandler.handle(invocation),
        )
        .await;
        assert!(
            early.is_err(),
            "wait should not return before the minimum timeout clamp"
        );

        let _ = thread
            .thread
            .submit(Op::Shutdown {})
            .await
            .expect("shutdown should submit");
    }

    #[tokio::test]
    async fn wait_returns_final_status_without_timeout() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let config = turn.config.as_ref().clone();
        let thread = manager.start_thread(config).await.expect("start thread");
        let agent_id = thread.thread_id;
        let mut status_rx = manager
            .agent_control()
            .subscribe_status(agent_id)
            .await
            .expect("subscribe should succeed");

        let _ = thread
            .thread
            .submit(Op::Shutdown {})
            .await
            .expect("shutdown should submit");
        let _ = timeout(Duration::from_secs(1), status_rx.changed())
            .await
            .expect("shutdown status should arrive");

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "wait",
            function_payload(json!({
                "ids": [agent_id.to_string()],
                "timeout_ms": 1000
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("wait should succeed");
        let (content, success) = expect_text_output(output);
        let result: wait::WaitResult =
            serde_json::from_str(&content).expect("wait result should be json");
        assert_eq!(
            result,
            wait::WaitResult {
                status: HashMap::from([(agent_id, AgentStatus::Shutdown)]),
                timed_out: false
            }
        );
        assert_eq!(success, None);
    }

    #[tokio::test]
    async fn wait_returns_non_interrupted_errors_immediately() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let config = turn.config.as_ref().clone();
        let thread = manager.start_thread(config).await.expect("start thread");
        let agent_id = thread.thread_id;

        thread
            .thread
            .codex
            .session
            .send_event_raw(Event {
                id: "err-1".to_string(),
                msg: EventMsg::Error(ErrorEvent {
                    message: "boom".to_string(),
                    codex_error_info: None,
                }),
            })
            .await;

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "wait",
            function_payload(json!({
                "ids": [agent_id.to_string()],
                "timeout_ms": 1000
            })),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("wait should succeed");
        let (content, success) = expect_text_output(output);
        let result: wait::WaitResult =
            serde_json::from_str(&content).expect("wait result should be json");
        assert_eq!(
            result,
            wait::WaitResult {
                status: HashMap::from([(agent_id, AgentStatus::Errored("boom".to_string()))]),
                timed_out: false
            }
        );
        assert_eq!(success, None);

        let _ = thread
            .thread
            .submit(Op::Shutdown {})
            .await
            .expect("shutdown should submit");
    }

    #[tokio::test]
    async fn wait_for_final_status_ignores_interrupted_status() {
        let (session, _turn) = make_session_and_context().await;
        let agent_id = ThreadId::new();
        let (status_tx, status_rx) = watch::channel(AgentStatus::Interrupted);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            status_tx.send_replace(AgentStatus::Shutdown);
        });

        let result = timeout(
            Duration::from_secs(1),
            wait::wait_for_final_status(Arc::new(session), agent_id, status_rx),
        )
        .await
        .expect("wait should complete once a truly final status arrives");
        assert_eq!(result, Some((agent_id, AgentStatus::Shutdown)));
    }

    #[tokio::test]
    async fn close_agent_submits_shutdown_and_returns_status() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let config = turn.config.as_ref().clone();
        let thread = manager.start_thread(config).await.expect("start thread");
        let agent_id = thread.thread_id;
        let status_before = manager.agent_control().get_status(agent_id).await;

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "close_agent",
            function_payload(json!({"id": agent_id.to_string()})),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("close_agent should succeed");
        let (content, success) = expect_text_output(output);
        let result: close_agent::CloseAgentResult =
            serde_json::from_str(&content).expect("close_agent result should be json");
        let status_after = manager.agent_control().get_status(agent_id).await;
        assert_eq!(result.status, status_before);
        assert_eq!(result.close_result, close_agent::CloseAgentOutcome::Closed);
        assert_eq!(success, Some(true));

        let ops = manager.captured_ops();
        let submitted_shutdown = ops
            .iter()
            .any(|(id, op)| *id == agent_id && matches!(op, Op::Shutdown));
        assert_eq!(submitted_shutdown, true);

        assert_eq!(status_after, AgentStatus::NotFound);
    }

    #[tokio::test]
    async fn close_agent_reports_already_closed_for_known_id() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let config = turn.config.as_ref().clone();
        let agent_id = session
            .services
            .agent_control
            .spawn_agent_handle(config, None)
            .await
            .expect("spawn agent handle");

        session
            .services
            .agent_control
            .shutdown_agent(agent_id)
            .await
            .expect("shutdown agent");

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "close_agent",
            function_payload(json!({"id": agent_id.to_string()})),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("close_agent should succeed");
        let (content, success) = expect_text_output(output);
        let result: close_agent::CloseAgentResult =
            serde_json::from_str(&content).expect("close_agent result should be json");
        assert_eq!(result.status, AgentStatus::NotFound);
        assert_eq!(
            result.close_result,
            close_agent::CloseAgentOutcome::AlreadyClosed
        );
        assert_eq!(success, Some(true));
    }

    #[tokio::test]
    async fn close_agent_reports_not_found_for_unknown_id() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let unknown_id = ThreadId::new();

        let invocation = invocation(
            Arc::new(session),
            Arc::new(turn),
            "close_agent",
            function_payload(json!({"id": unknown_id.to_string()})),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("close_agent should succeed");
        let (content, success) = expect_text_output(output);
        let result: close_agent::CloseAgentResult =
            serde_json::from_str(&content).expect("close_agent result should be json");
        assert_eq!(result.status, AgentStatus::NotFound);
        assert_eq!(
            result.close_result,
            close_agent::CloseAgentOutcome::NotFound
        );
        assert_eq!(success, Some(true));
    }

    #[tokio::test]
    async fn close_agent_reports_already_closed_for_registered_watchdog_without_live_thread() {
        let (mut session, turn) = make_session_and_context().await;
        let manager = thread_manager();
        session.services.agent_control = manager.agent_control();
        let owner_thread = manager
            .start_thread(turn.config.as_ref().clone())
            .await
            .expect("start owner thread");
        session.conversation_id = owner_thread.thread_id;

        let session = Arc::new(session);
        let turn = Arc::new(turn);
        let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;
        let _ = manager.remove_thread(&watchdog_id).await;

        let invocation = invocation(
            session.clone(),
            turn,
            "close_agent",
            function_payload(json!({"id": watchdog_id.to_string()})),
        );
        let output = MultiAgentHandler
            .handle(invocation)
            .await
            .expect("close_agent should succeed");
        let (content, success) = expect_text_output(output);
        let result: close_agent::CloseAgentResult =
            serde_json::from_str(&content).expect("close_agent result should be json");
        assert_eq!(result.status, AgentStatus::NotFound);
        assert_eq!(
            result.close_result,
            close_agent::CloseAgentOutcome::AlreadyClosed
        );
        assert_eq!(success, Some(true));

        let _ = session
            .services
            .agent_control
            .shutdown_agent(owner_thread.thread_id)
            .await;
    }

    #[tokio::test]
    async fn build_agent_spawn_config_uses_turn_context_values() {
        fn pick_allowed_sandbox_policy(
            constraint: &crate::config::Constrained<SandboxPolicy>,
            base: SandboxPolicy,
        ) -> SandboxPolicy {
            let candidates = [
                SandboxPolicy::new_read_only_policy(),
                SandboxPolicy::new_workspace_write_policy(),
                SandboxPolicy::DangerFullAccess,
            ];
            candidates
                .into_iter()
                .find(|candidate| *candidate != base && constraint.can_set(candidate).is_ok())
                .unwrap_or(base)
        }

        let (_session, mut turn) = make_session_and_context().await;
        let base_instructions = BaseInstructions {
            text: "base".to_string(),
        };
        turn.developer_instructions = Some("dev".to_string());
        turn.compact_prompt = Some("compact".to_string());
        turn.shell_environment_policy = ShellEnvironmentPolicy {
            use_profile: true,
            ..ShellEnvironmentPolicy::default()
        };
        let temp_dir = tempfile::tempdir().expect("temp dir");
        turn.cwd = temp_dir.path().to_path_buf();
        turn.codex_linux_sandbox_exe = Some(PathBuf::from("/bin/echo"));
        let sandbox_policy = pick_allowed_sandbox_policy(
            &turn.config.permissions.sandbox_policy,
            turn.config.permissions.sandbox_policy.get().clone(),
        );
        turn.sandbox_policy
            .set(sandbox_policy)
            .expect("sandbox policy set");
        turn.approval_policy
            .set(AskForApproval::OnRequest)
            .expect("approval policy set");

        let config = build_agent_spawn_config(
            &base_instructions,
            &turn,
            0,
            SpawnConfigStrategy::ContextFreeSpawn,
        )
        .expect("spawn config");
        let mut expected = (*turn.config).clone();
        expected.base_instructions = Some(base_instructions.text);
        expected.model = Some(turn.model_info.slug.clone());
        expected.model_provider = turn.provider.clone();
        expected.model_reasoning_effort = turn.reasoning_effort;
        expected.model_reasoning_summary = Some(turn.reasoning_summary);
        // build_agent_spawn_config intentionally clears turn-local developer instructions.
        expected.developer_instructions = None;
        expected.compact_prompt = turn.compact_prompt.clone();
        expected.permissions.shell_environment_policy = turn.shell_environment_policy.clone();
        expected.codex_linux_sandbox_exe = turn.codex_linux_sandbox_exe.clone();
        expected.cwd = turn.cwd.clone();
        expected
            .permissions
            .approval_policy
            .set(AskForApproval::OnRequest)
            .expect("approval policy set");
        expected
            .permissions
            .sandbox_policy
            .set(turn.sandbox_policy.get().clone())
            .expect("sandbox policy set");
        assert_eq!(config, expected);
    }

    #[tokio::test]
    async fn build_agent_spawn_config_preserves_base_user_instructions() {
        let (_session, mut turn) = make_session_and_context().await;
        let mut base_config = (*turn.config).clone();
        base_config.user_instructions = Some("base-user".to_string());
        turn.user_instructions = Some("resolved-user".to_string());
        turn.config = Arc::new(base_config.clone());
        let base_instructions = BaseInstructions {
            text: "base".to_string(),
        };

        let config = build_agent_spawn_config(
            &base_instructions,
            &turn,
            0,
            SpawnConfigStrategy::ContextFreeSpawn,
        )
        .expect("spawn config");

        assert_eq!(config.user_instructions, base_config.user_instructions);
    }

    #[tokio::test]
    async fn build_agent_resume_config_context_free_uses_shared_fields() {
        let (_session, mut turn) = make_session_and_context().await;
        let mut base_config = (*turn.config).clone();
        base_config.base_instructions = Some("caller-base".to_string());
        base_config.developer_instructions = Some("base-dev".to_string());
        turn.developer_instructions = Some("turn-dev".to_string());
        turn.config = Arc::new(base_config.clone());
        turn.approval_policy
            .set(AskForApproval::OnRequest)
            .expect("approval policy set");

        let config =
            build_agent_resume_config(&turn, 0, &resume_agent::RecordedResumeContext::default())
                .expect("resume config");

        let mut expected = base_config;
        expected.base_instructions = None;
        expected.model = Some(turn.model_info.slug.clone());
        expected.model_provider = turn.provider.clone();
        expected.model_reasoning_effort = turn.reasoning_effort;
        expected.model_reasoning_summary = Some(turn.reasoning_summary);
        expected.compact_prompt = turn.compact_prompt.clone();
        expected.permissions.shell_environment_policy = turn.shell_environment_policy.clone();
        expected.codex_linux_sandbox_exe = turn.codex_linux_sandbox_exe.clone();
        expected.cwd = turn.cwd.clone();
        expected
            .permissions
            .approval_policy
            .set(AskForApproval::OnRequest)
            .expect("approval policy set");
        expected
            .permissions
            .sandbox_policy
            .set(turn.sandbox_policy.get().clone())
            .expect("sandbox policy set");
        assert_eq!(config, expected);
    }

    #[tokio::test]
    async fn build_agent_resume_config_prefers_recorded_developer_instructions() {
        let (_session, mut turn) = make_session_and_context().await;
        let mut base_config = (*turn.config).clone();
        base_config.base_instructions = Some("caller-base".to_string());
        base_config.developer_instructions = Some("base-dev".to_string());
        turn.developer_instructions = Some("turn-dev".to_string());
        turn.config = Arc::new(base_config.clone());
        turn.approval_policy
            .set(AskForApproval::OnRequest)
            .expect("approval policy set");

        let recorded_resume_context = resume_agent::RecordedResumeContext {
            developer_instructions: Some(turn.developer_instructions.clone()),
            model: Some("gpt-5.1-codex-mini".to_string()),
            reasoning_effort: Some(Some(ReasoningEffort::High)),
        };
        let config =
            build_agent_resume_config(&turn, 0, &recorded_resume_context).expect("resume config");

        let mut expected = base_config;
        expected.base_instructions = None;
        expected.developer_instructions = turn.developer_instructions.clone();
        expected.model = Some("gpt-5.1-codex-mini".to_string());
        expected.model_provider = turn.provider.clone();
        expected.model_reasoning_effort = Some(ReasoningEffort::High);
        expected.model_reasoning_summary = Some(turn.reasoning_summary);
        expected.compact_prompt = turn.compact_prompt.clone();
        expected.permissions.shell_environment_policy = turn.shell_environment_policy.clone();
        expected.codex_linux_sandbox_exe = turn.codex_linux_sandbox_exe.clone();
        expected.cwd = turn.cwd.clone();
        expected
            .permissions
            .approval_policy
            .set(AskForApproval::OnRequest)
            .expect("approval policy set");
        expected
            .permissions
            .sandbox_policy
            .set(turn.sandbox_policy.get().clone())
            .expect("sandbox policy set");
        assert_eq!(config, expected);
    }

    #[tokio::test]
    async fn build_agent_spawn_config_fork_like_uses_turn_developer_instructions() {
        let (_session, mut turn) = make_session_and_context().await;
        let mut base_config = (*turn.config).clone();
        base_config.developer_instructions = Some("base-dev".to_string());
        base_config
            .features
            .enable(Feature::Collab)
            .expect("collab feature enable");
        turn.config = Arc::new(base_config.clone());
        turn.developer_instructions = Some("turn-dev".to_string());
        let base_instructions = BaseInstructions {
            text: "base".to_string(),
        };

        let config =
            build_agent_spawn_config(&base_instructions, &turn, 0, SpawnConfigStrategy::ForkLike)
                .expect("fork-like spawn config");

        assert_eq!(config.developer_instructions, turn.developer_instructions);
        assert_eq!(
            config.features.enabled(Feature::Collab),
            base_config.features.enabled(Feature::Collab)
        );
    }

    #[tokio::test]
    async fn build_agent_spawn_config_context_free_keeps_multi_agent_tools_at_max_depth() {
        let (_session, mut turn) = make_session_and_context().await;
        let mut base_config = (*turn.config).clone();
        base_config
            .features
            .enable(Feature::Collab)
            .expect("collab feature enable");
        turn.config = Arc::new(base_config);
        let base_instructions = BaseInstructions {
            text: "base".to_string(),
        };

        let config = build_agent_spawn_config(
            &base_instructions,
            &turn,
            turn.config.agent_max_depth,
            SpawnConfigStrategy::ContextFreeSpawn,
        )
        .expect("context-free spawn config");

        assert!(config.features.enabled(Feature::Collab));
    }

    #[tokio::test]
    async fn build_agent_spawn_config_context_free_disables_multi_agent_tools_past_max_depth() {
        let (_session, mut turn) = make_session_and_context().await;
        let mut base_config = (*turn.config).clone();
        base_config
            .features
            .enable(Feature::Collab)
            .expect("collab feature enable");
        turn.config = Arc::new(base_config);
        let base_instructions = BaseInstructions {
            text: "base".to_string(),
        };

        let config = build_agent_spawn_config(
            &base_instructions,
            &turn,
            turn.config.agent_max_depth + 1,
            SpawnConfigStrategy::ContextFreeSpawn,
        )
        .expect("context-free spawn config");

        assert_eq!(config.features.enabled(Feature::Collab), false);
    }
}
