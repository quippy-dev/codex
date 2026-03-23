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
    let default_spawn_mode = match default_spawn_mode_for_role(turn.config.as_ref(), role_name) {
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
