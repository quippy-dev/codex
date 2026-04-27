use super::*;
use crate::agent::DEFAULT_WATCHDOG_INTERVAL_S;
use crate::agent::RemovedWatchdog;
use crate::agent::WatchdogRegistration;
use crate::agent::control::SpawnAgentForkMode;
use crate::agent::control::SpawnAgentOptions;
use crate::agent::control::render_input_preview;
use crate::agent::exceeds_thread_spawn_depth_limit;
use crate::agent::next_thread_spawn_depth;
use crate::agent::role::DEFAULT_ROLE_NAME;
use crate::agent::role::apply_role_to_config;
use crate::session::turn_context::TurnEnvironment;
use std::collections::HashSet;
use tracing::info;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
enum SpawnMode {
    #[default]
    Spawn,
    Fork,
    Watchdog,
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

pub(crate) struct Handler;

impl ToolHandler for Handler {
    type Output = SpawnAgentResult;

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
            payload,
            call_id,
            ..
        } = invocation;
        let arguments = function_arguments(payload)?;
        let args: SpawnAgentArgs = parse_arguments(&arguments)?;
        let requested_spawn_mode = args.spawn_mode.unwrap_or_default();
        let spawn_mode = if args.fork_context {
            match requested_spawn_mode {
                SpawnMode::Watchdog => {
                    return Err(FunctionCallError::RespondToModel(
                        "fork_context cannot be used with spawn_mode = \"watchdog\"".to_string(),
                    ));
                }
                SpawnMode::Spawn | SpawnMode::Fork => SpawnMode::Fork,
            }
        } else {
            requested_spawn_mode
        };
        let role_name = args
            .agent_type
            .as_deref()
            .map(str::trim)
            .filter(|role| !role.is_empty());
        let input_items = parse_collab_input(args.message, args.items)?;
        let prompt = render_input_preview(&input_items);
        let session_source = turn.session_source.clone();
        let child_depth = next_thread_spawn_depth(&session_source);
        if matches!(spawn_mode, SpawnMode::Watchdog)
            && matches!(
                session_source,
                codex_protocol::protocol::SessionSource::SubAgent(_)
            )
        {
            return Err(FunctionCallError::RespondToModel(
                "watchdogs can only be spawned by root agents".to_string(),
            ));
        }
        let max_depth = turn.config.agent_max_depth;
        if exceeds_thread_spawn_depth_limit(child_depth, max_depth) {
            return Err(FunctionCallError::RespondToModel(
                "Agent depth limit reached. Solve the task yourself.".to_string(),
            ));
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
        let mut config =
            build_agent_spawn_config(&session.get_base_instructions().await, turn.as_ref())?;
        if matches!(spawn_mode, SpawnMode::Fork) {
            reject_full_fork_spawn_overrides(
                role_name,
                args.model.as_deref(),
                args.reasoning_effort,
            )?;
        } else {
            apply_requested_spawn_agent_model_overrides(
                &session,
                turn.as_ref(),
                &mut config,
                args.model.as_deref(),
                args.reasoning_effort,
            )
            .await?;
            apply_role_to_config(&mut config, role_name)
                .await
                .map_err(FunctionCallError::RespondToModel)?;
        }
        apply_spawn_agent_runtime_overrides(&mut config, turn.as_ref())?;
        apply_spawn_agent_overrides(&mut config, child_depth);

        let spawn_source = thread_spawn_source(
            session.conversation_id,
            &turn.session_source,
            child_depth,
            role_name,
            /*task_name*/ None,
        )?;
        let environments = Some(
            turn.environments
                .iter()
                .map(TurnEnvironment::selection)
                .collect(),
        );
        let result = match spawn_mode {
            SpawnMode::Spawn | SpawnMode::Fork => {
                Box::pin(
                    session.services.agent_control.spawn_agent_with_metadata(
                        config,
                        input_items,
                        Some(spawn_source),
                        SpawnAgentOptions {
                            fork_parent_spawn_call_id: matches!(spawn_mode, SpawnMode::Fork)
                                .then(|| call_id.clone()),
                            fork_mode: matches!(spawn_mode, SpawnMode::Fork)
                                .then_some(SpawnAgentForkMode::FullHistory),
                            environments,
                        },
                    ),
                )
                .await
            }
            SpawnMode::Watchdog => {
                let interval_s = watchdog_interval(args.interval_s)?;
                spawn_watchdog(
                    &session.services.agent_control,
                    config,
                    prompt.clone(),
                    session.conversation_id,
                    child_depth,
                    interval_s,
                    spawn_source,
                    environments,
                )
                .await
            }
        }
        .map_err(collab_spawn_error);
        let (new_thread_id, new_agent_metadata, status) = match &result {
            Ok(spawned_agent) => (
                Some(spawned_agent.thread_id),
                Some(spawned_agent.metadata.clone()),
                spawned_agent.status.clone(),
            ),
            Err(_) => (None, None, AgentStatus::NotFound),
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
        let (_new_agent_path, new_agent_nickname, new_agent_role) =
            match (&agent_snapshot, new_agent_metadata) {
                (Some(snapshot), _) => (
                    snapshot.session_source.get_agent_path().map(String::from),
                    snapshot.session_source.get_nickname(),
                    snapshot.session_source.get_agent_role(),
                ),
                (None, Some(metadata)) => (
                    metadata.agent_path.map(String::from),
                    metadata.agent_nickname,
                    metadata.agent_role,
                ),
                (None, None) => (None, None, None),
            };
        let effective_model = agent_snapshot
            .as_ref()
            .map(|snapshot| snapshot.model.clone())
            .unwrap_or_else(|| args.model.clone().unwrap_or_default());
        let effective_reasoning_effort = agent_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.reasoning_effort)
            .unwrap_or(args.reasoning_effort.unwrap_or_default());
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
        let new_thread_id = result?.thread_id;
        session
            .services
            .agent_control
            .record_prompt_preview(new_thread_id, &prompt)
            .await;
        let role_tag = role_name.unwrap_or(DEFAULT_ROLE_NAME);
        turn.session_telemetry.counter(
            "codex.multi_agent.spawn",
            /*inc*/ 1,
            &[("role", role_tag)],
        );

        Ok(SpawnAgentResult {
            agent_id: new_thread_id.to_string(),
            nickname,
        })
    }
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
pub(crate) struct SpawnAgentResult {
    agent_id: String,
    nickname: Option<String>,
}

fn watchdog_interval(interval_override_s: Option<i64>) -> Result<i64, FunctionCallError> {
    let interval = interval_override_s.unwrap_or(DEFAULT_WATCHDOG_INTERVAL_S);
    if interval <= 0 {
        return Err(FunctionCallError::RespondToModel(
            "interval_s must be greater than zero".to_string(),
        ));
    }
    Ok(interval)
}

async fn spawn_watchdog(
    agent_control: &crate::agent::AgentControl,
    config: crate::config::Config,
    prompt: String,
    owner_thread_id: ThreadId,
    child_depth: i32,
    interval_s: i64,
    spawn_source: codex_protocol::protocol::SessionSource,
    environments: Option<Vec<codex_protocol::protocol::TurnEnvironmentSelection>>,
) -> crate::error::Result<crate::agent::control::LiveAgent> {
    let spawned_agent = agent_control
        .spawn_agent_handle(
            config.clone(),
            Some(spawn_source),
            SpawnAgentOptions {
                fork_parent_spawn_call_id: None,
                fork_mode: None,
                environments: environments.clone(),
            },
        )
        .await?;
    let superseded_before_register = agent_control
        .unregister_watchdogs_for_owner(owner_thread_id)
        .await;
    shutdown_removed_watchdogs(agent_control, superseded_before_register).await;
    let registration = WatchdogRegistration {
        owner_thread_id,
        target_thread_id: spawned_agent.thread_id,
        child_depth,
        interval_s,
        prompt,
        config,
        environments,
    };
    let superseded_after_register = match agent_control.register_watchdog(registration).await {
        Ok(superseded_after_register) => superseded_after_register,
        Err(err) => {
            let _ = agent_control
                .shutdown_live_agent(spawned_agent.thread_id)
                .await;
            return Err(err);
        }
    };
    shutdown_removed_watchdogs(agent_control, superseded_after_register).await;
    Ok(spawned_agent)
}

async fn shutdown_removed_watchdogs(
    agent_control: &crate::agent::AgentControl,
    removed_watchdogs: Vec<RemovedWatchdog>,
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
        let _ = agent_control.shutdown_live_agent(thread_id).await;
    }
}

impl ToolOutput for SpawnAgentResult {
    fn log_preview(&self) -> String {
        tool_output_json_text(self, "spawn_agent")
    }

    fn success_for_logging(&self) -> bool {
        true
    }

    fn to_response_item(&self, call_id: &str, payload: &ToolPayload) -> ResponseInputItem {
        tool_output_response_item(call_id, payload, self, Some(true), "spawn_agent")
    }

    fn code_mode_result(&self, _payload: &ToolPayload) -> JsonValue {
        tool_output_code_mode_result(self, "spawn_agent")
    }
}
