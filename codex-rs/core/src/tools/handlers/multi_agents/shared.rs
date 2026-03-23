use super::*;
use crate::config::Config;

pub(crate) fn agent_id(id: &str) -> Result<ThreadId, FunctionCallError> {
    ThreadId::from_string(id)
        .map_err(|e| FunctionCallError::RespondToModel(format!("invalid agent id {id}: {e:?}")))
}

pub(crate) fn multi_agent_spawn_error(err: CodexErr) -> FunctionCallError {
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

pub(crate) fn multi_agent_tool_error(agent_id: ThreadId, err: CodexErr) -> FunctionCallError {
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
pub(crate) fn thread_spawn_source(parent_thread_id: ThreadId, depth: i32) -> SessionSource {
    thread_spawn_source_with_metadata(parent_thread_id, depth, None, None)
}

pub(crate) fn thread_spawn_source_with_metadata(
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

pub(crate) fn parse_multi_agent_input(
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

pub(crate) fn input_preview(items: &[UserInput]) -> String {
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

pub(crate) fn single_text_input(items: &[UserInput]) -> Option<String> {
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

pub(crate) fn build_agent_resume_config(
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

pub(crate) fn apply_spawn_agent_runtime_overrides(
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

pub(crate) fn apply_spawn_agent_overrides(config: &mut Config, child_depth: i32) {
    if child_depth >= config.agent_max_depth {
        let _ = config.features.disable(Feature::SpawnCsv);
        let _ = config.features.disable(Feature::Collab);
    }
}

pub(crate) async fn apply_spawn_agent_model_overrides(
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

pub(crate) async fn revalidate_spawn_agent_model_reasoning(
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

pub(crate) fn build_wait_agent_statuses(
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

pub(crate) fn watchdog_ref_spawn_mode(
    watchdog_target_ids: &HashSet<ThreadId>,
    receiver_thread_id: ThreadId,
) -> Option<AgentSpawnMode> {
    watchdog_target_ids
        .contains(&receiver_thread_id)
        .then_some(AgentSpawnMode::Watchdog)
}

pub(crate) async fn resolve_owner_thread_id(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpawnConfigStrategy {
    ContextFreeSpawn,
    ForkLike,
}
