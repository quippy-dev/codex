use codex_protocol::protocol::AgentSpawnMode;

pub(crate) fn merge_subagent_identity(
    nickname: &mut Option<String>,
    agent_role: &mut Option<String>,
    incoming_nickname: Option<&str>,
    incoming_agent_role: Option<&str>,
) {
    if let Some(nickname_value) = normalized_identity_value(incoming_nickname) {
        *nickname = Some(nickname_value);
    }
    if let Some(agent_role_value) = normalized_identity_value(incoming_agent_role) {
        *agent_role = Some(agent_role_value);
    }
}

pub(crate) fn format_subagent_label(
    ordinal: i32,
    agent_nickname: Option<&str>,
    agent_role: Option<&str>,
    spawn_mode: AgentSpawnMode,
) -> String {
    let base =
        normalized_identity_value(agent_nickname).unwrap_or_else(|| format!("Agent #{ordinal}"));
    if spawn_mode == AgentSpawnMode::Watchdog {
        return format!("{base} [watchdog]");
    }

    match normalized_identity_value(agent_role) {
        Some(agent_role_value) => format!("{base} [{agent_role_value}]"),
        None => base,
    }
}

fn normalized_identity_value(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}
