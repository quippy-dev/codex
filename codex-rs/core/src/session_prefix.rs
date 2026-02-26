use crate::contextual_user_message::SUBAGENT_NOTIFICATION_CLOSE_TAG;
use crate::contextual_user_message::SUBAGENT_NOTIFICATION_FRAGMENT;
use crate::contextual_user_message::SUBAGENT_NOTIFICATION_OPEN_TAG;
use crate::contextual_user_message::TURN_ABORTED_OPEN_TAG;
use codex_protocol::protocol::AgentStatus;
use codex_protocol::protocol::ENVIRONMENT_CONTEXT_OPEN_TAG;
use serde::Deserialize;

/// Helpers for identifying model-visible "session prefix" messages.
///
/// A session prefix is a user-role message that carries configuration or state needed by
/// follow-up turns (e.g. `<environment_context>`, `<turn_aborted>`). These items are persisted in
/// history so the model can see them, but they are not user intent and must not create user-turn
/// boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct SubagentNotification {
    pub(crate) agent_id: String,
    pub(crate) status: AgentStatus,
}

fn starts_with_ascii_case_insensitive(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

/// Returns true if `text` starts with a session prefix marker (case-insensitive).
pub(crate) fn is_session_prefix(text: &str) -> bool {
    let trimmed = text.trim_start();
    starts_with_ascii_case_insensitive(trimmed, ENVIRONMENT_CONTEXT_OPEN_TAG)
        || starts_with_ascii_case_insensitive(trimmed, TURN_ABORTED_OPEN_TAG)
        || starts_with_ascii_case_insensitive(trimmed, SUBAGENT_NOTIFICATION_OPEN_TAG)
}

pub(crate) fn format_subagent_notification_message(agent_id: &str, status: &AgentStatus) -> String {
    let payload_json = serde_json::json!({
        "agent_id": agent_id,
        "status": status,
    })
    .to_string();
    SUBAGENT_NOTIFICATION_FRAGMENT.wrap(payload_json)
}

pub(crate) fn format_subagent_context_line(agent_id: &str, agent_nickname: Option<&str>) -> String {
    match agent_nickname.filter(|nickname| !nickname.is_empty()) {
        Some(agent_nickname) => format!("- {agent_id}: {agent_nickname}"),
        None => format!("- {agent_id}"),
    }
}

pub(crate) fn parse_subagent_notification(text: &str) -> Option<SubagentNotification> {
    let trimmed = text.trim();
    let payload = trimmed
        .strip_prefix(SUBAGENT_NOTIFICATION_OPEN_TAG)?
        .strip_suffix(SUBAGENT_NOTIFICATION_CLOSE_TAG)?;
    serde_json::from_str::<SubagentNotification>(payload.trim()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parse_subagent_notification_round_trips_format() {
        let message = format_subagent_notification_message(
            "agent-1",
            &AgentStatus::Completed(Some("done".to_string())),
        );
        let parsed = parse_subagent_notification(&message);

        assert_eq!(
            parsed,
            Some(SubagentNotification {
                agent_id: "agent-1".to_string(),
                status: AgentStatus::Completed(Some("done".to_string())),
            })
        );
    }

    #[test]
    fn parse_subagent_notification_handles_embedded_close_tag_in_payload() {
        let embedded_close_tag = format!("contains {}", SUBAGENT_NOTIFICATION_CLOSE_TAG);
        let message = format_subagent_notification_message(
            "agent-1",
            &AgentStatus::Completed(Some(embedded_close_tag.clone())),
        );
        let parsed = parse_subagent_notification(&message);

        assert_eq!(
            parsed,
            Some(SubagentNotification {
                agent_id: "agent-1".to_string(),
                status: AgentStatus::Completed(Some(embedded_close_tag)),
            })
        );
    }

    #[test]
    fn is_session_prefix_is_case_insensitive() {
        assert_eq!(
            is_session_prefix("<SUBAGENT_NOTIFICATION>{}</subagent_notification>"),
            true
        );
    }
}
