use codex_protocol::protocol::AgentStatus;
use codex_protocol::protocol::EventMsg;

/// Derive the next agent status from a single emitted event.
/// Returns `None` when the event does not affect status tracking.
pub(crate) fn agent_status_from_event(msg: &EventMsg) -> Option<AgentStatus> {
    match msg {
        EventMsg::TurnStarted(_) => Some(AgentStatus::Running),
        EventMsg::TurnComplete(ev) => Some(AgentStatus::Completed(ev.last_agent_message.clone())),
        EventMsg::TurnAborted(ev) => Some(AgentStatus::Errored(format!("{:?}", ev.reason))),
        EventMsg::Error(ev) => Some(AgentStatus::Errored(ev.message.clone())),
        EventMsg::ShutdownComplete => Some(AgentStatus::Shutdown),
        _ => None,
    }
}

pub(crate) fn is_final(status: &AgentStatus) -> bool {
    !matches!(status, AgentStatus::PendingInit | AgentStatus::Running)
}

pub(crate) fn completed_message_for_collab_fallback(
    status: &AgentStatus,
    last_completed_turn_used_collab_send_input: bool,
) -> Option<&str> {
    if last_completed_turn_used_collab_send_input {
        return None;
    }

    match status {
        AgentStatus::Completed(Some(message)) if !message.trim().is_empty() => Some(message),
        AgentStatus::Completed(None)
        | AgentStatus::Completed(Some(_))
        | AgentStatus::PendingInit
        | AgentStatus::Running
        | AgentStatus::Errored(_)
        | AgentStatus::Shutdown
        | AgentStatus::NotFound => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn completed_message_for_collab_fallback_matrix() {
        let completed = AgentStatus::Completed(Some("done".to_string()));
        let whitespace = AgentStatus::Completed(Some(" \n\t ".to_string()));
        let empty = AgentStatus::Completed(None);
        let errored = AgentStatus::Errored("boom".to_string());

        assert_eq!(
            completed_message_for_collab_fallback(&completed, false),
            Some("done")
        );
        assert_eq!(
            completed_message_for_collab_fallback(&completed, true),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&whitespace, false),
            None
        );
        assert_eq!(completed_message_for_collab_fallback(&empty, false), None);
        assert_eq!(completed_message_for_collab_fallback(&errored, false), None);
        assert_eq!(
            completed_message_for_collab_fallback(&AgentStatus::PendingInit, false),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&AgentStatus::Running, false),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&AgentStatus::Shutdown, false),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&AgentStatus::NotFound, false),
            None
        );
    }
}
