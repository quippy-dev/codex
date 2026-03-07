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
    require_message_for_final_status: bool,
) -> Option<String> {
    if last_completed_turn_used_collab_send_input {
        return None;
    }

    match status {
        AgentStatus::Completed(Some(message)) if !message.trim().is_empty() => Some(message.clone()),
        AgentStatus::Completed(None) | AgentStatus::Completed(Some(_))
            if require_message_for_final_status =>
        {
            Some(
                "Watchdog check-in completed without calling send_input or returning a final message."
                    .to_string(),
            )
        }
        AgentStatus::Errored(message) if require_message_for_final_status => {
            if message.trim().is_empty() {
                Some("Watchdog check-in failed before calling send_input.".to_string())
            } else {
                Some(format!(
                    "Watchdog check-in failed before calling send_input: {message}"
                ))
            }
        }
        AgentStatus::Shutdown if require_message_for_final_status => {
            Some("Watchdog check-in ended before calling send_input.".to_string())
        }
        AgentStatus::NotFound if require_message_for_final_status => {
            Some("Watchdog check-in disappeared before calling send_input.".to_string())
        }
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
            completed_message_for_collab_fallback(&completed, false, false),
            Some("done".to_string())
        );
        assert_eq!(
            completed_message_for_collab_fallback(&completed, true, false),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&whitespace, false, false),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&empty, false, false),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&errored, false, false),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&AgentStatus::PendingInit, false, false),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&AgentStatus::Running, false, false),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&AgentStatus::Shutdown, false, false),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&AgentStatus::NotFound, false, false),
            None
        );
        assert_eq!(
            completed_message_for_collab_fallback(&empty, false, true),
            Some(
                "Watchdog check-in completed without calling send_input or returning a final message."
                    .to_string(),
            )
        );
        assert_eq!(
            completed_message_for_collab_fallback(&whitespace, false, true),
            Some(
                "Watchdog check-in completed without calling send_input or returning a final message."
                    .to_string(),
            )
        );
        assert_eq!(
            completed_message_for_collab_fallback(&errored, false, true),
            Some("Watchdog check-in failed before calling send_input: boom".to_string())
        );
        assert_eq!(
            completed_message_for_collab_fallback(&AgentStatus::Shutdown, false, true),
            Some("Watchdog check-in ended before calling send_input.".to_string())
        );
        assert_eq!(
            completed_message_for_collab_fallback(&AgentStatus::NotFound, false, true),
            Some("Watchdog check-in disappeared before calling send_input.".to_string())
        );
    }
}
