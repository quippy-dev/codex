use crate::codex::DeferredCollabEnqueueError;
use codex_protocol::ThreadId;
use codex_protocol::protocol::AgentStatus;
use tracing::warn;

pub(crate) fn should_defer_collab_delivery(
    receiver_has_active_turn: bool,
    post_interrupt_collab_hold_armed: bool,
    sender_is_watchdog_helper_for_receiver: bool,
) -> bool {
    !receiver_has_active_turn
        && post_interrupt_collab_hold_armed
        && !sender_is_watchdog_helper_for_receiver
}

pub(crate) fn log_deferred_collab_enqueue_error(
    agent_id: ThreadId,
    sender_thread_id: ThreadId,
    err: DeferredCollabEnqueueError,
) {
    match err {
        DeferredCollabEnqueueError::TooManyItems {
            existing_items,
            incoming_items,
            max_items,
        } => {
            warn!(
                receiver_thread_id = %agent_id,
                sender_thread_id = %sender_thread_id,
                existing_items,
                incoming_items,
                max_items,
                "deferred collab queue item limit exceeded; injecting immediately and relaxing ordering guarantee"
            );
        }
        DeferredCollabEnqueueError::TooManyBytes {
            existing_bytes,
            incoming_bytes,
            max_bytes,
        } => {
            warn!(
                receiver_thread_id = %agent_id,
                sender_thread_id = %sender_thread_id,
                existing_bytes,
                incoming_bytes,
                max_bytes,
                "deferred collab queue byte limit exceeded; injecting immediately and relaxing ordering guarantee"
            );
        }
        DeferredCollabEnqueueError::Serialization { message } => {
            warn!(
                receiver_thread_id = %agent_id,
                sender_thread_id = %sender_thread_id,
                error = message,
                "failed to serialize deferred collab payload; injecting immediately and relaxing ordering guarantee"
            );
        }
    }
}

pub(crate) fn completed_message_for_collab_fallback(
    status: &AgentStatus,
    last_completed_turn_used_agent_send_input: bool,
    require_message_for_final_status: bool,
) -> Option<String> {
    if last_completed_turn_used_agent_send_input {
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
