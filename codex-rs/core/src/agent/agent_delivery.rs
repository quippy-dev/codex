use crate::codex::DeferredCollabEnqueueError;
use codex_protocol::ThreadId;
use codex_protocol::protocol::AgentStatus;
use tracing::warn;

pub(crate) fn should_queue_agent_delivery_until_turn_end(
    post_turn_agent_flush_pending: bool,
) -> bool {
    post_turn_agent_flush_pending
}

pub(crate) fn should_defer_agent_delivery(
    receiver_has_active_turn: bool,
    post_interrupt_agent_hold_armed: bool,
    sender_is_watchdog_helper_for_receiver: bool,
) -> bool {
    !receiver_has_active_turn
        && post_interrupt_agent_hold_armed
        && !sender_is_watchdog_helper_for_receiver
}

pub(crate) fn log_post_turn_agent_enqueue_error(
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
                "post-turn agent queue item limit exceeded; injecting immediately and relaxing ordering guarantee"
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
                "post-turn agent queue byte limit exceeded; injecting immediately and relaxing ordering guarantee"
            );
        }
        DeferredCollabEnqueueError::Serialization { message } => {
            warn!(
                receiver_thread_id = %agent_id,
                sender_thread_id = %sender_thread_id,
                error = message,
                "failed to serialize post-turn agent payload; injecting immediately and relaxing ordering guarantee"
            );
        }
    }
}

pub(crate) fn log_deferred_agent_enqueue_error(
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
                "deferred agent queue item limit exceeded; injecting immediately and relaxing ordering guarantee"
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
                "deferred agent queue byte limit exceeded; injecting immediately and relaxing ordering guarantee"
            );
        }
        DeferredCollabEnqueueError::Serialization { message } => {
            warn!(
                receiver_thread_id = %agent_id,
                sender_thread_id = %sender_thread_id,
                error = message,
                "failed to serialize deferred agent payload; injecting immediately and relaxing ordering guarantee"
            );
        }
    }
}

pub(crate) fn completed_message_for_agent_fallback(
    status: &AgentStatus,
    last_completed_turn_used_agent_send_input: bool,
    last_completed_turn_forwarded_same_message: bool,
    require_message_for_final_status: bool,
) -> Option<String> {
    if require_message_for_final_status && last_completed_turn_used_agent_send_input {
        return None;
    }

    match status {
        AgentStatus::Completed(Some(message))
            if !message.trim().is_empty() && !last_completed_turn_forwarded_same_message =>
        {
            Some(message.clone())
        }
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
        | AgentStatus::Interrupted
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
    fn completed_message_for_agent_fallback_matrix() {
        let completed = AgentStatus::Completed(Some("done".to_string()));
        let whitespace = AgentStatus::Completed(Some(" \n\t ".to_string()));
        let empty = AgentStatus::Completed(None);
        let errored = AgentStatus::Errored("boom".to_string());

        assert_eq!(
            completed_message_for_agent_fallback(&completed, false, false, false),
            Some("done".to_string())
        );
        assert_eq!(
            completed_message_for_agent_fallback(&completed, false, true, false),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&whitespace, false, false, false),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&empty, false, false, false),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&errored, false, false, false),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&AgentStatus::PendingInit, false, false, false),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&AgentStatus::Running, false, false, false),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&AgentStatus::Shutdown, false, false, false),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&AgentStatus::NotFound, false, false, false),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&empty, false, false, true),
            Some(
                "Watchdog check-in completed without calling send_input or returning a final message."
                    .to_string(),
            )
        );
        assert_eq!(
            completed_message_for_agent_fallback(&whitespace, false, false, true),
            Some(
                "Watchdog check-in completed without calling send_input or returning a final message."
                    .to_string(),
            )
        );
        assert_eq!(
            completed_message_for_agent_fallback(&errored, false, false, true),
            Some("Watchdog check-in failed before calling send_input: boom".to_string())
        );
        assert_eq!(
            completed_message_for_agent_fallback(&AgentStatus::Shutdown, false, false, true),
            Some("Watchdog check-in ended before calling send_input.".to_string())
        );
        assert_eq!(
            completed_message_for_agent_fallback(&AgentStatus::NotFound, false, false, true),
            Some("Watchdog check-in disappeared before calling send_input.".to_string())
        );
        assert_eq!(
            completed_message_for_agent_fallback(&empty, true, false, true),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&completed, true, false, true),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&whitespace, true, false, true),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&errored, true, false, true),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&AgentStatus::Shutdown, true, false, true),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&AgentStatus::NotFound, true, false, true),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&completed, true, false, true),
            None
        );
        assert_eq!(
            completed_message_for_agent_fallback(&completed, true, false, false),
            Some("done".to_string())
        );
    }
}
