use super::control::AgentControl;
use super::control::LateAgentDeliveryMode;
use super::inbox_delivery::build_agent_inbox_items;
use crate::codex::DeferredCollabEnqueueError;
use crate::error::CodexErr;
use crate::error::Result as CodexResult;
use codex_protocol::ThreadId;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::AgentStatus;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::SessionSource;
use codex_protocol::user_input::UserInput;
#[cfg(test)]
use std::future::Future;
#[cfg(test)]
use std::pin::Pin;
use tracing::warn;
use uuid::Uuid;

impl AgentControl {
    /// Send a `user` prompt to an existing agent thread.
    pub(crate) async fn send_prompt(
        &self,
        agent_id: ThreadId,
        prompt: String,
    ) -> CodexResult<String> {
        self.send_input(
            agent_id,
            vec![UserInput::Text {
                text: prompt,
                text_elements: Vec::new(),
            }],
        )
        .await
    }

    /// Send rich user input items to an existing agent thread.
    pub(crate) async fn send_input(
        &self,
        agent_id: ThreadId,
        items: Vec<UserInput>,
    ) -> CodexResult<String> {
        let state = self.upgrade()?;
        let result = state
            .send_op(
                agent_id,
                Op::UserInput {
                    items,
                    final_output_json_schema: None,
                },
            )
            .await;
        if matches!(result, Err(CodexErr::InternalAgentDied)) {
            let _ = state.remove_thread(&agent_id).await;
            self.guards.release_spawned_thread(agent_id);
        }
        result
    }

    async fn note_watchdog_delivery_if_needed(
        &self,
        sender_thread_id: ThreadId,
        sender_is_watchdog_helper_for_receiver: bool,
    ) {
        if sender_is_watchdog_helper_for_receiver {
            let _ = self
                .mark_watchdog_idle_episode_satisfied_for_helper(sender_thread_id)
                .await;
        }
    }

    pub(crate) async fn drop_pending_input(&self, agent_id: ThreadId) -> CodexResult<bool> {
        let state = self.upgrade()?;
        let thread = state.get_thread(agent_id).await?;
        Ok(thread.codex.session.drop_pending_input().await)
    }

    pub(crate) fn was_spawned_thread(&self, agent_id: ThreadId) -> bool {
        self.guards.was_spawned_thread(agent_id)
    }

    /// Send a prompt to an existing agent thread using the configured collab inbox delivery role.
    pub(crate) async fn send_agent_message(
        &self,
        agent_id: ThreadId,
        sender_thread_id: ThreadId,
        message: String,
    ) -> CodexResult<String> {
        self.send_agent_message_inner(
            agent_id,
            sender_thread_id,
            message,
            true,
            LateAgentDeliveryMode::QueuePostTurn,
            #[cfg(test)]
            None,
        )
        .await
    }

    pub(crate) async fn send_agent_message_inner(
        &self,
        agent_id: ThreadId,
        sender_thread_id: ThreadId,
        message: String,
        record_live_sender_message_for_completion_dedupe: bool,
        late_delivery_mode: LateAgentDeliveryMode,
        #[cfg(test)] before_live_inject: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
    ) -> CodexResult<String> {
        let state = self.upgrade()?;
        let thread = state.get_thread(agent_id).await?;
        let snapshot = thread.config_snapshot().await;
        let (sender_agent_nickname, sender_agent_role) = self
            .get_agent_nickname_and_role(sender_thread_id)
            .await
            .unwrap_or((None, None));

        if matches!(snapshot.session_source, SessionSource::SubAgent(_)) {
            return self.send_prompt(agent_id, message).await;
        }

        let receiver_has_active_turn = thread.has_active_turn().await;
        let post_turn_agent_flush_pending =
            thread.codex.session.post_turn_agent_flush_pending().await;
        let post_interrupt_collab_hold_armed = thread
            .codex
            .session
            .post_interrupt_collab_hold_armed()
            .await;
        let sender_is_watchdog_helper_for_receiver = self
            .watchdog_owner_for_active_helper(sender_thread_id)
            .await
            == Some(agent_id);
        if should_queue_agent_delivery_until_turn_end(post_turn_agent_flush_pending) {
            let queued_items = build_agent_inbox_items(
                snapshot.collab_inbox_delivery_role,
                sender_thread_id,
                sender_agent_nickname.clone(),
                sender_agent_role.clone(),
                message.clone(),
                false,
            )?;
            match thread
                .codex
                .session
                .enqueue_post_turn_agent_items(queued_items)
                .await
            {
                Ok(()) => {
                    self.note_watchdog_delivery_if_needed(
                        sender_thread_id,
                        sender_is_watchdog_helper_for_receiver,
                    )
                    .await;
                    return Ok(Uuid::now_v7().to_string());
                }
                Err(err) => log_post_turn_agent_enqueue_error(agent_id, sender_thread_id, err),
            }
        }
        if receiver_has_active_turn {
            #[cfg(test)]
            if let Some(before_live_inject) = before_live_inject {
                before_live_inject.await;
            }
            let live_items = build_agent_inbox_items(
                snapshot.collab_inbox_delivery_role,
                sender_thread_id,
                sender_agent_nickname.clone(),
                sender_agent_role.clone(),
                message.clone(),
                false,
            )?;
            match thread.codex.session.inject_response_items(live_items).await {
                Ok(()) => {
                    if record_live_sender_message_for_completion_dedupe {
                        self.record_live_forwarded_agent_message(sender_thread_id, &message)
                            .await;
                    }
                    self.note_watchdog_delivery_if_needed(
                        sender_thread_id,
                        sender_is_watchdog_helper_for_receiver,
                    )
                    .await;
                    return Ok(Uuid::now_v7().to_string());
                }
                Err(late_items) => {
                    let post_interrupt_collab_hold_armed = thread
                        .codex
                        .session
                        .post_interrupt_collab_hold_armed()
                        .await;
                    let should_defer_late_items = should_defer_agent_delivery(
                        false,
                        post_interrupt_collab_hold_armed,
                        sender_is_watchdog_helper_for_receiver,
                    );
                    if should_defer_late_items {
                        match thread
                            .codex
                            .session
                            .enqueue_deferred_collab_items(late_items)
                            .await
                        {
                            Ok(()) => {
                                self.note_watchdog_delivery_if_needed(
                                    sender_thread_id,
                                    sender_is_watchdog_helper_for_receiver,
                                )
                                .await;
                                return Ok(Uuid::now_v7().to_string());
                            }
                            Err(err) => {
                                log_deferred_agent_enqueue_error(agent_id, sender_thread_id, err)
                            }
                        }
                    } else if late_delivery_mode
                        == LateAgentDeliveryMode::LiveOnlyAfterSamplingComplete
                        && let Some(turn_context) =
                            thread.codex.session.current_active_turn_context().await
                    {
                        let sender_thread_id_text = sender_thread_id.to_string();
                        if thread
                            .codex
                            .session
                            .active_turn_has_live_emitted_agent_inbox_message(
                                sender_thread_id_text.as_str(),
                                &message,
                            )
                            .await
                        {
                            return Ok(Uuid::now_v7().to_string());
                        }
                        let live_response_items = late_items
                            .into_iter()
                            .map(ResponseItem::from)
                            .collect::<Vec<_>>();
                        thread
                            .codex
                            .session
                            .record_conversation_items(turn_context.as_ref(), &live_response_items)
                            .await;
                        if record_live_sender_message_for_completion_dedupe {
                            self.record_live_forwarded_agent_message(sender_thread_id, &message)
                                .await;
                        }
                        self.note_watchdog_delivery_if_needed(
                            sender_thread_id,
                            sender_is_watchdog_helper_for_receiver,
                        )
                        .await;
                        return Ok(Uuid::now_v7().to_string());
                    } else {
                        match thread
                            .codex
                            .session
                            .enqueue_post_turn_agent_items(late_items)
                            .await
                        {
                            Ok(()) => {
                                if thread
                                    .codex
                                    .session
                                    .arm_post_turn_agent_flush_if_items()
                                    .await
                                {
                                    if thread.has_active_turn().await {
                                        self.note_watchdog_delivery_if_needed(
                                            sender_thread_id,
                                            sender_is_watchdog_helper_for_receiver,
                                        )
                                        .await;
                                        return Ok(Uuid::now_v7().to_string());
                                    }
                                    if let Err(err) = state
                                        .send_op(
                                            agent_id,
                                            Op::InjectResponseItems { items: Vec::new() },
                                        )
                                        .await
                                    {
                                        warn!(
                                            receiver_thread_id = %agent_id,
                                            sender_thread_id = %sender_thread_id,
                                            "failed to submit post-turn agent items after late active-turn inject miss: {err}"
                                        );
                                        thread.codex.session.clear_post_turn_agent_items().await;
                                    } else {
                                        self.note_watchdog_delivery_if_needed(
                                            sender_thread_id,
                                            sender_is_watchdog_helper_for_receiver,
                                        )
                                        .await;
                                        return Ok(Uuid::now_v7().to_string());
                                    }
                                } else {
                                    self.note_watchdog_delivery_if_needed(
                                        sender_thread_id,
                                        sender_is_watchdog_helper_for_receiver,
                                    )
                                    .await;
                                    return Ok(Uuid::now_v7().to_string());
                                }
                            }
                            Err(err) => {
                                log_post_turn_agent_enqueue_error(agent_id, sender_thread_id, err)
                            }
                        }
                    }
                }
            }
        }
        if should_defer_agent_delivery(
            receiver_has_active_turn,
            post_interrupt_collab_hold_armed,
            sender_is_watchdog_helper_for_receiver,
        ) {
            let deferred_items = build_agent_inbox_items(
                snapshot.collab_inbox_delivery_role,
                sender_thread_id,
                sender_agent_nickname.clone(),
                sender_agent_role.clone(),
                message.clone(),
                false,
            )?;
            match thread
                .codex
                .session
                .enqueue_deferred_collab_items(deferred_items)
                .await
            {
                Ok(()) => {
                    self.note_watchdog_delivery_if_needed(
                        sender_thread_id,
                        sender_is_watchdog_helper_for_receiver,
                    )
                    .await;
                    return Ok(Uuid::now_v7().to_string());
                }
                Err(err) => log_deferred_agent_enqueue_error(agent_id, sender_thread_id, err),
            }
        }

        let items = build_agent_inbox_items(
            snapshot.collab_inbox_delivery_role,
            sender_thread_id,
            sender_agent_nickname,
            sender_agent_role,
            message.clone(),
            false,
        )?;
        let submission_id = state
            .send_op(agent_id, Op::InjectResponseItems { items })
            .await?;
        self.note_watchdog_delivery_if_needed(
            sender_thread_id,
            sender_is_watchdog_helper_for_receiver,
        )
        .await;
        Ok(submission_id)
    }

    async fn record_live_forwarded_agent_message(&self, sender_thread_id: ThreadId, message: &str) {
        if let Ok(state) = self.upgrade()
            && let Ok(sender_thread) = state.get_thread(sender_thread_id).await
        {
            sender_thread
                .codex
                .session
                .record_turn_live_forwarded_agent_message(message)
                .await;
        }
    }
}

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
