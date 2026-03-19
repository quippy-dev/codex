/*
This module holds the temporary adapter layer between the TUI and the app
server during the hybrid migration period.

For now, the TUI still owns its existing direct-core behavior, but startup
allocates a local in-process app server and drains its event stream. Keeping
the app-server-specific wiring here keeps that transitional logic out of the
main `app.rs` orchestration path.

As more TUI flows move onto the app-server surface directly, this adapter
should shrink and eventually disappear.
*/

use super::App;
use crate::app_event::AppEvent;
use crate::app_server_session::AppServerSession;
use crate::app_server_session::app_server_rate_limit_snapshot_to_core;
use crate::app_server_session::status_account_display_from_auth_mode;
use crate::local_chatgpt_auth::load_local_chatgpt_auth;
use codex_app_server_client::AppServerEvent;
use codex_app_server_protocol::ChatgptAuthTokensRefreshParams;
use codex_app_server_protocol::JSONRPCErrorError;
use codex_app_server_protocol::RequestId;
use codex_app_server_protocol::ServerNotification;
use codex_app_server_protocol::ServerRequest;
#[cfg(test)]
use codex_app_server_protocol::Thread;
use codex_app_server_protocol::ThreadItem;
use codex_app_server_protocol::Turn;
use codex_app_server_protocol::TurnStatus;
use codex_protocol::ThreadId;
use codex_protocol::config_types::ModeKind;
use codex_protocol::items::AgentMessageContent;
use codex_protocol::items::AgentMessageItem;
use codex_protocol::items::ContextCompactionItem;
use codex_protocol::items::ImageGenerationItem;
use codex_protocol::items::PlanItem;
use codex_protocol::items::ReasoningItem;
use codex_protocol::items::TurnItem;
use codex_protocol::items::UserMessageItem;
use codex_protocol::items::WebSearchItem;
use codex_protocol::protocol::AgentMessageDeltaEvent;
use codex_protocol::protocol::AgentReasoningDeltaEvent;
use codex_protocol::protocol::AgentReasoningRawContentDeltaEvent;
use codex_protocol::protocol::ContextCompactedEvent;
use codex_protocol::protocol::DeprecationNoticeEvent;
use codex_protocol::protocol::ErrorEvent;
use codex_protocol::protocol::Event;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::GuardianAssessmentEvent;
use codex_protocol::protocol::GuardianAssessmentStatus;
use codex_protocol::protocol::GuardianRiskLevel;
use codex_protocol::protocol::ItemCompletedEvent;
use codex_protocol::protocol::ItemStartedEvent;
use codex_protocol::protocol::PlanDeltaEvent;
use codex_protocol::protocol::RealtimeConversationClosedEvent;
use codex_protocol::protocol::RealtimeConversationRealtimeEvent;
use codex_protocol::protocol::RealtimeConversationStartedEvent;
use codex_protocol::protocol::RealtimeEvent;
use codex_protocol::protocol::RealtimeHandoffRequested;
use codex_protocol::protocol::RealtimeInputAudioSpeechStarted;
use codex_protocol::protocol::RealtimeResponseCancelled;
use codex_protocol::protocol::RealtimeTranscriptEntry;
use codex_protocol::protocol::TerminalInteractionEvent;
use codex_protocol::protocol::ThreadNameUpdatedEvent;
use codex_protocol::protocol::TokenCountEvent;
use codex_protocol::protocol::TokenUsage;
use codex_protocol::protocol::TokenUsageInfo;
use codex_protocol::protocol::TurnAbortReason;
use codex_protocol::protocol::TurnAbortedEvent;
use codex_protocol::protocol::TurnCompleteEvent;
use codex_protocol::protocol::TurnDiffEvent;
use codex_protocol::protocol::TurnStartedEvent;
use serde_json::Value;

impl App {
    pub(super) async fn handle_app_server_event(
        &mut self,
        app_server_client: &AppServerSession,
        event: AppServerEvent,
    ) {
        match event {
            AppServerEvent::Lagged { skipped } => {
                tracing::warn!(
                    skipped,
                    "app-server event consumer lagged; dropping ignored events"
                );
            }
            AppServerEvent::ServerNotification(notification) => match notification {
                ServerNotification::ServerRequestResolved(notification) => {
                    self.pending_app_server_requests
                        .resolve_notification(&notification.request_id);
                }
                ServerNotification::AccountRateLimitsUpdated(notification) => {
                    self.chat_widget.on_rate_limit_snapshot(Some(
                        app_server_rate_limit_snapshot_to_core(notification.rate_limits),
                    ));
                }
                ServerNotification::AccountUpdated(notification) => {
                    self.chat_widget.update_account_state(
                        status_account_display_from_auth_mode(
                            notification.auth_mode,
                            notification.plan_type,
                        ),
                        notification.plan_type,
                        matches!(
                            notification.auth_mode,
                            Some(codex_app_server_protocol::AuthMode::Chatgpt)
                        ),
                    );
                }
                notification => {
                    if let Some(events) = server_notification_global_events(&notification) {
                        for event in events {
                            if let Err(err) = self.enqueue_primary_event(event).await {
                                tracing::warn!(
                                    "failed to enqueue primary app-server server notification: {err}"
                                );
                            }
                        }
                        return;
                    }
                    if !app_server_client.is_remote()
                        && matches!(
                            notification,
                            ServerNotification::TurnCompleted(_)
                                | ServerNotification::ThreadRealtimeItemAdded(_)
                                | ServerNotification::ThreadRealtimeOutputAudioDelta(_)
                                | ServerNotification::ThreadRealtimeError(_)
                        )
                    {
                        return;
                    }
                    if let Some((thread_id, events)) =
                        server_notification_thread_events(notification)
                    {
                        for event in events {
                            if self.primary_thread_id.is_none()
                                || matches!(event.msg, EventMsg::SessionConfigured(_))
                                    && self.primary_thread_id == Some(thread_id)
                            {
                                if let Err(err) = self.enqueue_primary_event(event).await {
                                    tracing::warn!(
                                        "failed to enqueue primary app-server server notification: {err}"
                                    );
                                }
                            } else if let Err(err) =
                                self.enqueue_thread_event(thread_id, event).await
                            {
                                tracing::warn!(
                                    "failed to enqueue app-server server notification for {thread_id}: {err}"
                                );
                            }
                        }
                    }
                }
            },
            AppServerEvent::LegacyNotification(notification) => {
                if let Some((thread_id, event)) = legacy_thread_event(notification.params) {
                    self.pending_app_server_requests.note_legacy_event(&event);
                    if legacy_event_is_shadowed_by_server_notification(&event.msg) {
                        return;
                    }
                    if self.primary_thread_id.is_none()
                        || matches!(event.msg, EventMsg::SessionConfigured(_))
                            && self.primary_thread_id == Some(thread_id)
                    {
                        if let Err(err) = self.enqueue_primary_event(event).await {
                            tracing::warn!("failed to enqueue primary app-server event: {err}");
                        }
                    } else if let Err(err) = self.enqueue_thread_event(thread_id, event).await {
                        tracing::warn!(
                            "failed to enqueue app-server thread event for {thread_id}: {err}"
                        );
                    }
                }
            }
            AppServerEvent::ServerRequest(request) => {
                if let ServerRequest::ChatgptAuthTokensRefresh { request_id, params } = request {
                    self.handle_chatgpt_auth_tokens_refresh_request(
                        app_server_client,
                        request_id,
                        params,
                    )
                    .await;
                    return;
                }
                if let Some(unsupported) = self
                    .pending_app_server_requests
                    .note_server_request(&request)
                {
                    tracing::warn!(
                        request_id = ?unsupported.request_id,
                        message = unsupported.message,
                        "rejecting unsupported app-server request"
                    );
                    self.chat_widget
                        .add_error_message(unsupported.message.clone());
                    if let Err(err) = self
                        .reject_app_server_request(
                            app_server_client,
                            unsupported.request_id,
                            unsupported.message,
                        )
                        .await
                    {
                        tracing::warn!("{err}");
                    }
                }
            }
            AppServerEvent::Disconnected { message } => {
                tracing::warn!("app-server event stream disconnected: {message}");
                self.chat_widget.add_error_message(message.clone());
                self.app_event_tx.send(AppEvent::FatalExitRequest(message));
            }
        }
    }

    async fn handle_chatgpt_auth_tokens_refresh_request(
        &mut self,
        app_server_client: &AppServerSession,
        request_id: RequestId,
        params: ChatgptAuthTokensRefreshParams,
    ) {
        let auth_storage_home = self.chat_widget.auth_manager.storage_home().to_path_buf();
        let auth_credentials_store_mode = self.config.cli_auth_credentials_store_mode;
        let forced_chatgpt_workspace_id = self.config.forced_chatgpt_workspace_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            resolve_chatgpt_auth_tokens_refresh_response(
                &auth_storage_home,
                auth_credentials_store_mode,
                forced_chatgpt_workspace_id.as_deref(),
                &params,
            )
        })
        .await;

        match result {
            Ok(Ok(response)) => {
                let response = serde_json::to_value(response).map_err(|err| {
                    format!("failed to serialize chatgpt auth refresh response: {err}")
                });
                match response {
                    Ok(response) => {
                        if let Err(err) = app_server_client
                            .resolve_server_request(request_id, response)
                            .await
                        {
                            tracing::warn!("failed to resolve chatgpt auth refresh request: {err}");
                        }
                    }
                    Err(err) => {
                        self.chat_widget.add_error_message(err.clone());
                        if let Err(reject_err) = self
                            .reject_app_server_request(app_server_client, request_id, err)
                            .await
                        {
                            tracing::warn!("{reject_err}");
                        }
                    }
                }
            }
            Ok(Err(err)) => {
                self.chat_widget.add_error_message(err.clone());
                if let Err(reject_err) = self
                    .reject_app_server_request(app_server_client, request_id, err)
                    .await
                {
                    tracing::warn!("{reject_err}");
                }
            }
            Err(err) => {
                let message = format!("chatgpt auth refresh task failed: {err}");
                self.chat_widget.add_error_message(message.clone());
                if let Err(reject_err) = self
                    .reject_app_server_request(app_server_client, request_id, message)
                    .await
                {
                    tracing::warn!("{reject_err}");
                }
            }
        }
    }

    async fn reject_app_server_request(
        &self,
        app_server_client: &AppServerSession,
        request_id: codex_app_server_protocol::RequestId,
        reason: String,
    ) -> std::result::Result<(), String> {
        app_server_client
            .reject_server_request(
                request_id,
                JSONRPCErrorError {
                    code: -32000,
                    message: reason,
                    data: None,
                },
            )
            .await
            .map_err(|err| format!("failed to reject app-server request: {err}"))
    }
}

fn resolve_chatgpt_auth_tokens_refresh_response(
    codex_home: &std::path::Path,
    auth_credentials_store_mode: codex_core::auth::AuthCredentialsStoreMode,
    forced_chatgpt_workspace_id: Option<&str>,
    params: &ChatgptAuthTokensRefreshParams,
) -> Result<codex_app_server_protocol::ChatgptAuthTokensRefreshResponse, String> {
    let auth = load_local_chatgpt_auth(
        codex_home,
        auth_credentials_store_mode,
        forced_chatgpt_workspace_id,
    )?;
    if let Some(previous_account_id) = params.previous_account_id.as_deref()
        && previous_account_id != auth.chatgpt_account_id
    {
        return Err(format!(
            "local ChatGPT auth refresh account mismatch: expected `{previous_account_id}`, got `{}`",
            auth.chatgpt_account_id
        ));
    }
    Ok(
        codex_app_server_protocol::ChatgptAuthTokensRefreshResponse {
            access_token: auth.access_token,
            chatgpt_account_id: auth.chatgpt_account_id,
            chatgpt_plan_type: auth.chatgpt_plan_type,
        },
    )
}

/// Convert a `Thread` snapshot into a flat sequence of protocol `Event`s
/// suitable for replaying into the TUI event store.
///
/// Each turn is expanded into `TurnStarted`, zero or more `ItemCompleted`,
/// and a terminal event that matches the turn's `TurnStatus`. Returns an
/// empty vec (with a warning log) if the thread ID is not a valid UUID.
#[cfg(test)]
pub(super) fn thread_snapshot_events(
    thread: &Thread,
    show_raw_agent_reasoning: bool,
) -> Vec<Event> {
    let Ok(thread_id) = ThreadId::from_string(&thread.id) else {
        tracing::warn!(
            thread_id = %thread.id,
            "ignoring app-server thread snapshot with invalid thread id"
        );
        return Vec::new();
    };

    thread
        .turns
        .iter()
        .flat_map(|turn| turn_snapshot_events(thread_id, turn, show_raw_agent_reasoning))
        .collect()
}

fn legacy_thread_event(params: Option<Value>) -> Option<(ThreadId, Event)> {
    let Value::Object(mut params) = params? else {
        return None;
    };
    let thread_id = params
        .remove("conversationId")
        .and_then(|value| serde_json::from_value::<String>(value).ok())
        .and_then(|value| ThreadId::from_string(&value).ok());
    let event = serde_json::from_value::<Event>(Value::Object(params)).ok()?;
    let thread_id = thread_id.or(match &event.msg {
        EventMsg::SessionConfigured(session) => Some(session.session_id),
        _ => None,
    })?;
    Some((thread_id, event))
}

fn legacy_event_is_shadowed_by_server_notification(msg: &EventMsg) -> bool {
    matches!(
        msg,
        EventMsg::TokenCount(_)
            | EventMsg::Error(_)
            | EventMsg::ThreadNameUpdated(_)
            | EventMsg::TurnStarted(_)
            | EventMsg::ItemStarted(_)
            | EventMsg::ItemCompleted(_)
            | EventMsg::AgentMessageDelta(_)
            | EventMsg::PlanDelta(_)
            | EventMsg::AgentReasoningDelta(_)
            | EventMsg::AgentReasoningRawContentDelta(_)
            | EventMsg::RealtimeConversationStarted(_)
            | EventMsg::RealtimeConversationClosed(_)
    )
}

fn server_notification_global_events(notification: &ServerNotification) -> Option<Vec<Event>> {
    match notification {
        ServerNotification::DeprecationNotice(notification) => Some(vec![Event {
            id: String::new(),
            msg: EventMsg::DeprecationNotice(DeprecationNoticeEvent {
                summary: notification.summary.clone(),
                details: notification.details.clone(),
            }),
        }]),
        _ => None,
    }
}

fn server_notification_thread_events(
    notification: ServerNotification,
) -> Option<(ThreadId, Vec<Event>)> {
    match notification {
        ServerNotification::ThreadTokenUsageUpdated(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::TokenCount(TokenCountEvent {
                    info: Some(TokenUsageInfo {
                        total_token_usage: token_usage_from_app_server(
                            notification.token_usage.total,
                        ),
                        last_token_usage: token_usage_from_app_server(
                            notification.token_usage.last,
                        ),
                        model_context_window: notification.token_usage.model_context_window,
                    }),
                    rate_limits: None,
                }),
            }],
        )),
        ServerNotification::Error(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::Error(ErrorEvent {
                    message: notification.error.message,
                    codex_error_info: notification
                        .error
                        .codex_error_info
                        .and_then(app_server_codex_error_info_to_core),
                }),
            }],
        )),
        ServerNotification::ThreadNameUpdated(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::ThreadNameUpdated(ThreadNameUpdatedEvent {
                    thread_id: ThreadId::from_string(&notification.thread_id).ok()?,
                    thread_name: notification.thread_name,
                }),
            }],
        )),
        ServerNotification::TurnStarted(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::TurnStarted(TurnStartedEvent {
                    turn_id: notification.turn.id,
                    model_context_window: None,
                    collaboration_mode_kind: ModeKind::default(),
                }),
            }],
        )),
        ServerNotification::TurnCompleted(notification) => {
            let thread_id = ThreadId::from_string(&notification.thread_id).ok()?;
            let mut events = Vec::new();
            append_terminal_turn_events(
                &mut events,
                &notification.turn,
                /*include_failed_error*/ false,
            );
            Some((thread_id, events))
        }
        ServerNotification::ItemStarted(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::ItemStarted(ItemStartedEvent {
                    thread_id: ThreadId::from_string(&notification.thread_id).ok()?,
                    turn_id: notification.turn_id,
                    item: thread_item_to_core(&notification.item)?,
                }),
            }],
        )),
        ServerNotification::ItemCompleted(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::ItemCompleted(ItemCompletedEvent {
                    thread_id: ThreadId::from_string(&notification.thread_id).ok()?,
                    turn_id: notification.turn_id,
                    item: thread_item_to_core(&notification.item)?,
                }),
            }],
        )),
        ServerNotification::AgentMessageDelta(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::AgentMessageDelta(AgentMessageDeltaEvent {
                    delta: notification.delta,
                }),
            }],
        )),
        ServerNotification::PlanDelta(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::PlanDelta(PlanDeltaEvent {
                    thread_id: notification.thread_id,
                    turn_id: notification.turn_id,
                    item_id: notification.item_id,
                    delta: notification.delta,
                }),
            }],
        )),
        ServerNotification::TurnDiffUpdated(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::TurnDiff(TurnDiffEvent {
                    unified_diff: notification.diff,
                }),
            }],
        )),
        ServerNotification::ReasoningSummaryTextDelta(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::AgentReasoningDelta(AgentReasoningDeltaEvent {
                    delta: notification.delta,
                }),
            }],
        )),
        ServerNotification::ReasoningTextDelta(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::AgentReasoningRawContentDelta(AgentReasoningRawContentDeltaEvent {
                    delta: notification.delta,
                }),
            }],
        )),
        ServerNotification::ThreadRealtimeStarted(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::RealtimeConversationStarted(RealtimeConversationStartedEvent {
                    session_id: notification.session_id,
                    version: notification.version,
                }),
            }],
        )),
        ServerNotification::ThreadRealtimeItemAdded(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::RealtimeConversationRealtime(RealtimeConversationRealtimeEvent {
                    payload: realtime_event_from_app_server_item(notification.item),
                }),
            }],
        )),
        ServerNotification::ThreadRealtimeOutputAudioDelta(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::RealtimeConversationRealtime(RealtimeConversationRealtimeEvent {
                    payload: RealtimeEvent::AudioOut(notification.audio.into()),
                }),
            }],
        )),
        ServerNotification::ThreadRealtimeError(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::RealtimeConversationRealtime(RealtimeConversationRealtimeEvent {
                    payload: RealtimeEvent::Error(notification.message),
                }),
            }],
        )),
        ServerNotification::ThreadRealtimeClosed(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::RealtimeConversationClosed(RealtimeConversationClosedEvent {
                    reason: notification.reason,
                }),
            }],
        )),
        ServerNotification::TerminalInteraction(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::TerminalInteraction(TerminalInteractionEvent {
                    call_id: notification.item_id,
                    process_id: notification.process_id,
                    stdin: notification.stdin,
                }),
            }],
        )),
        ServerNotification::ContextCompacted(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::ContextCompacted(ContextCompactedEvent),
            }],
        )),
        ServerNotification::ItemGuardianApprovalReviewStarted(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::GuardianAssessment(guardian_assessment_event(
                    notification.turn_id,
                    notification.target_item_id,
                    notification.review,
                    notification.action,
                )?),
            }],
        )),
        ServerNotification::ItemGuardianApprovalReviewCompleted(notification) => Some((
            ThreadId::from_string(&notification.thread_id).ok()?,
            vec![Event {
                id: String::new(),
                msg: EventMsg::GuardianAssessment(guardian_assessment_event(
                    notification.turn_id,
                    notification.target_item_id,
                    notification.review,
                    notification.action,
                )?),
            }],
        )),
        _ => None,
    }
}

fn guardian_assessment_event(
    turn_id: String,
    id: String,
    review: codex_app_server_protocol::GuardianApprovalReview,
    action: Option<Value>,
) -> Option<GuardianAssessmentEvent> {
    Some(GuardianAssessmentEvent {
        id,
        turn_id,
        status: match review.status {
            codex_app_server_protocol::GuardianApprovalReviewStatus::InProgress => {
                GuardianAssessmentStatus::InProgress
            }
            codex_app_server_protocol::GuardianApprovalReviewStatus::Approved => {
                GuardianAssessmentStatus::Approved
            }
            codex_app_server_protocol::GuardianApprovalReviewStatus::Denied => {
                GuardianAssessmentStatus::Denied
            }
            codex_app_server_protocol::GuardianApprovalReviewStatus::Aborted => {
                GuardianAssessmentStatus::Aborted
            }
        },
        risk_score: review.risk_score,
        risk_level: review.risk_level.map(|risk_level| match risk_level {
            codex_app_server_protocol::GuardianRiskLevel::Low => GuardianRiskLevel::Low,
            codex_app_server_protocol::GuardianRiskLevel::Medium => GuardianRiskLevel::Medium,
            codex_app_server_protocol::GuardianRiskLevel::High => GuardianRiskLevel::High,
        }),
        rationale: review.rationale,
        action,
    })
}

fn realtime_event_from_app_server_item(item: Value) -> RealtimeEvent {
    let Some(item_type) = item.get("type").and_then(Value::as_str) else {
        return RealtimeEvent::ConversationItemAdded(item);
    };

    match item_type {
        "input_audio_buffer.speech_started" => {
            RealtimeEvent::InputAudioSpeechStarted(RealtimeInputAudioSpeechStarted {
                item_id: item
                    .get("item_id")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            })
        }
        "response.cancelled" => RealtimeEvent::ResponseCancelled(RealtimeResponseCancelled {
            response_id: item
                .get("response")
                .and_then(Value::as_object)
                .and_then(|response| response.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    item.get("response_id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                }),
        }),
        "handoff_request" => RealtimeEvent::HandoffRequested(RealtimeHandoffRequested {
            handoff_id: item
                .get("handoff_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            item_id: item
                .get("item_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            input_transcript: item
                .get("input_transcript")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            active_transcript: item
                .get("active_transcript")
                .cloned()
                .and_then(|value| {
                    serde_json::from_value::<Vec<RealtimeTranscriptEntry>>(value).ok()
                })
                .unwrap_or_default(),
        }),
        _ => RealtimeEvent::ConversationItemAdded(item),
    }
}

fn token_usage_from_app_server(
    value: codex_app_server_protocol::TokenUsageBreakdown,
) -> TokenUsage {
    TokenUsage {
        input_tokens: value.input_tokens,
        cached_input_tokens: value.cached_input_tokens,
        output_tokens: value.output_tokens,
        reasoning_output_tokens: value.reasoning_output_tokens,
        total_tokens: value.total_tokens,
    }
}

/// Expand a single `Turn` into the event sequence the TUI would have
/// observed if it had been connected for the turn's entire lifetime.
///
/// Snapshot replay keeps committed-item semantics for user / plan /
/// agent-message items, while replaying the legacy events that still
/// drive rendering for reasoning, web-search, image-generation, and
/// context-compaction history cells.
#[cfg(test)]
fn turn_snapshot_events(
    thread_id: ThreadId,
    turn: &Turn,
    show_raw_agent_reasoning: bool,
) -> Vec<Event> {
    let mut events = vec![Event {
        id: String::new(),
        msg: EventMsg::TurnStarted(TurnStartedEvent {
            turn_id: turn.id.clone(),
            model_context_window: None,
            collaboration_mode_kind: ModeKind::default(),
        }),
    }];

    for item in &turn.items {
        let Some(item) = thread_item_to_core(item) else {
            continue;
        };
        match item {
            TurnItem::UserMessage(_) | TurnItem::Plan(_) | TurnItem::AgentMessage(_) => {
                events.push(Event {
                    id: String::new(),
                    msg: EventMsg::ItemCompleted(ItemCompletedEvent {
                        thread_id,
                        turn_id: turn.id.clone(),
                        item,
                    }),
                });
            }
            TurnItem::Reasoning(_)
            | TurnItem::WebSearch(_)
            | TurnItem::ImageGeneration(_)
            | TurnItem::ContextCompaction(_) => {
                events.extend(
                    item.as_legacy_events(show_raw_agent_reasoning)
                        .into_iter()
                        .map(|msg| Event {
                            id: String::new(),
                            msg,
                        }),
                );
            }
        }
    }

    append_terminal_turn_events(&mut events, turn, /*include_failed_error*/ true);

    events
}

/// Append the terminal event(s) for a turn based on its `TurnStatus`.
///
/// This function is shared between the live notification bridge
/// (`TurnCompleted` handling) and the snapshot replay path so that both
/// produce identical `EventMsg` sequences for the same turn status.
///
/// - `Completed` → `TurnComplete`
/// - `Interrupted` → `TurnAborted { reason: Interrupted }`
/// - `Failed` → `Error` (if present) then `TurnComplete`
/// - `InProgress` → no events (the turn is still running)
fn append_terminal_turn_events(events: &mut Vec<Event>, turn: &Turn, include_failed_error: bool) {
    match turn.status {
        TurnStatus::Completed => events.push(Event {
            id: String::new(),
            msg: EventMsg::TurnComplete(TurnCompleteEvent {
                turn_id: turn.id.clone(),
                last_agent_message: None,
            }),
        }),
        TurnStatus::Interrupted => events.push(Event {
            id: String::new(),
            msg: EventMsg::TurnAborted(TurnAbortedEvent {
                turn_id: Some(turn.id.clone()),
                reason: TurnAbortReason::Interrupted,
            }),
        }),
        TurnStatus::Failed => {
            if include_failed_error && let Some(error) = &turn.error {
                events.push(Event {
                    id: String::new(),
                    msg: EventMsg::Error(ErrorEvent {
                        message: error.message.clone(),
                        codex_error_info: error
                            .codex_error_info
                            .clone()
                            .and_then(app_server_codex_error_info_to_core),
                    }),
                });
            }
            events.push(Event {
                id: String::new(),
                msg: EventMsg::TurnComplete(TurnCompleteEvent {
                    turn_id: turn.id.clone(),
                    last_agent_message: None,
                }),
            });
        }
        TurnStatus::InProgress => {
            // Preserve unfinished turns during snapshot replay without emitting completion events.
        }
    }
}

fn thread_item_to_core(item: &ThreadItem) -> Option<TurnItem> {
    match item {
        ThreadItem::UserMessage { id, content } => Some(TurnItem::UserMessage(UserMessageItem {
            id: id.clone(),
            content: content
                .iter()
                .cloned()
                .map(codex_app_server_protocol::UserInput::into_core)
                .collect(),
        })),
        ThreadItem::AgentMessage {
            id,
            text,
            phase,
            memory_citation,
        } => Some(TurnItem::AgentMessage(AgentMessageItem {
            id: id.clone(),
            content: vec![AgentMessageContent::Text { text: text.clone() }],
            phase: phase.clone(),
            memory_citation: memory_citation.clone().map(|citation| {
                codex_protocol::memory_citation::MemoryCitation {
                    entries: citation
                        .entries
                        .into_iter()
                        .map(
                            |entry| codex_protocol::memory_citation::MemoryCitationEntry {
                                path: entry.path,
                                line_start: entry.line_start,
                                line_end: entry.line_end,
                                note: entry.note,
                            },
                        )
                        .collect(),
                    rollout_ids: citation.thread_ids,
                }
            }),
        })),
        ThreadItem::Plan { id, text } => Some(TurnItem::Plan(PlanItem {
            id: id.clone(),
            text: text.clone(),
        })),
        ThreadItem::Reasoning {
            id,
            summary,
            content,
        } => Some(TurnItem::Reasoning(ReasoningItem {
            id: id.clone(),
            summary_text: summary.clone(),
            raw_content: content.clone(),
        })),
        ThreadItem::WebSearch { id, query, action } => Some(TurnItem::WebSearch(WebSearchItem {
            id: id.clone(),
            query: query.clone(),
            action: app_server_web_search_action_to_core(action.clone()?)?,
        })),
        ThreadItem::ImageGeneration {
            id,
            status,
            revised_prompt,
            result,
        } => Some(TurnItem::ImageGeneration(ImageGenerationItem {
            id: id.clone(),
            status: status.clone(),
            revised_prompt: revised_prompt.clone(),
            result: result.clone(),
            saved_path: None,
        })),
        ThreadItem::ContextCompaction { id } => {
            Some(TurnItem::ContextCompaction(ContextCompactionItem {
                id: id.clone(),
            }))
        }
        ThreadItem::CommandExecution { .. }
        | ThreadItem::FileChange { .. }
        | ThreadItem::McpToolCall { .. }
        | ThreadItem::DynamicToolCall { .. }
        | ThreadItem::CollabAgentToolCall { .. }
        | ThreadItem::ImageView { .. }
        | ThreadItem::EnteredReviewMode { .. }
        | ThreadItem::ExitedReviewMode { .. } => {
            tracing::debug!("ignoring unsupported app-server thread item in TUI adapter");
            None
        }
    }
}

fn app_server_web_search_action_to_core(
    action: codex_app_server_protocol::WebSearchAction,
) -> Option<codex_protocol::models::WebSearchAction> {
    match action {
        codex_app_server_protocol::WebSearchAction::Search { query, queries } => {
            Some(codex_protocol::models::WebSearchAction::Search { query, queries })
        }
        codex_app_server_protocol::WebSearchAction::OpenPage { url } => {
            Some(codex_protocol::models::WebSearchAction::OpenPage { url })
        }
        codex_app_server_protocol::WebSearchAction::FindInPage { url, pattern } => {
            Some(codex_protocol::models::WebSearchAction::FindInPage { url, pattern })
        }
        codex_app_server_protocol::WebSearchAction::Other => {
            Some(codex_protocol::models::WebSearchAction::Other)
        }
    }
}

fn app_server_codex_error_info_to_core(
    value: codex_app_server_protocol::CodexErrorInfo,
) -> Option<codex_protocol::protocol::CodexErrorInfo> {
    serde_json::from_value(serde_json::to_value(value).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::resolve_chatgpt_auth_tokens_refresh_response;
    use super::server_notification_global_events;
    use super::server_notification_thread_events;
    use super::thread_snapshot_events;
    use super::turn_snapshot_events;
    use base64::Engine as _;
    use chrono::Utc;
    use codex_app_server_protocol::AgentMessageDeltaNotification;
    use codex_app_server_protocol::AuthMode;
    use codex_app_server_protocol::ChatgptAuthTokensRefreshParams;
    use codex_app_server_protocol::CodexErrorInfo;
    use codex_app_server_protocol::ContextCompactedNotification;
    use codex_app_server_protocol::DeprecationNoticeNotification;
    use codex_app_server_protocol::GuardianApprovalReview;
    use codex_app_server_protocol::GuardianApprovalReviewStatus;
    use codex_app_server_protocol::ItemCompletedNotification;
    use codex_app_server_protocol::ItemGuardianApprovalReviewCompletedNotification;
    use codex_app_server_protocol::ItemGuardianApprovalReviewStartedNotification;
    use codex_app_server_protocol::ReasoningSummaryTextDeltaNotification;
    use codex_app_server_protocol::ServerNotification;
    use codex_app_server_protocol::TerminalInteractionNotification;
    use codex_app_server_protocol::Thread;
    use codex_app_server_protocol::ThreadItem;
    use codex_app_server_protocol::ThreadRealtimeItemAddedNotification;
    use codex_app_server_protocol::ThreadStatus;
    use codex_app_server_protocol::Turn;
    use codex_app_server_protocol::TurnCompletedNotification;
    use codex_app_server_protocol::TurnDiffUpdatedNotification;
    use codex_app_server_protocol::TurnError;
    use codex_app_server_protocol::TurnStatus;
    use codex_core::auth::AuthCredentialsStoreMode;
    use codex_core::auth::AuthDotJson;
    use codex_core::auth::save_auth;
    use codex_core::token_data::TokenData;
    use codex_protocol::ThreadId;
    use codex_protocol::items::AgentMessageContent;
    use codex_protocol::items::AgentMessageItem;
    use codex_protocol::items::TurnItem;
    use codex_protocol::models::MessagePhase;
    use codex_protocol::protocol::EventMsg;
    use codex_protocol::protocol::RealtimeEvent;
    use codex_protocol::protocol::RealtimeHandoffRequested;
    use codex_protocol::protocol::RealtimeTranscriptEntry;
    use codex_protocol::protocol::SessionSource;
    use codex_protocol::protocol::TurnAbortReason;
    use codex_protocol::protocol::TurnAbortedEvent;
    use pretty_assertions::assert_eq;
    use serde::Serialize;
    use serde_json::json;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn fake_jwt(email: &str, account_id: &str, plan_type: &str) -> String {
        #[derive(Serialize)]
        struct Header {
            alg: &'static str,
            typ: &'static str,
        }

        let header = Header {
            alg: "none",
            typ: "JWT",
        };
        let payload = json!({
            "email": email,
            "https://api.openai.com/auth": {
                "chatgpt_account_id": account_id,
                "chatgpt_plan_type": plan_type,
            },
        });
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let header_b64 = encode(&serde_json::to_vec(&header).expect("serialize header"));
        let payload_b64 = encode(&serde_json::to_vec(&payload).expect("serialize payload"));
        let signature_b64 = encode(b"sig");
        format!("{header_b64}.{payload_b64}.{signature_b64}")
    }

    fn write_chatgpt_auth(codex_home: &std::path::Path, account_id: &str, access_token: &str) {
        let id_token = fake_jwt("user@example.com", account_id, "business");
        let auth = AuthDotJson {
            auth_mode: Some(AuthMode::Chatgpt),
            openai_api_key: None,
            tokens: Some(TokenData {
                id_token: codex_core::token_data::parse_chatgpt_jwt_claims(&id_token)
                    .expect("id token should parse"),
                access_token: access_token.to_string(),
                refresh_token: "refresh-token".to_string(),
                account_id: Some(account_id.to_string()),
            }),
            last_refresh: Some(Utc::now()),
        };
        save_auth(codex_home, &auth, AuthCredentialsStoreMode::File)
            .expect("chatgpt auth should save");
    }

    #[test]
    fn bridges_completed_agent_messages_from_server_notifications() {
        let thread_id = "019cee8c-b993-7e33-88c0-014d4e62612d".to_string();
        let turn_id = "019cee8c-b9b4-7f10-a1b0-38caa876a012".to_string();
        let item_id = "msg_123".to_string();

        let (actual_thread_id, events) = server_notification_thread_events(
            ServerNotification::ItemCompleted(ItemCompletedNotification {
                item: ThreadItem::AgentMessage {
                    id: item_id,
                    text: "Hello from your coding assistant.".to_string(),
                    phase: Some(MessagePhase::FinalAnswer),
                    memory_citation: None,
                },
                thread_id: thread_id.clone(),
                turn_id: turn_id.clone(),
            }),
        )
        .expect("notification should bridge");

        assert_eq!(
            actual_thread_id,
            ThreadId::from_string(&thread_id).expect("valid thread id")
        );
        let [event] = events.as_slice() else {
            panic!("expected one bridged event");
        };
        assert_eq!(event.id, String::new());
        let EventMsg::ItemCompleted(completed) = &event.msg else {
            panic!("expected item completed event");
        };
        assert_eq!(
            completed.thread_id,
            ThreadId::from_string(&thread_id).expect("valid thread id")
        );
        assert_eq!(completed.turn_id, turn_id);
        match &completed.item {
            TurnItem::AgentMessage(AgentMessageItem {
                id, content, phase, ..
            }) => {
                assert_eq!(id, "msg_123");
                let [AgentMessageContent::Text { text }] = content.as_slice() else {
                    panic!("expected a single text content item");
                };
                assert_eq!(text, "Hello from your coding assistant.");
                assert_eq!(*phase, Some(MessagePhase::FinalAnswer));
            }
            _ => panic!("expected bridged agent message item"),
        }
    }

    #[test]
    fn bridges_turn_completion_from_server_notifications() {
        let thread_id = "019cee8c-b993-7e33-88c0-014d4e62612d".to_string();
        let turn_id = "019cee8c-b9b4-7f10-a1b0-38caa876a012".to_string();

        let (actual_thread_id, events) = server_notification_thread_events(
            ServerNotification::TurnCompleted(TurnCompletedNotification {
                thread_id: thread_id.clone(),
                turn: Turn {
                    id: turn_id.clone(),
                    items: Vec::new(),
                    status: TurnStatus::Completed,
                    error: None,
                },
            }),
        )
        .expect("notification should bridge");

        assert_eq!(
            actual_thread_id,
            ThreadId::from_string(&thread_id).expect("valid thread id")
        );
        let [event] = events.as_slice() else {
            panic!("expected one bridged event");
        };
        assert_eq!(event.id, String::new());
        let EventMsg::TurnComplete(completed) = &event.msg else {
            panic!("expected turn complete event");
        };
        assert_eq!(completed.turn_id, turn_id);
        assert_eq!(completed.last_agent_message, None);
    }

    #[test]
    fn bridges_interrupted_turn_completion_from_server_notifications() {
        let thread_id = "019cee8c-b993-7e33-88c0-014d4e62612d".to_string();
        let turn_id = "019cee8c-b9b4-7f10-a1b0-38caa876a012".to_string();

        let (actual_thread_id, events) = server_notification_thread_events(
            ServerNotification::TurnCompleted(TurnCompletedNotification {
                thread_id: thread_id.clone(),
                turn: Turn {
                    id: turn_id.clone(),
                    items: Vec::new(),
                    status: TurnStatus::Interrupted,
                    error: None,
                },
            }),
        )
        .expect("notification should bridge");

        assert_eq!(
            actual_thread_id,
            ThreadId::from_string(&thread_id).expect("valid thread id")
        );
        let [event] = events.as_slice() else {
            panic!("expected one bridged event");
        };
        let EventMsg::TurnAborted(aborted) = &event.msg else {
            panic!("expected turn aborted event");
        };
        assert_eq!(aborted.turn_id.as_deref(), Some(turn_id.as_str()));
        assert_eq!(aborted.reason, TurnAbortReason::Interrupted);
    }

    #[test]
    fn bridges_failed_turn_completion_from_server_notifications() {
        let thread_id = "019cee8c-b993-7e33-88c0-014d4e62612d".to_string();
        let turn_id = "019cee8c-b9b4-7f10-a1b0-38caa876a012".to_string();

        let (actual_thread_id, events) = server_notification_thread_events(
            ServerNotification::TurnCompleted(TurnCompletedNotification {
                thread_id: thread_id.clone(),
                turn: Turn {
                    id: turn_id.clone(),
                    items: Vec::new(),
                    status: TurnStatus::Failed,
                    error: Some(TurnError {
                        message: "request failed".to_string(),
                        codex_error_info: Some(CodexErrorInfo::Other),
                        additional_details: None,
                    }),
                },
            }),
        )
        .expect("notification should bridge");

        assert_eq!(
            actual_thread_id,
            ThreadId::from_string(&thread_id).expect("valid thread id")
        );
        let [complete_event] = events.as_slice() else {
            panic!("expected turn completion only");
        };
        let EventMsg::TurnComplete(completed) = &complete_event.msg else {
            panic!("expected turn complete event");
        };
        assert_eq!(completed.turn_id, turn_id);
        assert_eq!(completed.last_agent_message, None);
    }

    #[test]
    fn bridges_text_deltas_from_server_notifications() {
        let thread_id = "019cee8c-b993-7e33-88c0-014d4e62612d".to_string();

        let (_, agent_events) = server_notification_thread_events(
            ServerNotification::AgentMessageDelta(AgentMessageDeltaNotification {
                thread_id: thread_id.clone(),
                turn_id: "turn".to_string(),
                item_id: "item".to_string(),
                delta: "Hello".to_string(),
            }),
        )
        .expect("notification should bridge");
        let [agent_event] = agent_events.as_slice() else {
            panic!("expected one bridged agent delta event");
        };
        assert_eq!(agent_event.id, String::new());
        let EventMsg::AgentMessageDelta(delta) = &agent_event.msg else {
            panic!("expected bridged agent message delta");
        };
        assert_eq!(delta.delta, "Hello");

        let (_, reasoning_events) = server_notification_thread_events(
            ServerNotification::ReasoningSummaryTextDelta(ReasoningSummaryTextDeltaNotification {
                thread_id,
                turn_id: "turn".to_string(),
                item_id: "item".to_string(),
                delta: "Thinking".to_string(),
                summary_index: 0,
            }),
        )
        .expect("notification should bridge");
        let [reasoning_event] = reasoning_events.as_slice() else {
            panic!("expected one bridged reasoning delta event");
        };
        assert_eq!(reasoning_event.id, String::new());
        let EventMsg::AgentReasoningDelta(delta) = &reasoning_event.msg else {
            panic!("expected bridged reasoning delta");
        };
        assert_eq!(delta.delta, "Thinking");
    }

    #[test]
    fn bridges_server_only_notifications_from_server_notifications() {
        let thread_id = "019cee8c-b993-7e33-88c0-014d4e62612d".to_string();

        let (_, terminal_events) = server_notification_thread_events(
            ServerNotification::TerminalInteraction(TerminalInteractionNotification {
                thread_id: thread_id.clone(),
                turn_id: "turn".to_string(),
                item_id: "call-1".to_string(),
                process_id: "proc-1".to_string(),
                stdin: "pwd\n".to_string(),
            }),
        )
        .expect("terminal interaction should bridge");
        assert!(matches!(
            terminal_events[0].msg,
            EventMsg::TerminalInteraction(_)
        ));

        let (_, diff_events) = server_notification_thread_events(
            ServerNotification::TurnDiffUpdated(TurnDiffUpdatedNotification {
                thread_id: thread_id.clone(),
                turn_id: "turn".to_string(),
                diff: "@@ -1 +1 @@".to_string(),
            }),
        )
        .expect("turn diff should bridge");
        let EventMsg::TurnDiff(turn_diff) = &diff_events[0].msg else {
            panic!("expected turn diff event");
        };
        assert_eq!(turn_diff.unified_diff, "@@ -1 +1 @@");

        let (_, compacted_events) = server_notification_thread_events(
            ServerNotification::ContextCompacted(ContextCompactedNotification {
                thread_id: thread_id.clone(),
                turn_id: "turn".to_string(),
            }),
        )
        .expect("context compacted should bridge");
        assert!(matches!(
            compacted_events[0].msg,
            EventMsg::ContextCompacted(_)
        ));

        let deprecation_events = server_notification_global_events(
            &ServerNotification::DeprecationNotice(DeprecationNoticeNotification {
                summary: "old thing".to_string(),
                details: Some("use new thing".to_string()),
            }),
        )
        .expect("deprecation notice should bridge");
        let EventMsg::DeprecationNotice(deprecation) = &deprecation_events[0].msg else {
            panic!("expected deprecation notice event");
        };
        assert_eq!(deprecation.summary, "old thing");
        assert_eq!(deprecation.details.as_deref(), Some("use new thing"));

        let review = GuardianApprovalReview {
            status: GuardianApprovalReviewStatus::Denied,
            risk_score: Some(99),
            risk_level: Some(codex_app_server_protocol::GuardianRiskLevel::High),
            rationale: Some("blocked".to_string()),
        };
        let (_, started_events) = server_notification_thread_events(
            ServerNotification::ItemGuardianApprovalReviewStarted(
                ItemGuardianApprovalReviewStartedNotification {
                    thread_id: thread_id.clone(),
                    turn_id: "turn".to_string(),
                    target_item_id: "tool-1".to_string(),
                    review: review.clone(),
                    action: Some(serde_json::json!({"tool":"shell"})),
                },
            ),
        )
        .expect("guardian started should bridge");
        let EventMsg::GuardianAssessment(started) = &started_events[0].msg else {
            panic!("expected guardian assessment event");
        };
        assert_eq!(started.id, "tool-1");
        assert_eq!(started.turn_id, "turn");
        assert_eq!(
            started.status,
            codex_protocol::protocol::GuardianAssessmentStatus::Denied
        );
        assert_eq!(
            started.risk_level,
            Some(codex_protocol::protocol::GuardianRiskLevel::High)
        );

        let (_, completed_events) = server_notification_thread_events(
            ServerNotification::ItemGuardianApprovalReviewCompleted(
                ItemGuardianApprovalReviewCompletedNotification {
                    thread_id,
                    turn_id: "turn".to_string(),
                    target_item_id: "tool-2".to_string(),
                    review,
                    action: None,
                },
            ),
        )
        .expect("guardian completed should bridge");
        assert!(matches!(
            completed_events[0].msg,
            EventMsg::GuardianAssessment(_)
        ));
    }

    #[test]
    fn preserves_typed_realtime_item_notifications() {
        let thread_id = "019cee8c-b993-7e33-88c0-014d4e62612d".to_string();

        let (_, speech_events) = server_notification_thread_events(
            ServerNotification::ThreadRealtimeItemAdded(ThreadRealtimeItemAddedNotification {
                thread_id: thread_id.clone(),
                item: serde_json::json!({
                    "type": "input_audio_buffer.speech_started",
                    "item_id": "item-1",
                }),
            }),
        )
        .expect("speech started should bridge");
        let EventMsg::RealtimeConversationRealtime(speech_event) = &speech_events[0].msg else {
            panic!("expected realtime event");
        };
        assert_eq!(
            speech_event.payload,
            RealtimeEvent::InputAudioSpeechStarted(
                codex_protocol::protocol::RealtimeInputAudioSpeechStarted {
                    item_id: Some("item-1".to_string()),
                }
            )
        );

        let (_, cancelled_events) = server_notification_thread_events(
            ServerNotification::ThreadRealtimeItemAdded(ThreadRealtimeItemAddedNotification {
                thread_id: thread_id.clone(),
                item: serde_json::json!({
                    "type": "response.cancelled",
                    "response_id": "resp-1",
                }),
            }),
        )
        .expect("response cancelled should bridge");
        let EventMsg::RealtimeConversationRealtime(cancelled_event) = &cancelled_events[0].msg
        else {
            panic!("expected realtime event");
        };
        assert_eq!(
            cancelled_event.payload,
            RealtimeEvent::ResponseCancelled(codex_protocol::protocol::RealtimeResponseCancelled {
                response_id: Some("resp-1".to_string()),
            })
        );

        let (_, handoff_events) = server_notification_thread_events(
            ServerNotification::ThreadRealtimeItemAdded(ThreadRealtimeItemAddedNotification {
                thread_id,
                item: serde_json::json!({
                    "type": "handoff_request",
                    "handoff_id": "handoff-1",
                    "item_id": "item-2",
                    "input_transcript": "fallback transcript",
                    "active_transcript": [
                        {
                            "role": "user",
                            "text": "live transcript",
                        }
                    ],
                }),
            }),
        )
        .expect("handoff request should bridge");
        let EventMsg::RealtimeConversationRealtime(handoff_event) = &handoff_events[0].msg else {
            panic!("expected realtime event");
        };
        assert_eq!(
            handoff_event.payload,
            RealtimeEvent::HandoffRequested(RealtimeHandoffRequested {
                handoff_id: "handoff-1".to_string(),
                item_id: "item-2".to_string(),
                input_transcript: "fallback transcript".to_string(),
                active_transcript: vec![RealtimeTranscriptEntry {
                    role: "user".to_string(),
                    text: "live transcript".to_string(),
                }],
            })
        );
    }

    #[test]
    fn bridges_thread_snapshot_turns_for_resume_restore() {
        let thread_id = ThreadId::new();
        let events = thread_snapshot_events(
            &Thread {
                id: thread_id.to_string(),
                preview: "hello".to_string(),
                ephemeral: false,
                model_provider: "openai".to_string(),
                created_at: 0,
                updated_at: 0,
                status: ThreadStatus::Idle,
                path: None,
                cwd: PathBuf::from("/tmp/project"),
                cli_version: "test".to_string(),
                source: SessionSource::Cli.into(),
                agent_nickname: None,
                agent_role: None,
                git_info: None,
                name: Some("restore".to_string()),
                turns: vec![
                    Turn {
                        id: "turn-complete".to_string(),
                        items: vec![
                            ThreadItem::UserMessage {
                                id: "user-1".to_string(),
                                content: vec![codex_app_server_protocol::UserInput::Text {
                                    text: "hello".to_string(),
                                    text_elements: Vec::new(),
                                }],
                            },
                            ThreadItem::AgentMessage {
                                id: "assistant-1".to_string(),
                                text: "hi".to_string(),
                                phase: Some(MessagePhase::FinalAnswer),
                                memory_citation: None,
                            },
                        ],
                        status: TurnStatus::Completed,
                        error: None,
                    },
                    Turn {
                        id: "turn-interrupted".to_string(),
                        items: Vec::new(),
                        status: TurnStatus::Interrupted,
                        error: None,
                    },
                    Turn {
                        id: "turn-failed".to_string(),
                        items: Vec::new(),
                        status: TurnStatus::Failed,
                        error: Some(TurnError {
                            message: "request failed".to_string(),
                            codex_error_info: Some(CodexErrorInfo::Other),
                            additional_details: None,
                        }),
                    },
                ],
            },
            /*show_raw_agent_reasoning*/ false,
        );

        assert_eq!(events.len(), 9);
        assert!(matches!(events[0].msg, EventMsg::TurnStarted(_)));
        assert!(matches!(events[1].msg, EventMsg::ItemCompleted(_)));
        assert!(matches!(events[2].msg, EventMsg::ItemCompleted(_)));
        assert!(matches!(events[3].msg, EventMsg::TurnComplete(_)));
        assert!(matches!(events[4].msg, EventMsg::TurnStarted(_)));
        let EventMsg::TurnAborted(TurnAbortedEvent { turn_id, reason }) = &events[5].msg else {
            panic!("expected interrupted turn replay");
        };
        assert_eq!(turn_id.as_deref(), Some("turn-interrupted"));
        assert_eq!(*reason, TurnAbortReason::Interrupted);
        assert!(matches!(events[6].msg, EventMsg::TurnStarted(_)));
        let EventMsg::Error(error) = &events[7].msg else {
            panic!("expected failed turn error replay");
        };
        assert_eq!(error.message, "request failed");
        assert_eq!(
            error.codex_error_info,
            Some(codex_protocol::protocol::CodexErrorInfo::Other)
        );
        assert!(matches!(events[8].msg, EventMsg::TurnComplete(_)));
    }

    #[test]
    fn bridges_non_message_snapshot_items_via_legacy_events() {
        let events = turn_snapshot_events(
            ThreadId::new(),
            &Turn {
                id: "turn-complete".to_string(),
                items: vec![
                    ThreadItem::Reasoning {
                        id: "reasoning-1".to_string(),
                        summary: vec!["Need to inspect config".to_string()],
                        content: vec!["hidden chain".to_string()],
                    },
                    ThreadItem::WebSearch {
                        id: "search-1".to_string(),
                        query: "ratatui stylize".to_string(),
                        action: Some(codex_app_server_protocol::WebSearchAction::Other),
                    },
                    ThreadItem::ImageGeneration {
                        id: "image-1".to_string(),
                        status: "completed".to_string(),
                        revised_prompt: Some("diagram".to_string()),
                        result: "image.png".to_string(),
                    },
                    ThreadItem::ContextCompaction {
                        id: "compact-1".to_string(),
                    },
                ],
                status: TurnStatus::Completed,
                error: None,
            },
            /*show_raw_agent_reasoning*/ false,
        );

        assert_eq!(events.len(), 6);
        assert!(matches!(events[0].msg, EventMsg::TurnStarted(_)));
        let EventMsg::AgentReasoning(reasoning) = &events[1].msg else {
            panic!("expected reasoning replay");
        };
        assert_eq!(reasoning.text, "Need to inspect config");
        let EventMsg::WebSearchEnd(web_search) = &events[2].msg else {
            panic!("expected web search replay");
        };
        assert_eq!(web_search.call_id, "search-1");
        assert_eq!(web_search.query, "ratatui stylize");
        assert_eq!(
            web_search.action,
            codex_protocol::models::WebSearchAction::Other
        );
        let EventMsg::ImageGenerationEnd(image_generation) = &events[3].msg else {
            panic!("expected image generation replay");
        };
        assert_eq!(image_generation.call_id, "image-1");
        assert_eq!(image_generation.status, "completed");
        assert_eq!(image_generation.revised_prompt.as_deref(), Some("diagram"));
        assert_eq!(image_generation.result, "image.png");
        assert!(matches!(events[4].msg, EventMsg::ContextCompacted(_)));
        assert!(matches!(events[5].msg, EventMsg::TurnComplete(_)));
    }

    #[test]
    fn bridges_raw_reasoning_snapshot_items_when_enabled() {
        let events = turn_snapshot_events(
            ThreadId::new(),
            &Turn {
                id: "turn-complete".to_string(),
                items: vec![ThreadItem::Reasoning {
                    id: "reasoning-1".to_string(),
                    summary: vec!["Need to inspect config".to_string()],
                    content: vec!["hidden chain".to_string()],
                }],
                status: TurnStatus::Completed,
                error: None,
            },
            /*show_raw_agent_reasoning*/ true,
        );

        assert_eq!(events.len(), 4);
        assert!(matches!(events[0].msg, EventMsg::TurnStarted(_)));
        let EventMsg::AgentReasoning(reasoning) = &events[1].msg else {
            panic!("expected reasoning replay");
        };
        assert_eq!(reasoning.text, "Need to inspect config");
        let EventMsg::AgentReasoningRawContent(raw_reasoning) = &events[2].msg else {
            panic!("expected raw reasoning replay");
        };
        assert_eq!(raw_reasoning.text, "hidden chain");
        assert!(matches!(events[3].msg, EventMsg::TurnComplete(_)));
    }

    #[test]
    fn chatgpt_auth_refresh_reads_from_resolved_auth_storage_home() {
        let default_home = TempDir::new().expect("tempdir");
        let override_home = TempDir::new().expect("tempdir");
        write_chatgpt_auth(default_home.path(), "workspace-default", "default-token");
        write_chatgpt_auth(override_home.path(), "workspace-override", "override-token");

        let response = resolve_chatgpt_auth_tokens_refresh_response(
            override_home.path(),
            AuthCredentialsStoreMode::File,
            Some("workspace-override"),
            &ChatgptAuthTokensRefreshParams {
                reason: codex_app_server_protocol::ChatgptAuthTokensRefreshReason::Unauthorized,
                previous_account_id: Some("workspace-override".to_string()),
            },
        )
        .expect("chatgpt auth refresh should load from override home");

        assert_eq!(response.chatgpt_account_id, "workspace-override");
        assert_eq!(response.access_token, "override-token");
    }
}
