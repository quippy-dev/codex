use super::*;
use codex_models_manager::collaboration_mode_presets::CollaborationModesConfig;
pub(super) use codex_protocol::items::PlanItem;
pub(super) use codex_protocol::items::TurnItem;
pub(super) use codex_protocol::protocol::AgentMessageEvent;
pub(super) use codex_protocol::protocol::ErrorEvent;
pub(super) use codex_protocol::protocol::Event;
pub(super) use codex_protocol::protocol::EventMsg;
pub(super) use codex_protocol::protocol::ExecCommandBeginEvent;
pub(super) use codex_protocol::protocol::ExecCommandSource as CoreExecCommandSource;
pub(super) use codex_protocol::protocol::ExitedReviewModeEvent;
pub(super) use codex_protocol::protocol::ItemCompletedEvent;
use codex_protocol::protocol::ReviewOutputEvent;
pub(super) use codex_protocol::protocol::SessionSource;
pub(super) use codex_protocol::protocol::TurnCompleteEvent;
pub(super) use codex_protocol::protocol::TurnStartedEvent;
pub(super) use codex_protocol::protocol::UndoCompletedEvent;
pub(super) use codex_protocol::protocol::UndoStartedEvent;
pub(super) use codex_protocol::protocol::UserMessageEvent;
use pretty_assertions::assert_eq;

pub(super) trait CodexEventCompatExt {
    fn handle_codex_event(&mut self, event: Event);
    fn handle_codex_event_replay(&mut self, event: Event);
    fn on_exited_review_mode(&mut self, event: ExitedReviewModeEvent);
}

impl CodexEventCompatExt for ChatWidget {
    fn handle_codex_event(&mut self, event: Event) {
        dispatch_compat_event(self, event, /*replay_kind*/ None);
    }

    fn handle_codex_event_replay(&mut self, event: Event) {
        dispatch_compat_event(self, event, Some(ReplayKind::ThreadSnapshot));
    }

    fn on_exited_review_mode(&mut self, event: ExitedReviewModeEvent) {
        if let Some(ReviewOutputEvent {
            overall_explanation,
            ..
        }) = event.review_output
        {
            self.record_agent_markdown(overall_explanation.trim());
        }
        self.exit_review_mode_after_item();
    }
}

fn dispatch_compat_event(chat: &mut ChatWidget, event: Event, replay_kind: Option<ReplayKind>) {
    match event.msg {
        EventMsg::TurnStarted(ev) => {
            chat.last_turn_id = Some(ev.turn_id);
            chat.last_non_retry_error = None;
            if !matches!(replay_kind, Some(ReplayKind::ResumeInitialMessages)) {
                chat.on_task_started();
            }
        }
        EventMsg::TurnComplete(ev) => {
            chat.last_turn_id = Some(ev.turn_id);
            chat.last_non_retry_error = None;
            chat.on_task_complete(ev.last_agent_message, ev.duration_ms, replay_kind.is_some());
        }
        EventMsg::ThreadNameUpdated(ev) => {
            chat.on_thread_name_updated(ev.thread_id, ev.thread_name);
        }
        EventMsg::UserMessage(ev) => {
            let mut content = vec![AppServerUserInput::Text {
                text: ev.message,
                text_elements: ev.text_elements.into_iter().map(Into::into).collect(),
            }];
            if let Some(images) = ev.images {
                content.extend(
                    images
                        .into_iter()
                        .map(|url| AppServerUserInput::Image { url }),
                );
            }
            content.extend(
                ev.local_images
                    .into_iter()
                    .map(|path| AppServerUserInput::LocalImage { path }),
            );
            chat.on_committed_user_message(&content, replay_kind.is_some());
        }
        EventMsg::AgentMessage(ev) => {
            chat.on_agent_message_item_completed(AgentMessageItem {
                id: event.id,
                content: vec![AgentMessageContent::Text { text: ev.message }],
                phase: ev.phase,
                memory_citation: ev.memory_citation,
            });
        }
        EventMsg::ItemCompleted(ev) => match ev.item {
            TurnItem::UserMessage(item) => {
                let content = item
                    .content
                    .into_iter()
                    .map(AppServerUserInput::from)
                    .collect::<Vec<_>>();
                chat.on_committed_user_message(&content, replay_kind.is_some());
            }
            TurnItem::AgentMessage(item) => chat.on_agent_message_item_completed(item),
            TurnItem::Plan(item) => chat.on_plan_item_completed(item.text),
            _ => {}
        },
        EventMsg::ExecCommandBegin(ev) => {
            let command_actions = ev
                .parsed_cmd
                .into_iter()
                .map(|parsed| AppServerCommandAction::from_core_with_cwd(parsed, &ev.cwd))
                .collect();
            chat.on_command_execution_started(AppServerThreadItem::CommandExecution {
                id: ev.call_id,
                command: codex_shell_command::parse_command::shlex_join(&ev.command),
                cwd: ev.cwd,
                process_id: ev.process_id,
                source: app_server_exec_source(ev.source),
                status: AppServerCommandExecutionStatus::InProgress,
                command_actions,
                aggregated_output: None,
                exit_code: None,
                duration_ms: None,
            });
        }
        EventMsg::ExecCommandEnd(ev) => {
            let command_actions = ev
                .parsed_cmd
                .into_iter()
                .map(|parsed| AppServerCommandAction::from_core_with_cwd(parsed, &ev.cwd))
                .collect();
            chat.on_command_execution_completed(AppServerThreadItem::CommandExecution {
                id: ev.call_id,
                command: codex_shell_command::parse_command::shlex_join(&ev.command),
                cwd: ev.cwd,
                process_id: ev.process_id,
                source: app_server_exec_source(ev.source),
                status: if ev.exit_code == 0 {
                    AppServerCommandExecutionStatus::Completed
                } else {
                    AppServerCommandExecutionStatus::Failed
                },
                command_actions,
                aggregated_output: Some(if ev.aggregated_output.is_empty() {
                    ev.formatted_output
                } else {
                    ev.aggregated_output
                }),
                exit_code: Some(ev.exit_code),
                duration_ms: Some(ev.duration.as_millis() as i64),
            });
        }
        EventMsg::TerminalInteraction(ev) => chat.on_terminal_interaction(ev.process_id, ev.stdin),
        EventMsg::HookStarted(ev) => {
            let run = serde_json::from_value(serde_json::to_value(ev.run).expect("hook run value"))
                .expect("hook run conversion");
            chat.on_hook_started(run);
        }
        EventMsg::HookCompleted(ev) => {
            let run = serde_json::from_value(serde_json::to_value(ev.run).expect("hook run value"))
                .expect("hook run conversion");
            chat.on_hook_completed(run);
        }
        EventMsg::UndoStarted(ev) => {
            chat.on_task_started();
            chat.bottom_pane.set_interrupt_hint_visible(false);
            if let Some(message) = ev.message {
                chat.set_status_header(message);
            }
        }
        EventMsg::UndoCompleted(ev) => {
            chat.finalize_turn();
            if !ev.success {
                chat.add_to_history(history_cell::new_error_event(
                    ev.message
                        .unwrap_or_else(|| "Failed to restore workspace state.".to_string()),
                ));
            } else if let Some(message) = ev.message {
                chat.add_to_history(history_cell::new_info_event(message, /*hint*/ None));
            }
            chat.request_redraw();
        }
        EventMsg::Error(ev) => {
            chat.handle_non_retry_error(ev.message, ev.codex_error_info.map(Into::into));
        }
        _ => {}
    }
}

fn app_server_exec_source(source: CoreExecCommandSource) -> ExecCommandSource {
    match source {
        CoreExecCommandSource::Agent => ExecCommandSource::Agent,
        CoreExecCommandSource::UserShell => ExecCommandSource::UserShell,
        CoreExecCommandSource::UnifiedExecStartup => ExecCommandSource::UnifiedExecStartup,
        CoreExecCommandSource::UnifiedExecInteraction => ExecCommandSource::UnifiedExecInteraction,
    }
}

fn core_exec_source(source: ExecCommandSource) -> CoreExecCommandSource {
    match source {
        ExecCommandSource::Agent => CoreExecCommandSource::Agent,
        ExecCommandSource::UserShell => CoreExecCommandSource::UserShell,
        ExecCommandSource::UnifiedExecStartup => CoreExecCommandSource::UnifiedExecStartup,
        ExecCommandSource::UnifiedExecInteraction => CoreExecCommandSource::UnifiedExecInteraction,
    }
}

pub(super) async fn test_config() -> Config {
    // Start from the built-in defaults so tests do not inherit host/system config.
    let codex_home = tempfile::Builder::new()
        .prefix("chatwidget-tests-")
        .tempdir()
        .expect("tempdir")
        .keep();
    let mut config =
        Config::load_default_with_cli_overrides_for_codex_home(codex_home.clone(), Vec::new())
            .await
            .expect("config");
    config.codex_home = codex_home.abs();
    config.sqlite_home = codex_home.clone();
    config.log_dir = codex_home.join("log");
    config.cwd = PathBuf::from(test_path_display("/tmp/project")).abs();
    config.config_layer_stack = ConfigLayerStack::default();
    config.startup_warnings.clear();
    config.user_instructions = None;
    config
}

pub(super) fn test_project_path() -> PathBuf {
    PathBuf::from(test_path_display("/tmp/project"))
}

pub(super) fn truncated_path_variants(path: &str) -> Vec<String> {
    let chars: Vec<char> = path.chars().collect();
    (1..chars.len())
        .map(|len| chars[..len].iter().collect::<String>())
        .collect()
}

pub(super) fn normalize_snapshot_paths(text: impl Into<String>) -> String {
    let mut text = text.into();
    let platform_test_cwd = test_path_display("/tmp/project");
    if platform_test_cwd == "/tmp/project" {
        text
    } else {
        text = text.replace(&platform_test_cwd, "/tmp/project");

        for platform_prefix in truncated_path_variants(&platform_test_cwd)
            .into_iter()
            .rev()
        {
            let unix_prefix: String = "/tmp/project"
                .chars()
                .take(platform_prefix.chars().count())
                .collect();
            text = text.replace(&format!("{platform_prefix}…"), &format!("{unix_prefix}…"));
        }

        text
    }
}

pub(super) fn normalized_backend_snapshot<T: std::fmt::Display>(value: &T) -> String {
    let platform_test_cwd = test_path_display("/tmp/project");
    let rendered = format!("{value}");

    if platform_test_cwd == "/tmp/project" {
        return rendered;
    }

    rendered
        .lines()
        .map(|line| {
            if let Some(content) = line
                .strip_prefix('"')
                .and_then(|line| line.strip_suffix('"'))
            {
                let width = content.chars().count();
                let normalized = normalize_snapshot_paths(content);
                format!("\"{normalized:width$}\"")
            } else {
                normalize_snapshot_paths(line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn invalid_value(
    candidate: impl Into<String>,
    allowed: impl Into<String>,
) -> ConstraintError {
    ConstraintError::InvalidValue {
        field_name: "<unknown>",
        candidate: candidate.into(),
        allowed: allowed.into(),
        requirement_source: RequirementSource::Unknown,
    }
}

pub(super) fn snapshot(percent: f64) -> RateLimitSnapshot {
    RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: percent.round() as i32,
            window_duration_mins: Some(60),
            resets_at: None,
        }),
        secondary: None,
        credits: None,
        plan_type: None,
        rate_limit_reached_type: None,
    }
}

pub(super) fn test_session_telemetry(config: &Config, model: &str) -> SessionTelemetry {
    let model_info = crate::legacy_core::test_support::construct_model_info_offline(model, config);
    SessionTelemetry::new(
        ThreadId::new(),
        model,
        model_info.slug.as_str(),
        /*account_id*/ None,
        /*account_email*/ None,
        /*auth_mode*/ None,
        "test_originator".to_string(),
        /*log_user_prompts*/ false,
        "test".to_string(),
        SessionSource::Cli,
    )
}

pub(super) fn test_model_catalog(config: &Config) -> Arc<ModelCatalog> {
    let collaboration_modes_config = CollaborationModesConfig {
        default_mode_request_user_input: config
            .features
            .enabled(Feature::RequestUserInputOutsidePlanMode),
    };
    Arc::new(ModelCatalog::new(
        crate::legacy_core::test_support::all_model_presets().clone(),
        collaboration_modes_config,
    ))
}

// --- Helpers for tests that need direct construction and event draining ---
pub(super) async fn make_chatwidget_manual(
    model_override: Option<&str>,
) -> (
    ChatWidget,
    tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
    tokio::sync::mpsc::UnboundedReceiver<Op>,
) {
    let (tx_raw, rx) = unbounded_channel::<AppEvent>();
    let app_event_tx = AppEventSender::new(tx_raw);
    let (op_tx, op_rx) = unbounded_channel::<Op>();
    let mut cfg = test_config().await;
    let resolved_model = model_override.map(str::to_owned).unwrap_or_else(|| {
        crate::legacy_core::test_support::get_model_offline(cfg.model.as_deref())
    });
    if let Some(model) = model_override {
        cfg.model = Some(model.to_string());
    }
    let session_telemetry = test_session_telemetry(&cfg, resolved_model.as_str());
    let init = ChatWidgetInit {
        config: cfg.clone(),
        frame_requester: FrameRequester::test_dummy(),
        app_event_tx,
        workspace_command_runner: None,
        initial_user_message: None,
        enhanced_keys_supported: false,
        has_chatgpt_account: false,
        model_catalog: test_model_catalog(&cfg),
        feedback: codex_feedback::CodexFeedback::new(),
        is_first_run: true,
        status_account_display: None,
        runtime_model_provider_base_url: None,
        initial_plan_type: None,
        model: Some(resolved_model.clone()),
        startup_tooltip_override: None,
        status_line_invalid_items_warned: Arc::new(AtomicBool::new(false)),
        terminal_title_invalid_items_warned: Arc::new(AtomicBool::new(false)),
        session_telemetry,
    };
    let mut widget = ChatWidget::new_with_op_target(init, super::CodexOpTarget::Direct(op_tx));
    widget.config = cfg;
    widget.set_model(&resolved_model);
    (widget, rx, op_rx)
}

// ChatWidget may emit other `Op`s (e.g. history/logging updates) on the same channel; this helper
// filters until we see a submission op.
pub(super) fn next_submit_op(op_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Op>) -> Op {
    loop {
        match op_rx.try_recv() {
            Ok(op @ Op::UserTurn { .. }) => return op,
            Ok(_) => continue,
            Err(TryRecvError::Empty) => panic!("expected a submit op but queue was empty"),
            Err(TryRecvError::Disconnected) => panic!("expected submit op but channel closed"),
        }
    }
}

pub(super) fn next_interrupt_op(op_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Op>) {
    loop {
        match op_rx.try_recv() {
            Ok(Op::Interrupt) => return,
            Ok(_) => continue,
            Err(TryRecvError::Empty) => panic!("expected interrupt op but queue was empty"),
            Err(TryRecvError::Disconnected) => panic!("expected interrupt op but channel closed"),
        }
    }
}

pub(super) fn next_realtime_close_op(op_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Op>) {
    loop {
        match op_rx.try_recv() {
            Ok(Op::RealtimeConversationClose) => return,
            Ok(_) => continue,
            Err(TryRecvError::Empty) => {
                panic!("expected realtime close op but queue was empty")
            }
            Err(TryRecvError::Disconnected) => {
                panic!("expected realtime close op but channel closed")
            }
        }
    }
}

pub(super) fn assert_no_submit_op(op_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Op>) {
    while let Ok(op) = op_rx.try_recv() {
        assert!(
            !matches!(op, Op::UserTurn { .. }),
            "unexpected submit op: {op:?}"
        );
    }
}

pub(crate) fn set_chatgpt_auth(chat: &mut ChatWidget) {
    chat.has_chatgpt_account = true;
    chat.model_catalog = test_model_catalog(&chat.config);
}

fn test_model_info(slug: &str, priority: i32, supports_fast_mode: bool) -> ModelInfo {
    let additional_speed_tiers = if supports_fast_mode {
        vec![codex_protocol::openai_models::SPEED_TIER_FAST]
    } else {
        Vec::new()
    };
    serde_json::from_value(json!({
        "slug": slug,
        "display_name": slug,
        "description": format!("{slug} description"),
        "default_reasoning_level": "medium",
        "supported_reasoning_levels": [{"effort": "medium", "description": "medium"}],
        "shell_type": "shell_command",
        "visibility": "list",
        "supported_in_api": true,
        "priority": priority,
        "additional_speed_tiers": additional_speed_tiers,
        "availability_nux": null,
        "upgrade": null,
        "base_instructions": "base instructions",
        "supports_reasoning_summaries": false,
        "default_reasoning_summary": "none",
        "support_verbosity": false,
        "default_verbosity": null,
        "apply_patch_tool_type": null,
        "truncation_policy": {"mode": "bytes", "limit": 10_000},
        "supports_parallel_tool_calls": false,
        "supports_image_detail_original": false,
        "context_window": 272_000,
        "experimental_supported_tools": [],
    }))
    .expect("valid model info")
}

pub(crate) fn set_fast_mode_test_catalog(chat: &mut ChatWidget) {
    let models: Vec<ModelPreset> = ModelsResponse {
        models: vec![
            test_model_info(
                "gpt-5.4", /*priority*/ 0, /*supports_fast_mode*/ true,
            ),
            test_model_info(
                "gpt-5.3-codex",
                /*priority*/ 1,
                /*supports_fast_mode*/ false,
            ),
        ],
    }
    .models
    .into_iter()
    .map(Into::into)
    .collect();

    chat.model_catalog = Arc::new(ModelCatalog::new(
        models,
        CollaborationModesConfig {
            default_mode_request_user_input: chat
                .config
                .features
                .enabled(Feature::RequestUserInputOutsidePlanMode),
        },
    ));
}

pub(crate) async fn make_chatwidget_manual_with_sender() -> (
    ChatWidget,
    AppEventSender,
    tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
    tokio::sync::mpsc::UnboundedReceiver<Op>,
) {
    let (widget, rx, op_rx) = make_chatwidget_manual(/*model_override*/ None).await;
    let app_event_tx = widget.app_event_tx.clone();
    (widget, app_event_tx, rx, op_rx)
}

pub(super) fn drain_insert_history(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<AppEvent>,
) -> Vec<Vec<ratatui::text::Line<'static>>> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let AppEvent::InsertHistoryCell(cell) = ev {
            let mut lines = cell.display_lines(/*width*/ 80);
            if !cell.is_stream_continuation() && !out.is_empty() && !lines.is_empty() {
                lines.insert(0, "".into());
            }
            out.push(lines)
        }
    }
    out
}

pub(super) fn lines_to_single_string(lines: &[ratatui::text::Line<'static>]) -> String {
    let mut s = String::new();
    for line in lines {
        for span in &line.spans {
            s.push_str(&span.content);
        }
        s.push('\n');
    }
    s
}

pub(super) fn status_line_text(chat: &ChatWidget) -> Option<String> {
    chat.status_line_text()
}

pub(super) fn make_token_info(total_tokens: i64, context_window: i64) -> TokenUsageInfo {
    fn usage(total_tokens: i64) -> TokenUsage {
        TokenUsage {
            total_tokens,
            ..TokenUsage::default()
        }
    }

    TokenUsageInfo {
        total_token_usage: usage(total_tokens),
        last_token_usage: usage(total_tokens),
        model_context_window: Some(context_window),
    }
}

pub(super) fn handle_exec_approval_request(
    chat: &mut ChatWidget,
    id: &str,
    ev: ExecApprovalRequestEvent,
) {
    chat.on_exec_approval_request(id.to_string(), ev);
}

pub(super) fn handle_apply_patch_approval_request(
    chat: &mut ChatWidget,
    id: &str,
    ev: ApplyPatchApprovalRequestEvent,
) {
    chat.on_apply_patch_approval_request(id.to_string(), ev);
}

pub(super) fn handle_turn_started(chat: &mut ChatWidget, turn_id: &str) {
    chat.handle_server_notification(
        ServerNotification::TurnStarted(TurnStartedNotification {
            thread_id: chat.thread_id.map(|id| id.to_string()).unwrap_or_default(),
            turn: AppServerTurn {
                id: turn_id.to_string(),
                items: Vec::new(),
                status: AppServerTurnStatus::InProgress,
                error: None,
                started_at: None,
                completed_at: None,
                duration_ms: None,
            },
        }),
        /*replay_kind*/ None,
    );
}

pub(super) fn handle_turn_completed(
    chat: &mut ChatWidget,
    turn_id: &str,
    duration_ms: Option<i64>,
) {
    chat.handle_server_notification(
        ServerNotification::TurnCompleted(TurnCompletedNotification {
            thread_id: chat.thread_id.map(|id| id.to_string()).unwrap_or_default(),
            turn: AppServerTurn {
                id: turn_id.to_string(),
                items: Vec::new(),
                status: AppServerTurnStatus::Completed,
                error: None,
                started_at: None,
                completed_at: None,
                duration_ms,
            },
        }),
        /*replay_kind*/ None,
    );
}

pub(super) fn handle_turn_interrupted(chat: &mut ChatWidget, turn_id: &str) {
    chat.handle_server_notification(
        ServerNotification::TurnCompleted(TurnCompletedNotification {
            thread_id: chat.thread_id.map(|id| id.to_string()).unwrap_or_default(),
            turn: AppServerTurn {
                id: turn_id.to_string(),
                items: Vec::new(),
                status: AppServerTurnStatus::Interrupted,
                error: None,
                started_at: None,
                completed_at: None,
                duration_ms: None,
            },
        }),
        /*replay_kind*/ None,
    );
}

pub(super) fn handle_budget_limited_turn(chat: &mut ChatWidget, turn_id: &str) {
    chat.budget_limited_turn_ids.insert(turn_id.to_string());
    handle_turn_interrupted(chat, turn_id);
}

pub(super) fn handle_agent_message_delta(chat: &mut ChatWidget, delta: impl AsRef<str>) {
    chat.on_agent_message_delta(delta.as_ref().to_string());
}

pub(super) fn handle_agent_reasoning_delta(chat: &mut ChatWidget, delta: impl AsRef<str>) {
    chat.on_agent_reasoning_delta(delta.as_ref().to_string());
}

pub(super) fn handle_agent_reasoning_final(chat: &mut ChatWidget) {
    chat.on_agent_reasoning_final();
}

pub(super) fn handle_error(
    chat: &mut ChatWidget,
    message: &str,
    codex_error_info: Option<CodexErrorInfo>,
) {
    chat.handle_server_notification(
        ServerNotification::Error(ErrorNotification {
            error: AppServerTurnError {
                message: message.to_string(),
                codex_error_info,
                additional_details: None,
            },
            will_retry: false,
            thread_id: chat.thread_id.map(|id| id.to_string()).unwrap_or_default(),
            turn_id: chat.last_turn_id.clone().unwrap_or_default(),
        }),
        /*replay_kind*/ None,
    );
}

pub(super) fn handle_warning(chat: &mut ChatWidget, message: &str) {
    chat.on_warning(message.to_string());
}

pub(super) fn handle_stream_error(
    chat: &mut ChatWidget,
    message: &str,
    additional_details: Option<String>,
) {
    handle_stream_error_with_replay(chat, message, additional_details, /*replay_kind*/ None);
}

pub(super) fn handle_stream_error_with_replay(
    chat: &mut ChatWidget,
    message: &str,
    additional_details: Option<String>,
    replay_kind: Option<ReplayKind>,
) {
    chat.handle_server_notification(
        ServerNotification::Error(ErrorNotification {
            error: AppServerTurnError {
                message: message.to_string(),
                codex_error_info: None,
                additional_details,
            },
            will_retry: true,
            thread_id: chat.thread_id.map(|id| id.to_string()).unwrap_or_default(),
            turn_id: chat.last_turn_id.clone().unwrap_or_default(),
        }),
        replay_kind,
    );
}

pub(super) fn replay_user_message_text(
    chat: &mut ChatWidget,
    item_id: &str,
    text: &str,
    replay_kind: ReplayKind,
) {
    replay_user_message_inputs(
        chat,
        item_id,
        vec![AppServerUserInput::Text {
            text: text.to_string(),
            text_elements: Vec::new(),
        }],
        replay_kind,
    );
}

pub(super) fn replay_user_message_inputs(
    chat: &mut ChatWidget,
    item_id: &str,
    content: Vec<AppServerUserInput>,
    replay_kind: ReplayKind,
) {
    chat.replay_thread_item(
        AppServerThreadItem::UserMessage {
            id: item_id.to_string(),
            content,
        },
        "turn-1".to_string(),
        replay_kind,
    );
}

pub(super) fn replay_agent_message(
    chat: &mut ChatWidget,
    item_id: &str,
    text: &str,
    replay_kind: ReplayKind,
) {
    chat.replay_thread_item(
        AppServerThreadItem::AgentMessage {
            id: item_id.to_string(),
            text: text.to_string(),
            phase: None,
            memory_citation: None,
        },
        "turn-1".to_string(),
        replay_kind,
    );
}

pub(super) fn replay_entered_review_mode(chat: &mut ChatWidget, hint: &str) {
    chat.replay_thread_item(
        AppServerThreadItem::EnteredReviewMode {
            id: "entered-review".to_string(),
            review: hint.to_string(),
        },
        "turn-1".to_string(),
        ReplayKind::ThreadSnapshot,
    );
}

pub(super) fn replay_turn_started(chat: &mut ChatWidget, replay_kind: ReplayKind) {
    chat.handle_server_notification(
        ServerNotification::TurnStarted(TurnStartedNotification {
            thread_id: chat.thread_id.map(|id| id.to_string()).unwrap_or_default(),
            turn: AppServerTurn {
                id: "turn-1".to_string(),
                items: Vec::new(),
                status: AppServerTurnStatus::InProgress,
                error: None,
                started_at: None,
                completed_at: None,
                duration_ms: None,
            },
        }),
        Some(replay_kind),
    );
}

pub(super) fn replay_agent_message_delta(
    chat: &mut ChatWidget,
    delta: &str,
    replay_kind: ReplayKind,
) {
    chat.handle_server_notification(
        ServerNotification::AgentMessageDelta(
            codex_app_server_protocol::AgentMessageDeltaNotification {
                thread_id: chat.thread_id.map(|id| id.to_string()).unwrap_or_default(),
                turn_id: "turn-1".to_string(),
                item_id: "agent-1".to_string(),
                delta: delta.to_string(),
            },
        ),
        Some(replay_kind),
    );
}

pub(super) fn handle_token_count(chat: &mut ChatWidget, info: Option<TokenUsageInfo>) {
    chat.set_token_info(info);
}

pub(super) fn handle_model_verification(
    chat: &mut ChatWidget,
    verifications: Vec<AppServerModelVerification>,
) {
    chat.on_app_server_model_verification(&verifications);
}

pub(super) fn handle_entered_review_mode(chat: &mut ChatWidget, hint: &str) {
    chat.enter_review_mode_with_hint(hint.to_string(), /*from_replay*/ false);
}

pub(super) fn handle_exited_review_mode(chat: &mut ChatWidget) {
    chat.exit_review_mode_after_item();
}

pub(super) fn handle_exec_begin(chat: &mut ChatWidget, item: AppServerThreadItem) {
    chat.on_command_execution_started(item);
}

pub(super) fn handle_exec_end(chat: &mut ChatWidget, item: AppServerThreadItem) {
    chat.on_command_execution_completed(item);
}

pub(super) fn handle_patch_apply_begin(
    chat: &mut ChatWidget,
    _call_id: &str,
    _turn_id: &str,
    changes: HashMap<PathBuf, FileChange>,
) {
    chat.on_patch_apply_begin(changes);
}

pub(super) fn handle_patch_apply_end(
    chat: &mut ChatWidget,
    call_id: &str,
    _turn_id: &str,
    changes: HashMap<PathBuf, FileChange>,
    status: AppServerPatchApplyStatus,
) {
    let file_changes = changes
        .into_iter()
        .map(|(path, change)| {
            let (kind, diff) = match change {
                FileChange::Add { content } => (PatchChangeKind::Add, content),
                FileChange::Delete { content } => (PatchChangeKind::Delete, content),
                FileChange::Update {
                    unified_diff,
                    move_path,
                } => (PatchChangeKind::Update { move_path }, unified_diff),
            };
            FileUpdateChange {
                path: path.to_string_lossy().to_string(),
                kind,
                diff,
            }
        })
        .collect();
    chat.handle_file_change_completed_now(AppServerThreadItem::FileChange {
        id: call_id.to_string(),
        changes: file_changes,
        status,
    });
}

pub(super) fn handle_hook_started(chat: &mut ChatWidget, run: AppServerHookRunSummary) {
    chat.on_hook_started(run);
}

pub(super) fn handle_hook_completed(chat: &mut ChatWidget, run: AppServerHookRunSummary) {
    chat.on_hook_completed(run);
}

pub(super) fn handle_view_image_tool_call(
    chat: &mut ChatWidget,
    _call_id: &str,
    path: AbsolutePathBuf,
) {
    chat.on_view_image_tool_call(path);
}

pub(super) fn handle_image_generation_end(
    chat: &mut ChatWidget,
    call_id: &str,
    revised_prompt: Option<String>,
    saved_path: Option<AbsolutePathBuf>,
) {
    chat.on_image_generation_end(call_id.to_string(), revised_prompt, saved_path);
}

// --- Small helpers to tersely drive exec begin/end and snapshot active cell ---
pub(super) fn begin_exec_with_source(
    chat: &mut ChatWidget,
    call_id: &str,
    raw_cmd: &str,
    source: ExecCommandSource,
) -> ExecCommandBeginEvent {
    let command = vec!["bash".to_string(), "-lc".to_string(), raw_cmd.to_string()];
    let parsed_cmd: Vec<ParsedCommand> =
        codex_shell_command::parse_command::parse_command(&command);
    let cwd = AbsolutePathBuf::current_dir().expect("current dir");
    let event = ExecCommandBeginEvent {
        call_id: call_id.to_string(),
        process_id: None,
        turn_id: "turn-1".to_string(),
        started_at_ms: 0,
        command,
        cwd: cwd.clone(),
        parsed_cmd: parsed_cmd.clone(),
        source: core_exec_source(source),
        interaction_input: None,
    };
    let command_actions = parsed_cmd
        .into_iter()
        .map(|parsed| AppServerCommandAction::from_core_with_cwd(parsed, &cwd))
        .collect();
    handle_exec_begin(
        chat,
        AppServerThreadItem::CommandExecution {
            id: call_id.to_string(),
            command: codex_shell_command::parse_command::shlex_join(&event.command),
            cwd,
            process_id: None,
            source,
            status: AppServerCommandExecutionStatus::InProgress,
            command_actions,
            aggregated_output: None,
            exit_code: None,
            duration_ms: None,
        },
    );
    event
}

pub(super) fn begin_unified_exec_startup(
    chat: &mut ChatWidget,
    call_id: &str,
    process_id: &str,
    raw_cmd: &str,
) -> ExecCommandBeginEvent {
    let command = vec!["bash".to_string(), "-lc".to_string(), raw_cmd.to_string()];
    let cwd = AbsolutePathBuf::current_dir().expect("current dir");
    let event = ExecCommandBeginEvent {
        call_id: call_id.to_string(),
        process_id: Some(process_id.to_string()),
        turn_id: "turn-1".to_string(),
        started_at_ms: 0,
        command,
        cwd: cwd.clone(),
        parsed_cmd: Vec::new(),
        source: CoreExecCommandSource::UnifiedExecStartup,
        interaction_input: None,
    };
    handle_exec_begin(
        chat,
        AppServerThreadItem::CommandExecution {
            id: call_id.to_string(),
            command: codex_shell_command::parse_command::shlex_join(&event.command),
            cwd,
            process_id: Some(process_id.to_string()),
            source: ExecCommandSource::UnifiedExecStartup,
            status: AppServerCommandExecutionStatus::InProgress,
            command_actions: Vec::new(),
            aggregated_output: None,
            exit_code: None,
            duration_ms: None,
        },
    );
    event
}

pub(super) fn terminal_interaction(
    chat: &mut ChatWidget,
    call_id: &str,
    process_id: &str,
    stdin: &str,
) {
    let _ = call_id;
    chat.on_terminal_interaction(process_id.to_string(), stdin.to_string());
}

pub(super) fn complete_assistant_message(
    chat: &mut ChatWidget,
    item_id: &str,
    text: &str,
    phase: Option<MessagePhase>,
) {
    chat.on_agent_message_item_completed(AgentMessageItem {
        id: item_id.to_string(),
        content: vec![AgentMessageContent::Text {
            text: text.to_string(),
        }],
        phase,
        memory_citation: None,
    });
}

pub(super) fn pending_steer(text: &str) -> PendingSteer {
    PendingSteer {
        user_message: UserMessage::from(text),
        history_record: UserMessageHistoryRecord::UserMessageText,
        compare_key: PendingSteerCompareKey {
            message: text.to_string(),
            image_count: 0,
        },
    }
}

pub(super) fn complete_user_message(chat: &mut ChatWidget, item_id: &str, text: &str) {
    complete_user_message_for_inputs(
        chat,
        item_id,
        vec![UserInput::Text {
            text: text.to_string(),
            text_elements: Vec::new(),
        }],
    );
}

pub(super) fn complete_user_message_for_inputs(
    chat: &mut ChatWidget,
    _item_id: &str,
    content: Vec<UserInput>,
) {
    chat.on_committed_user_message(&content, /*from_replay*/ false);
}

pub(super) fn begin_exec(
    chat: &mut ChatWidget,
    call_id: &str,
    raw_cmd: &str,
) -> ExecCommandBeginEvent {
    begin_exec_with_source(chat, call_id, raw_cmd, ExecCommandSource::Agent)
}

pub(super) fn end_exec(
    chat: &mut ChatWidget,
    begin_event: ExecCommandBeginEvent,
    stdout: &str,
    stderr: &str,
    exit_code: i32,
) {
    let aggregated = if stderr.is_empty() {
        stdout.to_string()
    } else {
        format!("{stdout}{stderr}")
    };
    let ExecCommandBeginEvent {
        call_id,
        turn_id,
        command,
        cwd,
        parsed_cmd,
        source,
        interaction_input,
        process_id,
        ..
    } = begin_event;
    let _ = (turn_id, interaction_input);
    let command_actions = parsed_cmd
        .into_iter()
        .map(|parsed| AppServerCommandAction::from_core_with_cwd(parsed, &cwd))
        .collect();
    handle_exec_end(
        chat,
        AppServerThreadItem::CommandExecution {
            id: call_id,
            command: codex_shell_command::parse_command::shlex_join(&command),
            cwd,
            process_id,
            source: app_server_exec_source(source),
            status: if exit_code == 0 {
                AppServerCommandExecutionStatus::Completed
            } else {
                AppServerCommandExecutionStatus::Failed
            },
            command_actions,
            aggregated_output: Some(aggregated),
            exit_code: Some(exit_code),
            duration_ms: Some(5),
        },
    );
}

pub(super) fn active_blob(chat: &ChatWidget) -> String {
    let lines = chat
        .active_cell
        .as_ref()
        .expect("active cell present")
        .display_lines(/*width*/ 80);
    lines_to_single_string(&lines)
}

pub(super) fn active_hook_blob(chat: &ChatWidget) -> String {
    let Some(cell) = chat.active_hook_cell.as_ref() else {
        return "<empty>\n".to_string();
    };
    let lines = cell.display_lines(/*width*/ 80);
    lines_to_single_string(&lines)
}

pub(super) fn expire_quiet_hook_linger(chat: &mut ChatWidget) {
    if let Some(cell) = chat.active_hook_cell.as_mut() {
        cell.expire_quiet_runs_now_for_test();
    }
    chat.pre_draw_tick();
}

pub(super) fn reveal_running_hooks(chat: &mut ChatWidget) {
    if let Some(cell) = chat.active_hook_cell.as_mut() {
        cell.reveal_running_runs_now_for_test();
    }
    chat.pre_draw_tick();
}

pub(super) fn reveal_running_hooks_after_delayed_redraw(chat: &mut ChatWidget) {
    if let Some(cell) = chat.active_hook_cell.as_mut() {
        cell.reveal_running_runs_after_delayed_redraw_for_test();
    }
    chat.pre_draw_tick();
}

pub(super) fn get_available_model(chat: &ChatWidget, model: &str) -> ModelPreset {
    let models = chat
        .model_catalog
        .try_list_models()
        .expect("models lock available");
    models
        .iter()
        .find(|&preset| preset.model == model)
        .cloned()
        .unwrap_or_else(|| panic!("{model} preset not found"))
}

pub(super) async fn assert_shift_left_edits_most_recent_queued_message_for_terminal(
    terminal_info: TerminalInfo,
) {
    let (mut chat, _rx, _op_rx) = make_chatwidget_manual(/*model_override*/ None).await;
    chat.queued_message_edit_hint_binding =
        Some(queued_message_edit_binding_for_terminal(terminal_info));
    chat.bottom_pane
        .set_queued_message_edit_binding(chat.queued_message_edit_hint_binding);

    // Simulate a running task so messages would normally be queued.
    chat.bottom_pane.set_task_running(/*running*/ true);

    // Seed two queued messages.
    chat.queued_user_messages
        .push_back(UserMessage::from("first queued".to_string()).into());
    chat.queued_user_messages
        .push_back(UserMessage::from("second queued".to_string()).into());
    chat.refresh_pending_input_preview();

    // Press Shift+Left to edit the most recent (last) queued message.
    chat.handle_key_event(KeyEvent::new(KeyCode::Left, KeyModifiers::SHIFT));

    // Composer should now contain the last queued message.
    assert_eq!(
        chat.bottom_pane.composer_text(),
        "second queued".to_string()
    );
    // And the queue should now contain only the remaining (older) item.
    assert_eq!(chat.queued_user_messages.len(), 1);
    assert_eq!(
        chat.queued_user_messages.front().unwrap().text,
        "first queued"
    );
}

pub(super) fn render_bottom_first_row(chat: &ChatWidget, width: u16) -> String {
    let height = chat.desired_height(width);
    let area = Rect::new(0, 0, width, height);
    let mut buf = Buffer::empty(area);
    chat.render(area, &mut buf);
    for y in 0..area.height {
        let mut row = String::new();
        for x in 0..area.width {
            let s = buf[(x, y)].symbol();
            if s.is_empty() {
                row.push(' ');
            } else {
                row.push_str(s);
            }
        }
        if !row.trim().is_empty() {
            return row;
        }
    }
    String::new()
}

pub(super) fn render_bottom_popup(chat: &ChatWidget, width: u16) -> String {
    let height = chat.desired_height(width);
    let area = Rect::new(0, 0, width, height);
    let mut buf = Buffer::empty(area);
    chat.render(area, &mut buf);

    let mut lines: Vec<String> = (0..area.height)
        .map(|row| {
            let mut line = String::new();
            for col in 0..area.width {
                let symbol = buf[(area.x + col, area.y + row)].symbol();
                if symbol.is_empty() {
                    line.push(' ');
                } else {
                    line.push_str(symbol);
                }
            }
            line.trim_end().to_string()
        })
        .collect();

    while lines.first().is_some_and(|line| line.trim().is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }

    lines.join("\n")
}

pub(super) fn strip_osc8_for_snapshot(text: &str) -> String {
    // Snapshots should assert the visible popup text, not terminal hyperlink escapes.
    let bytes = text.as_bytes();
    let mut stripped = String::with_capacity(text.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i..].starts_with(b"\x1B]8;;") {
            i += 5;
            while i < bytes.len() {
                if bytes[i] == b'\x07' {
                    i += 1;
                    break;
                }
                if i + 1 < bytes.len() && bytes[i] == b'\x1B' && bytes[i + 1] == b'\\' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }

        let ch = text[i..]
            .chars()
            .next()
            .expect("slice should always contain a char");
        stripped.push(ch);
        i += ch.len_utf8();
    }

    stripped
}

pub(super) fn plugins_test_absolute_path(path: &str) -> AbsolutePathBuf {
    std::env::temp_dir()
        .join("codex-plugin-menu-tests")
        .join(path)
        .abs()
}

pub(super) fn plugins_test_interface(
    display_name: Option<&str>,
    short_description: Option<&str>,
    long_description: Option<&str>,
) -> PluginInterface {
    PluginInterface {
        display_name: display_name.map(str::to_string),
        short_description: short_description.map(str::to_string),
        long_description: long_description.map(str::to_string),
        developer_name: None,
        category: None,
        capabilities: Vec::new(),
        website_url: None,
        privacy_policy_url: None,
        terms_of_service_url: None,
        default_prompt: None,
        brand_color: None,
        composer_icon: None,
        composer_icon_url: None,
        logo: None,
        logo_url: None,
        screenshots: Vec::new(),
        screenshot_urls: Vec::new(),
    }
}

pub(super) fn plugins_test_summary(
    id: &str,
    name: &str,
    display_name: Option<&str>,
    description: Option<&str>,
    installed: bool,
    enabled: bool,
    install_policy: PluginInstallPolicy,
) -> PluginSummary {
    PluginSummary {
        id: id.to_string(),
        name: name.to_string(),
        source: PluginSource::Local {
            path: plugins_test_absolute_path(&format!("plugins/{name}")),
        },
        installed,
        enabled,
        install_policy,
        auth_policy: PluginAuthPolicy::OnInstall,
        availability: codex_app_server_protocol::PluginAvailability::Available,
        interface: Some(plugins_test_interface(
            display_name,
            description,
            /*long_description*/ None,
        )),
    }
}

pub(super) fn plugins_test_curated_marketplace(
    plugins: Vec<PluginSummary>,
) -> PluginMarketplaceEntry {
    PluginMarketplaceEntry {
        name: OPENAI_CURATED_MARKETPLACE_NAME.to_string(),
        path: Some(plugins_test_absolute_path("marketplaces/chatgpt")),
        interface: Some(MarketplaceInterface {
            display_name: Some("ChatGPT Marketplace".to_string()),
        }),
        plugins,
    }
}

pub(super) fn plugins_test_repo_marketplace(plugins: Vec<PluginSummary>) -> PluginMarketplaceEntry {
    PluginMarketplaceEntry {
        name: "repo".to_string(),
        path: Some(plugins_test_absolute_path("marketplaces/repo")),
        interface: Some(MarketplaceInterface {
            display_name: Some("Repo Marketplace".to_string()),
        }),
        plugins,
    }
}

pub(super) fn plugins_test_response(
    marketplaces: Vec<PluginMarketplaceEntry>,
) -> PluginListResponse {
    PluginListResponse {
        marketplaces,
        marketplace_load_errors: Vec::new(),
        featured_plugin_ids: Vec::new(),
    }
}

pub(super) fn render_loaded_plugins_popup(
    chat: &mut ChatWidget,
    response: PluginListResponse,
) -> String {
    let cwd = chat.config.cwd.clone();
    chat.on_plugins_loaded(cwd.to_path_buf(), Ok(response));
    chat.add_plugins_output();
    render_bottom_popup(chat, /*width*/ 100)
}

pub(super) fn plugins_test_detail(
    summary: PluginSummary,
    description: Option<&str>,
    skills: &[&str],
    apps: &[(&str, bool)],
    mcp_servers: &[&str],
) -> PluginDetail {
    PluginDetail {
        marketplace_name: "ChatGPT Marketplace".to_string(),
        marketplace_path: Some(plugins_test_absolute_path("marketplaces/chatgpt")),
        summary,
        description: description.map(str::to_string),
        skills: skills
            .iter()
            .map(|name| SkillSummary {
                name: (*name).to_string(),
                description: format!("{name} description"),
                short_description: None,
                interface: None,
                path: Some(plugins_test_absolute_path(&format!(
                    "skills/{name}/SKILL.md"
                ))),
                enabled: true,
            })
            .collect(),
        apps: apps
            .iter()
            .map(|(name, needs_auth)| AppSummary {
                id: format!("{name}-id"),
                name: (*name).to_string(),
                description: Some(format!("{name} app")),
                install_url: Some(format!("https://example.test/{name}")),
                needs_auth: *needs_auth,
            })
            .collect(),
        mcp_servers: mcp_servers.iter().map(|name| (*name).to_string()).collect(),
    }
}

pub(super) fn plugins_test_popup_row_position(popup: &str, needle: &str) -> usize {
    popup
        .find(needle)
        .unwrap_or_else(|| panic!("expected popup to contain {needle}: {popup}"))
}

pub(super) fn type_plugins_search_query(chat: &mut ChatWidget, query: &str) {
    for ch in query.chars() {
        chat.handle_key_event(KeyEvent::from(KeyCode::Char(ch)));
    }
}

pub(super) async fn assert_hook_events_snapshot(
    event_name: AppServerHookEventName,
    run_id: &str,
    status_message: &str,
    snapshot_name: &str,
) {
    let (mut chat, mut rx, _op_rx) = make_chatwidget_manual(/*model_override*/ None).await;

    handle_hook_started(
        &mut chat,
        AppServerHookRunSummary {
            id: run_id.to_string(),
            event_name,
            handler_type: AppServerHookHandlerType::Command,
            execution_mode: AppServerHookExecutionMode::Sync,
            scope: AppServerHookScope::Turn,
            source_path: PathBuf::from(test_path_display("/tmp/hooks.json")).abs(),
            source: codex_app_server_protocol::HookSource::User,
            display_order: 0,
            status: AppServerHookRunStatus::Running,
            status_message: Some(status_message.to_string()),
            started_at: 1,
            completed_at: None,
            duration_ms: None,
            entries: vec![],
        },
    );
    assert!(
        drain_insert_history(&mut rx).is_empty(),
        "hook start should update the live hook cell instead of writing history"
    );
    reveal_running_hooks(&mut chat);
    assert!(
        active_hook_blob(&chat).contains(&format!(
            "Running {} hook: {status_message}",
            hook_event_label(event_name)
        )),
        "hook start should render in the live hook cell"
    );

    handle_hook_completed(
        &mut chat,
        AppServerHookRunSummary {
            id: run_id.to_string(),
            event_name,
            handler_type: AppServerHookHandlerType::Command,
            execution_mode: AppServerHookExecutionMode::Sync,
            scope: AppServerHookScope::Turn,
            source_path: PathBuf::from(test_path_display("/tmp/hooks.json")).abs(),
            source: codex_app_server_protocol::HookSource::User,
            display_order: 0,
            status: AppServerHookRunStatus::Completed,
            status_message: Some(status_message.to_string()),
            started_at: 1,
            completed_at: Some(11),
            duration_ms: Some(10),
            entries: vec![
                AppServerHookOutputEntry {
                    kind: AppServerHookOutputEntryKind::Warning,
                    text: "Heads up from the hook".to_string(),
                },
                AppServerHookOutputEntry {
                    kind: AppServerHookOutputEntryKind::Context,
                    text: "Remember the startup checklist.".to_string(),
                },
            ],
        },
    );

    let cells = drain_insert_history(&mut rx);
    let combined = cells
        .iter()
        .map(|lines| lines_to_single_string(lines))
        .collect::<String>();
    assert_chatwidget_snapshot!(snapshot_name, combined);
}

fn hook_event_label(event_name: AppServerHookEventName) -> &'static str {
    match event_name {
        AppServerHookEventName::PreToolUse => "PreToolUse",
        AppServerHookEventName::PermissionRequest => "PermissionRequest",
        AppServerHookEventName::PostToolUse => "PostToolUse",
        AppServerHookEventName::SessionStart => "SessionStart",
        AppServerHookEventName::UserPromptSubmit => "UserPromptSubmit",
        AppServerHookEventName::Stop => "Stop",
    }
}
