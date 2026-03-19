use super::*;
use crate::AuthManager;
use crate::CodexAuth;
use crate::CodexThread;
use crate::ThreadManager;
use crate::agent::agent_status_from_event;
use crate::auth::AuthCredentialsStoreMode;
use crate::config::AgentRoleConfig;
use crate::config::Config;
use crate::config::ConfigBuilder;
use crate::contextual_user_message::SUBAGENT_NOTIFICATION_OPEN_TAG;
use crate::tasks::CompactTask;
use crate::tasks::SessionTask;
use crate::tasks::SessionTaskContext;

use assert_matches::assert_matches;
use codex_protocol::config_types::ModeKind;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::ErrorEvent;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::RawResponseItemEvent;
use codex_protocol::protocol::TurnAbortReason;
use codex_protocol::protocol::TurnAbortedEvent;
use codex_protocol::protocol::TurnCompleteEvent;
use codex_protocol::protocol::TurnStartedEvent;
use pretty_assertions::assert_eq;
use serial_test::serial;
use std::env;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use toml::Value as TomlValue;

#[derive(Clone, Copy)]
struct WaitForCancellationTask;

#[async_trait::async_trait]
impl SessionTask for WaitForCancellationTask {
    fn kind(&self) -> crate::state::TaskKind {
        crate::state::TaskKind::Regular
    }

    fn span_name(&self) -> &'static str {
        "session_task.wait_for_cancellation"
    }

    async fn run(
        self: Arc<Self>,
        _session: Arc<SessionTaskContext>,
        _ctx: Arc<crate::codex::TurnContext>,
        _input: Vec<UserInput>,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) -> Option<String> {
        cancellation_token.cancelled().await;
        None
    }
}

struct EnvVarGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let original = env::var(key).ok();
        unsafe { env::set_var(key, value) };
        Self { key, original }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            unsafe { env::set_var(self.key, original) };
        } else {
            unsafe { env::remove_var(self.key) };
        }
    }
}

async fn test_config_with_cli_overrides(
    cli_overrides: Vec<(String, TomlValue)>,
) -> (TempDir, Config) {
    let home = TempDir::new().expect("create temp dir");
    let config = ConfigBuilder::default()
        .codex_home(home.path().to_path_buf())
        .cli_overrides(cli_overrides)
        .build()
        .await
        .expect("load default test config");
    (home, config)
}

async fn test_config() -> (TempDir, Config) {
    test_config_with_cli_overrides(Vec::new()).await
}

fn text_input(text: &str) -> Vec<UserInput> {
    vec![UserInput::Text {
        text: text.to_string(),
        text_elements: Vec::new(),
    }]
}

fn thread_spawn_source(parent_thread_id: ThreadId) -> SessionSource {
    SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id,
        depth: 1,
        agent_nickname: None,
        agent_role: None,
    })
}

fn history_contains_text(history_items: &[ResponseItem], needle: &str) -> bool {
    history_items.iter().any(|item| match item {
        ResponseItem::Message { content, .. } => {
            content.iter().any(|content_item| match content_item {
                ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                    text.contains(needle)
                }
                ContentItem::InputImage { .. } => false,
            })
        }
        ResponseItem::FunctionCallOutput { output, .. } => output
            .text_content()
            .is_some_and(|text| text.contains(needle)),
        _ => false,
    })
}

fn count_history_text(history_items: &[ResponseItem], needle: &str) -> usize {
    history_items
        .iter()
        .filter(|item| match item {
            ResponseItem::Message { content, .. } => {
                content.iter().any(|content_item| match content_item {
                    ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                        text.contains(needle)
                    }
                    ContentItem::InputImage { .. } => false,
                })
            }
            ResponseItem::FunctionCallOutput { output, .. } => output
                .text_content()
                .is_some_and(|text| text.contains(needle)),
            _ => false,
        })
        .count()
}

fn has_subagent_notification(history_items: &[ResponseItem]) -> bool {
    history_items.iter().any(|item| {
        let ResponseItem::Message { role, content, .. } = item else {
            return false;
        };
        if role != "user" {
            return false;
        }
        content.iter().any(|content_item| match content_item {
            ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                text.contains(SUBAGENT_NOTIFICATION_OPEN_TAG)
            }
            ContentItem::InputImage { .. } => false,
        })
    })
}

async fn wait_for_subagent_notification(parent_thread: &Arc<CodexThread>) -> bool {
    let wait = async {
        loop {
            let history_items = parent_thread
                .codex
                .session
                .clone_history()
                .await
                .raw_items()
                .to_vec();
            if has_subagent_notification(&history_items) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), wait)
        .await
        .is_ok()
}

async fn wait_for_history_text(parent_thread: &Arc<CodexThread>, needle: &str) -> bool {
    let wait = async {
        loop {
            let history_items = parent_thread
                .codex
                .session
                .clone_history()
                .await
                .raw_items()
                .to_vec();
            if history_contains_text(&history_items, needle) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), wait)
        .await
        .is_ok()
}

async fn wait_for_raw_response_text(thread: &Arc<CodexThread>, needle: &str) -> bool {
    wait_for_raw_response_text_with_timeout(thread, needle, std::time::Duration::from_secs(2)).await
}

async fn wait_for_raw_response_text_with_timeout(
    thread: &Arc<CodexThread>,
    needle: &str,
    timeout: std::time::Duration,
) -> bool {
    let wait = async {
        loop {
            let event = thread
                .next_event()
                .await
                .expect("event should be available");
            if let EventMsg::RawResponseItem(RawResponseItemEvent { item }) = event.msg
                && history_contains_text(&[item], needle)
            {
                return true;
            }
        }
    };
    tokio::time::timeout(timeout, wait).await.is_ok()
}

fn auth_manager_with_auth_file(config: &Config, root: &TempDir, label: &str) -> Arc<AuthManager> {
    AuthManager::shared_with_auth_file(
        config.codex_home.clone(),
        false,
        AuthCredentialsStoreMode::File,
        Some(root.path().join(label).join("auth.json")),
    )
    .expect("auth manager with override auth file")
}

struct AgentControlHarness {
    _home: TempDir,
    config: Config,
    manager: ThreadManager,
    control: AgentControl,
}

impl AgentControlHarness {
    async fn new() -> Self {
        let (home, config) = test_config().await;
        let manager = ThreadManager::with_models_provider_and_home_for_tests(
            CodexAuth::from_api_key("dummy"),
            config.model_provider.clone(),
            config.codex_home.clone(),
        );
        let control = manager.agent_control();
        Self {
            _home: home,
            config,
            manager,
            control,
        }
    }

    async fn start_thread(&self) -> (ThreadId, Arc<CodexThread>) {
        let new_thread = self
            .manager
            .start_thread(self.config.clone())
            .await
            .expect("start thread");
        (new_thread.thread_id, new_thread.thread)
    }

    async fn start_thread_with_auth_manager(
        &self,
        auth_manager: Arc<AuthManager>,
    ) -> (ThreadId, Arc<CodexThread>) {
        let new_thread = self
            .manager
            .resume_thread_with_history(
                self.config.clone(),
                InitialHistory::New,
                auth_manager,
                false,
                None,
            )
            .await
            .expect("start thread");
        (new_thread.thread_id, new_thread.thread)
    }

    async fn arm_post_interrupt_hold(&self, thread: &Arc<CodexThread>) {
        {
            let mut active = thread.codex.session.active_turn.lock().await;
            *active = Some(crate::state::ActiveTurn::default());
        }
        thread.codex.session.interrupt_task().await;
    }
}

#[tokio::test]
async fn send_input_errors_when_manager_dropped() {
    let control = AgentControl::default();
    let err = control
        .send_input(
            ThreadId::new(),
            vec![UserInput::Text {
                text: "hello".to_string(),
                text_elements: Vec::new(),
            }],
        )
        .await
        .expect_err("send_input should fail without a manager");
    assert_eq!(
        err.to_string(),
        "unsupported operation: thread manager dropped"
    );
}

#[tokio::test]
async fn drop_pending_input_clears_buffered_items() {
    let harness = AgentControlHarness::new().await;
    let (agent_id, thread) = harness.start_thread().await;

    {
        let mut active = thread.codex.session.active_turn.lock().await;
        *active = Some(crate::state::ActiveTurn::default());
    }

    thread
        .codex
        .session
        .inject_response_items(vec![ResponseInputItem::Message {
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "queued".to_string(),
            }],
        }])
        .await
        .expect("inject pending input");

    let dropped = harness
        .control
        .drop_pending_input(agent_id)
        .await
        .expect("drop pending input should succeed");
    assert_eq!(dropped, true);
    assert_eq!(thread.codex.session.has_pending_input().await, false);

    let _ = harness.control.shutdown_agent(agent_id).await;
}

#[tokio::test]
async fn get_status_returns_not_found_without_manager() {
    let control = AgentControl::default();
    let got = control.get_status(ThreadId::new()).await;
    assert_eq!(got, AgentStatus::NotFound);
}

#[tokio::test]
async fn on_event_updates_status_from_task_started() {
    let status = agent_status_from_event(&EventMsg::TurnStarted(TurnStartedEvent {
        turn_id: "turn-1".to_string(),
        model_context_window: None,
        collaboration_mode_kind: ModeKind::Default,
    }));
    assert_eq!(status, Some(AgentStatus::Running));
}

#[tokio::test]
async fn on_event_updates_status_from_task_complete() {
    let status = agent_status_from_event(&EventMsg::TurnComplete(TurnCompleteEvent {
        turn_id: "turn-1".to_string(),
        last_agent_message: Some("done".to_string()),
    }));
    let expected = AgentStatus::Completed(Some("done".to_string()));
    assert_eq!(status, Some(expected));
}

#[tokio::test]
async fn on_event_updates_status_from_error() {
    let status = agent_status_from_event(&EventMsg::Error(ErrorEvent {
        message: "boom".to_string(),
        codex_error_info: None,
    }));

    let expected = AgentStatus::Errored("boom".to_string());
    assert_eq!(status, Some(expected));
}

#[tokio::test]
async fn on_event_updates_status_from_turn_aborted() {
    let status = agent_status_from_event(&EventMsg::TurnAborted(TurnAbortedEvent {
        turn_id: Some("turn-1".to_string()),
        reason: TurnAbortReason::Interrupted,
    }));

    let expected = AgentStatus::Interrupted;
    assert_eq!(status, Some(expected));
}

#[tokio::test]
async fn interrupted_status_is_not_final() {
    assert_eq!(is_final(&AgentStatus::Interrupted), false);
}

#[tokio::test]
async fn on_event_updates_status_from_shutdown_complete() {
    let status = agent_status_from_event(&EventMsg::ShutdownComplete);
    assert_eq!(status, Some(AgentStatus::Shutdown));
}

#[tokio::test]
async fn spawn_agent_errors_when_manager_dropped() {
    let control = AgentControl::default();
    let (_home, config) = test_config().await;
    let err = control
        .spawn_agent(config, text_input("hello"), None)
        .await
        .expect_err("spawn_agent should fail without a manager");
    assert_eq!(
        err.to_string(),
        "unsupported operation: thread manager dropped"
    );
}

#[tokio::test]
async fn resume_agent_errors_when_manager_dropped() {
    let control = AgentControl::default();
    let (_home, config) = test_config().await;
    let err = control
        .resume_agent_from_rollout(config, ThreadId::new(), SessionSource::Exec)
        .await
        .expect_err("resume_agent should fail without a manager");
    assert_eq!(
        err.to_string(),
        "unsupported operation: thread manager dropped"
    );
}

#[tokio::test]
async fn send_input_errors_when_thread_missing() {
    let harness = AgentControlHarness::new().await;
    let thread_id = ThreadId::new();
    let err = harness
        .control
        .send_input(
            thread_id,
            vec![UserInput::Text {
                text: "hello".to_string(),
                text_elements: Vec::new(),
            }],
        )
        .await
        .expect_err("send_input should fail for missing thread");
    assert_matches!(err, CodexErr::ThreadNotFound(id) if id == thread_id);
}

#[tokio::test]
async fn get_status_returns_not_found_for_missing_thread() {
    let harness = AgentControlHarness::new().await;
    let status = harness.control.get_status(ThreadId::new()).await;
    assert_eq!(status, AgentStatus::NotFound);
}

#[tokio::test]
async fn get_status_returns_pending_init_for_new_thread() {
    let harness = AgentControlHarness::new().await;
    let (thread_id, _) = harness.start_thread().await;
    let status = harness.control.get_status(thread_id).await;
    assert_eq!(status, AgentStatus::PendingInit);
}

#[tokio::test]
async fn subscribe_status_errors_for_missing_thread() {
    let harness = AgentControlHarness::new().await;
    let thread_id = ThreadId::new();
    let err = harness
        .control
        .subscribe_status(thread_id)
        .await
        .expect_err("subscribe_status should fail for missing thread");
    assert_matches!(err, CodexErr::ThreadNotFound(id) if id == thread_id);
}

#[tokio::test]
async fn subscribe_status_updates_on_shutdown() {
    let harness = AgentControlHarness::new().await;
    let (thread_id, thread) = harness.start_thread().await;
    let mut status_rx = harness
        .control
        .subscribe_status(thread_id)
        .await
        .expect("subscribe_status should succeed");
    assert_eq!(status_rx.borrow().clone(), AgentStatus::PendingInit);

    let _ = thread
        .submit(Op::Shutdown {})
        .await
        .expect("shutdown should submit");

    let _ = status_rx.changed().await;
    assert_eq!(status_rx.borrow().clone(), AgentStatus::Shutdown);
}

#[tokio::test]
async fn send_input_submits_user_message() {
    let harness = AgentControlHarness::new().await;
    let (thread_id, _thread) = harness.start_thread().await;

    let submission_id = harness
        .control
        .send_input(
            thread_id,
            vec![UserInput::Text {
                text: "hello from tests".to_string(),
                text_elements: Vec::new(),
            }],
        )
        .await
        .expect("send_input should succeed");
    assert!(!submission_id.is_empty());
    let expected = (
        thread_id,
        Op::UserInput {
            items: vec![UserInput::Text {
                text: "hello from tests".to_string(),
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
        },
    );
    let captured = harness
        .manager
        .captured_ops()
        .into_iter()
        .find(|entry| *entry == expected);
    assert_eq!(captured, Some(expected));
}

#[tokio::test]
async fn send_agent_message_to_idle_thread_avoids_empty_user_bootstrap() {
    let harness = AgentControlHarness::new().await;
    let (receiver_thread_id, _thread) = harness.start_thread().await;
    let sender_thread_id = ThreadId::new();

    let submission_id = harness
        .control
        .send_agent_message(
            receiver_thread_id,
            sender_thread_id,
            "watchdog update".to_string(),
        )
        .await
        .expect("send_agent_message should succeed");
    assert!(!submission_id.is_empty());

    let captured = harness
        .manager
        .captured_ops()
        .into_iter()
        .find(|(thread_id, op)| {
            *thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
        })
        .expect("expected injected collab inbox op");

    let Op::InjectResponseItems { items } = captured.1 else {
        unreachable!("matched above");
    };
    assert_eq!(items.len(), 1);
    match &items[0] {
        ResponseInputItem::FunctionCallOutput { output, .. } => {
            let output_text = output
                .body
                .to_text()
                .expect("payload should convert to text");
            let payload: AgentInboxPayload =
                serde_json::from_str(&output_text).expect("payload should be valid json");
            assert_eq!(payload.sender_thread_id, sender_thread_id);
            assert_eq!(payload.message, "watchdog update");
        }
        other => panic!("expected collab function call output, got {other:?}"),
    }
}

#[tokio::test]
async fn send_agent_message_to_active_root_thread_injects_immediately() {
    let harness = AgentControlHarness::new().await;
    let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
    let sender_thread_id = ThreadId::new();

    let turn_context = receiver_thread
        .codex
        .session
        .new_default_turn_with_sub_id("active-root-turn".to_string())
        .await;
    receiver_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&turn_context),
            text_input("active root turn"),
            WaitForCancellationTask,
        )
        .await;
    assert!(receiver_thread.has_active_turn().await);

    let submission_id = harness
        .control
        .send_agent_message(
            receiver_thread_id,
            sender_thread_id,
            "same-turn update".to_string(),
        )
        .await
        .expect("send_agent_message should inject into the active root turn");
    assert!(!submission_id.is_empty());

    let (queued_items, queued_bytes, flush_pending) =
        receiver_thread.codex.session.post_turn_agent_stats().await;
    assert_eq!(queued_items, 0);
    assert_eq!(queued_bytes, 0);
    assert_eq!(flush_pending, false);
    let injected_items = receiver_thread.codex.session.get_pending_input().await;
    assert_eq!(injected_items.len(), 1);
    assert!(
        harness
            .manager
            .captured_ops()
            .into_iter()
            .all(|(thread_id, op)| {
                thread_id != receiver_thread_id || !matches!(op, Op::InjectResponseItems { .. })
            })
    );

    receiver_thread
        .codex
        .session
        .abort_all_tasks(TurnAbortReason::Interrupted)
        .await;
    assert_eq!(
        receiver_thread
            .codex
            .session
            .post_turn_agent_stats()
            .await
            .0,
        0
    );
    let _ = harness.control.shutdown_agent(receiver_thread_id).await;
}

#[tokio::test]
async fn send_agent_message_late_active_turn_miss_queues_post_turn_flush() {
    let harness = AgentControlHarness::new().await;
    let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
    let sender_thread_id = ThreadId::new();

    let turn_context = receiver_thread
        .codex
        .session
        .new_default_turn_with_sub_id("late-active-root-turn".to_string())
        .await;
    receiver_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&turn_context),
            text_input("active root turn"),
            WaitForCancellationTask,
        )
        .await;
    assert!(receiver_thread.has_active_turn().await);

    let receiver_session = Arc::clone(&receiver_thread.codex.session);
    let submission_id = harness
        .control
        .send_agent_message_inner(
            receiver_thread_id,
            sender_thread_id,
            "late same-turn update".to_string(),
            true,
            LateAgentDeliveryMode::QueuePostTurn,
            Some(Box::pin(async move {
                receiver_session
                    .abort_all_tasks(TurnAbortReason::Replaced)
                    .await;
            })),
        )
        .await
        .expect("send_agent_message should recover a late active-turn miss");
    assert!(!submission_id.is_empty());

    let inject_ops: Vec<Op> = harness
        .manager
        .captured_ops()
        .into_iter()
        .filter_map(|(thread_id, op)| (thread_id == receiver_thread_id).then_some(op))
        .filter(|op| matches!(op, Op::InjectResponseItems { .. }))
        .collect();
    assert_eq!(inject_ops.len(), 1);
    match &inject_ops[0] {
        Op::InjectResponseItems { items } => {
            assert!(items.is_empty(), "late miss should arm an empty flush op");
        }
        other => panic!("expected inject response items op, got {other:?}"),
    }

    receiver_thread
        .codex
        .session
        .clear_post_turn_agent_items()
        .await;
    let _ = harness.control.shutdown_agent(receiver_thread_id).await;
}

#[tokio::test]
async fn send_agent_message_after_sampling_completed_queues_post_turn_flush() {
    let harness = AgentControlHarness::new().await;
    let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
    let sender_thread_id = ThreadId::new();

    let turn_context = receiver_thread
        .codex
        .session
        .new_default_turn_with_sub_id("sampling-completed-turn".to_string())
        .await;
    receiver_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&turn_context),
            text_input("active root turn"),
            WaitForCancellationTask,
        )
        .await;
    assert!(receiver_thread.has_active_turn().await);

    let receiver_session = Arc::clone(&receiver_thread.codex.session);
    let submission_id = harness
        .control
        .send_agent_message_inner(
            receiver_thread_id,
            sender_thread_id,
            "late completed update".to_string(),
            true,
            LateAgentDeliveryMode::QueuePostTurn,
            Some(Box::pin(async move {
                receiver_session.mark_active_turn_sampling_completed().await;
            })),
        )
        .await
        .expect("send_agent_message should queue after sampling completed");
    assert!(!submission_id.is_empty());

    let (queued_items, queued_bytes, flush_pending) =
        receiver_thread.codex.session.post_turn_agent_stats().await;
    assert_eq!(queued_items, 1);
    assert!(queued_bytes > 0);
    assert!(flush_pending);
    assert!(
        receiver_thread
            .codex
            .session
            .get_pending_input()
            .await
            .is_empty()
    );

    assert!(
        harness
            .manager
            .captured_ops()
            .into_iter()
            .filter_map(|(thread_id, op)| (thread_id == receiver_thread_id).then_some(op))
            .all(|op| !matches!(op, Op::InjectResponseItems { .. }))
    );

    receiver_thread
        .codex
        .session
        .clear_post_turn_agent_items()
        .await;
    let _ = harness.control.shutdown_agent(receiver_thread_id).await;
}

#[tokio::test]
async fn send_agent_message_late_interrupt_miss_preserves_post_interrupt_hold() {
    let harness = AgentControlHarness::new().await;
    let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
    let sender_thread_id = ThreadId::new();

    let turn_context = receiver_thread
        .codex
        .session
        .new_default_turn_with_sub_id("late-interrupt-turn".to_string())
        .await;
    receiver_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&turn_context),
            text_input("active root turn"),
            WaitForCancellationTask,
        )
        .await;
    assert!(receiver_thread.has_active_turn().await);

    let receiver_session = Arc::clone(&receiver_thread.codex.session);
    let submission_id = harness
        .control
        .send_agent_message_inner(
            receiver_thread_id,
            sender_thread_id,
            "late interrupt update".to_string(),
            true,
            LateAgentDeliveryMode::QueuePostTurn,
            Some(Box::pin(async move {
                receiver_session.interrupt_task().await;
            })),
        )
        .await
        .expect("send_agent_message should defer after late interrupt miss");
    assert!(!submission_id.is_empty());

    let (deferred_items, deferred_bytes) =
        receiver_thread.codex.session.deferred_collab_stats().await;
    assert_eq!(deferred_items, 1);
    assert!(deferred_bytes > 0);
    let (queued_items, queued_bytes, flush_pending) =
        receiver_thread.codex.session.post_turn_agent_stats().await;
    assert_eq!((queued_items, queued_bytes, flush_pending), (0, 0, false));
    assert!(
        receiver_thread
            .codex
            .session
            .post_interrupt_collab_hold_armed()
            .await
    );
    let injected = harness
        .manager
        .captured_ops()
        .into_iter()
        .any(|(thread_id, op)| {
            thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
        });
    assert!(!injected);

    let _ = receiver_thread
        .codex
        .session
        .take_deferred_collab_items()
        .await;
    let _ = harness.control.shutdown_agent(receiver_thread_id).await;
}

#[tokio::test]
async fn send_agent_message_keeps_turn_boundary_replies_in_same_post_turn_queue() {
    let harness = AgentControlHarness::new().await;
    let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
    let first_sender = ThreadId::new();
    let second_sender = ThreadId::new();
    let queued_items = build_agent_inbox_items(
        CollabInboxDeliveryRole::Tool,
        first_sender,
        None,
        None,
        "queued before boundary".to_string(),
        false,
    )
    .expect("build queued items");
    receiver_thread
        .codex
        .session
        .enqueue_post_turn_agent_items(queued_items)
        .await
        .expect("seed boundary queue");
    assert!(
        receiver_thread
            .codex
            .session
            .arm_post_turn_agent_flush_if_items()
            .await
    );

    harness
        .control
        .send_agent_message(
            receiver_thread_id,
            second_sender,
            "queued during boundary flush".to_string(),
        )
        .await
        .expect("second send should join the same queue");

    let (queued_items, queued_bytes, flush_pending) =
        receiver_thread.codex.session.post_turn_agent_stats().await;
    assert_eq!(queued_items, 2);
    assert!(queued_bytes > 0);
    assert_eq!(flush_pending, true);

    let injected = harness
        .manager
        .captured_ops()
        .into_iter()
        .any(|(thread_id, op)| {
            thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
        });
    assert_eq!(injected, false);

    receiver_thread
        .codex
        .session
        .clear_post_turn_agent_items()
        .await;
    let _ = harness.control.shutdown_agent(receiver_thread_id).await;
}

#[tokio::test]
async fn send_agent_message_defers_when_post_interrupt_hold_is_armed() {
    let harness = AgentControlHarness::new().await;
    let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
    harness.arm_post_interrupt_hold(&receiver_thread).await;

    let submission_id = harness
        .control
        .send_agent_message(
            receiver_thread_id,
            ThreadId::new(),
            "deferred update".to_string(),
        )
        .await
        .expect("send_agent_message should defer while hold is armed");
    assert!(!submission_id.is_empty());

    let (deferred_items, deferred_bytes) =
        receiver_thread.codex.session.deferred_collab_stats().await;
    assert_eq!(deferred_items, 1);
    assert!(deferred_bytes > 0);

    let injected = harness
        .manager
        .captured_ops()
        .into_iter()
        .any(|(thread_id, op)| {
            thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
        });
    assert_eq!(injected, false);

    let _ = harness.control.shutdown_agent(receiver_thread_id).await;
}

#[tokio::test]
async fn send_agent_message_watchdog_helper_bypasses_deferral() {
    let harness = AgentControlHarness::new().await;
    let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
    harness.arm_post_interrupt_hold(&receiver_thread).await;

    let watchdog_handle_id = harness
        .control
        .spawn_agent_handle(
            harness.config.clone(),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: receiver_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
        )
        .await
        .expect("spawn watchdog handle");
    harness
        .control
        .register_watchdog(WatchdogRegistration {
            owner_thread_id: receiver_thread_id,
            target_thread_id: watchdog_handle_id,
            child_depth: 1,
            interval_s: 30,
            prompt: "watchdog".to_string(),
            config: harness.config.clone(),
        })
        .await
        .expect("register watchdog");

    let helper_id = harness
        .control
        .spawn_agent_handle(
            harness.config.clone(),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: receiver_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
        )
        .await
        .expect("spawn helper");
    harness
        .control
        .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_id)
        .await;

    let submission_id = harness
        .control
        .send_agent_message(receiver_thread_id, helper_id, "watchdog bypass".to_string())
        .await
        .expect("watchdog helper should bypass deferred collab queue");
    assert!(!submission_id.is_empty());

    let (deferred_items, _deferred_bytes) =
        receiver_thread.codex.session.deferred_collab_stats().await;
    assert_eq!(deferred_items, 0);

    let injected = harness
        .manager
        .captured_ops()
        .into_iter()
        .any(|(thread_id, op)| {
            thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
        });
    assert_eq!(injected, true);

    let _ = harness.control.shutdown_agent(watchdog_handle_id).await;
    let _ = harness.control.shutdown_agent(receiver_thread_id).await;
}

#[tokio::test]
async fn root_watchdog_helper_shutdown_without_send_input_wakes_owner() {
    let harness = AgentControlHarness::new().await;
    let (owner_thread_id, owner_thread) = harness.start_thread().await;
    let watchdog_handle_id = harness
        .control
        .spawn_agent_handle(
            harness.config.clone(),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog handle should spawn");
    let helper_thread_id = harness
        .control
        .spawn_agent(
            harness.config.clone(),
            text_input("check in"),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog helper should spawn");
    let removed = harness
        .control
        .register_watchdog(WatchdogRegistration {
            owner_thread_id,
            target_thread_id: watchdog_handle_id,
            child_depth: 1,
            interval_s: 1,
            prompt: "check in".to_string(),
            config: harness.config.clone(),
        })
        .await
        .expect("watchdog registration should succeed");
    assert_eq!(removed, Vec::<RemovedWatchdog>::new());
    harness
        .control
        .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
        .await;

    let _ = harness
        .control
        .shutdown_agent(helper_thread_id)
        .await
        .expect("helper shutdown should submit");
    timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                harness.control.get_status(helper_thread_id).await,
                AgentStatus::Shutdown | AgentStatus::NotFound
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("helper should reach shutdown");
    assert_eq!(
        wait_for_history_text(&owner_thread, "before calling send_input").await,
        true
    );
    harness
        .control
        .force_watchdog_due_for_tests(watchdog_handle_id)
        .await;
    harness.control.run_watchdogs_once_for_tests().await;
    tokio::task::yield_now().await;
    let owner_history = owner_thread
        .codex
        .session
        .clone_history()
        .await
        .raw_items()
        .to_vec();
    assert_eq!(
        count_history_text(&owner_history, "before calling send_input"),
        1
    );
}

#[tokio::test]
async fn root_watchdog_helper_shutdown_without_send_input_survives_handle_shutdown() {
    let harness = AgentControlHarness::new().await;
    let (owner_thread_id, owner_thread) = harness.start_thread().await;
    let watchdog_handle_id = harness
        .control
        .spawn_agent_handle(
            harness.config.clone(),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog handle should spawn");
    let helper_thread_id = harness
        .control
        .spawn_agent(
            harness.config.clone(),
            text_input("check in"),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog helper should spawn");
    let removed = harness
        .control
        .register_watchdog(WatchdogRegistration {
            owner_thread_id,
            target_thread_id: watchdog_handle_id,
            child_depth: 1,
            interval_s: 1,
            prompt: "check in".to_string(),
            config: harness.config.clone(),
        })
        .await
        .expect("watchdog registration should succeed");
    assert_eq!(removed, Vec::<RemovedWatchdog>::new());
    harness
        .control
        .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
        .await;

    let _ = harness
        .control
        .shutdown_agent(helper_thread_id)
        .await
        .expect("helper shutdown should submit");
    timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                harness.control.get_status(helper_thread_id).await,
                AgentStatus::Shutdown | AgentStatus::NotFound
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("helper should reach shutdown");
    tokio::task::yield_now().await;

    let _ = harness
        .control
        .shutdown_agent(watchdog_handle_id)
        .await
        .expect("watchdog handle shutdown should submit");

    assert_eq!(
        wait_for_history_text(&owner_thread, "before calling send_input").await,
        true
    );
}

#[tokio::test]
async fn root_watchdog_helper_completed_without_final_body_after_send_input_does_not_emit_false_fallback()
 {
    let harness = AgentControlHarness::new().await;
    let (owner_thread_id, owner_thread) = harness.start_thread().await;
    let owner_turn = owner_thread
        .codex
        .session
        .new_default_turn_with_sub_id("owner-watchdog-wait-turn".to_string())
        .await;
    owner_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&owner_turn),
            text_input("wait for watchdog"),
            WaitForCancellationTask,
        )
        .await;

    let watchdog_handle_id = harness
        .control
        .spawn_agent_handle(
            harness.config.clone(),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog handle should spawn");
    let helper_thread_id = harness
        .control
        .spawn_agent(
            harness.config.clone(),
            text_input("check in"),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog helper should spawn");
    let helper_thread = harness
        .manager
        .get_thread(helper_thread_id)
        .await
        .expect("watchdog helper thread should exist");
    let helper_turn = helper_thread
        .codex
        .session
        .new_default_turn_with_sub_id("watchdog-helper-turn".to_string())
        .await;
    helper_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&helper_turn),
            text_input("helper task"),
            WaitForCancellationTask,
        )
        .await;

    let removed = harness
        .control
        .register_watchdog(WatchdogRegistration {
            owner_thread_id,
            target_thread_id: watchdog_handle_id,
            child_depth: 1,
            interval_s: 1,
            prompt: "check in".to_string(),
            config: harness.config.clone(),
        })
        .await
        .expect("watchdog registration should succeed");
    assert_eq!(removed, Vec::<RemovedWatchdog>::new());
    harness
        .control
        .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
        .await;

    helper_thread
        .codex
        .session
        .mark_turn_used_agent_send_input();
    harness
        .control
        .send_agent_message(
            owner_thread_id,
            helper_thread_id,
            "watchdog progress".to_string(),
        )
        .await
        .expect("watchdog progress send_input should succeed");
    assert!(wait_for_raw_response_text(&owner_thread, "watchdog progress").await);

    helper_thread
        .codex
        .session
        .on_task_finished(Arc::clone(&helper_turn), None)
        .await;

    let duplicate_false_fallback =
        tokio::time::timeout(std::time::Duration::from_millis(300), async {
            loop {
                let event = owner_thread
                    .next_event()
                    .await
                    .expect("event should be available");
                if matches!(
                    event.msg,
                    EventMsg::RawResponseItem(RawResponseItemEvent { item })
                        if history_contains_text(std::slice::from_ref(&item), "without calling send_input")
                            || history_contains_text(std::slice::from_ref(&item), "before calling send_input")
                ) {
                    return true;
                }
            }
        })
        .await
        .is_ok();
    assert_eq!(duplicate_false_fallback, false);

    owner_thread
        .codex
        .session
        .abort_all_tasks(TurnAbortReason::Interrupted)
        .await;
}

#[tokio::test]
async fn send_agent_message_overflow_fails_open_with_immediate_inject() {
    const DEFERRED_COLLAB_ITEMS_MAX: usize = 8192;

    let harness = AgentControlHarness::new().await;
    let (receiver_thread_id, receiver_thread) = harness.start_thread().await;
    harness.arm_post_interrupt_hold(&receiver_thread).await;
    let sender_thread_id = ThreadId::new();

    let seeded_items = (0..DEFERRED_COLLAB_ITEMS_MAX)
        .map(|idx| ResponseInputItem::Message {
            role: "developer".to_string(),
            content: vec![ContentItem::InputText {
                text: format!("seed-{idx}"),
            }],
        })
        .collect::<Vec<_>>();
    receiver_thread
        .codex
        .session
        .enqueue_deferred_collab_items(seeded_items)
        .await
        .expect("seed deferred collab items");
    let (queued_before, _queued_before_bytes) =
        receiver_thread.codex.session.deferred_collab_stats().await;
    assert_eq!(queued_before, DEFERRED_COLLAB_ITEMS_MAX);

    let overflow_submission_id = harness
        .control
        .send_agent_message(receiver_thread_id, sender_thread_id, "overflow".to_string())
        .await
        .expect("overflow should fail open and inject");
    assert!(!overflow_submission_id.is_empty());

    let (queued_after, _queued_after_bytes) =
        receiver_thread.codex.session.deferred_collab_stats().await;
    assert_eq!(queued_after, DEFERRED_COLLAB_ITEMS_MAX);

    let injected_ops = harness
        .manager
        .captured_ops()
        .into_iter()
        .filter(|(thread_id, op)| {
            *thread_id == receiver_thread_id && matches!(op, Op::InjectResponseItems { .. })
        })
        .collect::<Vec<_>>();
    assert_eq!(injected_ops.len(), 1);

    let Op::InjectResponseItems { items } = &injected_ops[0].1 else {
        unreachable!("filtered to inject ops");
    };
    assert_eq!(items.len(), 1);
    assert_matches!(&items[0], ResponseInputItem::FunctionCallOutput { .. });

    let _ = harness.control.shutdown_agent(receiver_thread_id).await;
}

#[tokio::test]
async fn spawn_agent_creates_thread_and_sends_prompt() {
    let harness = AgentControlHarness::new().await;
    let thread_id = harness
        .control
        .spawn_agent(harness.config.clone(), text_input("spawned"), None)
        .await
        .expect("spawn_agent should succeed");
    let _thread = harness
        .manager
        .get_thread(thread_id)
        .await
        .expect("thread should be registered");
    let expected = (
        thread_id,
        Op::UserInput {
            items: vec![UserInput::Text {
                text: "spawned".to_string(),
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
        },
    );
    let captured = harness
        .manager
        .captured_ops()
        .into_iter()
        .find(|entry| *entry == expected);
    assert_eq!(captured, Some(expected));
}

#[tokio::test]
async fn fork_agent_falls_back_to_rollout_on_disk_when_parent_missing_in_memory() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    parent_thread
        .inject_user_message_without_turn("parent seed context".to_string())
        .await;
    parent_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    parent_thread.codex.session.flush_rollout().await;
    let _ = harness.manager.remove_thread(&parent_thread_id).await;

    let thread_id = harness
        .control
        .fork_agent(
            harness.config.clone(),
            text_input("forked"),
            parent_thread_id,
            usize::MAX,
            SessionSource::Exec,
        )
        .await
        .expect("fork_agent should fall back to rollout on disk");
    let thread = harness
        .manager
        .get_thread(thread_id)
        .await
        .expect("thread should be registered");
    let history = thread.codex.session.clone_history().await;
    assert!(history_contains_text(
        history.raw_items(),
        "parent seed context"
    ));

    let expected = (
        thread_id,
        Op::UserInput {
            items: vec![UserInput::Text {
                text: "forked".to_string(),
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
        },
    );
    let captured = harness
        .manager
        .captured_ops()
        .into_iter()
        .find(|entry| *entry == expected);
    assert_eq!(captured, Some(expected));
}

#[tokio::test]
async fn fork_agent_errors_when_parent_missing_from_memory_and_rollout() {
    let harness = AgentControlHarness::new().await;
    let parent_thread_id = ThreadId::new();

    let err = harness
        .control
        .fork_agent(
            harness.config.clone(),
            text_input("forked"),
            parent_thread_id,
            0,
            SessionSource::Exec,
        )
        .await
        .expect_err("fork_agent should fail when parent rollout is unavailable");
    assert_matches!(
        err,
        CodexErr::UnsupportedOperation(message)
            if message == format!("rollout history unavailable for thread {parent_thread_id}")
    );
}

#[tokio::test]
async fn spawn_agent_can_fork_parent_thread_history() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    parent_thread
        .inject_user_message_without_turn("parent seed context".to_string())
        .await;
    let turn_context = parent_thread.codex.session.new_default_turn().await;
    let parent_spawn_call_id = "spawn-call-history".to_string();
    let parent_spawn_call = ResponseItem::FunctionCall {
        id: None,
        name: "spawn_agent".to_string(),
        namespace: None,
        arguments: "{}".to_string(),
        call_id: parent_spawn_call_id.clone(),
    };
    parent_thread
        .codex
        .session
        .record_conversation_items(turn_context.as_ref(), &[parent_spawn_call])
        .await;
    parent_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    parent_thread.codex.session.flush_rollout().await;

    let child_thread_id = harness
        .control
        .spawn_agent_with_options(
            harness.config.clone(),
            text_input("child task"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
            SpawnAgentOptions {
                fork_parent_spawn_call_id: Some(parent_spawn_call_id),
            },
        )
        .await
        .expect("forked spawn should succeed");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    assert_ne!(child_thread_id, parent_thread_id);
    let history = child_thread.codex.session.clone_history().await;
    assert!(history_contains_text(
        history.raw_items(),
        "parent seed context"
    ));

    let expected = (
        child_thread_id,
        Op::UserInput {
            items: vec![UserInput::Text {
                text: "child task".to_string(),
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
        },
    );
    let captured = harness
        .manager
        .captured_ops()
        .into_iter()
        .find(|entry| *entry == expected);
    assert_eq!(captured, Some(expected));

    let _ = harness
        .control
        .shutdown_agent(child_thread_id)
        .await
        .expect("child shutdown should submit");
    let _ = parent_thread
        .submit(Op::Shutdown {})
        .await
        .expect("parent shutdown should submit");
}

#[tokio::test]
async fn spawn_agent_fork_injects_output_for_parent_spawn_call() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    let turn_context = parent_thread.codex.session.new_default_turn().await;
    let parent_spawn_call_id = "spawn-call-1".to_string();
    let parent_spawn_call = ResponseItem::FunctionCall {
        id: None,
        name: "spawn_agent".to_string(),
        namespace: None,
        arguments: "{}".to_string(),
        call_id: parent_spawn_call_id.clone(),
    };
    parent_thread
        .codex
        .session
        .record_conversation_items(turn_context.as_ref(), &[parent_spawn_call])
        .await;
    parent_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    parent_thread.codex.session.flush_rollout().await;

    let child_thread_id = harness
        .control
        .spawn_agent_with_options(
            harness.config.clone(),
            text_input("child task"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
            SpawnAgentOptions {
                fork_parent_spawn_call_id: Some(parent_spawn_call_id.clone()),
            },
        )
        .await
        .expect("forked spawn should succeed");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    let history = child_thread.codex.session.clone_history().await;
    let injected_output = history.raw_items().iter().find_map(|item| match item {
        ResponseItem::FunctionCallOutput { call_id, output }
            if call_id == &parent_spawn_call_id =>
        {
            Some(output)
        }
        _ => None,
    });
    let injected_output =
        injected_output.expect("forked child should contain synthetic tool output");
    assert_eq!(
        injected_output.text_content(),
        Some(FORKED_SPAWN_AGENT_OUTPUT_MESSAGE)
    );
    assert_eq!(injected_output.success, Some(true));

    let _ = harness
        .control
        .shutdown_agent(child_thread_id)
        .await
        .expect("child shutdown should submit");
    let _ = parent_thread
        .submit(Op::Shutdown {})
        .await
        .expect("parent shutdown should submit");
}

#[tokio::test]
async fn spawn_agent_fork_flushes_parent_rollout_before_loading_history() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    let turn_context = parent_thread.codex.session.new_default_turn().await;
    let parent_spawn_call_id = "spawn-call-unflushed".to_string();
    let parent_spawn_call = ResponseItem::FunctionCall {
        id: None,
        name: "spawn_agent".to_string(),
        namespace: None,
        arguments: "{}".to_string(),
        call_id: parent_spawn_call_id.clone(),
    };
    parent_thread
        .codex
        .session
        .record_conversation_items(turn_context.as_ref(), &[parent_spawn_call])
        .await;

    let child_thread_id = harness
        .control
        .spawn_agent_with_options(
            harness.config.clone(),
            text_input("child task"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
            SpawnAgentOptions {
                fork_parent_spawn_call_id: Some(parent_spawn_call_id.clone()),
            },
        )
        .await
        .expect("forked spawn should flush parent rollout before loading history");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    let history = child_thread.codex.session.clone_history().await;

    let mut parent_call_index = None;
    let mut injected_output_index = None;
    for (idx, item) in history.raw_items().iter().enumerate() {
        match item {
            ResponseItem::FunctionCall { call_id, .. } if call_id == &parent_spawn_call_id => {
                parent_call_index = Some(idx);
            }
            ResponseItem::FunctionCallOutput { call_id, .. }
                if call_id == &parent_spawn_call_id =>
            {
                injected_output_index = Some(idx);
            }
            _ => {}
        }
    }

    let parent_call_index =
        parent_call_index.expect("forked child should include the parent spawn_agent call");
    let injected_output_index = injected_output_index
        .expect("forked child should include synthetic output for the parent spawn_agent call");
    assert!(parent_call_index < injected_output_index);

    let _ = harness
        .control
        .shutdown_agent(child_thread_id)
        .await
        .expect("child shutdown should submit");
    let _ = parent_thread
        .submit(Op::Shutdown {})
        .await
        .expect("parent shutdown should submit");
}

#[tokio::test]
async fn spawn_agent_fork_persists_fork_reference_instead_of_parent_history() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    parent_thread
        .inject_user_message_without_turn("parent seed context".to_string())
        .await;
    let turn_context = parent_thread.codex.session.new_default_turn().await;
    let parent_spawn_call_id = "spawn-call-dedup".to_string();
    let parent_spawn_call = ResponseItem::FunctionCall {
        id: None,
        name: "spawn_agent".to_string(),
        namespace: None,
        arguments: "{}".to_string(),
        call_id: parent_spawn_call_id.clone(),
    };
    parent_thread
        .codex
        .session
        .record_conversation_items(turn_context.as_ref(), &[parent_spawn_call])
        .await;
    parent_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    parent_thread.codex.session.flush_rollout().await;
    let parent_rollout_path = parent_thread
        .rollout_path()
        .expect("parent rollout path should be available");

    let child_thread_id = harness
        .control
        .spawn_agent_with_options(
            harness.config.clone(),
            text_input("child task"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
            SpawnAgentOptions {
                fork_parent_spawn_call_id: Some(parent_spawn_call_id),
            },
        )
        .await
        .expect("forked spawn should succeed");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    let child_rollout_path = child_thread
        .rollout_path()
        .expect("child rollout path should be available");
    let InitialHistory::Resumed(resumed) =
        RolloutRecorder::get_rollout_history(child_rollout_path.as_path())
            .await
            .expect("child rollout should load")
    else {
        panic!("child rollout should include session metadata");
    };

    assert!(
        resumed.history.iter().any(|item| {
            matches!(
                item,
                RolloutItem::ForkReference(ForkReferenceItem {
                    rollout_path,
                    nth_user_message,
                }) if rollout_path == &parent_rollout_path && *nth_user_message == usize::MAX
            )
        }),
        "child rollout should persist a fork reference to the parent rollout"
    );

    let raw_response_items: Vec<ResponseItem> = resumed
        .history
        .iter()
        .filter_map(|item| match item {
            RolloutItem::ResponseItem(response_item) => Some(response_item.clone()),
            RolloutItem::SessionMeta(_)
            | RolloutItem::ForkReference(_)
            | RolloutItem::Compacted(_)
            | RolloutItem::TurnContext(_)
            | RolloutItem::EventMsg(_) => None,
        })
        .collect();
    assert!(
        !history_contains_text(&raw_response_items, "parent seed context"),
        "child rollout should not duplicate the parent's raw transcript"
    );

    let history = child_thread.codex.session.clone_history().await;
    assert!(history_contains_text(
        history.raw_items(),
        "parent seed context"
    ));

    let _ = harness
        .control
        .shutdown_agent(child_thread_id)
        .await
        .expect("child shutdown should submit");
    let _ = parent_thread
        .submit(Op::Shutdown {})
        .await
        .expect("parent shutdown should submit");
}

#[tokio::test]
async fn spawn_agent_respects_max_threads_limit() {
    let max_threads = 1usize;
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(max_threads as i64),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();

    let _ = manager
        .start_thread(config.clone())
        .await
        .expect("start thread");

    let first_agent_id = control
        .spawn_agent(config.clone(), text_input("hello"), None)
        .await
        .expect("spawn_agent should succeed");

    let err = control
        .spawn_agent(config, text_input("hello again"), None)
        .await
        .expect_err("spawn_agent should respect max threads");
    let CodexErr::AgentLimitReached {
        max_threads: seen_max_threads,
    } = err
    else {
        panic!("expected CodexErr::AgentLimitReached");
    };
    assert_eq!(seen_max_threads, max_threads);

    let _ = control
        .shutdown_agent(first_agent_id)
        .await
        .expect("shutdown agent");
}

#[tokio::test]
async fn spawn_agent_releases_slot_after_shutdown() {
    let max_threads = 1usize;
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(max_threads as i64),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();

    let first_agent_id = control
        .spawn_agent(config.clone(), text_input("hello"), None)
        .await
        .expect("spawn_agent should succeed");
    let _ = control
        .shutdown_agent(first_agent_id)
        .await
        .expect("shutdown agent");

    let second_agent_id = control
        .spawn_agent(config.clone(), text_input("hello again"), None)
        .await
        .expect("spawn_agent should succeed after shutdown");
    let _ = control
        .shutdown_agent(second_agent_id)
        .await
        .expect("shutdown agent");
}

#[tokio::test]
async fn spawn_agent_reconciles_stale_guard_slots() {
    let max_threads = 1usize;
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(max_threads as i64),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();

    let stale_agent_id = control
        .spawn_agent(config.clone(), text_input("stale"), None)
        .await
        .expect("spawn stale agent");
    let _ = manager.remove_thread(&stale_agent_id).await;

    let replacement_agent_id = control
        .spawn_agent(config.clone(), text_input("replacement"), None)
        .await
        .expect("spawn should reconcile stale guard slot");

    let _ = control
        .shutdown_agent(replacement_agent_id)
        .await
        .expect("shutdown replacement agent");
}

#[tokio::test]
async fn submit_initial_input_cleanup_releases_guard_slot_after_send_error() {
    let max_threads = 1usize;
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(max_threads as i64),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();

    let missing_thread_id = ThreadId::new();
    let reservation = control
        .guards
        .reserve_spawn_slot(Some(max_threads))
        .expect("reserve slot");
    reservation.commit(missing_thread_id);

    let state = control.upgrade().expect("thread manager state");
    let err = control
        .submit_initial_input_or_cleanup(&state, missing_thread_id, text_input("hello"))
        .await
        .expect_err("send_input should fail for missing thread");
    assert_matches!(err, CodexErr::ThreadNotFound(id) if id == missing_thread_id);

    let replacement = control
        .spawn_agent(config, text_input("replacement"), None)
        .await
        .expect("slot should be released after cleanup");
    let _ = control.shutdown_agent(replacement).await;
}

#[tokio::test]
async fn shutdown_agent_releases_descendant_slots() {
    let max_threads = 2usize;
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(max_threads as i64),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();

    let root_thread_id = ThreadId::new();
    let first_agent_id = control
        .spawn_agent(
            config.clone(),
            text_input("first"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: root_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
        )
        .await
        .expect("spawn first agent");
    let _second_agent_id = control
        .spawn_agent(
            config.clone(),
            text_input("second"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: first_agent_id,
                depth: 2,
                agent_nickname: None,
                agent_role: None,
            })),
        )
        .await
        .expect("spawn descendant agent");

    let _ = control
        .shutdown_agent(first_agent_id)
        .await
        .expect("shutdown should close subtree");

    let replacement_a = control
        .spawn_agent(config.clone(), text_input("replacement-a"), None)
        .await
        .expect("first replacement spawn should succeed");
    let replacement_b = control
        .spawn_agent(config.clone(), text_input("replacement-b"), None)
        .await
        .expect("second replacement spawn should succeed after subtree shutdown");

    let _ = control
        .shutdown_agent(replacement_a)
        .await
        .expect("shutdown replacement_a");
    let _ = control
        .shutdown_agent(replacement_b)
        .await
        .expect("shutdown replacement_b");
}

#[tokio::test]
async fn shutdown_watchdog_handle_releases_active_helper_slot() {
    let max_threads = 2usize;
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(max_threads as i64),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();
    let owner_thread = manager
        .start_thread(config.clone())
        .await
        .expect("start owner thread");
    let owner_thread_id = owner_thread.thread_id;

    let watchdog_handle_id = control
        .spawn_agent_handle(
            config.clone(),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: owner_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
        )
        .await
        .expect("spawn watchdog handle");
    control
        .register_watchdog(WatchdogRegistration {
            owner_thread_id,
            target_thread_id: watchdog_handle_id,
            child_depth: 1,
            interval_s: 30,
            prompt: "watchdog".to_string(),
            config: config.clone(),
        })
        .await
        .expect("register watchdog");

    let helper_id = control
        .spawn_agent(
            config.clone(),
            text_input("helper"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: owner_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
        )
        .await
        .expect("spawn helper");
    control
        .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_id)
        .await;

    let _ = control
        .shutdown_agent(watchdog_handle_id)
        .await
        .expect("shutdown watchdog handle");
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if matches!(control.get_status(helper_id).await, AgentStatus::NotFound) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("watchdog helper should be cleaned up before replacement spawns");

    let replacement_a = control
        .spawn_agent(config.clone(), text_input("replacement-a"), None)
        .await
        .expect("first replacement spawn should succeed");
    let replacement_b = control
        .spawn_agent(config.clone(), text_input("replacement-b"), None)
        .await
        .expect("second replacement spawn should succeed");

    let _ = control
        .shutdown_agent(replacement_a)
        .await
        .expect("shutdown replacement_a");
    let _ = control
        .shutdown_agent(replacement_b)
        .await
        .expect("shutdown replacement_b");
    let _ = control.shutdown_agent(owner_thread_id).await;
}

#[tokio::test]
async fn watchdog_run_once_cleans_up_final_helper_thread() {
    let (_home, config) = test_config().await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();

    let owner_thread = manager
        .start_thread(config.clone())
        .await
        .expect("start owner thread");
    let owner_thread_id = owner_thread.thread_id;
    let watchdog_handle_id = control
        .spawn_agent_handle(
            config.clone(),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: owner_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
        )
        .await
        .expect("spawn watchdog handle");
    control
        .register_watchdog(WatchdogRegistration {
            owner_thread_id,
            target_thread_id: watchdog_handle_id,
            child_depth: 1,
            interval_s: 30,
            prompt: "watchdog".to_string(),
            config: config.clone(),
        })
        .await
        .expect("register watchdog");

    let helper_id = control
        .spawn_agent_handle(
            config,
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: owner_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
        )
        .await
        .expect("spawn helper");
    control
        .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_id)
        .await;
    control
        .force_watchdog_due_for_tests(watchdog_handle_id)
        .await;
    let helper_thread = manager
        .get_thread(helper_id)
        .await
        .expect("helper thread should exist");
    let mut helper_status_rx = helper_thread.subscribe_status();
    let _ = helper_thread.submit(Op::Shutdown {}).await;
    if !crate::agent::status::is_final(&helper_status_rx.borrow()) {
        let _ = helper_status_rx.changed().await;
    }

    control.run_watchdogs_once_for_tests().await;

    let helper_after = manager.get_thread(helper_id).await;
    assert!(matches!(helper_after, Err(CodexErr::ThreadNotFound(id)) if id == helper_id));
    let _ = control.shutdown_agent(watchdog_handle_id).await;
    let _ = control.shutdown_agent(owner_thread_id).await;
}

#[tokio::test]
async fn watchdog_run_once_cleans_up_active_helper_when_owner_missing() {
    let max_threads = 2usize;
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(max_threads as i64),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();

    let owner_thread = manager
        .start_thread(config.clone())
        .await
        .expect("start owner thread");
    let owner_thread_id = owner_thread.thread_id;
    let watchdog_handle_id = control
        .spawn_agent_handle(
            config.clone(),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: owner_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
        )
        .await
        .expect("spawn watchdog handle");
    control
        .register_watchdog(WatchdogRegistration {
            owner_thread_id,
            target_thread_id: watchdog_handle_id,
            child_depth: 1,
            interval_s: 30,
            prompt: "watchdog".to_string(),
            config: config.clone(),
        })
        .await
        .expect("register watchdog");

    let helper_id = control
        .spawn_agent(
            config.clone(),
            text_input("helper"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: owner_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
        )
        .await
        .expect("spawn helper");
    control
        .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_id)
        .await;

    let _ = manager.remove_thread(&owner_thread_id).await;

    control.run_watchdogs_once_for_tests().await;

    let helper_after = manager.get_thread(helper_id).await;
    assert!(matches!(helper_after, Err(CodexErr::ThreadNotFound(id)) if id == helper_id));

    let replacement = control
        .spawn_agent(config, text_input("replacement"), None)
        .await
        .expect("replacement spawn should succeed after helper cleanup");
    let _ = control.shutdown_agent(replacement).await;
    let _ = control.shutdown_agent(watchdog_handle_id).await;
}

#[tokio::test]
async fn run_watchdogs_once_cleans_up_handle_and_helper_after_owner_shutdown() {
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(2),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();
    let owner_thread = manager
        .start_thread(config.clone())
        .await
        .expect("start owner thread");
    let owner_thread_id = owner_thread.thread_id;
    let watchdog_handle_id = control
        .spawn_agent_handle(config.clone(), Some(thread_spawn_source(owner_thread_id)))
        .await
        .expect("watchdog handle should spawn");
    let helper_thread_id = control
        .spawn_agent_handle(config.clone(), Some(thread_spawn_source(owner_thread_id)))
        .await
        .expect("watchdog helper should spawn");
    let removed = control
        .register_watchdog(WatchdogRegistration {
            owner_thread_id,
            target_thread_id: watchdog_handle_id,
            child_depth: 1,
            interval_s: 1,
            prompt: "check in".to_string(),
            config: config.clone(),
        })
        .await
        .expect("watchdog registration should succeed");
    assert_eq!(removed, Vec::<RemovedWatchdog>::new());
    control
        .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
        .await;
    assert_eq!(
        control
            .watchdog_owner_for_active_helper(helper_thread_id)
            .await,
        Some(owner_thread_id)
    );
    let tracked_before = control.guards.tracked_thread_ids();
    assert!(tracked_before.contains(&watchdog_handle_id));
    assert!(tracked_before.contains(&helper_thread_id));

    let mut owner_status_rx = control
        .subscribe_status(owner_thread_id)
        .await
        .expect("owner status subscription should succeed");
    let _ = owner_thread
        .thread
        .submit(Op::Shutdown {})
        .await
        .expect("owner shutdown should submit");
    timeout(Duration::from_secs(2), async {
        loop {
            if matches!(owner_status_rx.borrow().clone(), AgentStatus::Shutdown) {
                break;
            }
            owner_status_rx
                .changed()
                .await
                .expect("owner status should reach shutdown");
        }
    })
    .await
    .expect("owner should reach shutdown");

    control.run_watchdogs_once_for_tests().await;

    assert_eq!(
        control.get_status(watchdog_handle_id).await,
        AgentStatus::NotFound
    );
    assert_eq!(
        control.get_status(helper_thread_id).await,
        AgentStatus::NotFound
    );
    assert_eq!(
        control
            .watchdog_owner_for_active_helper(helper_thread_id)
            .await,
        None
    );
    let tracked_after = control.guards.tracked_thread_ids();
    assert!(!tracked_after.contains(&watchdog_handle_id));
    assert!(!tracked_after.contains(&helper_thread_id));

    let replacement_thread_id = control
        .spawn_agent_handle(config.clone(), None)
        .await
        .expect("cleanup should release watchdog helper slots");
    let ops = manager.captured_ops();
    assert!(
        ops.iter()
            .any(|(thread_id, op)| *thread_id == watchdog_handle_id && matches!(op, Op::Shutdown))
    );
    assert!(
        ops.iter()
            .any(|(thread_id, op)| *thread_id == helper_thread_id && matches!(op, Op::Shutdown))
    );

    let _ = control
        .shutdown_agent(replacement_thread_id)
        .await
        .expect("replacement thread shutdown should submit");
}

#[tokio::test]
async fn compact_parent_for_watchdog_helper_blocks_until_finish_hook() {
    let harness = AgentControlHarness::new().await;
    let (owner_thread_id, _owner_thread) = harness.start_thread().await;
    let watchdog_handle_id = harness
        .control
        .spawn_agent_handle(
            harness.config.clone(),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog handle should spawn");
    let helper_thread_id = harness
        .control
        .spawn_agent_handle(
            harness.config.clone(),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog helper should spawn");
    let removed = harness
        .control
        .register_watchdog(WatchdogRegistration {
            owner_thread_id,
            target_thread_id: watchdog_handle_id,
            child_depth: 1,
            interval_s: 1,
            prompt: "compact if needed".to_string(),
            config: harness.config.clone(),
        })
        .await
        .expect("watchdog registration should succeed");
    assert_eq!(removed, Vec::<RemovedWatchdog>::new());
    harness
        .control
        .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
        .await;

    let result = harness
        .control
        .compact_parent_for_watchdog_helper(helper_thread_id)
        .await
        .expect("first compact request should submit");
    let submission_id = match result {
        WatchdogParentCompactionResult::Submitted {
            parent_thread_id,
            submission_id,
        } => {
            assert_eq!(parent_thread_id, owner_thread_id);
            submission_id
        }
        other => panic!("expected submitted compaction result, got {other:?}"),
    };
    assert!(!submission_id.is_empty());
    assert_eq!(
        harness
            .manager
            .captured_ops()
            .iter()
            .filter(|(thread_id, op)| *thread_id == owner_thread_id && matches!(op, Op::Compact))
            .count(),
        1
    );

    let result = harness
        .control
        .compact_parent_for_watchdog_helper(helper_thread_id)
        .await
        .expect("duplicate compact should be blocked");
    assert_eq!(
        result,
        WatchdogParentCompactionResult::AlreadyInProgress {
            parent_thread_id: owner_thread_id
        }
    );

    harness
        .control
        .finish_watchdog_parent_compaction(owner_thread_id)
        .await;

    let result = harness
        .control
        .compact_parent_for_watchdog_helper(helper_thread_id)
        .await
        .expect("completed compact should unblock later requests");
    let resubmitted_id = match result {
        WatchdogParentCompactionResult::Submitted {
            parent_thread_id,
            submission_id,
        } => {
            assert_eq!(parent_thread_id, owner_thread_id);
            submission_id
        }
        other => panic!("expected submitted compaction result after finish, got {other:?}"),
    };
    assert!(!resubmitted_id.is_empty());
    assert_eq!(
        harness
            .manager
            .captured_ops()
            .iter()
            .filter(|(thread_id, op)| *thread_id == owner_thread_id && matches!(op, Op::Compact))
            .count(),
        2
    );

    let _ = harness
        .control
        .shutdown_agent(watchdog_handle_id)
        .await
        .expect("watchdog handle shutdown should submit");
    let _ = harness
        .control
        .shutdown_agent(owner_thread_id)
        .await
        .expect("owner shutdown should submit");
}

#[tokio::test]
async fn compact_parent_for_watchdog_helper_rechecks_parent_idleness_before_submitting() {
    let harness = AgentControlHarness::new().await;
    let (owner_thread_id, owner_thread) = harness.start_thread().await;
    let watchdog_handle_id = harness
        .control
        .spawn_agent_handle(
            harness.config.clone(),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog handle should spawn");
    let helper_thread_id = harness
        .control
        .spawn_agent_handle(
            harness.config.clone(),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog helper should spawn");
    let removed = harness
        .control
        .register_watchdog(WatchdogRegistration {
            owner_thread_id,
            target_thread_id: watchdog_handle_id,
            child_depth: 1,
            interval_s: 1,
            prompt: "compact if needed".to_string(),
            config: harness.config.clone(),
        })
        .await
        .expect("watchdog registration should succeed");
    assert_eq!(removed, Vec::<RemovedWatchdog>::new());
    harness
        .control
        .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
        .await;

    let owner_session = Arc::clone(&owner_thread.codex.session);
    let result = harness
        .control
        .compact_parent_for_watchdog_helper_inner(
            helper_thread_id,
            Some(Box::pin(async move {
                let mut active_turn = owner_session.active_turn.lock().await;
                *active_turn = Some(crate::state::ActiveTurn::default());
            })),
        )
        .await
        .expect("recheck should return a busy result");
    assert_eq!(
        result,
        WatchdogParentCompactionResult::ParentBusy {
            parent_thread_id: owner_thread_id
        }
    );
    assert_eq!(
        harness
            .manager
            .captured_ops()
            .iter()
            .filter(|(thread_id, op)| *thread_id == owner_thread_id && matches!(op, Op::Compact))
            .count(),
        0
    );

    {
        let mut active_turn = owner_thread.codex.session.active_turn.lock().await;
        *active_turn = None;
    }

    let result = harness
        .control
        .compact_parent_for_watchdog_helper(helper_thread_id)
        .await
        .expect("recheck cleanup should allow a later submit");
    let submission_id = match result {
        WatchdogParentCompactionResult::Submitted {
            parent_thread_id,
            submission_id,
        } => {
            assert_eq!(parent_thread_id, owner_thread_id);
            submission_id
        }
        other => {
            panic!("expected submitted compaction result after parent idles, got {other:?}")
        }
    };
    assert!(!submission_id.is_empty());
    assert_eq!(
        harness
            .manager
            .captured_ops()
            .iter()
            .filter(|(thread_id, op)| *thread_id == owner_thread_id && matches!(op, Op::Compact))
            .count(),
        1
    );

    let _ = harness
        .control
        .shutdown_agent(watchdog_handle_id)
        .await
        .expect("watchdog handle shutdown should submit");
    let _ = harness
        .control
        .shutdown_agent(owner_thread_id)
        .await
        .expect("owner shutdown should submit");
}

#[tokio::test]
async fn compact_handler_rechecks_watchdog_parent_idleness_at_execution_time() {
    let harness = AgentControlHarness::new().await;
    let (owner_thread_id, owner_thread) = harness.start_thread().await;

    harness
        .control
        .mark_watchdog_parent_compaction_in_progress_for_tests(owner_thread_id)
        .await;

    {
        let mut active_turn = owner_thread.codex.session.active_turn.lock().await;
        *active_turn = Some(crate::state::ActiveTurn::default());
    }

    owner_thread
        .submit(Op::Compact)
        .await
        .expect("compact submit should succeed");

    timeout(Duration::from_secs(2), async {
        loop {
            if !harness
                .control
                .watchdog_parent_compaction_in_progress(owner_thread_id)
                .await
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("watchdog compaction marker should be cleared");

    assert!(
        owner_thread.has_active_turn().await,
        "execution-time recheck must not replace an active parent turn"
    );

    {
        let mut active_turn = owner_thread.codex.session.active_turn.lock().await;
        *active_turn = None;
    }

    let _ = harness
        .control
        .shutdown_agent(owner_thread_id)
        .await
        .expect("owner shutdown should submit");
}

#[tokio::test]
async fn queued_watchdog_compact_skips_execution_when_parent_became_active() {
    let harness = AgentControlHarness::new().await;
    let (owner_thread_id, owner_thread) = harness.start_thread().await;
    let owner_control = owner_thread.codex.session.services.agent_control.clone();

    owner_control
        .mark_watchdog_parent_compaction_in_progress_for_tests(owner_thread_id)
        .await;

    {
        let mut active_turn = owner_thread.codex.session.active_turn.lock().await;
        *active_turn = Some(crate::state::ActiveTurn::default());
    }

    assert!(
        crate::codex::skip_watchdog_parent_compact_if_parent_busy(&owner_thread.codex.session)
            .await,
        "execution-time watchdog compaction recheck should skip when the parent is active"
    );

    let active_turn = owner_thread.codex.session.active_turn.lock().await;
    let active_turn = active_turn
        .as_ref()
        .expect("queued watchdog compact must not replace the active turn");
    assert!(
        active_turn.tasks.is_empty(),
        "queued watchdog compact should not spawn a replacement task"
    );
    assert!(
        !owner_control
            .watchdog_parent_compaction_in_progress(owner_thread_id)
            .await,
        "execution-time recheck should clear the in-progress marker"
    );

    let _ = owner_control
        .shutdown_agent(owner_thread_id)
        .await
        .expect("owner shutdown should submit");
}

#[tokio::test]
async fn compact_parent_for_watchdog_helper_unblocks_after_compact_abort_cleanup() {
    let harness = AgentControlHarness::new().await;
    let (owner_thread_id, owner_thread) = harness.start_thread().await;
    let owner_control = owner_thread.codex.session.services.agent_control.clone();
    let watchdog_handle_id = owner_control
        .spawn_agent_handle(
            harness.config.clone(),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog handle should spawn");
    let helper_thread_id = owner_control
        .spawn_agent_handle(
            harness.config.clone(),
            Some(thread_spawn_source(owner_thread_id)),
        )
        .await
        .expect("watchdog helper should spawn");
    let removed = owner_control
        .register_watchdog(WatchdogRegistration {
            owner_thread_id,
            target_thread_id: watchdog_handle_id,
            child_depth: 1,
            interval_s: 1,
            prompt: "compact if needed".to_string(),
            config: harness.config.clone(),
        })
        .await
        .expect("watchdog registration should succeed");
    assert_eq!(removed, Vec::<RemovedWatchdog>::new());
    owner_control
        .set_watchdog_active_helper_for_tests(watchdog_handle_id, helper_thread_id)
        .await;

    let result = owner_control
        .compact_parent_for_watchdog_helper(helper_thread_id)
        .await
        .expect("first compact request should submit");
    let submission_id = match result {
        WatchdogParentCompactionResult::Submitted {
            parent_thread_id,
            submission_id,
        } => {
            assert_eq!(parent_thread_id, owner_thread_id);
            submission_id
        }
        other => panic!("expected submitted compaction result, got {other:?}"),
    };
    assert!(!submission_id.is_empty());

    let result = owner_control
        .compact_parent_for_watchdog_helper(helper_thread_id)
        .await
        .expect("duplicate compact should be blocked");
    assert_eq!(
        result,
        WatchdogParentCompactionResult::AlreadyInProgress {
            parent_thread_id: owner_thread_id
        }
    );

    Arc::new(CompactTask)
        .abort(
            Arc::new(SessionTaskContext::new(Arc::clone(
                &owner_thread.codex.session,
            ))),
            owner_thread.codex.session.new_default_turn().await,
        )
        .await;

    let result = owner_control
        .compact_parent_for_watchdog_helper(helper_thread_id)
        .await
        .expect("abort cleanup should unblock later requests");
    let resubmitted_id = match result {
        WatchdogParentCompactionResult::Submitted {
            parent_thread_id,
            submission_id,
        } => {
            assert_eq!(parent_thread_id, owner_thread_id);
            submission_id
        }
        other => panic!("expected submitted compaction result after abort, got {other:?}"),
    };
    assert!(!resubmitted_id.is_empty());
}

#[tokio::test]
async fn list_agents_all_includes_tracked_not_found_threads() {
    let max_threads = 1usize;
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(max_threads as i64),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();

    let orphaned_agent_id = control
        .spawn_agent(config.clone(), text_input("orphan"), None)
        .await
        .expect("spawn orphaned agent");
    let _ = manager.remove_thread(&orphaned_agent_id).await;

    let listings = control
        .list_agents(ThreadId::new(), true, true)
        .await
        .expect("list all agents");
    let listing = listings
        .into_iter()
        .find(|entry| entry.thread_id == orphaned_agent_id)
        .expect("orphaned tracked agent should be listed");
    assert_eq!(listing.status, AgentStatus::NotFound);
    assert_eq!(listing.depth, 0);

    let _ = control.shutdown_agent(orphaned_agent_id).await;

    let replacement = control
        .spawn_agent(config, text_input("replacement"), None)
        .await
        .expect("replacement spawn should succeed after cleanup");
    let _ = control.shutdown_agent(replacement).await;
}

#[tokio::test]
async fn list_agents_all_excludes_live_manager_threads_when_untracked() {
    let (_home, config) = test_config().await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();

    let agent_id = control
        .spawn_agent(config, text_input("live thread"), None)
        .await
        .expect("spawn live thread");
    control.guards.release_spawned_thread(agent_id);

    let listings = control
        .list_agents(ThreadId::new(), true, true)
        .await
        .expect("list all agents");
    let listing = listings
        .into_iter()
        .find(|entry| entry.thread_id == agent_id);
    assert!(listing.is_none());

    let _ = control.shutdown_agent(agent_id).await;
}

#[tokio::test]
async fn spawn_agent_limit_shared_across_clones() {
    let max_threads = 1usize;
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(max_threads as i64),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();
    let cloned = control.clone();

    let first_agent_id = cloned
        .spawn_agent(config.clone(), text_input("hello"), None)
        .await
        .expect("spawn_agent should succeed");

    let err = control
        .spawn_agent(config, text_input("hello again"), None)
        .await
        .expect_err("spawn_agent should respect shared guard");
    let CodexErr::AgentLimitReached { max_threads } = err else {
        panic!("expected CodexErr::AgentLimitReached");
    };
    assert_eq!(max_threads, 1);

    let _ = control
        .shutdown_agent(first_agent_id)
        .await
        .expect("shutdown agent");
}

#[test]
fn build_agent_inbox_items_tool_role_emits_function_call_and_output() {
    let sender_thread_id = ThreadId::new();
    let message = "ping".to_string();

    let items = build_agent_inbox_items(
        CollabInboxDeliveryRole::Tool,
        sender_thread_id,
        Some("Atlas".to_string()),
        Some("worker".to_string()),
        message,
        false,
    )
    .expect("tool role should build inbox items");

    assert_eq!(items.len(), 1);

    let _call_id = match &items[0] {
        ResponseInputItem::FunctionCallOutput { call_id, output } => {
            let call_id = call_id.clone();
            let output_text = output
                .body
                .to_text()
                .expect("payload should convert to text");
            let payload: AgentInboxPayload =
                serde_json::from_str(&output_text).expect("payload should be valid json");
            assert!(payload.injected);
            assert_eq!(payload.kind, AGENT_INBOX_KIND);
            assert_eq!(payload.sender_thread_id, sender_thread_id);
            assert_eq!(payload.sender_agent_nickname.as_deref(), Some("Atlas"));
            assert_eq!(payload.sender_agent_role.as_deref(), Some("worker"));
            assert_eq!(payload.message, "ping");
            call_id
        }
        other => panic!("expected function call output item, got {other:?}"),
    };
}

#[tokio::test]
async fn resume_agent_respects_max_threads_limit() {
    let max_threads = 1usize;
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(max_threads as i64),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();

    let resumable_id = control
        .spawn_agent(config.clone(), text_input("hello"), None)
        .await
        .expect("spawn_agent should succeed");
    let resumable_thread = manager
        .get_thread(resumable_id)
        .await
        .expect("resumable thread should exist");
    resumable_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    resumable_thread.flush_rollout().await;
    let _ = control
        .shutdown_agent(resumable_id)
        .await
        .expect("shutdown resumable thread");

    let active_id = control
        .spawn_agent(config.clone(), text_input("occupy"), None)
        .await
        .expect("spawn_agent should succeed for active slot");

    let err = control
        .resume_agent_from_rollout(config, resumable_id, SessionSource::Exec)
        .await
        .expect_err("resume should respect max threads");
    let CodexErr::AgentLimitReached {
        max_threads: seen_max_threads,
    } = err
    else {
        panic!("expected CodexErr::AgentLimitReached");
    };
    assert_eq!(seen_max_threads, max_threads);

    let _ = control
        .shutdown_agent(active_id)
        .await
        .expect("shutdown active thread");
}

#[tokio::test]
async fn resume_agent_releases_slot_after_resume_failure() {
    let max_threads = 1usize;
    let (_home, config) = test_config_with_cli_overrides(vec![(
        "agents.max_threads".to_string(),
        TomlValue::Integer(max_threads as i64),
    )])
    .await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();

    let _ = control
        .resume_agent_from_rollout(config.clone(), ThreadId::new(), SessionSource::Exec)
        .await
        .expect_err("resume should fail for missing rollout");

    let resumed_id = control
        .spawn_agent(config, text_input("hello"), None)
        .await
        .expect("spawn should succeed after failed resume");
    let _ = control
        .shutdown_agent(resumed_id)
        .await
        .expect("shutdown resumed thread");
}

#[tokio::test]
async fn spawn_child_completion_notifies_parent_history() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;

    let child_thread_id = harness
        .control
        .spawn_agent(
            harness.config.clone(),
            text_input("hello child"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            })),
        )
        .await
        .expect("child spawn should succeed");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should exist");
    let _ = child_thread
        .submit(Op::Shutdown {})
        .await
        .expect("child shutdown should submit");

    assert_eq!(wait_for_subagent_notification(&parent_thread).await, true);
}

#[tokio::test]
async fn completion_watcher_forwards_terminal_message_live_to_active_root_parent() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    let parent_turn = parent_thread
        .codex
        .session
        .new_default_turn_with_sub_id("parent-wait-turn".to_string())
        .await;
    parent_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&parent_turn),
            text_input("wait for child"),
            WaitForCancellationTask,
        )
        .await;

    let (child_thread_id, child_thread) = harness.start_thread().await;
    let child_turn = child_thread
        .codex
        .session
        .new_default_turn_with_sub_id("child-final-turn".to_string())
        .await;
    child_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&child_turn),
            text_input("child work"),
            WaitForCancellationTask,
        )
        .await;

    harness.control.maybe_start_completion_watcher(
        child_thread_id,
        Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth: 1,
            agent_nickname: None,
            agent_role: Some("explorer".to_string()),
        })),
    );

    child_thread
        .codex
        .session
        .on_task_finished(
            Arc::clone(&child_turn),
            Some("final explorer result".to_string()),
        )
        .await;

    assert!(
        wait_for_raw_response_text(&parent_thread, "final explorer result").await,
        "expected live fallback Agent message while parent wait turn is still active"
    );

    parent_thread
        .codex
        .session
        .abort_all_tasks(TurnAbortReason::Interrupted)
        .await;
}

#[tokio::test]
async fn completion_watcher_forwards_terminal_message_live_after_parent_sampling_completed() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    let parent_turn = parent_thread
        .codex
        .session
        .new_default_turn_with_sub_id("parent-post-sampling-wait-turn".to_string())
        .await;
    parent_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&parent_turn),
            text_input("wait for child"),
            WaitForCancellationTask,
        )
        .await;

    let (child_thread_id, child_thread) = harness.start_thread().await;
    let child_turn = child_thread
        .codex
        .session
        .new_default_turn_with_sub_id("child-post-sampling-final-turn".to_string())
        .await;
    child_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&child_turn),
            text_input("child work"),
            WaitForCancellationTask,
        )
        .await;

    harness.control.maybe_start_completion_watcher(
        child_thread_id,
        Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth: 1,
            agent_nickname: None,
            agent_role: Some("explorer".to_string()),
        })),
    );

    parent_thread
        .codex
        .session
        .mark_active_turn_sampling_completed()
        .await;

    child_thread
        .codex
        .session
        .on_task_finished(
            Arc::clone(&child_turn),
            Some("late final explorer result".to_string()),
        )
        .await;

    assert!(
        wait_for_raw_response_text(&parent_thread, "late final explorer result").await,
        "expected live fallback Agent message even after parent sampling completed"
    );
    assert!(
        harness
            .manager
            .captured_ops()
            .into_iter()
            .all(|(thread_id, op)| {
                thread_id != parent_thread_id || !matches!(op, Op::InjectResponseItems { .. })
            }),
        "late completion fallback should not arm an empty boundary flush turn"
    );

    parent_thread
        .codex
        .session
        .abort_all_tasks(TurnAbortReason::Interrupted)
        .await;
}

#[tokio::test]
async fn completion_watcher_forwards_distinct_terminal_message_after_progress_send_input() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    let parent_turn = parent_thread
        .codex
        .session
        .new_default_turn_with_sub_id("parent-progress-wait-turn".to_string())
        .await;
    parent_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&parent_turn),
            text_input("wait for child"),
            WaitForCancellationTask,
        )
        .await;

    let (child_thread_id, child_thread) = harness.start_thread().await;
    let child_turn = child_thread
        .codex
        .session
        .new_default_turn_with_sub_id("child-progress-turn".to_string())
        .await;
    child_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&child_turn),
            text_input("child work"),
            WaitForCancellationTask,
        )
        .await;

    harness.control.maybe_start_completion_watcher(
        child_thread_id,
        Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth: 1,
            agent_nickname: None,
            agent_role: Some("explorer".to_string()),
        })),
    );

    child_thread.codex.session.mark_turn_used_agent_send_input();
    harness
        .control
        .send_agent_message(
            parent_thread_id,
            child_thread_id,
            "progress update".to_string(),
        )
        .await
        .expect("progress send_input should succeed");

    assert!(wait_for_raw_response_text(&parent_thread, "progress update").await);

    child_thread
        .codex
        .session
        .on_task_finished(
            Arc::clone(&child_turn),
            Some("final explorer result".to_string()),
        )
        .await;

    assert!(
        wait_for_raw_response_text(&parent_thread, "final explorer result").await,
        "expected final completion body to stay live even after earlier progress send_input"
    );

    parent_thread
        .codex
        .session
        .abort_all_tasks(TurnAbortReason::Interrupted)
        .await;
}

#[tokio::test]
async fn completion_watcher_forwards_distinct_terminal_message_after_progress_send_input_and_parent_sampling_completed()
 {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    let parent_turn = parent_thread
        .codex
        .session
        .new_default_turn_with_sub_id("parent-progress-post-sampling-wait-turn".to_string())
        .await;
    parent_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&parent_turn),
            text_input("wait for child"),
            WaitForCancellationTask,
        )
        .await;

    let (child_thread_id, child_thread) = harness.start_thread().await;
    let child_turn = child_thread
        .codex
        .session
        .new_default_turn_with_sub_id("child-progress-post-sampling-turn".to_string())
        .await;
    child_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&child_turn),
            text_input("child work"),
            WaitForCancellationTask,
        )
        .await;

    harness.control.maybe_start_completion_watcher(
        child_thread_id,
        Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth: 1,
            agent_nickname: None,
            agent_role: Some("explorer".to_string()),
        })),
    );

    child_thread.codex.session.mark_turn_used_agent_send_input();
    harness
        .control
        .send_agent_message(
            parent_thread_id,
            child_thread_id,
            "progress update".to_string(),
        )
        .await
        .expect("progress send_input should succeed");

    assert!(wait_for_raw_response_text(&parent_thread, "progress update").await);

    parent_thread
        .codex
        .session
        .mark_active_turn_sampling_completed()
        .await;

    child_thread
        .codex
        .session
        .on_task_finished(
            Arc::clone(&child_turn),
            Some("late final explorer result".to_string()),
        )
        .await;

    assert!(
        wait_for_raw_response_text(&parent_thread, "late final explorer result").await,
        "expected final completion body to stay live after sampling completed"
    );
    assert!(
        harness
            .manager
            .captured_ops()
            .into_iter()
            .all(|(thread_id, op)| {
                thread_id != parent_thread_id || !matches!(op, Op::InjectResponseItems { .. })
            }),
        "late completion fallback should not arm a follow-up inject turn"
    );

    parent_thread
        .codex
        .session
        .abort_all_tasks(TurnAbortReason::Interrupted)
        .await;
}

#[tokio::test]
async fn completion_watcher_forwards_terminal_message_when_same_text_progress_was_only_queued() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    let parent_turn = parent_thread
        .codex
        .session
        .new_default_turn_with_sub_id("parent-queued-same-text-wait-turn".to_string())
        .await;
    parent_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&parent_turn),
            text_input("wait for child"),
            WaitForCancellationTask,
        )
        .await;

    let (child_thread_id, child_thread) = harness.start_thread().await;
    let child_turn = child_thread
        .codex
        .session
        .new_default_turn_with_sub_id("child-queued-same-text-turn".to_string())
        .await;
    child_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&child_turn),
            text_input("child work"),
            WaitForCancellationTask,
        )
        .await;

    harness.control.maybe_start_completion_watcher(
        child_thread_id,
        Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth: 1,
            agent_nickname: None,
            agent_role: Some("explorer".to_string()),
        })),
    );

    child_thread.codex.session.mark_turn_used_agent_send_input();
    parent_thread
        .codex
        .session
        .mark_active_turn_sampling_completed()
        .await;
    harness
        .control
        .send_agent_message(
            parent_thread_id,
            child_thread_id,
            "same queued final message".to_string(),
        )
        .await
        .expect("queued progress send_input should succeed");

    assert!(
        !wait_for_raw_response_text_with_timeout(
            &parent_thread,
            "same queued final message",
            std::time::Duration::from_millis(300),
        )
        .await,
        "expected same-text progress to stay queued once parent sampling completed"
    );

    child_thread
        .codex
        .session
        .on_task_finished(
            Arc::clone(&child_turn),
            Some("same queued final message".to_string()),
        )
        .await;

    assert!(
        wait_for_raw_response_text(&parent_thread, "same queued final message").await,
        "expected queued same-text progress not to suppress the live completion body"
    );
    assert!(
        harness
            .manager
            .captured_ops()
            .into_iter()
            .all(|(thread_id, op)| {
                thread_id != parent_thread_id || !matches!(op, Op::InjectResponseItems { .. })
            }),
        "late completion fallback should not arm a follow-up inject turn"
    );

    parent_thread
        .codex
        .session
        .abort_all_tasks(TurnAbortReason::Interrupted)
        .await;
}

#[tokio::test]
async fn completion_watcher_reused_child_repeated_same_terminal_message_stays_live() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    let parent_turn = parent_thread
        .codex
        .session
        .new_default_turn_with_sub_id("parent-reused-child-wait-turn".to_string())
        .await;
    parent_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&parent_turn),
            text_input("wait for child"),
            WaitForCancellationTask,
        )
        .await;

    let (child_thread_id, child_thread) = harness.start_thread().await;
    harness.control.maybe_start_completion_watcher(
        child_thread_id,
        Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth: 1,
            agent_nickname: None,
            agent_role: Some("explorer".to_string()),
        })),
    );

    let first_child_turn = child_thread
        .codex
        .session
        .new_default_turn_with_sub_id("child-reused-first-turn".to_string())
        .await;
    child_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&first_child_turn),
            text_input("child work"),
            WaitForCancellationTask,
        )
        .await;
    child_thread
        .codex
        .session
        .on_task_finished(Arc::clone(&first_child_turn), Some("Done".to_string()))
        .await;
    assert!(wait_for_raw_response_text(&parent_thread, "Done").await);

    let second_child_turn = child_thread
        .codex
        .session
        .new_default_turn_with_sub_id("child-reused-second-turn".to_string())
        .await;
    child_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&second_child_turn),
            text_input("child work again"),
            WaitForCancellationTask,
        )
        .await;
    harness.control.maybe_start_completion_watcher(
        child_thread_id,
        Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth: 1,
            agent_nickname: None,
            agent_role: Some("explorer".to_string()),
        })),
    );
    child_thread
        .codex
        .session
        .on_task_finished(Arc::clone(&second_child_turn), Some("Done".to_string()))
        .await;

    assert!(
        wait_for_raw_response_text(&parent_thread, "Done").await,
        "expected reused child to surface repeated same-text completion on a later turn"
    );

    parent_thread
        .codex
        .session
        .abort_all_tasks(TurnAbortReason::Interrupted)
        .await;
}

#[tokio::test]
async fn completion_watcher_suppresses_duplicate_terminal_message_already_forwarded_live() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    let parent_turn = parent_thread
        .codex
        .session
        .new_default_turn_with_sub_id("parent-dedupe-wait-turn".to_string())
        .await;
    parent_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&parent_turn),
            text_input("wait for child"),
            WaitForCancellationTask,
        )
        .await;

    let (child_thread_id, child_thread) = harness.start_thread().await;
    let child_turn = child_thread
        .codex
        .session
        .new_default_turn_with_sub_id("child-dedupe-turn".to_string())
        .await;
    child_thread
        .codex
        .session
        .spawn_task(
            Arc::clone(&child_turn),
            text_input("child work"),
            WaitForCancellationTask,
        )
        .await;

    harness.control.maybe_start_completion_watcher(
        child_thread_id,
        Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth: 1,
            agent_nickname: None,
            agent_role: Some("explorer".to_string()),
        })),
    );

    child_thread.codex.session.mark_turn_used_agent_send_input();
    harness
        .control
        .send_agent_message(
            parent_thread_id,
            child_thread_id,
            "same final message".to_string(),
        )
        .await
        .expect("initial send_input should succeed");

    assert!(wait_for_raw_response_text(&parent_thread, "same final message").await);

    child_thread
        .codex
        .session
        .on_task_finished(
            Arc::clone(&child_turn),
            Some("same final message".to_string()),
        )
        .await;
    assert!(
        child_thread
            .codex
            .session
            .last_completed_turn_live_forwarded_agent_message("same final message")
            .await,
        "expected child dedupe state to survive task completion"
    );

    let duplicate = tokio::time::timeout(std::time::Duration::from_millis(300), async {
        loop {
            let event = parent_thread
                .next_event()
                .await
                .expect("event should be available");
            if matches!(
                event.msg,
                EventMsg::RawResponseItem(RawResponseItemEvent { item })
                    if history_contains_text(std::slice::from_ref(&item), "same final message")
            ) {
                return true;
            }
        }
    })
    .await
    .is_ok();
    assert_eq!(duplicate, false);

    parent_thread
        .codex
        .session
        .abort_all_tasks(TurnAbortReason::Interrupted)
        .await;
}

#[tokio::test]
async fn completion_watcher_notifies_parent_when_child_is_missing() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, parent_thread) = harness.start_thread().await;
    let child_thread_id = ThreadId::new();

    harness.control.maybe_start_completion_watcher(
        child_thread_id,
        Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth: 1,
            agent_nickname: None,
            agent_role: Some("explorer".to_string()),
        })),
    );

    assert_eq!(wait_for_subagent_notification(&parent_thread).await, true);

    let history_items = parent_thread
        .codex
        .session
        .clone_history()
        .await
        .raw_items()
        .to_vec();
    assert_eq!(
        history_contains_text(
            &history_items,
            &format!("\"agent_id\":\"{child_thread_id}\"")
        ),
        true
    );
    assert_eq!(
        history_contains_text(&history_items, "\"status\":\"not_found\""),
        true
    );
}

#[tokio::test]
async fn spawn_thread_subagent_gets_random_nickname_in_session_source() {
    let harness = AgentControlHarness::new().await;
    let (parent_thread_id, _parent_thread) = harness.start_thread().await;

    let child_thread_id = harness
        .control
        .spawn_agent(
            harness.config.clone(),
            text_input("hello child"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            })),
        )
        .await
        .expect("child spawn should succeed");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    let snapshot = child_thread.config_snapshot().await;

    let SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: seen_parent_thread_id,
        depth,
        agent_nickname,
        agent_role,
    }) = snapshot.session_source
    else {
        panic!("expected thread-spawn sub-agent source");
    };
    assert_eq!(seen_parent_thread_id, parent_thread_id);
    assert_eq!(depth, 1);
    assert!(agent_nickname.is_some());
    assert_eq!(agent_role, Some("explorer".to_string()));
}

#[tokio::test]
async fn spawn_agent_uses_parent_thread_auth_manager_when_parent_differs_from_manager_default() {
    let harness = AgentControlHarness::new().await;
    let parent_auth_manager =
        auth_manager_with_auth_file(&harness.config, &harness._home, "spawn-parent");
    let (parent_thread_id, parent_thread) = harness
        .start_thread_with_auth_manager(parent_auth_manager.clone())
        .await;

    let child_thread_id = harness
        .control
        .spawn_agent(
            harness.config.clone(),
            text_input("hello child"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            })),
        )
        .await
        .expect("child spawn should succeed");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    assert!(Arc::ptr_eq(
        &parent_thread.codex.session.services.auth_manager,
        &child_thread.codex.session.services.auth_manager,
    ));
    assert!(Arc::ptr_eq(
        &parent_auth_manager,
        &child_thread.codex.session.services.auth_manager,
    ));
}

#[tokio::test]
async fn spawn_agent_fork_from_parent_history_uses_parent_thread_auth_manager() {
    let harness = AgentControlHarness::new().await;
    let parent_auth_manager =
        auth_manager_with_auth_file(&harness.config, &harness._home, "history-parent");
    let (parent_thread_id, parent_thread) = harness
        .start_thread_with_auth_manager(parent_auth_manager.clone())
        .await;
    let turn_context = parent_thread.codex.session.new_default_turn().await;
    let parent_spawn_call_id = "spawn-call-auth".to_string();
    let parent_spawn_call = ResponseItem::FunctionCall {
        id: None,
        name: "spawn_agent".to_string(),
        namespace: None,
        arguments: "{}".to_string(),
        call_id: parent_spawn_call_id.clone(),
    };
    parent_thread
        .codex
        .session
        .record_conversation_items(turn_context.as_ref(), &[parent_spawn_call])
        .await;
    parent_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    parent_thread.codex.session.flush_rollout().await;

    let child_thread_id = harness
        .control
        .spawn_agent_with_options(
            harness.config.clone(),
            text_input("child task"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: None,
            })),
            SpawnAgentOptions {
                fork_parent_spawn_call_id: Some(parent_spawn_call_id),
            },
        )
        .await
        .expect("forked spawn should succeed");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    assert!(Arc::ptr_eq(
        &parent_thread.codex.session.services.auth_manager,
        &child_thread.codex.session.services.auth_manager,
    ));
    assert!(Arc::ptr_eq(
        &parent_auth_manager,
        &child_thread.codex.session.services.auth_manager,
    ));
}

#[tokio::test]
async fn fork_agent_uses_parent_thread_auth_manager_when_parent_differs_from_manager_default() {
    let harness = AgentControlHarness::new().await;
    let parent_auth_manager =
        auth_manager_with_auth_file(&harness.config, &harness._home, "fork-parent");
    let (parent_thread_id, parent_thread) = harness
        .start_thread_with_auth_manager(parent_auth_manager.clone())
        .await;
    parent_thread
        .inject_user_message_without_turn("parent seed context".to_string())
        .await;
    parent_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    parent_thread.codex.session.flush_rollout().await;

    let child_thread_id = harness
        .control
        .fork_agent(
            harness.config.clone(),
            text_input("forked"),
            parent_thread_id,
            usize::MAX,
            SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            }),
        )
        .await
        .expect("fork_agent should succeed");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    assert!(Arc::ptr_eq(
        &parent_thread.codex.session.services.auth_manager,
        &child_thread.codex.session.services.auth_manager,
    ));
    assert!(Arc::ptr_eq(
        &parent_auth_manager,
        &child_thread.codex.session.services.auth_manager,
    ));
}

#[tokio::test]
async fn fork_agent_uses_parent_thread_auth_file_from_rollout_when_parent_missing_in_memory() {
    let harness = AgentControlHarness::new().await;
    let parent_auth_manager =
        auth_manager_with_auth_file(&harness.config, &harness._home, "fork-parent-disk");
    let (parent_thread_id, parent_thread) = harness
        .start_thread_with_auth_manager(parent_auth_manager.clone())
        .await;
    parent_thread
        .inject_user_message_without_turn("parent seed context".to_string())
        .await;
    parent_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    parent_thread.codex.session.flush_rollout().await;
    let _ = harness.manager.remove_thread(&parent_thread_id).await;

    let child_thread_id = harness
        .control
        .fork_agent(
            harness.config.clone(),
            text_input("forked"),
            parent_thread_id,
            usize::MAX,
            SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            }),
        )
        .await
        .expect("fork_agent should succeed");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    assert_eq!(
        child_thread
            .codex
            .session
            .services
            .auth_manager
            .auth_file_override()
            .map(std::path::Path::to_path_buf),
        parent_auth_manager
            .auth_file_override()
            .map(std::path::Path::to_path_buf),
    );
}

#[tokio::test]
#[serial(codex_api_key)]
async fn fork_agent_uses_manager_default_auth_when_parent_rollout_has_no_auth_file() {
    let _guard = EnvVarGuard::set(crate::auth::CODEX_API_KEY_ENV_VAR, "sk-env-parent");
    let (home, config) = test_config().await;
    let default_auth_manager = AuthManager::shared(
        config.codex_home.clone(),
        true,
        AuthCredentialsStoreMode::File,
    );
    let manager = ThreadManager::new(
        &config,
        default_auth_manager.clone(),
        SessionSource::default(),
        crate::models_manager::collaboration_mode_presets::CollaborationModesConfig::default(),
    );
    let control = manager.agent_control();

    let parent_thread = manager
        .start_thread(config.clone())
        .await
        .expect("start parent thread");
    parent_thread
        .thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    parent_thread.thread.codex.session.flush_rollout().await;
    let _ = manager.remove_thread(&parent_thread.thread_id).await;

    let child_thread_id = control
        .fork_agent(
            config.clone(),
            text_input("forked"),
            parent_thread.thread_id,
            usize::MAX,
            SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: parent_thread.thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            }),
        )
        .await
        .expect("fork_agent should succeed");

    let child_thread = manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    assert!(Arc::ptr_eq(
        &default_auth_manager,
        &child_thread.codex.session.services.auth_manager,
    ));
    assert!(
        child_thread
            .codex
            .session
            .services
            .auth_manager
            .auth_cached()
            .is_some(),
        "child should retain env-backed auth through the default manager fallback"
    );

    let _ = control.shutdown_agent(child_thread_id).await;
    drop(home);
}

#[tokio::test]
async fn spawn_thread_subagent_uses_role_specific_nickname_candidates() {
    let mut harness = AgentControlHarness::new().await;
    harness.config.agent_roles.insert(
        "researcher".to_string(),
        AgentRoleConfig {
            description: Some("Research role".to_string()),
            model: None,
            config_file: None,
            spawn_mode: None,
            nickname_candidates: Some(vec!["Atlas".to_string()]),
        },
    );
    let (parent_thread_id, _parent_thread) = harness.start_thread().await;

    let child_thread_id = harness
        .control
        .spawn_agent(
            harness.config.clone(),
            text_input("hello child"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("researcher".to_string()),
            })),
        )
        .await
        .expect("child spawn should succeed");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    let snapshot = child_thread.config_snapshot().await;

    let SessionSource::SubAgent(SubAgentSource::ThreadSpawn { agent_nickname, .. }) =
        snapshot.session_source
    else {
        panic!("expected thread-spawn sub-agent source");
    };
    assert_eq!(agent_nickname, Some("Atlas".to_string()));
}

#[tokio::test]
async fn resume_thread_subagent_preserves_supplied_nickname_and_role() {
    let (_home, config) = test_config().await;
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();
    let harness = AgentControlHarness {
        _home,
        config,
        manager,
        control,
    };
    let (parent_thread_id, _parent_thread) = harness.start_thread().await;

    let child_thread_id = harness
        .control
        .spawn_agent(
            harness.config.clone(),
            text_input("hello child"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            })),
        )
        .await
        .expect("child spawn should succeed");

    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should exist");
    child_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    child_thread.flush_rollout().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let rollout_path = crate::find_thread_path_by_id_str(
                harness.config.codex_home.as_path(),
                &child_thread_id.to_string(),
            )
            .await
            .expect("rollout lookup should succeed");
            if rollout_path.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("child thread rollout should be discoverable before shutdown");
    let original_snapshot = child_thread.config_snapshot().await;
    let original_nickname = original_snapshot
        .session_source
        .get_nickname()
        .expect("spawned sub-agent should have a nickname");

    let _ = harness
        .control
        .shutdown_agent(child_thread_id)
        .await
        .expect("child shutdown should submit");

    let resumed_thread_id = harness
        .control
        .resume_agent_from_rollout(
            harness.config.clone(),
            child_thread_id,
            SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: Some(original_nickname.clone()),
                agent_role: Some("explorer".to_string()),
            }),
        )
        .await
        .expect("resume should succeed");
    assert_eq!(resumed_thread_id, child_thread_id);

    let resumed_snapshot = harness
        .manager
        .get_thread(resumed_thread_id)
        .await
        .expect("resumed child thread should exist")
        .config_snapshot()
        .await;
    let SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: resumed_parent_thread_id,
        depth: resumed_depth,
        agent_nickname,
        agent_role,
    }) = resumed_snapshot.session_source
    else {
        panic!("expected resumed thread-spawn sub-agent source");
    };
    assert_eq!(resumed_parent_thread_id, parent_thread_id);
    assert_eq!(resumed_depth, 1);
    assert_eq!(agent_nickname, Some(original_nickname));
    assert_eq!(agent_role, Some("explorer".to_string()));
}

#[tokio::test]
async fn resume_agent_uses_parent_thread_auth_manager_when_parent_differs_from_manager_default() {
    let harness = AgentControlHarness::new().await;
    let parent_auth_manager =
        auth_manager_with_auth_file(&harness.config, &harness._home, "resume-parent");
    let (parent_thread_id, parent_thread) = harness
        .start_thread_with_auth_manager(parent_auth_manager.clone())
        .await;
    let child_thread_id = harness
        .control
        .spawn_agent(
            harness.config.clone(),
            text_input("hello child"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            })),
        )
        .await
        .expect("child spawn should succeed");
    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should exist");
    child_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    child_thread.flush_rollout().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let rollout_path = crate::find_thread_path_by_id_str(
                harness.config.codex_home.as_path(),
                &child_thread_id.to_string(),
            )
            .await
            .expect("rollout lookup should succeed");
            if rollout_path.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("resumable thread rollout should be discoverable before shutdown");
    let _ = harness
        .control
        .shutdown_agent(child_thread_id)
        .await
        .expect("shutdown child thread");

    let resumed_thread_id = harness
        .control
        .resume_agent_from_rollout(
            harness.config.clone(),
            child_thread_id,
            SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            }),
        )
        .await
        .expect("resume should succeed");

    let resumed_thread = harness
        .manager
        .get_thread(resumed_thread_id)
        .await
        .expect("resumed child thread should exist");
    assert!(Arc::ptr_eq(
        &parent_thread.codex.session.services.auth_manager,
        &resumed_thread.codex.session.services.auth_manager,
    ));
    assert!(Arc::ptr_eq(
        &parent_auth_manager,
        &resumed_thread.codex.session.services.auth_manager,
    ));
}

#[tokio::test]
async fn resume_agent_uses_parent_thread_auth_file_from_rollout_when_parent_missing_in_memory() {
    let harness = AgentControlHarness::new().await;
    let parent_auth_manager =
        auth_manager_with_auth_file(&harness.config, &harness._home, "resume-parent-disk");
    let (parent_thread_id, parent_thread) = harness
        .start_thread_with_auth_manager(parent_auth_manager.clone())
        .await;
    parent_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    parent_thread.codex.session.flush_rollout().await;
    let child_thread_id = harness
        .control
        .spawn_agent(
            harness.config.clone(),
            text_input("hello child"),
            Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            })),
        )
        .await
        .expect("child spawn should succeed");
    let child_thread = harness
        .manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should exist");
    child_thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    child_thread.flush_rollout().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let rollout_path = crate::find_thread_path_by_id_str(
                harness.config.codex_home.as_path(),
                &child_thread_id.to_string(),
            )
            .await
            .expect("rollout lookup should succeed");
            if rollout_path.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("resumable thread rollout should be discoverable before shutdown");
    let _ = harness
        .control
        .shutdown_agent(child_thread_id)
        .await
        .expect("shutdown child thread");
    let _ = harness.manager.remove_thread(&parent_thread_id).await;

    let resumed_thread_id = harness
        .control
        .resume_agent_from_rollout(
            harness.config.clone(),
            child_thread_id,
            SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            }),
        )
        .await
        .expect("resume should succeed");

    let resumed_thread = harness
        .manager
        .get_thread(resumed_thread_id)
        .await
        .expect("resumed child thread should exist");
    assert_eq!(
        resumed_thread
            .codex
            .session
            .services
            .auth_manager
            .auth_file_override()
            .map(std::path::Path::to_path_buf),
        parent_auth_manager
            .auth_file_override()
            .map(std::path::Path::to_path_buf),
    );
}

#[tokio::test]
async fn fork_agent_rebases_relative_parent_auth_file_to_parent_session_cwd() {
    let (_home, mut config) = test_config().await;
    let parent_cwd = tempfile::tempdir().expect("parent cwd");
    config.cwd = parent_cwd.path().to_path_buf();
    let relative_auth_file = PathBuf::from("relative/auth.json");
    let parent_auth_manager = AuthManager::shared_with_auth_file(
        config.codex_home.clone(),
        false,
        AuthCredentialsStoreMode::File,
        Some(relative_auth_file.clone()),
    )
    .expect("relative auth manager");
    let manager = ThreadManager::with_models_provider_and_home_for_tests(
        CodexAuth::from_api_key("dummy"),
        config.model_provider.clone(),
        config.codex_home.clone(),
    );
    let control = manager.agent_control();
    let parent_thread = manager
        .resume_thread_with_history(
            config.clone(),
            InitialHistory::New,
            parent_auth_manager,
            false,
            None,
        )
        .await
        .expect("start parent thread");
    parent_thread
        .thread
        .codex
        .session
        .ensure_rollout_materialized()
        .await;
    parent_thread.thread.codex.session.flush_rollout().await;
    let _ = manager.remove_thread(&parent_thread.thread_id).await;

    let child_thread_id = control
        .fork_agent(
            config.clone(),
            text_input("forked"),
            parent_thread.thread_id,
            usize::MAX,
            SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: parent_thread.thread_id,
                depth: 1,
                agent_nickname: None,
                agent_role: Some("explorer".to_string()),
            }),
        )
        .await
        .expect("fork_agent should succeed");

    let child_thread = manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should be registered");
    assert_eq!(
        child_thread
            .codex
            .session
            .services
            .auth_manager
            .auth_file_override()
            .map(std::path::Path::to_path_buf),
        Some(parent_cwd.path().join(relative_auth_file)),
    );

    let _ = control.shutdown_agent(child_thread_id).await;
}

#[test]
fn build_agent_inbox_items_tool_role_prepends_empty_user_message_when_requested() {
    let sender_thread_id = ThreadId::new();
    let message = "ping".to_string();

    let items = build_agent_inbox_items(
        CollabInboxDeliveryRole::Tool,
        sender_thread_id,
        None,
        None,
        message,
        true,
    )
    .expect("tool role should build inbox items");

    assert_eq!(items.len(), 2);
    match &items[0] {
        ResponseInputItem::Message { role, content } => {
            assert_eq!(role, "user");
            assert_eq!(
                content,
                &vec![ContentItem::InputText {
                    text: String::new()
                }]
            );
        }
        other => panic!("expected prepended user message, got {other:?}"),
    }
    assert_matches!(&items[1], ResponseInputItem::FunctionCallOutput { .. });
}

#[test]
fn build_agent_inbox_items_assistant_role_prepends_empty_user_message_when_requested() {
    let sender_thread_id = ThreadId::new();
    let message = "hello".to_string();

    let items = build_agent_inbox_items(
        CollabInboxDeliveryRole::Assistant,
        sender_thread_id,
        None,
        None,
        message,
        true,
    )
    .expect("assistant role should build inbox items");

    assert_eq!(items.len(), 2);
    match &items[0] {
        ResponseInputItem::Message { role, content } => {
            assert_eq!(role, "user");
            assert_eq!(
                content,
                &vec![ContentItem::InputText {
                    text: String::new()
                }]
            );
        }
        other => panic!("expected prepended user message, got {other:?}"),
    }
    match &items[1] {
        ResponseInputItem::Message { role, .. } => assert_eq!(role, "assistant"),
        other => panic!("expected assistant message, got {other:?}"),
    }
}

#[test]
fn build_agent_inbox_items_developer_role_prepends_empty_user_message_when_requested() {
    let sender_thread_id = ThreadId::new();
    let message = "hello".to_string();

    let items = build_agent_inbox_items(
        CollabInboxDeliveryRole::Developer,
        sender_thread_id,
        None,
        None,
        message,
        true,
    )
    .expect("developer role should build inbox items");

    assert_eq!(items.len(), 2);
    match &items[0] {
        ResponseInputItem::Message { role, content } => {
            assert_eq!(role, "user");
            assert_eq!(
                content,
                &vec![ContentItem::InputText {
                    text: String::new()
                }]
            );
        }
        other => panic!("expected prepended user message, got {other:?}"),
    }
    match &items[1] {
        ResponseInputItem::Message { role, .. } => assert_eq!(role, "developer"),
        other => panic!("expected developer message, got {other:?}"),
    }
}
