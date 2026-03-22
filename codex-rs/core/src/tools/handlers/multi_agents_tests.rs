use super::*;
use crate::AuthManager;
use crate::CodexAuth;
use crate::ThreadManager;
use crate::built_in_model_providers;
use crate::codex::make_session_and_context;
use crate::codex::make_session_and_context_with_rx;
use crate::config::AgentRoleConfig;
use crate::config::AgentRoleSpawnMode;
use crate::config::types::ShellEnvironmentPolicy;
use crate::function_tool::FunctionCallError;
use crate::protocol::AskForApproval;
use crate::protocol::ErrorEvent;
use crate::protocol::Event;
use crate::protocol::EventMsg;
use crate::protocol::FileSystemSandboxPolicy;
use crate::protocol::NetworkSandboxPolicy;
use crate::protocol::Op;
use crate::protocol::SandboxPolicy;
use crate::protocol::SessionSource;
use crate::protocol::SubAgentSource;
use crate::tools::context::ToolOutput;
use crate::turn_diff_tracker::TurnDiffTracker;
use codex_features::Feature;
use codex_protocol::ThreadId;
use codex_protocol::models::ContentItem;
use codex_protocol::models::FunctionCallOutputBody;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::protocol::AgentMessageEvent;
use codex_protocol::protocol::AgentReasoningDeltaEvent;
use codex_protocol::protocol::AgentSpawnMode;
use codex_protocol::protocol::InitialHistory;
use codex_protocol::protocol::RolloutItem;
use codex_protocol::protocol::TurnContextItem;
use pretty_assertions::assert_eq;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::watch;
use tokio::time::timeout;

fn invocation(
    session: Arc<crate::codex::Session>,
    turn: Arc<TurnContext>,
    tool_name: &str,
    payload: ToolPayload,
) -> ToolInvocation {
    ToolInvocation {
        session,
        turn,
        tracker: Arc::new(Mutex::new(TurnDiffTracker::default())),
        call_id: "call-1".to_string(),
        tool_name: tool_name.to_string(),
        tool_namespace: None,
        payload,
    }
}

fn function_payload(args: serde_json::Value) -> ToolPayload {
    ToolPayload::Function {
        arguments: args.to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct SpawnAgentResultForTest {
    agent_id: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct ListAgentsResultForTest {
    agents: Vec<ListAgentEntryForTest>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct ListAgentEntryForTest {
    id: String,
    parent_id: String,
    status: AgentStatus,
    depth: usize,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct PeekAgentsResultForTest {
    agents: Vec<PeekAgentEntryForTest>,
    next_cursor: u64,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct PeekAgentEntryForTest {
    id: String,
    parent_id: String,
    status: AgentStatus,
    depth: usize,
    cursor: u64,
    prompt_preview: Option<String>,
    reasoning_summary: Option<String>,
    latest_message_preview: Option<String>,
    terminal_summary: Option<String>,
}

async fn spawn_watchdog_for_test(
    session: Arc<crate::codex::Session>,
    turn: Arc<TurnContext>,
) -> ThreadId {
    let invocation = invocation(
        session,
        turn,
        "spawn_agent",
        function_payload(json!({
            "message": "watchdog check-in",
            "spawn_mode": "watchdog"
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("spawn_agent should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResultForTest =
        serde_json::from_str(&content).expect("spawn result should be json");
    agent_id(&result.agent_id).expect("spawn result should contain a valid agent id")
}

fn thread_manager() -> ThreadManager {
    ThreadManager::with_models_provider_for_tests(
        CodexAuth::from_api_key("dummy"),
        built_in_model_providers(/* openai_base_url */ None)["openai"].clone(),
    )
}

async fn visible_models(session: &Session) -> Vec<ModelPreset> {
    session
        .services
        .models_manager
        .list_models(crate::models_manager::manager::RefreshStrategy::Offline)
        .await
        .into_iter()
        .filter(|preset| preset.show_in_picker)
        .collect()
}

fn expect_text_output<T>(output: T) -> (String, Option<bool>)
where
    T: ToolOutput,
{
    let response = output.to_response_item(
        "call-1",
        &ToolPayload::Function {
            arguments: "{}".to_string(),
        },
    );
    match response {
        ResponseInputItem::FunctionCallOutput { output, .. }
        | ResponseInputItem::CustomToolCallOutput { output, .. } => {
            let content = match output.body {
                FunctionCallOutputBody::Text(text) => text,
                FunctionCallOutputBody::ContentItems(items) => {
                    codex_protocol::models::function_call_output_content_items_to_text(&items)
                        .unwrap_or_default()
                }
            };
            (content, output.success)
        }
        other => panic!("expected function output, got {other:?}"),
    }
}

#[tokio::test]
async fn handler_rejects_non_function_payloads() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        ToolPayload::Custom {
            input: "hello".to_string(),
        },
    );
    let Err(err) = SpawnAgentHandler.handle(invocation).await else {
        panic!("payload should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel(
            "multi-agent handler received unsupported payload".to_string()
        )
    );
}

#[tokio::test]
async fn handler_rejects_unknown_tool() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "unknown_tool",
        function_payload(json!({})),
    );
    let Err(err) = MultiAgentHandler.handle(invocation).await else {
        panic!("tool should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel("unsupported multi-agent tool unknown_tool".to_string())
    );
}

#[tokio::test]
async fn spawn_agent_rejects_empty_message() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({"message": "   "})),
    );
    let Err(err) = SpawnAgentHandler.handle(invocation).await else {
        panic!("empty message should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel("Empty message can't be sent to an agent".to_string())
    );
}

#[tokio::test]
async fn spawn_agent_rejects_when_message_and_items_are_both_set() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "hello",
            "items": [{"type": "mention", "name": "drive", "path": "app://drive"}]
        })),
    );
    let Err(err) = SpawnAgentHandler.handle(invocation).await else {
        panic!("message+items should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel(
            "Provide either message or items, but not both".to_string()
        )
    );
}

#[tokio::test]
async fn spawn_agent_uses_explorer_role_and_preserves_runtime_approval_policy() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
        nickname: Option<String>,
    }

    let (mut session, mut turn, rx) = make_session_and_context_with_rx().await;
    let manager = thread_manager();
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .services
        .agent_control = manager.agent_control();
    let mut config = (*turn.config).clone();
    let provider = built_in_model_providers(/* openai_base_url */ None)["ollama"].clone();
    config.model_provider_id = "ollama".to_string();
    config.model_provider = provider.clone();
    config
        .permissions
        .approval_policy
        .set(AskForApproval::OnRequest)
        .expect("approval policy should be set");
    Arc::get_mut(&mut turn).expect("no extra turn refs").config = Arc::new(config);
    Arc::get_mut(&mut turn)
        .expect("no extra turn refs")
        .approval_policy
        .set(AskForApproval::OnRequest)
        .expect("approval policy should be set");
    let expected_model = turn.model_info.slug.clone();
    let expected_reasoning_effort = turn.reasoning_effort.unwrap_or_default();

    let invocation = invocation(
        session.clone(),
        turn.clone(),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "agent_type": "explorer"
        })),
    );
    let output = SpawnAgentHandler
        .handle(invocation)
        .await
        .expect("spawn_agent should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
    assert!(
        result
            .nickname
            .as_deref()
            .is_some_and(|nickname| !nickname.is_empty())
    );
    let snapshot = manager
        .get_thread(agent_id)
        .await
        .expect("spawned agent thread should exist")
        .config_snapshot()
        .await;
    assert_eq!(snapshot.model, expected_model);
    let spawn_event = timeout(Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.expect("collab event");
            if let EventMsg::CollabAgentSpawnEnd(event) = event.msg {
                break event;
            }
        }
    })
    .await
    .expect("spawn end event should arrive");
    assert_eq!(spawn_event.model, expected_model);
    assert_eq!(spawn_event.reasoning_effort, expected_reasoning_effort);
    assert_eq!(snapshot.approval_policy, AskForApproval::OnRequest);
}

#[tokio::test]
async fn spawn_agent_errors_when_manager_dropped() {
    let (mut session, turn, rx) = make_session_and_context_with_rx().await;
    let manager = thread_manager();
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .services
        .models_manager = manager.get_models_manager();
    let selected_model = visible_models(&session)
        .await
        .into_iter()
        .find(|preset| !preset.supported_reasoning_efforts.is_empty())
        .expect("expected visible model with reasoning support");
    let selected_effort = selected_model
        .supported_reasoning_efforts
        .first()
        .map(|effort| effort.effort)
        .expect("expected reasoning effort");
    let invocation = invocation(
        session.clone(),
        turn.clone(),
        "spawn_agent",
        function_payload(json!({
            "message": "hello",
            "model": selected_model.model,
            "reasoning_effort": selected_effort,
        })),
    );
    let Err(err) = SpawnAgentHandler.handle(invocation).await else {
        panic!("spawn should fail without a manager");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel("multi-agent manager unavailable".to_string())
    );
    let spawn_event = timeout(Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.expect("collab event");
            if let EventMsg::CollabAgentSpawnEnd(event) = event.msg {
                break event;
            }
        }
    })
    .await
    .expect("spawn end event should arrive");
    assert_eq!(spawn_event.new_thread_id, None);
    assert_eq!(spawn_event.status, AgentStatus::NotFound);
    assert_eq!(spawn_event.model, selected_model.model);
    assert_eq!(spawn_event.reasoning_effort, selected_effort);
}

#[tokio::test]
async fn spawn_agent_reapplies_runtime_sandbox_after_role_config() {
    fn pick_allowed_sandbox_policy(
        constraint: &crate::config::Constrained<SandboxPolicy>,
        base: SandboxPolicy,
    ) -> SandboxPolicy {
        let candidates = [
            SandboxPolicy::DangerFullAccess,
            SandboxPolicy::new_workspace_write_policy(),
            SandboxPolicy::new_read_only_policy(),
        ];
        candidates
            .into_iter()
            .find(|candidate| *candidate != base && constraint.can_set(candidate).is_ok())
            .unwrap_or(base)
    }

    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
        nickname: Option<String>,
    }

    let (mut session, mut turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let expected_sandbox = pick_allowed_sandbox_policy(
        &turn.config.permissions.sandbox_policy,
        turn.config.permissions.sandbox_policy.get().clone(),
    );
    let expected_file_system_sandbox_policy =
        FileSystemSandboxPolicy::from_legacy_sandbox_policy(&expected_sandbox, &turn.cwd);
    let expected_network_sandbox_policy = NetworkSandboxPolicy::from(&expected_sandbox);
    turn.approval_policy
        .set(AskForApproval::OnRequest)
        .expect("approval policy should be set");
    turn.sandbox_policy
        .set(expected_sandbox.clone())
        .expect("sandbox policy should be set");
    turn.file_system_sandbox_policy = expected_file_system_sandbox_policy.clone();
    turn.network_sandbox_policy = expected_network_sandbox_policy;
    assert_ne!(
        expected_sandbox,
        turn.config.permissions.sandbox_policy.get().clone(),
        "test requires a runtime sandbox override that differs from base config"
    );

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "await this command",
            "agent_type": "awaiter"
        })),
    );
    let output = SpawnAgentHandler
        .handle(invocation)
        .await
        .expect("spawn_agent should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
    assert!(
        result
            .nickname
            .as_deref()
            .is_some_and(|nickname| !nickname.is_empty())
    );

    let snapshot = manager
        .get_thread(agent_id)
        .await
        .expect("spawned agent thread should exist")
        .config_snapshot()
        .await;
    assert_eq!(snapshot.sandbox_policy, expected_sandbox);
    assert_eq!(snapshot.approval_policy, AskForApproval::OnRequest);
    let child_thread = manager
        .get_thread(agent_id)
        .await
        .expect("spawned agent thread should exist");
    let child_turn = child_thread.codex.session.new_default_turn().await;
    assert_eq!(
        child_turn.file_system_sandbox_policy,
        expected_file_system_sandbox_policy
    );
    assert_eq!(
        child_turn.network_sandbox_policy,
        expected_network_sandbox_policy
    );
}

#[tokio::test]
async fn spawn_agent_rejects_when_depth_limit_exceeded() {
    let (mut session, mut turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let max_depth = turn.config.agent_max_depth;

    turn.session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: session.conversation_id,
        depth: max_depth,
        agent_path: None,
        agent_nickname: None,
        agent_role: None,
    });

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "hello",
            "spawn_mode": "spawn"
        })),
    );
    let Err(err) = SpawnAgentHandler.handle(invocation).await else {
        panic!("spawn should fail when depth limit exceeded");
    };
    let FunctionCallError::RespondToModel(message) = err else {
        panic!("expected respond-to-model error");
    };
    assert!(message.contains("depth limit reached"));
}

#[tokio::test]
async fn spawn_agent_hides_multi_agent_tools_at_configured_max_depth() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
        nickname: Option<String>,
    }

    let (mut session, mut turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let mut config = (*turn.config).clone();
    config
        .features
        .enable(Feature::Collab)
        .expect("collab feature enable");
    config
        .features
        .enable(Feature::SpawnCsv)
        .expect("spawn csv feature enable");
    turn.config = Arc::new(config);
    let current_max_depth = turn.config.agent_max_depth;

    let mut config = (*turn.config).clone();
    config.agent_max_depth = current_max_depth + 1;
    turn.config = Arc::new(config);
    turn.session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: session.conversation_id,
        depth: current_max_depth,
        agent_path: None,
        agent_nickname: None,
        agent_role: None,
    });

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({"message": "hello"})),
    );
    let output = SpawnAgentHandler
        .handle(invocation)
        .await
        .expect("spawn should succeed within configured depth");
    let (content, success) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    assert!(!result.agent_id.is_empty());
    assert!(
        result
            .nickname
            .as_deref()
            .is_some_and(|nickname| !nickname.is_empty())
    );
    assert_eq!(success, Some(true));
    let spawned_thread = manager
        .get_thread(agent_id(&result.agent_id).expect("agent_id should be valid"))
        .await
        .expect("spawned agent thread should exist");
    assert!(!spawned_thread.enabled(Feature::Collab));
    assert!(!spawned_thread.enabled(Feature::SpawnCsv));
}

#[tokio::test]
async fn spawn_agent_config_backed_role_hides_multi_agent_tools_at_configured_max_depth() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
    }

    let (mut session, mut turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let mut config = (*turn.config).clone();
    config
        .features
        .enable(Feature::Collab)
        .expect("collab feature enable");
    config
        .features
        .enable(Feature::SpawnCsv)
        .expect("spawn csv feature enable");
    turn.config = Arc::new(config);
    let current_max_depth = turn.config.agent_max_depth;

    let mut config = (*turn.config).clone();
    config.agent_max_depth = current_max_depth + 1;
    turn.config = Arc::new(config);
    turn.session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: session.conversation_id,
        depth: current_max_depth,
        agent_path: None,
        agent_nickname: None,
        agent_role: None,
    });

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "await this command",
            "agent_type": "awaiter",
            "spawn_mode": "spawn"
        })),
    );
    let output = SpawnAgentHandler
        .handle(invocation)
        .await
        .expect("spawn should succeed within configured depth");
    let (content, success) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    assert_eq!(success, Some(true));
    let spawned_thread = manager
        .get_thread(agent_id(&result.agent_id).expect("agent_id should be valid"))
        .await
        .expect("spawned agent thread should exist");
    assert!(!spawned_thread.enabled(Feature::Collab));
    assert!(!spawned_thread.enabled(Feature::SpawnCsv));
}

#[tokio::test]
async fn spawn_agent_accepts_watchdog_interval_override() {
    let (mut session, mut turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let mut config = (*turn.config).clone();
    let _ = config.features.enable(Feature::AgentWatchdog);
    turn.config = Arc::new(config);

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "watchdog check-in",
            "spawn_mode": "watchdog",
            "interval_s": 5
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("interval override should be accepted");
    let (_, success) = expect_text_output(output);
    assert_eq!(success, Some(true));
}

#[tokio::test]
async fn spawn_agent_rejects_empty_model_override() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "model": "   "
        })),
    );
    let Err(err) = MultiAgentHandler.handle(invocation).await else {
        panic!("empty model override should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel("model must be non-empty when provided".to_string())
    );
}

#[tokio::test]
async fn spawn_agent_rejects_watchdog_from_subagent() {
    let (mut session, mut turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    turn.session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: session.conversation_id,
        depth: 0,
        agent_path: None,
        agent_nickname: None,
        agent_role: None,
    });

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "watchdog check-in",
            "spawn_mode": "watchdog"
        })),
    );
    let Err(err) = MultiAgentHandler.handle(invocation).await else {
        panic!("watchdog spawn should be rejected for subagents");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel(
            "watchdogs can only be spawned by root agents".to_string()
        )
    );
}

#[tokio::test]
async fn spawn_agent_rejects_watchdog_when_feature_disabled() {
    let (mut session, mut turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let mut config = (*turn.config).clone();
    let _ = config.features.disable(Feature::AgentWatchdog);
    turn.config = Arc::new(config);

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "watchdog check-in",
            "spawn_mode": "watchdog"
        })),
    );
    let Err(err) = MultiAgentHandler.handle(invocation).await else {
        panic!("watchdog spawn should be rejected when the feature is disabled");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel("watchdogs are disabled".to_string())
    );
}

#[tokio::test]
async fn spawn_agent_role_model_beats_explicit_model_override() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
    }

    let (mut session, mut turn, rx) = make_session_and_context_with_rx().await;
    let manager = thread_manager();
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .services
        .agent_control = manager.agent_control();
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .services
        .models_manager = manager.get_models_manager();
    let visible_models = visible_models(&session).await;
    let role_model = visible_models
        .iter()
        .find(|preset| {
            preset
                .supported_reasoning_efforts
                .iter()
                .any(|effort| effort.effort == ReasoningEffort::High)
        })
        .expect("expected visible model with high reasoning support")
        .clone();
    let selected_model = visible_models
        .iter()
        .find(|preset| {
            preset.model != role_model.model && !preset.supported_reasoning_efforts.is_empty()
        })
        .expect("expected second visible model with reasoning support")
        .clone();
    let requested_reasoning_effort = selected_model
        .supported_reasoning_efforts
        .first()
        .expect("expected supported reasoning effort")
        .effort;

    let role_dir = tempfile::tempdir().expect("temp dir");
    let role_path = role_dir.path().join("custom-role.toml");
    tokio::fs::write(
        &role_path,
        format!(
            "model = \"{}\"\nmodel_reasoning_effort = \"high\"\n",
            role_model.model
        ),
    )
    .await
    .expect("write role config");

    let mut config = (*turn.config).clone();
    config.agent_roles.insert(
        "custom".to_string(),
        AgentRoleConfig {
            description: None,
            model: None,
            config_file: Some(role_path),
            spawn_mode: None,
            nickname_candidates: None,
        },
    );
    Arc::get_mut(&mut turn).expect("no extra turn refs").config = Arc::new(config);

    let invocation = invocation(
        session.clone(),
        turn.clone(),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "agent_type": "custom",
            "model": selected_model.model,
            "reasoning_effort": requested_reasoning_effort
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("spawn_agent should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
    let snapshot = manager
        .get_thread(agent_id)
        .await
        .expect("spawned agent thread should exist")
        .config_snapshot()
        .await;
    assert_eq!(snapshot.model, role_model.model);
    assert_eq!(snapshot.reasoning_effort, Some(ReasoningEffort::High));
    let spawn_event = timeout(Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.expect("collab event");
            if let EventMsg::CollabAgentSpawnEnd(event) = event.msg {
                break event;
            }
        }
    })
    .await
    .expect("spawn end event should arrive");
    assert_eq!(spawn_event.model, role_model.model);
    assert_eq!(spawn_event.reasoning_effort, ReasoningEffort::High);
}

#[tokio::test]
async fn spawn_agent_role_without_model_preserves_explicit_model_override() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
    }

    let (mut session, mut turn, rx) = make_session_and_context_with_rx().await;
    let manager = thread_manager();
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .services
        .agent_control = manager.agent_control();
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .services
        .models_manager = manager.get_models_manager();
    let selected_model = visible_models(&session)
        .await
        .into_iter()
        .next()
        .expect("expected visible model");

    let mut config = (*turn.config).clone();
    config.agent_roles.insert(
        "custom".to_string(),
        AgentRoleConfig {
            description: Some("Role without model override".to_string()),
            model: None,
            config_file: None,
            spawn_mode: None,
            nickname_candidates: None,
        },
    );
    Arc::get_mut(&mut turn).expect("no extra turn refs").config = Arc::new(config);

    let invocation = invocation(
        session.clone(),
        turn.clone(),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "agent_type": "custom",
            "model": selected_model.model,
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("spawn_agent should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
    let snapshot = manager
        .get_thread(agent_id)
        .await
        .expect("spawned agent thread should exist")
        .config_snapshot()
        .await;
    assert_eq!(snapshot.model, selected_model.model);
    let spawn_event = timeout(Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.expect("collab event");
            if let EventMsg::CollabAgentSpawnEnd(event) = event.msg {
                break event;
            }
        }
    })
    .await
    .expect("spawn end event should arrive");
    assert_eq!(spawn_event.model, selected_model.model);
}

#[tokio::test]
async fn spawn_agent_rejects_role_reasoning_effort_incompatible_with_selected_model() {
    let (mut session, mut turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    session.services.models_manager = manager.get_models_manager();
    let candidate_efforts = [
        ReasoningEffort::None,
        ReasoningEffort::Minimal,
        ReasoningEffort::Low,
        ReasoningEffort::Medium,
        ReasoningEffort::High,
        ReasoningEffort::XHigh,
    ];
    let selected_model = visible_models(&session)
        .await
        .into_iter()
        .find(|preset| {
            candidate_efforts.iter().any(|candidate| {
                !preset
                    .supported_reasoning_efforts
                    .iter()
                    .any(|effort| effort.effort == *candidate)
            })
        })
        .expect("expected a visible model without full reasoning coverage");
    let unsupported_effort = candidate_efforts
        .into_iter()
        .find(|candidate| {
            !selected_model
                .supported_reasoning_efforts
                .iter()
                .any(|effort| effort.effort == *candidate)
        })
        .expect("expected unsupported effort");

    let role_dir = tempfile::tempdir().expect("temp dir");
    let role_path = role_dir.path().join("custom-role.toml");
    tokio::fs::write(
        &role_path,
        format!("model_reasoning_effort = \"{unsupported_effort}\"\n"),
    )
    .await
    .expect("write role config");

    let mut config = (*turn.config).clone();
    config.agent_roles.insert(
        "custom".to_string(),
        AgentRoleConfig {
            description: Some("Role overrides reasoning only".to_string()),
            model: None,
            config_file: Some(role_path),
            spawn_mode: None,
            nickname_candidates: None,
        },
    );
    turn.config = Arc::new(config);

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "agent_type": "custom",
            "model": selected_model.model,
        })),
    );
    let Err(err) = MultiAgentHandler.handle(invocation).await else {
        panic!("unsupported role reasoning effort should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel(format!(
            "spawn_agent reasoning_effort `{unsupported_effort}` is not supported for model `{}`. Choose one of: {}",
            selected_model.model,
            selected_model
                .supported_reasoning_efforts
                .iter()
                .map(|effort| format!("`{}`", effort.effort))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    );
}

#[tokio::test]
async fn spawn_agent_omitted_spawn_mode_uses_role_default() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
    }

    let (mut session, mut turn, rx) = make_session_and_context_with_rx().await;
    let manager = thread_manager();
    let owner_thread = manager
        .start_thread(turn.config.as_ref().clone())
        .await
        .expect("start owner thread");
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .services
        .agent_control = manager.agent_control();
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .conversation_id = owner_thread.thread_id;

    let mut config = (*turn.config).clone();
    config.agent_roles.insert(
        "custom".to_string(),
        AgentRoleConfig {
            description: Some("Fork by default".to_string()),
            model: None,
            config_file: None,
            spawn_mode: Some(AgentRoleSpawnMode::Fork),
            nickname_candidates: None,
        },
    );
    Arc::get_mut(&mut turn).expect("no extra turn refs").config = Arc::new(config);

    let invocation = invocation(
        session.clone(),
        turn.clone(),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "agent_type": "custom"
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("spawn_agent should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
    let spawn_event = timeout(Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.expect("collab event");
            if let EventMsg::CollabAgentSpawnEnd(event) = event.msg {
                break event;
            }
        }
    })
    .await
    .expect("spawn end event should arrive");

    assert_eq!(spawn_event.spawn_mode, AgentSpawnMode::Fork);

    let _ = manager
        .agent_control()
        .shutdown_agent(agent_id)
        .await
        .expect("shutdown spawned agent");
    let _ = manager
        .agent_control()
        .shutdown_agent(owner_thread.thread_id)
        .await
        .expect("shutdown owner thread");
}

#[tokio::test]
async fn spawn_agent_fork_context_defaults_spawn_mode_to_fork() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
    }

    let (mut session, turn, rx) = make_session_and_context_with_rx().await;
    let manager = thread_manager();
    let owner_thread = manager
        .start_thread(turn.config.as_ref().clone())
        .await
        .expect("start owner thread");
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .services
        .agent_control = manager.agent_control();
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .conversation_id = owner_thread.thread_id;

    let invocation = invocation(
        session.clone(),
        turn.clone(),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "fork_context": true
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("spawn_agent should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
    let spawn_event = timeout(Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.expect("collab event");
            if let EventMsg::CollabAgentSpawnEnd(event) = event.msg {
                break event;
            }
        }
    })
    .await
    .expect("spawn end event should arrive");

    assert_eq!(spawn_event.spawn_mode, AgentSpawnMode::Fork);

    let _ = manager
        .agent_control()
        .shutdown_agent(agent_id)
        .await
        .expect("shutdown spawned agent");
    let _ = manager
        .agent_control()
        .shutdown_agent(owner_thread.thread_id)
        .await
        .expect("shutdown owner thread");
}

#[tokio::test]
async fn spawn_agent_fork_context_overrides_explicit_spawn_mode_to_fork() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
    }

    let (mut session, turn, rx) = make_session_and_context_with_rx().await;
    let manager = thread_manager();
    let owner_thread = manager
        .start_thread(turn.config.as_ref().clone())
        .await
        .expect("start owner thread");
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .services
        .agent_control = manager.agent_control();
    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .conversation_id = owner_thread.thread_id;

    let invocation = invocation(
        session.clone(),
        turn.clone(),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "spawn_mode": "spawn",
            "fork_context": true
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("spawn_agent should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
    let spawn_event = timeout(Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.expect("collab event");
            if let EventMsg::CollabAgentSpawnEnd(event) = event.msg {
                break event;
            }
        }
    })
    .await
    .expect("spawn end event should arrive");

    assert_eq!(spawn_event.spawn_mode, AgentSpawnMode::Fork);

    let _ = manager
        .agent_control()
        .shutdown_agent(agent_id)
        .await
        .expect("shutdown spawned agent");
    let _ = manager
        .agent_control()
        .shutdown_agent(owner_thread.thread_id)
        .await
        .expect("shutdown owner thread");
}

#[tokio::test]
async fn spawn_agent_fork_context_rejects_watchdog_spawn_mode() {
    let (mut session, mut turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let mut config = (*turn.config).clone();
    let _ = config.features.enable(Feature::AgentWatchdog);
    turn.config = Arc::new(config);

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "watchdog check-in",
            "spawn_mode": "watchdog",
            "fork_context": true
        })),
    );
    let Err(err) = MultiAgentHandler.handle(invocation).await else {
        panic!("watchdog spawn with fork_context should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel(
            "fork_context cannot be used with spawn_mode = \"watchdog\"".to_string()
        )
    );
}

#[tokio::test]
async fn spawn_agent_applies_explicit_model_override() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
        nickname: Option<String>,
    }

    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    session.services.models_manager = manager.get_models_manager();
    let visible_models = visible_models(&session).await;
    let selected_model = visible_models
        .iter()
        .find(|preset| preset.model != turn.model_info.slug)
        .unwrap_or_else(|| {
            panic!(
                "expected visible model distinct from {}",
                turn.model_info.slug
            )
        })
        .clone();

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "model": selected_model.model
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("spawn_agent should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    assert!(
        result
            .nickname
            .as_deref()
            .is_some_and(|nickname| !nickname.is_empty())
    );
    let snapshot = manager
        .get_thread(agent_id(&result.agent_id).expect("agent_id should be valid"))
        .await
        .expect("spawned agent thread should exist")
        .config_snapshot()
        .await;
    assert_eq!(snapshot.model, selected_model.model);
    assert_eq!(
        snapshot.reasoning_effort,
        Some(selected_model.default_reasoning_effort)
    );
}

#[tokio::test]
async fn spawn_agent_applies_explicit_reasoning_effort_override() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
    }

    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    session.services.models_manager = manager.get_models_manager();
    let turn = if turn.model_info.supported_reasoning_levels.is_empty() {
        let selected_model = visible_models(&session)
            .await
            .into_iter()
            .find(|preset| !preset.supported_reasoning_efforts.is_empty())
            .expect("expected a visible model with reasoning support");
        turn.with_model(selected_model.model, &session.services.models_manager)
            .await
    } else {
        turn
    };
    let inherited_model = turn.model_info.slug.clone();
    let selected_effort = turn
        .model_info
        .supported_reasoning_levels
        .iter()
        .find(|preset| Some(preset.effort) != turn.reasoning_effort)
        .or_else(|| turn.model_info.supported_reasoning_levels.first())
        .map(|preset| preset.effort)
        .expect("expected at least one supported reasoning level");

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "reasoning_effort": selected_effort
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("spawn_agent should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    let agent_id = agent_id(&result.agent_id).expect("agent_id should be valid");
    let snapshot = manager
        .get_thread(agent_id)
        .await
        .expect("spawned agent thread should exist")
        .config_snapshot()
        .await;
    assert_eq!(snapshot.model, inherited_model);
    assert_eq!(snapshot.reasoning_effort, Some(selected_effort));
}

#[tokio::test]
async fn spawn_agent_accepts_fallback_resolvable_model_override() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
    }

    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    session.services.models_manager = manager.get_models_manager();
    let selected_model = visible_models(&session)
        .await
        .into_iter()
        .next()
        .expect("expected at least one visible model");
    let requested_model = format!("custom/{}", selected_model.model);
    let expected_model_info = session
        .services
        .models_manager
        .get_model_info(requested_model.as_str(), turn.config.as_ref())
        .await;

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "model": requested_model.clone()
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("spawn_agent should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    let snapshot = manager
        .get_thread(agent_id(&result.agent_id).expect("agent_id should be valid"))
        .await
        .expect("spawned agent thread should exist")
        .config_snapshot()
        .await;
    assert_eq!(snapshot.model, requested_model);
    assert_eq!(
        snapshot.reasoning_effort,
        expected_model_info.default_reasoning_level
    );
}

#[tokio::test]
async fn spawn_agent_rejects_unsupported_reasoning_effort_for_selected_model() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    session.services.models_manager = manager.get_models_manager();
    let candidate_efforts = [
        ReasoningEffort::None,
        ReasoningEffort::Minimal,
        ReasoningEffort::Low,
        ReasoningEffort::Medium,
        ReasoningEffort::High,
        ReasoningEffort::XHigh,
    ];
    let selected_model = visible_models(&session)
        .await
        .into_iter()
        .find(|preset| {
            candidate_efforts.iter().any(|candidate| {
                !preset
                    .supported_reasoning_efforts
                    .iter()
                    .any(|effort| effort.effort == *candidate)
            })
        })
        .expect("expected a visible model without full reasoning coverage");
    let unsupported_effort = candidate_efforts
        .into_iter()
        .find(|candidate| {
            !selected_model
                .supported_reasoning_efforts
                .iter()
                .any(|effort| effort.effort == *candidate)
        })
        .expect("expected unsupported effort");

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "spawn_agent",
        function_payload(json!({
            "message": "inspect this repo",
            "model": selected_model.model,
            "reasoning_effort": unsupported_effort,
        })),
    );
    let Err(err) = MultiAgentHandler.handle(invocation).await else {
        panic!("unsupported reasoning effort should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel(format!(
            "spawn_agent reasoning_effort `{unsupported_effort}` is not supported for model `{}`. Choose one of: {}",
            selected_model.model,
            selected_model
                .supported_reasoning_efforts
                .iter()
                .map(|effort| format!("`{}`", effort.effort))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    );
}

#[tokio::test]
async fn spawn_agent_watchdog_handle_uses_explicit_overrides() {
    #[derive(Debug, Deserialize)]
    struct SpawnAgentResult {
        agent_id: String,
    }

    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    session.services.models_manager = manager.get_models_manager();
    let selected_model = visible_models(&session)
        .await
        .into_iter()
        .find(|preset| !preset.supported_reasoning_efforts.is_empty())
        .expect("expected visible model with reasoning support");
    let requested_effort = selected_model
        .supported_reasoning_efforts
        .first()
        .map(|effort| effort.effort)
        .expect("expected reasoning effort");
    let mut config = (*turn.config).clone();
    let _ = config.features.enable(Feature::AgentWatchdog);
    session.services.agent_control = manager.agent_control();
    let turn = Arc::new(TurnContext {
        config: Arc::new(config),
        ..turn
    });

    let invocation = invocation(
        Arc::new(session),
        turn,
        "spawn_agent",
        function_payload(json!({
            "message": "watchdog check-in",
            "spawn_mode": "watchdog",
            "model": selected_model.model,
            "reasoning_effort": requested_effort
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("watchdog spawn should succeed");
    let (content, _) = expect_text_output(output);
    let result: SpawnAgentResult =
        serde_json::from_str(&content).expect("spawn_agent result should be json");
    let watchdog_id = agent_id(&result.agent_id).expect("agent_id should be valid");
    let snapshot = manager
        .get_thread(watchdog_id)
        .await
        .expect("watchdog handle should exist")
        .config_snapshot()
        .await;
    assert_eq!(snapshot.model, selected_model.model);
    assert_eq!(snapshot.reasoning_effort, Some(requested_effort));
}

#[tokio::test]
async fn compact_parent_context_rejects_when_feature_disabled() {
    let (session, mut turn) = make_session_and_context().await;
    let mut config = (*turn.config).clone();
    let _ = config.features.disable(Feature::AgentWatchdog);
    turn.config = Arc::new(config);

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "compact_parent_context",
        function_payload(json!({})),
    );
    let Err(err) = MultiAgentHandler.handle(invocation).await else {
        panic!("compact_parent_context should be rejected when the feature is disabled");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel("watchdogs are disabled".to_string())
    );
}

#[tokio::test]
async fn send_input_rejects_empty_message() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "send_input",
        function_payload(json!({"id": ThreadId::new().to_string(), "message": ""})),
    );
    let Err(err) = SendInputHandler.handle(invocation).await else {
        panic!("empty message should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel("Empty message can't be sent to an agent".to_string())
    );
}

#[tokio::test]
async fn send_input_rejects_when_message_and_items_are_both_set() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "send_input",
        function_payload(json!({
            "id": ThreadId::new().to_string(),
            "message": "hello",
            "items": [{"type": "mention", "name": "drive", "path": "app://drive"}]
        })),
    );
    let Err(err) = SendInputHandler.handle(invocation).await else {
        panic!("message+items should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel(
            "Provide either message or items, but not both".to_string()
        )
    );
}

#[tokio::test]
async fn send_input_rejects_invalid_id() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "send_input",
        function_payload(json!({"id": "not-a-uuid", "message": "hi"})),
    );
    let Err(err) = SendInputHandler.handle(invocation).await else {
        panic!("invalid id should be rejected");
    };
    let FunctionCallError::RespondToModel(msg) = err else {
        panic!("expected respond-to-model error");
    };
    assert!(msg.starts_with("invalid agent id not-a-uuid:"));
}

#[tokio::test]
async fn send_input_requires_id_without_parent_agent() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "send_input",
        function_payload(json!({"message": "hi"})),
    );
    let Err(err) = MultiAgentHandler.handle(invocation).await else {
        panic!("missing id should be rejected without a parent agent");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel(
            "send_input requires an id when no parent agent is available".to_string()
        )
    );
}

#[tokio::test]
async fn send_input_reports_missing_agent() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let agent_id = ThreadId::new();
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "send_input",
        function_payload(json!({"id": agent_id.to_string(), "message": "hi"})),
    );
    let Err(err) = SendInputHandler.handle(invocation).await else {
        panic!("missing agent should be reported");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel(format!("agent with id {agent_id} not found"))
    );
}

#[tokio::test]
async fn list_agents_root_alias_resolves_true_root_from_nested_subagents() {
    let (mut root_session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    root_session.services.agent_control = manager.agent_control();
    let root_thread_id = root_session.conversation_id;
    let child_id = manager
        .agent_control()
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(root_thread_id, 1)),
        )
        .await
        .expect("spawn child handle");
    let grandchild_id = manager
        .agent_control()
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(child_id, 2)),
        )
        .await
        .expect("spawn grandchild handle");
    let grandchild_session = manager
        .get_thread(grandchild_id)
        .await
        .expect("grandchild thread should exist")
        .codex
        .session
        .clone();
    let invocation = invocation(
        grandchild_session.clone(),
        Arc::new(turn),
        "list_agents",
        function_payload(json!({
            "id": "root",
            "recursive": true
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("list_agents should succeed");
    let (content, success) = expect_text_output(output);
    let result: ListAgentsResultForTest =
        serde_json::from_str(&content).expect("list_agents result should be json");
    let expected_child_status = manager.agent_control().get_status(child_id).await;
    let expected_grandchild_status = manager.agent_control().get_status(grandchild_id).await;
    assert_eq!(
        result,
        ListAgentsResultForTest {
            agents: vec![
                ListAgentEntryForTest {
                    id: child_id.to_string(),
                    parent_id: root_thread_id.to_string(),
                    status: expected_child_status,
                    depth: 1,
                },
                ListAgentEntryForTest {
                    id: grandchild_id.to_string(),
                    parent_id: child_id.to_string(),
                    status: expected_grandchild_status,
                    depth: 2,
                },
            ],
        }
    );
    assert_eq!(success, Some(true));

    let _ = grandchild_session
        .services
        .agent_control
        .shutdown_agent(child_id)
        .await;
}

#[tokio::test]
async fn list_agents_parent_alias_targets_immediate_parent() {
    let (mut root_session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    root_session.services.agent_control = manager.agent_control();
    let root_thread_id = root_session.conversation_id;
    let child_id = manager
        .agent_control()
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(root_thread_id, 1)),
        )
        .await
        .expect("spawn child handle");
    let grandchild_id = manager
        .agent_control()
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(child_id, 2)),
        )
        .await
        .expect("spawn grandchild handle");
    let child_session = manager
        .get_thread(grandchild_id)
        .await
        .expect("grandchild thread should exist")
        .codex
        .session
        .clone();

    let invocation = invocation(
        child_session.clone(),
        Arc::new(turn),
        "list_agents",
        function_payload(json!({
            "id": "parent",
            "recursive": false
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("list_agents should succeed");
    let (content, success) = expect_text_output(output);
    let result: ListAgentsResultForTest =
        serde_json::from_str(&content).expect("list_agents result should be json");
    let expected_status = manager.agent_control().get_status(grandchild_id).await;
    assert_eq!(
        result,
        ListAgentsResultForTest {
            agents: vec![ListAgentEntryForTest {
                id: grandchild_id.to_string(),
                parent_id: child_id.to_string(),
                status: expected_status,
                depth: 1,
            }],
        }
    );
    assert_eq!(success, Some(true));

    let _ = child_session
        .services
        .agent_control
        .shutdown_agent(child_id)
        .await;
}

#[tokio::test]
async fn peek_agents_parent_alias_targets_immediate_parent_with_cached_progress() {
    let (mut root_session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    let agent_control = manager.agent_control();
    root_session.services.agent_control = agent_control.clone();
    let root_thread_id = root_session.conversation_id;
    let child_id = agent_control
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(root_thread_id, 1)),
        )
        .await
        .expect("spawn child handle");
    let grandchild_id = agent_control
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(child_id, 2)),
        )
        .await
        .expect("spawn grandchild handle");

    agent_control
        .record_prompt_preview(grandchild_id, "  investigate   flaky wait path  ")
        .await;
    agent_control
        .observe_progress_event(
            grandchild_id,
            &EventMsg::AgentReasoningDelta(AgentReasoningDeltaEvent {
                delta: "collecting signal".to_string(),
            }),
        )
        .await;
    agent_control
        .observe_progress_event(
            grandchild_id,
            &EventMsg::AgentMessage(AgentMessageEvent {
                message: "found root cause".to_string(),
                phase: None,
                memory_citation: None,
            }),
        )
        .await;

    let child_session = manager
        .get_thread(grandchild_id)
        .await
        .expect("grandchild thread should exist")
        .codex
        .session
        .clone();

    let invocation = invocation(
        child_session.clone(),
        Arc::new(turn),
        "peek_agents",
        function_payload(json!({
            "id": "parent",
            "recursive": false
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("peek_agents should succeed");
    let (content, success) = expect_text_output(output);
    let result: PeekAgentsResultForTest =
        serde_json::from_str(&content).expect("peek_agents result should be json");
    let expected_status = agent_control.get_status(grandchild_id).await;
    assert_eq!(
        result.agents,
        vec![PeekAgentEntryForTest {
            id: grandchild_id.to_string(),
            parent_id: child_id.to_string(),
            status: expected_status,
            depth: 1,
            cursor: result.agents[0].cursor,
            prompt_preview: Some("investigate flaky wait path".to_string()),
            reasoning_summary: Some("collecting signal".to_string()),
            latest_message_preview: Some("found root cause".to_string()),
            terminal_summary: None,
        }]
    );
    assert_eq!(result.next_cursor, result.agents[0].cursor);
    assert_eq!(success, Some(true));

    let _ = child_session
        .services
        .agent_control
        .shutdown_agent(child_id)
        .await;
}

#[tokio::test]
async fn peek_agents_cursor_returns_incremental_updates_with_limit() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    let agent_control = manager.agent_control();
    session.services.agent_control = agent_control.clone();
    let root_thread_id = session.conversation_id;
    let child_a = agent_control
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(root_thread_id, 1)),
        )
        .await
        .expect("spawn child a");
    let child_b = agent_control
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(root_thread_id, 1)),
        )
        .await
        .expect("spawn child b");

    agent_control
        .record_prompt_preview(child_a, "alpha work item")
        .await;
    agent_control
        .record_prompt_preview(child_b, "beta work item")
        .await;
    let session = Arc::new(session);
    let turn = Arc::new(turn);

    let first = MultiAgentHandler
        .handle(invocation(
            session.clone(),
            turn.clone(),
            "peek_agents",
            function_payload(json!({ "recursive": false })),
        ))
        .await
        .expect("initial peek_agents should succeed");
    let (first_content, _) = expect_text_output(first);
    let first_result: PeekAgentsResultForTest =
        serde_json::from_str(&first_content).expect("first peek result should be json");
    assert_eq!(first_result.agents.len(), 2);
    let first_cursor = first_result.next_cursor;

    agent_control
        .observe_progress_event(
            child_b,
            &EventMsg::AgentMessage(AgentMessageEvent {
                message: "beta completed".to_string(),
                phase: None,
                memory_citation: None,
            }),
        )
        .await;
    agent_control
        .observe_progress_event(
            child_a,
            &EventMsg::AgentMessage(AgentMessageEvent {
                message: "alpha completed".to_string(),
                phase: None,
                memory_citation: None,
            }),
        )
        .await;

    let second = MultiAgentHandler
        .handle(invocation(
            session,
            turn,
            "peek_agents",
            function_payload(json!({
                "recursive": false,
                "cursor": first_cursor,
                "limit": 1
            })),
        ))
        .await
        .expect("incremental peek_agents should succeed");
    let (second_content, _) = expect_text_output(second);
    let second_result: PeekAgentsResultForTest =
        serde_json::from_str(&second_content).expect("second peek result should be json");
    assert_eq!(second_result.agents.len(), 1);
    assert!(second_result.agents[0].cursor > first_cursor);
    assert_eq!(second_result.next_cursor, second_result.agents[0].cursor);
}

#[tokio::test]
async fn peek_agents_default_returns_newest_updates_first_when_limited() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    let agent_control = manager.agent_control();
    session.services.agent_control = agent_control.clone();
    let root_thread_id = session.conversation_id;
    let child_recent = agent_control
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(root_thread_id, 1)),
        )
        .await
        .expect("spawn recent child");
    let child_old = agent_control
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(root_thread_id, 1)),
        )
        .await
        .expect("spawn old child");
    let _child_idle = agent_control
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(root_thread_id, 1)),
        )
        .await
        .expect("spawn idle child");

    agent_control
        .record_prompt_preview(child_old, "old progress")
        .await;
    agent_control
        .record_prompt_preview(child_recent, "recent progress")
        .await;
    agent_control
        .observe_progress_event(
            child_recent,
            &EventMsg::AgentMessage(AgentMessageEvent {
                message: "newest event".to_string(),
                phase: None,
                memory_citation: None,
            }),
        )
        .await;

    let output = MultiAgentHandler
        .handle(invocation(
            Arc::new(session),
            Arc::new(turn),
            "peek_agents",
            function_payload(json!({
                "recursive": false,
                "limit": 1
            })),
        ))
        .await
        .expect("peek_agents should succeed");
    let (content, success) = expect_text_output(output);
    let result: PeekAgentsResultForTest =
        serde_json::from_str(&content).expect("peek result should be json");

    assert_eq!(result.agents.len(), 1);
    assert_eq!(result.agents[0].id, child_recent.to_string());
    assert_eq!(
        result.agents[0].latest_message_preview.as_deref(),
        Some("newest event")
    );
    assert_eq!(result.next_cursor, result.agents[0].cursor);
    assert_eq!(success, Some(true));
}

#[tokio::test]
async fn send_input_interrupts_before_prompt() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let config = turn.config.as_ref().clone();
    let thread = manager.start_thread(config).await.expect("start thread");
    let agent_id = thread.thread_id;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "send_input",
        function_payload(json!({
            "id": agent_id.to_string(),
            "message": "hi",
            "interrupt": true
        })),
    );
    SendInputHandler
        .handle(invocation)
        .await
        .expect("send_input should succeed");

    let ops = manager.captured_ops();
    let ops_for_agent: Vec<&Op> = ops
        .iter()
        .filter_map(|(id, op)| (*id == agent_id).then_some(op))
        .collect();
    assert!(
        !ops_for_agent.is_empty(),
        "expected at least one op for the target agent"
    );
    assert!(matches!(ops_for_agent[0], Op::Interrupt));

    let _ = thread
        .thread
        .submit(Op::Shutdown {})
        .await
        .expect("shutdown should submit");
}

#[tokio::test]
async fn send_input_parent_alias_uses_collab_inbox_delivery_for_text() {
    let (mut root_session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    root_session.services.agent_control = manager.agent_control();
    let root_thread = manager
        .start_thread(turn.config.as_ref().clone())
        .await
        .expect("start root thread");
    let child_id = manager
        .agent_control()
        .spawn_agent_handle(
            turn.config.as_ref().clone(),
            Some(thread_spawn_source(root_thread.thread_id, 1)),
        )
        .await
        .expect("spawn child handle");
    let child_session = manager
        .get_thread(child_id)
        .await
        .expect("child thread should exist")
        .codex
        .session
        .clone();

    let invocation = invocation(
        child_session.clone(),
        Arc::new(turn),
        "send_input",
        function_payload(json!({
            "id": "parent",
            "message": "watchdog check-in"
        })),
    );
    MultiAgentHandler
        .handle(invocation)
        .await
        .expect("send_input should succeed");

    let ops = manager.captured_ops();
    let parent_received_collab_inbox = ops.iter().any(|(id, op)| {
        *id == root_thread.thread_id && matches!(op, Op::InjectResponseItems { .. })
    });
    assert!(parent_received_collab_inbox);
    let parent_received_user_input = ops
        .iter()
        .any(|(id, op)| *id == root_thread.thread_id && matches!(op, Op::UserInput { .. }));
    assert!(!parent_received_user_input);

    let _ = child_session
        .services
        .agent_control
        .shutdown_agent(child_id)
        .await;
    let _ = child_session
        .services
        .agent_control
        .shutdown_agent(root_thread.thread_id)
        .await;
}

#[tokio::test]
async fn send_input_rejects_watchdog_handle() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();

    let owner_thread = manager
        .start_thread(turn.config.as_ref().clone())
        .await
        .expect("start owner thread");
    session.conversation_id = owner_thread.thread_id;

    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;

    let invocation = invocation(
        session.clone(),
        turn.clone(),
        "send_input",
        function_payload(json!({
            "id": watchdog_id.to_string(),
            "message": "hi"
        })),
    );
    let result = MultiAgentHandler.handle(invocation).await;
    assert!(matches!(
        result,
        Err(FunctionCallError::RespondToModel(message))
            if message
                == "send_input cannot target watchdog handles. Send the message to the parent/root agent instead."
    ));

    let _ = session
        .services
        .agent_control
        .shutdown_agent(watchdog_id)
        .await;
    let _ = session
        .services
        .agent_control
        .shutdown_agent(owner_thread.thread_id)
        .await;
}

#[tokio::test]
async fn send_input_interrupt_rejects_watchdog_handle() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();

    let owner_thread = manager
        .start_thread(turn.config.as_ref().clone())
        .await
        .expect("start owner thread");
    session.conversation_id = owner_thread.thread_id;

    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;

    let invocation = invocation(
        session.clone(),
        turn.clone(),
        "send_input",
        function_payload(json!({
            "id": watchdog_id.to_string(),
            "message": "hi",
            "interrupt": true
        })),
    );
    let result = MultiAgentHandler.handle(invocation).await;
    assert!(matches!(
        result,
        Err(FunctionCallError::RespondToModel(message))
            if message
                == "send_input cannot target watchdog handles. Send the message to the parent/root agent instead."
    ));

    let _ = session
        .services
        .agent_control
        .shutdown_agent(watchdog_id)
        .await;
    let _ = session
        .services
        .agent_control
        .shutdown_agent(owner_thread.thread_id)
        .await;
}

#[tokio::test]
async fn send_input_accepts_structured_items() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let config = turn.config.as_ref().clone();
    let thread = manager.start_thread(config).await.expect("start thread");
    let agent_id = thread.thread_id;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "send_input",
        function_payload(json!({
            "id": agent_id.to_string(),
            "items": [
                {"type": "mention", "name": "drive", "path": "app://google_drive"},
                {"type": "text", "text": "read the folder"}
            ]
        })),
    );
    SendInputHandler
        .handle(invocation)
        .await
        .expect("send_input should succeed");

    let expected = Op::UserInput {
        items: vec![
            UserInput::Mention {
                name: "drive".to_string(),
                path: "app://google_drive".to_string(),
            },
            UserInput::Text {
                text: "read the folder".to_string(),
                text_elements: Vec::new(),
            },
        ],
        final_output_json_schema: None,
    };
    let captured = manager
        .captured_ops()
        .into_iter()
        .find(|(id, op)| *id == agent_id && *op == expected);
    assert_eq!(captured, Some((agent_id, expected)));

    let _ = thread
        .thread
        .submit(Op::Shutdown {})
        .await
        .expect("shutdown should submit");
}

#[tokio::test]
async fn resume_agent_rejects_invalid_id() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "resume_agent",
        function_payload(json!({"id": "not-a-uuid"})),
    );
    let Err(err) = ResumeAgentHandler.handle(invocation).await else {
        panic!("invalid id should be rejected");
    };
    let FunctionCallError::RespondToModel(msg) = err else {
        panic!("expected respond-to-model error");
    };
    assert!(msg.starts_with("invalid agent id not-a-uuid:"));
}

#[tokio::test]
async fn resume_agent_reports_missing_agent() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let agent_id = ThreadId::new();
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "resume_agent",
        function_payload(json!({"id": agent_id.to_string()})),
    );
    let Err(err) = ResumeAgentHandler.handle(invocation).await else {
        panic!("missing agent should be reported");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel(format!("agent with id {agent_id} not found"))
    );
}

#[tokio::test]
async fn resume_agent_noops_for_active_agent() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let config = turn.config.as_ref().clone();
    let thread = manager.start_thread(config).await.expect("start thread");
    let agent_id = thread.thread_id;
    let status_before = manager.agent_control().get_status(agent_id).await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "resume_agent",
        function_payload(json!({"id": agent_id.to_string()})),
    );

    let output = ResumeAgentHandler
        .handle(invocation)
        .await
        .expect("resume_agent should succeed");
    let (content, success) = expect_text_output(output);
    let result: resume_agent::ResumeAgentResult =
        serde_json::from_str(&content).expect("resume_agent result should be json");
    assert_eq!(result.status, status_before);
    assert_eq!(success, Some(true));

    let thread_ids = manager.list_thread_ids().await;
    assert_eq!(thread_ids, vec![agent_id]);

    let _ = thread
        .thread
        .submit(Op::Shutdown {})
        .await
        .expect("shutdown should submit");
}

#[tokio::test]
async fn resume_agent_restores_closed_agent_and_accepts_send_input() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let config = turn.config.as_ref().clone();
    let thread = manager
        .resume_thread_with_history(
            config,
            InitialHistory::Forked(vec![RolloutItem::ResponseItem(ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "materialized".to_string(),
                }],
                end_turn: None,
                phase: None,
            })]),
            AuthManager::from_auth_for_testing(CodexAuth::from_api_key("dummy")),
            false,
            None,
        )
        .await
        .expect("start thread");
    let agent_id = thread.thread_id;
    let _ = manager
        .agent_control()
        .shutdown_live_agent(agent_id)
        .await
        .expect("shutdown agent");
    assert_eq!(
        manager.agent_control().get_status(agent_id).await,
        AgentStatus::NotFound
    );
    let session = Arc::new(session);
    let turn = Arc::new(turn);

    let resume_invocation = invocation(
        session.clone(),
        turn.clone(),
        "resume_agent",
        function_payload(json!({"id": agent_id.to_string()})),
    );
    let output = ResumeAgentHandler
        .handle(resume_invocation)
        .await
        .expect("resume_agent should succeed");
    let (content, success) = expect_text_output(output);
    let result: resume_agent::ResumeAgentResult =
        serde_json::from_str(&content).expect("resume_agent result should be json");
    assert_ne!(result.status, AgentStatus::NotFound);
    assert_eq!(success, Some(true));

    let send_invocation = invocation(
        session,
        turn,
        "send_input",
        function_payload(json!({"id": agent_id.to_string(), "message": "hello"})),
    );
    let output = SendInputHandler
        .handle(send_invocation)
        .await
        .expect("send_input should succeed after resume");
    let (content, success) = expect_text_output(output);
    let result: serde_json::Value =
        serde_json::from_str(&content).expect("send_input result should be json");
    let submission_id = result
        .get("submission_id")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(!submission_id.is_empty());
    assert_eq!(success, Some(true));

    let _ = manager
        .agent_control()
        .shutdown_live_agent(agent_id)
        .await
        .expect("shutdown resumed agent");
}

#[tokio::test]
async fn resume_agent_restores_closed_fork_agent_with_turn_developer_instructions() {
    let (mut session, mut turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let mut config = turn.config.as_ref().clone();
    config.developer_instructions = Some("base-dev".to_string());
    turn.developer_instructions = Some("turn-dev".to_string());
    turn.reasoning_effort = Some(ReasoningEffort::XHigh);
    turn.config = Arc::new(config.clone());
    let thread = manager
        .resume_thread_with_history(
            config,
            InitialHistory::Forked(vec![
                RolloutItem::TurnContext(TurnContextItem {
                    turn_id: Some("turn-1".to_string()),
                    cwd: turn.cwd.clone(),
                    current_date: turn.current_date.clone(),
                    timezone: turn.timezone.clone(),
                    trace_id: None,
                    approval_policy: turn.approval_policy.value(),
                    sandbox_policy: turn.sandbox_policy.get().clone(),
                    network: None,
                    model: "gpt-5.1-codex-mini".to_string(),
                    personality: turn.personality,
                    collaboration_mode: Some(turn.collaboration_mode.clone()),
                    realtime_active: Some(turn.realtime_active),
                    effort: Some(ReasoningEffort::High),
                    summary: turn.reasoning_summary,
                    user_instructions: turn.user_instructions.clone(),
                    developer_instructions: turn.developer_instructions.clone(),
                    final_output_json_schema: turn.final_output_json_schema.clone(),
                    truncation_policy: Some(turn.truncation_policy.into()),
                }),
                RolloutItem::ResponseItem(ResponseItem::Message {
                    id: None,
                    role: "user".to_string(),
                    content: vec![ContentItem::InputText {
                        text: "materialized".to_string(),
                    }],
                    end_turn: None,
                    phase: None,
                }),
            ]),
            AuthManager::from_auth_for_testing(CodexAuth::from_api_key("dummy")),
            false,
            None,
        )
        .await
        .expect("start thread");
    let agent_id = thread.thread_id;
    let _ = manager
        .agent_control()
        .shutdown_agent(agent_id)
        .await
        .expect("shutdown agent");
    assert_eq!(
        manager.agent_control().get_status(agent_id).await,
        AgentStatus::NotFound
    );
    let session = Arc::new(session);
    let turn = Arc::new(turn);

    let resume_invocation = invocation(
        session,
        turn.clone(),
        "resume_agent",
        function_payload(json!({"id": agent_id.to_string()})),
    );
    let output = MultiAgentHandler
        .handle(resume_invocation)
        .await
        .expect("resume_agent should succeed");
    let (content, success) = expect_text_output(output);
    let result: resume_agent::ResumeAgentResult =
        serde_json::from_str(&content).expect("resume_agent result should be json");
    assert_ne!(result.status, AgentStatus::NotFound);
    assert_eq!(success, Some(true));

    let resumed_thread = manager
        .get_thread(agent_id)
        .await
        .expect("resumed thread should be registered");
    let resumed_config = resumed_thread.codex.session.get_config().await;
    assert_eq!(resumed_config.model.as_deref(), Some("gpt-5.1-codex-mini"));
    assert_eq!(
        resumed_config.model_reasoning_effort,
        Some(ReasoningEffort::High)
    );
    assert_eq!(
        resumed_config.developer_instructions,
        turn.developer_instructions
    );

    let _ = manager
        .agent_control()
        .shutdown_agent(agent_id)
        .await
        .expect("shutdown resumed agent");
}

#[tokio::test]
async fn resume_agent_rejects_when_depth_limit_exceeded() {
    let (mut session, mut turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let max_depth = turn.config.agent_max_depth;

    turn.session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: session.conversation_id,
        depth: max_depth,
        agent_path: None,
        agent_nickname: None,
        agent_role: None,
    });

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "resume_agent",
        function_payload(json!({"id": ThreadId::new().to_string()})),
    );
    let Err(err) = ResumeAgentHandler.handle(invocation).await else {
        panic!("resume should fail when depth limit exceeded");
    };
    let FunctionCallError::RespondToModel(message) = err else {
        panic!("expected respond-to-model error");
    };
    assert!(message.contains("depth limit reached"));
}

#[tokio::test]
async fn wait_agent_rejects_non_positive_timeout() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "wait_agent",
        function_payload(json!({
            "ids": [ThreadId::new().to_string()],
            "timeout_ms": 0
        })),
    );
    let Err(err) = WaitAgentHandler.handle(invocation).await else {
        panic!("non-positive timeout should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel("timeout_ms must be greater than zero".to_string())
    );
}

#[tokio::test]
async fn wait_agent_rejects_invalid_id() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "wait_agent",
        function_payload(json!({"ids": ["invalid"]})),
    );
    let Err(err) = WaitAgentHandler.handle(invocation).await else {
        panic!("invalid id should be rejected");
    };
    let FunctionCallError::RespondToModel(msg) = err else {
        panic!("expected respond-to-model error");
    };
    assert!(msg.starts_with("invalid agent id invalid:"));
}

#[tokio::test]
async fn wait_agent_rejects_empty_ids() {
    let (session, turn) = make_session_and_context().await;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "wait_agent",
        function_payload(json!({"ids": []})),
    );
    let Err(err) = WaitAgentHandler.handle(invocation).await else {
        panic!("empty ids should be rejected");
    };
    assert_eq!(
        err,
        FunctionCallError::RespondToModel("ids must be non-empty".to_string())
    );
}

#[tokio::test]
async fn wait_agent_returns_not_found_for_missing_agents() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let id_a = ThreadId::new();
    let id_b = ThreadId::new();
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "wait_agent",
        function_payload(json!({
            "ids": [id_a.to_string(), id_b.to_string()],
            "timeout_ms": 1000
        })),
    );
    let output = WaitAgentHandler
        .handle(invocation)
        .await
        .expect("wait_agent should succeed");
    let (content, success) = expect_text_output(output);
    let result: wait::WaitAgentResult =
        serde_json::from_str(&content).expect("wait_agent result should be json");
    assert_eq!(
        result,
        wait::WaitAgentResult {
            status: HashMap::from([(id_a, AgentStatus::NotFound), (id_b, AgentStatus::NotFound),]),
            timed_out: false
        }
    );
    assert_eq!(success, None);
}

#[tokio::test]
async fn wait_agent_times_out_when_status_is_not_final() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let config = turn.config.as_ref().clone();
    let thread = manager.start_thread(config).await.expect("start thread");
    let agent_id = thread.thread_id;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "wait_agent",
        function_payload(json!({
            "ids": [agent_id.to_string()],
            "timeout_ms": MIN_WAIT_TIMEOUT_MS
        })),
    );
    let output = WaitAgentHandler
        .handle(invocation)
        .await
        .expect("wait_agent should succeed");
    let (content, success) = expect_text_output(output);
    let result: wait::WaitAgentResult =
        serde_json::from_str(&content).expect("wait_agent result should be json");
    assert_eq!(
        result,
        wait::WaitAgentResult {
            status: HashMap::new(),
            timed_out: true
        }
    );
    assert_eq!(success, None);

    let _ = thread
        .thread
        .submit(Op::Shutdown {})
        .await
        .expect("shutdown should submit");
}

#[tokio::test]
async fn wait_rejects_watchdog_only_handles() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();

    let owner_thread = manager
        .start_thread(turn.config.as_ref().clone())
        .await
        .expect("start owner thread");
    session.conversation_id = owner_thread.thread_id;

    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;

    let invocation = invocation(
        session.clone(),
        turn,
        "wait",
        function_payload(json!({
            "ids": [watchdog_id.to_string()],
            "timeout_ms": 10
        })),
    );

    let wait_result = timeout(
        Duration::from_millis(250),
        MultiAgentHandler.handle(invocation),
    )
    .await
    .expect("wait should return immediately for watchdog handles");
    let Err(err) = wait_result else {
        panic!("watchdog-only wait should return a correction");
    };
    let FunctionCallError::RespondToModel(message) = err else {
        panic!("expected respond-to-model error");
    };
    assert!(message.contains("wait cannot be used to wait for watchdog check-ins"));
    assert!(message.contains("watchdog interval"));
    assert!(message.contains("Continue the task now or end the turn"));
    assert!(message.contains(&watchdog_id.to_string()));

    let _ = session
        .services
        .agent_control
        .shutdown_agent(watchdog_id)
        .await;
    let _ = session
        .services
        .agent_control
        .shutdown_agent(owner_thread.thread_id)
        .await;
}

#[tokio::test]
async fn wait_rejects_active_watchdog_helper_sessions() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();

    let owner_thread = manager
        .start_thread(turn.config.as_ref().clone())
        .await
        .expect("start owner thread");
    session.conversation_id = owner_thread.thread_id;

    let mut session = Arc::new(session);
    let turn = Arc::new(turn);
    let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;
    let owner_thread_id = owner_thread.thread_id;

    let mut helper_config = turn.config.as_ref().clone();
    helper_config.ephemeral = true;
    let helper_id = session
        .services
        .agent_control
        .spawn_agent_handle(
            helper_config.clone(),
            Some(thread_spawn_source(owner_thread_id, 1)),
        )
        .await
        .expect("spawn helper handle");
    session
        .services
        .agent_control
        .set_watchdog_active_helper_for_tests(watchdog_id, helper_id)
        .await;

    Arc::get_mut(&mut session)
        .expect("no extra session refs")
        .conversation_id = helper_id;
    let (_, mut helper_turn) = make_session_and_context().await;
    helper_turn.session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
        parent_thread_id: owner_thread_id,
        depth: 1,
        agent_path: None,
        agent_nickname: None,
        agent_role: None,
    });
    helper_turn.config = Arc::new(helper_config);
    let helper_turn = Arc::new(helper_turn);
    let invocation = invocation(
        session.clone(),
        helper_turn,
        "wait",
        function_payload(json!({
            "ids": [watchdog_id.to_string()]
        })),
    );

    let Err(err) = MultiAgentHandler.handle(invocation).await else {
        panic!("watchdog helper wait should be rejected");
    };
    let FunctionCallError::RespondToModel(message) = err else {
        panic!("expected model-visible correction");
    };
    assert!(message.contains("wait is not available to watchdog check-in agents"));
    assert!(message.contains("send_input"));

    let _ = session
        .services
        .agent_control
        .shutdown_agent(helper_id)
        .await;
    let _ = session
        .services
        .agent_control
        .shutdown_agent(watchdog_id)
        .await;
    let _ = session
        .services
        .agent_control
        .shutdown_agent(owner_thread_id)
        .await;
}

#[tokio::test]
async fn wait_includes_watchdog_status_when_non_watchdog_is_final() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();

    let owner_thread = manager
        .start_thread(turn.config.as_ref().clone())
        .await
        .expect("start owner thread");
    session.conversation_id = owner_thread.thread_id;

    let worker_thread = manager
        .start_thread(turn.config.as_ref().clone())
        .await
        .expect("start worker thread");
    let worker_id = worker_thread.thread_id;

    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;

    let mut worker_status_rx = session
        .services
        .agent_control
        .subscribe_status(worker_id)
        .await
        .expect("subscribe should succeed");
    let _ = worker_thread
        .thread
        .submit(Op::Shutdown {})
        .await
        .expect("shutdown should submit");
    let _ = timeout(Duration::from_secs(1), worker_status_rx.changed())
        .await
        .expect("shutdown status should arrive");

    let invocation = invocation(
        session.clone(),
        turn,
        "wait",
        function_payload(json!({
            "ids": [watchdog_id.to_string(), worker_id.to_string()],
            "timeout_ms": 10
        })),
    );
    let output = timeout(
        Duration::from_millis(250),
        MultiAgentHandler.handle(invocation),
    )
    .await
    .expect("wait should return quickly when non-watchdog is already final")
    .expect("wait should succeed");

    let (content, success) = expect_text_output(output);
    let result: wait::WaitResult =
        serde_json::from_str(&content).expect("wait result should be json");
    let expected_watchdog_status = session.services.agent_control.get_status(watchdog_id).await;
    assert_eq!(
        result,
        wait::WaitResult {
            status: HashMap::from([
                (watchdog_id, expected_watchdog_status),
                (worker_id, AgentStatus::Shutdown),
            ]),
            timed_out: false
        }
    );
    assert_eq!(success, None);

    let _ = session
        .services
        .agent_control
        .shutdown_agent(watchdog_id)
        .await;
    let _ = session
        .services
        .agent_control
        .shutdown_agent(worker_id)
        .await;
    let _ = session
        .services
        .agent_control
        .shutdown_agent(owner_thread.thread_id)
        .await;
}

#[tokio::test]
async fn wait_clamps_short_timeouts_to_minimum() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let config = turn.config.as_ref().clone();
    let thread = manager.start_thread(config).await.expect("start thread");
    let agent_id = thread.thread_id;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "wait_agent",
        function_payload(json!({
            "ids": [agent_id.to_string()],
            "timeout_ms": 10
        })),
    );

    let early = timeout(
        Duration::from_millis(50),
        WaitAgentHandler.handle(invocation),
    )
    .await;
    assert!(
        early.is_err(),
        "wait_agent should not return before the minimum timeout clamp"
    );

    let _ = thread
        .thread
        .submit(Op::Shutdown {})
        .await
        .expect("shutdown should submit");
}

#[tokio::test]
async fn wait_agent_returns_final_status_without_timeout() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let config = turn.config.as_ref().clone();
    let thread = manager.start_thread(config).await.expect("start thread");
    let agent_id = thread.thread_id;
    let mut status_rx = manager
        .agent_control()
        .subscribe_status(agent_id)
        .await
        .expect("subscribe should succeed");

    let _ = thread
        .thread
        .submit(Op::Shutdown {})
        .await
        .expect("shutdown should submit");
    let _ = timeout(Duration::from_secs(1), status_rx.changed())
        .await
        .expect("shutdown status should arrive");

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "wait_agent",
        function_payload(json!({
            "ids": [agent_id.to_string()],
            "timeout_ms": 1000
        })),
    );
    let output = WaitAgentHandler
        .handle(invocation)
        .await
        .expect("wait_agent should succeed");
    let (content, success) = expect_text_output(output);
    let result: wait::WaitAgentResult =
        serde_json::from_str(&content).expect("wait_agent result should be json");
    assert_eq!(
        result,
        wait::WaitAgentResult {
            status: HashMap::from([(agent_id, AgentStatus::Shutdown)]),
            timed_out: false
        }
    );
    assert_eq!(success, None);
}

#[tokio::test]
async fn wait_returns_non_interrupted_errors_immediately() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let config = turn.config.as_ref().clone();
    let thread = manager.start_thread(config).await.expect("start thread");
    let agent_id = thread.thread_id;

    thread
        .thread
        .codex
        .session
        .send_event_raw(Event {
            id: "err-1".to_string(),
            msg: EventMsg::Error(ErrorEvent {
                message: "boom".to_string(),
                codex_error_info: None,
            }),
        })
        .await;

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "wait",
        function_payload(json!({
            "ids": [agent_id.to_string()],
            "timeout_ms": 1000
        })),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("wait should succeed");
    let (content, success) = expect_text_output(output);
    let result: wait::WaitResult =
        serde_json::from_str(&content).expect("wait result should be json");
    assert_eq!(
        result,
        wait::WaitResult {
            status: HashMap::from([(agent_id, AgentStatus::Errored("boom".to_string()))]),
            timed_out: false
        }
    );
    assert_eq!(success, None);

    let _ = thread
        .thread
        .submit(Op::Shutdown {})
        .await
        .expect("shutdown should submit");
}

#[tokio::test]
async fn wait_for_final_status_ignores_interrupted_status() {
    let (session, _turn) = make_session_and_context().await;
    let agent_id = ThreadId::new();
    let (status_tx, status_rx) = watch::channel(AgentStatus::Interrupted);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        status_tx.send_replace(AgentStatus::Shutdown);
    });

    let result = timeout(
        Duration::from_secs(1),
        wait::wait_for_final_status(Arc::new(session), agent_id, status_rx),
    )
    .await
    .expect("wait should complete once a truly final status arrives");
    assert_eq!(result, Some((agent_id, AgentStatus::Shutdown)));
}

#[tokio::test]
async fn close_agent_submits_shutdown_and_returns_status() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let config = turn.config.as_ref().clone();
    let thread = manager.start_thread(config).await.expect("start thread");
    let agent_id = thread.thread_id;
    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "close_agent",
        function_payload(json!({"id": agent_id.to_string()})),
    );
    let output = CloseAgentHandler
        .handle(invocation)
        .await
        .expect("close_agent should succeed");
    let (content, success) = expect_text_output(output);
    let result: close_agent::CloseAgentResult =
        serde_json::from_str(&content).expect("close_agent result should be json");
    let status_after = manager.agent_control().get_status(agent_id).await;
    assert_eq!(result.status, status_after);
    assert_eq!(result.close_result, close_agent::CloseAgentOutcome::Closed);
    assert_eq!(success, Some(true));

    let ops = manager.captured_ops();
    let submitted_shutdown = ops
        .iter()
        .any(|(id, op)| *id == agent_id && matches!(op, Op::Shutdown));
    assert_eq!(submitted_shutdown, true);

    assert_eq!(status_after, AgentStatus::NotFound);
}

#[tokio::test]
async fn close_agent_reports_already_closed_for_known_id() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let config = turn.config.as_ref().clone();
    let agent_id = session
        .services
        .agent_control
        .spawn_agent_handle(config, None)
        .await
        .expect("spawn agent handle");

    session
        .services
        .agent_control
        .shutdown_agent(agent_id)
        .await
        .expect("shutdown agent");

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "close_agent",
        function_payload(json!({"id": agent_id.to_string()})),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("close_agent should succeed");
    let (content, success) = expect_text_output(output);
    let result: close_agent::CloseAgentResult =
        serde_json::from_str(&content).expect("close_agent result should be json");
    assert_eq!(result.status, AgentStatus::NotFound);
    assert_eq!(
        result.close_result,
        close_agent::CloseAgentOutcome::AlreadyClosed
    );
    assert_eq!(success, Some(true));
}

#[tokio::test]
async fn close_agent_reports_not_found_for_unknown_id() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let unknown_id = ThreadId::new();

    let invocation = invocation(
        Arc::new(session),
        Arc::new(turn),
        "close_agent",
        function_payload(json!({"id": unknown_id.to_string()})),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("close_agent should succeed");
    let (content, success) = expect_text_output(output);
    let result: close_agent::CloseAgentResult =
        serde_json::from_str(&content).expect("close_agent result should be json");
    assert_eq!(result.status, AgentStatus::NotFound);
    assert_eq!(
        result.close_result,
        close_agent::CloseAgentOutcome::NotFound
    );
    assert_eq!(success, Some(true));
}

#[tokio::test]
async fn close_agent_reports_already_closed_for_registered_watchdog_without_live_thread() {
    let (mut session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    session.services.agent_control = manager.agent_control();
    let owner_thread = manager
        .start_thread(turn.config.as_ref().clone())
        .await
        .expect("start owner thread");
    session.conversation_id = owner_thread.thread_id;

    let session = Arc::new(session);
    let turn = Arc::new(turn);
    let watchdog_id = spawn_watchdog_for_test(session.clone(), turn.clone()).await;
    let _ = manager.remove_thread(&watchdog_id).await;

    let invocation = invocation(
        session.clone(),
        turn,
        "close_agent",
        function_payload(json!({"id": watchdog_id.to_string()})),
    );
    let output = MultiAgentHandler
        .handle(invocation)
        .await
        .expect("close_agent should succeed");
    let (content, success) = expect_text_output(output);
    let result: close_agent::CloseAgentResult =
        serde_json::from_str(&content).expect("close_agent result should be json");
    assert_eq!(result.status, AgentStatus::NotFound);
    assert_eq!(
        result.close_result,
        close_agent::CloseAgentOutcome::AlreadyClosed
    );
    assert_eq!(success, Some(true));

    let _ = session
        .services
        .agent_control
        .shutdown_agent(owner_thread.thread_id)
        .await;
}

#[tokio::test]
async fn tool_handlers_cascade_close_and_resume_and_keep_explicitly_closed_subtrees_closed() {
    let (_session, turn) = make_session_and_context().await;
    let manager = thread_manager();
    let mut config = turn.config.as_ref().clone();
    config.agent_max_depth = 3;
    config
        .features
        .enable(Feature::Sqlite)
        .expect("test config should allow sqlite");

    let parent = manager
        .start_thread(config.clone())
        .await
        .expect("parent thread should start");
    let parent_thread_id = parent.thread_id;
    let parent_session = parent.thread.codex.session.clone();

    let child_spawn_output = SpawnAgentHandler
        .handle(invocation(
            parent_session.clone(),
            parent_session.new_default_turn().await,
            "spawn_agent",
            function_payload(json!({"message": "hello child"})),
        ))
        .await
        .expect("child spawn should succeed");
    let (child_content, child_success) = expect_text_output(child_spawn_output);
    let child_result: serde_json::Value =
        serde_json::from_str(&child_content).expect("child spawn result should be json");
    let child_thread_id = agent_id(
        child_result
            .get("agent_id")
            .and_then(serde_json::Value::as_str)
            .expect("child spawn result should include agent_id"),
    )
    .expect("child agent_id should be valid");
    assert_eq!(child_success, Some(true));

    let child_thread = manager
        .get_thread(child_thread_id)
        .await
        .expect("child thread should exist");
    let child_session = child_thread.codex.session.clone();
    let grandchild_spawn_output = SpawnAgentHandler
        .handle(invocation(
            child_session.clone(),
            child_session.new_default_turn().await,
            "spawn_agent",
            function_payload(json!({"message": "hello grandchild"})),
        ))
        .await
        .expect("grandchild spawn should succeed");
    let (grandchild_content, grandchild_success) = expect_text_output(grandchild_spawn_output);
    let grandchild_result: serde_json::Value =
        serde_json::from_str(&grandchild_content).expect("grandchild spawn result should be json");
    let grandchild_thread_id = agent_id(
        grandchild_result
            .get("agent_id")
            .and_then(serde_json::Value::as_str)
            .expect("grandchild spawn result should include agent_id"),
    )
    .expect("grandchild agent_id should be valid");
    assert_eq!(grandchild_success, Some(true));

    let close_output = CloseAgentHandler
        .handle(invocation(
            parent_session.clone(),
            parent_session.new_default_turn().await,
            "close_agent",
            function_payload(json!({"id": child_thread_id.to_string()})),
        ))
        .await
        .expect("close_agent should close the child subtree");
    let (close_content, close_success) = expect_text_output(close_output);
    let close_result: close_agent::CloseAgentResult =
        serde_json::from_str(&close_content).expect("close_agent result should be json");
    assert_eq!(close_result.status, AgentStatus::NotFound);
    assert_eq!(
        close_result.close_result,
        close_agent::CloseAgentOutcome::Closed
    );
    assert_eq!(close_success, Some(true));
    assert_eq!(
        manager.agent_control().get_status(child_thread_id).await,
        AgentStatus::NotFound
    );
    assert_eq!(
        manager
            .agent_control()
            .get_status(grandchild_thread_id)
            .await,
        AgentStatus::NotFound
    );

    let child_resume_output = ResumeAgentHandler
        .handle(invocation(
            parent_session.clone(),
            parent_session.new_default_turn().await,
            "resume_agent",
            function_payload(json!({"id": child_thread_id.to_string()})),
        ))
        .await
        .expect("resume_agent should reopen the child subtree");
    let (child_resume_content, child_resume_success) = expect_text_output(child_resume_output);
    let child_resume_result: resume_agent::ResumeAgentResult =
        serde_json::from_str(&child_resume_content).expect("resume result should be json");
    assert_ne!(child_resume_result.status, AgentStatus::NotFound);
    assert_eq!(child_resume_success, Some(true));
    assert_ne!(
        manager.agent_control().get_status(child_thread_id).await,
        AgentStatus::NotFound
    );
    assert_ne!(
        manager
            .agent_control()
            .get_status(grandchild_thread_id)
            .await,
        AgentStatus::NotFound
    );

    let close_again_output = CloseAgentHandler
        .handle(invocation(
            parent_session.clone(),
            parent_session.new_default_turn().await,
            "close_agent",
            function_payload(json!({"id": child_thread_id.to_string()})),
        ))
        .await
        .expect("close_agent should be repeatable for the child subtree");
    let (close_again_content, close_again_success) = expect_text_output(close_again_output);
    let close_again_result: close_agent::CloseAgentResult =
        serde_json::from_str(&close_again_content)
            .expect("second close_agent result should be json");
    assert_eq!(close_again_result.status, AgentStatus::NotFound);
    assert_eq!(
        close_again_result.close_result,
        close_agent::CloseAgentOutcome::Closed
    );
    assert_eq!(close_again_success, Some(true));
    assert_eq!(
        manager.agent_control().get_status(child_thread_id).await,
        AgentStatus::NotFound
    );
    assert_eq!(
        manager
            .agent_control()
            .get_status(grandchild_thread_id)
            .await,
        AgentStatus::NotFound
    );

    let operator = manager
        .start_thread(config)
        .await
        .expect("operator thread should start");
    let operator_session = operator.thread.codex.session.clone();
    let _ = manager
        .agent_control()
        .shutdown_live_agent(parent_thread_id)
        .await
        .expect("parent shutdown should succeed");
    assert_eq!(
        manager.agent_control().get_status(parent_thread_id).await,
        AgentStatus::NotFound
    );

    let parent_resume_output = ResumeAgentHandler
        .handle(invocation(
            operator_session,
            operator.thread.codex.session.new_default_turn().await,
            "resume_agent",
            function_payload(json!({"id": parent_thread_id.to_string()})),
        ))
        .await
        .expect("resume_agent should reopen the parent thread");
    let (parent_resume_content, parent_resume_success) = expect_text_output(parent_resume_output);
    let parent_resume_result: resume_agent::ResumeAgentResult =
        serde_json::from_str(&parent_resume_content).expect("parent resume result should be json");
    assert_ne!(parent_resume_result.status, AgentStatus::NotFound);
    assert_eq!(parent_resume_success, Some(true));
    assert_ne!(
        manager.agent_control().get_status(parent_thread_id).await,
        AgentStatus::NotFound
    );
    assert_eq!(
        manager.agent_control().get_status(child_thread_id).await,
        AgentStatus::NotFound
    );
    assert_eq!(
        manager
            .agent_control()
            .get_status(grandchild_thread_id)
            .await,
        AgentStatus::NotFound
    );

    let shutdown_report = manager
        .shutdown_all_threads_bounded(Duration::from_secs(5))
        .await;
    assert_eq!(shutdown_report.submit_failed, Vec::<ThreadId>::new());
    assert_eq!(shutdown_report.timed_out, Vec::<ThreadId>::new());
}

#[tokio::test]
async fn build_agent_spawn_config_uses_turn_context_values() {
    fn pick_allowed_sandbox_policy(
        constraint: &crate::config::Constrained<SandboxPolicy>,
        base: SandboxPolicy,
    ) -> SandboxPolicy {
        let candidates = [
            SandboxPolicy::new_read_only_policy(),
            SandboxPolicy::new_workspace_write_policy(),
            SandboxPolicy::DangerFullAccess,
        ];
        candidates
            .into_iter()
            .find(|candidate| *candidate != base && constraint.can_set(candidate).is_ok())
            .unwrap_or(base)
    }

    let (_session, mut turn) = make_session_and_context().await;
    let base_instructions = BaseInstructions {
        text: "base".to_string(),
    };
    turn.developer_instructions = Some("dev".to_string());
    turn.compact_prompt = Some("compact".to_string());
    turn.shell_environment_policy = ShellEnvironmentPolicy {
        use_profile: true,
        ..ShellEnvironmentPolicy::default()
    };
    let temp_dir = tempfile::tempdir().expect("temp dir");
    turn.cwd = temp_dir.path().to_path_buf();
    turn.codex_linux_sandbox_exe = Some(PathBuf::from("/bin/echo"));
    let sandbox_policy = pick_allowed_sandbox_policy(
        &turn.config.permissions.sandbox_policy,
        turn.config.permissions.sandbox_policy.get().clone(),
    );
    let file_system_sandbox_policy =
        FileSystemSandboxPolicy::from_legacy_sandbox_policy(&sandbox_policy, &turn.cwd);
    let network_sandbox_policy = NetworkSandboxPolicy::from(&sandbox_policy);
    turn.sandbox_policy
        .set(sandbox_policy)
        .expect("sandbox policy set");
    turn.file_system_sandbox_policy = file_system_sandbox_policy.clone();
    turn.network_sandbox_policy = network_sandbox_policy;
    turn.approval_policy
        .set(AskForApproval::OnRequest)
        .expect("approval policy set");

    let config = build_agent_spawn_config(
        &base_instructions,
        &turn,
        0,
        SpawnConfigStrategy::ContextFreeSpawn,
    )
    .expect("spawn config");
    let mut expected = (*turn.config).clone();
    expected.base_instructions = Some(base_instructions.text);
    expected.model = Some(turn.model_info.slug.clone());
    expected.model_provider = turn.provider.clone();
    expected.model_reasoning_effort = turn.reasoning_effort;
    expected.model_reasoning_summary = Some(turn.reasoning_summary);
    // build_agent_spawn_config intentionally clears turn-local developer instructions.
    expected.developer_instructions = None;
    expected.compact_prompt = turn.compact_prompt.clone();
    expected.permissions.shell_environment_policy = turn.shell_environment_policy.clone();
    expected.codex_linux_sandbox_exe = turn.codex_linux_sandbox_exe.clone();
    expected.cwd = turn.cwd.clone();
    expected
        .permissions
        .approval_policy
        .set(AskForApproval::OnRequest)
        .expect("approval policy set");
    expected
        .permissions
        .sandbox_policy
        .set(turn.sandbox_policy.get().clone())
        .expect("sandbox policy set");
    expected.permissions.file_system_sandbox_policy = file_system_sandbox_policy;
    expected.permissions.network_sandbox_policy = network_sandbox_policy;
    assert_eq!(config, expected);
}

#[tokio::test]
async fn build_agent_spawn_config_preserves_base_user_instructions() {
    let (_session, mut turn) = make_session_and_context().await;
    let mut base_config = (*turn.config).clone();
    base_config.user_instructions = Some("base-user".to_string());
    turn.user_instructions = Some("resolved-user".to_string());
    turn.config = Arc::new(base_config.clone());
    let base_instructions = BaseInstructions {
        text: "base".to_string(),
    };

    let config = build_agent_spawn_config(
        &base_instructions,
        &turn,
        0,
        SpawnConfigStrategy::ContextFreeSpawn,
    )
    .expect("spawn config");

    assert_eq!(config.user_instructions, base_config.user_instructions);
}

#[tokio::test]
async fn build_agent_resume_config_context_free_uses_shared_fields() {
    let (_session, mut turn) = make_session_and_context().await;
    let mut base_config = (*turn.config).clone();
    base_config.base_instructions = Some("caller-base".to_string());
    base_config.developer_instructions = Some("base-dev".to_string());
    turn.developer_instructions = Some("turn-dev".to_string());
    turn.config = Arc::new(base_config.clone());
    turn.approval_policy
        .set(AskForApproval::OnRequest)
        .expect("approval policy set");

    let config =
        build_agent_resume_config(&turn, 0, &resume_agent::RecordedResumeContext::default())
            .expect("resume config");

    let mut expected = base_config;
    expected.base_instructions = None;
    expected.model = Some(turn.model_info.slug.clone());
    expected.model_provider = turn.provider.clone();
    expected.model_reasoning_effort = turn.reasoning_effort;
    expected.model_reasoning_summary = Some(turn.reasoning_summary);
    expected.compact_prompt = turn.compact_prompt.clone();
    expected.permissions.shell_environment_policy = turn.shell_environment_policy.clone();
    expected.codex_linux_sandbox_exe = turn.codex_linux_sandbox_exe.clone();
    expected.cwd = turn.cwd.clone();
    expected
        .permissions
        .approval_policy
        .set(AskForApproval::OnRequest)
        .expect("approval policy set");
    expected
        .permissions
        .sandbox_policy
        .set(turn.sandbox_policy.get().clone())
        .expect("sandbox policy set");
    assert_eq!(config, expected);
}

#[tokio::test]
async fn build_agent_resume_config_prefers_recorded_developer_instructions() {
    let (_session, mut turn) = make_session_and_context().await;
    let mut base_config = (*turn.config).clone();
    base_config.base_instructions = Some("caller-base".to_string());
    base_config.developer_instructions = Some("base-dev".to_string());
    turn.developer_instructions = Some("turn-dev".to_string());
    turn.config = Arc::new(base_config.clone());
    turn.approval_policy
        .set(AskForApproval::OnRequest)
        .expect("approval policy set");

    let recorded_resume_context = resume_agent::RecordedResumeContext {
        developer_instructions: Some(turn.developer_instructions.clone()),
        model: Some("gpt-5.1-codex-mini".to_string()),
        reasoning_effort: Some(Some(ReasoningEffort::High)),
    };
    let config =
        build_agent_resume_config(&turn, 0, &recorded_resume_context).expect("resume config");

    let mut expected = base_config;
    expected.base_instructions = None;
    expected.developer_instructions = turn.developer_instructions.clone();
    expected.model = Some("gpt-5.1-codex-mini".to_string());
    expected.model_provider = turn.provider.clone();
    expected.model_reasoning_effort = Some(ReasoningEffort::High);
    expected.model_reasoning_summary = Some(turn.reasoning_summary);
    expected.compact_prompt = turn.compact_prompt.clone();
    expected.permissions.shell_environment_policy = turn.shell_environment_policy.clone();
    expected.codex_linux_sandbox_exe = turn.codex_linux_sandbox_exe.clone();
    expected.cwd = turn.cwd.clone();
    expected
        .permissions
        .approval_policy
        .set(AskForApproval::OnRequest)
        .expect("approval policy set");
    expected
        .permissions
        .sandbox_policy
        .set(turn.sandbox_policy.get().clone())
        .expect("sandbox policy set");
    assert_eq!(config, expected);
}

#[tokio::test]
async fn build_agent_spawn_config_fork_like_uses_turn_developer_instructions() {
    let (_session, mut turn) = make_session_and_context().await;
    let mut base_config = (*turn.config).clone();
    base_config.developer_instructions = Some("base-dev".to_string());
    base_config
        .features
        .enable(Feature::Collab)
        .expect("collab feature enable");
    turn.config = Arc::new(base_config.clone());
    turn.developer_instructions = Some("turn-dev".to_string());
    let base_instructions = BaseInstructions {
        text: "base".to_string(),
    };

    let config =
        build_agent_spawn_config(&base_instructions, &turn, 0, SpawnConfigStrategy::ForkLike)
            .expect("fork-like spawn config");

    assert_eq!(config.developer_instructions, turn.developer_instructions);
    assert_eq!(
        config.features.enabled(Feature::Collab),
        base_config.features.enabled(Feature::Collab)
    );
}

#[tokio::test]
async fn build_agent_spawn_config_context_free_hides_multi_agent_tools_at_max_depth() {
    let (_session, mut turn) = make_session_and_context().await;
    let mut base_config = (*turn.config).clone();
    base_config
        .features
        .enable(Feature::Collab)
        .expect("collab feature enable");
    base_config
        .features
        .enable(Feature::SpawnCsv)
        .expect("spawn csv feature enable");
    turn.config = Arc::new(base_config);
    let base_instructions = BaseInstructions {
        text: "base".to_string(),
    };

    let config = build_agent_spawn_config(
        &base_instructions,
        &turn,
        turn.config.agent_max_depth,
        SpawnConfigStrategy::ContextFreeSpawn,
    )
    .expect("context-free spawn config");

    assert_eq!(config.features.enabled(Feature::Collab), false);
    assert_eq!(config.features.enabled(Feature::SpawnCsv), false);
}

#[tokio::test]
async fn build_agent_spawn_config_context_free_hides_multi_agent_tools_past_max_depth() {
    let (_session, mut turn) = make_session_and_context().await;
    let mut base_config = (*turn.config).clone();
    base_config
        .features
        .enable(Feature::Collab)
        .expect("collab feature enable");
    base_config
        .features
        .enable(Feature::SpawnCsv)
        .expect("spawn csv feature enable");
    turn.config = Arc::new(base_config);
    let base_instructions = BaseInstructions {
        text: "base".to_string(),
    };

    let config = build_agent_spawn_config(
        &base_instructions,
        &turn,
        turn.config.agent_max_depth + 1,
        SpawnConfigStrategy::ContextFreeSpawn,
    )
    .expect("context-free spawn config");

    assert_eq!(config.features.enabled(Feature::Collab), false);
    assert_eq!(config.features.enabled(Feature::SpawnCsv), false);
}
