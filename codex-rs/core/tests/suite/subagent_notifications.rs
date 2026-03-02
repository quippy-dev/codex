use anyhow::Context;
use anyhow::Result;
use codex_core::features::Feature;
use codex_protocol::ThreadId;
use codex_protocol::config_types::ReasoningSummary;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::SandboxPolicy;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ResponsesRequest;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_function_call;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::mount_response_once_match;
use core_test_support::responses::mount_sse_once_match;
use core_test_support::responses::sse;
use core_test_support::responses::sse_response;
use core_test_support::responses::start_mock_server;
use core_test_support::skip_if_no_network;
use core_test_support::test_codex::TestCodex;
use core_test_support::test_codex::test_codex;
use serde_json::json;
use std::time::Duration;
use tokio::time::Instant;
use tokio::time::sleep;
use wiremock::MockServer;

const SPAWN_CALL_ID: &str = "spawn-call-1";
const WAIT_CALL_ID: &str = "wait-call-1";
const TURN_0_FORK_PROMPT: &str = "seed fork context";
const TURN_1_PROMPT: &str = "spawn a child and continue";
const TURN_2_NO_WAIT_PROMPT: &str = "follow up without wait";
const TURN_2_WAIT_PROMPT: &str = "wait for child completion";
const TURN_2_WAIT_UNRELATED_PROMPT: &str = "wait on unrelated id";
const TURN_3_PROMPT: &str = "next turn after wait";
const CHILD_PROMPT: &str = "child: do work";

fn body_contains(req: &wiremock::Request, text: &str) -> bool {
    let is_zstd = req
        .headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|entry| entry.trim().eq_ignore_ascii_case("zstd"))
        });
    let bytes = if is_zstd {
        zstd::stream::decode_all(std::io::Cursor::new(&req.body)).ok()
    } else {
        Some(req.body.clone())
    };
    bytes
        .and_then(|body| String::from_utf8(body).ok())
        .is_some_and(|body| body.contains(text))
}

fn body_contains_function_call_output(req: &wiremock::Request, call_id: &str) -> bool {
    body_contains(req, "\"type\":\"function_call_output\"") && body_contains(req, call_id)
}

fn has_subagent_notification(req: &ResponsesRequest) -> bool {
    req.message_input_texts("user")
        .iter()
        .any(|text| text.contains("<subagent_notification>"))
}

fn wait_call_args(agent_id: &str) -> Result<String> {
    serde_json::to_string(&json!({
        "ids": [agent_id],
    }))
    .context("serialize wait args")
}

async fn submit_turn_no_wait(test: &TestCodex, prompt: &str) -> Result<()> {
    let session_model = test.session_configured.model.clone();
    let _ = test
        .codex
        .submit(Op::UserTurn {
            items: vec![UserInput::Text {
                text: prompt.into(),
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
            cwd: test.cwd.path().to_path_buf(),
            approval_policy: AskForApproval::Never,
            sandbox_policy: SandboxPolicy::DangerFullAccess,
            model: session_model,
            effort: None,
            summary: Some(ReasoningSummary::Auto),
            collaboration_mode: None,
            personality: None,
        })
        .await?;
    Ok(())
}

async fn wait_for_spawned_thread_id(test: &TestCodex) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let ids = test.thread_manager.list_thread_ids().await;
        if let Some(spawned_id) = ids
            .iter()
            .find(|id| **id != test.session_configured.session_id)
        {
            return Ok(spawned_id.to_string());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for spawned thread id");
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_requests(
    mock: &core_test_support::responses::ResponseMock,
) -> Result<Vec<ResponsesRequest>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let requests = mock.requests();
        if !requests.is_empty() {
            return Ok(requests);
        }
        if Instant::now() >= deadline {
            anyhow::bail!("expected at least 1 request, got {}", requests.len());
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn setup_turn_one_with_spawned_child(
    server: &MockServer,
    child_response_delay: Option<Duration>,
) -> Result<(TestCodex, String)> {
    let spawn_args = serde_json::to_string(&json!({
        "message": CHILD_PROMPT,
    }))?;

    mount_sse_once_match(
        server,
        |req: &wiremock::Request| body_contains(req, TURN_1_PROMPT),
        sse(vec![
            ev_response_created("resp-turn1-1"),
            ev_function_call(SPAWN_CALL_ID, "spawn_agent", &spawn_args),
            ev_completed("resp-turn1-1"),
        ]),
    )
    .await;

    let child_sse = sse(vec![
        ev_response_created("resp-child-1"),
        ev_assistant_message("msg-child-1", "child done"),
        ev_completed("resp-child-1"),
    ]);
    let child_request_log = if let Some(delay) = child_response_delay {
        mount_response_once_match(
            server,
            |req: &wiremock::Request| {
                body_contains(req, CHILD_PROMPT) && !body_contains(req, SPAWN_CALL_ID)
            },
            sse_response(child_sse).set_delay(delay),
        )
        .await
    } else {
        mount_sse_once_match(
            server,
            |req: &wiremock::Request| {
                body_contains(req, CHILD_PROMPT) && !body_contains(req, SPAWN_CALL_ID)
            },
            child_sse,
        )
        .await
    };

    let _turn1_followup = mount_sse_once_match(
        server,
        |req: &wiremock::Request| body_contains(req, SPAWN_CALL_ID),
        sse(vec![
            ev_response_created("resp-turn1-2"),
            ev_assistant_message("msg-turn1-2", "parent done"),
            ev_completed("resp-turn1-2"),
        ]),
    )
    .await;

    let mut builder = test_codex().with_config(|config| {
        config.features.enable(Feature::Collab);
    });
    let test = builder.build(server).await?;
    submit_turn_no_wait(&test, TURN_1_PROMPT).await?;
    if child_response_delay.is_none() {
        let _ = wait_for_requests(&child_request_log).await?;
        let rollout_path = test
            .codex
            .rollout_path()
            .ok_or_else(|| anyhow::anyhow!("expected parent rollout path"))?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let has_notification = tokio::fs::read_to_string(&rollout_path)
                .await
                .is_ok_and(|rollout| rollout.contains("<subagent_notification>"));
            if has_notification {
                break;
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "timed out waiting for parent rollout to include subagent notification"
                );
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
    let spawned_id = wait_for_spawned_thread_id(&test).await?;

    Ok((test, spawned_id))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subagent_notification_is_included_without_wait() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let (test, _spawned_id) = setup_turn_one_with_spawned_child(&server, None).await?;

    let turn2 = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains(req, TURN_2_NO_WAIT_PROMPT),
        sse(vec![
            ev_response_created("resp-turn2-1"),
            ev_assistant_message("msg-turn2-1", "no wait path"),
            ev_completed("resp-turn2-1"),
        ]),
    )
    .await;
    submit_turn_no_wait(&test, TURN_2_NO_WAIT_PROMPT).await?;

    let turn2_requests = wait_for_requests(&turn2).await?;
    assert!(turn2_requests.iter().any(has_subagent_notification));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subagent_notification_is_deduped_after_matching_wait() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let (test, spawned_id) = setup_turn_one_with_spawned_child(&server, None).await?;

    let wait_args = wait_call_args(&spawned_id)?;
    let turn2_wait = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains(req, TURN_2_WAIT_PROMPT),
        sse(vec![
            ev_response_created("resp-turn2-1"),
            ev_function_call(WAIT_CALL_ID, "wait", &wait_args),
            ev_completed("resp-turn2-1"),
        ]),
    )
    .await;
    let turn2_wait_followup = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains_function_call_output(req, WAIT_CALL_ID),
        sse(vec![
            ev_response_created("resp-turn2-2"),
            ev_assistant_message("msg-turn2-2", "waited"),
            ev_completed("resp-turn2-2"),
        ]),
    )
    .await;
    submit_turn_no_wait(&test, TURN_2_WAIT_PROMPT).await?;
    let _ = wait_for_requests(&turn2_wait)
        .await
        .context("turn2 wait call request not observed")?;
    let _ = wait_for_requests(&turn2_wait_followup)
        .await
        .context("turn2 wait followup request not observed")?;

    let turn3 = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains(req, TURN_3_PROMPT),
        sse(vec![
            ev_response_created("resp-turn3-1"),
            ev_assistant_message("msg-turn3-1", "after wait"),
            ev_completed("resp-turn3-1"),
        ]),
    )
    .await;
    submit_turn_no_wait(&test, TURN_3_PROMPT).await?;

    let turn3_requests = wait_for_requests(&turn3).await?;
    assert!(turn3_requests.iter().any(has_subagent_notification));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subagent_notification_is_deduped_when_wait_finishes_child_in_flight() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let (test, spawned_id) =
        setup_turn_one_with_spawned_child(&server, Some(Duration::from_millis(500))).await?;

    let wait_args = wait_call_args(&spawned_id)?;
    let turn2_wait = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains(req, TURN_2_WAIT_PROMPT),
        sse(vec![
            ev_response_created("resp-turn2f-1"),
            ev_function_call(WAIT_CALL_ID, "wait", &wait_args),
            ev_completed("resp-turn2f-1"),
        ]),
    )
    .await;
    let turn2_wait_followup = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains_function_call_output(req, WAIT_CALL_ID),
        sse(vec![
            ev_response_created("resp-turn2f-2"),
            ev_assistant_message("msg-turn2f-2", "waited in flight"),
            ev_completed("resp-turn2f-2"),
        ]),
    )
    .await;
    submit_turn_no_wait(&test, TURN_2_WAIT_PROMPT).await?;
    let _ = wait_for_requests(&turn2_wait)
        .await
        .context("turn2 in-flight wait call request not observed")?;
    let _ = wait_for_requests(&turn2_wait_followup)
        .await
        .context("turn2 in-flight wait followup request not observed")?;

    let turn3 = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains(req, TURN_3_PROMPT),
        sse(vec![
            ev_response_created("resp-turn3f-1"),
            ev_assistant_message("msg-turn3f-1", "after in-flight wait"),
            ev_completed("resp-turn3f-1"),
        ]),
    )
    .await;
    submit_turn_no_wait(&test, TURN_3_PROMPT).await?;

    let turn3_requests = wait_for_requests(&turn3).await?;
    assert!(turn3_requests.iter().any(has_subagent_notification));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subagent_notification_is_kept_after_non_matching_wait() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let (test, _spawned_id) = setup_turn_one_with_spawned_child(&server, None).await?;

    let unrelated_agent_id = ThreadId::new().to_string();
    let wait_args = wait_call_args(&unrelated_agent_id)?;
    let turn2_wait = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains(req, TURN_2_WAIT_UNRELATED_PROMPT),
        sse(vec![
            ev_response_created("resp-turn2u-1"),
            ev_function_call(WAIT_CALL_ID, "wait", &wait_args),
            ev_completed("resp-turn2u-1"),
        ]),
    )
    .await;
    let turn2_wait_followup = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains_function_call_output(req, WAIT_CALL_ID),
        sse(vec![
            ev_response_created("resp-turn2u-2"),
            ev_assistant_message("msg-turn2u-2", "waited unrelated"),
            ev_completed("resp-turn2u-2"),
        ]),
    )
    .await;
    submit_turn_no_wait(&test, TURN_2_WAIT_UNRELATED_PROMPT).await?;
    let _ = wait_for_requests(&turn2_wait)
        .await
        .context("turn2 unrelated wait call request not observed")?;
    let _ = wait_for_requests(&turn2_wait_followup)
        .await
        .context("turn2 unrelated wait followup request not observed")?;

    let turn3 = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains(req, TURN_3_PROMPT),
        sse(vec![
            ev_response_created("resp-turn3u-1"),
            ev_assistant_message("msg-turn3u-1", "after unrelated wait"),
            ev_completed("resp-turn3u-1"),
        ]),
    )
    .await;
    submit_turn_no_wait(&test, TURN_3_PROMPT).await?;

    let turn3_requests = wait_for_requests(&turn3).await?;
    assert!(turn3_requests.iter().any(has_subagent_notification));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawned_child_receives_forked_parent_context() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;

    let seed_turn = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains(req, TURN_0_FORK_PROMPT),
        sse(vec![
            ev_response_created("resp-seed-1"),
            ev_assistant_message("msg-seed-1", "seeded"),
            ev_completed("resp-seed-1"),
        ]),
    )
    .await;

    let spawn_args = serde_json::to_string(&json!({
        "message": CHILD_PROMPT,
        "spawn_mode": "fork",
    }))?;
    let spawn_turn = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains(req, TURN_1_PROMPT),
        sse(vec![
            ev_response_created("resp-turn1-1"),
            ev_function_call(SPAWN_CALL_ID, "spawn_agent", &spawn_args),
            ev_completed("resp-turn1-1"),
        ]),
    )
    .await;

    let _child_request_log = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains(req, CHILD_PROMPT),
        sse(vec![
            ev_response_created("resp-child-1"),
            ev_assistant_message("msg-child-1", "child done"),
            ev_completed("resp-child-1"),
        ]),
    )
    .await;

    let _turn1_followup = mount_sse_once_match(
        &server,
        |req: &wiremock::Request| body_contains(req, SPAWN_CALL_ID),
        sse(vec![
            ev_response_created("resp-turn1-2"),
            ev_assistant_message("msg-turn1-2", "parent done"),
            ev_completed("resp-turn1-2"),
        ]),
    )
    .await;

    let mut builder = test_codex().with_config(|config| {
        config.features.enable(Feature::Collab);
    });
    let test = builder.build(&server).await?;

    test.submit_turn(TURN_0_FORK_PROMPT).await?;
    let _ = seed_turn.single_request();

    test.submit_turn(TURN_1_PROMPT).await?;
    let _ = spawn_turn.single_request();

    let deadline = Instant::now() + Duration::from_secs(6);
    let child_request = loop {
        if let Some(request) = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|request| body_contains(request, CHILD_PROMPT))
        {
            break request;
        }
        if Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for forked child request");
        }
        sleep(Duration::from_millis(10)).await;
    };
    assert!(body_contains(&child_request, TURN_0_FORK_PROMPT));
    assert!(body_contains(&child_request, "seeded"));

    let child_body = child_request
        .body_json::<serde_json::Value>()
        .expect("forked child request body should be json");
    let has_spawn_result_output = child_body["input"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| {
            item["type"].as_str() == Some("function_call_output")
                && item["call_id"].as_str() == Some(SPAWN_CALL_ID)
        })
        .any(|function_call_output| {
            let output_text = match &function_call_output["output"] {
                serde_json::Value::String(text) => Some(text.as_str()),
                serde_json::Value::Object(output) => {
                    if output.get("success").and_then(serde_json::Value::as_bool) == Some(false) {
                        return false;
                    }
                    output.get("content").and_then(serde_json::Value::as_str)
                }
                _ => None,
            };
            output_text
                .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
                .and_then(|json| {
                    json.get("agent_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .is_some()
        });
    assert!(
        has_spawn_result_output,
        "expected forked child request to include spawn_agent result output: {child_body}"
    );

    Ok(())
}
