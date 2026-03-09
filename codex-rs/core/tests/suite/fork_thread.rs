use codex_core::NewThread;
use codex_core::parse_turn_item;
use codex_protocol::items::TurnItem;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::RolloutItem;
use codex_protocol::protocol::RolloutLine;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::sse;
use core_test_support::skip_if_no_network;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

fn find_user_input_positions(items: &[RolloutItem]) -> Vec<usize> {
    let mut pos = Vec::new();
    for (i, it) in items.iter().enumerate() {
        if let RolloutItem::ResponseItem(response_item) = it
            && let Some(TurnItem::UserMessage(_)) = parse_turn_item(response_item)
        {
            pos.push(i);
        }
    }
    pos
}

fn truncate_before_nth_user_message(
    items: &[RolloutItem],
    nth_user_message: usize,
) -> Vec<RolloutItem> {
    if nth_user_message == usize::MAX {
        return items.to_vec();
    }
    let user_inputs = find_user_input_positions(items);
    let Some(cut_idx) = user_inputs.get(nth_user_message).copied() else {
        return Vec::new();
    };
    items[..cut_idx].to_vec()
}

fn rollout_items_match(lhs: &RolloutItem, rhs: &RolloutItem) -> bool {
    match (serde_json::to_value(lhs), serde_json::to_value(rhs)) {
        (Ok(lhs), Ok(rhs)) => lhs == rhs,
        _ => false,
    }
}

fn rollout_items_start_with(items: &[RolloutItem], prefix: &[RolloutItem]) -> bool {
    items.len() >= prefix.len()
        && items
            .iter()
            .zip(prefix.iter())
            .all(|(item, prefix_item)| rollout_items_match(item, prefix_item))
}

fn materialize_rollout_items(items: &[RolloutItem]) -> Vec<RolloutItem> {
    let mut materialized = Vec::new();
    let mut idx = 0;

    while idx < items.len() {
        match &items[idx] {
            RolloutItem::SessionMeta(_) => {
                idx += 1;
            }
            RolloutItem::ForkReference(reference) => {
                let parent_text =
                    std::fs::read_to_string(&reference.rollout_path).unwrap_or_else(|err| {
                        panic!("read rollout file {:?}: {err}", reference.rollout_path)
                    });
                let mut parent_raw_items = Vec::new();
                for line in parent_text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let value: serde_json::Value = serde_json::from_str(line)
                        .unwrap_or_else(|err| panic!("jsonl line parse: {err}"));
                    let rollout_line: RolloutLine = serde_json::from_value(value)
                        .unwrap_or_else(|err| panic!("rollout line parse: {err}"));
                    parent_raw_items.push(rollout_line.item);
                }

                let raw_parent_items =
                    truncate_before_nth_user_message(&parent_raw_items, reference.nth_user_message);
                let parent_items = read_items_materialized(&reference.rollout_path);
                let truncated_parent_items =
                    truncate_before_nth_user_message(&parent_items, reference.nth_user_message);
                let remaining_items = &items[idx + 1..];
                let copied_materialized_parent_prefix =
                    rollout_items_start_with(remaining_items, &truncated_parent_items);
                let copied_raw_parent_prefix =
                    rollout_items_start_with(remaining_items, &raw_parent_items);
                let copied_parent_prefix =
                    copied_materialized_parent_prefix || copied_raw_parent_prefix;
                let copied_parent_prefix_len = if copied_parent_prefix {
                    if copied_materialized_parent_prefix {
                        truncated_parent_items.len()
                    } else {
                        raw_parent_items.len()
                    }
                } else {
                    0
                };
                materialized.extend(truncated_parent_items);
                idx += 1 + copied_parent_prefix_len;
            }
            item => {
                materialized.push(item.clone());
                idx += 1;
            }
        }
    }

    materialized
}

fn read_items_materialized(p: &std::path::Path) -> Vec<RolloutItem> {
    let text =
        std::fs::read_to_string(p).unwrap_or_else(|err| panic!("read rollout file {p:?}: {err}"));
    let mut raw_items: Vec<RolloutItem> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|err| panic!("jsonl line parse: {err}"));
        let rl: RolloutLine =
            serde_json::from_value(v).unwrap_or_else(|err| panic!("rollout line parse: {err}"));
        raw_items.push(rl.item);
    }
    materialize_rollout_items(&raw_items)
}

fn read_items_raw(p: &std::path::Path) -> Vec<RolloutItem> {
    let text =
        std::fs::read_to_string(p).unwrap_or_else(|err| panic!("read rollout file {p:?}: {err}"));
    let mut raw_items: Vec<RolloutItem> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|err| panic!("jsonl line parse: {err}"));
        let rl: RolloutLine =
            serde_json::from_value(v).unwrap_or_else(|err| panic!("rollout line parse: {err}"));
        if !matches!(rl.item, RolloutItem::SessionMeta(_)) {
            raw_items.push(rl.item);
        }
    }
    raw_items
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fork_thread_twice_drops_to_first_message() {
    skip_if_no_network!();

    // Start a mock server that completes three turns.
    let server = MockServer::start().await;
    let sse = sse(vec![ev_response_created("resp"), ev_completed("resp")]);
    let first = ResponseTemplate::new(200)
        .insert_header("content-type", "text/event-stream")
        .set_body_raw(sse.clone(), "text/event-stream");

    // Expect three calls to /v1/responses – one per user input.
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(first)
        .expect(3)
        .mount(&server)
        .await;

    let mut builder = test_codex();
    let test = builder.build(&server).await.expect("create conversation");
    let codex = test.codex.clone();
    let thread_manager = test.thread_manager.clone();
    let config_for_fork = test.config.clone();

    // Send three user messages; wait for three completed turns.
    for text in ["first", "second", "third"] {
        codex
            .submit(Op::UserInput {
                items: vec![UserInput::Text {
                    text: text.to_string(),
                    text_elements: Vec::new(),
                }],
                final_output_json_schema: None,
            })
            .await
            .unwrap();
        let _ = wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;
    }

    // Request history from the base conversation to obtain rollout path.
    let base_path = codex.rollout_path().expect("rollout path");

    // GetHistory flushes before returning the path; no wait needed.

    // Compute expected prefixes after each fork by truncating base rollout
    // strictly before the nth user input (0-based).
    let base_items = read_items_materialized(&base_path);
    let user_inputs = find_user_input_positions(&base_items);

    // After cutting at nth user input (n=1 → second user message), cut strictly before that input.
    let cut1 = user_inputs.get(1).copied().unwrap_or(0);
    let expected_after_first: Vec<RolloutItem> = base_items[..cut1].to_vec();

    // After dropping again (n=1 on fork1), compute expected relative to fork1's rollout.

    // Fork once with n=1 → drops the last user input and everything after.
    let NewThread {
        thread: codex_fork1,
        ..
    } = thread_manager
        .fork_thread(1, config_for_fork.clone(), base_path.clone(), false)
        .await
        .expect("fork 1");

    let fork1_path = codex_fork1.rollout_path().expect("rollout path");

    // GetHistory on fork1 flushed; the file is ready.
    let fork1_raw_items = read_items_raw(&fork1_path);
    assert!(
        matches!(fork1_raw_items.first(), Some(RolloutItem::ForkReference(_))),
        "forked rollout should retain a fork reference marker"
    );
    let fork1_items = read_items_materialized(&fork1_path);
    assert_eq!(
        find_user_input_positions(&fork1_items).len(),
        find_user_input_positions(&expected_after_first).len(),
        "fork replay should not duplicate inherited user turns"
    );
    pretty_assertions::assert_eq!(
        serde_json::to_value(&fork1_items[..expected_after_first.len()]).unwrap(),
        serde_json::to_value(&expected_after_first).unwrap()
    );

    // Fork again with n=0 → drops the (new) last user message, leaving only the first.
    let NewThread {
        thread: codex_fork2,
        ..
    } = thread_manager
        .fork_thread(0, config_for_fork.clone(), fork1_path.clone(), false)
        .await
        .expect("fork 2");

    let fork2_path = codex_fork2.rollout_path().expect("rollout path");
    // GetHistory on fork2 flushed; the file is ready.
    let fork2_items = read_items_materialized(&fork2_path);
    assert!(
        find_user_input_positions(&fork2_items).is_empty(),
        "forking a single-turn fork with n=0 should drop the remaining user turn"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fork_thread_twice_with_nonzero_cut_keeps_expected_prefix() {
    skip_if_no_network!();

    let server = MockServer::start().await;
    let sse = sse(vec![ev_response_created("resp"), ev_completed("resp")]);
    let first = ResponseTemplate::new(200)
        .insert_header("content-type", "text/event-stream")
        .set_body_raw(sse.clone(), "text/event-stream");

    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(first)
        .expect(4)
        .mount(&server)
        .await;

    let mut builder = test_codex();
    let test = builder.build(&server).await.expect("create conversation");
    let codex = test.codex.clone();
    let thread_manager = test.thread_manager.clone();
    let config_for_fork = test.config.clone();

    for text in ["first", "second", "third", "fourth"] {
        codex
            .submit(Op::UserInput {
                items: vec![UserInput::Text {
                    text: text.to_string(),
                    text_elements: Vec::new(),
                }],
                final_output_json_schema: None,
            })
            .await
            .unwrap();
        let _ = wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;
    }

    let base_path = codex.rollout_path().expect("rollout path");
    let base_items = read_items_materialized(&base_path);
    let expected_after_first = truncate_before_nth_user_message(&base_items, 2);

    let NewThread {
        thread: codex_fork1,
        ..
    } = thread_manager
        .fork_thread(2, config_for_fork.clone(), base_path, false)
        .await
        .expect("fork 1");
    let fork1_path = codex_fork1.rollout_path().expect("rollout path");
    let fork1_items = read_items_materialized(&fork1_path);
    assert_eq!(
        find_user_input_positions(&fork1_items).len(),
        find_user_input_positions(&expected_after_first).len(),
    );
    pretty_assertions::assert_eq!(
        serde_json::to_value(&fork1_items[..expected_after_first.len()]).unwrap(),
        serde_json::to_value(&expected_after_first).unwrap()
    );

    let expected_after_second = truncate_before_nth_user_message(&expected_after_first, 1);
    let NewThread {
        thread: codex_fork2,
        ..
    } = thread_manager
        .fork_thread(1, config_for_fork, fork1_path, false)
        .await
        .expect("fork 2");
    let fork2_path = codex_fork2.rollout_path().expect("rollout path");
    let fork2_items = read_items_materialized(&fork2_path);
    assert_eq!(
        find_user_input_positions(&fork2_items).len(),
        find_user_input_positions(&expected_after_second).len(),
        "nested fork replay should preserve the inherited user-turn prefix exactly once"
    );
    pretty_assertions::assert_eq!(
        serde_json::to_value(&fork2_items[..expected_after_second.len()]).unwrap(),
        serde_json::to_value(&expected_after_second).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fork_thread_session_configured_preserves_parent_and_history() {
    skip_if_no_network!();

    let server = MockServer::start().await;
    let sse = sse(vec![ev_response_created("resp"), ev_completed("resp")]);
    let first = ResponseTemplate::new(200)
        .insert_header("content-type", "text/event-stream")
        .set_body_raw(sse, "text/event-stream");

    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(first)
        .expect(1)
        .mount(&server)
        .await;

    let mut builder = test_codex();
    let test = builder.build(&server).await.expect("create conversation");
    let codex = test.codex.clone();
    let thread_manager = test.thread_manager.clone();
    let config_for_fork = test.config.clone();
    let parent_thread_id = test.session_configured.session_id;

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "seed".to_string(),
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
        })
        .await
        .unwrap();
    let _ = wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    let base_path = codex.rollout_path().expect("rollout path");

    let NewThread {
        thread_id: child_thread_id,
        session_configured,
        ..
    } = thread_manager
        .fork_thread(usize::MAX, config_for_fork, base_path, false)
        .await
        .expect("fork thread");

    pretty_assertions::assert_eq!(session_configured.forked_from_id, Some(parent_thread_id));
    assert_ne!(child_thread_id, parent_thread_id);
    assert!(
        session_configured
            .initial_messages
            .as_ref()
            .is_some_and(|messages| {
                messages
                    .iter()
                    .filter(|message| matches!(message, EventMsg::UserMessage(_)))
                    .count()
                    == 1
            })
    );
}
