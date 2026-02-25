use codex_core::NewThread;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
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

    // Grab the base rollout path for the first fork.
    let base_path = codex.rollout_path().expect("rollout path");

    // Fork once with n=1 → drops the last user input and everything after.
    let NewThread {
        thread_id: _fork1_thread_id,
        thread: codex_fork1,
        session_configured: _fork1_session_configured,
        ..
    } = thread_manager
        .fork_thread(1, config_for_fork.clone(), base_path.clone(), false)
        .await
        .expect("fork 1");

    let fork1_path = codex_fork1.rollout_path().expect("fork1 rollout path");

    // Fork again with n=0 → drops the (new) last user message, leaving only the first.
    let NewThread {
        thread_id: _fork2_thread_id,
        thread: _codex_fork2,
        session_configured: fork2_session_configured,
        ..
    } = thread_manager
        .fork_thread(0, config_for_fork.clone(), fork1_path.clone(), false)
        .await
        .expect("fork 2");
    let fork2_path = fork2_session_configured
        .rollout_path
        .expect("fork2 rollout path");
    assert_ne!(fork2_path, base_path);
    assert_ne!(fork2_path, fork1_path);
}
