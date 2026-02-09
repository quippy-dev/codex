use std::sync::Arc;

use crate::ModelProviderInfo;
use crate::Prompt;
use crate::client::ModelClientSession;
use crate::client_common::ResponseEvent;
use crate::codex::Session;
use crate::codex::TurnContext;
use crate::codex::get_last_assistant_message_from_turn;
use crate::error::CodexErr;
use crate::error::Result as CodexResult;
use crate::protocol::CompactedItem;
use crate::protocol::EventMsg;
use crate::protocol::TurnContextItem;
use crate::protocol::TurnStartedEvent;
use crate::protocol::WarningEvent;
use crate::util::backoff;
use codex_protocol::items::ContextCompactionItem;
use codex_protocol::items::TurnItem;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::RolloutItem;
use codex_protocol::user_input::UserInput;
use futures::prelude::*;
use tracing::error;

pub(crate) mod context_trim;
mod history;

pub(crate) use history::build_compacted_history;
pub(crate) use history::collect_user_messages;
pub(crate) use history::process_compacted_history;

pub const SUMMARIZATION_PROMPT: &str = include_str!("../templates/compact/prompt.md");
pub const SUMMARY_PREFIX: &str = include_str!("../templates/compact/summary_prefix.md");

pub(crate) fn should_use_remote_compact_task(provider: &ModelProviderInfo) -> bool {
    provider.is_openai()
}

pub(crate) async fn run_inline_auto_compact_task(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
) -> CodexResult<()> {
    let prompt = turn_context.compact_prompt().to_string();
    let input = vec![UserInput::Text {
        text: prompt,
        // Compaction prompt is synthesized; no UI element ranges to preserve.
        text_elements: Vec::new(),
    }];

    run_compact_task_inner(sess, turn_context, input).await?;
    Ok(())
}

pub(crate) async fn run_compact_task(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
    input: Vec<UserInput>,
) -> CodexResult<()> {
    let start_event = EventMsg::TurnStarted(TurnStartedEvent {
        model_context_window: turn_context.model_context_window(),
        collaboration_mode_kind: turn_context.collaboration_mode.mode,
    });
    sess.send_event(&turn_context, start_event).await;
    run_compact_task_inner(sess.clone(), turn_context, input).await
}

async fn run_compact_task_inner(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
    input: Vec<UserInput>,
) -> CodexResult<()> {
    let compaction_item = TurnItem::ContextCompaction(ContextCompactionItem::new());
    sess.emit_turn_item_started(&turn_context, &compaction_item)
        .await;
    let initial_input_for_turn: ResponseInputItem = ResponseInputItem::from(input);

    let mut history = sess.clone_history().await;
    history.record_items(
        &[initial_input_for_turn.into()],
        turn_context.truncation_policy,
    );

    let mut truncated_count = 0usize;

    let max_retries = turn_context.provider.stream_max_retries();
    let mut retries = 0;
    let turn_metadata_header = turn_context.resolve_turn_metadata_header().await;
    let mut client_session = sess.services.model_client.new_session();
    // Reuse one client session so turn-scoped state (sticky routing, websocket append tracking)
    // survives retries within this compact turn.

    // TODO: If we need to guarantee the persisted mode always matches the prompt used for this
    // turn, capture it in TurnContext at creation time. Using SessionConfiguration here avoids
    // duplicating model settings on TurnContext, but an Op after turn start could update the
    // session config before this write occurs.
    let collaboration_mode = sess.current_collaboration_mode().await;
    let rollout_item = RolloutItem::TurnContext(TurnContextItem {
        cwd: turn_context.cwd.clone(),
        approval_policy: turn_context.approval_policy,
        sandbox_policy: turn_context.sandbox_policy.clone(),
        model: turn_context.model_info.slug.clone(),
        personality: turn_context.personality,
        collaboration_mode: Some(collaboration_mode),
        effort: turn_context.reasoning_effort,
        summary: turn_context.reasoning_summary,
        user_instructions: turn_context.user_instructions.clone(),
        developer_instructions: turn_context.developer_instructions.clone(),
        final_output_json_schema: turn_context.final_output_json_schema.clone(),
        truncation_policy: Some(turn_context.truncation_policy.into()),
    });
    sess.persist_rollout_items(&[rollout_item]).await;

    loop {
        // Clone is required because of the loop
        let turn_input = history.clone().for_prompt();
        let turn_input_len = turn_input.len();
        let prompt = Prompt {
            input: turn_input,
            base_instructions: sess.get_base_instructions().await,
            personality: turn_context.personality,
            ..Default::default()
        };
        let attempt_result = drain_to_completed(
            &sess,
            turn_context.as_ref(),
            &mut client_session,
            turn_metadata_header.as_deref(),
            &prompt,
        )
        .await;

        match attempt_result {
            Ok(()) => {
                if truncated_count > 0 {
                    sess.notify_background_event(
                        turn_context.as_ref(),
                        format!(
                            "Trimmed {truncated_count} older thread item(s) before compacting so the prompt fits the model context window."
                        ),
                    )
                    .await;
                }
                break;
            }
            Err(CodexErr::Interrupted) => {
                return Err(CodexErr::Interrupted);
            }
            Err(e @ CodexErr::ContextWindowExceeded) => {
                if turn_input_len > 1 {
                    // Trim from the beginning to preserve cache (prefix-based) and keep recent messages intact.
                    error!(
                        "Context window exceeded while compacting; removing oldest history item. Error: {e}"
                    );
                    history.remove_first_item();
                    truncated_count += 1;
                    retries = 0;
                    continue;
                }
                sess.set_total_tokens_full(turn_context.as_ref()).await;
                let event = EventMsg::Error(e.to_error_event(None));
                sess.send_event(&turn_context, event).await;
                return Err(e);
            }
            Err(e) => {
                if retries < max_retries {
                    retries += 1;
                    let delay = backoff(retries);
                    sess.notify_stream_error(
                        turn_context.as_ref(),
                        format!("Reconnecting... {retries}/{max_retries}"),
                        e,
                    )
                    .await;
                    tokio::time::sleep(delay).await;
                    continue;
                } else {
                    let event = EventMsg::Error(e.to_error_event(None));
                    sess.send_event(&turn_context, event).await;
                    return Err(e);
                }
            }
        }
    }

    let history_snapshot = sess.clone_history().await;
    let history_items = history_snapshot.raw_items();
    let summary_suffix = get_last_assistant_message_from_turn(history_items).unwrap_or_default();
    let summary_text = format!("{SUMMARY_PREFIX}\n{summary_suffix}");
    let user_messages = collect_user_messages(history_items);

    let initial_context = sess.build_initial_context(turn_context.as_ref()).await;
    let mut new_history = build_compacted_history(initial_context, &user_messages, &summary_text);
    let ghost_snapshots: Vec<ResponseItem> = history_items
        .iter()
        .filter(|item| matches!(item, ResponseItem::GhostSnapshot { .. }))
        .cloned()
        .collect();
    new_history.extend(ghost_snapshots);
    sess.replace_history(new_history).await;
    sess.recompute_token_usage(&turn_context).await;

    let rollout_item = RolloutItem::Compacted(CompactedItem {
        message: summary_text.clone(),
        replacement_history: None,
    });
    sess.persist_rollout_items(&[rollout_item]).await;

    sess.emit_turn_item_completed(&turn_context, compaction_item)
        .await;
    let warning = EventMsg::Warning(WarningEvent {
        message: "Heads up: Long threads and multiple compactions can cause the model to be less accurate. Start a new thread when possible to keep threads small and targeted.".to_string(),
    });
    sess.send_event(&turn_context, warning).await;
    Ok(())
}

pub fn content_items_to_text(content: &[ContentItem]) -> Option<String> {
    let mut pieces = Vec::new();
    for item in content {
        match item {
            ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                if !text.is_empty() {
                    pieces.push(text.as_str());
                }
            }
            ContentItem::InputImage { .. } => {}
        }
    }
    if pieces.is_empty() {
        None
    } else {
        Some(pieces.join("\n"))
    }
}

async fn drain_to_completed(
    sess: &Session,
    turn_context: &TurnContext,
    client_session: &mut ModelClientSession,
    turn_metadata_header: Option<&str>,
    prompt: &Prompt,
) -> CodexResult<()> {
    let mut stream = client_session
        .stream(
            prompt,
            &turn_context.model_info,
            &turn_context.otel_manager,
            turn_context.reasoning_effort,
            turn_context.reasoning_summary,
            turn_metadata_header,
        )
        .await?;
    loop {
        let maybe_event = stream.next().await;
        let Some(event) = maybe_event else {
            return Err(CodexErr::Stream(
                "stream closed before response.completed".into(),
                None,
            ));
        };
        match event {
            Ok(ResponseEvent::OutputItemDone(item)) => {
                sess.record_into_history(std::slice::from_ref(&item), turn_context)
                    .await;
            }
            Ok(ResponseEvent::ServerReasoningIncluded(included)) => {
                sess.set_server_reasoning_included(included).await;
            }
            Ok(ResponseEvent::RateLimits(snapshot)) => {
                sess.update_rate_limits(turn_context, snapshot).await;
            }
            Ok(ResponseEvent::Completed { token_usage, .. }) => {
                sess.update_token_usage_info(turn_context, token_usage.as_ref())
                    .await;
                return Ok(());
            }
            Ok(_) => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn content_items_to_text_joins_non_empty_segments() {
        let items = vec![
            ContentItem::InputText {
                text: "hello".to_string(),
            },
            ContentItem::OutputText {
                text: String::new(),
            },
            ContentItem::OutputText {
                text: "world".to_string(),
            },
        ];

        let joined = content_items_to_text(&items);

        assert_eq!(Some("hello\nworld".to_string()), joined);
    }

    #[test]
    fn content_items_to_text_ignores_image_only_content() {
        let items = vec![ContentItem::InputImage {
            image_url: "file://image.png".to_string(),
        }];

        let joined = content_items_to_text(&items);

        assert_eq!(None, joined);
    }

    #[test]
    fn collect_user_messages_extracts_user_text_only() {
        let items = vec![
            ResponseItem::Message {
                id: Some("assistant".to_string()),
                role: "assistant".to_string(),
                content: vec![ContentItem::OutputText {
                    text: "ignored".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: Some("user".to_string()),
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "first".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Other,
        ];

        let collected = collect_user_messages(&items);

        assert_eq!(vec!["first".to_string()], collected);
    }

    #[test]
    fn collect_user_messages_filters_session_prefix_entries() {
        let items = vec![
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: r#"# AGENTS.md instructions for project

<INSTRUCTIONS>
do things
</INSTRUCTIONS>"#
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "<ENVIRONMENT_CONTEXT>cwd=/tmp</ENVIRONMENT_CONTEXT>".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "real user message".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
        ];

        let collected = collect_user_messages(&items);

        assert_eq!(vec!["real user message".to_string()], collected);
    }

    #[test]
    fn build_token_limited_compacted_history_truncates_overlong_user_messages() {
        // Use a small truncation limit so the test remains fast while still validating
        // that oversized user content is truncated.
        let max_tokens = 16;
        let big = "word ".repeat(200);
        let history = super::history::build_compacted_history_with_limit(
            Vec::new(),
            std::slice::from_ref(&big),
            "SUMMARY",
            max_tokens,
        );
        assert_eq!(history.len(), 2);

        let truncated_message = &history[0];
        let summary_message = &history[1];

        let truncated_text = match truncated_message {
            ResponseItem::Message { role, content, .. } if role == "user" => {
                content_items_to_text(content).unwrap_or_default()
            }
            other => panic!("unexpected item in history: {other:?}"),
        };

        assert!(
            truncated_text.contains("tokens truncated"),
            "expected truncation marker in truncated user message"
        );
        assert!(
            !truncated_text.contains(&big),
            "truncated user message should not include the full oversized user text"
        );

        let summary_text = match summary_message {
            ResponseItem::Message { role, content, .. } if role == "user" => {
                content_items_to_text(content).unwrap_or_default()
            }
            other => panic!("unexpected item in history: {other:?}"),
        };
        assert_eq!(summary_text, "SUMMARY");
    }

    #[test]
    fn build_token_limited_compacted_history_appends_summary_message() {
        let initial_context: Vec<ResponseItem> = Vec::new();
        let user_messages = vec!["first user message".to_string()];
        let summary_text = "summary text";

        let history = build_compacted_history(initial_context, &user_messages, summary_text);
        assert!(
            !history.is_empty(),
            "expected compacted history to include summary"
        );

        let last = history.last().expect("history should have a summary entry");
        let summary = match last {
            ResponseItem::Message { role, content, .. } if role == "user" => {
                content_items_to_text(content).unwrap_or_default()
            }
            other => panic!("expected summary message, found {other:?}"),
        };
        assert_eq!(summary, summary_text);
    }

    #[test]
    fn process_compacted_history_replaces_developer_messages() {
        let compacted_history = vec![
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "stale permissions".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "summary".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "stale personality".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
        ];
        let initial_context = vec![
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "fresh permissions".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: r#"<environment_context>
  <cwd>/tmp</cwd>
  <shell>zsh</shell>
</environment_context>"#
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "fresh personality".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
        ];

        let refreshed = process_compacted_history(compacted_history, &initial_context);
        let expected = vec![
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "summary".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "fresh permissions".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: r#"<environment_context>
  <cwd>/tmp</cwd>
  <shell>zsh</shell>
</environment_context>"#
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "fresh personality".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
        ];
        assert_eq!(refreshed, expected);
    }

    #[test]
    fn process_compacted_history_reinjects_full_initial_context() {
        let compacted_history = vec![ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "summary".to_string(),
            }],
            end_turn: None,
            phase: None,
        }];
        let initial_context = vec![
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "fresh permissions".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: r#"# AGENTS.md instructions for /repo

<INSTRUCTIONS>
keep me updated
</INSTRUCTIONS>"#
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: r#"<environment_context>
  <cwd>/repo</cwd>
  <shell>zsh</shell>
</environment_context>"#
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: r#"<turn_aborted>
  <turn_id>turn-1</turn_id>
  <reason>interrupted</reason>
</turn_aborted>"#
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
        ];

        let refreshed = process_compacted_history(compacted_history, &initial_context);
        let expected = vec![
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "summary".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "fresh permissions".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: r#"# AGENTS.md instructions for /repo

<INSTRUCTIONS>
keep me updated
</INSTRUCTIONS>"#
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: r#"<environment_context>
  <cwd>/repo</cwd>
  <shell>zsh</shell>
</environment_context>"#
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
        ];
        assert_eq!(refreshed, expected);
    }

    #[test]
    fn process_compacted_history_drops_largest_uncapped_context_items_to_fit_budget() {
        let compacted_history = vec![ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "summary".to_string(),
            }],
            end_turn: None,
            phase: None,
        }];
        let oversized_user_instructions = format!(
            "# AGENTS.md instructions for /repo\n\n<INSTRUCTIONS>\n{}\n</INSTRUCTIONS>",
            "u".repeat(48_000)
        );
        let medium_developer_instructions = "d".repeat(8_000);
        let initial_context = vec![
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "<permissions instructions>\nallowed\n</permissions instructions>"
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: oversized_user_instructions.clone(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: medium_developer_instructions.clone(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "<environment_context>\n  <cwd>/repo</cwd>\n  <shell>zsh</shell>\n</environment_context>".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
        ];
        let initial_context_tokens: usize = initial_context
            .iter()
            .map(super::history::estimate_response_item_tokens)
            .sum();
        assert!(
            initial_context_tokens > super::history::REINJECTED_INITIAL_CONTEXT_MAX_TOKENS,
            "test setup should exceed reinjected initial context budget"
        );

        let refreshed = process_compacted_history(compacted_history, &initial_context);
        let reinjected_context_tokens: usize = refreshed
            .iter()
            .skip(1)
            .map(super::history::estimate_response_item_tokens)
            .sum();
        assert!(
            reinjected_context_tokens <= super::history::REINJECTED_INITIAL_CONTEXT_MAX_TOKENS,
            "re-injected context should respect budget"
        );
        assert!(
            refreshed.iter().any(|item| matches!(
                item,
                ResponseItem::Message { role, content, .. }
                    if role == "developer"
                        && content_items_to_text(content).as_deref() == Some(
                            "<permissions instructions>\nallowed\n</permissions instructions>"
                        )
            )),
            "permissions instructions should always be re-injected"
        );
        assert!(
            refreshed.iter().any(|item| matches!(
                item,
                ResponseItem::Message { role, content, .. }
                    if role == "user"
                        && content_items_to_text(content).as_deref() == Some(
                            "<environment_context>\n  <cwd>/repo</cwd>\n  <shell>zsh</shell>\n</environment_context>"
                        )
            )),
            "environment context should always be re-injected"
        );
        assert!(
            refreshed.iter().all(|item| !matches!(
                item,
                ResponseItem::Message { role, content, .. }
                    if role == "user"
                        && content_items_to_text(content).as_deref()
                            == Some(oversized_user_instructions.as_str())
            )),
            "largest droppable context item should be removed first"
        );
        assert!(
            refreshed.iter().any(|item| matches!(
                item,
                ResponseItem::Message { role, content, .. }
                    if role == "developer"
                        && content_items_to_text(content).as_deref()
                            == Some(medium_developer_instructions.as_str())
            )),
            "smaller droppable context items should remain when budget allows"
        );
    }

    #[test]
    fn process_compacted_history_drops_non_user_content_messages() {
        let compacted_history = vec![
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: r#"# AGENTS.md instructions for /repo

<INSTRUCTIONS>
keep me updated
</INSTRUCTIONS>"#
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: r#"<environment_context>
  <cwd>/repo</cwd>
  <shell>zsh</shell>
</environment_context>"#
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: r#"<turn_aborted>
  <turn_id>turn-1</turn_id>
  <reason>interrupted</reason>
</turn_aborted>"#
                        .to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "summary".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "stale developer instructions".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
        ];
        let initial_context = vec![ResponseItem::Message {
            id: None,
            role: "developer".to_string(),
            content: vec![ContentItem::InputText {
                text: "fresh developer instructions".to_string(),
            }],
            end_turn: None,
            phase: None,
        }];

        let refreshed = process_compacted_history(compacted_history, &initial_context);
        let expected = vec![
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "summary".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "fresh developer instructions".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
        ];
        assert_eq!(refreshed, expected);
    }

    #[test]
    fn process_compacted_history_appends_context_after_compacted_history() {
        let compacted_history = vec![
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "older user".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: format!("{SUMMARY_PREFIX}\nsummary text"),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "latest user".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
        ];
        let initial_context = vec![ResponseItem::Message {
            id: None,
            role: "developer".to_string(),
            content: vec![ContentItem::InputText {
                text: "fresh permissions".to_string(),
            }],
            end_turn: None,
            phase: None,
        }];

        let refreshed = process_compacted_history(compacted_history, &initial_context);
        let expected = vec![
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "older user".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: format!("{SUMMARY_PREFIX}\nsummary text"),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "latest user".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Message {
                id: None,
                role: "developer".to_string(),
                content: vec![ContentItem::InputText {
                    text: "fresh permissions".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
        ];
        assert_eq!(refreshed, expected);
    }
}
