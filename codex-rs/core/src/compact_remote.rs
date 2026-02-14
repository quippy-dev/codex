use std::sync::Arc;

use crate::Prompt;
use crate::codex::Session;
use crate::codex::TurnContext;
use crate::compact::context_trim::trim_function_call_history_to_fit_context_window;
use crate::compact::extract_trailing_model_switch_update_for_compaction_request;
use crate::context_manager::TotalTokenUsageBreakdown;
use crate::context_manager::estimate_response_item_model_visible_bytes;
use crate::encrypted_content_fallback::apply_invalid_encrypted_content_fallback;
use crate::error::CodexErr;
use crate::error::Result as CodexResult;
use crate::protocol::CompactedItem;
use crate::protocol::EventMsg;
use crate::protocol::RolloutItem;
use crate::protocol::TurnStartedEvent;
use codex_protocol::items::ContextCompactionItem;
use codex_protocol::items::TurnItem;
use codex_protocol::models::ResponseItem;
use tracing::error;
use tracing::info;

pub(crate) async fn run_inline_remote_auto_compact_task(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
) -> CodexResult<()> {
    run_remote_compact_task_inner(&sess, &turn_context).await?;
    Ok(())
}

pub(crate) async fn run_remote_compact_task(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
) -> CodexResult<()> {
    let start_event = EventMsg::TurnStarted(TurnStartedEvent {
        turn_id: turn_context.sub_id.clone(),
        model_context_window: turn_context.model_context_window(),
        collaboration_mode_kind: turn_context.collaboration_mode.mode,
    });
    sess.send_event(&turn_context, start_event).await;

    run_remote_compact_task_inner(&sess, &turn_context).await
}

async fn run_remote_compact_task_inner(
    sess: &Arc<Session>,
    turn_context: &Arc<TurnContext>,
) -> CodexResult<()> {
    if let Err(err) = run_remote_compact_task_inner_impl(sess, turn_context).await {
        let event = EventMsg::Error(
            err.to_error_event(Some("Error running remote compact task".to_string())),
        );
        sess.send_event(turn_context, event).await;
        return Err(err);
    }
    Ok(())
}

async fn run_remote_compact_task_inner_impl(
    sess: &Arc<Session>,
    turn_context: &Arc<TurnContext>,
) -> CodexResult<()> {
    let compaction_item = TurnItem::ContextCompaction(ContextCompactionItem::new());
    sess.emit_turn_item_started(turn_context, &compaction_item)
        .await;
    let mut history = sess.clone_history().await;
    // Keep compaction prompts in-distribution: if a model-switch update was injected at the
    // tail of history (between turns), exclude it from the compaction request payload.
    let stripped_model_switch_item =
        extract_trailing_model_switch_update_for_compaction_request(&mut history);
    let base_instructions = sess.get_base_instructions().await;
    let deleted_items = trim_function_call_history_to_fit_context_window(
        &mut history,
        turn_context.as_ref(),
        &base_instructions,
    );
    if deleted_items > 0 {
        info!(
            turn_id = %turn_context.sub_id,
            deleted_items,
            "trimmed history items before remote compaction"
        );
    }

    // Required to keep `/undo` available after compaction
    let ghost_snapshots: Vec<ResponseItem> = history
        .raw_items()
        .iter()
        .filter(|item| matches!(item, ResponseItem::GhostSnapshot { .. }))
        .cloned()
        .collect();

    let prompt = Prompt {
        input: history.for_prompt(&turn_context.model_info.input_modalities),
        tools: vec![],
        parallel_tool_calls: false,
        base_instructions,
        personality: turn_context.personality,
        output_schema: None,
    };
    let mut retried_invalid_encrypted_content = false;
    let mut compact_prompt = prompt.clone();
    let mut new_history = loop {
        let result = sess
            .services
            .model_client
            .compact_conversation_history(
                &compact_prompt,
                &turn_context.model_info,
                &turn_context.otel_manager,
            )
            .await;
        match result {
            Ok(new_history) => break new_history,
            Err(err) => {
                if apply_invalid_encrypted_content_fallback(
                    &mut retried_invalid_encrypted_content,
                    &err,
                    &mut compact_prompt.input,
                ) {
                    tracing::warn!(
                        "invalid_encrypted_content during remote compact - retrying once with sanitized prompt input"
                    );
                    continue;
                }
                let total_usage_breakdown = sess.get_total_token_usage_breakdown().await;
                let compact_request_log_data = build_compact_request_log_data(
                    &compact_prompt.input,
                    &compact_prompt.base_instructions.text,
                );
                log_remote_compact_failure(
                    turn_context,
                    &compact_request_log_data,
                    total_usage_breakdown,
                    &err,
                );
                return Err(err);
            }
        }
    };
    new_history = sess
        .process_compacted_history(turn_context, new_history)
        .await;
    // Reattach the stripped model-switch update only after successful compaction so the model
    // still sees the switch instructions on the next real sampling request.
    if let Some(model_switch_item) = stripped_model_switch_item {
        new_history.push(model_switch_item);
    }

    if !ghost_snapshots.is_empty() {
        new_history.extend(ghost_snapshots);
    }
    sess.replace_history(new_history.clone()).await;
    sess.recompute_token_usage(turn_context).await;

    let compacted_item = CompactedItem {
        message: String::new(),
        replacement_history: Some(new_history),
    };
    sess.persist_rollout_items(&[RolloutItem::Compacted(compacted_item)])
        .await;

    sess.emit_turn_item_completed(turn_context, compaction_item)
        .await;
    Ok(())
}

#[derive(Debug)]
struct CompactRequestLogData {
    failing_compaction_request_model_visible_bytes: i64,
}

fn build_compact_request_log_data(
    input: &[ResponseItem],
    instructions: &str,
) -> CompactRequestLogData {
    let failing_compaction_request_model_visible_bytes = input
        .iter()
        .map(estimate_response_item_model_visible_bytes)
        .fold(
            i64::try_from(instructions.len()).unwrap_or(i64::MAX),
            i64::saturating_add,
        );

    CompactRequestLogData {
        failing_compaction_request_model_visible_bytes,
    }
}

fn log_remote_compact_failure(
    turn_context: &TurnContext,
    log_data: &CompactRequestLogData,
    total_usage_breakdown: TotalTokenUsageBreakdown,
    err: &CodexErr,
) {
    error!(
        turn_id = %turn_context.sub_id,
        compact_error_status = ?match err {
            CodexErr::InvalidRequest(_) => Some(400),
            CodexErr::UnexpectedStatus(status) => Some(status.status.as_u16()),
            CodexErr::ContextWindowExceeded => Some(400),
            _ => None,
        },
        last_api_response_total_tokens = total_usage_breakdown.last_api_response_total_tokens,
        all_history_items_model_visible_bytes = total_usage_breakdown.all_history_items_model_visible_bytes,
        estimated_tokens_of_items_added_since_last_successful_api_response = total_usage_breakdown.estimated_tokens_of_items_added_since_last_successful_api_response,
        estimated_bytes_of_items_added_since_last_successful_api_response = total_usage_breakdown.estimated_bytes_of_items_added_since_last_successful_api_response,
        model_context_window_tokens = ?turn_context.model_context_window(),
        failing_compaction_request_model_visible_bytes = log_data.failing_compaction_request_model_visible_bytes,
        compact_error = %err,
        "remote compaction failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codex::make_session_and_context;
    use crate::context_manager::ContextManager;
    use codex_protocol::models::BaseInstructions;
    use codex_protocol::models::ContentItem;
    use pretty_assertions::assert_eq;
    #[tokio::test]
    async fn trim_keeps_trailing_function_call_without_output() {
        let (_session, mut turn_context) = make_session_and_context().await;
        turn_context.model_info.context_window = Some(200);
        turn_context.model_info.effective_context_window_percent = 100;

        let mut history = ContextManager::new();
        history.record_items(
            &[
                ResponseItem::Message {
                    id: None,
                    role: "user".to_string(),
                    content: vec![ContentItem::InputText {
                        text: "user question".to_string(),
                    }],
                    end_turn: None,
                    phase: None,
                },
                ResponseItem::FunctionCall {
                    id: None,
                    name: "shell_command".to_string(),
                    arguments: serde_json::json!({
                        "command": format!("echo {}", "x".repeat(2_000)),
                    })
                    .to_string(),
                    call_id: "pending-call".to_string(),
                },
            ],
            turn_context.truncation_policy,
        );

        let deleted_items = trim_function_call_history_to_fit_context_window(
            &mut history,
            &turn_context,
            &BaseInstructions {
                text: "base".to_string(),
            },
        );

        assert_eq!(deleted_items, 0);
        assert!(
            history
                .raw_items()
                .iter()
                .any(|item| matches!(item, ResponseItem::FunctionCall { call_id, .. } if call_id == "pending-call")),
            "expected trailing function_call without output to be preserved"
        );
    }
}
