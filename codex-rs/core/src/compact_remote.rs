use std::collections::HashSet;
use std::sync::Arc;

use crate::Prompt;
use crate::compact::CompactTrigger;
use crate::compact::CompactionAnalyticsAttempt;
use crate::compact::InitialContextInjection;
use crate::compact::compaction_status_from_result;
use crate::compact::insert_initial_context_before_last_real_user_or_summary;
use crate::compact_remote_invariants::insert_retained_plan_for_remote_compaction;
use crate::compact_remote_invariants::retry_once_invalid_encrypted_content_with_sanitized_prompt_input;
use crate::context_manager::ContextManager;
use crate::context_manager::TotalTokenUsageBreakdown;
use crate::context_manager::estimate_response_item_model_visible_bytes;
use crate::context_manager::is_user_turn_boundary;
use crate::session::session::Session;
use crate::session::turn::built_tools;
use crate::session::turn_context::TurnContext;
use codex_analytics::CompactionImplementation;
use codex_analytics::CompactionPhase;
use codex_analytics::CompactionReason;
use codex_analytics::CompactionTrigger;
use codex_protocol::error::CodexErr;
use codex_protocol::error::Result as CodexResult;
use codex_protocol::items::ContextCompactionItem;
use codex_protocol::items::TurnItem;
use codex_protocol::models::BaseInstructions;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::CompactedItem;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::TurnStartedEvent;
use codex_rollout_trace::CompactionCheckpointTracePayload;
use codex_tools::ToolSpec;
use codex_tools::create_tools_json_for_responses_api;
use codex_utils_output_truncation::approx_token_count;
use tokio_util::sync::CancellationToken;
use tracing::error;
use tracing::info;

pub(crate) async fn run_inline_remote_auto_compact_task(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
    initial_context_injection: InitialContextInjection,
    reason: CompactionReason,
    phase: CompactionPhase,
) -> CodexResult<()> {
    run_remote_compact_task_inner(
        &sess,
        &turn_context,
        initial_context_injection,
        CompactTrigger::Auto,
        CompactionTrigger::Auto,
        reason,
        phase,
    )
    .await?;
    Ok(())
}

pub(crate) async fn run_remote_compact_task(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
) -> CodexResult<()> {
    let start_event = EventMsg::TurnStarted(TurnStartedEvent {
        turn_id: turn_context.sub_id.clone(),
        started_at: turn_context.turn_timing_state.started_at_unix_secs().await,
        model_context_window: turn_context.model_context_window(),
        collaboration_mode_kind: turn_context.collaboration_mode.mode,
    });
    sess.send_event(&turn_context, start_event).await;

    run_remote_compact_task_inner(
        &sess,
        &turn_context,
        InitialContextInjection::DoNotInject,
        CompactTrigger::Manual,
        CompactionTrigger::Manual,
        CompactionReason::UserRequested,
        CompactionPhase::StandaloneTurn,
    )
    .await
}

async fn run_remote_compact_task_inner(
    sess: &Arc<Session>,
    turn_context: &Arc<TurnContext>,
    initial_context_injection: InitialContextInjection,
    compact_trigger: CompactTrigger,
    trigger: CompactionTrigger,
    reason: CompactionReason,
    phase: CompactionPhase,
) -> CodexResult<()> {
    let attempt = CompactionAnalyticsAttempt::begin(
        sess.as_ref(),
        turn_context.as_ref(),
        trigger,
        reason,
        CompactionImplementation::ResponsesCompact,
        phase,
    )
    .await;
    let result = run_remote_compact_task_inner_impl(
        sess,
        turn_context,
        initial_context_injection,
        compact_trigger,
    )
    .await;
    attempt
        .track(
            sess.as_ref(),
            compaction_status_from_result(&result),
            result.as_ref().err().map(ToString::to_string),
        )
        .await;
    if let Err(err) = result {
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
    initial_context_injection: InitialContextInjection,
    compact_trigger: CompactTrigger,
) -> CodexResult<()> {
    let context_compaction_item = ContextCompactionItem::new();
    // Use the UI compaction item ID as the trace compaction ID so protocol lifecycle events,
    // endpoint attempts, and the installed history checkpoint all have one join key.
    let compaction_trace = sess.services.rollout_thread_trace.compaction_trace_context(
        turn_context.sub_id.as_str(),
        context_compaction_item.id.as_str(),
        turn_context.model_info.slug.as_str(),
        turn_context.provider.info().name.as_str(),
    );
    let compaction_item = TurnItem::ContextCompaction(context_compaction_item);
    sess.emit_turn_item_started(turn_context, &compaction_item)
        .await;
    let mut history = sess.clone_history().await;
    let base_instructions = sess.get_base_instructions().await;
    let prompt_input = history
        .clone()
        .for_prompt(&turn_context.model_info.input_modalities);
    let compact_tools = build_compact_tools(
        sess.as_ref(),
        turn_context.as_ref(),
        &prompt_input,
        &CancellationToken::new(),
    )
    .await?;
    let compact_tool_token_count = estimate_tool_token_count(&compact_tools)?;
    let deleted_items = trim_history_to_fit_context_window_for_remote_compaction(
        &mut history,
        turn_context.as_ref(),
        &base_instructions,
        compact_tool_token_count,
    );
    if deleted_items > 0 {
        info!(
            turn_id = %turn_context.sub_id,
            deleted_items,
            "trimmed history items before remote compaction"
        );
    }
    // This is the history selected for remote compaction, after any trimming required to fit the
    // compact endpoint. The checkpoint below records it separately from the next sampling request,
    // whose prompt will repeat current developer/context prefix items.
    let trace_input_history = history.raw_items().to_vec();
    // Required to keep `/undo` available after compaction
    let ghost_snapshots: Vec<ResponseItem> = history
        .raw_items()
        .iter()
        .filter(|item| matches!(item, ResponseItem::GhostSnapshot { .. }))
        .cloned()
        .collect();

    let prompt_input = history.for_prompt(&turn_context.model_info.input_modalities);
    let prompt = Prompt {
        input: prompt_input,
        tools: compact_tools,
        parallel_tool_calls: turn_context.model_info.supports_parallel_tool_calls,
        base_instructions,
        personality: turn_context.personality,
        output_schema: None,
        output_schema_strict: true,
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
                turn_context.reasoning_effort,
                turn_context.reasoning_summary,
                &turn_context.session_telemetry,
                &compaction_trace,
            )
            .await;
        match result {
            Ok(new_history) => break new_history,
            Err(err) => {
                if retry_once_invalid_encrypted_content_with_sanitized_prompt_input(
                    &mut retried_invalid_encrypted_content,
                    &err,
                    &mut compact_prompt.input,
                ) {
                    continue;
                }
                let total_usage_breakdown = sess.get_total_token_usage_breakdown().await;
                let compact_request_log_data = build_compact_request_log_data(
                    &compact_prompt.input,
                    &compact_prompt.base_instructions.text,
                    &compact_prompt.tools,
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
    new_history = process_compacted_history(
        sess.as_ref(),
        turn_context.as_ref(),
        new_history,
        initial_context_injection,
    )
    .await;
    let (new_history_with_retained_plan, retained_proposed_plan) =
        insert_retained_plan_for_remote_compaction(
            sess.as_ref(),
            turn_context.as_ref(),
            compact_trigger,
            new_history,
        )
        .await;
    new_history = new_history_with_retained_plan;

    if !ghost_snapshots.is_empty() {
        new_history.extend(ghost_snapshots);
    }
    let reference_context_item = match initial_context_injection {
        InitialContextInjection::DoNotInject => None,
        InitialContextInjection::BeforeLastUserMessage => Some(turn_context.to_turn_context_item()),
    };
    let compacted_item = CompactedItem {
        message: String::new(),
        retained_proposed_plan,
        replacement_history: Some(new_history.clone()),
    };
    // Install is the semantic boundary where the compact endpoint's output becomes live
    // thread history. Keep it distinct from the later inference request so the reducer can
    // still represent repeated developer/context prefix items exactly as the model saw them.
    compaction_trace.record_installed(&CompactionCheckpointTracePayload {
        input_history: &trace_input_history,
        replacement_history: &new_history,
    });
    sess.replace_compacted_history(new_history, reference_context_item, compacted_item)
        .await;
    sess.recompute_token_usage(turn_context).await;

    sess.emit_turn_item_completed(turn_context, compaction_item)
        .await;
    Ok(())
}

pub(crate) async fn process_compacted_history(
    sess: &Session,
    turn_context: &TurnContext,
    mut compacted_history: Vec<ResponseItem>,
    initial_context_injection: InitialContextInjection,
) -> Vec<ResponseItem> {
    // Mid-turn compaction is the only path that must inject initial context above the last user
    // message in the replacement history. Pre-turn compaction instead injects context after the
    // compaction item, but mid-turn compaction keeps the compaction item last for model training.
    let initial_context = if matches!(
        initial_context_injection,
        InitialContextInjection::BeforeLastUserMessage
    ) {
        sess.build_initial_context(turn_context).await
    } else {
        Vec::new()
    };

    compacted_history.retain(should_keep_compacted_history_item);
    insert_initial_context_before_last_real_user_or_summary(compacted_history, initial_context)
}

/// Returns whether an item from remote compaction output should be preserved.
///
/// Called while processing the model-provided compacted transcript, before we
/// append fresh canonical context from the current session.
///
/// We drop:
/// - `developer` messages because remote output can include stale/duplicated
///   instruction content.
/// - non-user-content `user` messages (session prefix/instruction wrappers),
///   while preserving real user messages and persisted hook prompts.
///
/// This intentionally keeps:
/// - `assistant` messages (future remote compaction models may emit them)
/// - `user`-role warnings and compaction-generated summary messages because
///   they parse as `TurnItem::UserMessage`.
fn should_keep_compacted_history_item(item: &ResponseItem) -> bool {
    match item {
        ResponseItem::Message { role, .. } if role == "developer" => false,
        ResponseItem::Message { role, .. } if role == "user" => {
            matches!(
                crate::event_mapping::parse_turn_item(item),
                Some(TurnItem::UserMessage(_) | TurnItem::HookPrompt(_))
            )
        }
        ResponseItem::Message { role, .. } if role == "assistant" => true,
        ResponseItem::Message { .. } => false,
        ResponseItem::Compaction { .. } => true,
        ResponseItem::Reasoning { .. }
        | ResponseItem::LocalShellCall { .. }
        | ResponseItem::FunctionCall { .. }
        | ResponseItem::ToolSearchCall { .. }
        | ResponseItem::FunctionCallOutput { .. }
        | ResponseItem::ToolSearchOutput { .. }
        | ResponseItem::CustomToolCall { .. }
        | ResponseItem::CustomToolCallOutput { .. }
        | ResponseItem::WebSearchCall { .. }
        | ResponseItem::ImageGenerationCall { .. }
        | ResponseItem::GhostSnapshot { .. }
        | ResponseItem::ContextCompaction { .. }
        | ResponseItem::Other => false,
    }
}

#[derive(Debug)]
pub(crate) struct CompactRequestLogData {
    failing_compaction_request_model_visible_bytes: i64,
}

pub(crate) fn build_compact_request_log_data(
    input: &[ResponseItem],
    instructions: &str,
    tools: &[ToolSpec],
) -> CompactRequestLogData {
    let tool_tokens = estimate_tool_token_count(tools).unwrap_or_default();
    let failing_compaction_request_model_visible_bytes = input
        .iter()
        .map(estimate_response_item_model_visible_bytes)
        .fold(
            i64::try_from(instructions.len()).unwrap_or(i64::MAX),
            i64::saturating_add,
        )
        .saturating_add(tool_tokens);

    CompactRequestLogData {
        failing_compaction_request_model_visible_bytes,
    }
}

pub(crate) fn log_remote_compact_failure(
    turn_context: &TurnContext,
    log_data: &CompactRequestLogData,
    total_usage_breakdown: TotalTokenUsageBreakdown,
    err: &CodexErr,
) {
    error!(
        turn_id = %turn_context.sub_id,
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

pub(crate) fn trim_history_to_fit_context_window_for_remote_compaction(
    history: &mut ContextManager,
    turn_context: &TurnContext,
    base_instructions: &BaseInstructions,
    extra_token_budget: i64,
) -> usize {
    let Some(context_window) = turn_context.model_context_window() else {
        return 0;
    };

    trim_history_to_fit_token_budget_for_remote_compaction(
        history,
        context_window,
        base_instructions,
        extra_token_budget,
    )
}

fn trim_history_to_fit_token_budget_for_remote_compaction(
    history: &mut ContextManager,
    context_window: i64,
    base_instructions: &BaseInstructions,
    extra_token_budget: i64,
) -> usize {
    let mut deleted_items = 0usize;

    while history
        .estimate_token_count_with_base_instructions(base_instructions)
        .is_some_and(|estimated_tokens| {
            estimated_tokens.saturating_add(extra_token_budget) > context_window
        })
    {
        // Preserve the oldest real user goal plus the newest user/tail context when possible.
        if history.remove_oldest_item_between_first_and_last_user_message() {
            deleted_items += 1;
            continue;
        }

        // Single-user-turn histories still need the old tail-trimming escape hatch so oversized
        // assistant/tool output can be removed before remote compaction retries.
        let Some(last_item) = history.raw_items().last() else {
            break;
        };
        if is_user_turn_boundary(last_item) || !history.remove_last_item() {
            break;
        }
        deleted_items += 1;
    }

    deleted_items
}

async fn build_compact_tools(
    sess: &Session,
    turn_context: &TurnContext,
    prompt_input: &[ResponseItem],
    cancellation_token: &CancellationToken,
) -> CodexResult<Vec<ToolSpec>> {
    let skills_outcome = Some(turn_context.turn_skills.outcome.as_ref());
    let tool_router = built_tools(
        sess,
        turn_context,
        prompt_input,
        &HashSet::new(),
        skills_outcome,
        cancellation_token,
    )
    .await?;
    Ok(tool_router.model_visible_specs())
}

pub(crate) fn estimate_tool_token_count(tools: &[ToolSpec]) -> CodexResult<i64> {
    let tools_json = create_tools_json_for_responses_api(tools)?;
    let serialized = serde_json::to_string(&tools_json)?;
    Ok(i64::try_from(approx_token_count(&serialized)).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::trim_history_to_fit_token_budget_for_remote_compaction;
    use crate::context_manager::ContextManager;
    use codex_protocol::models::BaseInstructions;
    use codex_protocol::models::ContentItem;
    use codex_protocol::models::FunctionCallOutputBody;
    use codex_protocol::models::FunctionCallOutputPayload;
    use codex_protocol::models::ResponseItem;
    use codex_utils_output_truncation::TruncationPolicy;

    #[test]
    fn trim_function_call_history_accounts_for_tool_budget() {
        let mut history = ContextManager::new();
        let first_user = ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "first goal".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        let middle_assistant = ResponseItem::Message {
            id: None,
            role: "assistant".to_string(),
            content: vec![ContentItem::OutputText {
                text: "older response".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        let latest_user = ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "latest question".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        history.record_items(
            [&first_user, &middle_assistant, &latest_user],
            TruncationPolicy::Tokens(10_000),
        );

        let base_instructions = BaseInstructions {
            text: String::new(),
        };
        let mut trimmed_history = ContextManager::new();
        trimmed_history.record_items(
            [&first_user, &latest_user],
            TruncationPolicy::Tokens(10_000),
        );
        let trimmed_tokens = trimmed_history
            .estimate_token_count_with_base_instructions(&base_instructions)
            .expect("history should estimate");
        let extra_tool_budget = 64;
        let context_window = trimmed_tokens.saturating_add(extra_tool_budget);

        let deleted_items = trim_history_to_fit_token_budget_for_remote_compaction(
            &mut history,
            context_window,
            &base_instructions,
            extra_tool_budget,
        );

        assert_eq!(deleted_items, 1);
        assert_eq!(history.raw_items(), &[first_user, latest_user]);
    }

    #[test]
    fn trim_history_preserves_first_and_last_user_messages() {
        let mut history = ContextManager::new();
        let prefix = ResponseItem::Message {
            id: None,
            role: "assistant".to_string(),
            content: vec![ContentItem::OutputText {
                text: "session prefix".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        let first_user = ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "first goal".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        let old_assistant = ResponseItem::Message {
            id: None,
            role: "assistant".to_string(),
            content: vec![ContentItem::OutputText {
                text: "older response".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        let middle_user = ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "middle question".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        let latest_user = ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "latest question".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        let latest_assistant = ResponseItem::Message {
            id: None,
            role: "assistant".to_string(),
            content: vec![ContentItem::OutputText {
                text: "latest answer".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        history.record_items(
            [
                &prefix,
                &first_user,
                &old_assistant,
                &middle_user,
                &latest_user,
                &latest_assistant,
            ],
            TruncationPolicy::Tokens(10_000),
        );

        let base_instructions = BaseInstructions {
            text: String::new(),
        };
        let mut trimmed_history = ContextManager::new();
        trimmed_history.record_items(
            [&prefix, &first_user, &latest_user, &latest_assistant],
            TruncationPolicy::Tokens(10_000),
        );
        let latest_tail_tokens = trimmed_history
            .estimate_token_count_with_base_instructions(&base_instructions)
            .expect("trimmed history should estimate");

        let deleted_items = trim_history_to_fit_token_budget_for_remote_compaction(
            &mut history,
            latest_tail_tokens,
            &base_instructions,
            0,
        );

        assert_eq!(deleted_items, 2);
        assert_eq!(
            history.raw_items(),
            &[prefix, first_user, latest_user, latest_assistant]
        );
    }

    #[test]
    fn trim_history_without_real_user_messages_falls_back_to_oldest_items() {
        let mut history = ContextManager::new();
        let developer = ResponseItem::Message {
            id: None,
            role: "developer".to_string(),
            content: vec![ContentItem::InputText {
                text: "system guidance".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        let tool_output = ResponseItem::FunctionCallOutput {
            call_id: "call-1".to_string(),
            output: FunctionCallOutputPayload {
                body: FunctionCallOutputBody::Text("tool output".to_string()),
                ..Default::default()
            },
        };
        history.record_items([&developer, &tool_output], TruncationPolicy::Tokens(10_000));

        let base_instructions = BaseInstructions {
            text: String::new(),
        };
        let context_window = 0;

        let deleted_items = trim_history_to_fit_token_budget_for_remote_compaction(
            &mut history,
            context_window,
            &base_instructions,
            0,
        );

        assert_eq!(deleted_items, 2);
        assert!(history.raw_items().is_empty());
    }

    #[test]
    fn trim_history_single_user_turn_falls_back_to_tail_generated_items() {
        let mut history = ContextManager::new();
        let user = ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: "only user turn".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        let assistant = ResponseItem::Message {
            id: None,
            role: "assistant".to_string(),
            content: vec![ContentItem::OutputText {
                text: "assistant output".to_string(),
            }],
            end_turn: None,
            phase: None,
        };
        let tool_output = ResponseItem::FunctionCallOutput {
            call_id: "call-1".to_string(),
            output: FunctionCallOutputPayload {
                body: FunctionCallOutputBody::Text("large tool output".to_string()),
                ..Default::default()
            },
        };
        history.record_items(
            [&user, &assistant, &tool_output],
            TruncationPolicy::Tokens(10_000),
        );

        let base_instructions = BaseInstructions {
            text: String::new(),
        };
        let mut trimmed_history = ContextManager::new();
        trimmed_history.record_items([&user], TruncationPolicy::Tokens(10_000));
        let trimmed_tokens = trimmed_history
            .estimate_token_count_with_base_instructions(&base_instructions)
            .expect("user-only history should estimate");

        let deleted_items = trim_history_to_fit_token_budget_for_remote_compaction(
            &mut history,
            trimmed_tokens,
            &base_instructions,
            0,
        );

        assert_eq!(deleted_items, 2);
        assert_eq!(history.raw_items(), &[user]);
    }
}
