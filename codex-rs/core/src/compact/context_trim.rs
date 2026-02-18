use crate::codex::TurnContext;
use crate::context_manager::ContextManager;
use crate::context_manager::is_codex_generated_item;
use codex_protocol::models::BaseInstructions;
use codex_protocol::models::ResponseItem;

pub(crate) fn trim_function_call_history_to_fit_context_window(
    history: &mut ContextManager,
    turn_context: &TurnContext,
    base_instructions: &BaseInstructions,
) -> usize {
    let mut deleted_items = 0usize;
    let Some(context_window) = turn_context.model_context_window() else {
        return deleted_items;
    };

    while history
        .estimate_token_count_with_base_instructions(base_instructions)
        .is_some_and(|estimated_tokens| estimated_tokens > context_window)
    {
        let Some(last_item) = history.raw_items().last() else {
            break;
        };
        // Keep a trailing tool call until its output is present; trimming the
        // call first can orphan a later-arriving output during mid-stream auto-compaction.
        if is_pending_tool_call_without_output(last_item, history.raw_items()) {
            break;
        }
        if !is_remote_compaction_trim_candidate(last_item) {
            break;
        }
        if !history.remove_last_item() {
            break;
        }
        deleted_items += 1;
    }

    deleted_items
}

fn is_remote_compaction_trim_candidate(item: &ResponseItem) -> bool {
    is_codex_generated_item(item)
        || matches!(
            item,
            ResponseItem::FunctionCall { .. }
                | ResponseItem::CustomToolCall { .. }
                | ResponseItem::LocalShellCall { .. }
        )
}

fn is_pending_tool_call_without_output(item: &ResponseItem, items: &[ResponseItem]) -> bool {
    match item {
        ResponseItem::FunctionCall { call_id, .. } => !items.iter().any(|candidate| {
            matches!(
                candidate,
                ResponseItem::FunctionCallOutput {
                    call_id: existing, ..
                } if existing == call_id
            )
        }),
        ResponseItem::CustomToolCall { call_id, .. } => !items.iter().any(|candidate| {
            matches!(
                candidate,
                ResponseItem::CustomToolCallOutput {
                    call_id: existing, ..
                } if existing == call_id
            )
        }),
        ResponseItem::LocalShellCall { call_id, .. } => {
            let Some(call_id) = call_id.as_ref() else {
                return true;
            };
            !items.iter().any(|candidate| {
                matches!(
                    candidate,
                    ResponseItem::FunctionCallOutput {
                        call_id: existing, ..
                    } if existing == call_id
                )
            })
        }
        _ => false,
    }
}
