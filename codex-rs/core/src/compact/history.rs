use crate::instructions::UserInstructions;
use crate::truncate::TruncationPolicy;
use crate::truncate::approx_token_count;
use crate::truncate::truncate_text;
use codex_protocol::items::TurnItem;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;

const COMPACT_USER_MESSAGE_MAX_TOKENS: usize = 20_000;
// Turn context messages are re-injected after compaction so the next turn sees
// canonical session state (permissions, environment context, instructions).
//
// Some of those entries can be very large (for example AGENTS.md or custom
// developer instructions), and their size is otherwise unbounded here. Without
// a cap, re-injection can dominate post-compaction history and quickly push
// token usage back toward auto-compaction thresholds.
//
// We therefore budget the reinjected context separately and drop only
// droppable context items (largest first) when needed. Using half of the
// existing compact user-message budget keeps this heuristic simple and local to
// compaction behavior.
pub(crate) const REINJECTED_INITIAL_CONTEXT_MAX_TOKENS: usize = COMPACT_USER_MESSAGE_MAX_TOKENS / 2;
const PERMISSIONS_INSTRUCTIONS_OPEN_TAG: &str = "<permissions instructions>";

pub(crate) fn collect_user_messages(items: &[ResponseItem]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match crate::event_mapping::parse_turn_item(item) {
            Some(TurnItem::UserMessage(user)) => {
                if is_summary_message(&user.message()) {
                    None
                } else {
                    Some(user.message())
                }
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn is_summary_message(message: &str) -> bool {
    message.starts_with(format!("{}\n", super::SUMMARY_PREFIX).as_str())
}

pub(crate) fn process_compacted_history(
    mut compacted_history: Vec<ResponseItem>,
    initial_context: &[ResponseItem],
) -> Vec<ResponseItem> {
    compacted_history.retain(should_keep_compacted_history_item);

    let initial_context = initial_context_for_reinjection(initial_context);

    // Re-inject canonical context from the current session since we stripped from the pre-compaction history.
    compacted_history.extend(initial_context);

    compacted_history
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
///   keeping only real user messages as parsed by `parse_turn_item`.
/// - `<turn_aborted>` session prefix markers, which should not persist after compaction.
///
/// This intentionally keeps `user`-role warnings and compaction-generated
/// summary messages because they parse as `TurnItem::UserMessage`.
fn should_keep_compacted_history_item(item: &ResponseItem) -> bool {
    match item {
        _ if is_turn_aborted_marker(item) => false,
        ResponseItem::Message { role, .. } if role == "developer" => false,
        ResponseItem::Message { role, .. } if role == "user" => matches!(
            crate::event_mapping::parse_turn_item(item),
            Some(TurnItem::UserMessage(_))
        ),
        _ => true,
    }
}

fn is_turn_aborted_marker(item: &ResponseItem) -> bool {
    let ResponseItem::Message { role, content, .. } = item else {
        return false;
    };
    if role != "user" {
        return false;
    }
    content.iter().any(|content_item| match content_item {
        ContentItem::InputText { text } => text
            .trim_start()
            .to_ascii_lowercase()
            .starts_with(crate::session_prefix::TURN_ABORTED_OPEN_TAG),
        _ => false,
    })
}

fn initial_context_for_reinjection(initial_context: &[ResponseItem]) -> Vec<ResponseItem> {
    let initial_context = initial_context
        .iter()
        .filter(|item| !is_turn_aborted_marker(item))
        .cloned()
        .collect::<Vec<_>>();
    let mut selected: Vec<Option<ResponseItem>> =
        initial_context.iter().cloned().map(Some).collect();
    let mut total_tokens: usize = initial_context
        .iter()
        .map(estimate_response_item_tokens)
        .sum();
    if total_tokens <= REINJECTED_INITIAL_CONTEXT_MAX_TOKENS {
        return initial_context;
    }

    let mut droppable_items: Vec<(usize, usize)> = initial_context
        .iter()
        .enumerate()
        .filter(|(_, item)| is_droppable_initial_context_item(item))
        .map(|(idx, item)| (idx, estimate_response_item_tokens(item)))
        .collect();
    // Prefer dropping the largest droppable context chunks first.
    droppable_items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    for (idx, item_tokens) in droppable_items {
        if total_tokens <= REINJECTED_INITIAL_CONTEXT_MAX_TOKENS {
            break;
        }
        selected[idx] = None;
        total_tokens = total_tokens.saturating_sub(item_tokens);
    }

    selected.into_iter().flatten().collect()
}

fn is_droppable_initial_context_item(item: &ResponseItem) -> bool {
    let ResponseItem::Message { role, content, .. } = item else {
        return false;
    };
    // We keep permissions and environment context stable, and allow large
    // instruction wrappers to be omitted since compaction can summarize them.
    if role == "user" {
        return UserInstructions::is_user_instructions(content);
    }
    if role == "developer" {
        return !is_permissions_developer_message(content);
    }
    false
}

fn is_permissions_developer_message(content: &[ContentItem]) -> bool {
    let [ContentItem::InputText { text }] = content else {
        return false;
    };
    text.starts_with(PERMISSIONS_INSTRUCTIONS_OPEN_TAG)
}

pub(crate) fn estimate_response_item_tokens(item: &ResponseItem) -> usize {
    serde_json::to_string(item)
        .map(|s| approx_token_count(&s))
        .unwrap_or_default()
}

pub(crate) fn build_compacted_history(
    initial_context: Vec<ResponseItem>,
    user_messages: &[String],
    summary_text: &str,
) -> Vec<ResponseItem> {
    build_compacted_history_with_limit(
        initial_context,
        user_messages,
        summary_text,
        COMPACT_USER_MESSAGE_MAX_TOKENS,
    )
}

pub(crate) fn build_compacted_history_with_limit(
    mut history: Vec<ResponseItem>,
    user_messages: &[String],
    summary_text: &str,
    max_tokens: usize,
) -> Vec<ResponseItem> {
    let mut selected_messages: Vec<String> = Vec::new();
    if max_tokens > 0 {
        let mut remaining = max_tokens;
        for message in user_messages.iter().rev() {
            if remaining == 0 {
                break;
            }
            let tokens = approx_token_count(message);
            if tokens <= remaining {
                selected_messages.push(message.clone());
                remaining = remaining.saturating_sub(tokens);
            } else {
                let truncated = truncate_text(message, TruncationPolicy::Tokens(remaining));
                selected_messages.push(truncated);
                break;
            }
        }
        selected_messages.reverse();
    }

    for message in &selected_messages {
        history.push(ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: message.clone(),
            }],
            end_turn: None,
            phase: None,
        });
    }

    let summary_text = if summary_text.is_empty() {
        "(no summary available)".to_string()
    } else {
        summary_text.to_string()
    };

    history.push(ResponseItem::Message {
        id: None,
        role: "user".to_string(),
        content: vec![ContentItem::InputText { text: summary_text }],
        end_turn: None,
        phase: None,
    });

    history
}
