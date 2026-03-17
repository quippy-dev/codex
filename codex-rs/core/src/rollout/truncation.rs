//! Helpers for truncating rollouts based on "user turn" boundaries.
//!
//! In core, "user turns" are detected by scanning `ResponseItem::Message` items and
//! interpreting them via `event_mapping::parse_turn_item(...)`.

use crate::event_mapping;
use crate::resolve_fork_reference_rollout_path;
use crate::rollout::RolloutRecorder;
use codex_protocol::items::TurnItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::RolloutItem;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use tracing::warn;

/// Return the indices of user message boundaries in a rollout.
///
/// A user message boundary is a `RolloutItem::ResponseItem(ResponseItem::Message { .. })`
/// whose parsed turn item is `TurnItem::UserMessage`.
///
/// Rollouts can contain `ThreadRolledBack` markers. Those markers indicate that the
/// last N user turns were removed from the effective thread history; we apply them here so
/// indexing uses the post-rollback history rather than the raw stream.
pub(crate) fn user_message_positions_in_rollout(items: &[RolloutItem]) -> Vec<usize> {
    let mut user_positions = Vec::new();
    for (idx, item) in items.iter().enumerate() {
        match item {
            RolloutItem::ResponseItem(item @ ResponseItem::Message { .. })
                if matches!(
                    event_mapping::parse_turn_item(item),
                    Some(TurnItem::UserMessage(_))
                ) =>
            {
                user_positions.push(idx);
            }
            RolloutItem::EventMsg(EventMsg::ThreadRolledBack(rollback)) => {
                let num_turns = usize::try_from(rollback.num_turns).unwrap_or(usize::MAX);
                let new_len = user_positions.len().saturating_sub(num_turns);
                user_positions.truncate(new_len);
            }
            _ => {}
        }
    }
    user_positions
}

/// Return a prefix of `items` obtained by cutting strictly before the nth user message.
///
/// The boundary index is 0-based from the start of `items` (so `n_from_start = 0` returns
/// a prefix that excludes the first user message and everything after it).
///
/// If `n_from_start` is `usize::MAX`, this returns the full rollout (no truncation).
/// If fewer than or equal to `n_from_start` user messages exist, this returns an empty
/// vector (out of range).
pub(crate) fn truncate_rollout_before_nth_user_message_from_start(
    items: &[RolloutItem],
    n_from_start: usize,
) -> Vec<RolloutItem> {
    if n_from_start == usize::MAX {
        return items.to_vec();
    }

    let user_positions = user_message_positions_in_rollout(items);

    // If fewer than or equal to n user messages exist, treat as empty (out of range).
    if user_positions.len() <= n_from_start {
        return Vec::new();
    }

    // Cut strictly before the nth user message (do not keep the nth itself).
    let cut_idx = user_positions[n_from_start];
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

fn materialize_rollout_items_for_replay_at_depth<'a>(
    codex_home: &'a Path,
    rollout_items: &'a [RolloutItem],
    depth: usize,
) -> Pin<Box<dyn Future<Output = Vec<RolloutItem>> + Send + 'a>> {
    const MAX_FORK_REFERENCE_DEPTH: usize = 8;

    Box::pin(async move {
        let mut materialized = Vec::new();
        let mut idx = 0;

        while idx < rollout_items.len() {
            match &rollout_items[idx] {
                RolloutItem::ForkReference(reference) => {
                    if depth >= MAX_FORK_REFERENCE_DEPTH {
                        warn!(
                            "skipping fork reference recursion at depth {} for {:?}",
                            depth, reference.rollout_path
                        );
                        idx += 1;
                        continue;
                    }

                    let resolved_rollout_path = match resolve_fork_reference_rollout_path(
                        codex_home,
                        &reference.rollout_path,
                    )
                    .await
                    {
                        Ok(path) => path,
                        Err(err) => {
                            warn!(
                                "failed to resolve fork reference rollout {:?}: {err}",
                                reference.rollout_path
                            );
                            idx += 1;
                            continue;
                        }
                    };
                    let parent_history = match RolloutRecorder::get_rollout_history(
                        &resolved_rollout_path,
                    )
                    .await
                    {
                        Ok(history) => history,
                        Err(err) => {
                            warn!(
                                "failed to load fork reference rollout {:?} (resolved from {:?}): {err}",
                                resolved_rollout_path, reference.rollout_path
                            );
                            idx += 1;
                            continue;
                        }
                    };
                    let parent_history_items = parent_history.get_rollout_items();
                    let raw_parent_items = truncate_rollout_before_nth_user_message_from_start(
                        &parent_history_items,
                        reference.nth_user_message,
                    );
                    let parent_items = materialize_rollout_items_for_replay_at_depth(
                        codex_home,
                        &parent_history_items,
                        depth + 1,
                    )
                    .await;
                    let truncated_parent_items =
                        truncate_rollout_before_nth_user_message_from_start(
                            &parent_items,
                            reference.nth_user_message,
                        );
                    let remaining_items = &rollout_items[idx + 1..];
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
                    idx += 1;
                    idx += copied_parent_prefix_len;
                }
                item => {
                    materialized.push(item.clone());
                    idx += 1;
                }
            }
        }

        materialized
    })
}

pub(crate) async fn materialize_rollout_items_for_replay(
    codex_home: &Path,
    rollout_items: &[RolloutItem],
) -> Vec<RolloutItem> {
    materialize_rollout_items_for_replay_at_depth(codex_home, rollout_items, 0).await
}

#[cfg(test)]
#[path = "truncation_tests.rs"]
mod tests;
