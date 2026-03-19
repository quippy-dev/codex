use codex_app_server_protocol::Turn;
use codex_app_server_protocol::TurnStatus;
use codex_core::RolloutRecorder;
use codex_core::resolve_fork_reference_rollout_path;
use codex_protocol::items::TurnItem;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::RolloutItem;
use codex_protocol::protocol::USER_MESSAGE_BEGIN;
use std::ffi::OsStr;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use tracing::warn;
use uuid::Uuid;

pub(crate) async fn read_rollout_items_from_rollout(
    path: &Path,
) -> std::io::Result<Vec<RolloutItem>> {
    let items = match RolloutRecorder::get_rollout_history(path).await? {
        codex_protocol::protocol::InitialHistory::New => Vec::new(),
        codex_protocol::protocol::InitialHistory::Forked(items) => items,
        codex_protocol::protocol::InitialHistory::Resumed(resumed) => resumed.history,
    };

    Ok(materialize_rollout_items_for_replay(codex_home_from_rollout_path(path), &items).await)
}

pub(crate) fn preview_from_rollout_items(items: &[RolloutItem]) -> String {
    items
        .iter()
        .find_map(|item| match item {
            RolloutItem::ResponseItem(item) => match codex_core::parse_turn_item(item) {
                Some(TurnItem::UserMessage(user)) => Some(user.message()),
                _ => None,
            },
            _ => None,
        })
        .map(|preview| match preview.find(USER_MESSAGE_BEGIN) {
            Some(idx) => preview[idx + USER_MESSAGE_BEGIN.len()..].trim().to_string(),
            None => preview,
        })
        .unwrap_or_default()
}

pub(crate) fn build_turns_from_response_history_items(items: &[RolloutItem]) -> Vec<Turn> {
    let mut turns = Vec::new();
    let mut current_turn_id: Option<String> = None;
    let mut current_turn_items = Vec::new();

    for item in items {
        let RolloutItem::ResponseItem(response_item) = item else {
            continue;
        };
        let Some(turn_item) = codex_core::parse_turn_item(response_item) else {
            continue;
        };

        let next_turn_id = match &turn_item {
            TurnItem::UserMessage(user) => Some(user.id.clone()),
            _ => None,
        };

        if matches!(turn_item, TurnItem::UserMessage(_)) && !current_turn_items.is_empty() {
            turns.push(Turn {
                id: current_turn_id
                    .take()
                    .unwrap_or_else(|| Uuid::now_v7().to_string()),
                items: std::mem::take(&mut current_turn_items),
                status: TurnStatus::Completed,
                error: None,
            });
        }

        if current_turn_id.is_none() {
            current_turn_id = next_turn_id.or_else(|| Some(Uuid::now_v7().to_string()));
        }

        current_turn_items.push(turn_item.into());
    }

    if !current_turn_items.is_empty() {
        turns.push(Turn {
            id: current_turn_id.unwrap_or_else(|| Uuid::now_v7().to_string()),
            items: current_turn_items,
            status: TurnStatus::Completed,
            error: None,
        });
    }

    turns
}

fn user_message_positions_in_rollout(items: &[RolloutItem]) -> Vec<usize> {
    let mut user_positions = Vec::new();
    for (idx, item) in items.iter().enumerate() {
        match item {
            RolloutItem::ResponseItem(item)
                if matches!(
                    codex_core::parse_turn_item(item),
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
            RolloutItem::ResponseItem(_)
            | RolloutItem::SessionMeta(_)
            | RolloutItem::ForkReference(_)
            | RolloutItem::Compacted(_)
            | RolloutItem::TurnContext(_)
            | RolloutItem::EventMsg(_) => {}
        }
    }
    user_positions
}

fn truncate_rollout_before_nth_user_message_from_start(
    items: &[RolloutItem],
    n_from_start: usize,
) -> Vec<RolloutItem> {
    if n_from_start == usize::MAX {
        return items.to_vec();
    }

    let user_positions = user_message_positions_in_rollout(items);
    if user_positions.len() <= n_from_start {
        return Vec::new();
    }

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

pub(crate) fn codex_home_from_rollout_path(path: &Path) -> Option<&Path> {
    path.ancestors().find_map(|ancestor| {
        let name = ancestor.file_name().and_then(OsStr::to_str)?;
        if name == codex_core::SESSIONS_SUBDIR || name == codex_core::ARCHIVED_SESSIONS_SUBDIR {
            ancestor.parent()
        } else {
            None
        }
    })
}

fn materialize_rollout_items_for_replay_at_depth<'a>(
    codex_home: Option<&'a Path>,
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

                    let resolved_rollout_path = if let Some(codex_home) = codex_home {
                        match resolve_fork_reference_rollout_path(
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
                        }
                    } else {
                        reference.rollout_path.clone()
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
    codex_home: Option<&Path>,
    rollout_items: &[RolloutItem],
) -> Vec<RolloutItem> {
    materialize_rollout_items_for_replay_at_depth(codex_home, rollout_items, 0).await
}

#[cfg(test)]
mod tests {
    use super::build_turns_from_response_history_items;
    use codex_app_server_protocol::ThreadItem;
    use codex_protocol::models::ContentItem;
    use codex_protocol::models::ResponseItem;
    use codex_protocol::protocol::RolloutItem;
    use pretty_assertions::assert_eq;

    #[test]
    fn build_turns_from_response_history_items_groups_user_boundaries() {
        let items = vec![
            RolloutItem::ResponseItem(ResponseItem::Message {
                id: Some("user-1".to_string()),
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "hello".to_string(),
                }],
                end_turn: None,
                phase: None,
            }),
            RolloutItem::ResponseItem(ResponseItem::Message {
                id: Some("assistant-1".to_string()),
                role: "assistant".to_string(),
                content: vec![ContentItem::OutputText {
                    text: "hi".to_string(),
                }],
                end_turn: None,
                phase: None,
            }),
            RolloutItem::ResponseItem(ResponseItem::Message {
                id: Some("user-2".to_string()),
                role: "user".to_string(),
                content: vec![ContentItem::InputText {
                    text: "again".to_string(),
                }],
                end_turn: None,
                phase: None,
            }),
        ];

        let turns = build_turns_from_response_history_items(&items);

        assert_eq!(turns.len(), 2);
        assert!(!turns[0].id.is_empty());
        assert!(!turns[1].id.is_empty());
        assert_ne!(turns[0].id, turns[1].id);
        assert!(matches!(turns[0].items[0], ThreadItem::UserMessage { .. }));
        assert!(matches!(turns[0].items[1], ThreadItem::AgentMessage { .. }));
        assert!(matches!(turns[1].items[0], ThreadItem::UserMessage { .. }));
    }
}
