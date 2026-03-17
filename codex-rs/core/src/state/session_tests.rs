use super::*;
use crate::codex::make_session_configuration_for_tests;
use crate::protocol::RateLimitWindow;
use codex_protocol::models::ContentItem;
use pretty_assertions::assert_eq;

fn deferred_collab_message(text: String) -> ResponseInputItem {
    ResponseInputItem::Message {
        role: "developer".to_string(),
        content: vec![ContentItem::InputText { text }],
    }
}

#[tokio::test]
// Verifies connector merging deduplicates repeated IDs.
async fn merge_connector_selection_deduplicates_entries() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    let merged = state.merge_connector_selection([
        "calendar".to_string(),
        "calendar".to_string(),
        "drive".to_string(),
    ]);

    assert_eq!(
        merged,
        HashSet::from(["calendar".to_string(), "drive".to_string()])
    );
}

#[tokio::test]
// Verifies clearing connector selection removes all saved IDs.
async fn clear_connector_selection_removes_entries() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    state.merge_connector_selection(["calendar".to_string()]);

    state.clear_connector_selection();

    assert_eq!(state.get_connector_selection(), HashSet::new());
}

#[tokio::test]
async fn restore_deferred_collab_items_enforces_item_cap_after_interleaving_enqueue() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    let restored_item = deferred_collab_message("restored-priority-item".to_string());

    state
        .enqueue_deferred_collab_items(vec![restored_item.clone()])
        .expect("enqueue initial deferred item");
    let taken_for_restore = state.take_deferred_collab_items();
    assert_eq!(taken_for_restore, vec![restored_item.clone()]);

    let interleaved_items = (0..DEFERRED_COLLAB_ITEMS_MAX)
        .map(|idx| deferred_collab_message(format!("interleaved-item-{idx}")))
        .collect::<Vec<_>>();
    state
        .enqueue_deferred_collab_items(interleaved_items)
        .expect("enqueue interleaved deferred items");

    state.restore_deferred_collab_items(taken_for_restore);

    let (item_count, total_bytes) = state.deferred_collab_stats();
    assert_eq!(item_count, DEFERRED_COLLAB_ITEMS_MAX);
    assert!(total_bytes <= DEFERRED_COLLAB_BYTES_MAX);

    let restored_queue = state.take_deferred_collab_items();
    assert_eq!(restored_queue.first(), Some(&restored_item));
    assert_eq!(restored_queue.len(), DEFERRED_COLLAB_ITEMS_MAX);
}

#[tokio::test]
async fn restore_deferred_collab_items_enforces_byte_cap_after_interleaving_enqueue() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    let payload = "x".repeat(DEFERRED_COLLAB_BYTES_MAX / 2);
    let restored_item = deferred_collab_message(payload.clone());
    let interleaved_item = deferred_collab_message(payload);

    state
        .enqueue_deferred_collab_items(vec![restored_item.clone()])
        .expect("enqueue deferred item to later restore");
    let taken_for_restore = state.take_deferred_collab_items();

    state
        .enqueue_deferred_collab_items(vec![interleaved_item])
        .expect("enqueue interleaved deferred item");

    state.restore_deferred_collab_items(taken_for_restore);

    let (item_count, total_bytes) = state.deferred_collab_stats();
    assert_eq!(item_count, 1);
    assert!(total_bytes <= DEFERRED_COLLAB_BYTES_MAX);

    let expected_bytes =
        serialized_response_input_items_bytes(std::slice::from_ref(&restored_item))
            .expect("serialize restored deferred item");
    assert_eq!(total_bytes, expected_bytes);
    assert_eq!(state.take_deferred_collab_items(), vec![restored_item]);
}

#[tokio::test]
async fn enqueue_post_turn_agent_items_tracks_stats_and_take_clears_queue() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    let items = vec![
        deferred_collab_message("post-turn-agent-1".to_string()),
        deferred_collab_message("post-turn-agent-2".to_string()),
    ];
    let expected_bytes =
        serialized_response_input_items_bytes(&items).expect("serialize post-turn items");

    state
        .enqueue_post_turn_agent_items(items.clone())
        .expect("enqueue post-turn agent items");

    assert_eq!(state.post_turn_agent_stats(), (2, expected_bytes, false));
    assert_eq!(state.take_post_turn_agent_items(), items);
    assert_eq!(state.post_turn_agent_stats(), (0, 0, false));
}

#[tokio::test]
async fn enqueue_post_turn_agent_items_enforces_item_cap() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);
    let items = (0..=DEFERRED_COLLAB_ITEMS_MAX)
        .map(|idx| deferred_collab_message(format!("post-turn-item-{idx}")))
        .collect::<Vec<_>>();

    let err = state
        .enqueue_post_turn_agent_items(items)
        .expect_err("item cap should be enforced");

    assert_eq!(
        err,
        DeferredCollabEnqueueError::TooManyItems {
            existing_items: 0,
            incoming_items: DEFERRED_COLLAB_ITEMS_MAX + 1,
            max_items: DEFERRED_COLLAB_ITEMS_MAX,
        }
    );
}

#[tokio::test]
async fn set_rate_limits_defaults_limit_id_to_codex_when_missing() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);

    state.set_rate_limits(RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: 12.0,
            window_minutes: Some(60),
            resets_at: Some(100),
        }),
        secondary: None,
        credits: None,
        plan_type: None,
    });

    assert_eq!(
        state
            .latest_rate_limits
            .as_ref()
            .and_then(|v| v.limit_id.clone()),
        Some("codex".to_string())
    );
}

#[tokio::test]
async fn set_rate_limits_defaults_to_codex_when_limit_id_missing_after_other_bucket() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);

    state.set_rate_limits(RateLimitSnapshot {
        limit_id: Some("codex_other".to_string()),
        limit_name: Some("codex_other".to_string()),
        primary: Some(RateLimitWindow {
            used_percent: 20.0,
            window_minutes: Some(60),
            resets_at: Some(200),
        }),
        secondary: None,
        credits: None,
        plan_type: None,
    });
    state.set_rate_limits(RateLimitSnapshot {
        limit_id: None,
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: 30.0,
            window_minutes: Some(60),
            resets_at: Some(300),
        }),
        secondary: None,
        credits: None,
        plan_type: None,
    });

    assert_eq!(
        state
            .latest_rate_limits
            .as_ref()
            .and_then(|v| v.limit_id.clone()),
        Some("codex".to_string())
    );
}

#[tokio::test]
async fn set_rate_limits_carries_credits_and_plan_type_from_codex_to_codex_other() {
    let session_configuration = make_session_configuration_for_tests().await;
    let mut state = SessionState::new(session_configuration);

    state.set_rate_limits(RateLimitSnapshot {
        limit_id: Some("codex".to_string()),
        limit_name: Some("codex".to_string()),
        primary: Some(RateLimitWindow {
            used_percent: 10.0,
            window_minutes: Some(60),
            resets_at: Some(100),
        }),
        secondary: None,
        credits: Some(crate::protocol::CreditsSnapshot {
            has_credits: true,
            unlimited: false,
            balance: Some("50".to_string()),
        }),
        plan_type: Some(codex_protocol::account::PlanType::Plus),
    });

    state.set_rate_limits(RateLimitSnapshot {
        limit_id: Some("codex_other".to_string()),
        limit_name: None,
        primary: Some(RateLimitWindow {
            used_percent: 30.0,
            window_minutes: Some(120),
            resets_at: Some(200),
        }),
        secondary: None,
        credits: None,
        plan_type: None,
    });

    assert_eq!(
        state.latest_rate_limits,
        Some(RateLimitSnapshot {
            limit_id: Some("codex_other".to_string()),
            limit_name: None,
            primary: Some(RateLimitWindow {
                used_percent: 30.0,
                window_minutes: Some(120),
                resets_at: Some(200),
            }),
            secondary: None,
            credits: Some(crate::protocol::CreditsSnapshot {
                has_credits: true,
                unlimited: false,
                balance: Some("50".to_string()),
            }),
            plan_type: Some(codex_protocol::account::PlanType::Plus),
        })
    );
}
