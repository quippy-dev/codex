use crate::compact::CompactTrigger;
use crate::compact::SUMMARY_PREFIX;
use crate::session::session::Session;
use crate::session::turn_context::TurnContext;
use codex_protocol::RetainedProposedPlan;
use codex_protocol::config_types::ModeKind;
use codex_protocol::items::TurnItem;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;

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
    message.starts_with(format!("{SUMMARY_PREFIX}\n").as_str())
}

pub(crate) fn retained_proposed_plan_context_message(plan_text: &str) -> ResponseItem {
    let text = format!("<proposed_plan>\n{plan_text}</proposed_plan>");
    ResponseItem::Message {
        id: None,
        role: "developer".to_string(),
        content: vec![ContentItem::InputText { text }],
        phase: None,
    }
}

pub(crate) async fn retained_proposed_plan_for_manual_plan_compaction(
    sess: &Session,
    turn_context: &TurnContext,
    compact_trigger: CompactTrigger,
) -> RetainedProposedPlan {
    if compact_trigger != CompactTrigger::Manual {
        return RetainedProposedPlan::None;
    }
    if turn_context.collaboration_mode.mode != ModeKind::Plan {
        return RetainedProposedPlan::None;
    }
    let Some(plan_text) = sess.latest_proposed_plan_text().await else {
        return RetainedProposedPlan::None;
    };
    if plan_text.trim().is_empty() {
        return RetainedProposedPlan::None;
    }
    RetainedProposedPlan::ProposedPlan { text: plan_text }
}

pub(crate) fn insert_retained_plan_context_message(
    mut history: Vec<ResponseItem>,
    retained_proposed_plan: &RetainedProposedPlan,
) -> Vec<ResponseItem> {
    let RetainedProposedPlan::ProposedPlan { text } = retained_proposed_plan else {
        return history;
    };
    if text.trim().is_empty() {
        return history;
    }

    let insertion_index = history.iter().enumerate().rev().find_map(|(idx, item)| {
        if let Some(TurnItem::UserMessage(user)) = crate::event_mapping::parse_turn_item(item)
            && is_summary_message(&user.message())
        {
            return Some(idx);
        }
        matches!(item, ResponseItem::Compaction { .. }).then_some(idx)
    });

    let retained = retained_proposed_plan_context_message(text);
    if let Some(idx) = insertion_index {
        history.insert(idx, retained);
    } else {
        history.push(retained);
    }
    history
}
