use crate::compact;
use crate::compact::plan_retention::markers;
use codex_protocol::RetainedProposedPlan;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;
use codex_utils_stream_parser::extract_proposed_plan_text;
use codex_utils_stream_parser::strip_citations;

pub(crate) fn hydrate_latest_proposed_plan_text(
    latest_proposed_plan_text: &mut Option<String>,
    retained_proposed_plan: &RetainedProposedPlan,
) {
    if latest_proposed_plan_text.is_none()
        && let RetainedProposedPlan::ProposedPlan { text } = retained_proposed_plan
    {
        *latest_proposed_plan_text = Some(text.clone());
    }
}

pub(crate) fn rebuild_legacy_compaction_history(
    history: &[ResponseItem],
    summary_text: &str,
    retained_proposed_plan: &RetainedProposedPlan,
) -> Vec<ResponseItem> {
    let user_messages = markers::collect_user_messages(history);
    let rebuilt = compact::build_compacted_history(Vec::new(), &user_messages, summary_text);
    markers::insert_retained_plan_context_message(rebuilt, retained_proposed_plan)
}

pub(crate) fn latest_proposed_plan_text(history: &[ResponseItem]) -> Option<String> {
    history.iter().rev().find_map(|item| {
        let ResponseItem::Message { content, .. } = item else {
            return None;
        };

        let mut text = String::new();
        for entry in content {
            match entry {
                ContentItem::InputText { text: chunk }
                | ContentItem::OutputText { text: chunk } => text.push_str(chunk),
                _ => {}
            }
        }

        let plan_text = extract_proposed_plan_text(&text)?;
        let (plan_text, _citations) = strip_citations(&plan_text);
        (!plan_text.trim().is_empty()).then_some(plan_text)
    })
}
