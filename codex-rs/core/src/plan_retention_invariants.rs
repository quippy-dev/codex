use codex_protocol::items::TurnItem;

pub(crate) fn completed_plan_text_for_manual_compaction(item: &TurnItem) -> Option<String> {
    match item {
        TurnItem::Plan(plan_item) => Some(plan_item.text.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_protocol::items::PlanItem;

    #[test]
    fn extracts_text_for_completed_plan_item() {
        let item = TurnItem::Plan(PlanItem {
            id: "plan-id".to_string(),
            text: "cached plan".to_string(),
        });

        assert_eq!(
            completed_plan_text_for_manual_compaction(&item),
            Some("cached plan".to_string())
        );
    }
}
