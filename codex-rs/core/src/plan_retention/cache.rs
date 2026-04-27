use crate::plan_retention_invariants::completed_plan_text_for_manual_compaction;
use crate::session::session::Session;
use codex_protocol::items::TurnItem;

pub(crate) async fn cache_completed_plan_item(sess: &Session, item: &TurnItem) {
    if let Some(plan_text) = completed_plan_text_for_manual_compaction(item) {
        sess.set_latest_proposed_plan_text(Some(plan_text)).await;
    }
}

pub(crate) async fn clear_latest_proposed_plan_text(sess: &Session) {
    sess.set_latest_proposed_plan_text(None).await;
}

pub(crate) async fn hydrate_latest_proposed_plan_text(
    sess: &Session,
    latest_proposed_plan_text: Option<String>,
) {
    sess.set_latest_proposed_plan_text(latest_proposed_plan_text)
        .await;
}
