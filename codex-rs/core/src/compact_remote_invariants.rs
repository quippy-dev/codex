use crate::compact::CompactTrigger;
use crate::compact::insert_retained_plan_context_message;
use crate::compact::retained_proposed_plan_for_manual_plan_compaction;
use crate::encrypted_content_fallback::apply_invalid_encrypted_content_fallback;
use crate::session::session::Session;
use crate::session::turn_context::TurnContext;
use codex_protocol::RetainedProposedPlan;
use codex_protocol::error::CodexErr;
use codex_protocol::models::ResponseItem;

pub(crate) fn retry_once_invalid_encrypted_content_with_sanitized_prompt_input(
    already_retried: &mut bool,
    err: &CodexErr,
    prompt_input: &mut Vec<ResponseItem>,
) -> bool {
    if apply_invalid_encrypted_content_fallback(already_retried, err, prompt_input) {
        tracing::warn!(
            "invalid_encrypted_content during remote compact - retrying once with sanitized prompt input"
        );
        return true;
    }

    false
}

pub(crate) async fn insert_retained_plan_for_remote_compaction(
    sess: &Session,
    turn_context: &TurnContext,
    compact_trigger: CompactTrigger,
    compacted_history: Vec<ResponseItem>,
) -> (Vec<ResponseItem>, RetainedProposedPlan) {
    let retained_proposed_plan =
        retained_proposed_plan_for_manual_plan_compaction(sess, turn_context, compact_trigger)
            .await;
    (
        insert_retained_plan_context_message(compacted_history, &retained_proposed_plan),
        retained_proposed_plan,
    )
}
