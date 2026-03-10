use crate::config::types::CollabInboxDeliveryRole;
use crate::error::CodexErr;
use crate::error::Result as CodexResult;
use codex_protocol::ThreadId;
use codex_protocol::agent_inbox::build_legacy_message_text;
use codex_protocol::agent_inbox::build_tool_response_input_items;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseInputItem;
use uuid::Uuid;

pub(super) fn build_agent_inbox_items(
    role: CollabInboxDeliveryRole,
    sender_thread_id: ThreadId,
    message: String,
    prepend_turn_start_user_message: bool,
) -> CodexResult<Vec<ResponseInputItem>> {
    let mut items = Vec::new();
    if prepend_turn_start_user_message {
        items.push(ResponseInputItem::Message {
            role: "user".to_string(),
            content: vec![ContentItem::InputText {
                text: String::new(),
            }],
        });
    }

    let role_items = match role {
        CollabInboxDeliveryRole::Tool => {
            let call_id = format!("agent_inbox_{}", Uuid::new_v4());
            build_tool_response_input_items(sender_thread_id, message, call_id).map_err(|err| {
                CodexErr::UnsupportedOperation(format!(
                    "failed to serialize collab inbox payload: {err}"
                ))
            })?
        }
        CollabInboxDeliveryRole::Assistant => vec![ResponseInputItem::Message {
            role: "assistant".to_string(),
            content: vec![ContentItem::OutputText {
                text: build_legacy_message_text(sender_thread_id, &message),
            }],
        }],
        CollabInboxDeliveryRole::Developer => vec![ResponseInputItem::Message {
            role: "developer".to_string(),
            content: vec![ContentItem::InputText {
                text: build_legacy_message_text(sender_thread_id, &message),
            }],
        }],
    };
    items.extend(role_items);
    Ok(items)
}
