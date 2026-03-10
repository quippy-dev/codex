use crate::ThreadId;
use crate::models::ContentItem;
use crate::models::FunctionCallOutputBody;
use crate::models::FunctionCallOutputPayload;
use crate::models::ResponseInputItem;
use crate::models::ResponseItem;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

pub const AGENT_INBOX_KIND: &str = "agent_inbox";
pub const AGENT_INBOX_MESSAGE_PREFIX: &str = "[agent_inbox:";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
pub struct AgentInboxPayload {
    pub injected: bool,
    pub kind: String,
    pub sender_thread_id: ThreadId,
    pub message: String,
}

impl AgentInboxPayload {
    pub fn new(sender_thread_id: ThreadId, message: String) -> Self {
        Self {
            injected: true,
            kind: AGENT_INBOX_KIND.to_string(),
            sender_thread_id,
            message,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentInboxEncoding {
    FunctionCallOutput,
    LegacyMessage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentInboxMessage {
    pub sender: Option<String>,
    pub message: String,
    pub encoding: AgentInboxEncoding,
}

pub fn build_tool_response_input_items(
    sender_thread_id: ThreadId,
    message: String,
    call_id: String,
) -> Result<Vec<ResponseInputItem>, serde_json::Error> {
    let payload = AgentInboxPayload::new(sender_thread_id, message);
    let output = serde_json::to_string(&payload)?;

    Ok(vec![
        ResponseInputItem::FunctionCall {
            name: AGENT_INBOX_KIND.to_string(),
            arguments: "{}".to_string(),
            call_id: call_id.clone(),
        },
        ResponseInputItem::FunctionCallOutput {
            call_id,
            output: FunctionCallOutputPayload {
                body: FunctionCallOutputBody::Text(output),
                ..Default::default()
            },
        },
    ])
}

pub fn build_legacy_message_text(sender_thread_id: ThreadId, message: &str) -> String {
    format!("{AGENT_INBOX_MESSAGE_PREFIX}{sender_thread_id}] {message}")
}

pub fn parse_agent_inbox_message_from_item(item: &ResponseItem) -> Option<AgentInboxMessage> {
    match item {
        ResponseItem::FunctionCallOutput { output, .. } => {
            let text = output.body.to_text()?;
            let payload: AgentInboxPayload = serde_json::from_str(&text).ok()?;
            if !payload.injected || payload.kind != AGENT_INBOX_KIND {
                return None;
            }
            Some(AgentInboxMessage {
                sender: Some(payload.sender_thread_id.to_string()),
                message: payload.message,
                encoding: AgentInboxEncoding::FunctionCallOutput,
            })
        }
        ResponseItem::Message { content, .. } => {
            let text = content.iter().find_map(|item| match item {
                ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                    Some(text.as_str())
                }
                _ => None,
            })?;
            let rest = text.strip_prefix(AGENT_INBOX_MESSAGE_PREFIX)?;
            let (sender, message) = rest.split_once(']')?;
            Some(AgentInboxMessage {
                sender: normalized_sender(sender),
                message: message.trim_start().to_string(),
                encoding: AgentInboxEncoding::LegacyMessage,
            })
        }
        _ => None,
    }
}

fn normalized_sender(sender: &str) -> Option<String> {
    let sender = sender.trim();
    (!sender.is_empty()).then(|| sender.to_string())
}
