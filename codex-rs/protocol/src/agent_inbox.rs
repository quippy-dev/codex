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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_agent_nickname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_agent_role: Option<String>,
    pub message: String,
}

impl AgentInboxPayload {
    pub fn new(
        sender_thread_id: ThreadId,
        sender_agent_nickname: Option<String>,
        sender_agent_role: Option<String>,
        message: String,
    ) -> Self {
        Self {
            injected: true,
            kind: AGENT_INBOX_KIND.to_string(),
            sender_thread_id,
            sender_agent_nickname,
            sender_agent_role,
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
    pub canonical_sender: Option<String>,
    pub message: String,
    pub encoding: AgentInboxEncoding,
}

pub fn build_tool_response_input_items(
    sender_thread_id: ThreadId,
    sender_agent_nickname: Option<String>,
    sender_agent_role: Option<String>,
    message: String,
    call_id: String,
) -> Result<Vec<ResponseInputItem>, serde_json::Error> {
    let payload = AgentInboxPayload::new(
        sender_thread_id,
        sender_agent_nickname,
        sender_agent_role,
        message,
    );
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
    if !is_agent_inbox_response_item(item) {
        return None;
    }

    match item {
        ResponseItem::FunctionCallOutput { output, .. } => {
            let text = output.body.to_text()?;
            let payload: AgentInboxPayload = serde_json::from_str(&text).ok()?;
            Some(AgentInboxMessage {
                sender: Some(format_sender_label(
                    payload.sender_thread_id,
                    payload.sender_agent_nickname.as_deref(),
                    payload.sender_agent_role.as_deref(),
                )),
                canonical_sender: Some(payload.sender_thread_id.to_string()),
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
            let canonical_sender = normalized_sender(sender);
            Some(AgentInboxMessage {
                sender: canonical_sender.clone(),
                canonical_sender,
                message: message.trim_start().to_string(),
                encoding: AgentInboxEncoding::LegacyMessage,
            })
        }
        _ => None,
    }
}

pub fn is_agent_inbox_response_item(item: &ResponseItem) -> bool {
    match item {
        ResponseItem::FunctionCall { name, .. } => name == AGENT_INBOX_KIND,
        ResponseItem::FunctionCallOutput { output, .. } => {
            let Some(text) = output.body.to_text() else {
                return false;
            };
            let Ok(payload) = serde_json::from_str::<AgentInboxPayload>(&text) else {
                return false;
            };
            payload.injected && payload.kind == AGENT_INBOX_KIND
        }
        ResponseItem::Message { content, .. } => {
            content.iter().filter_map(message_text).any(|text| {
                let Some(rest) = text.strip_prefix(AGENT_INBOX_MESSAGE_PREFIX) else {
                    return false;
                };
                let Some((sender, _message)) = rest.split_once(']') else {
                    return false;
                };
                ThreadId::from_string(sender.trim()).is_ok()
            })
        }
        _ => false,
    }
}

fn message_text(item: &ContentItem) -> Option<&str> {
    match item {
        ContentItem::InputText { text } | ContentItem::OutputText { text } => Some(text.as_str()),
        _ => None,
    }
}

fn normalized_sender(sender: &str) -> Option<String> {
    let sender = sender.trim();
    (!sender.is_empty()).then(|| sender.to_string())
}

fn format_sender_label(
    sender_thread_id: ThreadId,
    sender_agent_nickname: Option<&str>,
    sender_agent_role: Option<&str>,
) -> String {
    let sender_agent_nickname = sender_agent_nickname
        .map(str::trim)
        .filter(|nickname| !nickname.is_empty());
    let sender_agent_role = sender_agent_role
        .map(str::trim)
        .filter(|role| !role.is_empty());
    match (sender_agent_nickname, sender_agent_role) {
        (Some(sender_agent_nickname), Some(sender_agent_role)) => {
            format!("{sender_agent_nickname} [{sender_agent_role}]")
        }
        (Some(sender_agent_nickname), None) => sender_agent_nickname.to_string(),
        (None, Some(sender_agent_role)) => format!("[{sender_agent_role}]"),
        (None, None) => sender_thread_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_function_call_output_prefers_sender_identity_label() {
        let sender_thread_id =
            ThreadId::from_string("019cbff7-558b-77d3-8653-8238ab5361ec").expect("valid thread");
        let items = build_tool_response_input_items(
            sender_thread_id,
            Some("Atlas".to_string()),
            Some("worker".to_string()),
            "Please review the latest diff".to_string(),
            "call-1".to_string(),
        )
        .expect("agent inbox payload should serialize");
        let item = ResponseItem::from(
            items
                .last()
                .expect("function call output item should exist")
                .clone(),
        );

        let parsed = parse_agent_inbox_message_from_item(&item).expect("message should parse");
        assert_eq!(parsed.sender.as_deref(), Some("Atlas [worker]"));
        assert_eq!(parsed.message, "Please review the latest diff");
        assert_eq!(parsed.encoding, AgentInboxEncoding::FunctionCallOutput);
    }
}
