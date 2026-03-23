use crate::agent::AgentStatus;
use crate::agent::WatchdogParentCompactionResult;
use crate::codex::Session;
use crate::codex::TurnContext;
use crate::error::CodexErr;
use crate::function_tool::FunctionCallError;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::handlers::parse_arguments;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;
use async_trait::async_trait;
use codex_features::Feature;
use codex_protocol::ThreadId;
use codex_protocol::models::BaseInstructions;
use codex_protocol::openai_models::ModelInfo;
use codex_protocol::openai_models::ModelPreset;
use codex_protocol::openai_models::ReasoningEffort;
use codex_protocol::protocol::AgentSpawnMode;
use codex_protocol::protocol::CollabAgentInteractionBeginEvent;
use codex_protocol::protocol::CollabAgentInteractionEndEvent;
use codex_protocol::protocol::CollabAgentRef;
use codex_protocol::protocol::CollabAgentSpawnBeginEvent;
use codex_protocol::protocol::CollabAgentSpawnEndEvent;
use codex_protocol::protocol::CollabAgentStatusEntry;
use codex_protocol::protocol::CollabCloseBeginEvent;
use codex_protocol::protocol::CollabCloseEndEvent;
use codex_protocol::protocol::CollabCloseResult;
use codex_protocol::protocol::CollabPeekEndEvent;
use codex_protocol::protocol::CollabResumeBeginEvent;
use codex_protocol::protocol::CollabResumeEndEvent;
use codex_protocol::protocol::CollabWaitingBeginEvent;
use codex_protocol::protocol::CollabWaitingEndEvent;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::user_input::UserInput;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::HashSet;

pub mod close_agent;
mod discovery;
mod resume_agent;
mod send_input;
mod shared;
mod spawn;
pub(crate) mod wait;

pub(crate) use shared::*;

pub struct MultiAgentHandler;
pub(crate) struct SpawnAgentHandler;
pub(crate) struct SendInputHandler;
pub(crate) struct ResumeAgentHandler;
pub(crate) struct WaitAgentHandler;
pub(crate) struct CloseAgentHandler;

/// Minimum wait timeout to prevent tight polling loops from burning CPU.
pub(crate) const MIN_WAIT_TIMEOUT_MS: i64 = 10_000;
pub(crate) const DEFAULT_WAIT_TIMEOUT_MS: i64 = 30_000;
pub(crate) const MAX_WAIT_TIMEOUT_MS: i64 = 3600 * 1000;

#[derive(Debug, Deserialize)]
struct CloseAgentArgs {
    id: String,
}

#[async_trait]
impl ToolHandler for MultiAgentHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    fn matches_kind(&self, payload: &ToolPayload) -> bool {
        matches!(payload, ToolPayload::Function { .. })
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation {
            session,
            turn,
            tool_name,
            payload,
            call_id,
            ..
        } = invocation;

        let arguments = match payload {
            ToolPayload::Function { arguments } => arguments,
            _ => {
                return Err(FunctionCallError::RespondToModel(
                    "multi-agent handler received unsupported payload".to_string(),
                ));
            }
        };

        match tool_name.as_str() {
            "spawn_agent" => spawn::handle(session, turn, call_id, arguments).await,
            "send_input" => send_input::handle(session, turn, call_id, arguments).await,
            "resume_agent" => resume_agent::handle(session, turn, call_id, arguments).await,
            "compact_parent_context" if !turn.config.features.enabled(Feature::AgentWatchdog) => {
                Err(FunctionCallError::RespondToModel(
                    "watchdogs are disabled".to_string(),
                ))
            }
            "compact_parent_context" => {
                discovery::compact_parent_context::handle(session, turn, call_id, arguments).await
            }
            "list_agents" => {
                discovery::list_agents::handle(session, turn, call_id, arguments).await
            }
            "peek_agents" => {
                discovery::peek_agents::handle(session, turn, call_id, arguments).await
            }
            "wait" | "wait_agent" => wait::handle(session, turn, call_id, arguments).await,
            "close_agent" => close_agent::handle(session, turn, call_id, arguments).await,
            other => Err(FunctionCallError::RespondToModel(format!(
                "unsupported multi-agent tool {other}"
            ))),
        }
    }
}

fn function_arguments(payload: ToolPayload) -> Result<String, FunctionCallError> {
    match payload {
        ToolPayload::Function { arguments } => Ok(arguments),
        _ => Err(FunctionCallError::RespondToModel(
            "multi-agent handler received unsupported payload".to_string(),
        )),
    }
}

macro_rules! impl_forwarding_handler {
    ($handler:ident, $call:path) => {
        #[async_trait]
        impl ToolHandler for $handler {
            type Output = FunctionToolOutput;

            fn kind(&self) -> ToolKind {
                ToolKind::Function
            }

            fn matches_kind(&self, payload: &ToolPayload) -> bool {
                matches!(payload, ToolPayload::Function { .. })
            }

            async fn handle(
                &self,
                invocation: ToolInvocation,
            ) -> Result<Self::Output, FunctionCallError> {
                let ToolInvocation {
                    session,
                    turn,
                    payload,
                    call_id,
                    ..
                } = invocation;
                let arguments = function_arguments(payload)?;
                $call(session, turn, call_id, arguments).await
            }
        }
    };
}

impl_forwarding_handler!(SpawnAgentHandler, spawn::handle);
impl_forwarding_handler!(SendInputHandler, send_input::handle);
impl_forwarding_handler!(ResumeAgentHandler, resume_agent::handle);
impl_forwarding_handler!(WaitAgentHandler, wait::handle);
impl_forwarding_handler!(CloseAgentHandler, close_agent::handle);

#[cfg(test)]
#[path = "multi_agents_tests.rs"]
mod tests;
