use super::*;
use crate::tools::context::ToolInvocation;
use async_trait::async_trait;
use pretty_assertions::assert_eq;

struct TestHandler;

#[async_trait]
impl ToolHandler for TestHandler {
    type Output = crate::tools::context::FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, _invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        unreachable!("test handler should not be invoked")
    }
}

#[test]
fn unsupported_message_stays_generic_for_non_collab_function_tools() {
    let payload = ToolPayload::Function {
        arguments: "{}".to_string(),
    };

    let message = unsupported_tool_call_message(&payload, "shell", None);

    assert_eq!(message, "unsupported call: shell");
}

#[test]
fn unsupported_message_stays_generic_for_non_collab_custom_tools() {
    let payload = ToolPayload::Custom {
        input: "input".to_string(),
    };

    let message = unsupported_tool_call_message(&payload, "non_collab_custom_tool", None);

    assert_eq!(
        message,
        "unsupported custom tool call: non_collab_custom_tool"
    );
}

#[test]
fn unsupported_message_calls_out_collab_feature_or_depth_gating() {
    let payload = ToolPayload::Function {
        arguments: "{}".to_string(),
    };
    for tool_name in [
        "spawn_agent",
        "send_input",
        "resume_agent",
        "compact_parent_context",
        "list_agents",
        "wait",
        "close_agent",
    ] {
        let message = unsupported_tool_call_message(&payload, tool_name, None);
        assert_eq!(
            message,
            format!(
                "unsupported call: {tool_name}. collab tools may be disabled by feature/depth gating."
            )
        );
    }
}

#[test]
fn handler_looks_up_namespaced_aliases_explicitly() {
    let plain_handler = Arc::new(TestHandler) as Arc<dyn AnyToolHandler>;
    let namespaced_handler = Arc::new(TestHandler) as Arc<dyn AnyToolHandler>;
    let namespace = "mcp__codex_apps__gmail";
    let tool_name = "gmail_get_recent_emails";
    let namespaced_name = tool_handler_key(tool_name, Some(namespace));
    let registry = ToolRegistry::new(HashMap::from([
        (tool_name.to_string(), Arc::clone(&plain_handler)),
        (namespaced_name, Arc::clone(&namespaced_handler)),
    ]));

    let plain = registry.handler(tool_name, None);
    let namespaced = registry.handler(tool_name, Some(namespace));
    let missing_namespaced = registry.handler(tool_name, Some("mcp__codex_apps__calendar"));

    assert_eq!(plain.is_some(), true);
    assert_eq!(namespaced.is_some(), true);
    assert_eq!(missing_namespaced.is_none(), true);
    assert!(
        plain
            .as_ref()
            .is_some_and(|handler| Arc::ptr_eq(handler, &plain_handler))
    );
    assert!(
        namespaced
            .as_ref()
            .is_some_and(|handler| Arc::ptr_eq(handler, &namespaced_handler))
    );
}
