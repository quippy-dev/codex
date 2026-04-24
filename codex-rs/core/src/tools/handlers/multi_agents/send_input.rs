use super::*;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct SendInputArgs {
    id: Option<String>,
    message: Option<String>,
    items: Option<Vec<UserInput>>,
    #[serde(default)]
    interrupt: bool,
}

#[derive(Debug, Serialize)]
struct SendInputResult {
    submission_id: String,
}

pub async fn handle(
    session: Arc<Session>,
    turn: Arc<TurnContext>,
    call_id: String,
    arguments: String,
) -> Result<FunctionToolOutput, FunctionCallError> {
    let args: SendInputArgs = parse_arguments(&arguments)?;
    let receiver_thread_id = match args.id.as_deref().map(str::trim) {
        Some(id) if !id.is_empty() && !matches!(id, "parent" | "root") => agent_id(id)?,
        _ => session.parent_thread_id().await.ok_or_else(|| {
            FunctionCallError::RespondToModel(
                "send_input requires an id when no parent agent is available".to_string(),
            )
        })?,
    };
    let watchdog_targets = session
        .services
        .agent_control
        .watchdog_targets(&[receiver_thread_id])
        .await;
    if watchdog_targets.contains(&receiver_thread_id) {
        return Err(FunctionCallError::RespondToModel(
            "send_input cannot target watchdog handles. Send the message to the parent/root agent instead."
                .to_string(),
        ));
    }
    let input_items = parse_multi_agent_input(args.message, args.items)?;
    let prompt = input_preview(&input_items);
    let (receiver_agent_nickname, receiver_agent_role) = session
        .services
        .agent_control
        .get_agent_nickname_and_role(receiver_thread_id)
        .await
        .unwrap_or((None, None));
    if args.interrupt {
        session
            .services
            .agent_control
            .interrupt_agent(receiver_thread_id)
            .await
            .map_err(|err| multi_agent_tool_error(receiver_thread_id, err))?;
        let _ = session
            .services
            .agent_control
            .drop_pending_input(receiver_thread_id)
            .await
            .map_err(|err| multi_agent_tool_error(receiver_thread_id, err))?;
    }
    session
        .send_event(
            &turn,
            CollabAgentInteractionBeginEvent {
                call_id: call_id.clone(),
                sender_thread_id: session.conversation_id,
                receiver_thread_id,
                prompt: prompt.clone(),
            }
            .into(),
        )
        .await;
    let sender_is_watchdog_helper_for_receiver = session
        .services
        .agent_control
        .watchdog_owner_for_active_helper(session.conversation_id)
        .await
        == Some(receiver_thread_id);
    let result = if sender_is_watchdog_helper_for_receiver {
        session
            .services
            .agent_control
            .send_watchdog_wakeup(receiver_thread_id, session.conversation_id, prompt.clone())
            .await
            .map_err(|err| multi_agent_tool_error(receiver_thread_id, err))
    } else if let Some(message) = single_text_input(&input_items) {
        session
            .services
            .agent_control
            .send_agent_message(receiver_thread_id, session.conversation_id, message)
            .await
            .map_err(|err| multi_agent_tool_error(receiver_thread_id, err))
    } else {
        session
            .services
            .agent_control
            .send_input(receiver_thread_id, input_items)
            .await
            .map_err(|err| multi_agent_tool_error(receiver_thread_id, err))
    };
    let status = session
        .services
        .agent_control
        .get_status(receiver_thread_id)
        .await;
    session
        .send_event(
            &turn,
            CollabAgentInteractionEndEvent {
                call_id,
                sender_thread_id: session.conversation_id,
                receiver_thread_id,
                receiver_agent_nickname,
                receiver_agent_role,
                prompt: prompt.clone(),
                status,
            }
            .into(),
        )
        .await;
    let submission_id = result?;
    session
        .services
        .agent_control
        .record_prompt_preview(receiver_thread_id, &prompt)
        .await;
    session.mark_turn_used_agent_send_input();

    let content = serde_json::to_string(&SendInputResult { submission_id }).map_err(|err| {
        FunctionCallError::Fatal(format!("failed to serialize send_input result: {err}"))
    })?;

    Ok(FunctionToolOutput::from_text(content, Some(true)))
}
