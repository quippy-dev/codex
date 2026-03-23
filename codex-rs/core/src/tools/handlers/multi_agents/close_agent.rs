use super::*;
use crate::rollout::find_thread_path_by_id_str;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum CloseAgentOutcome {
    Closed,
    AlreadyClosed,
    NotFound,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct CloseAgentResult {
    pub(super) status: AgentStatus,
    pub(super) close_result: CloseAgentOutcome,
}

fn not_found_outcome(was_known: bool) -> CloseAgentOutcome {
    if was_known {
        CloseAgentOutcome::AlreadyClosed
    } else {
        CloseAgentOutcome::NotFound
    }
}

fn event_close_result(outcome: CloseAgentOutcome) -> CollabCloseResult {
    match outcome {
        CloseAgentOutcome::Closed => CollabCloseResult::Closed,
        CloseAgentOutcome::AlreadyClosed => CollabCloseResult::AlreadyClosed,
        CloseAgentOutcome::NotFound => CollabCloseResult::NotFound,
    }
}

pub async fn handle(
    session: Arc<Session>,
    turn: Arc<TurnContext>,
    call_id: String,
    arguments: String,
) -> Result<FunctionToolOutput, FunctionCallError> {
    let args: CloseAgentArgs = parse_arguments(&arguments)?;
    let agent_id = agent_id(&args.id)?;
    let status_before = session.services.agent_control.get_status(agent_id).await;
    let (receiver_agent_nickname, receiver_agent_role) = session
        .services
        .agent_control
        .get_agent_nickname_and_role(agent_id)
        .await
        .unwrap_or((None, None));
    let receiver_spawn_mode = watchdog_ref_spawn_mode(
        &session
            .services
            .agent_control
            .watchdog_targets(&[agent_id])
            .await,
        agent_id,
    );
    let mut was_known = if matches!(status_before, AgentStatus::NotFound) {
        let listed = session
            .services
            .agent_control
            .list_agents(session.conversation_id, true, true)
            .await
            .map(|agents| agents.into_iter().any(|agent| agent.thread_id == agent_id))
            .unwrap_or(false);
        let spawned = session.services.agent_control.was_spawned_thread(agent_id);
        let recorded = find_thread_path_by_id_str(turn.config.codex_home.as_path(), &args.id)
            .await
            .map(|path| path.is_some())
            .unwrap_or(false);
        listed || spawned || recorded
    } else {
        true
    };
    session
        .send_event(
            &turn,
            CollabCloseBeginEvent {
                call_id: call_id.clone(),
                sender_thread_id: session.conversation_id,
                receiver_thread_id: agent_id,
            }
            .into(),
        )
        .await;
    if let Err(err) = session
        .services
        .agent_control
        .subscribe_status(agent_id)
        .await
    {
        let removed_watchdog = session
            .services
            .agent_control
            .unregister_watchdog(agent_id)
            .await;
        if removed_watchdog.is_some() {
            was_known = true;
        }
        if let Some(helper_id) = removed_watchdog.and_then(|entry| entry.active_helper_id) {
            let _ = session
                .services
                .agent_control
                .shutdown_agent(helper_id)
                .await;
        }
        let _ = session.services.agent_control.close_agent(agent_id).await;
        let status = session.services.agent_control.get_status(agent_id).await;
        session
            .send_event(
                &turn,
                CollabCloseEndEvent {
                    call_id: call_id.clone(),
                    sender_thread_id: session.conversation_id,
                    receiver_thread_id: agent_id,
                    receiver_agent_nickname: receiver_agent_nickname.clone(),
                    receiver_agent_role: receiver_agent_role.clone(),
                    receiver_spawn_mode,
                    status: status.clone(),
                    close_result: event_close_result(not_found_outcome(was_known)),
                }
                .into(),
            )
            .await;
        return if matches!(err, CodexErr::ThreadNotFound(_)) {
            let content = serde_json::to_string(&CloseAgentResult {
                status,
                close_result: not_found_outcome(was_known),
            })
            .map_err(|serialize_err| {
                FunctionCallError::Fatal(format!(
                    "failed to serialize close_agent result: {serialize_err}"
                ))
            })?;

            Ok(FunctionToolOutput::from_text(content, Some(true)))
        } else {
            Err(multi_agent_tool_error(agent_id, err))
        };
    }
    let removed_watchdog = session
        .services
        .agent_control
        .unregister_watchdog(agent_id)
        .await;
    if removed_watchdog.is_some() {
        was_known = true;
    }
    if let Some(helper_id) = removed_watchdog.and_then(|entry| entry.active_helper_id) {
        let _ = session
            .services
            .agent_control
            .shutdown_agent(helper_id)
            .await;
    }
    let close_result = match session.services.agent_control.close_agent(agent_id).await {
        Ok(_) => Ok(CloseAgentOutcome::Closed),
        Err(CodexErr::ThreadNotFound(_)) | Err(CodexErr::InternalAgentDied) => {
            Ok(not_found_outcome(was_known))
        }
        Err(err) => Err(multi_agent_tool_error(agent_id, err)),
    };
    let status = match close_result {
        Ok(CloseAgentOutcome::Closed) => session.services.agent_control.get_status(agent_id).await,
        Ok(CloseAgentOutcome::AlreadyClosed) | Ok(CloseAgentOutcome::NotFound) => {
            session.services.agent_control.get_status(agent_id).await
        }
        Err(_) => session.services.agent_control.get_status(agent_id).await,
    };
    let close_result = close_result?;
    session
        .send_event(
            &turn,
            CollabCloseEndEvent {
                call_id,
                sender_thread_id: session.conversation_id,
                receiver_thread_id: agent_id,
                receiver_agent_nickname,
                receiver_agent_role,
                receiver_spawn_mode,
                status: status.clone(),
                close_result: event_close_result(close_result),
            }
            .into(),
        )
        .await;

    let content = serde_json::to_string(&CloseAgentResult {
        status,
        close_result,
    })
    .map_err(|err| {
        FunctionCallError::Fatal(format!("failed to serialize close_agent result: {err}"))
    })?;

    Ok(FunctionToolOutput::from_text(content, Some(true)))
}
