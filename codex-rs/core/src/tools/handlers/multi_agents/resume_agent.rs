use super::*;
use crate::agent::exceeds_thread_spawn_depth_limit;
use crate::agent::next_thread_spawn_depth;
use crate::rollout::RolloutRecorder;
use crate::rollout::find_archived_thread_path_by_id_str;
use crate::rollout::find_thread_path_by_id_str;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct ResumeAgentArgs {
    id: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct ResumeAgentResult {
    pub(super) status: AgentStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RecordedResumeContext {
    pub(crate) developer_instructions: Option<Option<String>>,
    pub(crate) model: Option<String>,
    pub(crate) reasoning_effort: Option<Option<ReasoningEffort>>,
}

pub async fn handle(
    session: Arc<Session>,
    turn: Arc<TurnContext>,
    call_id: String,
    arguments: String,
) -> Result<FunctionToolOutput, FunctionCallError> {
    let args: ResumeAgentArgs = parse_arguments(&arguments)?;
    let receiver_thread_id = agent_id(&args.id)?;
    let child_depth = next_thread_spawn_depth(&turn.session_source);
    let max_depth = turn.config.agent_max_depth;
    if exceeds_thread_spawn_depth_limit(child_depth, max_depth) {
        return Err(FunctionCallError::RespondToModel(format!(
            "agent depth limit reached: max depth is {max_depth}"
        )));
    }

    let (receiver_agent_nickname, receiver_agent_role) = session
        .services
        .agent_control
        .get_agent_nickname_and_role(receiver_thread_id)
        .await
        .unwrap_or((None, None));
    let receiver_spawn_mode = watchdog_ref_spawn_mode(
        &session
            .services
            .agent_control
            .watchdog_targets(&[receiver_thread_id])
            .await,
        receiver_thread_id,
    );
    session
        .send_event(
            &turn,
            CollabResumeBeginEvent {
                call_id: call_id.clone(),
                sender_thread_id: session.conversation_id,
                receiver_thread_id,
                receiver_agent_nickname: receiver_agent_nickname.clone(),
                receiver_agent_role: receiver_agent_role.clone(),
                receiver_spawn_mode,
            }
            .into(),
        )
        .await;

    let mut status = session
        .services
        .agent_control
        .get_status(receiver_thread_id)
        .await;
    let error = if matches!(status, AgentStatus::NotFound) {
        match try_resume_closed_agent(&session, &turn, receiver_thread_id, child_depth).await {
            Ok(resumed_status) => {
                status = resumed_status;
                None
            }
            Err(err) => {
                status = session
                    .services
                    .agent_control
                    .get_status(receiver_thread_id)
                    .await;
                Some(err)
            }
        }
    } else {
        None
    };
    let (receiver_agent_nickname, receiver_agent_role) = session
        .services
        .agent_control
        .get_agent_nickname_and_role(receiver_thread_id)
        .await
        .unwrap_or((receiver_agent_nickname, receiver_agent_role));

    session
        .send_event(
            &turn,
            CollabResumeEndEvent {
                call_id,
                sender_thread_id: session.conversation_id,
                receiver_thread_id,
                receiver_agent_nickname,
                receiver_agent_role,
                receiver_spawn_mode,
                status: status.clone(),
            }
            .into(),
        )
        .await;

    if let Some(err) = error {
        return Err(err);
    }
    turn.session_telemetry
        .counter("codex.multi_agent.resume", 1, &[]);

    let content = serde_json::to_string(&ResumeAgentResult { status }).map_err(|err| {
        FunctionCallError::Fatal(format!("failed to serialize resume_agent result: {err}"))
    })?;

    Ok(FunctionToolOutput::from_text(content, Some(true)))
}

async fn try_resume_closed_agent(
    session: &Arc<Session>,
    turn: &Arc<TurnContext>,
    receiver_thread_id: ThreadId,
    child_depth: i32,
) -> Result<AgentStatus, FunctionCallError> {
    let recorded_resume_context =
        load_recorded_resume_context(turn.as_ref(), receiver_thread_id).await?;
    let config = build_agent_resume_config(turn.as_ref(), child_depth, &recorded_resume_context)?;
    let (agent_nickname, agent_role) = match crate::state_db::get_state_db(&turn.config).await {
        Some(state_db_ctx) => match state_db_ctx.get_thread(receiver_thread_id).await {
            Ok(Some(metadata)) => (metadata.agent_nickname, metadata.agent_role),
            Ok(None) | Err(_) => (None, None),
        },
        None => (None, None),
    };
    let resumed_thread_id = session
        .services
        .agent_control
        .resume_agent_from_rollout(
            config,
            receiver_thread_id,
            thread_spawn_source_with_metadata(
                session.conversation_id,
                child_depth,
                agent_nickname,
                agent_role,
            ),
        )
        .await
        .map_err(|err| multi_agent_tool_error(receiver_thread_id, err))?;

    Ok(session
        .services
        .agent_control
        .get_status(resumed_thread_id)
        .await)
}

async fn load_recorded_resume_context(
    turn: &TurnContext,
    receiver_thread_id: ThreadId,
) -> Result<RecordedResumeContext, FunctionCallError> {
    let rollout_path = find_thread_path_by_id_str(
        turn.config.codex_home.as_path(),
        &receiver_thread_id.to_string(),
    )
    .await
    .map_err(|err| {
        FunctionCallError::RespondToModel(format!(
            "failed to inspect recorded agent {receiver_thread_id}: {err}"
        ))
    })?;
    let rollout_path = match rollout_path {
        Some(rollout_path) => Some(rollout_path),
        None => find_archived_thread_path_by_id_str(
            turn.config.codex_home.as_path(),
            &receiver_thread_id.to_string(),
        )
        .await
        .map_err(|err| {
            FunctionCallError::RespondToModel(format!(
                "failed to inspect recorded archived agent {receiver_thread_id}: {err}"
            ))
        })?,
    };
    let Some(rollout_path) = rollout_path else {
        return Ok(RecordedResumeContext::default());
    };
    let initial_history = RolloutRecorder::get_rollout_history(rollout_path.as_path())
        .await
        .map_err(|err| {
            FunctionCallError::RespondToModel(format!(
                "failed to load recorded agent {receiver_thread_id}: {err}"
            ))
        })?;
    let developer_instructions = initial_history
        .get_rollout_items()
        .into_iter()
        .rev()
        .find_map(|item| match item {
            codex_protocol::protocol::RolloutItem::TurnContext(context) => {
                Some(context.developer_instructions)
            }
            _ => None,
        })
        .or_else(|| {
            initial_history
                .forked_from_id()
                .map(|_| turn.developer_instructions.clone())
        });
    let model = initial_history
        .get_rollout_items()
        .into_iter()
        .rev()
        .find_map(|item| match item {
            codex_protocol::protocol::RolloutItem::TurnContext(context) => Some(context.model),
            _ => None,
        });
    let reasoning_effort = initial_history
        .get_rollout_items()
        .into_iter()
        .rev()
        .find_map(|item| match item {
            codex_protocol::protocol::RolloutItem::TurnContext(context) => Some(context.effort),
            _ => None,
        });
    Ok(RecordedResumeContext {
        developer_instructions,
        model,
        reasoning_effort,
    })
}
