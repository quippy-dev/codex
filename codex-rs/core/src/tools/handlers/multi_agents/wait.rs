use super::*;
use crate::agent::status::is_final;
use futures::FutureExt;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch::Receiver;
use tokio::time::Instant;

use tokio::time::timeout_at;

#[derive(Debug, Deserialize)]
struct WaitArgs {
    ids: Vec<String>,
    timeout_ms: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct WaitResult {
    pub(crate) status: HashMap<ThreadId, AgentStatus>,
    pub(crate) timed_out: bool,
}

#[cfg(test)]
pub(crate) type WaitAgentResult = WaitResult;

pub async fn handle(
    session: Arc<Session>,
    turn: Arc<TurnContext>,
    call_id: String,
    arguments: String,
) -> Result<FunctionToolOutput, FunctionCallError> {
    if let Some(owner_thread_id) = session
        .services
        .agent_control
        .watchdog_owner_for_active_helper(session.conversation_id)
        .await
    {
        return Err(FunctionCallError::RespondToModel(format!(
            "wait is not available to watchdog check-in agents. This thread is a one-shot watchdog check-in for owner {owner_thread_id}. Send the result to the parent/root agent with `send_input`. A successful watchdog handoff wakes the owner into a real follow-up turn. If you finish without `send_input`, runtime will forward your conclusory message to the owner as the mandatory fallback wake-up path. After a successful handoff, exit quietly and do not add extra completion narration."
        )));
    }
    let args: WaitArgs = parse_arguments(&arguments)?;
    if args.ids.is_empty() {
        return Err(FunctionCallError::RespondToModel(
            "ids must be non-empty".to_owned(),
        ));
    }
    let requested_thread_ids = args
        .ids
        .iter()
        .map(|id| agent_id(id))
        .collect::<Result<Vec<_>, _>>()?;
    let watchdog_target_ids = session
        .services
        .agent_control
        .watchdog_targets(&requested_thread_ids)
        .await;
    let event_receiver_thread_ids = requested_thread_ids.clone();
    let mut receiver_agents = Vec::with_capacity(event_receiver_thread_ids.len());
    for receiver_thread_id in &event_receiver_thread_ids {
        let (agent_nickname, agent_role) = session
            .services
            .agent_control
            .get_agent_nickname_and_role(*receiver_thread_id)
            .await
            .unwrap_or((None, None));
        receiver_agents.push(CollabAgentRef {
            thread_id: *receiver_thread_id,
            agent_nickname,
            agent_role,
            spawn_mode: watchdog_ref_spawn_mode(&watchdog_target_ids, *receiver_thread_id),
        });
    }
    let mut receiver_thread_ids = Vec::new();
    let mut watchdog_statuses = Vec::new();
    split_wait_ids(
        &session,
        requested_thread_ids,
        &watchdog_target_ids,
        &mut receiver_thread_ids,
        &mut watchdog_statuses,
    )
    .await;

    // Validate timeout.
    let timeout_ms = args.timeout_ms.unwrap_or(DEFAULT_WAIT_TIMEOUT_MS);
    let timeout_ms = match timeout_ms {
        ms if ms <= 0 => {
            return Err(FunctionCallError::RespondToModel(
                "timeout_ms must be greater than zero".to_owned(),
            ));
        }
        ms => ms.clamp(MIN_WAIT_TIMEOUT_MS, MAX_WAIT_TIMEOUT_MS),
    };

    session
        .send_event(
            &turn,
            CollabWaitingBeginEvent {
                sender_thread_id: session.conversation_id,
                receiver_thread_ids: event_receiver_thread_ids,
                receiver_agents: receiver_agents.clone(),
                call_id: call_id.clone(),
            }
            .into(),
        )
        .await;

    if receiver_thread_ids.is_empty() {
        let statuses_map = watchdog_statuses.into_iter().collect::<HashMap<_, _>>();
        session
            .send_event(
                &turn,
                CollabWaitingEndEvent {
                    sender_thread_id: session.conversation_id,
                    call_id,
                    agent_statuses: build_wait_agent_statuses(&statuses_map, &receiver_agents),
                    statuses: statuses_map.clone(),
                }
                .into(),
            )
            .await;

        let content = serde_json::to_string(&WaitResult {
            status: statuses_map,
            timed_out: false,
        })
        .map_err(|err| {
            FunctionCallError::Fatal(format!("failed to serialize wait result: {err}"))
        })?;

        return Err(FunctionCallError::RespondToModel(format!(
            "wait cannot be used to wait for watchdog check-ins. You passed only watchdog handle ids. Watchdog check-ins happen only after the current turn ends and the owner thread is idle for at least the watchdog interval. Each idle stretch allows at most one successful watchdog handoff; failed runs may retry while the owner stays idle until one succeeds. `wait` on a watchdog handle is status-only and cannot confirm a new check-in. Do not poll with `wait`, `list_agents`, or shell `sleep`: the owner thread is still active during this turn, so those calls cannot make the watchdog fire. Do not call `wait` again on this watchdog handle in this turn. Continue the task now or end the turn so the watchdog can check in later. Current watchdog handle statuses: {content}"
        )));
    }

    let mut status_rxs = Vec::with_capacity(receiver_thread_ids.len());
    let mut initial_final_statuses = Vec::new();
    for id in &receiver_thread_ids {
        match session.services.agent_control.subscribe_status(*id).await {
            Ok(rx) => {
                let status = rx.borrow().clone();
                if let Some(final_status) = observed_wait_final_status(&session, *id, status).await
                {
                    initial_final_statuses.push((*id, final_status));
                }
                status_rxs.push((*id, rx));
            }
            Err(CodexErr::ThreadNotFound(_)) => {
                initial_final_statuses.push((*id, AgentStatus::NotFound));
            }
            Err(err) => {
                let mut statuses = HashMap::with_capacity(1 + watchdog_statuses.len());
                statuses.insert(*id, session.services.agent_control.get_status(*id).await);
                statuses.extend(watchdog_statuses.iter().cloned());
                session
                    .send_event(
                        &turn,
                        CollabWaitingEndEvent {
                            sender_thread_id: session.conversation_id,
                            call_id: call_id.clone(),
                            agent_statuses: build_wait_agent_statuses(&statuses, &receiver_agents),
                            statuses,
                        }
                        .into(),
                    )
                    .await;
                return Err(multi_agent_tool_error(*id, err));
            }
        }
    }

    let statuses = if !initial_final_statuses.is_empty() {
        initial_final_statuses
    } else {
        // Wait for the first agent to reach a final status.
        let mut futures = FuturesUnordered::new();
        for (id, rx) in status_rxs.into_iter() {
            let session = session.clone();
            futures.push(wait_for_final_status(session, id, rx));
        }
        let mut results = Vec::new();
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        loop {
            match timeout_at(deadline, futures.next()).await {
                Ok(Some(Some(result))) => {
                    results.push(result);
                    break;
                }
                Ok(Some(None)) => continue,
                Ok(None) | Err(_) => break,
            }
        }
        if !results.is_empty() {
            // Drain the unlikely last elements to prevent race.
            loop {
                match futures.next().now_or_never() {
                    Some(Some(Some(result))) => results.push(result),
                    Some(Some(None)) => continue,
                    Some(None) | None => break,
                }
            }
        }
        results
    };

    // Convert payload.
    let wait_timed_out = statuses.is_empty();
    let mut statuses_with_watchdogs = statuses;
    statuses_with_watchdogs.extend(watchdog_statuses);
    let statuses_map = statuses_with_watchdogs
        .into_iter()
        .collect::<HashMap<_, _>>();
    let agent_statuses = build_wait_agent_statuses(&statuses_map, &receiver_agents);
    let result = WaitResult {
        status: statuses_map.clone(),
        timed_out: wait_timed_out,
    };

    // Final event emission.
    session
        .send_event(
            &turn,
            CollabWaitingEndEvent {
                sender_thread_id: session.conversation_id,
                call_id,
                agent_statuses,
                statuses: statuses_map,
            }
            .into(),
        )
        .await;

    let content = serde_json::to_string(&result).map_err(|err| {
        FunctionCallError::Fatal(format!("failed to serialize wait result: {err}"))
    })?;

    Ok(FunctionToolOutput::from_text(content, None))
}

// Pub only for tests. Do not use.
pub(super) async fn wait_for_final_status(
    session: Arc<Session>,
    thread_id: ThreadId,
    mut status_rx: Receiver<AgentStatus>,
) -> Option<(ThreadId, AgentStatus)> {
    let status = status_rx.borrow().clone();
    if let Some(final_status) = observed_wait_final_status(&session, thread_id, status).await {
        return Some((thread_id, final_status));
    }

    loop {
        if status_rx.changed().await.is_err() {
            let latest = session.services.agent_control.get_status(thread_id).await;
            return observed_wait_final_status(&session, thread_id, latest)
                .await
                .map(|final_status| (thread_id, final_status));
        }
        let status = status_rx.borrow().clone();
        if let Some(final_status) = observed_wait_final_status(&session, thread_id, status).await {
            return Some((thread_id, final_status));
        }
    }
}

async fn observed_wait_final_status(
    session: &Arc<Session>,
    thread_id: ThreadId,
    observed_status: AgentStatus,
) -> Option<AgentStatus> {
    let follow_up_status = if matches!(&observed_status, AgentStatus::Errored(reason) if reason == "Interrupted")
    {
        Some(session.services.agent_control.get_status(thread_id).await)
    } else {
        None
    };
    finalized_wait_status(observed_status, follow_up_status)
}

fn finalized_wait_status(
    observed_status: AgentStatus,
    follow_up_status: Option<AgentStatus>,
) -> Option<AgentStatus> {
    if !is_final(&observed_status) {
        return None;
    }
    if !matches!(&observed_status, AgentStatus::Errored(reason) if reason == "Interrupted") {
        return Some(observed_status);
    }

    let Some(follow_up_status) = follow_up_status else {
        return Some(observed_status);
    };
    if matches!(
        &follow_up_status,
        AgentStatus::PendingInit | AgentStatus::Running
    ) {
        return None;
    }

    Some(follow_up_status)
}

async fn split_wait_ids(
    session: &Arc<Session>,
    requested_thread_ids: Vec<ThreadId>,
    watchdog_target_ids: &HashSet<ThreadId>,
    receiver_thread_ids: &mut Vec<ThreadId>,
    watchdog_statuses: &mut Vec<(ThreadId, AgentStatus)>,
) {
    for thread_id in requested_thread_ids {
        if watchdog_target_ids.contains(&thread_id) {
            let status = session.services.agent_control.get_status(thread_id).await;
            watchdog_statuses.push((thread_id, status));
        } else {
            receiver_thread_ids.push(thread_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::finalized_wait_status;
    use codex_protocol::protocol::AgentStatus;
    use pretty_assertions::assert_eq;

    #[test]
    fn interrupted_follow_up_running_is_treated_as_non_final() {
        assert_eq!(
            finalized_wait_status(
                AgentStatus::Errored("Interrupted".to_string()),
                Some(AgentStatus::Running),
            ),
            None
        );
    }

    #[test]
    fn interrupted_follow_up_pending_init_is_treated_as_non_final() {
        assert_eq!(
            finalized_wait_status(
                AgentStatus::Errored("Interrupted".to_string()),
                Some(AgentStatus::PendingInit),
            ),
            None
        );
    }

    #[test]
    fn interrupted_follow_up_final_status_wins() {
        assert_eq!(
            finalized_wait_status(
                AgentStatus::Errored("Interrupted".to_string()),
                Some(AgentStatus::Shutdown),
            ),
            Some(AgentStatus::Shutdown)
        );
    }

    #[test]
    fn non_interrupted_error_is_unchanged() {
        assert_eq!(
            finalized_wait_status(
                AgentStatus::Errored("boom".to_string()),
                Some(AgentStatus::Running),
            ),
            Some(AgentStatus::Errored("boom".to_string()))
        );
    }
}
