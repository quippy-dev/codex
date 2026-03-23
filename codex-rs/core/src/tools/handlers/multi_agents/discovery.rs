use super::*;

pub(crate) mod compact_parent_context {
    use super::*;
    use std::sync::Arc;

    #[derive(Debug, Deserialize)]
    struct CompactParentContextArgs {
        reason: Option<String>,
        evidence: Option<String>,
    }

    #[derive(Debug, Serialize)]
    struct CompactParentContextResult {
        parent_id: String,
        submission_id: String,
    }

    pub async fn handle(
        session: Arc<Session>,
        _turn: Arc<TurnContext>,
        _call_id: String,
        arguments: String,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        let args: CompactParentContextArgs = parse_arguments(&arguments)?;
        let _reason = args.reason.and_then(|reason| {
            let trimmed = reason.trim();
            (!trimmed.is_empty()).then_some(trimmed.to_string())
        });
        let _evidence = args.evidence.and_then(|evidence| {
            let trimmed = evidence.trim();
            (!trimmed.is_empty()).then_some(trimmed.to_string())
        });

        let helper_thread_id = session.conversation_id;
        let result = session
            .services
            .agent_control
            .compact_parent_for_watchdog_helper(helper_thread_id)
            .await
            .map_err(|err| multi_agent_tool_error(helper_thread_id, err))?;

        let (parent_thread_id, submission_id) = match result {
            WatchdogParentCompactionResult::NotWatchdogHelper => {
                return Err(FunctionCallError::RespondToModel(
                    "compact_parent_context is only available to active watchdog helpers"
                        .to_string(),
                ));
            }
            WatchdogParentCompactionResult::ParentBusy { parent_thread_id } => {
                return Err(FunctionCallError::RespondToModel(format!(
                    "parent agent {parent_thread_id} has an active turn; compact_parent_context requires an idle parent"
                )));
            }
            WatchdogParentCompactionResult::AlreadyInProgress { parent_thread_id } => {
                return Err(FunctionCallError::RespondToModel(format!(
                    "parent agent {parent_thread_id} already has a compaction in progress"
                )));
            }
            WatchdogParentCompactionResult::Submitted {
                parent_thread_id,
                submission_id,
            } => (parent_thread_id, submission_id),
        };

        let content = serde_json::to_string(&CompactParentContextResult {
            parent_id: parent_thread_id.to_string(),
            submission_id,
        })
        .map_err(|err| {
            FunctionCallError::Fatal(format!(
                "failed to serialize compact_parent_context result: {err}"
            ))
        })?;

        Ok(FunctionToolOutput::from_text(content, Some(true)))
    }
}

pub(crate) mod list_agents {
    use super::*;
    use std::sync::Arc;

    #[derive(Debug, Deserialize)]
    struct ListAgentsArgs {
        id: Option<String>,
        #[serde(default = "default_recursive")]
        recursive: bool,
        #[serde(default)]
        all: bool,
    }

    #[derive(Debug, Serialize)]
    struct ListAgentsResult {
        agents: Vec<ListAgentEntry>,
    }

    #[derive(Debug, Serialize)]
    struct ListAgentEntry {
        id: String,
        parent_id: String,
        status: AgentStatus,
        depth: usize,
    }

    fn default_recursive() -> bool {
        true
    }

    pub async fn handle(
        session: Arc<Session>,
        _turn: Arc<TurnContext>,
        _call_id: String,
        arguments: String,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        let args: ListAgentsArgs = parse_arguments(&arguments)?;
        let owner_thread_id =
            resolve_owner_thread_id(session.as_ref(), args.id.as_deref().map(str::trim)).await?;

        let listings = session
            .services
            .agent_control
            .list_agents(owner_thread_id, args.recursive, args.all)
            .await
            .map_err(multi_agent_spawn_error)?;

        let agents = listings
            .into_iter()
            .map(|entry| ListAgentEntry {
                id: entry.thread_id.to_string(),
                parent_id: entry
                    .parent_thread_id
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                status: entry.status,
                depth: entry.depth,
            })
            .collect();

        let content = serde_json::to_string(&ListAgentsResult { agents }).map_err(|err| {
            FunctionCallError::Fatal(format!("failed to serialize list_agents result: {err}"))
        })?;

        Ok(FunctionToolOutput::from_text(content, Some(true)))
    }
}

pub(crate) mod peek_agents {
    use super::*;
    use crate::agent::AgentProgressSnapshot;
    use std::sync::Arc;

    const DEFAULT_PEEK_LIMIT: usize = 20;
    const MAX_PEEK_LIMIT: usize = 200;

    #[derive(Debug, Deserialize)]
    struct PeekAgentsArgs {
        id: Option<String>,
        #[serde(default = "default_recursive")]
        recursive: bool,
        cursor: Option<u64>,
        limit: Option<usize>,
    }

    #[derive(Debug, Serialize)]
    struct PeekAgentsResult {
        agents: Vec<PeekAgentEntry>,
        next_cursor: u64,
    }

    #[derive(Debug, Serialize)]
    struct PeekAgentEntry {
        id: String,
        parent_id: String,
        status: AgentStatus,
        depth: usize,
        cursor: u64,
        prompt_preview: Option<String>,
        reasoning_summary: Option<String>,
        latest_message_preview: Option<String>,
        terminal_summary: Option<String>,
    }

    fn default_recursive() -> bool {
        true
    }

    pub async fn handle(
        session: Arc<Session>,
        _turn: Arc<TurnContext>,
        _call_id: String,
        arguments: String,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        let args: PeekAgentsArgs = parse_arguments(&arguments)?;
        let owner_thread_id =
            resolve_owner_thread_id(session.as_ref(), args.id.as_deref().map(str::trim)).await?;
        let listings = session
            .services
            .agent_control
            .list_agents(owner_thread_id, args.recursive, /*all*/ false)
            .await
            .map_err(multi_agent_spawn_error)?;
        let thread_ids = listings
            .iter()
            .map(|entry| entry.thread_id)
            .collect::<Vec<_>>();
        let progress_by_thread = session
            .services
            .agent_control
            .progress_snapshots(&thread_ids)
            .await;
        let max_selected_cursor = progress_by_thread
            .values()
            .map(|snapshot| snapshot.cursor)
            .max()
            .unwrap_or_default();
        let cursor = args.cursor.unwrap_or_default();
        let limit = args
            .limit
            .unwrap_or(DEFAULT_PEEK_LIMIT)
            .clamp(1, MAX_PEEK_LIMIT);
        let incremental = args.cursor.is_some();

        let mut agents = listings
            .into_iter()
            .filter_map(|entry| {
                let progress = progress_by_thread.get(&entry.thread_id).cloned();
                let snapshot_cursor = progress
                    .as_ref()
                    .map(|snapshot| snapshot.cursor)
                    .unwrap_or_default();
                if incremental && snapshot_cursor <= cursor {
                    return None;
                }
                Some(build_peek_agent_entry(entry, progress))
            })
            .collect::<Vec<_>>();
        if incremental {
            agents.sort_by(|left, right| {
                left.cursor
                    .cmp(&right.cursor)
                    .then(left.id.cmp(&right.id))
                    .then(left.depth.cmp(&right.depth))
            });
        } else {
            agents.sort_by(|left, right| {
                right
                    .cursor
                    .cmp(&left.cursor)
                    .then(left.id.cmp(&right.id))
                    .then(left.depth.cmp(&right.depth))
            });
        }
        let truncated = agents.len() > limit;
        agents.truncate(limit);

        let next_cursor = if truncated {
            if incremental {
                agents
                    .last()
                    .map(|entry| entry.cursor)
                    .unwrap_or(max_selected_cursor.max(cursor))
            } else {
                max_selected_cursor.max(cursor)
            }
        } else {
            max_selected_cursor.max(cursor)
        };
        let content = serde_json::to_string(&PeekAgentsResult {
            agents,
            next_cursor,
        })
        .map_err(|err| {
            FunctionCallError::Fatal(format!("failed to serialize peek_agents result: {err}"))
        })?;

        Ok(FunctionToolOutput::from_text(content, Some(true)))
    }

    fn build_peek_agent_entry(
        listing: crate::agent::control::AgentListing,
        progress: Option<AgentProgressSnapshot>,
    ) -> PeekAgentEntry {
        let AgentProgressSnapshot {
            cursor,
            prompt_preview,
            reasoning_summary,
            latest_message_preview,
            terminal_summary,
        } = progress.unwrap_or_default();
        PeekAgentEntry {
            id: listing.thread_id.to_string(),
            parent_id: listing
                .parent_thread_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            status: listing.status,
            depth: listing.depth,
            cursor,
            prompt_preview,
            reasoning_summary,
            latest_message_preview,
            terminal_summary,
        }
    }
}
