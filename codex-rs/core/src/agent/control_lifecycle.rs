use super::*;

impl AgentControl {
    /// Interrupt the current task for an existing agent thread.
    pub(crate) async fn interrupt_agent(&self, agent_id: ThreadId) -> CodexResult<String> {
        let state = self.upgrade()?;
        state.send_op(agent_id, Op::Interrupt).await
    }

    /// Submit a shutdown request to an existing agent thread and any live descendants.
    pub(crate) async fn shutdown_agent(&self, agent_id: ThreadId) -> CodexResult<String> {
        let state = self.upgrade()?;
        let mut descendants = self.collect_descendants(&state, agent_id).await;
        descendants.reverse();
        for descendant_id in descendants {
            match self.shutdown_single_live_agent(&state, descendant_id).await {
                Ok(_) | Err(CodexErr::ThreadNotFound(_)) | Err(CodexErr::InternalAgentDied) => {}
                Err(err) => return Err(err),
            }
        }
        self.shutdown_single_live_agent(&state, agent_id).await
    }

    /// Submit a shutdown request for a live agent without marking it explicitly closed in
    /// persisted spawn-edge state.
    pub(crate) async fn shutdown_live_agent(&self, agent_id: ThreadId) -> CodexResult<String> {
        let state = self.upgrade()?;
        self.shutdown_single_live_agent(&state, agent_id).await
    }

    /// Mark `agent_id` and its persisted spawned subtree explicitly closed, then shut down the
    /// agent and any live descendants reached from the in-memory tree.
    pub(crate) async fn close_agent(&self, agent_id: ThreadId) -> CodexResult<String> {
        let state = self.upgrade()?;
        self.mark_persisted_spawn_subtree_closed(&state, agent_id)
            .await;
        self.shutdown_agent_tree(agent_id).await
    }

    /// Shut down `agent_id` and any live descendants reachable from the in-memory spawn tree.
    pub(crate) async fn shutdown_agent_tree(&self, agent_id: ThreadId) -> CodexResult<String> {
        let descendant_ids = self.live_thread_spawn_descendants(agent_id).await?;
        let result = self.shutdown_live_agent(agent_id).await;
        for descendant_id in descendant_ids {
            match self.shutdown_live_agent(descendant_id).await {
                Ok(_) | Err(CodexErr::ThreadNotFound(_)) | Err(CodexErr::InternalAgentDied) => {}
                Err(err) => return Err(err),
            }
        }
        result
    }

    async fn shutdown_single_live_agent(
        &self,
        state: &Arc<ThreadManagerState>,
        agent_id: ThreadId,
    ) -> CodexResult<String> {
        if let Some(removed_watchdog) = self.watchdogs.unregister(agent_id).await
            && let Some(helper_id) = removed_watchdog.active_helper_id
        {
            if let Ok(owner_thread) = state.get_thread(removed_watchdog.owner_thread_id).await
                && !is_final(&owner_thread.agent_status().await)
            {
                self.watchdogs
                    .preserve_helper_owner_for_completion_fallback(
                        helper_id,
                        removed_watchdog.owner_thread_id,
                    )
                    .await;
            }
            let _ = state.send_op(helper_id, Op::Shutdown {}).await;
            let _ = state.remove_thread(&helper_id).await;
            self.guards.release_spawned_thread(helper_id);
        }

        let result = if let Ok(thread) = state.get_thread(agent_id).await {
            thread.codex.session.ensure_rollout_materialized().await;
            thread.codex.session.flush_rollout().await;
            if matches!(thread.agent_status().await, AgentStatus::Shutdown) {
                Ok(String::new())
            } else {
                state.send_op(agent_id, Op::Shutdown {}).await
            }
        } else {
            state.send_op(agent_id, Op::Shutdown {}).await
        };
        let _ = state.remove_thread(&agent_id).await;
        self.guards.release_spawned_thread(agent_id);
        result
    }

    async fn mark_persisted_spawn_subtree_closed(
        &self,
        state: &ThreadManagerState,
        agent_id: ThreadId,
    ) {
        let state_db_ctx = if let Ok(thread) = state.get_thread(agent_id).await {
            thread.state_db()
        } else {
            state
                .list_threads()
                .await
                .into_iter()
                .find_map(|(_, thread)| thread.state_db())
        };

        let Some(state_db_ctx) = state_db_ctx else {
            return;
        };

        if let Err(err) = state_db_ctx
            .set_thread_spawn_subtree_status(agent_id, DirectionalThreadSpawnEdgeStatus::Closed)
            .await
        {
            warn!("failed to persist thread-spawn subtree status for {agent_id}: {err}");
        }
    }

    async fn collect_descendants(
        &self,
        state: &ThreadManagerState,
        owner_thread_id: ThreadId,
    ) -> Vec<ThreadId> {
        let threads = state.list_threads().await;
        let mut children_by_parent: HashMap<ThreadId, Vec<ThreadId>> = HashMap::new();
        for (thread_id, thread) in &threads {
            let snapshot = thread.config_snapshot().await;
            if let SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id, ..
            }) = snapshot.session_source
            {
                children_by_parent
                    .entry(parent_thread_id)
                    .or_default()
                    .push(*thread_id);
            }
        }

        for children in children_by_parent.values_mut() {
            children.sort_by_key(ToString::to_string);
        }

        let mut descendants = Vec::new();
        let mut queue = VecDeque::new();
        if let Some(children) = children_by_parent.get(&owner_thread_id) {
            for child in children {
                queue.push_back(*child);
            }
        }

        while let Some(thread_id) = queue.pop_front() {
            descendants.push(thread_id);
            if let Some(children) = children_by_parent.get(&thread_id) {
                for child in children {
                    queue.push_back(*child);
                }
            }
        }

        descendants
    }

    /// Starts a detached watcher for sub-agents spawned from another thread.
    ///
    /// This is only enabled for `SubAgentSource::ThreadSpawn`, where a parent thread exists and
    /// can receive completion notifications.
    pub(crate) fn maybe_start_completion_watcher(
        &self,
        child_thread_id: ThreadId,
        session_source: Option<SessionSource>,
    ) {
        let Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id, ..
        })) = session_source
        else {
            return;
        };
        let control = self.clone();
        tokio::spawn(async move {
            let status = match control.subscribe_status(child_thread_id).await {
                Ok(mut status_rx) => {
                    let mut status = status_rx.borrow().clone();
                    while !is_final(&status) {
                        if status_rx.changed().await.is_err() {
                            status = control.get_status(child_thread_id).await;
                            break;
                        }
                        status = status_rx.borrow().clone();
                    }
                    status
                }
                Err(_) => control.get_status(child_thread_id).await,
            };
            if !is_final(&status) {
                return;
            }

            let Ok(state) = control.upgrade() else {
                return;
            };
            let Ok(parent_thread) = state.get_thread(parent_thread_id).await else {
                return;
            };
            let parent_is_root_thread = !matches!(
                parent_thread.config_snapshot().await.session_source,
                SessionSource::SubAgent(_)
            );
            let child_is_watchdog_helper_for_parent = control
                .watchdog_owner_for_active_helper(child_thread_id)
                .await
                == Some(parent_thread_id);

            if parent_is_root_thread {
                let child_used_agent_send_input =
                    if let Ok(child_thread) = state.get_thread(child_thread_id).await {
                        child_thread
                            .codex
                            .session
                            .last_completed_turn_used_agent_send_input()
                    } else {
                        false
                    };
                let child_completed_message_already_forwarded = match &status {
                    AgentStatus::Completed(Some(message)) if !message.trim().is_empty() => {
                        if let Ok(child_thread) = state.get_thread(child_thread_id).await {
                            child_thread
                                .codex
                                .session
                                .last_completed_turn_live_forwarded_agent_message(message)
                                .await
                        } else {
                            false
                        }
                    }
                    _ => false,
                };
                if let Some(message) = completed_message_for_agent_fallback(
                    &status,
                    child_used_agent_send_input,
                    child_completed_message_already_forwarded,
                    child_is_watchdog_helper_for_parent,
                ) {
                    match control
                        .send_agent_message_inner(
                            parent_thread_id,
                            child_thread_id,
                            message,
                            false,
                            if child_is_watchdog_helper_for_parent {
                                LateAgentDeliveryMode::QueuePostTurn
                            } else {
                                LateAgentDeliveryMode::LiveOnlyAfterSamplingComplete
                            },
                            #[cfg(test)]
                            None,
                        )
                        .await
                    {
                        Ok(_) => {
                            if child_is_watchdog_helper_for_parent {
                                control
                                    .mark_watchdog_idle_episode_satisfied_for_helper(
                                        child_thread_id,
                                    )
                                    .await;
                            }
                        }
                        Err(err) => {
                            warn!(
                                child_thread_id = %child_thread_id,
                                parent_thread_id = %parent_thread_id,
                                "subagent completion fallback forward failed: {err}"
                            );
                        }
                    }
                }
            }
            parent_thread
                .inject_user_message_without_turn(format_subagent_notification_message(
                    &child_thread_id.to_string(),
                    &status,
                ))
                .await;
            control
                .watchdogs
                .clear_preserved_helper_owner(child_thread_id)
                .await;
        });
    }

    pub(crate) async fn register_watchdog(
        &self,
        registration: WatchdogRegistration,
    ) -> CodexResult<Vec<RemovedWatchdog>> {
        self.watchdogs.register(registration).await
    }

    pub(crate) async fn unregister_watchdog(
        &self,
        target_thread_id: ThreadId,
    ) -> Option<RemovedWatchdog> {
        self.watchdogs.unregister(target_thread_id).await
    }

    pub(crate) async fn unregister_watchdogs_for_owner(
        &self,
        owner_thread_id: ThreadId,
    ) -> Vec<RemovedWatchdog> {
        self.watchdogs.take_for_owner(owner_thread_id).await
    }

    pub(crate) async fn compact_parent_for_watchdog_helper(
        &self,
        helper_thread_id: ThreadId,
    ) -> CodexResult<WatchdogParentCompactionResult> {
        self.compact_parent_for_watchdog_helper_inner(
            helper_thread_id,
            #[cfg(test)]
            None,
        )
        .await
    }

    pub(crate) async fn compact_parent_for_watchdog_helper_inner(
        &self,
        helper_thread_id: ThreadId,
        #[cfg(test)] before_submit_recheck: Option<
            Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
        >,
    ) -> CodexResult<WatchdogParentCompactionResult> {
        let Some(parent_thread_id) = self
            .watchdogs
            .owner_for_active_helper(helper_thread_id)
            .await
        else {
            return Ok(WatchdogParentCompactionResult::NotWatchdogHelper);
        };
        let state = self.upgrade()?;
        let parent_thread = state.get_thread(parent_thread_id).await?;
        let parent_has_active_turn = parent_thread.has_active_turn().await;

        #[cfg(test)]
        if let Some(before_submit_recheck) = before_submit_recheck {
            before_submit_recheck.await;
        }

        {
            let mut compacting = self.watchdog_compactions_in_progress.lock().await;
            if compacting.contains(&parent_thread_id) {
                return Ok(WatchdogParentCompactionResult::AlreadyInProgress { parent_thread_id });
            }
            if parent_has_active_turn {
                return Ok(WatchdogParentCompactionResult::ParentBusy { parent_thread_id });
            }
            compacting.insert(parent_thread_id);
        }

        if parent_thread.has_active_turn().await {
            let mut compacting = self.watchdog_compactions_in_progress.lock().await;
            compacting.remove(&parent_thread_id);
            return Ok(WatchdogParentCompactionResult::ParentBusy { parent_thread_id });
        }

        match state.send_op(parent_thread_id, Op::Compact).await {
            Ok(submission_id) => Ok(WatchdogParentCompactionResult::Submitted {
                parent_thread_id,
                submission_id,
            }),
            Err(err) => {
                let mut compacting = self.watchdog_compactions_in_progress.lock().await;
                compacting.remove(&parent_thread_id);
                Err(err)
            }
        }
    }

    pub(crate) async fn finish_watchdog_parent_compaction(&self, parent_thread_id: ThreadId) {
        let mut compacting = self.watchdog_compactions_in_progress.lock().await;
        compacting.remove(&parent_thread_id);
    }

    pub(crate) async fn watchdog_parent_compaction_in_progress(
        &self,
        parent_thread_id: ThreadId,
    ) -> bool {
        let compacting = self.watchdog_compactions_in_progress.lock().await;
        compacting.contains(&parent_thread_id)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn run_watchdogs_once_for_tests(&self) {
        self.watchdogs.run_once().await;
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn force_watchdog_due_for_tests(&self, target_thread_id: ThreadId) {
        self.watchdogs.force_due_for_tests(target_thread_id).await;
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn set_watchdog_active_helper_for_tests(
        &self,
        target_thread_id: ThreadId,
        helper_thread_id: ThreadId,
    ) {
        self.watchdogs
            .set_active_helper_for_tests(target_thread_id, helper_thread_id)
            .await;
    }

    #[cfg(test)]
    pub(crate) async fn mark_watchdog_parent_compaction_in_progress_for_tests(
        &self,
        parent_thread_id: ThreadId,
    ) {
        let mut compacting = self.watchdog_compactions_in_progress.lock().await;
        compacting.insert(parent_thread_id);
    }

    pub(crate) async fn watchdog_owner_for_active_helper(
        &self,
        helper_thread_id: ThreadId,
    ) -> Option<ThreadId> {
        self.watchdogs
            .owner_for_active_helper(helper_thread_id)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn watchdog_active_helper_for_tests(
        &self,
        target_thread_id: ThreadId,
    ) -> Option<ThreadId> {
        self.watchdogs
            .active_helper_for_target(target_thread_id)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn watchdog_idle_episode_satisfied_for_tests(
        &self,
        target_thread_id: ThreadId,
    ) -> Option<bool> {
        self.watchdogs
            .idle_episode_satisfied_for_target(target_thread_id)
            .await
    }

    pub(crate) async fn mark_watchdog_idle_episode_satisfied_for_helper(
        &self,
        helper_thread_id: ThreadId,
    ) -> bool {
        self.watchdogs
            .mark_idle_episode_satisfied_for_helper(helper_thread_id)
            .await
    }
}
