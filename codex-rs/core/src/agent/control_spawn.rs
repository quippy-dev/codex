use super::*;

impl AgentControl {
    /// Spawn a new agent thread and submit the initial prompt.
    pub(crate) async fn spawn_agent(
        &self,
        config: Config,
        items: Vec<UserInput>,
        session_source: Option<SessionSource>,
    ) -> CodexResult<ThreadId> {
        self.spawn_agent_with_options(config, items, session_source, SpawnAgentOptions::default())
            .await
    }

    pub(crate) async fn spawn_agent_with_options(
        &self,
        config: crate::config::Config,
        items: Vec<UserInput>,
        session_source: Option<SessionSource>,
        options: SpawnAgentOptions,
    ) -> CodexResult<ThreadId> {
        let state = self.upgrade()?;
        let mut reservation = self
            .reserve_spawn_slot_with_reconcile(&state, config.agent_max_threads)
            .await?;
        let inherited_shell_snapshot = self
            .inherited_shell_snapshot_for_source(&state, session_source.as_ref())
            .await;
        let session_source =
            self.maybe_reserve_thread_spawn_identity(&config, &mut reservation, session_source)?;
        let inherited_exec_policy = self
            .inherited_exec_policy_for_source(&state, session_source.as_ref(), &config)
            .await;
        let notification_source = session_source.clone();
        let auth_manager = self
            .auth_manager_for_source(&config, &state, session_source.as_ref())
            .await;

        // The same `AgentControl` is sent to spawn the thread.
        let new_thread = match session_source {
            Some(session_source) => {
                if let Some(call_id) = options.fork_parent_spawn_call_id.as_ref() {
                    let SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                        parent_thread_id,
                        ..
                    }) = session_source.clone()
                    else {
                        return Err(CodexErr::Fatal(
                            "spawn_agent fork requires a thread-spawn session source".to_string(),
                        ));
                    };
                    let parent_thread = state.get_thread(parent_thread_id).await.ok();
                    if let Some(parent_thread) = parent_thread.as_ref() {
                        // `record_conversation_items` only queues rollout writes asynchronously.
                        // Flush/materialize the live parent before snapshotting JSONL for a fork.
                        parent_thread
                            .codex
                            .session
                            .ensure_rollout_materialized()
                            .await;
                        parent_thread.codex.session.flush_rollout().await;
                    }
                    let rollout_path = parent_thread
                        .as_ref()
                        .and_then(|parent_thread| parent_thread.rollout_path())
                        .or(find_thread_path_by_id_str(
                            config.codex_home.as_path(),
                            &parent_thread_id.to_string(),
                        )
                        .await?)
                        .ok_or_else(|| {
                            CodexErr::Fatal(format!(
                                "parent thread rollout unavailable for fork: {parent_thread_id}"
                            ))
                        })?;
                    let mut forked_rollout_items: Vec<RolloutItem> =
                        RolloutRecorder::get_rollout_history(&rollout_path)
                            .await?
                            .get_rollout_items();
                    if forked_rollout_items
                        .iter()
                        .any(|item| matches!(item, RolloutItem::ForkReference(_)))
                    {
                        forked_rollout_items =
                            crate::rollout::truncation::materialize_rollout_items_for_replay(
                                config.codex_home.as_path(),
                                &forked_rollout_items,
                            )
                            .await;
                    }
                    forked_rollout_items.push(RolloutItem::ForkReference(ForkReferenceItem {
                        rollout_path: rollout_path.clone(),
                        nth_user_message: usize::MAX,
                    }));
                    let mut output = FunctionCallOutputPayload::from_text(
                        FORKED_SPAWN_AGENT_OUTPUT_MESSAGE.to_string(),
                    );
                    output.success = Some(true);
                    forked_rollout_items.push(RolloutItem::ResponseItem(
                        ResponseItem::FunctionCallOutput {
                            call_id: call_id.clone(),
                            output,
                        },
                    ));
                    let initial_history = InitialHistory::Forked(forked_rollout_items);
                    state
                        .spawn_thread_from_history_with_source(
                            config,
                            initial_history,
                            auth_manager,
                            self.clone(),
                            session_source,
                            /*persist_extended_history*/ false,
                            inherited_shell_snapshot,
                            inherited_exec_policy,
                        )
                        .await?
                } else {
                    state
                        .spawn_new_thread_with_source(
                            config,
                            auth_manager,
                            self.clone(),
                            session_source,
                            /*persist_extended_history*/ false,
                            /*metrics_service_name*/ None,
                            inherited_shell_snapshot,
                            inherited_exec_policy,
                        )
                        .await?
                }
            }
            None => state.spawn_new_thread(config, self.clone()).await?,
        };
        reservation.commit(new_thread.thread_id);

        // Notify a new thread has been created. This notification will be processed by clients
        // to subscribe or drain this newly created thread.
        // TODO(jif) add helper for drain
        state.notify_thread_created(new_thread.thread_id);
        self.persist_thread_spawn_edge_for_source(
            new_thread.thread.as_ref(),
            new_thread.thread_id,
            notification_source.as_ref(),
        )
        .await;
        self.submit_initial_input_or_cleanup(&state, new_thread.thread_id, items)
            .await?;
        self.maybe_start_completion_watcher(new_thread.thread_id, notification_source);
        Ok(new_thread.thread_id)
    }

    /// Spawn a new agent thread but do not submit an initial prompt.
    ///
    /// This is used for watchdog handles, which should not run a model turn on
    /// their own. The watchdog manager will fork helpers from the owner thread
    /// when the owner becomes idle.
    pub(crate) async fn spawn_agent_handle(
        &self,
        config: Config,
        session_source: Option<SessionSource>,
    ) -> CodexResult<ThreadId> {
        let state = self.upgrade()?;
        let mut reservation = self
            .reserve_spawn_slot_with_reconcile(&state, config.agent_max_threads)
            .await?;
        let session_source =
            self.maybe_reserve_thread_spawn_identity(&config, &mut reservation, session_source)?;
        let notification_source = session_source.clone();
        let inherited_shell_snapshot = self
            .inherited_shell_snapshot_for_source(&state, session_source.as_ref())
            .await;
        let inherited_exec_policy = self
            .inherited_exec_policy_for_source(&state, session_source.as_ref(), &config)
            .await;
        let auth_manager = self
            .auth_manager_for_source(&config, &state, session_source.as_ref())
            .await;

        let new_thread = match session_source {
            Some(session_source) => {
                state
                    .spawn_new_thread_with_source(
                        config,
                        auth_manager,
                        self.clone(),
                        session_source,
                        false,
                        None,
                        inherited_shell_snapshot,
                        inherited_exec_policy,
                    )
                    .await?
            }
            None => state.spawn_new_thread(config, self.clone()).await?,
        };
        reservation.commit(new_thread.thread_id);

        // Notify a new thread has been created. This notification will be processed by clients
        // to subscribe or drain this newly created thread.
        state.notify_thread_created(new_thread.thread_id);
        self.persist_thread_spawn_edge_for_source(
            new_thread.thread.as_ref(),
            new_thread.thread_id,
            notification_source.as_ref(),
        )
        .await;

        Ok(new_thread.thread_id)
    }

    /// Fork an existing agent thread and submit a prompt to the fork.
    pub(crate) async fn fork_agent(
        &self,
        config: Config,
        items: Vec<UserInput>,
        parent_thread_id: ThreadId,
        nth_user_message: usize,
        session_source: SessionSource,
    ) -> CodexResult<ThreadId> {
        let state = self.upgrade()?;
        let mut reservation = self
            .reserve_spawn_slot_with_reconcile(&state, config.agent_max_threads)
            .await?;
        let session_source =
            self.reserve_thread_spawn_identity(&config, &mut reservation, session_source)?;
        let notification_source = Some(session_source.clone());
        let inherited_shell_snapshot = self
            .inherited_shell_snapshot_for_source(&state, Some(&session_source))
            .await;
        let inherited_exec_policy = self
            .inherited_exec_policy_for_source(&state, Some(&session_source), &config)
            .await;
        let auth_manager = self
            .auth_manager_for_parent_thread(&config, &state, parent_thread_id)
            .await;

        let live_rollout_path = match state.get_thread(parent_thread_id).await {
            Ok(parent_thread) => {
                parent_thread
                    .codex
                    .session
                    .ensure_rollout_materialized()
                    .await;
                parent_thread.flush_rollout().await;
                parent_thread.rollout_path()
            }
            Err(CodexErr::ThreadNotFound(_)) => None,
            Err(err) => return Err(err),
        };
        let rollout_path = match live_rollout_path {
            Some(path) => path,
            None => find_thread_path_by_id_str(
                config.codex_home.as_path(),
                &parent_thread_id.to_string(),
            )
            .await?
            .ok_or_else(|| {
                CodexErr::UnsupportedOperation(format!(
                    "rollout history unavailable for thread {parent_thread_id}"
                ))
            })?,
        };

        let new_thread = state
            .fork_thread_with_source(
                nth_user_message,
                config,
                auth_manager,
                self.clone(),
                false,
                rollout_path,
                session_source,
                inherited_shell_snapshot,
                inherited_exec_policy,
                None,
            )
            .await?;
        reservation.commit(new_thread.thread_id);
        state.notify_thread_created(new_thread.thread_id);
        self.persist_thread_spawn_edge_for_source(
            new_thread.thread.as_ref(),
            new_thread.thread_id,
            notification_source.as_ref(),
        )
        .await;
        self.submit_initial_input_or_cleanup(&state, new_thread.thread_id, items)
            .await?;
        self.maybe_start_completion_watcher(new_thread.thread_id, notification_source);

        Ok(new_thread.thread_id)
    }

    /// Resume an existing agent thread from a recorded rollout file.
    pub(crate) async fn resume_agent_from_rollout(
        &self,
        config: Config,
        thread_id: ThreadId,
        session_source: SessionSource,
    ) -> CodexResult<ThreadId> {
        let root_depth = thread_spawn_depth(&session_source).unwrap_or(0);
        let resumed_thread_id = self
            .resume_single_agent_from_rollout(config.clone(), thread_id, session_source)
            .await?;
        let state = self.upgrade()?;
        let Ok(resumed_thread) = state.get_thread(resumed_thread_id).await else {
            return Ok(resumed_thread_id);
        };
        let Some(state_db_ctx) = resumed_thread.state_db() else {
            return Ok(resumed_thread_id);
        };

        let mut resume_queue = VecDeque::from([(thread_id, root_depth)]);
        while let Some((parent_thread_id, parent_depth)) = resume_queue.pop_front() {
            let child_ids = match state_db_ctx
                .list_thread_spawn_children_with_status(
                    parent_thread_id,
                    DirectionalThreadSpawnEdgeStatus::Open,
                )
                .await
            {
                Ok(child_ids) => child_ids,
                Err(err) => {
                    warn!(
                        "failed to load persisted thread-spawn children for {parent_thread_id}: {err}"
                    );
                    continue;
                }
            };

            for child_thread_id in child_ids {
                let child_depth = parent_depth + 1;
                let child_resumed = if state.get_thread(child_thread_id).await.is_ok() {
                    true
                } else {
                    let child_session_source =
                        SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                            parent_thread_id,
                            depth: child_depth,
                            agent_path: None,
                            agent_nickname: None,
                            agent_role: None,
                        });
                    match self
                        .resume_single_agent_from_rollout(
                            config.clone(),
                            child_thread_id,
                            child_session_source,
                        )
                        .await
                    {
                        Ok(_) => true,
                        Err(err) => {
                            warn!("failed to resume descendant thread {child_thread_id}: {err}");
                            false
                        }
                    }
                };
                if child_resumed {
                    resume_queue.push_back((child_thread_id, child_depth));
                }
            }
        }

        Ok(resumed_thread_id)
    }

    async fn resume_single_agent_from_rollout(
        &self,
        mut config: crate::config::Config,
        thread_id: ThreadId,
        session_source: SessionSource,
    ) -> CodexResult<ThreadId> {
        if let SessionSource::SubAgent(SubAgentSource::ThreadSpawn { depth, .. }) = &session_source
            && *depth >= config.agent_max_depth
        {
            let _ = config.features.disable(Feature::SpawnCsv);
            let _ = config.features.disable(Feature::Collab);
        }
        let state = self.upgrade()?;
        let mut reservation = self
            .reserve_spawn_slot_with_reconcile(&state, config.agent_max_threads)
            .await?;
        let session_source = match session_source {
            SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth,
                agent_path,
                agent_nickname,
                agent_role,
            }) => {
                // Collab resume callers rebuild a placeholder ThreadSpawn source. Rehydrate the
                // stored nickname/role from sqlite when available, then prefer any explicit
                // values already present on the session source.
                let (stored_agent_nickname, stored_agent_role) =
                    if let Some(state_db_ctx) = state_db::get_state_db(&config).await {
                        match state_db_ctx.get_thread(thread_id).await {
                            Ok(Some(metadata)) => (metadata.agent_nickname, metadata.agent_role),
                            Ok(None) | Err(_) => (None, None),
                        }
                    } else {
                        (None, None)
                    };
                let resumed_agent_role = agent_role.or(stored_agent_role);
                let resumed_agent_nickname = agent_nickname.or(stored_agent_nickname);
                let reserved_agent_nickname = resumed_agent_nickname
                    .as_deref()
                    .map(|agent_nickname| {
                        let candidate_names =
                            agent_nickname_candidates(&config, resumed_agent_role.as_deref());
                        let candidate_name_refs: Vec<&str> =
                            candidate_names.iter().map(String::as_str).collect();
                        reservation.reserve_agent_nickname_with_preference(
                            &candidate_name_refs,
                            Some(agent_nickname),
                        )
                    })
                    .transpose()?;
                SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth,
                    agent_path,
                    agent_nickname: reserved_agent_nickname,
                    agent_role: resumed_agent_role,
                })
            }
            other => other,
        };
        let notification_source = session_source.clone();
        let inherited_shell_snapshot = self
            .inherited_shell_snapshot_for_source(&state, Some(&session_source))
            .await;
        let inherited_exec_policy = self
            .inherited_exec_policy_for_source(&state, Some(&session_source), &config)
            .await;
        let auth_manager = self
            .auth_manager_for_source(&config, &state, Some(&session_source))
            .await;
        let rollout_path =
            match find_thread_path_by_id_str(config.codex_home.as_path(), &thread_id.to_string())
                .await?
            {
                Some(rollout_path) => rollout_path,
                None => find_archived_thread_path_by_id_str(
                    config.codex_home.as_path(),
                    &thread_id.to_string(),
                )
                .await?
                .ok_or_else(|| CodexErr::ThreadNotFound(thread_id))?,
            };

        let resumed_thread = state
            .resume_thread_from_rollout_with_source(
                config,
                rollout_path,
                auth_manager,
                self.clone(),
                session_source,
                inherited_shell_snapshot,
                inherited_exec_policy,
            )
            .await?;
        reservation.commit(resumed_thread.thread_id);
        // Resumed threads are re-registered in-memory and need the same listener
        // attachment path as freshly spawned threads.
        state.notify_thread_created(resumed_thread.thread_id);
        self.maybe_start_completion_watcher(
            resumed_thread.thread_id,
            Some(notification_source.clone()),
        );
        self.persist_thread_spawn_edge_for_source(
            resumed_thread.thread.as_ref(),
            resumed_thread.thread_id,
            Some(&notification_source),
        )
        .await;

        Ok(resumed_thread.thread_id)
    }

    pub(crate) async fn submit_initial_input_or_cleanup(
        &self,
        state: &ThreadManagerState,
        thread_id: ThreadId,
        items: Vec<UserInput>,
    ) -> CodexResult<()> {
        if let Err(err) = self.send_input(thread_id, items).await {
            let _ = state.send_op(thread_id, Op::Shutdown {}).await;
            let _ = state.remove_thread(&thread_id).await;
            self.guards.release_spawned_thread(thread_id);
            return Err(err);
        }
        Ok(())
    }

    async fn reserve_spawn_slot_with_reconcile(
        &self,
        state: &ThreadManagerState,
        max_threads: Option<usize>,
    ) -> CodexResult<crate::agent::guards::SpawnReservation> {
        self.reconcile_stale_guard_slots(state).await;
        let first_attempt = self.guards.reserve_spawn_slot(max_threads);
        match first_attempt {
            Ok(reservation) => return Ok(reservation),
            Err(CodexErr::AgentLimitReached { .. }) => {}
            Err(err) => return Err(err),
        }

        self.reconcile_stale_guard_slots(state).await;
        let second_attempt = self.guards.reserve_spawn_slot(max_threads);
        if let Err(CodexErr::AgentLimitReached { max_threads }) = second_attempt.as_ref() {
            let live_thread_ids = state
                .list_threads()
                .await
                .into_iter()
                .map(|(thread_id, _)| thread_id)
                .collect::<HashSet<_>>();
            let snapshot = self.guards.thread_cap_snapshot();
            let stale_tracked = snapshot
                .tracked_thread_ids
                .iter()
                .filter(|thread_id| !live_thread_ids.contains(thread_id))
                .count();
            warn!(
                max_threads,
                guard_total_count = snapshot.total_count,
                guard_tracked_count = snapshot.tracked_count,
                guard_in_flight_reservations = snapshot.in_flight_reservations,
                live_thread_count = live_thread_ids.len(),
                stale_tracked_count = stale_tracked,
                tracked_thread_ids = ?snapshot.tracked_thread_ids,
                live_thread_ids = ?live_thread_ids,
                "agent thread cap reached after stale-slot reconciliation"
            );
        }
        second_attempt
    }

    async fn reconcile_stale_guard_slots(&self, state: &ThreadManagerState) {
        let live_thread_ids: HashSet<ThreadId> = state
            .list_threads()
            .await
            .into_iter()
            .map(|(thread_id, _)| thread_id)
            .collect();
        for tracked_thread_id in self.guards.tracked_thread_ids() {
            if !live_thread_ids.contains(&tracked_thread_id) {
                self.guards.release_spawned_thread(tracked_thread_id);
            }
        }
    }

    fn reserve_thread_spawn_identity(
        &self,
        config: &Config,
        reservation: &mut SpawnReservation,
        session_source: SessionSource,
    ) -> CodexResult<SessionSource> {
        match session_source {
            SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth,
                agent_path,
                agent_nickname,
                agent_role,
            }) => {
                let candidate_names = agent_nickname_candidates(config, agent_role.as_deref());
                let candidate_name_refs: Vec<&str> =
                    candidate_names.iter().map(String::as_str).collect();
                let agent_nickname = reservation.reserve_agent_nickname_with_preference(
                    &candidate_name_refs,
                    agent_nickname.as_deref(),
                )?;
                Ok(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                    parent_thread_id,
                    depth,
                    agent_path,
                    agent_nickname: Some(agent_nickname),
                    agent_role,
                }))
            }
            other => Ok(other),
        }
    }

    fn maybe_reserve_thread_spawn_identity(
        &self,
        config: &Config,
        reservation: &mut SpawnReservation,
        session_source: Option<SessionSource>,
    ) -> CodexResult<Option<SessionSource>> {
        session_source
            .map(|source| self.reserve_thread_spawn_identity(config, reservation, source))
            .transpose()
    }

    async fn inherited_shell_snapshot_for_source(
        &self,
        state: &Arc<ThreadManagerState>,
        session_source: Option<&SessionSource>,
    ) -> Option<Arc<ShellSnapshot>> {
        let Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id, ..
        })) = session_source
        else {
            return None;
        };

        let parent_thread = state.get_thread(*parent_thread_id).await.ok()?;
        parent_thread.codex.session.user_shell().shell_snapshot()
    }

    async fn auth_manager_for_source(
        &self,
        config: &Config,
        state: &Arc<ThreadManagerState>,
        session_source: Option<&SessionSource>,
    ) -> Arc<AuthManager> {
        let Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id, ..
        })) = session_source
        else {
            return state.default_auth_manager();
        };

        self.auth_manager_for_parent_thread(config, state, *parent_thread_id)
            .await
    }

    async fn auth_manager_for_parent_thread(
        &self,
        config: &Config,
        state: &Arc<ThreadManagerState>,
        parent_thread_id: ThreadId,
    ) -> Arc<AuthManager> {
        let default_auth_manager = state.default_auth_manager();
        match state.get_thread(parent_thread_id).await {
            Ok(parent_thread) => Arc::clone(&parent_thread.codex.session.services.auth_manager),
            Err(_) => self
                .auth_manager_from_parent_rollout(
                    config,
                    parent_thread_id,
                    default_auth_manager.enable_codex_api_key_env(),
                )
                .await
                .unwrap_or(default_auth_manager),
        }
    }

    async fn auth_manager_from_parent_rollout(
        &self,
        config: &Config,
        parent_thread_id: ThreadId,
        enable_codex_api_key_env: bool,
    ) -> Option<Arc<AuthManager>> {
        let rollout_path = match find_thread_path_by_id_str(
            config.codex_home.as_path(),
            &parent_thread_id.to_string(),
        )
        .await
        .ok()?
        {
            Some(rollout_path) => rollout_path,
            None => find_archived_thread_path_by_id_str(
                config.codex_home.as_path(),
                &parent_thread_id.to_string(),
            )
            .await
            .ok()??,
        };
        let session_meta = crate::rollout::list::read_session_meta_line(&rollout_path)
            .await
            .ok()?;
        let auth_file = replayed_parent_auth_file(&session_meta.meta)?;
        AuthManager::shared_with_auth_file(
            config.codex_home.clone(),
            enable_codex_api_key_env,
            config.cli_auth_credentials_store_mode,
            Some(auth_file),
        )
        .ok()
    }

    async fn inherited_exec_policy_for_source(
        &self,
        state: &Arc<ThreadManagerState>,
        session_source: Option<&SessionSource>,
        child_config: &crate::config::Config,
    ) -> Option<Arc<crate::exec_policy::ExecPolicyManager>> {
        let Some(SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id, ..
        })) = session_source
        else {
            return None;
        };

        let parent_thread = state.get_thread(*parent_thread_id).await.ok()?;
        let parent_config = parent_thread.codex.session.get_config().await;
        if !crate::exec_policy::child_uses_parent_exec_policy(&parent_config, child_config) {
            return None;
        }

        Some(Arc::clone(
            &parent_thread.codex.session.services.exec_policy,
        ))
    }

    async fn persist_thread_spawn_edge_for_source(
        &self,
        thread: &crate::CodexThread,
        child_thread_id: ThreadId,
        session_source: Option<&SessionSource>,
    ) {
        let Some(parent_thread_id) = session_source.and_then(thread_spawn_parent_thread_id) else {
            return;
        };
        let Some(state_db_ctx) = thread.state_db() else {
            return;
        };
        if let Err(err) = state_db_ctx
            .upsert_thread_spawn_edge(
                parent_thread_id,
                child_thread_id,
                DirectionalThreadSpawnEdgeStatus::Open,
            )
            .await
        {
            warn!("failed to persist thread-spawn edge: {err}");
        }
    }
}
