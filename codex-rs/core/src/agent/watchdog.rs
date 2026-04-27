use super::control::AgentControl;
use super::control::SpawnAgentForkMode;
use super::control::SpawnAgentOptions;
use super::exceeds_thread_spawn_depth_limit;
use super::status::is_final;
use crate::config::Config;
use crate::error::CodexErr;
use crate::error::Result as CodexResult;
use crate::thread_manager::ThreadManagerState;
use codex_protocol::ThreadId;
use codex_protocol::protocol::AgentStatus;
use codex_protocol::protocol::SessionSource;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::protocol::TurnEnvironmentSelection;
use codex_protocol::user_input::UserInput;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tokio::time::Instant;
use tracing::info;
use tracing::warn;

pub(crate) const DEFAULT_WATCHDOG_INTERVAL_S: i64 = 60;

const WATCHDOG_TICK_SECONDS: u64 = 1;

#[derive(Clone)]
pub(crate) struct WatchdogRegistration {
    pub(crate) owner_thread_id: ThreadId,
    pub(crate) target_thread_id: ThreadId,
    pub(crate) child_depth: i32,
    pub(crate) interval_s: i64,
    pub(crate) prompt: String,
    pub(crate) config: Config,
    pub(crate) environments: Option<Vec<TurnEnvironmentSelection>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RemovedWatchdog {
    pub(crate) owner_thread_id: ThreadId,
    pub(crate) target_thread_id: ThreadId,
    pub(crate) active_helper_id: Option<ThreadId>,
}

struct WatchdogEntry {
    registration: WatchdogRegistration,
    interval: Duration,
    last_trigger: Instant,
    active_helper_id: Option<ThreadId>,
    owner_idle_since: Option<Instant>,
    owner_was_running: bool,
    idle_episode_satisfied: bool,
    force_due_once: bool,
    generation: i64,
}

#[derive(Clone)]
struct WatchdogSnapshot {
    owner_thread_id: ThreadId,
    child_depth: i32,
    prompt: String,
    config: Config,
    environments: Option<Vec<TurnEnvironmentSelection>>,
    interval: Duration,
    last_trigger: Instant,
    active_helper_id: Option<ThreadId>,
    owner_idle_since: Option<Instant>,
}

pub(crate) struct WatchdogManager {
    manager: Weak<ThreadManagerState>,
    registrations: Mutex<HashMap<ThreadId, WatchdogEntry>>,
    preserved_helper_owners: Mutex<HashMap<ThreadId, ThreadId>>,
    helpers_that_notified_owner: Mutex<HashSet<ThreadId>>,
    handled_helper_completions: Mutex<HashSet<ThreadId>>,
    started: AtomicBool,
    next_generation: AtomicI64,
}

impl WatchdogManager {
    pub(crate) fn new(manager: Weak<ThreadManagerState>) -> Arc<Self> {
        Arc::new(Self {
            manager,
            registrations: Mutex::new(HashMap::new()),
            preserved_helper_owners: Mutex::new(HashMap::new()),
            helpers_that_notified_owner: Mutex::new(HashSet::new()),
            handled_helper_completions: Mutex::new(HashSet::new()),
            started: AtomicBool::new(false),
            next_generation: AtomicI64::new(1),
        })
    }

    pub(crate) fn start(self: &Arc<Self>, control: AgentControl) {
        if self
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let manager = Arc::clone(self);
        tokio::spawn(async move {
            manager.run_loop(control).await;
        });
    }

    async fn run_loop(self: Arc<Self>, control: AgentControl) {
        loop {
            self.run_once(&control).await;
            if self.manager.upgrade().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(WATCHDOG_TICK_SECONDS)).await;
        }
    }

    pub(crate) async fn run_once(self: &Arc<Self>, control: &AgentControl) {
        let Some(manager_state) = self.manager.upgrade() else {
            self.registrations.lock().await.clear();
            return;
        };

        let snapshots: Vec<(ThreadId, i64)> = {
            let registrations = self.registrations.lock().await;
            registrations
                .iter()
                .map(|(target_id, entry)| (*target_id, entry.generation))
                .collect()
        };
        let now = Instant::now();

        for (target_id, generation) in snapshots {
            self.evaluate(control, &manager_state, target_id, generation, now)
                .await;
        }
    }

    pub(crate) async fn register(
        self: &Arc<Self>,
        registration: WatchdogRegistration,
    ) -> CodexResult<Vec<RemovedWatchdog>> {
        if exceeds_thread_spawn_depth_limit(
            registration.child_depth,
            registration.config.agent_max_depth,
        ) {
            let max_depth = registration.config.agent_max_depth;
            return Err(CodexErr::UnsupportedOperation(format!(
                "agent depth limit reached: max depth is {max_depth}"
            )));
        }
        let interval = interval_duration(registration.interval_s)?;
        let generation = self.next_generation.fetch_add(1, Ordering::AcqRel);
        let now = Instant::now();
        let entry = WatchdogEntry {
            registration,
            interval,
            last_trigger: now,
            active_helper_id: None,
            owner_idle_since: Some(now),
            owner_was_running: false,
            idle_episode_satisfied: false,
            force_due_once: false,
            generation,
        };

        let mut registrations = self.registrations.lock().await;
        let superseded_targets: Vec<ThreadId> = registrations
            .iter()
            .filter_map(|(target_thread_id, existing_entry)| {
                (existing_entry.registration.owner_thread_id == entry.registration.owner_thread_id
                    && *target_thread_id != entry.registration.target_thread_id)
                    .then_some(*target_thread_id)
            })
            .collect();
        let mut superseded = Vec::new();
        for superseded_target in superseded_targets {
            if let Some(removed) = registrations.remove(&superseded_target) {
                superseded.push(RemovedWatchdog {
                    owner_thread_id: removed.registration.owner_thread_id,
                    target_thread_id: superseded_target,
                    active_helper_id: removed.active_helper_id,
                });
            }
        }
        registrations.insert(entry.registration.target_thread_id, entry);
        Ok(superseded)
    }

    async fn evaluate(
        self: &Arc<Self>,
        control: &AgentControl,
        manager_state: &Arc<ThreadManagerState>,
        target_thread_id: ThreadId,
        generation: i64,
        now: Instant,
    ) {
        let Some(snapshot) = self.snapshot(target_thread_id, generation).await else {
            return;
        };

        let owner_thread = manager_state.get_thread(snapshot.owner_thread_id).await;
        let owner_status = match owner_thread.as_ref() {
            Ok(thread) => thread.agent_status().await,
            Err(_) => AgentStatus::NotFound,
        };
        if is_watchdog_terminated(&owner_status) {
            match control.shutdown_live_agent(target_thread_id).await {
                Ok(_) | Err(CodexErr::ThreadNotFound(_)) | Err(CodexErr::InternalAgentDied) => {}
                Err(err) => {
                    warn!(
                        owner_thread_id = %snapshot.owner_thread_id,
                        target_thread_id = %target_thread_id,
                        "watchdog owner termination cleanup failed: {err}"
                    );
                }
            }
            return;
        }

        let force_due = self
            .take_force_due_if_generation(target_thread_id, generation)
            .await;
        let owner_running = match owner_thread {
            Ok(_) => agent_status_is_active(&owner_status) && !force_due,
            Err(_) => false,
        };
        let (owner_idle_since, idle_episode_satisfied) = self
            .update_owner_idle_state_if_generation(
                target_thread_id,
                generation,
                owner_running,
                now,
                force_due,
            )
            .await;
        if let Some(helper_id) = snapshot.active_helper_id {
            self.evaluate_active_helper(
                control,
                manager_state,
                target_thread_id,
                generation,
                now,
                snapshot.owner_thread_id,
                helper_id,
            )
            .await;
            return;
        }
        if owner_running {
            return;
        }

        let owner_idle_since = owner_idle_since.or(snapshot.owner_idle_since);
        let Some(owner_idle_since) = owner_idle_since else {
            return;
        };
        if !force_due && now.duration_since(owner_idle_since) < snapshot.interval {
            return;
        }
        if idle_episode_satisfied {
            return;
        }
        if !force_due && now.duration_since(snapshot.last_trigger) < snapshot.interval {
            return;
        }

        self.spawn_helper(control, target_thread_id, generation, now, snapshot)
            .await;
    }

    async fn evaluate_active_helper(
        self: &Arc<Self>,
        control: &AgentControl,
        manager_state: &Arc<ThreadManagerState>,
        target_thread_id: ThreadId,
        generation: i64,
        now: Instant,
        owner_thread_id: ThreadId,
        helper_id: ThreadId,
    ) {
        let mut helper_status = get_status(manager_state, helper_id).await;
        if !is_final(&helper_status) {
            helper_status = match manager_state.get_thread(helper_id).await {
                Ok(_) if agent_status_is_active(&helper_status) => return,
                Ok(_) => return,
                Err(_) => AgentStatus::NotFound,
            };
        }
        if !self.try_claim_helper_completion(helper_id).await {
            return;
        }

        let mut idle_episode_satisfied = self.helper_notified_owner(helper_id).await;
        if let Some(message) = watchdog_completion_message(&helper_status, idle_episode_satisfied) {
            match control
                .send_watchdog_wakeup(owner_thread_id, helper_id, message)
                .await
            {
                Ok(_) => {
                    idle_episode_satisfied = true;
                    info!(
                        helper_id = %helper_id,
                        owner_thread_id = %owner_thread_id,
                        "watchdog forwarded helper completion to owner"
                    );
                }
                Err(err) => {
                    warn!(
                        helper_id = %helper_id,
                        owner_thread_id = %owner_thread_id,
                        "watchdog helper forward failed: {err}"
                    );
                }
            }
        }
        if let Err(err) = control.shutdown_live_agent(helper_id).await {
            warn!(
                helper_id = %helper_id,
                owner_thread_id = %owner_thread_id,
                "watchdog helper cleanup failed: {err}"
            );
        }
        self.update_after_helper_completion(
            target_thread_id,
            generation,
            now,
            helper_id,
            idle_episode_satisfied,
        )
        .await;
        self.clear_preserved_helper_owner(helper_id).await;
    }

    async fn spawn_helper(
        self: &Arc<Self>,
        control: &AgentControl,
        target_thread_id: ThreadId,
        generation: i64,
        now: Instant,
        snapshot: WatchdogSnapshot,
    ) {
        let session_source = SessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id: snapshot.owner_thread_id,
            depth: snapshot.child_depth,
            agent_path: None,
            agent_nickname: None,
            agent_role: None,
        });
        let mut helper_config = snapshot.config.clone();
        helper_config.ephemeral = true;
        let helper_prompt = watchdog_helper_prompt(&snapshot.prompt);
        let spawn_result = control
            .spawn_agent_with_metadata(
                helper_config,
                vec![UserInput::Text {
                    text: helper_prompt,
                    text_elements: Vec::new(),
                }]
                .into(),
                Some(session_source),
                SpawnAgentOptions {
                    fork_parent_spawn_call_id: Some(format!("watchdog:{target_thread_id}")),
                    fork_mode: Some(SpawnAgentForkMode::FullHistory),
                    environments: snapshot.environments.clone(),
                },
            )
            .await;

        match spawn_result {
            Ok(helper) => {
                info!(
                    helper_id = %helper.thread_id,
                    target_thread_id = %target_thread_id,
                    "watchdog spawned helper"
                );
                self.update_after_spawn(target_thread_id, generation, now, Some(helper.thread_id))
                    .await;
            }
            Err(err) => {
                warn!("watchdog spawn failed for target {target_thread_id}: {err}");
                self.update_after_spawn(target_thread_id, generation, now, None)
                    .await;
            }
        }
    }

    async fn snapshot(
        &self,
        target_thread_id: ThreadId,
        generation: i64,
    ) -> Option<WatchdogSnapshot> {
        let registrations = self.registrations.lock().await;
        let entry = registrations.get(&target_thread_id)?;
        if entry.generation != generation {
            return None;
        }
        Some(WatchdogSnapshot {
            owner_thread_id: entry.registration.owner_thread_id,
            child_depth: entry.registration.child_depth,
            prompt: entry.registration.prompt.clone(),
            config: entry.registration.config.clone(),
            environments: entry.registration.environments.clone(),
            interval: entry.interval,
            last_trigger: entry.last_trigger,
            active_helper_id: entry.active_helper_id,
            owner_idle_since: entry.owner_idle_since,
        })
    }

    async fn update_owner_idle_state_if_generation(
        &self,
        target_thread_id: ThreadId,
        generation: i64,
        owner_running: bool,
        now: Instant,
        force_due: bool,
    ) -> (Option<Instant>, bool) {
        let mut registrations = self.registrations.lock().await;
        let Some(entry) = registrations.get_mut(&target_thread_id) else {
            return (None, false);
        };
        if entry.generation != generation {
            return (None, false);
        }

        if force_due {
            return (entry.owner_idle_since, entry.idle_episode_satisfied);
        }
        if owner_running {
            if !entry.idle_episode_satisfied {
                entry.owner_idle_since = None;
            }
            entry.owner_was_running = true;
            return (entry.owner_idle_since, entry.idle_episode_satisfied);
        }

        if entry.owner_was_running || entry.owner_idle_since.is_none() {
            entry.owner_idle_since = Some(now);
            entry.idle_episode_satisfied = false;
        }
        entry.owner_was_running = false;
        (entry.owner_idle_since, entry.idle_episode_satisfied)
    }

    async fn take_force_due_if_generation(
        &self,
        target_thread_id: ThreadId,
        generation: i64,
    ) -> bool {
        let mut registrations = self.registrations.lock().await;
        let Some(entry) = registrations.get_mut(&target_thread_id) else {
            return false;
        };
        if entry.generation != generation || !entry.force_due_once {
            return false;
        }
        entry.force_due_once = false;
        true
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn force_due_for_tests(&self, target_thread_id: ThreadId) {
        let mut registrations = self.registrations.lock().await;
        if let Some(entry) = registrations.get_mut(&target_thread_id) {
            entry.force_due_once = true;
        }
    }

    async fn update_after_spawn(
        &self,
        target_thread_id: ThreadId,
        generation: i64,
        now: Instant,
        active_helper_id: Option<ThreadId>,
    ) {
        let mut registrations = self.registrations.lock().await;
        let Some(entry) = registrations.get_mut(&target_thread_id) else {
            return;
        };
        if entry.generation != generation {
            return;
        }
        entry.last_trigger = now;
        entry.active_helper_id = active_helper_id;
    }

    async fn update_after_helper_completion(
        &self,
        target_thread_id: ThreadId,
        generation: i64,
        now: Instant,
        helper_thread_id: ThreadId,
        idle_episode_satisfied: bool,
    ) {
        let owner_thread_id = {
            let registrations = self.registrations.lock().await;
            let Some(entry) = registrations.get(&target_thread_id) else {
                return;
            };
            if entry.generation != generation {
                return;
            }
            entry.registration.owner_thread_id
        };

        self.preserve_helper_owner_for_completion_fallback(helper_thread_id, owner_thread_id)
            .await;

        let mut registrations = self.registrations.lock().await;
        let Some(entry) = registrations.get_mut(&target_thread_id) else {
            self.clear_helper_notified_owner(helper_thread_id).await;
            return;
        };
        if entry.generation != generation {
            self.clear_helper_notified_owner(helper_thread_id).await;
            return;
        }
        entry.last_trigger = now;
        entry.active_helper_id = None;
        entry.idle_episode_satisfied = idle_episode_satisfied;
        if idle_episode_satisfied {
            entry.owner_idle_since = None;
            entry.owner_was_running = true;
        }
        drop(registrations);
        self.clear_helper_notified_owner(helper_thread_id).await;
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn complete_active_helper(
        &self,
        helper_thread_id: ThreadId,
        now: Instant,
        idle_episode_satisfied: bool,
    ) {
        let registrations = self.registrations.lock().await;
        let Some((target_thread_id, generation)) =
            registrations.iter().find_map(|(target_thread_id, entry)| {
                (entry.active_helper_id == Some(helper_thread_id))
                    .then_some((*target_thread_id, entry.generation))
            })
        else {
            return;
        };
        drop(registrations);
        self.update_after_helper_completion(
            target_thread_id,
            generation,
            now,
            helper_thread_id,
            idle_episode_satisfied,
        )
        .await;
    }

    pub(crate) async fn unregister(&self, target_thread_id: ThreadId) -> Option<RemovedWatchdog> {
        let mut registrations = self.registrations.lock().await;
        registrations
            .remove(&target_thread_id)
            .map(|removed| RemovedWatchdog {
                owner_thread_id: removed.registration.owner_thread_id,
                target_thread_id,
                active_helper_id: removed.active_helper_id,
            })
    }

    pub(crate) async fn owner_for_active_helper(
        &self,
        helper_thread_id: ThreadId,
    ) -> Option<ThreadId> {
        let registrations = self.registrations.lock().await;
        if let Some(owner_thread_id) = registrations.values().find_map(|entry| {
            (entry.active_helper_id == Some(helper_thread_id))
                .then_some(entry.registration.owner_thread_id)
        }) {
            return Some(owner_thread_id);
        }
        drop(registrations);
        self.preserved_helper_owners
            .lock()
            .await
            .get(&helper_thread_id)
            .copied()
    }

    pub(crate) async fn registered_targets(&self, candidate_ids: &[ThreadId]) -> HashSet<ThreadId> {
        let registrations = self.registrations.lock().await;
        candidate_ids
            .iter()
            .copied()
            .filter(|candidate_id| registrations.contains_key(candidate_id))
            .collect()
    }

    pub(crate) async fn take_for_owner(&self, owner_thread_id: ThreadId) -> Vec<RemovedWatchdog> {
        let mut registrations = self.registrations.lock().await;
        let removed_targets: Vec<ThreadId> = registrations
            .iter()
            .filter_map(|(target_thread_id, entry)| {
                (entry.registration.owner_thread_id == owner_thread_id).then_some(*target_thread_id)
            })
            .collect();
        let mut removed = Vec::new();
        for removed_target in removed_targets {
            if let Some(entry) = registrations.remove(&removed_target) {
                removed.push(RemovedWatchdog {
                    owner_thread_id: entry.registration.owner_thread_id,
                    target_thread_id: removed_target,
                    active_helper_id: entry.active_helper_id,
                });
            }
        }
        removed
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn set_active_helper_for_tests(
        &self,
        target_thread_id: ThreadId,
        helper_thread_id: ThreadId,
    ) {
        let mut registrations = self.registrations.lock().await;
        let Some(entry) = registrations.get_mut(&target_thread_id) else {
            return;
        };
        let due_at = Instant::now() - entry.interval;
        entry.last_trigger = due_at;
        entry.owner_idle_since = Some(due_at);
        entry.owner_was_running = false;
        entry.idle_episode_satisfied = false;
        entry.active_helper_id = Some(helper_thread_id);
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn active_helper_for_target(
        &self,
        target_thread_id: ThreadId,
    ) -> Option<ThreadId> {
        let registrations = self.registrations.lock().await;
        registrations
            .get(&target_thread_id)
            .and_then(|entry| entry.active_helper_id)
    }

    pub(crate) async fn preserve_helper_owner_for_completion_fallback(
        &self,
        helper_thread_id: ThreadId,
        owner_thread_id: ThreadId,
    ) {
        self.preserved_helper_owners
            .lock()
            .await
            .insert(helper_thread_id, owner_thread_id);
    }

    pub(crate) async fn clear_preserved_helper_owner(&self, helper_thread_id: ThreadId) {
        self.preserved_helper_owners
            .lock()
            .await
            .remove(&helper_thread_id);
    }

    pub(crate) async fn clear_helper_notified_owner(&self, helper_thread_id: ThreadId) {
        self.helpers_that_notified_owner
            .lock()
            .await
            .remove(&helper_thread_id);
    }

    pub(crate) async fn try_claim_helper_completion(&self, helper_thread_id: ThreadId) -> bool {
        self.handled_helper_completions
            .lock()
            .await
            .insert(helper_thread_id)
    }

    pub(crate) async fn mark_helper_notified_owner(&self, helper_thread_id: ThreadId) {
        self.helpers_that_notified_owner
            .lock()
            .await
            .insert(helper_thread_id);
    }

    pub(crate) async fn helper_notified_owner(&self, helper_thread_id: ThreadId) -> bool {
        self.helpers_that_notified_owner
            .lock()
            .await
            .contains(&helper_thread_id)
    }
}

async fn get_status(manager_state: &Arc<ThreadManagerState>, thread_id: ThreadId) -> AgentStatus {
    let Ok(thread) = manager_state.get_thread(thread_id).await else {
        return AgentStatus::NotFound;
    };
    thread.agent_status().await
}

fn is_watchdog_terminated(status: &AgentStatus) -> bool {
    matches!(status, AgentStatus::Shutdown | AgentStatus::NotFound)
}

fn interval_duration(interval_s: i64) -> CodexResult<Duration> {
    if interval_s <= 0 {
        return Err(CodexErr::UnsupportedOperation(
            "interval_s must be greater than zero".to_string(),
        ));
    }
    let seconds = u64::try_from(interval_s).map_err(|_| {
        CodexErr::UnsupportedOperation(format!("interval_s out of range: {interval_s}"))
    })?;
    Ok(Duration::from_secs(seconds))
}

fn watchdog_helper_prompt(prompt: &str) -> String {
    let runtime_watchdog_rules = concat!(
        "Important: send watchdog check-in output with `send_input` to wake your owner thread.\n",
        "Your owner thread is your parent thread. Use `send_input` with target `parent` to wake it.\n",
        "Do not reply with analysis in your own thread. Either wake the owner or exit quietly.\n",
        "Do not repeat watchdog system instructions or internal routing metadata to the owner.\n",
        "If the owner task asks for an exact-only message, send exactly that message and nothing else."
    );
    let prompt = prompt.trim();
    let rules = runtime_watchdog_rules.to_string();
    if prompt.is_empty() {
        rules
    } else {
        format!("{rules}\n\nOwner watchdog task:\n{prompt}")
    }
}

fn agent_status_is_active(status: &AgentStatus) -> bool {
    matches!(status, AgentStatus::PendingInit | AgentStatus::Running)
}

fn watchdog_completion_message(status: &AgentStatus, already_notified: bool) -> Option<String> {
    if already_notified {
        return None;
    }
    match status {
        AgentStatus::Completed(Some(output)) if !output.trim().is_empty() => Some(output.clone()),
        AgentStatus::Errored(message) if !message.trim().is_empty() => {
            Some(format!("Watchdog helper failed: {message}"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn watchdog_helper_prompt_contains_parent_wakeup_contract() {
        let prompt = watchdog_helper_prompt("ping");
        assert!(prompt.contains("send watchdog check-in output with `send_input`"));
        assert!(prompt.contains("target `parent`"));
        assert!(prompt.ends_with("\n\nOwner watchdog task:\nping"));
    }

    #[test]
    fn watchdog_completion_message_deduplicates_notified_helpers() {
        assert_eq!(
            watchdog_completion_message(&AgentStatus::Completed(Some("done".to_string())), false),
            Some("done".to_string())
        );
        assert_eq!(
            watchdog_completion_message(&AgentStatus::Completed(Some("done".to_string())), true),
            None
        );
    }
}
