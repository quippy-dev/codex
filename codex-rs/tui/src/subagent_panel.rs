use crate::history_cell::HistoryCell;
use crate::history_cell::new_subagent_spawned_cell;
use crate::history_cell::new_subagent_update_cell;
use crate::shimmer::shimmer_spans;
use crate::status_indicator_widget::fmt_elapsed_compact;
use crate::subagent_identity::format_subagent_label;
use crate::subagent_identity::merge_subagent_identity;
use crate::subagent_transcript::SUBAGENT_UPDATE_PREVIEW_BUDGET;
use crate::subagent_transcript::SubagentUpdateLevel;
use crate::subagent_transcript::prompt_first_line;
use crate::subagent_transcript::prompt_preview;
use crate::subagent_transcript::running_preview;
use crate::subagent_transcript::terminal_summary;
use crate::text_formatting::extract_first_bold;
use crate::text_formatting::truncate_text;
use codex_protocol::ThreadId;
use codex_protocol::protocol::AgentMessageDeltaEvent;
use codex_protocol::protocol::AgentMessageEvent;
use codex_protocol::protocol::AgentSpawnMode;
use codex_protocol::protocol::AgentStatus;
use codex_protocol::protocol::CollabAgentSpawnEndEvent;
use codex_protocol::protocol::CollabCloseEndEvent;
use codex_protocol::protocol::CollabWaitingEndEvent;
use codex_protocol::protocol::ErrorEvent;
use codex_protocol::protocol::Event;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::TurnAbortedEvent;
use codex_protocol::protocol::TurnCompleteEvent;
use codex_protocol::protocol::TurnStartedEvent;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

const SUBAGENT_PENDING_EVENT_CAPACITY: usize = 12;
const SUBAGENT_SHIMMER_WINDOW: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub(crate) struct SubagentInfo {
    pub(crate) ordinal: i32,
    pub(crate) nickname: Option<String>,
    pub(crate) agent_role: Option<String>,
    pub(crate) prompt_preview: String,
    pub(crate) spawn_mode: AgentSpawnMode,
    pub(crate) status: AgentStatus,
    pub(crate) is_root_level: bool,
    pub(crate) spawned_at: Instant,
    pub(crate) started_at: Option<Instant>,
    pub(crate) latest_summary: String,
    pub(crate) latest_preview: String,
    pub(crate) latest_update_at: Instant,
    pub(crate) inflight_message: String,
    pub(crate) reasoning_buffer: String,
    pub(crate) notified_terminal: bool,
}

impl SubagentInfo {
    pub(crate) fn new(
        ordinal: i32,
        nickname: Option<String>,
        agent_role: Option<String>,
        prompt_preview: String,
        spawn_mode: AgentSpawnMode,
        is_root_level: bool,
    ) -> Self {
        let now = Instant::now();
        Self {
            ordinal,
            nickname,
            agent_role,
            prompt_preview: prompt_preview.clone(),
            spawn_mode,
            status: AgentStatus::PendingInit,
            is_root_level,
            spawned_at: now,
            started_at: None,
            latest_summary: String::new(),
            latest_preview: prompt_preview,
            latest_update_at: now,
            inflight_message: String::new(),
            reasoning_buffer: String::new(),
            notified_terminal: false,
        }
    }

    fn merge_identity(&mut self, nickname: Option<&str>, agent_role: Option<&str>) {
        merge_subagent_identity(
            &mut self.nickname,
            &mut self.agent_role,
            nickname,
            agent_role,
        );
    }

    pub(crate) fn label(&self) -> String {
        format_subagent_label(
            self.ordinal,
            self.nickname.as_deref(),
            self.agent_role.as_deref(),
            self.spawn_mode,
        )
    }

    fn is_running(&self) -> bool {
        matches!(self.status, AgentStatus::PendingInit | AgentStatus::Running)
    }

    fn is_watchdog(&self) -> bool {
        self.spawn_mode == AgentSpawnMode::Watchdog
    }

    fn is_visible_in_panel(&self) -> bool {
        if self.is_watchdog() {
            return matches!(self.status, AgentStatus::PendingInit | AgentStatus::Running);
        }
        self.is_running()
    }

    fn is_running_for_panel(&self) -> bool {
        if self.is_watchdog() {
            return matches!(self.status, AgentStatus::Running);
        }
        self.is_running()
    }

    fn running_started_at(&self) -> Instant {
        self.started_at.unwrap_or(self.spawned_at)
    }

    fn update_level(&self) -> SubagentUpdateLevel {
        if self.is_root_level {
            SubagentUpdateLevel::Root
        } else {
            SubagentUpdateLevel::Nested
        }
    }

    fn update_preview(&mut self, preview: String) {
        self.latest_preview = preview;
        self.latest_update_at = Instant::now();
    }

    fn update_reasoning_summary(&mut self, delta: &str) {
        self.reasoning_buffer.push_str(delta);
        if let Some(summary) = extract_first_bold(&self.reasoning_buffer) {
            self.latest_summary = truncate_text(summary.trim(), SUBAGENT_UPDATE_PREVIEW_BUDGET);
            self.latest_update_at = Instant::now();
        }
    }

    fn clear_turn_buffers(&mut self) {
        self.inflight_message.clear();
        self.reasoning_buffer.clear();
        self.latest_summary.clear();
    }

    fn should_shimmer(&self, now: Instant) -> bool {
        if self.is_watchdog() && matches!(self.status, AgentStatus::PendingInit) {
            return false;
        }
        if !self.is_running() {
            return false;
        }
        now.saturating_duration_since(self.latest_update_at) <= SUBAGENT_SHIMMER_WINDOW
    }
}

#[derive(Debug, Default)]
pub(crate) struct SubagentRegistry {
    pub(crate) root_thread_id: Option<ThreadId>,
    pub(crate) agents: HashMap<ThreadId, SubagentInfo>,
    pub(crate) order: Vec<ThreadId>,
    pub(crate) pending_events: HashMap<ThreadId, Vec<EventMsg>>,
    pub(crate) pending_history: Vec<Box<dyn HistoryCell>>,
    pub(crate) panel_state: Option<Arc<Mutex<SubagentPanelState>>>,
    pub(crate) panel_cell: Option<Arc<SubagentStatusCell>>,
    pub(crate) animations_enabled: bool,
}

impl SubagentRegistry {
    pub(crate) fn new(animations_enabled: bool) -> Self {
        Self {
            animations_enabled,
            ..Self::default()
        }
    }

    pub(crate) fn clear(&mut self) {
        self.root_thread_id = None;
        self.agents.clear();
        self.order.clear();
        self.pending_events.clear();
        self.pending_history.clear();
        self.panel_state = None;
        self.panel_cell = None;
    }

    pub(crate) fn set_root_thread(&mut self, thread_id: ThreadId) {
        if self
            .root_thread_id
            .is_some_and(|current| current != thread_id)
        {
            self.clear();
        }
        self.root_thread_id = Some(thread_id);
    }

    pub(crate) fn is_root_thread(&self, thread_id: ThreadId) -> bool {
        self.root_thread_id == Some(thread_id)
    }

    pub(crate) fn contains(&self, thread_id: ThreadId) -> bool {
        self.agents.contains_key(&thread_id)
    }

    pub(crate) fn process_event(
        &mut self,
        thread_id: ThreadId,
        primary_thread_id: Option<ThreadId>,
        event: &Event,
    ) -> Vec<Box<dyn HistoryCell>> {
        if primary_thread_id == Some(thread_id) {
            self.set_root_thread(thread_id);
        }

        match &event.msg {
            EventMsg::CollabAgentSpawnEnd(ev) => {
                // Keep registry/panel state in sync for both root and nested spawns, but let
                // chatwidget own lifecycle transcript cells for root-thread collab events.
                let _ = self.on_spawn_end(ev);
                Vec::new()
            }
            EventMsg::CollabWaitingEnd(ev) => {
                self.on_wait_end(ev);
                Vec::new()
            }
            EventMsg::CollabCloseEnd(ev) => {
                let is_nested_receiver = self
                    .agents
                    .get(&ev.receiver_thread_id)
                    .is_some_and(|info| info.update_level() == SubagentUpdateLevel::Nested);
                self.on_close_end(ev)
                    .filter(|_| is_nested_receiver)
                    .into_iter()
                    .collect()
            }
            _ if !self.is_root_thread(thread_id) => self.on_agent_event(thread_id, &event.msg),
            _ => Vec::new(),
        }
    }

    pub(crate) fn on_spawn_end(
        &mut self,
        event: &CollabAgentSpawnEndEvent,
    ) -> Option<Box<dyn HistoryCell>> {
        let new_thread_id = event.new_thread_id?;
        if event.spawn_mode == AgentSpawnMode::Watchdog {
            self.prune_superseded_watchdogs(new_thread_id);
        }
        if self.contains(new_thread_id) {
            return None;
        }
        let ordinal = i32::try_from(self.order.len())
            .unwrap_or(i32::MAX - 1)
            .saturating_add(1);
        let prompt_preview = prompt_preview(&event.prompt);
        let is_root_level = self.is_root_thread(event.sender_thread_id);
        let mut info = SubagentInfo::new(
            ordinal,
            event.new_agent_nickname.clone(),
            event.new_agent_role.clone(),
            prompt_preview,
            event.spawn_mode,
            is_root_level,
        );
        info.status = event.status.clone();
        info.latest_preview = info.prompt_preview.clone();
        info.latest_update_at = Instant::now();
        let label = info.label();

        self.order.push(new_thread_id);
        self.agents.insert(new_thread_id, info);

        let early_events = self
            .pending_events
            .remove(&new_thread_id)
            .unwrap_or_default();
        let mut follow_up = Vec::new();
        for msg in early_events {
            follow_up.extend(self.on_agent_event(new_thread_id, &msg));
        }
        for cell in follow_up {
            self.queue_history(cell);
        }

        let prompt_line = prompt_first_line(&event.prompt);
        Some(Box::new(new_subagent_spawned_cell(&label, &prompt_line)))
    }

    pub(crate) fn on_wait_end(&mut self, event: &CollabWaitingEndEvent) {
        for entry in &event.agent_statuses {
            let Some(info) = self.agents.get_mut(&entry.thread_id) else {
                continue;
            };
            info.merge_identity(entry.agent_nickname.as_deref(), entry.agent_role.as_deref());
        }

        for (thread_id, status) in &event.statuses {
            let Some(info) = self.agents.get_mut(thread_id) else {
                continue;
            };
            info.status = status.clone();
            info.latest_update_at = Instant::now();
        }
    }

    pub(crate) fn queue_history(&mut self, cell: Box<dyn HistoryCell>) {
        self.pending_history.push(cell);
    }

    pub(crate) fn take_pending_history(&mut self) -> Vec<Box<dyn HistoryCell>> {
        std::mem::take(&mut self.pending_history)
    }

    pub(crate) fn has_animating_agents(&self) -> bool {
        let now = Instant::now();
        self.agents.values().any(|info| info.should_shimmer(now))
    }

    pub(crate) fn rebuild_panel_state(&mut self) {
        let mut running_infos: Vec<&SubagentInfo> = self
            .agents
            .values()
            .filter(|info| info.is_visible_in_panel())
            .collect();
        running_infos.sort_by_key(|info| info.ordinal);

        if running_infos.is_empty() {
            self.panel_state = None;
            self.panel_cell = None;
            return;
        }

        let started_at = running_infos
            .iter()
            .map(|info| info.running_started_at())
            .min()
            .unwrap_or_else(Instant::now);
        let running_count = i32::try_from(
            running_infos
                .iter()
                .filter(|info| info.is_running_for_panel())
                .count(),
        )
        .unwrap_or(i32::MAX);
        let total_agents = i32::try_from(running_infos.len()).unwrap_or(i32::MAX);
        let running_agents = running_infos
            .into_iter()
            .map(|info| SubagentPanelAgent {
                ordinal: info.ordinal,
                name: info.label(),
                status: info.status.clone(),
                is_watchdog: info.is_watchdog(),
                preview: running_preview(
                    info.latest_summary.as_str(),
                    info.inflight_message.as_str(),
                    info.latest_preview.as_str(),
                    info.prompt_preview.as_str(),
                ),
                latest_update_at: info.latest_update_at,
            })
            .collect();

        let state = SubagentPanelState {
            started_at,
            total_agents,
            running_count,
            running_agents,
        };

        match &self.panel_state {
            Some(existing) => {
                let mut guard = existing
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *guard = state;
            }
            None => {
                self.panel_state = Some(Arc::new(Mutex::new(state)));
            }
        }

        if let Some(panel_state) = &self.panel_state {
            self.panel_cell = Some(Arc::new(SubagentStatusCell::new(
                Arc::clone(panel_state),
                self.animations_enabled,
            )));
        }
    }

    pub(crate) fn panel_cell(&self) -> Option<Arc<SubagentStatusCell>> {
        self.panel_cell.clone()
    }

    fn prune_superseded_watchdogs(&mut self, keep_thread_id: ThreadId) {
        let superseded: HashSet<ThreadId> = self
            .agents
            .iter()
            .filter_map(|(thread_id, info)| {
                (info.spawn_mode == AgentSpawnMode::Watchdog && *thread_id != keep_thread_id)
                    .then_some(*thread_id)
            })
            .collect();
        if superseded.is_empty() {
            return;
        }

        self.order
            .retain(|thread_id| !superseded.contains(thread_id));
        self.agents
            .retain(|thread_id, _| !superseded.contains(thread_id));
        self.pending_events
            .retain(|thread_id, _| !superseded.contains(thread_id));
    }

    fn on_close_end(&mut self, event: &CollabCloseEndEvent) -> Option<Box<dyn HistoryCell>> {
        let receiver_id = event.receiver_thread_id;
        let info = self.agents.get_mut(&receiver_id)?;
        info.merge_identity(
            event.receiver_agent_nickname.as_deref(),
            event.receiver_agent_role.as_deref(),
        );
        info.status = terminal_close_status(&event.status);
        info.latest_update_at = Instant::now();

        if is_terminal_status(&info.status) && !info.notified_terminal {
            info.notified_terminal = true;
            let summary = terminal_summary(&info.status);
            let label = info.label();
            return Some(Box::new(new_subagent_update_cell(
                &label,
                &info.status,
                summary.as_str(),
                info.update_level(),
            )));
        }
        None
    }

    pub(crate) fn on_agent_event(
        &mut self,
        thread_id: ThreadId,
        msg: &EventMsg,
    ) -> Vec<Box<dyn HistoryCell>> {
        let Some(info) = self.agents.get_mut(&thread_id) else {
            self.buffer_pending_event(thread_id, msg.clone());
            return Vec::new();
        };

        let mut history = Vec::new();
        match msg {
            EventMsg::TurnStarted(TurnStartedEvent { .. }) => {
                info.clear_turn_buffers();
                info.status = AgentStatus::Running;
                if info.started_at.is_none() {
                    info.started_at = Some(Instant::now());
                }
            }
            EventMsg::AgentReasoningDelta(ev) => {
                info.update_reasoning_summary(ev.delta.as_str());
            }
            EventMsg::AgentReasoningRawContentDelta(ev) => {
                info.update_reasoning_summary(ev.delta.as_str());
            }
            EventMsg::AgentReasoningRawContent(ev) => {
                info.update_reasoning_summary(ev.text.as_str());
                info.reasoning_buffer.clear();
            }
            EventMsg::AgentReasoning(_) => {
                info.reasoning_buffer.clear();
            }
            EventMsg::AgentReasoningSectionBreak(_) => {
                info.reasoning_buffer.clear();
            }
            EventMsg::AgentMessageDelta(AgentMessageDeltaEvent { delta }) => {
                info.inflight_message.push_str(delta);
                let preview =
                    truncate_text(info.inflight_message.trim(), SUBAGENT_UPDATE_PREVIEW_BUDGET);
                info.update_preview(preview);
            }
            EventMsg::AgentMessage(AgentMessageEvent { message, .. }) => {
                info.inflight_message.clear();
                let preview = truncate_text(message.trim(), SUBAGENT_UPDATE_PREVIEW_BUDGET);
                info.update_preview(preview);
            }
            EventMsg::TurnComplete(TurnCompleteEvent {
                last_agent_message, ..
            }) => {
                info.inflight_message.clear();
                info.status = AgentStatus::Completed(last_agent_message.clone());
                if !info.notified_terminal {
                    info.notified_terminal = true;
                    let summary = last_agent_message
                        .as_deref()
                        .map(str::trim)
                        .filter(|message| !message.is_empty())
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "completed".to_string());
                    let label = info.label();
                    history.push(Box::new(new_subagent_update_cell(
                        &label,
                        &info.status,
                        summary.as_str(),
                        info.update_level(),
                    )) as Box<dyn HistoryCell>);
                }
            }
            EventMsg::TurnAborted(TurnAbortedEvent { reason, .. }) => {
                info.inflight_message.clear();
                let reason_text = format!("{reason:?}").to_lowercase();
                let interrupted = matches!(
                    reason,
                    codex_protocol::protocol::TurnAbortReason::Interrupted
                );
                info.status = if interrupted {
                    AgentStatus::Interrupted
                } else {
                    AgentStatus::Errored(reason_text.clone())
                };
                if interrupted || !info.notified_terminal {
                    if !interrupted {
                        info.notified_terminal = true;
                    }
                    let label = info.label();
                    history.push(Box::new(new_subagent_update_cell(
                        &label,
                        &info.status,
                        reason_text.as_str(),
                        info.update_level(),
                    )) as Box<dyn HistoryCell>);
                }
            }
            EventMsg::Error(ErrorEvent { message, .. }) => {
                info.inflight_message.clear();
                let summary = message.trim();
                let summary = if summary.is_empty() {
                    "errored".to_string()
                } else {
                    summary.to_string()
                };
                info.status = AgentStatus::Errored(summary.clone());
                if !info.notified_terminal {
                    info.notified_terminal = true;
                    let label = info.label();
                    history.push(Box::new(new_subagent_update_cell(
                        &label,
                        &info.status,
                        summary.as_str(),
                        info.update_level(),
                    )) as Box<dyn HistoryCell>);
                }
            }
            EventMsg::ShutdownComplete => {
                info.inflight_message.clear();
                info.status = AgentStatus::Shutdown;
                if !info.notified_terminal {
                    info.notified_terminal = true;
                    let label = info.label();
                    history.push(Box::new(new_subagent_update_cell(
                        &label,
                        &info.status,
                        "shutdown",
                        info.update_level(),
                    )) as Box<dyn HistoryCell>);
                }
            }
            _ => {}
        }

        if history.is_empty() && matches!(msg, EventMsg::TurnStarted(_)) {
            info.latest_update_at = Instant::now();
        }

        history
    }

    pub(crate) fn buffer_pending_event(&mut self, thread_id: ThreadId, msg: EventMsg) {
        if self.is_root_thread(thread_id) {
            return;
        }
        let entry = self.pending_events.entry(thread_id).or_default();
        entry.push(msg);
        if entry.len() > SUBAGENT_PENDING_EVENT_CAPACITY {
            let excess = entry.len() - SUBAGENT_PENDING_EVENT_CAPACITY;
            entry.drain(0..excess);
        }
    }
}

fn terminal_close_status(status: &AgentStatus) -> AgentStatus {
    match status {
        AgentStatus::PendingInit | AgentStatus::Running | AgentStatus::Interrupted => {
            AgentStatus::Shutdown
        }
        other => other.clone(),
    }
}

fn is_terminal_status(status: &AgentStatus) -> bool {
    matches!(
        status,
        AgentStatus::Completed(_)
            | AgentStatus::Errored(_)
            | AgentStatus::Shutdown
            | AgentStatus::NotFound
    )
}

#[derive(Clone, Debug)]
pub(crate) struct SubagentPanelAgent {
    pub(crate) ordinal: i32,
    pub(crate) name: String,
    pub(crate) status: AgentStatus,
    pub(crate) is_watchdog: bool,
    pub(crate) preview: String,
    pub(crate) latest_update_at: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct SubagentPanelState {
    pub(crate) started_at: Instant,
    pub(crate) total_agents: i32,
    pub(crate) running_count: i32,
    pub(crate) running_agents: Vec<SubagentPanelAgent>,
}

impl SubagentPanelState {
    pub(crate) fn running_count(&self) -> i32 {
        self.running_count
    }

    pub(crate) fn has_animating_agents(&self, now: Instant) -> bool {
        self.running_agents
            .iter()
            .any(|agent| should_shimmer(agent, now))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SubagentStatusCell {
    state: Arc<Mutex<SubagentPanelState>>,
    animations_enabled: bool,
}

impl SubagentStatusCell {
    pub(crate) fn new(
        state: Arc<Mutex<SubagentPanelState>>,
        animations_enabled: bool,
    ) -> SubagentStatusCell {
        SubagentStatusCell {
            state,
            animations_enabled,
        }
    }

    pub(crate) fn state_handle(&self) -> Arc<Mutex<SubagentPanelState>> {
        Arc::clone(&self.state)
    }

    pub(crate) fn matches_state(&self, other: &Arc<Mutex<SubagentPanelState>>) -> bool {
        Arc::ptr_eq(&self.state, other)
    }
}

impl HistoryCell for SubagentStatusCell {
    fn display_lines(&self, width: u16) -> Vec<Line<'static>> {
        let state = {
            let guard = match self.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.clone()
        };
        if state.running_agents.is_empty() {
            return Vec::new();
        }

        let elapsed = fmt_elapsed_compact(state.started_at.elapsed().as_secs());
        let running_count = state.running_count();
        let total_agents = state.total_agents.max(running_count);
        let count_label = subagent_count_label(total_agents, running_count);
        let header_suffix = format!("({elapsed} • {count_label} • esc to interrupt)");

        let mut lines = Vec::new();
        lines.push(Line::from(vec![
            "• ".dim(),
            "Subagents".bold(),
            " ".into(),
            header_suffix.dim(),
        ]));

        let mut running_agents = state.running_agents;
        running_agents.sort_by_key(|left| left.ordinal);
        let preview_budget = running_preview_budget(width);
        let now = Instant::now();
        lines.extend(running_agents.into_iter().map(|agent| {
            let preview = truncate_text(agent.preview.trim(), preview_budget);
            let mut spans: Vec<Span<'static>> =
                vec!["• ".dim(), format!("[#{}] ", agent.ordinal).dim()];
            spans.push(Span::from(agent.name.clone()));
            spans.push(" ".into());
            spans.push(status_span_for_panel(&agent));
            spans.push(" — ".dim());
            if self.animations_enabled && should_shimmer(&agent, now) {
                spans.extend(shimmer_spans(&preview));
            } else {
                spans.push(Span::from(preview));
            }
            Line::from(spans)
        }));

        lines
    }

    fn transcript_animation_tick(&self) -> Option<u64> {
        if !self.animations_enabled {
            return None;
        }
        let guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        if !guard.has_animating_agents(now) {
            return None;
        }
        Some((now.duration_since(guard.started_at).as_millis() / 100) as u64)
    }
}

fn running_preview_budget(width: u16) -> usize {
    let width = width as usize;
    width.saturating_sub(24).clamp(60, 160)
}

fn is_running_status(status: &AgentStatus) -> bool {
    matches!(status, AgentStatus::PendingInit | AgentStatus::Running)
}

fn status_span_for_panel(agent: &SubagentPanelAgent) -> Span<'static> {
    match &agent.status {
        AgentStatus::PendingInit if agent.is_watchdog => "idle".dim(),
        AgentStatus::PendingInit | AgentStatus::Running => "running".cyan().bold(),
        AgentStatus::Interrupted => "interrupted".magenta(),
        AgentStatus::Completed(_) => "completed".green(),
        AgentStatus::Errored(_) => "errored".red(),
        AgentStatus::Shutdown => "shutdown".dim(),
        AgentStatus::NotFound => "not found".red(),
    }
}

fn should_shimmer(agent: &SubagentPanelAgent, now: Instant) -> bool {
    if agent.is_watchdog && matches!(agent.status, AgentStatus::PendingInit) {
        return false;
    }
    is_running_status(&agent.status)
        && now.saturating_duration_since(agent.latest_update_at) <= SUBAGENT_SHIMMER_WINDOW
}

fn subagent_count_label(total: i32, running: i32) -> String {
    if total <= 0 || running <= 0 {
        return "no subagents running".to_string();
    }
    let total_label = subagent_pluralize(total, "subagent");
    if running >= total {
        return format!("{total_label} running");
    }
    format!("{total_label}, {running} running")
}

fn subagent_pluralize(count: i32, singular: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {singular}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn cell_to_text(cell: &dyn HistoryCell) -> String {
        cell.display_lines(200)
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn interrupted_abort_marks_subagent_interrupted_and_emits_history() {
        let mut registry = SubagentRegistry::new(false);
        let root_thread_id = ThreadId::new();
        let subagent_thread_id = ThreadId::new();
        registry.set_root_thread(root_thread_id);

        let spawned = registry.process_event(
            root_thread_id,
            Some(root_thread_id),
            &Event {
                id: "spawn".to_string(),
                msg: EventMsg::CollabAgentSpawnEnd(CollabAgentSpawnEndEvent {
                    call_id: "call-spawn".to_string(),
                    sender_thread_id: root_thread_id,
                    new_thread_id: Some(subagent_thread_id),
                    new_agent_nickname: Some("Closer".to_string()),
                    new_agent_role: Some("worker".to_string()),
                    prompt: "interrupt me".to_string(),
                    model: String::new(),
                    reasoning_effort: Default::default(),
                    spawn_mode: AgentSpawnMode::Spawn,
                    status: AgentStatus::Running,
                }),
            },
        );
        assert!(spawned.is_empty());

        let history = registry.process_event(
            subagent_thread_id,
            Some(root_thread_id),
            &Event {
                id: "aborted".to_string(),
                msg: EventMsg::TurnAborted(TurnAbortedEvent {
                    turn_id: None,
                    reason: codex_protocol::protocol::TurnAbortReason::Interrupted,
                }),
            },
        );
        assert_eq!(history.len(), 1);
        assert_eq!(
            registry
                .agents
                .get(&subagent_thread_id)
                .expect("subagent should still be tracked")
                .status,
            AgentStatus::Interrupted
        );
        assert!(
            cell_to_text(history[0].as_ref())
                .contains("Subagent update: Closer [worker] interrupted"),
            "interrupted abort should render interrupted summary"
        );
        assert!(
            !registry
                .agents
                .get(&subagent_thread_id)
                .expect("subagent should still be tracked")
                .notified_terminal,
            "interrupted abort should not mark the agent terminal"
        );
    }

    #[test]
    fn interrupted_abort_can_resume_and_emit_terminal_history() {
        let mut registry = SubagentRegistry::new(false);
        let root_thread_id = ThreadId::new();
        let subagent_thread_id = ThreadId::new();
        registry.set_root_thread(root_thread_id);

        let spawned = registry.process_event(
            root_thread_id,
            Some(root_thread_id),
            &Event {
                id: "spawn".to_string(),
                msg: EventMsg::CollabAgentSpawnEnd(CollabAgentSpawnEndEvent {
                    call_id: "call-spawn".to_string(),
                    sender_thread_id: root_thread_id,
                    new_thread_id: Some(subagent_thread_id),
                    new_agent_nickname: Some("Closer".to_string()),
                    new_agent_role: Some("worker".to_string()),
                    prompt: "interrupt me".to_string(),
                    model: String::new(),
                    reasoning_effort: Default::default(),
                    spawn_mode: AgentSpawnMode::Spawn,
                    status: AgentStatus::Running,
                }),
            },
        );
        assert!(spawned.is_empty());

        let interrupted = registry.process_event(
            subagent_thread_id,
            Some(root_thread_id),
            &Event {
                id: "aborted".to_string(),
                msg: EventMsg::TurnAborted(TurnAbortedEvent {
                    turn_id: None,
                    reason: codex_protocol::protocol::TurnAbortReason::Interrupted,
                }),
            },
        );
        assert_eq!(interrupted.len(), 1);

        let restarted = registry.process_event(
            subagent_thread_id,
            Some(root_thread_id),
            &Event {
                id: "started".to_string(),
                msg: EventMsg::TurnStarted(TurnStartedEvent {
                    turn_id: "turn-2".to_string(),
                    model_context_window: None,
                    collaboration_mode_kind: Default::default(),
                }),
            },
        );
        assert!(restarted.is_empty());

        let completed = registry.process_event(
            subagent_thread_id,
            Some(root_thread_id),
            &Event {
                id: "completed".to_string(),
                msg: EventMsg::TurnComplete(TurnCompleteEvent {
                    turn_id: "turn-2".to_string(),
                    last_agent_message: Some("finished after resume".to_string()),
                }),
            },
        );
        assert_eq!(completed.len(), 1);
        assert!(
            cell_to_text(completed[0].as_ref())
                .contains("Subagent update: Closer [worker] completed"),
            "resumed completion should still emit its terminal completion cell"
        );
        let info = registry
            .agents
            .get(&subagent_thread_id)
            .expect("subagent should still be tracked");
        assert_eq!(
            info.status,
            AgentStatus::Completed(Some("finished after resume".to_string()))
        );
        assert!(info.notified_terminal);
    }
}
