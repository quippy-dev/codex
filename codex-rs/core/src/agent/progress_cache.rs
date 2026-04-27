use codex_protocol::ThreadId;
use codex_protocol::protocol::EventMsg;
use tokio::sync::Mutex;

use std::collections::HashMap;

const MAX_PREVIEW_CHARS: usize = 180;
const MAX_CACHE_ENTRIES: usize = 4096;
const MAX_TEXT_BUFFER_CHARS: usize = 4096;
const MAX_TERMINAL_BUFFER_CHARS: usize = 4096;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AgentProgressSnapshot {
    pub(crate) cursor: u64,
    pub(crate) prompt_preview: Option<String>,
    pub(crate) reasoning_summary: Option<String>,
    pub(crate) latest_message_preview: Option<String>,
    pub(crate) terminal_summary: Option<String>,
}

#[derive(Default)]
pub(crate) struct AgentProgressCache {
    inner: Mutex<AgentProgressCacheState>,
}

#[derive(Default)]
struct AgentProgressCacheState {
    next_cursor: u64,
    entries: HashMap<ThreadId, AgentProgressEntry>,
}

#[derive(Default)]
struct AgentProgressEntry {
    snapshot: AgentProgressSnapshot,
    reasoning_buffer: String,
    latest_message_buffer: String,
    terminal_buffer: String,
    last_completed_turn_id: Option<String>,
    latest_message_stream: Option<MessageStreamKey>,
    active_exec_call_id: Option<String>,
    reasoning_section_key: Option<ReasoningSectionKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MessageStreamKey {
    turn_id: String,
    item_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReasoningSectionKey {
    item_id: String,
    summary_index: i64,
}

impl AgentProgressCache {
    pub(crate) async fn record_prompt_preview(&self, thread_id: ThreadId, prompt: &str) {
        let mut state = self.inner.lock().await;
        state.update(thread_id, |entry| {
            set_if_changed(
                &mut entry.snapshot.prompt_preview,
                compact_preview_head(prompt),
            )
        });
    }

    pub(crate) async fn observe_event(&self, thread_id: ThreadId, event: &EventMsg) {
        let mut state = self.inner.lock().await;
        match event {
            EventMsg::AgentReasoning(ev) => {
                state.update(thread_id, |entry| {
                    entry.reasoning_section_key = None;
                    replace_text_preview(
                        &mut entry.reasoning_buffer,
                        &mut entry.snapshot.reasoning_summary,
                        &ev.text,
                    )
                });
            }
            EventMsg::AgentReasoningDelta(ev) => {
                state.update(thread_id, |entry| {
                    append_text_preview(
                        &mut entry.reasoning_buffer,
                        &mut entry.snapshot.reasoning_summary,
                        &ev.delta,
                    )
                });
            }
            EventMsg::AgentMessage(ev) => {
                state.update(thread_id, |entry| {
                    entry.latest_message_stream = None;
                    replace_text_preview(
                        &mut entry.latest_message_buffer,
                        &mut entry.snapshot.latest_message_preview,
                        &ev.message,
                    )
                });
            }
            EventMsg::TurnComplete(ev) => {
                state.update(thread_id, |entry| {
                    let mut changed = false;
                    if entry.last_completed_turn_id.as_deref() != Some(ev.turn_id.as_str()) {
                        entry.last_completed_turn_id = Some(ev.turn_id.clone());
                        changed = true;
                    }
                    if let Some(last_message) = ev.last_agent_message.as_deref() {
                        entry.latest_message_stream = None;
                        changed |= replace_text_preview(
                            &mut entry.latest_message_buffer,
                            &mut entry.snapshot.latest_message_preview,
                            last_message,
                        );
                    }
                    changed
                });
            }
            EventMsg::TurnStarted(_) => {
                state.update(thread_id, clear_turn_scoped_progress);
            }
            EventMsg::AgentReasoningSectionBreak(ev) => {
                state.update(thread_id, |entry| {
                    let replacement = Some(ReasoningSectionKey {
                        item_id: ev.item_id.clone(),
                        summary_index: ev.summary_index,
                    });
                    if entry.reasoning_section_key == replacement {
                        return false;
                    }
                    entry.reasoning_section_key = replacement;
                    clear_preview_and_buffer(
                        &mut entry.reasoning_buffer,
                        &mut entry.snapshot.reasoning_summary,
                    )
                });
            }
            EventMsg::AgentMessageContentDelta(ev) => {
                state.update(thread_id, |entry| {
                    let stream = MessageStreamKey {
                        turn_id: ev.turn_id.clone(),
                        item_id: ev.item_id.clone(),
                    };
                    if entry.latest_message_stream.as_ref() != Some(&stream) {
                        entry.latest_message_stream = Some(stream);
                        clear_preview_and_buffer(
                            &mut entry.latest_message_buffer,
                            &mut entry.snapshot.latest_message_preview,
                        );
                    }
                    append_text_preview(
                        &mut entry.latest_message_buffer,
                        &mut entry.snapshot.latest_message_preview,
                        &ev.delta,
                    )
                });
            }
            EventMsg::ExecCommandBegin(ev) => {
                state.update(thread_id, |entry| {
                    let mut changed = false;
                    if entry.active_exec_call_id.as_deref() != Some(ev.call_id.as_str()) {
                        entry.active_exec_call_id = Some(ev.call_id.clone());
                        changed = true;
                    }
                    changed |= clear_preview_and_buffer(
                        &mut entry.terminal_buffer,
                        &mut entry.snapshot.terminal_summary,
                    );
                    changed
                });
            }
            EventMsg::ExecCommandOutputDelta(ev) => {
                let output = String::from_utf8_lossy(&ev.chunk);
                state.update(thread_id, |entry| {
                    if entry.active_exec_call_id.as_deref() != Some(ev.call_id.as_str()) {
                        entry.active_exec_call_id = Some(ev.call_id.clone());
                        clear_preview_and_buffer(
                            &mut entry.terminal_buffer,
                            &mut entry.snapshot.terminal_summary,
                        );
                    }
                    append_terminal_preview(
                        &mut entry.terminal_buffer,
                        &mut entry.snapshot.terminal_summary,
                        &output,
                    )
                });
            }
            EventMsg::ExecCommandEnd(ev) => {
                if let Some(summary) = exec_terminal_summary(ev) {
                    state.update(thread_id, |entry| {
                        entry.active_exec_call_id = Some(ev.call_id.clone());
                        replace_terminal_preview(
                            &mut entry.terminal_buffer,
                            &mut entry.snapshot.terminal_summary,
                            &summary,
                        )
                    });
                }
            }
            EventMsg::TerminalInteraction(ev) => {
                state.update(thread_id, |entry| {
                    append_terminal_preview(
                        &mut entry.terminal_buffer,
                        &mut entry.snapshot.terminal_summary,
                        &format!("stdin: {}", ev.stdin),
                    )
                });
            }
            _ => {}
        }
    }

    pub(crate) async fn snapshots(
        &self,
        thread_ids: &[ThreadId],
    ) -> HashMap<ThreadId, AgentProgressSnapshot> {
        let state = self.inner.lock().await;
        thread_ids
            .iter()
            .filter_map(|thread_id| {
                state
                    .entries
                    .get(thread_id)
                    .map(|entry| entry.snapshot.clone())
                    .map(|snapshot| (*thread_id, snapshot))
            })
            .collect()
    }
}

impl AgentProgressCacheState {
    fn update<F>(&mut self, thread_id: ThreadId, mutator: F)
    where
        F: FnOnce(&mut AgentProgressEntry) -> bool,
    {
        let entry = self.entries.entry(thread_id).or_default();
        if !mutator(entry) {
            return;
        }
        self.next_cursor = self.next_cursor.saturating_add(1).max(1);
        entry.snapshot.cursor = self.next_cursor;
        self.trim_if_needed();
    }

    fn trim_if_needed(&mut self) {
        if self.entries.len() <= MAX_CACHE_ENTRIES {
            return;
        }
        let remove_count = self.entries.len() - MAX_CACHE_ENTRIES;
        let mut by_cursor = self
            .entries
            .iter()
            .map(|(thread_id, entry)| (*thread_id, entry.snapshot.cursor))
            .collect::<Vec<_>>();
        by_cursor.sort_by_key(|(thread_id, cursor)| (*cursor, thread_id.to_string()));
        for (thread_id, _) in by_cursor.into_iter().take(remove_count) {
            self.entries.remove(&thread_id);
        }
    }
}

fn set_if_changed(target: &mut Option<String>, replacement: Option<String>) -> bool {
    if *target == replacement {
        return false;
    }
    *target = replacement;
    true
}

fn replace_text_preview(buffer: &mut String, target: &mut Option<String>, raw: &str) -> bool {
    let replacement = truncate_chars(raw, MAX_TEXT_BUFFER_CHARS, /*keep_tail*/ false);
    if replacement == *buffer {
        return false;
    }
    *buffer = replacement;
    set_if_changed(target, compact_preview_head(buffer))
}

fn clear_preview_and_buffer(buffer: &mut String, target: &mut Option<String>) -> bool {
    let had_any = !buffer.is_empty() || target.is_some();
    buffer.clear();
    if target.is_some() {
        *target = None;
    }
    had_any
}

fn clear_turn_scoped_progress(entry: &mut AgentProgressEntry) -> bool {
    let mut changed = false;
    changed |= clear_preview_and_buffer(
        &mut entry.reasoning_buffer,
        &mut entry.snapshot.reasoning_summary,
    );
    changed |= clear_preview_and_buffer(
        &mut entry.latest_message_buffer,
        &mut entry.snapshot.latest_message_preview,
    );
    changed |= clear_preview_and_buffer(
        &mut entry.terminal_buffer,
        &mut entry.snapshot.terminal_summary,
    );
    if entry.latest_message_stream.take().is_some() {
        changed = true;
    }
    if entry.active_exec_call_id.take().is_some() {
        changed = true;
    }
    if entry.reasoning_section_key.take().is_some() {
        changed = true;
    }
    changed
}

fn append_text_preview(buffer: &mut String, target: &mut Option<String>, delta: &str) -> bool {
    if delta.is_empty() {
        return false;
    }
    append_with_limit(
        buffer,
        delta,
        MAX_TEXT_BUFFER_CHARS,
        /*keep_tail*/ false,
    );
    set_if_changed(target, compact_preview_head(buffer))
}

fn replace_terminal_preview(buffer: &mut String, target: &mut Option<String>, raw: &str) -> bool {
    let replacement = truncate_chars(raw, MAX_TERMINAL_BUFFER_CHARS, /*keep_tail*/ true);
    if replacement == *buffer {
        return false;
    }
    *buffer = replacement;
    set_if_changed(target, compact_preview_tail(buffer))
}

fn append_terminal_preview(buffer: &mut String, target: &mut Option<String>, delta: &str) -> bool {
    if delta.is_empty() {
        return false;
    }
    append_with_limit(
        buffer,
        delta,
        MAX_TERMINAL_BUFFER_CHARS,
        /*keep_tail*/ true,
    );
    set_if_changed(target, compact_preview_tail(buffer))
}

fn compact_preview_head(raw: &str) -> Option<String> {
    let compact = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = compact.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut chars = trimmed.chars();
    let preview = chars.by_ref().take(MAX_PREVIEW_CHARS).collect::<String>();
    if chars.next().is_some() {
        Some(format!("{preview}..."))
    } else {
        Some(preview)
    }
}

fn compact_preview_tail(raw: &str) -> Option<String> {
    let compact = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = compact.trim();
    if trimmed.is_empty() {
        return None;
    }
    let chars = trimmed.chars().collect::<Vec<_>>();
    let char_len = chars.len();
    if char_len <= MAX_PREVIEW_CHARS {
        return Some(chars.into_iter().collect());
    }
    let tail_len = MAX_PREVIEW_CHARS.saturating_sub(3);
    let tail = chars
        .into_iter()
        .skip(char_len.saturating_sub(tail_len))
        .collect::<String>();
    Some(format!("...{tail}"))
}

fn append_with_limit(buffer: &mut String, delta: &str, max_chars: usize, keep_tail: bool) {
    buffer.push_str(delta);
    let count = buffer.chars().count();
    if count <= max_chars {
        return;
    }
    *buffer = if keep_tail {
        buffer
            .chars()
            .skip(count.saturating_sub(max_chars))
            .collect::<String>()
    } else {
        buffer.chars().take(max_chars).collect::<String>()
    };
}

fn truncate_chars(raw: &str, max_chars: usize, keep_tail: bool) -> String {
    let count = raw.chars().count();
    if count <= max_chars {
        return raw.to_string();
    }
    if keep_tail {
        raw.chars()
            .skip(count.saturating_sub(max_chars))
            .collect::<String>()
    } else {
        raw.chars().take(max_chars).collect::<String>()
    }
}

fn exec_terminal_summary(event: &codex_protocol::protocol::ExecCommandEndEvent) -> Option<String> {
    let body = [
        event.formatted_output.as_str(),
        event.aggregated_output.as_str(),
        event.stdout.as_str(),
        event.stderr.as_str(),
    ]
    .into_iter()
    .find(|text| !text.trim().is_empty())
    .map(|text| text.to_string());
    let summary = match body {
        Some(body) => format!("exit {}: {body}", event.exit_code),
        None => format!("exit {}", event.exit_code),
    };
    compact_preview_tail(&summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_protocol::config_types::ModeKind;
    use codex_protocol::protocol::AgentMessageContentDeltaEvent;
    use codex_protocol::protocol::AgentMessageEvent;
    use codex_protocol::protocol::AgentReasoningDeltaEvent;
    use codex_protocol::protocol::AgentReasoningSectionBreakEvent;
    use codex_protocol::protocol::EventMsg;
    use codex_protocol::protocol::ExecCommandBeginEvent;
    use codex_protocol::protocol::ExecCommandEndEvent;
    use codex_protocol::protocol::ExecCommandOutputDeltaEvent;
    use codex_protocol::protocol::ExecCommandSource;
    use codex_protocol::protocol::ExecCommandStatus;
    use codex_protocol::protocol::ExecOutputStream;
    use codex_protocol::protocol::TurnCompleteEvent;
    use codex_protocol::protocol::TurnStartedEvent;
    use codex_utils_absolute_path::AbsolutePathBuf;
    use std::path::PathBuf;
    use std::time::Duration;

    #[tokio::test]
    async fn record_prompt_preview_compacts_whitespace_and_sets_cursor() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        cache
            .record_prompt_preview(thread_id, "  hello\n\nworld  ")
            .await;
        let snapshots = cache.snapshots(&[thread_id]).await;
        let snapshot = snapshots.get(&thread_id).expect("snapshot should exist");
        assert_eq!(snapshot.prompt_preview.as_deref(), Some("hello world"));
        assert_eq!(snapshot.cursor, 1);
    }

    #[tokio::test]
    async fn observe_event_accumulates_reasoning_and_message_deltas() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentReasoningDelta(AgentReasoningDeltaEvent {
                    delta: "considering ".to_string(),
                }),
            )
            .await;
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentReasoningDelta(AgentReasoningDeltaEvent {
                    delta: "options".to_string(),
                }),
            )
            .await;
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentMessageContentDelta(AgentMessageContentDeltaEvent {
                    thread_id: "thread".to_string(),
                    turn_id: "turn-1".to_string(),
                    item_id: "msg".to_string(),
                    delta: "work".to_string(),
                }),
            )
            .await;
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentMessageContentDelta(AgentMessageContentDeltaEvent {
                    thread_id: "thread".to_string(),
                    turn_id: "turn-1".to_string(),
                    item_id: "msg".to_string(),
                    delta: "ing".to_string(),
                }),
            )
            .await;

        let snapshots = cache.snapshots(&[thread_id]).await;
        let snapshot = snapshots.get(&thread_id).expect("snapshot should exist");
        assert_eq!(
            snapshot.reasoning_summary.as_deref(),
            Some("considering options")
        );
        assert_eq!(snapshot.latest_message_preview.as_deref(), Some("working"));
        assert_eq!(snapshot.cursor, 4);
    }

    #[tokio::test]
    async fn observe_event_updates_live_terminal_preview_from_exec_output_delta() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        cache
            .observe_event(
                thread_id,
                &EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
                    call_id: "call".to_string(),
                    stream: ExecOutputStream::Stdout,
                    chunk: "start".as_bytes().to_vec(),
                }),
            )
            .await;
        cache
            .observe_event(
                thread_id,
                &EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
                    call_id: "call".to_string(),
                    stream: ExecOutputStream::Stdout,
                    chunk: " -> finish".as_bytes().to_vec(),
                }),
            )
            .await;

        let snapshots = cache.snapshots(&[thread_id]).await;
        let snapshot = snapshots.get(&thread_id).expect("snapshot should exist");
        assert_eq!(
            snapshot.terminal_summary.as_deref(),
            Some("start -> finish")
        );
        assert_eq!(snapshot.cursor, 2);
    }

    #[tokio::test]
    async fn turn_started_clears_stale_turn_scoped_previews() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentReasoningDelta(AgentReasoningDeltaEvent {
                    delta: "thinking".to_string(),
                }),
            )
            .await;
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentMessageContentDelta(AgentMessageContentDeltaEvent {
                    thread_id: "thread".to_string(),
                    turn_id: "turn-1".to_string(),
                    item_id: "msg-1".to_string(),
                    delta: "draft".to_string(),
                }),
            )
            .await;
        cache
            .observe_event(
                thread_id,
                &EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
                    call_id: "call-1".to_string(),
                    stream: ExecOutputStream::Stdout,
                    chunk: b"running".to_vec(),
                }),
            )
            .await;

        cache
            .observe_event(
                thread_id,
                &EventMsg::TurnStarted(TurnStartedEvent {
                    turn_id: "turn-2".to_string(),
                    started_at: None,
                    model_context_window: None,
                    collaboration_mode_kind: ModeKind::Default,
                }),
            )
            .await;

        let snapshot = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .clone();
        assert_eq!(snapshot.reasoning_summary, None);
        assert_eq!(snapshot.latest_message_preview, None);
        assert_eq!(snapshot.terminal_summary, None);
        assert_eq!(snapshot.cursor, 4);
    }

    #[tokio::test]
    async fn quiet_turn_complete_advances_cursor_once_per_turn() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        cache.record_prompt_preview(thread_id, "task").await;
        let before = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .cursor;

        cache
            .observe_event(
                thread_id,
                &EventMsg::TurnComplete(TurnCompleteEvent {
                    turn_id: "turn-1".to_string(),
                    last_agent_message: None,
                    completed_at: None,
                    duration_ms: None,
                    time_to_first_token_ms: None,
                }),
            )
            .await;
        let after_first = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .cursor;

        cache
            .observe_event(
                thread_id,
                &EventMsg::TurnComplete(TurnCompleteEvent {
                    turn_id: "turn-1".to_string(),
                    last_agent_message: None,
                    completed_at: None,
                    duration_ms: None,
                    time_to_first_token_ms: None,
                }),
            )
            .await;
        let after_duplicate = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .cursor;

        assert!(after_first > before);
        assert_eq!(after_duplicate, after_first);
    }

    #[tokio::test]
    async fn message_deltas_reset_when_stream_item_changes() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentMessageContentDelta(AgentMessageContentDeltaEvent {
                    thread_id: "thread".to_string(),
                    turn_id: "turn-1".to_string(),
                    item_id: "msg-1".to_string(),
                    delta: "first".to_string(),
                }),
            )
            .await;
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentMessageContentDelta(AgentMessageContentDeltaEvent {
                    thread_id: "thread".to_string(),
                    turn_id: "turn-1".to_string(),
                    item_id: "msg-2".to_string(),
                    delta: "second".to_string(),
                }),
            )
            .await;

        let snapshot = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .clone();
        assert_eq!(snapshot.latest_message_preview.as_deref(), Some("second"));
    }

    #[tokio::test]
    async fn reasoning_section_break_resets_accumulated_preview() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentReasoningDelta(AgentReasoningDeltaEvent {
                    delta: "old section".to_string(),
                }),
            )
            .await;
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentReasoningSectionBreak(AgentReasoningSectionBreakEvent {
                    item_id: "item-2".to_string(),
                    summary_index: 2,
                }),
            )
            .await;
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentReasoningDelta(AgentReasoningDeltaEvent {
                    delta: "new section".to_string(),
                }),
            )
            .await;

        let snapshot = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .clone();
        assert_eq!(snapshot.reasoning_summary.as_deref(), Some("new section"));
    }

    #[tokio::test]
    async fn terminal_preview_keeps_recent_tail_and_updates_cursor() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        let large = "x".repeat(MAX_PREVIEW_CHARS + 40);
        cache
            .observe_event(
                thread_id,
                &EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
                    call_id: "call".to_string(),
                    stream: ExecOutputStream::Stderr,
                    chunk: large.into_bytes(),
                }),
            )
            .await;
        let first_snapshot = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .clone();
        assert!(
            first_snapshot
                .terminal_summary
                .as_deref()
                .is_some_and(|summary| summary.starts_with("..."))
        );

        cache
            .observe_event(
                thread_id,
                &EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
                    call_id: "call".to_string(),
                    stream: ExecOutputStream::Stderr,
                    chunk: "TAIL".as_bytes().to_vec(),
                }),
            )
            .await;

        let second_snapshot = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .clone();
        assert!(
            second_snapshot
                .terminal_summary
                .as_deref()
                .is_some_and(|summary| summary.ends_with("TAIL"))
        );
        assert!(second_snapshot.cursor > first_snapshot.cursor);
    }

    #[tokio::test]
    async fn exec_output_delta_resets_buffer_when_call_id_changes() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        cache
            .observe_event(
                thread_id,
                &EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
                    call_id: "call-1".to_string(),
                    stream: ExecOutputStream::Stdout,
                    chunk: b"old-call".to_vec(),
                }),
            )
            .await;
        cache
            .observe_event(
                thread_id,
                &EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
                    call_id: "call-2".to_string(),
                    stream: ExecOutputStream::Stdout,
                    chunk: b"new-call".to_vec(),
                }),
            )
            .await;

        let snapshot = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .clone();
        assert_eq!(snapshot.terminal_summary.as_deref(), Some("new-call"));
    }

    #[tokio::test]
    async fn exec_begin_clears_terminal_preview_before_first_output_delta() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        cache
            .observe_event(
                thread_id,
                &EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
                    call_id: "call-1".to_string(),
                    stream: ExecOutputStream::Stdout,
                    chunk: b"old-call".to_vec(),
                }),
            )
            .await;
        let first_cursor = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .cursor;

        cache
            .observe_event(
                thread_id,
                &EventMsg::ExecCommandBegin(ExecCommandBeginEvent {
                    call_id: "call-2".to_string(),
                    process_id: None,
                    turn_id: "turn".to_string(),
                    command: vec!["sleep".to_string(), "1".to_string()],
                    cwd: AbsolutePathBuf::try_from(PathBuf::from("/tmp")).expect("absolute path"),
                    parsed_cmd: vec![],
                    source: ExecCommandSource::Agent,
                    interaction_input: None,
                }),
            )
            .await;

        let snapshot = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .clone();
        assert_eq!(snapshot.terminal_summary, None);
        assert!(snapshot.cursor > first_cursor);
    }

    #[tokio::test]
    async fn observe_event_updates_compact_terminal_summary_on_exec_end() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        cache
            .observe_event(
                thread_id,
                &EventMsg::AgentMessage(AgentMessageEvent {
                    message: "done".to_string(),
                    phase: None,
                    memory_citation: None,
                }),
            )
            .await;
        cache
            .observe_event(
                thread_id,
                &EventMsg::ExecCommandEnd(ExecCommandEndEvent {
                    call_id: "call".to_string(),
                    process_id: None,
                    turn_id: "turn".to_string(),
                    command: vec!["echo".to_string()],
                    cwd: AbsolutePathBuf::try_from(PathBuf::from("/tmp")).expect("absolute path"),
                    parsed_cmd: vec![],
                    source: ExecCommandSource::Agent,
                    interaction_input: None,
                    stdout: "hello".to_string(),
                    stderr: String::new(),
                    aggregated_output: "hello".to_string(),
                    exit_code: 0,
                    duration: Duration::from_millis(5),
                    formatted_output: "hello".to_string(),
                    status: ExecCommandStatus::Completed,
                }),
            )
            .await;

        let snapshots = cache.snapshots(&[thread_id]).await;
        let snapshot = snapshots.get(&thread_id).expect("snapshot should exist");
        assert_eq!(snapshot.latest_message_preview.as_deref(), Some("done"));
        assert_eq!(snapshot.terminal_summary.as_deref(), Some("exit 0: hello"));
        assert_eq!(snapshot.cursor, 2);
    }

    #[tokio::test]
    async fn duplicate_event_payload_does_not_advance_cursor() {
        let cache = AgentProgressCache::default();
        let thread_id = ThreadId::new();
        let event = EventMsg::AgentMessage(AgentMessageEvent {
            message: "same".to_string(),
            phase: None,
            memory_citation: None,
        });
        cache.observe_event(thread_id, &event).await;
        let first_cursor = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .cursor;

        cache.observe_event(thread_id, &event).await;
        let second_cursor = cache
            .snapshots(&[thread_id])
            .await
            .get(&thread_id)
            .expect("snapshot should exist")
            .cursor;

        assert_eq!(first_cursor, second_cursor);
    }
}
