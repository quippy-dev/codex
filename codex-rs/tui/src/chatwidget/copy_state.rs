use std::fmt;

use codex_protocol::protocol::ReviewOutputEvent;

const COPY_UNAVAILABLE_MESSAGE: &str =
    "`/copy` is unavailable before the first Codex output or right after a rollback.";
const COPY_RUNNING_HINT: &str = "Current turn is still running; copied the latest completed output (not the in-progress response).";

#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct CopyState {
    latest_visible_output: Option<String>,
}

impl CopyState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record_plan_output(&mut self, plan_text: &str) {
        self.record_if_non_empty(plan_text);
    }

    pub(crate) fn record_agent_output(&mut self, message: Option<&str>) {
        if let Some(message) = message {
            self.record_if_non_empty(message);
        }
    }

    pub(crate) fn record_review_output(&mut self, review_output: &ReviewOutputEvent) {
        self.latest_visible_output = Some(codex_core::review_format::render_review_output_text(
            review_output,
        ));
    }

    pub(crate) fn clear(&mut self) {
        self.latest_visible_output = None;
    }

    pub(crate) fn clear_on_rollback(&mut self) {
        self.clear();
    }

    pub(crate) fn latest_output(&self) -> Option<&str> {
        self.latest_visible_output.as_deref()
    }

    pub(crate) fn unavailable_message(&self) -> &'static str {
        COPY_UNAVAILABLE_MESSAGE
    }

    pub(crate) fn running_copy_hint(&self, agent_turn_running: bool) -> Option<String> {
        agent_turn_running.then(|| COPY_RUNNING_HINT.to_string())
    }

    fn record_if_non_empty(&mut self, text: &str) {
        if !text.trim().is_empty() {
            self.latest_visible_output = Some(text.to_string());
        }
    }
}

impl fmt::Debug for CopyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.latest_visible_output.fmt(f)
    }
}

impl PartialEq<Option<String>> for CopyState {
    fn eq(&self, other: &Option<String>) -> bool {
        self.latest_visible_output == *other
    }
}
