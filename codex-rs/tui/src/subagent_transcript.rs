use crate::text_formatting::truncate_text;
use codex_protocol::protocol::AgentStatus;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;

pub(crate) const SUBAGENT_PROMPT_PREVIEW_BUDGET: usize = 120;
pub(crate) const SUBAGENT_UPDATE_PREVIEW_BUDGET: usize = 160;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubagentUpdateLevel {
    Root,
    Nested,
}

pub(crate) fn subagent_spawned_lines(name: &str, prompt_preview: &str) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        "• ".dim(),
        "Spawned subagent ".into(),
        Span::from(name.to_string()).bold(),
    ]));

    let preview = truncate_text(prompt_preview.trim(), 240);
    if !preview.is_empty() {
        lines.push(Line::from(vec![
            "  └ ".dim(),
            Span::from(format!("\"{preview}\"")).dim(),
        ]));
    }

    lines
}

pub(crate) fn subagent_update_lines(
    name: &str,
    status: &AgentStatus,
    summary: &str,
    update_level: SubagentUpdateLevel,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        "• ".dim(),
        "Subagent update: ".into(),
        Span::from(name.to_string()).bold(),
        " ".into(),
        status_label_span(status),
    ])];

    let summary = truncate_text(
        &summary.split_whitespace().collect::<Vec<_>>().join(" "),
        240,
    );
    let should_suppress_summary = matches!(
        (status, update_level),
        (AgentStatus::Completed(_), SubagentUpdateLevel::Root)
    );
    if !summary.is_empty() && !should_suppress_summary {
        lines.push(Line::from(vec!["  └ ".dim(), summary.into()]));
    }

    lines
}

pub(crate) fn prompt_first_line(prompt: &str) -> String {
    prompt
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default()
        .to_string()
}

pub(crate) fn prompt_preview(prompt: &str) -> String {
    let first_line = prompt_first_line(prompt);
    truncate_text(first_line.trim(), SUBAGENT_PROMPT_PREVIEW_BUDGET)
}

pub(crate) fn running_preview(
    latest_summary: &str,
    inflight_message: &str,
    latest_preview: &str,
    prompt_preview: &str,
) -> String {
    if !latest_summary.trim().is_empty() {
        return truncate_text(latest_summary.trim(), SUBAGENT_UPDATE_PREVIEW_BUDGET);
    }
    if !inflight_message.trim().is_empty() {
        return truncate_text(inflight_message.trim(), SUBAGENT_UPDATE_PREVIEW_BUDGET);
    }
    if !latest_preview.trim().is_empty() {
        return truncate_text(latest_preview.trim(), SUBAGENT_UPDATE_PREVIEW_BUDGET);
    }
    truncate_text(prompt_preview.trim(), SUBAGENT_PROMPT_PREVIEW_BUDGET)
}

pub(crate) fn terminal_summary(status: &AgentStatus) -> String {
    match status {
        AgentStatus::Completed(Some(message)) => {
            let message = message.trim();
            if message.is_empty() {
                "completed".to_string()
            } else {
                message.to_string()
            }
        }
        AgentStatus::Completed(None) => "completed".to_string(),
        AgentStatus::Interrupted => "interrupted".to_string(),
        AgentStatus::Errored(message) => {
            let message = message.trim();
            if message.is_empty() {
                "errored".to_string()
            } else {
                message.to_string()
            }
        }
        AgentStatus::Shutdown => "shutdown".to_string(),
        AgentStatus::NotFound => "not found".to_string(),
        AgentStatus::PendingInit | AgentStatus::Running => "running".to_string(),
    }
}

fn status_label_span(status: &AgentStatus) -> Span<'static> {
    match status {
        AgentStatus::PendingInit | AgentStatus::Running => "running".cyan().bold(),
        AgentStatus::Interrupted => "interrupted".yellow(),
        AgentStatus::Completed(_) => "completed".green(),
        AgentStatus::Errored(_) => "errored".red(),
        AgentStatus::Shutdown => "shutdown".dim(),
        AgentStatus::NotFound => "not found".red(),
    }
}
