#[cfg(test)]
use crate::history_cell::HistoryCell;
use crate::history_cell::PlainHistoryCell;
use crate::render::line_utils::prefix_lines;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;
use serde::Deserialize;

const AGENT_JOB_BEGIN_PREFIX: &str = "agent_job_begin:";
const AGENT_JOB_PROGRESS_PREFIX: &str = "agent_job_progress:";
const AGENT_JOB_END_PREFIX: &str = "agent_job_end:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentJobBackgroundEvent {
    Begin(AgentJobBeginUpdate),
    Progress(AgentJobProgressUpdate),
    End(AgentJobEndUpdate),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub(crate) struct AgentJobBeginUpdate {
    pub(crate) job_id: String,
    pub(crate) input_csv_path: String,
    pub(crate) output_csv_path: String,
    pub(crate) total_items: usize,
    pub(crate) effective_concurrency: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub(crate) struct AgentJobProgressUpdate {
    pub(crate) job_id: String,
    pub(crate) total_items: usize,
    pub(crate) pending_items: usize,
    pub(crate) running_items: usize,
    pub(crate) completed_items: usize,
    pub(crate) failed_items: usize,
    pub(crate) eta_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub(crate) struct AgentJobEndUpdate {
    pub(crate) job_id: String,
    pub(crate) status: String,
    pub(crate) output_csv_path: String,
    pub(crate) total_items: usize,
    pub(crate) completed_items: usize,
    pub(crate) failed_items: usize,
    pub(crate) job_error: Option<String>,
}

pub(crate) fn parse_background_event(message: &str) -> Option<AgentJobBackgroundEvent> {
    if let Some(payload) = message.strip_prefix(AGENT_JOB_BEGIN_PREFIX) {
        return serde_json::from_str(payload)
            .ok()
            .map(AgentJobBackgroundEvent::Begin);
    }
    if let Some(payload) = message.strip_prefix(AGENT_JOB_PROGRESS_PREFIX) {
        return serde_json::from_str(payload)
            .ok()
            .map(AgentJobBackgroundEvent::Progress);
    }
    if let Some(payload) = message.strip_prefix(AGENT_JOB_END_PREFIX) {
        return serde_json::from_str(payload)
            .ok()
            .map(AgentJobBackgroundEvent::End);
    }
    None
}

pub(crate) fn begin_cell(update: &AgentJobBeginUpdate) -> PlainHistoryCell {
    history_cell(
        title("Started CSV agent job", update.job_id.as_str()),
        vec![
            Line::from(format!(
                "{} items, concurrency {}",
                update.total_items, update.effective_concurrency
            )),
            Line::from(format!(
                "{} -> {}",
                update.input_csv_path, update.output_csv_path
            )),
        ],
    )
}

pub(crate) fn end_cell(update: &AgentJobEndUpdate) -> PlainHistoryCell {
    let status = update.status.trim();
    let title_prefix = if status.eq_ignore_ascii_case("completed") {
        "Finished CSV agent job"
    } else {
        "CSV agent job ended"
    };
    let mut details = vec![Line::from(format!(
        "{} completed, {} failed, {} total",
        update.completed_items, update.failed_items, update.total_items
    ))];
    details.push(Line::from(update.output_csv_path.clone()));
    if let Some(job_error) = update.job_error.as_deref().map(str::trim)
        && !job_error.is_empty()
    {
        details.push(Line::from(job_error.to_string()));
    }

    history_cell(title(title_prefix, update.job_id.as_str()), details)
}

pub(crate) fn progress_status_line(update: &AgentJobProgressUpdate) -> String {
    let mut message = format!(
        "Agent job {}: {}/{} complete",
        short_job_id(update.job_id.as_str()),
        update.completed_items,
        update.total_items
    );
    if update.running_items > 0 {
        message.push_str(&format!(", {} running", update.running_items));
    }
    if update.failed_items > 0 {
        message.push_str(&format!(", {} failed", update.failed_items));
    }
    if let Some(eta_seconds) = update.eta_seconds {
        message.push_str(&format!(", ETA {eta_seconds}s"));
    }
    message
}

fn history_cell(title: Line<'static>, details: Vec<Line<'static>>) -> PlainHistoryCell {
    let mut lines = vec![title];
    lines.extend(prefix_lines(details, "  └ ".dim(), "    ".into()));
    PlainHistoryCell::new(lines)
}

fn title(prefix: &str, job_id: &str) -> Line<'static> {
    Line::from(vec![
        "• ".dim(),
        Span::from(format!("{prefix} ")).bold(),
        Span::from(short_job_id(job_id)).cyan().bold(),
    ])
}

fn short_job_id(job_id: &str) -> String {
    job_id.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use insta::assert_snapshot;

    #[test]
    fn parse_background_events() {
        let begin = parse_background_event(
            "agent_job_begin:{\"job_id\":\"1234567890\",\"input_csv_path\":\"/tmp/in.csv\",\"output_csv_path\":\"/tmp/out.csv\",\"total_items\":2,\"effective_concurrency\":4}",
        );
        assert!(matches!(begin, Some(AgentJobBackgroundEvent::Begin(_))));

        let progress = parse_background_event(
            "agent_job_progress:{\"job_id\":\"1234567890\",\"total_items\":2,\"pending_items\":0,\"running_items\":1,\"completed_items\":1,\"failed_items\":0,\"eta_seconds\":3}",
        );
        assert!(matches!(
            progress,
            Some(AgentJobBackgroundEvent::Progress(_))
        ));

        let end = parse_background_event(
            "agent_job_end:{\"job_id\":\"1234567890\",\"status\":\"completed\",\"output_csv_path\":\"/tmp/out.csv\",\"total_items\":2,\"completed_items\":2,\"failed_items\":0,\"job_error\":null}",
        );
        assert!(matches!(end, Some(AgentJobBackgroundEvent::End(_))));
    }

    #[test]
    fn agent_job_cells_snapshot() {
        let begin = begin_cell(&AgentJobBeginUpdate {
            job_id: "1234567890abcdef".to_string(),
            input_csv_path: "/tmp/input.csv".to_string(),
            output_csv_path: "/tmp/output.csv".to_string(),
            total_items: 2,
            effective_concurrency: 4,
        });
        let end = end_cell(&AgentJobEndUpdate {
            job_id: "1234567890abcdef".to_string(),
            status: "completed".to_string(),
            output_csv_path: "/tmp/output.csv".to_string(),
            total_items: 2,
            completed_items: 2,
            failed_items: 0,
            job_error: None,
        });
        let progress = progress_status_line(&AgentJobProgressUpdate {
            job_id: "1234567890abcdef".to_string(),
            total_items: 2,
            pending_items: 0,
            running_items: 1,
            completed_items: 1,
            failed_items: 0,
            eta_seconds: Some(3),
        });

        let snapshot = [
            begin
                .display_lines(200)
                .iter()
                .map(line_to_text)
                .collect::<Vec<_>>()
                .join("\n"),
            end.display_lines(200)
                .iter()
                .map(line_to_text)
                .collect::<Vec<_>>()
                .join("\n"),
            progress,
        ]
        .join("\n\n");
        assert_snapshot!("agent_job_transcript", snapshot);
    }

    fn line_to_text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<Vec<_>>()
            .join("")
    }
}
