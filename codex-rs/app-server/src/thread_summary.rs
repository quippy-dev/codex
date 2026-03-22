use crate::thread_history_loader::preview_from_rollout_items;
use crate::thread_history_loader::read_rollout_items_from_rollout;
use chrono::DateTime;
use chrono::SecondsFormat;
use chrono::Utc;
use codex_app_server_protocol::ConversationGitInfo;
use codex_app_server_protocol::ConversationSummary;
use codex_app_server_protocol::GitInfo as ApiGitInfo;
use codex_app_server_protocol::Thread;
use codex_app_server_protocol::ThreadStatus;
use codex_core::SessionMeta;
use codex_core::ThreadConfigSnapshot;
use codex_core::config::Config;
use codex_core::read_head_for_summary;
use codex_core::state_db::StateDbHandle;
use codex_core::state_db::get_state_db;
use codex_protocol::ThreadId;
use codex_protocol::items::TurnItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::GitInfo as CoreGitInfo;
use codex_protocol::protocol::SessionMetaLine;
use codex_protocol::protocol::SessionSource as CoreSessionSource;
use codex_protocol::protocol::SubAgentSource;
use codex_protocol::protocol::USER_MESSAGE_BEGIN;
use std::io::Error as IoError;
use std::path::Path;
use std::path::PathBuf;

#[allow(dead_code)]
pub(crate) async fn read_summary_from_state_db_by_thread_id(
    config: &Config,
    thread_id: ThreadId,
) -> Option<ConversationSummary> {
    let state_db_ctx = get_state_db(config).await;
    read_summary_from_state_db_context_by_thread_id(state_db_ctx.as_ref(), thread_id).await
}

#[allow(dead_code)]
pub(crate) async fn read_summary_from_state_db_context_by_thread_id(
    state_db_ctx: Option<&StateDbHandle>,
    thread_id: ThreadId,
) -> Option<ConversationSummary> {
    let state_db_ctx = state_db_ctx?;

    let metadata = match state_db_ctx.get_thread(thread_id).await {
        Ok(Some(metadata)) => metadata,
        Ok(None) | Err(_) => return None,
    };
    Some(summary_from_state_db_metadata(
        metadata.id,
        metadata.rollout_path,
        metadata.first_user_message,
        metadata
            .created_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        metadata
            .updated_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        metadata.model_provider,
        metadata.cwd,
        metadata.cli_version,
        metadata.source,
        metadata.agent_nickname,
        metadata.agent_role,
        metadata.git_sha,
        metadata.git_branch,
        metadata.git_origin_url,
    ))
}

#[allow(dead_code)]
pub(crate) async fn summary_from_thread_list_item(
    it: codex_core::ThreadItem,
    fallback_provider: &str,
    state_db_ctx: Option<&StateDbHandle>,
) -> Option<ConversationSummary> {
    if let Some(thread_id) = it.thread_id {
        let timestamp = it.created_at.clone();
        let updated_at = it.updated_at.clone().or_else(|| timestamp.clone());
        let model_provider = it
            .model_provider
            .clone()
            .unwrap_or_else(|| fallback_provider.to_string());
        let cwd = it.cwd?;
        let cli_version = it.cli_version.unwrap_or_default();
        let source = with_thread_spawn_agent_metadata(
            it.source.unwrap_or(CoreSessionSource::Unknown),
            it.agent_nickname.clone(),
            it.agent_role.clone(),
        );
        return Some(ConversationSummary {
            conversation_id: thread_id,
            path: it.path,
            preview: it.first_user_message.unwrap_or_default(),
            timestamp,
            updated_at,
            model_provider,
            cwd,
            cli_version,
            source,
            git_info: if it.git_sha.is_none()
                && it.git_branch.is_none()
                && it.git_origin_url.is_none()
            {
                None
            } else {
                Some(ConversationGitInfo {
                    sha: it.git_sha,
                    branch: it.git_branch,
                    origin_url: it.git_origin_url,
                })
            },
        });
    }
    if let Some(thread_id) = thread_id_from_rollout_path(it.path.as_path()) {
        return read_summary_from_state_db_context_by_thread_id(state_db_ctx, thread_id).await;
    }
    None
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn summary_from_state_db_metadata(
    conversation_id: ThreadId,
    path: PathBuf,
    first_user_message: Option<String>,
    timestamp: String,
    updated_at: String,
    model_provider: String,
    cwd: PathBuf,
    cli_version: String,
    source: String,
    agent_nickname: Option<String>,
    agent_role: Option<String>,
    git_sha: Option<String>,
    git_branch: Option<String>,
    git_origin_url: Option<String>,
) -> ConversationSummary {
    let preview = first_user_message.unwrap_or_default();
    let source = serde_json::from_str(&source)
        .or_else(|_| serde_json::from_value(serde_json::Value::String(source.clone())))
        .unwrap_or(CoreSessionSource::Unknown);
    let source = with_thread_spawn_agent_metadata(source, agent_nickname, agent_role);
    let git_info = if git_sha.is_none() && git_branch.is_none() && git_origin_url.is_none() {
        None
    } else {
        Some(ConversationGitInfo {
            sha: git_sha,
            branch: git_branch,
            origin_url: git_origin_url,
        })
    };
    ConversationSummary {
        conversation_id,
        path,
        preview,
        timestamp: Some(timestamp),
        updated_at: Some(updated_at),
        model_provider,
        cwd,
        cli_version,
        source,
        git_info,
    }
}

pub(crate) async fn read_summary_from_rollout(
    path: &Path,
    fallback_provider: &str,
) -> std::io::Result<ConversationSummary> {
    let head = read_head_for_summary(path).await?;

    let Some(first) = head.first() else {
        return Err(IoError::other(format!(
            "rollout at {} is empty",
            path.display()
        )));
    };

    let session_meta_line =
        serde_json::from_value::<SessionMetaLine>(first.clone()).map_err(|_| {
            IoError::other(format!(
                "rollout at {} does not start with session metadata",
                path.display()
            ))
        })?;
    let SessionMetaLine {
        meta: session_meta,
        git,
    } = session_meta_line;
    let mut session_meta = session_meta;
    session_meta.source = with_thread_spawn_agent_metadata(
        session_meta.source.clone(),
        session_meta.agent_nickname.clone(),
        session_meta.agent_role.clone(),
    );

    let created_at = if session_meta.timestamp.is_empty() {
        None
    } else {
        Some(session_meta.timestamp.as_str())
    };
    let updated_at = read_updated_at(path, created_at).await;
    if let Some(summary) = extract_conversation_summary(
        path.to_path_buf(),
        &head,
        &session_meta,
        git.as_ref(),
        fallback_provider,
        updated_at.clone(),
    ) {
        return Ok(summary);
    }

    let timestamp = if session_meta.timestamp.is_empty() {
        None
    } else {
        Some(session_meta.timestamp.clone())
    };
    let model_provider = session_meta
        .model_provider
        .clone()
        .unwrap_or_else(|| fallback_provider.to_string());
    let git_info = git.as_ref().map(map_git_info);
    let updated_at = updated_at.or_else(|| timestamp.clone());
    let preview = read_rollout_items_from_rollout(path)
        .await
        .map(|items| preview_from_rollout_items(&items))
        .unwrap_or_default();

    Ok(ConversationSummary {
        conversation_id: session_meta.id,
        timestamp,
        updated_at,
        path: path.to_path_buf(),
        preview,
        model_provider,
        cwd: session_meta.cwd,
        cli_version: session_meta.cli_version,
        source: session_meta.source,
        git_info,
    })
}

fn extract_conversation_summary(
    path: PathBuf,
    head: &[serde_json::Value],
    session_meta: &SessionMeta,
    git: Option<&CoreGitInfo>,
    fallback_provider: &str,
    updated_at: Option<String>,
) -> Option<ConversationSummary> {
    let preview = head
        .iter()
        .filter_map(|value| serde_json::from_value::<ResponseItem>(value.clone()).ok())
        .find_map(|item| match codex_core::parse_turn_item(&item) {
            Some(TurnItem::UserMessage(user)) => Some(user.message()),
            _ => None,
        })?;

    let preview = match preview.find(USER_MESSAGE_BEGIN) {
        Some(idx) => preview[idx + USER_MESSAGE_BEGIN.len()..].trim(),
        None => preview.as_str(),
    };

    let timestamp = if session_meta.timestamp.is_empty() {
        None
    } else {
        Some(session_meta.timestamp.clone())
    };
    let conversation_id = session_meta.id;
    let model_provider = session_meta
        .model_provider
        .clone()
        .unwrap_or_else(|| fallback_provider.to_string());
    let git_info = git.map(map_git_info);
    let updated_at = updated_at.or_else(|| timestamp.clone());

    Some(ConversationSummary {
        conversation_id,
        timestamp,
        updated_at,
        path,
        preview: preview.to_string(),
        model_provider,
        cwd: session_meta.cwd.clone(),
        cli_version: session_meta.cli_version.clone(),
        source: session_meta.source.clone(),
        git_info,
    })
}

fn map_git_info(git_info: &CoreGitInfo) -> ConversationGitInfo {
    ConversationGitInfo {
        sha: git_info.commit_hash.clone(),
        branch: git_info.branch.clone(),
        origin_url: git_info.repository_url.clone(),
    }
}

#[allow(dead_code)]
pub(crate) async fn load_thread_summary_for_rollout(
    config: &Config,
    thread_id: ThreadId,
    rollout_path: &Path,
    fallback_provider: &str,
) -> std::result::Result<Thread, String> {
    let mut thread = read_summary_from_rollout(rollout_path, fallback_provider)
        .await
        .map(summary_to_thread)
        .map_err(|err| {
            format!(
                "failed to load rollout `{}` for thread {thread_id}: {err}",
                rollout_path.display()
            )
        })?;
    if let Some(summary) = read_summary_from_state_db_by_thread_id(config, thread_id).await {
        merge_mutable_thread_metadata(&mut thread, summary_to_thread(summary));
    }
    Ok(thread)
}

#[allow(dead_code)]
fn merge_mutable_thread_metadata(thread: &mut Thread, persisted_thread: Thread) {
    thread.git_info = persisted_thread.git_info;
}

#[allow(dead_code)]
fn thread_id_from_rollout_path(path: &Path) -> Option<ThreadId> {
    let file_name = path.file_name()?.to_str()?;
    let stem = file_name.strip_suffix(".jsonl")?;
    if stem.len() < 37 {
        return None;
    }
    let uuid_start = stem.len().saturating_sub(36);
    if !stem[..uuid_start].ends_with('-') {
        return None;
    }
    ThreadId::from_string(&stem[uuid_start..]).ok()
}

fn with_thread_spawn_agent_metadata(
    source: CoreSessionSource,
    agent_nickname: Option<String>,
    agent_role: Option<String>,
) -> CoreSessionSource {
    if agent_nickname.is_none() && agent_role.is_none() {
        return source;
    }

    match source {
        CoreSessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth,
            agent_path,
            agent_nickname: existing_agent_nickname,
            agent_role: existing_agent_role,
        }) => CoreSessionSource::SubAgent(SubAgentSource::ThreadSpawn {
            parent_thread_id,
            depth,
            agent_path,
            agent_nickname: agent_nickname.or(existing_agent_nickname),
            agent_role: agent_role.or(existing_agent_role),
        }),
        _ => source,
    }
}

fn parse_datetime(timestamp: Option<&str>) -> Option<DateTime<Utc>> {
    timestamp.and_then(|ts| {
        chrono::DateTime::parse_from_rfc3339(ts)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    })
}

async fn read_updated_at(path: &Path, created_at: Option<&str>) -> Option<String> {
    let updated_at = tokio::fs::metadata(path)
        .await
        .ok()
        .and_then(|meta| meta.modified().ok())
        .map(|modified| {
            let updated_at: DateTime<Utc> = modified.into();
            updated_at.to_rfc3339_opts(SecondsFormat::Secs, true)
        });
    updated_at.or_else(|| created_at.map(str::to_string))
}

pub(crate) fn build_thread_from_snapshot(
    thread_id: ThreadId,
    config_snapshot: &ThreadConfigSnapshot,
    path: Option<PathBuf>,
) -> Thread {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    Thread {
        id: thread_id.to_string(),
        preview: String::new(),
        ephemeral: config_snapshot.ephemeral,
        model_provider: config_snapshot.model_provider_id.clone(),
        created_at: now,
        updated_at: now,
        status: ThreadStatus::NotLoaded,
        path,
        cwd: config_snapshot.cwd.clone(),
        cli_version: env!("CARGO_PKG_VERSION").to_string(),
        agent_nickname: config_snapshot.session_source.get_nickname(),
        agent_role: config_snapshot.session_source.get_agent_role(),
        source: config_snapshot.session_source.clone().into(),
        git_info: None,
        name: None,
        turns: Vec::new(),
    }
}

#[allow(dead_code)]
pub(crate) fn merge_loaded_thread_rollout_summary(
    thread: &mut Thread,
    summary: ConversationSummary,
) {
    let rollout_thread = summary_to_thread(summary);
    thread.preview = rollout_thread.preview;
    thread.created_at = rollout_thread.created_at;
    thread.updated_at = rollout_thread.updated_at;
    thread.path = rollout_thread.path;
    thread.git_info = rollout_thread.git_info;
}

pub(crate) fn summary_to_thread(summary: ConversationSummary) -> Thread {
    let ConversationSummary {
        conversation_id,
        path,
        preview,
        timestamp,
        updated_at,
        model_provider,
        cwd,
        cli_version,
        source,
        git_info,
    } = summary;

    let created_at = parse_datetime(timestamp.as_deref());
    let updated_at = parse_datetime(updated_at.as_deref()).or(created_at);
    let git_info = git_info.map(|info| ApiGitInfo {
        sha: info.sha,
        branch: info.branch,
        origin_url: info.origin_url,
    });

    Thread {
        id: conversation_id.to_string(),
        preview,
        ephemeral: false,
        model_provider,
        created_at: created_at.map(|dt| dt.timestamp()).unwrap_or(0),
        updated_at: updated_at.map(|dt| dt.timestamp()).unwrap_or(0),
        status: ThreadStatus::NotLoaded,
        path: Some(path),
        cwd,
        cli_version,
        agent_nickname: source.get_nickname(),
        agent_role: source.get_agent_role(),
        source: source.into(),
        git_info,
        name: None,
        turns: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use codex_protocol::protocol::RolloutItem;
    use codex_protocol::protocol::RolloutLine;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn extract_conversation_summary_prefers_plain_user_messages() -> Result<()> {
        let conversation_id = ThreadId::from_string("3f941c35-29b3-493b-b0a4-e25800d9aeb0")?;
        let timestamp = Some("2025-09-05T16:53:11.850Z".to_string());
        let path = PathBuf::from("rollout.jsonl");

        let head = vec![
            json!({
                "id": conversation_id.to_string(),
                "timestamp": timestamp,
                "cwd": "/",
                "originator": "codex",
                "cli_version": "0.0.0",
                "model_provider": "test-provider"
            }),
            json!({
                "type": "message",
                "role": "user",
                "content": [{
                    "type": "input_text",
                    "text": "# AGENTS.md instructions for project\n\n<INSTRUCTIONS>\n<AGENTS.md contents>\n</INSTRUCTIONS>".to_string(),
                }],
            }),
            json!({
                "type": "message",
                "role": "user",
                "content": [{
                    "type": "input_text",
                    "text": format!("<prior context> {USER_MESSAGE_BEGIN}Count to 5"),
                }],
            }),
        ];

        let session_meta = serde_json::from_value::<SessionMeta>(head[0].clone())?;

        let summary = extract_conversation_summary(
            path.clone(),
            &head,
            &session_meta,
            None,
            "test-provider",
            timestamp.clone(),
        )
        .expect("summary");

        let expected = ConversationSummary {
            conversation_id,
            timestamp: timestamp.clone(),
            updated_at: timestamp,
            path,
            preview: "Count to 5".to_string(),
            model_provider: "test-provider".to_string(),
            cwd: PathBuf::from("/"),
            cli_version: "0.0.0".to_string(),
            source: CoreSessionSource::VSCode,
            git_info: None,
        };

        assert_eq!(summary, expected);
        Ok(())
    }

    #[tokio::test]
    async fn read_summary_from_rollout_returns_empty_preview_when_no_user_message() -> Result<()> {
        use std::fs;
        use std::fs::FileTimes;

        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("rollout.jsonl");

        let conversation_id = ThreadId::from_string("bfd12a78-5900-467b-9bc5-d3d35df08191")?;
        let timestamp = "2025-09-05T16:53:11.850Z".to_string();

        let session_meta = SessionMeta {
            id: conversation_id,
            timestamp: timestamp.clone(),
            model_provider: None,
            ..SessionMeta::default()
        };

        let line = RolloutLine {
            timestamp: timestamp.clone(),
            item: RolloutItem::SessionMeta(SessionMetaLine {
                meta: session_meta.clone(),
                git: None,
            }),
        };

        fs::write(&path, format!("{}\n", serde_json::to_string(&line)?))?;
        let parsed = chrono::DateTime::parse_from_rfc3339(&timestamp)?.with_timezone(&Utc);
        let times = FileTimes::new().set_modified(parsed.into());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .set_times(times)?;

        let summary = read_summary_from_rollout(path.as_path(), "fallback").await?;

        let expected = ConversationSummary {
            conversation_id,
            timestamp: Some(timestamp.clone()),
            updated_at: Some("2025-09-05T16:53:11Z".to_string()),
            path: path.clone(),
            preview: String::new(),
            model_provider: "fallback".to_string(),
            cwd: PathBuf::new(),
            cli_version: String::new(),
            source: CoreSessionSource::VSCode,
            git_info: None,
        };

        assert_eq!(summary, expected);
        Ok(())
    }

    #[tokio::test]
    async fn read_summary_from_rollout_preserves_agent_nickname() -> Result<()> {
        use std::fs;

        let temp_dir = TempDir::new()?;
        let path = temp_dir.path().join("rollout.jsonl");

        let conversation_id = ThreadId::from_string("bfd12a78-5900-467b-9bc5-d3d35df08191")?;
        let parent_thread_id = ThreadId::from_string("ad7f0408-99b8-4f6e-a46f-bd0eec433370")?;
        let timestamp = "2025-09-05T16:53:11.850Z".to_string();

        let session_meta = SessionMeta {
            id: conversation_id,
            timestamp: timestamp.clone(),
            source: CoreSessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id,
                depth: 1,
                agent_path: None,
                agent_nickname: None,
                agent_role: None,
            }),
            agent_nickname: Some("atlas".to_string()),
            agent_role: Some("explorer".to_string()),
            model_provider: Some("test-provider".to_string()),
            ..SessionMeta::default()
        };

        let line = RolloutLine {
            timestamp,
            item: RolloutItem::SessionMeta(SessionMetaLine {
                meta: session_meta,
                git: None,
            }),
        };
        fs::write(&path, format!("{}\n", serde_json::to_string(&line)?))?;

        let summary = read_summary_from_rollout(path.as_path(), "fallback").await?;
        let thread = summary_to_thread(summary);

        assert_eq!(thread.agent_nickname, Some("atlas".to_string()));
        assert_eq!(thread.agent_role, Some("explorer".to_string()));
        Ok(())
    }

    #[test]
    fn summary_from_state_db_metadata_preserves_agent_nickname() -> Result<()> {
        let conversation_id = ThreadId::from_string("bfd12a78-5900-467b-9bc5-d3d35df08191")?;
        let source =
            serde_json::to_string(&CoreSessionSource::SubAgent(SubAgentSource::ThreadSpawn {
                parent_thread_id: ThreadId::from_string("ad7f0408-99b8-4f6e-a46f-bd0eec433370")?,
                depth: 1,
                agent_path: None,
                agent_nickname: None,
                agent_role: None,
            }))?;

        let summary = summary_from_state_db_metadata(
            conversation_id,
            PathBuf::from("/tmp/rollout.jsonl"),
            Some("hi".to_string()),
            "2025-09-05T16:53:11Z".to_string(),
            "2025-09-05T16:53:12Z".to_string(),
            "test-provider".to_string(),
            PathBuf::from("/"),
            "0.0.0".to_string(),
            source,
            Some("atlas".to_string()),
            Some("explorer".to_string()),
            None,
            None,
            None,
        );

        let thread = summary_to_thread(summary);

        assert_eq!(thread.agent_nickname, Some("atlas".to_string()));
        assert_eq!(thread.agent_role, Some("explorer".to_string()));
        Ok(())
    }
}
