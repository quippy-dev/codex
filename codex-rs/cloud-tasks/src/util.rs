use anyhow::Context;
use chrono::DateTime;
use chrono::Local;
use chrono::Utc;
use reqwest::header::HeaderMap;
use std::path::PathBuf;
use std::sync::Arc;

use codex_core::config::Config;
use codex_login::AuthManager;
use codex_utils_cli::CliConfigOverrides;

pub fn set_user_agent_suffix(suffix: &str) {
    if let Ok(mut guard) = codex_login::default_client::USER_AGENT_SUFFIX.lock() {
        guard.replace(suffix.to_string());
    }
}

pub fn append_error_log(message: impl AsRef<str>) {
    let ts = Utc::now().to_rfc3339();
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("error.log")
    {
        use std::io::Write as _;
        let _ = writeln!(f, "[{ts}] {}", message.as_ref());
    }
}

/// Normalize the configured base URL to a canonical form used by the backend client.
/// - trims trailing '/'
/// - appends '/backend-api' for ChatGPT hosts when missing
pub fn normalize_base_url(input: &str) -> String {
    let mut base_url = input.to_string();
    while base_url.ends_with('/') {
        base_url.pop();
    }
    if (base_url.starts_with("https://chatgpt.com")
        || base_url.starts_with("https://chat.openai.com"))
        && !base_url.contains("/backend-api")
    {
        base_url = format!("{base_url}/backend-api");
    }
    base_url
}

pub async fn load_auth_manager(
    cli_overrides: &CliConfigOverrides,
    auth_file: Option<PathBuf>,
) -> anyhow::Result<Arc<AuthManager>> {
    let config = Config::load_with_cli_overrides(
        cli_overrides
            .parse_overrides()
            .map_err(anyhow::Error::msg)
            .context("failed to parse cloud-tasks config overrides")?,
    )
    .await
    .context("failed to load cloud-tasks config")?;
    let chatgpt_base_url = std::env::var("CODEX_CLOUD_TASKS_BASE_URL")
        .ok()
        .map(|base_url| normalize_base_url(&base_url))
        .unwrap_or_else(|| config.chatgpt_base_url.clone());
    AuthManager::shared_from_config_with_auth_file_and_base_url(
        &config,
        /*enable_codex_api_key_env*/ false,
        auth_file,
        Some(chatgpt_base_url),
    )
    .map_err(|err| anyhow::anyhow!("failed to create cloud-tasks auth manager: {err}"))
}

/// Build headers for ChatGPT-backed requests: `User-Agent`, optional `Authorization`,
/// and optional `ChatGPT-Account-Id`.
pub async fn build_chatgpt_headers(
    cli_overrides: &CliConfigOverrides,
    auth_file: Option<PathBuf>,
) -> anyhow::Result<HeaderMap> {
    use reqwest::header::HeaderValue;
    use reqwest::header::USER_AGENT;

    set_user_agent_suffix("codex_cloud_tasks_tui");
    let ua = codex_login::default_client::get_codex_user_agent();
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&ua).unwrap_or(HeaderValue::from_static("codex-cli")),
    );
    let auth_manager = load_auth_manager(cli_overrides, auth_file).await?;
    if let Some(auth) = auth_manager.auth().await
        && auth.uses_codex_backend()
    {
        headers.extend(codex_model_provider::auth_provider_from_auth(&auth).to_auth_headers());
    }
    Ok(headers)
}

/// Construct a browser-friendly task URL for the given backend base URL.
pub fn task_url(base_url: &str, task_id: &str) -> String {
    let normalized = normalize_base_url(base_url);
    if let Some(root) = normalized.strip_suffix("/backend-api") {
        return format!("{root}/codex/tasks/{task_id}");
    }
    if let Some(root) = normalized.strip_suffix("/api/codex") {
        return format!("{root}/codex/tasks/{task_id}");
    }
    if normalized.ends_with("/codex") {
        return format!("{normalized}/tasks/{task_id}");
    }
    format!("{normalized}/codex/tasks/{task_id}")
}

pub fn format_relative_time(reference: DateTime<Utc>, ts: DateTime<Utc>) -> String {
    let mut secs = (reference - ts).num_seconds();
    if secs < 0 {
        secs = 0;
    }
    if secs < 60 {
        return format!("{secs}s ago");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m ago");
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h ago");
    }
    let local = ts.with_timezone(&Local);
    local.format("%b %e %H:%M").to_string()
}

pub fn format_relative_time_now(ts: DateTime<Utc>) -> String {
    format_relative_time(Utc::now(), ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_login::AuthCredentialsStoreMode;
    use codex_login::AuthDotJson;
    use codex_login::AuthMode;
    use codex_login::auth::save_auth_with_auth_file;
    use pretty_assertions::assert_eq;
    use reqwest::header::AUTHORIZATION;
    use reqwest::header::USER_AGENT;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    #[tokio::test]
    async fn auth_file_override_loads_cloud_auth_manager_and_headers() {
        let dir = std::env::temp_dir().join(format!(
            "codex-cloud-tasks-auth-override-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time went backwards")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let auth_file = dir.join("custom").join("auth.json");
        let auth_dot_json = AuthDotJson {
            auth_mode: Some(AuthMode::ApiKey),
            openai_api_key: Some("sk-cloud-override".to_string()),
            tokens: None,
            last_refresh: None,
            agent_identity: None,
        };
        save_auth_with_auth_file(
            &dir,
            &auth_dot_json,
            AuthCredentialsStoreMode::File,
            Some(auth_file.clone()),
        )
        .expect("save auth override");

        let cli_overrides = vec![
            format!("codex_home={}", dir.display()),
            "cli_auth_credentials_store=file".to_string(),
        ];
        let cli_overrides = CliConfigOverrides {
            raw_overrides: cli_overrides,
        };

        let auth_manager = load_auth_manager(&cli_overrides, Some(auth_file.clone()))
            .await
            .expect("auth manager");
        assert_eq!(auth_manager.auth_mode(), Some(AuthMode::ApiKey));
        let auth = auth_manager.auth().await.expect("auth should load");
        assert_eq!(auth.api_key(), Some("sk-cloud-override"));

        let headers = build_chatgpt_headers(&cli_overrides, Some(auth_file))
            .await
            .expect("headers");
        assert!(headers.get(USER_AGENT).is_some());
        assert_eq!(
            headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            None
        );

        std::fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[tokio::test]
    async fn invalid_auth_file_override_returns_error() {
        let dir = std::env::temp_dir().join(format!(
            "codex-cloud-tasks-auth-invalid-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time went backwards")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let auth_file = dir.join("custom").join("auth.json");
        let cli_overrides = vec![
            format!("codex_home={}", dir.display()),
            "cli_auth_credentials_store=ephemeral".to_string(),
        ];
        let cli_overrides = CliConfigOverrides {
            raw_overrides: cli_overrides,
        };
        let err = load_auth_manager(&cli_overrides, Some(auth_file))
            .await
            .expect_err("invalid override should fail");
        assert!(
            err.to_string().contains("--auth-file cannot be used"),
            "expected auth-file validation error, got `{err}`"
        );

        std::fs::remove_dir_all(&dir).expect("remove temp dir");
    }
}
