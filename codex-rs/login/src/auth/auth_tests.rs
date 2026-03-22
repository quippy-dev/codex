use super::*;
use crate::auth::storage::FileAuthStorage;
use crate::auth::storage::get_auth_file;
use crate::token_data::IdTokenInfo;
use crate::token_data::KnownPlan as InternalKnownPlan;
use crate::token_data::PlanType as InternalPlanType;
use codex_protocol::account::PlanType as AccountPlanType;

use base64::Engine;
use codex_protocol::config_types::ForcedLoginMethod;
use pretty_assertions::assert_eq;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn refresh_without_id_token() {
    let codex_home = tempdir().unwrap();
    let fake_jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: None,
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let storage = create_auth_storage(
        codex_home.path().to_path_buf(),
        AuthCredentialsStoreMode::File,
    );
    let updated = super::persist_tokens(
        &storage,
        None,
        Some("new-access-token".to_string()),
        Some("new-refresh-token".to_string()),
    )
    .expect("update_tokens should succeed");

    let tokens = updated.tokens.expect("tokens should exist");
    assert_eq!(tokens.id_token.raw_jwt, fake_jwt);
    assert_eq!(tokens.access_token, "new-access-token");
    assert_eq!(tokens.refresh_token, "new-refresh-token");
}

#[test]
fn login_with_api_key_overwrites_existing_auth_json() {
    let dir = tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    let stale_auth = json!({
        "OPENAI_API_KEY": "sk-old",
        "tokens": {
            "id_token": "stale.header.payload",
            "access_token": "stale-access",
            "refresh_token": "stale-refresh",
            "account_id": "stale-acc"
        }
    });
    std::fs::write(
        &auth_path,
        serde_json::to_string_pretty(&stale_auth).unwrap(),
    )
    .unwrap();

    super::login_with_api_key(dir.path(), "sk-new", AuthCredentialsStoreMode::File)
        .expect("login_with_api_key should succeed");

    let storage = FileAuthStorage::new(dir.path().to_path_buf());
    let auth = storage
        .try_read_auth_json(&auth_path)
        .expect("auth.json should parse");
    assert_eq!(auth.openai_api_key.as_deref(), Some("sk-new"));
    assert!(auth.tokens.is_none(), "tokens should be cleared");
}

#[test]
fn missing_auth_json_returns_none() {
    let dir = tempdir().unwrap();
    let auth = CodexAuth::from_auth_storage(dir.path(), AuthCredentialsStoreMode::File)
        .expect("call should succeed");
    assert_eq!(auth, None);
}

#[tokio::test]
#[serial(codex_api_key)]
async fn pro_account_with_no_api_key_uses_chatgpt_auth() {
    let codex_home = tempdir().unwrap();
    let fake_jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: None,
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(codex_home.path(), false, AuthCredentialsStoreMode::File)
        .unwrap()
        .unwrap();
    assert_eq!(None, auth.api_key());
    assert_eq!(crate::AuthMode::Chatgpt, auth.auth_mode());
    assert_eq!(auth.get_chatgpt_user_id().as_deref(), Some("user-12345"));

    let auth_dot_json = auth
        .get_current_auth_json()
        .expect("AuthDotJson should exist");
    let last_refresh = auth_dot_json
        .last_refresh
        .expect("last_refresh should be recorded");

    assert_eq!(
        AuthDotJson {
            auth_mode: None,
            openai_api_key: None,
            tokens: Some(TokenData {
                id_token: IdTokenInfo {
                    email: Some("user@example.com".to_string()),
                    chatgpt_plan_type: Some(InternalPlanType::Known(InternalKnownPlan::Pro)),
                    chatgpt_user_id: Some("user-12345".to_string()),
                    chatgpt_account_id: None,
                    raw_jwt: fake_jwt,
                },
                access_token: "test-access-token".to_string(),
                refresh_token: "test-refresh-token".to_string(),
                account_id: None,
            }),
            last_refresh: Some(last_refresh),
        },
        auth_dot_json
    );
}

#[tokio::test]
#[serial(codex_api_key)]
async fn loads_api_key_from_auth_json() {
    let dir = tempdir().unwrap();
    let auth_file = dir.path().join("auth.json");
    std::fs::write(
        auth_file,
        r#"{"OPENAI_API_KEY":"sk-test-key","tokens":null,"last_refresh":null}"#,
    )
    .unwrap();

    let auth = super::load_auth(dir.path(), false, AuthCredentialsStoreMode::File)
        .unwrap()
        .unwrap();
    assert_eq!(auth.auth_mode(), crate::AuthMode::ApiKey);
    assert_eq!(auth.api_key(), Some("sk-test-key"));

    assert!(auth.get_token_data().is_err());
}

#[test]
fn logout_removes_auth_file() -> Result<(), std::io::Error> {
    let dir = tempdir()?;
    let auth_dot_json = AuthDotJson {
        auth_mode: Some(ApiAuthMode::ApiKey),
        openai_api_key: Some("sk-test-key".to_string()),
        tokens: None,
        last_refresh: None,
    };
    super::save_auth(dir.path(), &auth_dot_json, AuthCredentialsStoreMode::File)?;
    let auth_file = get_auth_file(dir.path());
    assert!(auth_file.exists());
    assert!(logout(dir.path(), AuthCredentialsStoreMode::File)?);
    assert!(!auth_file.exists());
    Ok(())
}

#[test]
fn auth_file_override_validation_disallows_keyring_auto_and_ephemeral() {
    let auth_file = PathBuf::from("/tmp/auth-override.json");
    let keyring_error =
        validate_auth_file_override(AuthCredentialsStoreMode::Keyring, Some(auth_file.as_path()))
            .expect_err("keyring mode should reject auth file override");
    assert_eq!(keyring_error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        keyring_error
            .to_string()
            .contains("cli_auth_credentials_store")
    );
    assert!(keyring_error.to_string().contains("keyring"));

    let auto_error =
        validate_auth_file_override(AuthCredentialsStoreMode::Auto, Some(auth_file.as_path()))
            .expect_err("auto mode should reject auth file override");
    assert_eq!(auto_error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        auto_error
            .to_string()
            .contains("cli_auth_credentials_store")
    );
    assert!(auto_error.to_string().contains("auto"));

    let ephemeral_error = validate_auth_file_override(
        AuthCredentialsStoreMode::Ephemeral,
        Some(auth_file.as_path()),
    )
    .expect_err("ephemeral mode should reject auth file override");
    assert_eq!(ephemeral_error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        ephemeral_error
            .to_string()
            .contains("cli_auth_credentials_store")
    );
    assert!(ephemeral_error.to_string().contains("ephemeral"));
}

#[test]
fn auth_file_override_validation_allows_file_without_override_modes() -> std::io::Result<()> {
    let auth_file = PathBuf::from("/tmp/auth-override.json");
    validate_auth_file_override(AuthCredentialsStoreMode::File, Some(auth_file.as_path()))?;
    validate_auth_file_override(AuthCredentialsStoreMode::Auto, None)?;
    validate_auth_file_override(AuthCredentialsStoreMode::Ephemeral, None)?;
    Ok(())
}

#[test]
fn resolve_auth_storage_home_without_override_returns_codex_home() -> std::io::Result<()> {
    let codex_home = PathBuf::from("/tmp/codex-home");
    let resolved =
        resolve_auth_storage_home(codex_home.clone(), None, AuthCredentialsStoreMode::File)?;
    assert_eq!(resolved, codex_home);
    Ok(())
}

#[test]
fn resolve_auth_storage_home_with_auth_json_returns_parent() -> std::io::Result<()> {
    let auth_file = PathBuf::from("/tmp/auth-state/auth.json");
    let resolved = resolve_auth_storage_home(
        PathBuf::from("/unused"),
        Some(auth_file.as_path()),
        AuthCredentialsStoreMode::File,
    )?;
    assert_eq!(resolved, PathBuf::from("/tmp/auth-state"));
    Ok(())
}

#[test]
fn resolve_auth_storage_home_rejects_non_auth_json_file() {
    let auth_file = PathBuf::from("/tmp/auth-state/custom.json");
    let err = resolve_auth_storage_home(
        PathBuf::from("/unused"),
        Some(auth_file.as_path()),
        AuthCredentialsStoreMode::File,
    )
    .expect_err("custom file name should be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("auth.json"));
}

#[test]
fn auth_storage_calls_with_auth_file_override_use_custom_file() -> std::io::Result<()> {
    let dir = tempdir()?;
    let auth_file = dir.path().join("nested").join("auth-override.json");
    let auth_dot_json = AuthDotJson {
        auth_mode: Some(ApiAuthMode::ApiKey),
        openai_api_key: Some("sk-override".to_string()),
        tokens: None,
        last_refresh: None,
    };

    save_auth_with_auth_file(
        dir.path(),
        &auth_dot_json,
        AuthCredentialsStoreMode::File,
        Some(auth_file.clone()),
    )?;

    assert!(auth_file.exists());
    assert!(!get_auth_file(dir.path()).exists());

    let loaded = load_auth_dot_json_with_auth_file(
        dir.path(),
        AuthCredentialsStoreMode::File,
        Some(auth_file.clone()),
    )?;
    assert_eq!(loaded, Some(auth_dot_json));

    let removed = logout_with_auth_file(
        dir.path(),
        AuthCredentialsStoreMode::File,
        Some(auth_file.clone()),
    )?;
    assert!(removed);
    assert!(!auth_file.exists());
    Ok(())
}

#[test]
fn from_auth_storage_with_auth_file_loads_override_path() -> std::io::Result<()> {
    let dir = tempdir()?;
    let auth_file = dir.path().join("override").join("auth.json");
    let auth_dot_json = AuthDotJson {
        auth_mode: Some(ApiAuthMode::ApiKey),
        openai_api_key: Some("sk-from-override".to_string()),
        tokens: None,
        last_refresh: None,
    };
    save_auth_with_auth_file(
        dir.path(),
        &auth_dot_json,
        AuthCredentialsStoreMode::File,
        Some(auth_file.clone()),
    )?;

    let default_auth = CodexAuth::from_auth_storage(dir.path(), AuthCredentialsStoreMode::File)?;
    assert_eq!(default_auth, None);

    let override_auth = CodexAuth::from_auth_storage_with_auth_file(
        dir.path(),
        AuthCredentialsStoreMode::File,
        Some(auth_file),
    )?;
    assert_eq!(
        override_auth
            .as_ref()
            .and_then(CodexAuth::api_key)
            .map(str::to_string),
        Some("sk-from-override".to_string())
    );
    Ok(())
}

#[test]
fn auth_manager_new_with_auth_file_uses_override() -> std::io::Result<()> {
    let dir = tempdir()?;
    let auth_file = dir.path().join("custom").join("auth.json");
    let auth_dot_json = AuthDotJson {
        auth_mode: Some(ApiAuthMode::ApiKey),
        openai_api_key: Some("sk-manager".to_string()),
        tokens: None,
        last_refresh: None,
    };
    save_auth_with_auth_file(
        dir.path(),
        &auth_dot_json,
        AuthCredentialsStoreMode::File,
        Some(auth_file.clone()),
    )?;

    let manager = AuthManager::new_with_auth_file(
        dir.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
        Some(auth_file.clone()),
    )?;
    assert_eq!(manager.auth_mode(), Some(AuthMode::ApiKey));

    let shared = AuthManager::shared_with_auth_file(
        dir.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
        Some(auth_file.clone()),
    )?;
    assert_eq!(shared.auth_mode(), Some(AuthMode::ApiKey));

    let removed = manager.logout()?;
    assert!(removed);
    assert!(!auth_file.exists());
    Ok(())
}

#[tokio::test]
async fn auth_manager_new_with_auth_file_ignores_default_ephemeral_store() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let auth_file = dir.path().join("custom").join("auth.json");
    let override_auth = AuthDotJson {
        auth_mode: Some(ApiAuthMode::ApiKey),
        openai_api_key: Some("sk-override".to_string()),
        tokens: None,
        last_refresh: None,
    };
    save_auth_with_auth_file(
        dir.path(),
        &override_auth,
        AuthCredentialsStoreMode::File,
        Some(auth_file.clone()),
    )?;

    let default_ephemeral_storage = create_auth_storage_with_auth_file(
        dir.path().to_path_buf(),
        AuthCredentialsStoreMode::Ephemeral,
        None,
    );
    default_ephemeral_storage.save(&AuthDotJson {
        auth_mode: Some(ApiAuthMode::ApiKey),
        openai_api_key: Some("sk-ephemeral".to_string()),
        tokens: None,
        last_refresh: None,
    })?;

    let manager = AuthManager::new_with_auth_file(
        dir.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
        Some(auth_file),
    )?;
    let loaded = manager.auth().await;
    assert_eq!(
        loaded
            .as_ref()
            .and_then(CodexAuth::api_key)
            .map(str::to_string),
        Some("sk-override".to_string())
    );
    Ok(())
}

#[test]
fn auth_manager_new_with_auth_file_rejects_ephemeral_override() {
    let auth_file = PathBuf::from("/tmp/custom/auth.json");
    let err = AuthManager::new_with_auth_file(
        PathBuf::from("/tmp/codex-home"),
        false,
        AuthCredentialsStoreMode::Ephemeral,
        Some(auth_file),
    )
    .expect_err("ephemeral mode should reject auth file override");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("ephemeral"));
}

#[test]
fn unauthorized_recovery_reports_mode_and_step_names() {
    let dir = tempdir().unwrap();
    let manager = AuthManager::shared(
        dir.path().to_path_buf(),
        false,
        AuthCredentialsStoreMode::File,
    );
    let managed = UnauthorizedRecovery {
        manager: Arc::clone(&manager),
        step: UnauthorizedRecoveryStep::Reload,
        expected_account_id: None,
        mode: UnauthorizedRecoveryMode::Managed,
    };
    assert_eq!(managed.mode_name(), "managed");
    assert_eq!(managed.step_name(), "reload");

    let external = UnauthorizedRecovery {
        manager,
        step: UnauthorizedRecoveryStep::ExternalRefresh,
        expected_account_id: None,
        mode: UnauthorizedRecoveryMode::External,
    };
    assert_eq!(external.mode_name(), "external");
    assert_eq!(external.step_name(), "external_refresh");
}

struct AuthFileParams {
    openai_api_key: Option<String>,
    chatgpt_plan_type: Option<String>,
    chatgpt_account_id: Option<String>,
}

fn write_auth_file(params: AuthFileParams, codex_home: &Path) -> std::io::Result<String> {
    let auth_file = get_auth_file(codex_home);
    // Create a minimal valid JWT for the id_token field.
    #[derive(Serialize)]
    struct Header {
        alg: &'static str,
        typ: &'static str,
    }
    let header = Header {
        alg: "none",
        typ: "JWT",
    };
    let mut auth_payload = serde_json::json!({
        "chatgpt_user_id": "user-12345",
        "user_id": "user-12345",
    });

    if let Some(chatgpt_plan_type) = params.chatgpt_plan_type {
        auth_payload["chatgpt_plan_type"] = serde_json::Value::String(chatgpt_plan_type);
    }

    if let Some(chatgpt_account_id) = params.chatgpt_account_id {
        let org_value = serde_json::Value::String(chatgpt_account_id);
        auth_payload["chatgpt_account_id"] = org_value;
    }

    let payload = serde_json::json!({
        "email": "user@example.com",
        "email_verified": true,
        "https://api.openai.com/auth": auth_payload,
    });
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let header_b64 = b64(&serde_json::to_vec(&header)?);
    let payload_b64 = b64(&serde_json::to_vec(&payload)?);
    let signature_b64 = b64(b"sig");
    let fake_jwt = format!("{header_b64}.{payload_b64}.{signature_b64}");

    let auth_json_data = json!({
        "OPENAI_API_KEY": params.openai_api_key,
        "tokens": {
            "id_token": fake_jwt,
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token"
        },
        "last_refresh": Utc::now(),
    });
    let auth_json = serde_json::to_string_pretty(&auth_json_data)?;
    std::fs::write(auth_file, auth_json)?;
    Ok(fake_jwt)
}

async fn build_config(
    codex_home: &Path,
    forced_login_method: Option<ForcedLoginMethod>,
    forced_chatgpt_workspace_id: Option<String>,
) -> AuthConfig {
    AuthConfig {
        codex_home: codex_home.to_path_buf(),
        auth_credentials_store_mode: AuthCredentialsStoreMode::File,
        forced_login_method,
        forced_chatgpt_workspace_id,
    }
}

/// Use sparingly.
/// TODO (gpeal): replace this with an injectable env var provider.
#[cfg(test)]
struct EnvVarGuard {
    key: &'static str,
    original: Option<std::ffi::OsString>,
}

#[cfg(test)]
impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let original = env::var_os(key);
        unsafe {
            env::set_var(key, value);
        }
        Self { key, original }
    }
}

#[cfg(test)]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        unsafe {
            match &self.original {
                Some(value) => env::set_var(self.key, value),
                None => env::remove_var(self.key),
            }
        }
    }
}

#[tokio::test]
async fn enforce_login_restrictions_logs_out_for_method_mismatch() {
    let codex_home = tempdir().unwrap();
    login_with_api_key(codex_home.path(), "sk-test", AuthCredentialsStoreMode::File)
        .expect("seed api key");

    let config = build_config(codex_home.path(), Some(ForcedLoginMethod::Chatgpt), None).await;

    let err =
        super::enforce_login_restrictions(&config).expect_err("expected method mismatch to error");
    assert!(err.to_string().contains("ChatGPT login is required"));
    assert!(
        !codex_home.path().join("auth.json").exists(),
        "auth.json should be removed on mismatch"
    );
}

#[tokio::test]
#[serial(codex_api_key)]
async fn enforce_login_restrictions_logs_out_for_workspace_mismatch() {
    let codex_home = tempdir().unwrap();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: Some("org_another_org".to_string()),
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let config = build_config(codex_home.path(), None, Some("org_mine".to_string())).await;

    let err = super::enforce_login_restrictions(&config)
        .expect_err("expected workspace mismatch to error");
    assert!(err.to_string().contains("workspace org_mine"));
    assert!(
        !codex_home.path().join("auth.json").exists(),
        "auth.json should be removed on mismatch"
    );
}

#[tokio::test]
#[serial(codex_api_key)]
async fn enforce_login_restrictions_allows_matching_workspace() {
    let codex_home = tempdir().unwrap();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: Some("org_mine".to_string()),
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let config = build_config(codex_home.path(), None, Some("org_mine".to_string())).await;

    super::enforce_login_restrictions(&config).expect("matching workspace should succeed");
    assert!(
        codex_home.path().join("auth.json").exists(),
        "auth.json should remain when restrictions pass"
    );
}

#[tokio::test]
async fn enforce_login_restrictions_allows_api_key_if_login_method_not_set_but_forced_chatgpt_workspace_id_is_set()
 {
    let codex_home = tempdir().unwrap();
    login_with_api_key(codex_home.path(), "sk-test", AuthCredentialsStoreMode::File)
        .expect("seed api key");

    let config = build_config(codex_home.path(), None, Some("org_mine".to_string())).await;

    super::enforce_login_restrictions(&config).expect("matching workspace should succeed");
    assert!(
        codex_home.path().join("auth.json").exists(),
        "auth.json should remain when restrictions pass"
    );
}

#[tokio::test]
#[serial(codex_api_key)]
async fn enforce_login_restrictions_blocks_env_api_key_when_chatgpt_required() {
    let _guard = EnvVarGuard::set(CODEX_API_KEY_ENV_VAR, "sk-env");
    let codex_home = tempdir().unwrap();

    let config = build_config(codex_home.path(), Some(ForcedLoginMethod::Chatgpt), None).await;

    let err = super::enforce_login_restrictions(&config)
        .expect_err("environment API key should not satisfy forced ChatGPT login");
    assert!(
        err.to_string()
            .contains("ChatGPT login is required, but an API key is currently being used.")
    );
}

#[test]
fn plan_type_maps_known_plan() {
    let codex_home = tempdir().unwrap();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("pro".to_string()),
            chatgpt_account_id: None,
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(codex_home.path(), false, AuthCredentialsStoreMode::File)
        .expect("load auth")
        .expect("auth available");

    pretty_assertions::assert_eq!(auth.account_plan_type(), Some(AccountPlanType::Pro));
}

#[test]
fn plan_type_maps_unknown_to_unknown() {
    let codex_home = tempdir().unwrap();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: Some("mystery-tier".to_string()),
            chatgpt_account_id: None,
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(codex_home.path(), false, AuthCredentialsStoreMode::File)
        .expect("load auth")
        .expect("auth available");

    pretty_assertions::assert_eq!(auth.account_plan_type(), Some(AccountPlanType::Unknown));
}

#[test]
fn missing_plan_type_maps_to_unknown() {
    let codex_home = tempdir().unwrap();
    let _jwt = write_auth_file(
        AuthFileParams {
            openai_api_key: None,
            chatgpt_plan_type: None,
            chatgpt_account_id: None,
        },
        codex_home.path(),
    )
    .expect("failed to write auth file");

    let auth = super::load_auth(codex_home.path(), false, AuthCredentialsStoreMode::File)
        .expect("load auth")
        .expect("auth available");

    pretty_assertions::assert_eq!(auth.account_plan_type(), Some(AccountPlanType::Unknown));
}
