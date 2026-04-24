use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use super::AuthDotJson;
use super::AuthManager;
use super::CodexAuth;
use super::logout;
use super::logout_with_auth_file;
use super::read_codex_api_key_from_env;
use super::resolve_auth_storage_home;
use super::storage::create_auth_storage_with_auth_file;
use super::validate_auth_file_override;
use crate::AuthCredentialsStoreMode;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthFileRuntime {
    codex_home: PathBuf,
    auth_storage_home: PathBuf,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    auth_file: Option<PathBuf>,
}

impl AuthFileRuntime {
    pub fn new(
        codex_home: PathBuf,
        auth_credentials_store_mode: AuthCredentialsStoreMode,
        auth_file: Option<PathBuf>,
    ) -> std::io::Result<Self> {
        let auth_storage_home = resolve_auth_storage_home(
            codex_home.clone(),
            auth_file.as_deref(),
            auth_credentials_store_mode,
        )?;
        Ok(Self {
            codex_home,
            auth_storage_home,
            auth_credentials_store_mode,
            auth_file,
        })
    }

    pub fn auth_storage_home(&self) -> &Path {
        &self.auth_storage_home
    }

    pub fn into_auth_storage_home(self) -> PathBuf {
        self.auth_storage_home
    }

    pub fn auth_file(&self) -> Option<&Path> {
        self.auth_file.as_deref()
    }

    pub fn auth_credentials_store_mode(&self) -> AuthCredentialsStoreMode {
        self.auth_credentials_store_mode
    }

    pub fn shared_auth_manager(
        &self,
        enable_codex_api_key_env: bool,
    ) -> std::io::Result<Arc<AuthManager>> {
        AuthManager::shared_with_auth_file(
            self.codex_home.clone(),
            enable_codex_api_key_env,
            self.auth_credentials_store_mode,
            self.auth_file.clone(),
        )
    }
}

pub(crate) fn logout_all_stores_with_auth_file(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    auth_file: Option<&Path>,
) -> std::io::Result<bool> {
    let auth_storage_home = resolve_auth_storage_home(
        codex_home.to_path_buf(),
        auth_file,
        auth_credentials_store_mode,
    )?;
    if auth_credentials_store_mode == AuthCredentialsStoreMode::Ephemeral {
        return logout(&auth_storage_home, AuthCredentialsStoreMode::Ephemeral);
    }
    let removed_ephemeral = logout(&auth_storage_home, AuthCredentialsStoreMode::Ephemeral)?;
    let removed_managed = logout_with_auth_file(
        &auth_storage_home,
        auth_credentials_store_mode,
        auth_file.map(Path::to_path_buf),
    )?;
    Ok(removed_ephemeral || removed_managed)
}

pub(crate) fn load_auth_with_auth_file(
    codex_home: &Path,
    enable_codex_api_key_env: bool,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    auth_file: Option<PathBuf>,
) -> std::io::Result<Option<CodexAuth>> {
    validate_auth_file_override(auth_credentials_store_mode, auth_file.as_deref())?;
    let auth_storage_home = resolve_auth_storage_home(
        codex_home.to_path_buf(),
        auth_file.as_deref(),
        auth_credentials_store_mode,
    )?;

    let build_auth = |auth_dot_json: AuthDotJson, storage_mode| {
        let client = crate::default_client::create_client();
        CodexAuth::from_auth_dot_json(
            &auth_storage_home,
            auth_dot_json,
            storage_mode,
            auth_file.clone(),
            client,
        )
    };

    if enable_codex_api_key_env && let Some(api_key) = read_codex_api_key_from_env() {
        let client = crate::default_client::create_client();
        return Ok(Some(CodexAuth::from_api_key_with_client(
            api_key.as_str(),
            client,
        )));
    }

    let ephemeral_storage = create_auth_storage_with_auth_file(
        auth_storage_home.clone(),
        AuthCredentialsStoreMode::Ephemeral,
        auth_file.clone(),
    );
    if let Some(auth_dot_json) = ephemeral_storage.load()? {
        let auth = build_auth(auth_dot_json, AuthCredentialsStoreMode::Ephemeral)?;
        return Ok(Some(auth));
    }

    if auth_credentials_store_mode == AuthCredentialsStoreMode::Ephemeral {
        return Ok(None);
    }

    let storage = create_auth_storage_with_auth_file(
        auth_storage_home.clone(),
        auth_credentials_store_mode,
        auth_file.clone(),
    );
    let Some(auth_dot_json) = storage.load()? else {
        return Ok(None);
    };

    let auth = build_auth(auth_dot_json, auth_credentials_store_mode)?;
    Ok(Some(auth))
}
