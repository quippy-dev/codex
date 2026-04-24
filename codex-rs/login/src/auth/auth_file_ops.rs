use std::path::Path;
use std::path::PathBuf;

use super::AuthDotJson;
use super::storage::create_auth_storage_with_auth_file;
use super::validate_auth_file_override;
use crate::AuthCredentialsStoreMode;

pub fn logout_with_auth_file(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    auth_file: Option<PathBuf>,
) -> std::io::Result<bool> {
    validate_auth_file_override(auth_credentials_store_mode, auth_file.as_deref())?;
    let storage = create_auth_storage_with_auth_file(
        codex_home.to_path_buf(),
        auth_credentials_store_mode,
        auth_file,
    );
    storage.delete()
}

pub fn save_auth_with_auth_file(
    codex_home: &Path,
    auth: &AuthDotJson,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    auth_file: Option<PathBuf>,
) -> std::io::Result<()> {
    validate_auth_file_override(auth_credentials_store_mode, auth_file.as_deref())?;
    let storage = create_auth_storage_with_auth_file(
        codex_home.to_path_buf(),
        auth_credentials_store_mode,
        auth_file,
    );
    storage.save(auth)
}

pub fn load_auth_dot_json_with_auth_file(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    auth_file: Option<PathBuf>,
) -> std::io::Result<Option<AuthDotJson>> {
    validate_auth_file_override(auth_credentials_store_mode, auth_file.as_deref())?;
    let storage = create_auth_storage_with_auth_file(
        codex_home.to_path_buf(),
        auth_credentials_store_mode,
        auth_file,
    );
    storage.load()
}
