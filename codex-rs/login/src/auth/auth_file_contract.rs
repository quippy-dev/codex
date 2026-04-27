use std::path::Path;
use std::path::PathBuf;

use crate::AuthCredentialsStoreMode;

pub fn validate_auth_file_override(
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    auth_file: Option<&Path>,
) -> std::io::Result<()> {
    if auth_file.is_some()
        && matches!(
            auth_credentials_store_mode,
            AuthCredentialsStoreMode::Auto
                | AuthCredentialsStoreMode::Ephemeral
                | AuthCredentialsStoreMode::Keyring
        )
    {
        let mode = match auth_credentials_store_mode {
            AuthCredentialsStoreMode::Auto => "auto",
            AuthCredentialsStoreMode::Ephemeral => "ephemeral",
            AuthCredentialsStoreMode::Keyring => "keyring",
            _ => unreachable!(),
        };
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "--auth-file cannot be used when `cli_auth_credentials_store` is `{mode}`. Set `-c cli_auth_credentials_store=file` and retry."
            ),
        ));
    }
    Ok(())
}

pub fn resolve_auth_storage_home(
    codex_home: PathBuf,
    auth_file: Option<&Path>,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> std::io::Result<PathBuf> {
    validate_auth_file_override(auth_credentials_store_mode, auth_file)?;

    let Some(auth_file) = auth_file else {
        return Ok(codex_home);
    };

    if auth_file.file_name().and_then(|name| name.to_str()) != Some("auth.json") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "--auth-file must point to a file named `auth.json` so it can map to core auth storage. Got: {}",
                auth_file.display()
            ),
        ));
    }

    Ok(auth_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".")))
}
