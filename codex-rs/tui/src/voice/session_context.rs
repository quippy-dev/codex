use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::Mutex;

use codex_login::AuthCredentialsStoreMode;

static TRANSCRIPTION_SESSION_CONTEXT: LazyLock<Mutex<Option<TranscriptionSessionContext>>> =
    LazyLock::new(|| Mutex::new(None));

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TranscriptionSessionContext {
    pub(crate) auth_storage_home: PathBuf,
    pub(crate) auth_credentials_store_mode: AuthCredentialsStoreMode,
    pub(crate) chatgpt_base_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TranscriptionAuthInput {
    pub(crate) auth_storage_home: PathBuf,
    pub(crate) auth_credentials_store_mode: AuthCredentialsStoreMode,
    pub(crate) chatgpt_base_url: String,
}

pub(crate) fn set_transcription_session_context(
    auth_storage_home: PathBuf,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    chatgpt_base_url: String,
) {
    if let Ok(mut stored) = TRANSCRIPTION_SESSION_CONTEXT.lock() {
        *stored = Some(TranscriptionSessionContext {
            auth_storage_home,
            auth_credentials_store_mode,
            chatgpt_base_url,
        });
    }
}

pub(crate) fn transcription_auth_input() -> Result<TranscriptionAuthInput, String> {
    let session_context = current_transcription_session_context()?
        .ok_or_else(|| "transcription session context was not initialized".to_string())?;
    Ok(TranscriptionAuthInput {
        auth_storage_home: session_context.auth_storage_home,
        auth_credentials_store_mode: session_context.auth_credentials_store_mode,
        chatgpt_base_url: session_context.chatgpt_base_url,
    })
}

pub(crate) fn current_transcription_session_context()
-> Result<Option<TranscriptionSessionContext>, String> {
    TRANSCRIPTION_SESSION_CONTEXT
        .lock()
        .map(|stored| stored.clone())
        .map_err(|_| "failed to access transcription session context".to_string())
}
