use codex_exec::Cli as ExecCli;
use codex_tui::Cli as TuiCli;
use std::path::PathBuf;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AuthFileDispatch {
    auth_file: Option<PathBuf>,
}

impl AuthFileDispatch {
    pub(crate) fn new(auth_file: Option<PathBuf>) -> Self {
        Self { auth_file }
    }

    pub(crate) fn clone_path(&self) -> Option<PathBuf> {
        self.auth_file.clone()
    }

    pub(crate) fn apply_to_tui(&self, interactive: &mut TuiCli) {
        interactive.auth_file = self.clone_path();
    }

    pub(crate) fn apply_to_exec(&self, exec_cli: &mut ExecCli) {
        exec_cli.auth_file = self.clone_path();
    }
}
