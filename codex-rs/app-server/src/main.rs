use codex_app_server::run_main;
use codex_arg0::arg0_dispatch_or_else;
use codex_common::CliConfigOverrides;
use codex_core::config_loader::LoaderOverrides;
use std::path::PathBuf;

// Debug-only test hook: lets integration tests point the server at a temporary
// managed config file without writing to /etc.
#[cfg(debug_assertions)]
const MANAGED_CONFIG_PATH_ENV_VAR: &str = "CODEX_APP_SERVER_MANAGED_CONFIG_PATH";
#[cfg(debug_assertions)]
const IGNORE_SYSTEM_CONFIG_ENV_VAR: &str = "CODEX_APP_SERVER_IGNORE_SYSTEM_CONFIG";
#[cfg(debug_assertions)]
const IGNORE_SYSTEM_REQUIREMENTS_ENV_VAR: &str = "CODEX_APP_SERVER_IGNORE_SYSTEM_REQUIREMENTS";

fn main() -> anyhow::Result<()> {
    arg0_dispatch_or_else(|codex_linux_sandbox_exe| async move {
        let managed_config_path = managed_config_path_from_debug_env();
        let loader_overrides = LoaderOverrides {
            managed_config_path,
            ignore_system_config: ignore_system_config_from_debug_env(),
            ignore_system_requirements: ignore_system_requirements_from_debug_env(),
            ..Default::default()
        };

        run_main(
            codex_linux_sandbox_exe,
            CliConfigOverrides::default(),
            loader_overrides,
            false,
        )
        .await?;
        Ok(())
    })
}

#[cfg(debug_assertions)]
fn managed_config_path_from_debug_env() -> Option<PathBuf> {
    if let Ok(value) = std::env::var(MANAGED_CONFIG_PATH_ENV_VAR) {
        return if value.is_empty() {
            None
        } else {
            Some(PathBuf::from(value))
        };
    }
    None
}

#[cfg(not(debug_assertions))]
fn managed_config_path_from_debug_env() -> Option<PathBuf> {
    None
}

#[cfg(debug_assertions)]
fn ignore_system_config_from_debug_env() -> bool {
    bool_from_debug_env(IGNORE_SYSTEM_CONFIG_ENV_VAR)
}

#[cfg(not(debug_assertions))]
fn ignore_system_config_from_debug_env() -> bool {
    false
}

#[cfg(debug_assertions)]
fn ignore_system_requirements_from_debug_env() -> bool {
    bool_from_debug_env(IGNORE_SYSTEM_REQUIREMENTS_ENV_VAR)
}

#[cfg(not(debug_assertions))]
fn ignore_system_requirements_from_debug_env() -> bool {
    false
}

#[cfg(debug_assertions)]
fn bool_from_debug_env(name: &str) -> bool {
    if let Ok(value) = std::env::var(name) {
        return matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    false
}
