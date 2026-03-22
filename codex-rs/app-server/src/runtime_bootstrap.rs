use super::*;
use codex_core::auth::AuthFileRuntime;

pub(crate) struct RuntimeBootstrap {
    pub(crate) cli_kv_overrides: Vec<(String, TomlValue)>,
    pub(crate) cloud_requirements: CloudRequirementsLoader,
    pub(crate) config: Config,
    pub(crate) config_warnings: Vec<ConfigWarningNotification>,
    pub(crate) auth_storage_home: PathBuf,
    pub(crate) loader_overrides_for_config_api: LoaderOverrides,
}

pub(crate) async fn prepare_runtime_bootstrap(
    cli_config_overrides: &CliConfigOverrides,
    loader_overrides: LoaderOverrides,
    auth_file: Option<PathBuf>,
) -> IoResult<RuntimeBootstrap> {
    let cli_kv_overrides = cli_config_overrides.parse_overrides().map_err(|e| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("error parsing -c overrides: {e}"),
        )
    })?;

    let cloud_requirements = match ConfigBuilder::default()
        .cli_overrides(cli_kv_overrides.clone())
        .loader_overrides(loader_overrides.clone())
        .build()
        .await
    {
        Ok(config) => {
            let effective_toml = config.config_layer_stack.effective_config();
            match effective_toml.try_into() {
                Ok(config_toml) => {
                    if let Err(err) = codex_core::personality_migration::maybe_migrate_personality(
                        &config.codex_home,
                        &config_toml,
                    )
                    .await
                    {
                        warn!(error = %err, "Failed to run personality migration");
                    }
                }
                Err(err) => {
                    warn!(error = %err, "Failed to deserialize config for personality migration");
                }
            }

            let auth_runtime = AuthFileRuntime::new(
                config.codex_home.clone(),
                config.cli_auth_credentials_store_mode,
                auth_file.clone(),
            )?;
            let auth_manager = auth_runtime.shared_auth_manager(false)?;
            cloud_requirements_loader(
                auth_manager,
                config.chatgpt_base_url,
                config.codex_home.clone(),
            )
        }
        Err(err) => {
            warn!(error = %err, "Failed to preload config for cloud requirements");
            CloudRequirementsLoader::default()
        }
    };

    let loader_overrides_for_config_api = loader_overrides.clone();
    let mut config_warnings = Vec::new();
    let config = match ConfigBuilder::default()
        .cli_overrides(cli_kv_overrides.clone())
        .loader_overrides(loader_overrides)
        .cloud_requirements(cloud_requirements.clone())
        .build()
        .await
    {
        Ok(config) => config,
        Err(err) => {
            let message = config_warning_from_error("Invalid configuration; using defaults.", &err);
            config_warnings.push(message);
            Config::load_default_with_cli_overrides_and_loader_overrides(
                cli_kv_overrides.clone(),
                loader_overrides_for_config_api.clone(),
                cloud_requirements.clone(),
            )
            .await
            .map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("error loading default config after config error: {e}"),
                )
            })?
        }
    };

    let auth_storage_home = AuthFileRuntime::new(
        config.codex_home.clone(),
        config.cli_auth_credentials_store_mode,
        auth_file,
    )?
    .into_auth_storage_home();

    Ok(RuntimeBootstrap {
        cli_kv_overrides,
        cloud_requirements,
        config,
        config_warnings,
        auth_storage_home,
        loader_overrides_for_config_api,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_app_server_protocol::ConfigLayerSource;
    use codex_core::config::CONFIG_TOML_FILE;
    use codex_core::config_loader::ConfigLayerStackOrdering;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            unsafe { std::env::set_var(key, value) };
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(original) = self.original.take() {
                unsafe { std::env::set_var(self.key, original) };
            } else {
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    #[tokio::test]
    async fn prepare_runtime_bootstrap_preserves_loader_overrides_on_default_fallback()
    -> std::io::Result<()> {
        let codex_home = TempDir::new()?;
        let managed_config = TempDir::new()?;
        let managed_config_path = managed_config.path().join("managed_config.toml");
        std::fs::write(&managed_config_path, "invalid = [")?;
        std::fs::write(codex_home.path().join(CONFIG_TOML_FILE), "invalid = [")?;
        let _guard = EnvVarGuard::set("CODEX_HOME", codex_home.path().to_string_lossy().as_ref());
        let loader_overrides = LoaderOverrides {
            managed_config_path: Some(managed_config_path.clone()),
            ..LoaderOverrides::default()
        };

        let bootstrap = prepare_runtime_bootstrap(
            &CliConfigOverrides::default(),
            loader_overrides.clone(),
            None,
        )
        .await?;

        assert_eq!(
            bootstrap
                .loader_overrides_for_config_api
                .managed_config_path,
            loader_overrides.managed_config_path,
        );
        assert!(
            bootstrap
                .config_warnings
                .iter()
                .any(|warning| warning.summary.contains("using defaults")),
            "fallback should warn and continue"
        );
        assert!(
            bootstrap
                .config
                .config_layer_stack
                .get_layers(
                    ConfigLayerStackOrdering::LowestPrecedenceFirst,
                    /*include_disabled*/ false,
                )
                .iter()
                .any(|layer| {
                    matches!(
                        &layer.name,
                        ConfigLayerSource::LegacyManagedConfigTomlFromFile { file }
                            if file.as_path() == managed_config_path.as_path()
                    )
                }),
            "managed config layer should survive default fallback"
        );

        Ok(())
    }
}
