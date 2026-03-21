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
            Config::load_default_with_cli_overrides(cli_kv_overrides.clone()).map_err(|e| {
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
