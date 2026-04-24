use super::*;

pub(super) async fn load_config_requirements_with_sources(
    _fs: &dyn ExecutorFileSystem,
    _codex_home: &AbsolutePathBuf,
    overrides: &LoaderOverrides,
    host_name: Option<&str>,
    cloud_requirements: CloudRequirementsLoader,
) -> io::Result<ConfigRequirementsWithSources> {
    let mut config_requirements_toml = ConfigRequirementsWithSources::default();

    if let Some(requirements) = cloud_requirements.get().await.map_err(io::Error::other)? {
        config_requirements_toml
            .merge_unset_fields(RequirementSource::CloudRequirements, requirements);
    }

    #[cfg(target_os = "macos")]
    macos::load_managed_admin_requirements_toml(
        &mut config_requirements_toml,
        overrides
            .macos_managed_config_requirements_base64
            .as_deref(),
        host_name,
    )
    .await?;

    Ok(config_requirements_toml)
}

pub(super) async fn merge_system_and_legacy_requirements(
    fs: &dyn ExecutorFileSystem,
    codex_home: &AbsolutePathBuf,
    host_name: Option<&str>,
    config_requirements_toml: &mut ConfigRequirementsWithSources,
    system_requirements_toml_file_override: Option<AbsolutePathBuf>,
) -> io::Result<()> {
    let requirements_toml_file =
        system_requirements_toml_file_override.unwrap_or(system_requirements_toml_file()?);
    load_requirements_toml(
        fs,
        config_requirements_toml,
        &requirements_toml_file,
        host_name,
    )
    .await?;
    let loaded_config_layers =
        layer_io::load_config_layers_internal(fs, codex_home, LoaderOverrides::default()).await?;
    load_requirements_from_legacy_scheme(config_requirements_toml, loaded_config_layers, host_name)
        .await?;
    Ok(())
}
