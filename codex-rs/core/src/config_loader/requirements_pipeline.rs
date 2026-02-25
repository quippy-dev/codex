use super::*;

pub(super) async fn load_config_requirements_with_sources(
    overrides: &LoaderOverrides,
    cloud_requirements: CloudRequirementsLoader,
) -> io::Result<ConfigRequirementsWithSources> {
    let mut config_requirements_toml = ConfigRequirementsWithSources::default();

    if let Some(requirements) = cloud_requirements.get().await {
        config_requirements_toml
            .merge_unset_fields(RequirementSource::CloudRequirements, requirements);
    }

    #[cfg(target_os = "macos")]
    macos::load_managed_admin_requirements_toml(
        &mut config_requirements_toml,
        overrides
            .macos_managed_config_requirements_base64
            .as_deref(),
    )
    .await?;

    Ok(config_requirements_toml)
}

pub(super) async fn merge_system_and_legacy_requirements(
    config_requirements_toml: &mut ConfigRequirementsWithSources,
    system_requirements_toml_file_override: Option<AbsolutePathBuf>,
    loaded_config_layers: LoadedConfigLayers,
) -> io::Result<()> {
    let requirements_toml_file =
        system_requirements_toml_file_override.unwrap_or(system_requirements_toml_file()?);
    load_requirements_toml(config_requirements_toml, requirements_toml_file).await?;
    load_requirements_from_legacy_scheme(config_requirements_toml, loaded_config_layers).await?;
    Ok(())
}
