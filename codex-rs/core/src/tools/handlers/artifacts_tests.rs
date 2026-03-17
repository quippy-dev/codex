use super::*;
use crate::exec::StreamOutput;
use codex_artifacts::RuntimeEntrypoints;
use codex_artifacts::RuntimePathEntry;
use tempfile::TempDir;

#[test]
fn parse_freeform_args_without_pragma() {
    let args = parse_freeform_args("console.log('ok');").expect("parse args");
    assert_eq!(args.source, "console.log('ok');");
    assert_eq!(args.timeout_ms, None);
}

#[test]
fn parse_freeform_args_with_pragma() {
    let args = parse_freeform_args("// codex-artifacts: timeout_ms=45000\nconsole.log('ok');")
        .expect("parse args");
    assert_eq!(args.source, "console.log('ok');");
    assert_eq!(args.timeout_ms, Some(45_000));
}

#[test]
fn parse_freeform_args_with_artifact_tool_pragma() {
    let args = parse_freeform_args("// codex-artifact-tool: timeout_ms=45000\nconsole.log('ok');")
        .expect("parse args");
    assert_eq!(args.source, "console.log('ok');");
    assert_eq!(args.timeout_ms, Some(45_000));
}

#[test]
fn parse_freeform_args_rejects_json_wrapped_code() {
    let err = parse_freeform_args("{\"code\":\"console.log('ok')\"}").expect_err("expected error");
    assert!(
        err.to_string()
            .contains("artifacts is a freeform tool and expects raw JavaScript source")
    );
}

#[test]
fn load_pinned_runtime_requires_cached_runtime() {
    let codex_home = TempDir::new().expect("create temp codex home");
    let error = load_pinned_runtime(codex_home.path()).expect_err("missing runtime should fail");

    assert!(
        error
            .to_string()
            .contains("will not download or install them during tool execution"),
        "unexpected error: {error}"
    );
}

#[test]
fn load_pinned_runtime_reads_pinned_cache_path() {
    let codex_home = TempDir::new().expect("create temp codex home");
    let platform =
        codex_artifacts::ArtifactRuntimePlatform::detect_current().expect("detect platform");
    let install_dir = codex_home
        .path()
        .join("packages")
        .join("artifacts")
        .join(PINNED_ARTIFACT_RUNTIME_VERSION)
        .join(platform.as_str());
    std::fs::create_dir_all(&install_dir).expect("create install dir");
    std::fs::write(
        install_dir.join("manifest.json"),
        serde_json::json!({
            "schema_version": 1,
            "runtime_version": PINNED_ARTIFACT_RUNTIME_VERSION,
            "node": { "relative_path": "node/bin/node" },
            "entrypoints": {
                "build_js": { "relative_path": "artifact-tool/dist/artifact_tool.mjs" },
                "render_cli": { "relative_path": "granola-render/dist/render_cli.mjs" }
            }
        })
        .to_string(),
    )
    .expect("write manifest");
    std::fs::create_dir_all(install_dir.join("artifact-tool/dist"))
        .expect("create build entrypoint dir");
    std::fs::create_dir_all(install_dir.join("granola-render/dist"))
        .expect("create render entrypoint dir");
    std::fs::write(
        install_dir.join("artifact-tool/dist/artifact_tool.mjs"),
        "export const ok = true;\n",
    )
    .expect("write build entrypoint");
    std::fs::write(
        install_dir.join("granola-render/dist/render_cli.mjs"),
        "export const ok = true;\n",
    )
    .expect("write render entrypoint");

    let runtime = load_pinned_runtime(codex_home.path()).expect("resolve runtime");
    assert_eq!(runtime.runtime_version(), PINNED_ARTIFACT_RUNTIME_VERSION);
    assert_eq!(
        runtime.manifest().entrypoints,
        RuntimeEntrypoints {
            build_js: RuntimePathEntry {
                relative_path: "artifact-tool/dist/artifact_tool.mjs".to_string(),
            },
            render_cli: RuntimePathEntry {
                relative_path: "granola-render/dist/render_cli.mjs".to_string(),
            },
        }
    );
}

#[test]
fn format_artifact_output_includes_success_message_when_silent() {
    let formatted = format_artifact_output(&ExecToolCallOutput {
        exit_code: 0,
        stdout: StreamOutput::new(String::new()),
        stderr: StreamOutput::new(String::new()),
        aggregated_output: StreamOutput::new(String::new()),
        duration: Duration::ZERO,
        timed_out: false,
    });
    assert!(formatted.contains("artifact JS completed successfully."));
}

#[test]
fn format_artifact_output_includes_timeout_message() {
    let formatted = format_artifact_output(&ExecToolCallOutput {
        exit_code: 124,
        stdout: StreamOutput::new(String::new()),
        stderr: StreamOutput::new("render hung".to_string()),
        aggregated_output: StreamOutput::new("render hung".to_string()),
        duration: Duration::from_millis(1_500),
        timed_out: true,
    });

    assert!(formatted.contains("command timed out after 1500 milliseconds"));
    assert!(formatted.contains("render hung"));
}

#[test]
fn artifact_prefix_rule_uses_stable_launcher_prefix() {
    let command = build_artifact_build_command(
        Path::new("/runtime/node"),
        Path::new("/codex/home/runtime-scripts/artifacts/build-launcher.mjs"),
        Path::new("/tmp/artifact-source.mjs"),
    );

    assert_eq!(
        artifact_prefix_rule(&command),
        vec![
            "/runtime/node".to_string(),
            "/codex/home/runtime-scripts/artifacts/build-launcher.mjs".to_string(),
        ]
    );
}

#[test]
fn artifact_display_command_is_user_facing() {
    assert_eq!(artifact_display_command(), vec!["artifacts".to_string()]);
}

#[test]
fn build_artifact_env_includes_required_entrypoints() {
    let runtime = codex_artifacts::InstalledArtifactRuntime::new(
        PathBuf::from("/runtime"),
        PINNED_ARTIFACT_RUNTIME_VERSION.to_string(),
        codex_artifacts::ArtifactRuntimePlatform::detect_current().expect("detect platform"),
        codex_artifacts::ExtractedRuntimeManifest {
            schema_version: 1,
            runtime_version: PINNED_ARTIFACT_RUNTIME_VERSION.to_string(),
            node: RuntimePathEntry {
                relative_path: "node/bin/node".to_string(),
            },
            entrypoints: RuntimeEntrypoints {
                build_js: RuntimePathEntry {
                    relative_path: "artifact-tool/dist/artifact_tool.mjs".to_string(),
                },
                render_cli: RuntimePathEntry {
                    relative_path: "granola-render/dist/render_cli.mjs".to_string(),
                },
            },
        },
        PathBuf::from("/runtime/node/bin/node"),
        PathBuf::from("/runtime/artifact-tool/dist/artifact_tool.mjs"),
        PathBuf::from("/runtime/granola-render/dist/render_cli.mjs"),
    );

    let env = build_artifact_env(&runtime, false);

    assert_eq!(
        env.get("CODEX_ARTIFACT_BUILD_ENTRYPOINT"),
        Some(&"/runtime/artifact-tool/dist/artifact_tool.mjs".to_string())
    );
    assert_eq!(
        env.get("CODEX_ARTIFACT_RENDER_ENTRYPOINT"),
        Some(&"/runtime/granola-render/dist/render_cli.mjs".to_string())
    );
    assert!(
        !env.contains_key("ELECTRON_RUN_AS_NODE"),
        "node runtime should not require ELECTRON_RUN_AS_NODE"
    );
}

#[test]
fn build_artifact_env_sets_electron_run_as_node_when_required() {
    let runtime = codex_artifacts::InstalledArtifactRuntime::new(
        PathBuf::from("/runtime"),
        PINNED_ARTIFACT_RUNTIME_VERSION.to_string(),
        codex_artifacts::ArtifactRuntimePlatform::detect_current().expect("detect platform"),
        codex_artifacts::ExtractedRuntimeManifest {
            schema_version: 1,
            runtime_version: PINNED_ARTIFACT_RUNTIME_VERSION.to_string(),
            node: RuntimePathEntry {
                relative_path: "node/bin/node".to_string(),
            },
            entrypoints: RuntimeEntrypoints {
                build_js: RuntimePathEntry {
                    relative_path: "artifact-tool/dist/artifact_tool.mjs".to_string(),
                },
                render_cli: RuntimePathEntry {
                    relative_path: "granola-render/dist/render_cli.mjs".to_string(),
                },
            },
        },
        PathBuf::from("/runtime/node/bin/node"),
        PathBuf::from("/runtime/artifact-tool/dist/artifact_tool.mjs"),
        PathBuf::from("/runtime/granola-render/dist/render_cli.mjs"),
    );

    let env = build_artifact_env(&runtime, true);

    assert_eq!(env.get("ELECTRON_RUN_AS_NODE"), Some(&"1".to_string()));
}

#[tokio::test]
async fn ensure_artifact_build_launcher_writes_expected_source() {
    let codex_home = TempDir::new().expect("create temp codex home");

    let launcher_path = ensure_artifact_build_launcher(codex_home.path())
        .await
        .expect("write launcher");

    assert_eq!(
        launcher_path,
        codex_home.path().join(ARTIFACT_BUILD_LAUNCHER_RELATIVE)
    );
    let launcher_source =
        std::fs::read_to_string(&launcher_path).expect("read artifact launcher source");
    assert!(launcher_source.contains("globalThis.artifacts = artifactTool;"));
    assert!(launcher_source.contains("await import(pathToFileURL(sourcePath).href);"));
}
