use async_trait::async_trait;
use codex_artifacts::InstalledArtifactRuntime;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;
use tokio::fs;

use crate::exec::ExecToolCallOutput;
use crate::exec_policy::ExecApprovalRequest;
use crate::features::Feature;
use crate::function_tool::FunctionCallError;
use crate::protocol::ExecCommandSource;
use crate::sandboxing::SandboxPermissions;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::events::ToolEmitter;
use crate::tools::events::ToolEventCtx;
use crate::tools::events::ToolEventFailure;
use crate::tools::events::ToolEventStage;
use crate::tools::orchestrator::ToolOrchestrator;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;
use crate::tools::runtimes::artifacts::ArtifactApprovalKey;
use crate::tools::runtimes::artifacts::ArtifactExecRequest;
use crate::tools::runtimes::artifacts::ArtifactRuntime;
use crate::tools::sandboxing::ToolError;

const ARTIFACTS_TOOL_NAME: &str = "artifacts";
const ARTIFACTS_PRAGMA_PREFIXES: [&str; 2] = ["// codex-artifacts:", "// codex-artifact-tool:"];
pub(crate) const PINNED_ARTIFACT_RUNTIME_VERSION: &str = "2.4.0";
const DEFAULT_EXECUTION_TIMEOUT: Duration = Duration::from_secs(30);
const ARTIFACT_BUILD_LAUNCHER_RELATIVE: &str = "runtime-scripts/artifacts/build-launcher.mjs";
const ARTIFACT_BUILD_LAUNCHER_SOURCE: &str = concat!(
    "import { pathToFileURL } from \"node:url\";\n",
    "const [sourcePath] = process.argv.slice(2);\n",
    "if (!sourcePath) {\n",
    "  throw new Error(\"missing artifact source path\");\n",
    "}\n",
    "const artifactTool = await import(pathToFileURL(process.env.CODEX_ARTIFACT_BUILD_ENTRYPOINT).href);\n",
    "globalThis.artifactTool = artifactTool;\n",
    "globalThis.artifacts = artifactTool;\n",
    "globalThis.codexArtifacts = artifactTool;\n",
    "for (const [name, value] of Object.entries(artifactTool)) {\n",
    "  if (name === \"default\" || Object.prototype.hasOwnProperty.call(globalThis, name)) {\n",
    "    continue;\n",
    "  }\n",
    "  globalThis[name] = value;\n",
    "}\n",
    "await import(pathToFileURL(sourcePath).href);\n",
);

pub struct ArtifactsHandler;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactsToolArgs {
    source: String,
    timeout_ms: Option<u64>,
}

struct PreparedArtifactBuild {
    request: ArtifactExecRequest,
    _source_dir: TempDir,
}

#[async_trait]
impl ToolHandler for ArtifactsHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    fn matches_kind(&self, payload: &ToolPayload) -> bool {
        matches!(payload, ToolPayload::Custom { .. })
    }

    async fn is_mutating(&self, _invocation: &ToolInvocation) -> bool {
        true
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation {
            session,
            turn,
            payload,
            call_id,
            ..
        } = invocation;

        if !session.enabled(Feature::Artifact) {
            return Err(FunctionCallError::RespondToModel(
                "artifacts is disabled by feature flag".to_string(),
            ));
        }

        let args = match payload {
            ToolPayload::Custom { input } => parse_freeform_args(&input)?,
            _ => {
                return Err(FunctionCallError::RespondToModel(
                    "artifacts expects freeform JavaScript input authored against the preloaded @oai/artifact-tool surface".to_string(),
                ));
            }
        };

        let prepared = prepare_artifact_build(
            session.as_ref(),
            turn.as_ref(),
            args.source,
            args.timeout_ms
                .unwrap_or(DEFAULT_EXECUTION_TIMEOUT.as_millis() as u64),
        )
        .await?;
        let emitter = ToolEmitter::shell(
            artifact_display_command(),
            prepared.request.cwd.clone(),
            ExecCommandSource::Agent,
            true,
        );
        let event_ctx = ToolEventCtx::new(session.as_ref(), turn.as_ref(), &call_id, None);
        emitter.begin(event_ctx).await;

        let mut orchestrator = ToolOrchestrator::new();
        let mut runtime = ArtifactRuntime;
        let tool_ctx = crate::tools::sandboxing::ToolCtx {
            session: session.clone(),
            turn: turn.clone(),
            call_id: call_id.clone(),
            tool_name: ARTIFACTS_TOOL_NAME.to_string(),
        };
        let result = orchestrator
            .run(
                &mut runtime,
                &prepared.request,
                &tool_ctx,
                &turn,
                turn.approval_policy.value(),
            )
            .await
            .map(|result| result.output);

        Ok(finish_artifact_execution(&emitter, event_ctx, result).await)
    }
}

fn parse_freeform_args(input: &str) -> Result<ArtifactsToolArgs, FunctionCallError> {
    if input.trim().is_empty() {
        return Err(FunctionCallError::RespondToModel(
            "artifacts expects raw JavaScript source text (non-empty) authored against the preloaded @oai/artifact-tool surface. Provide JS only, optionally with first-line `// codex-artifacts: timeout_ms=15000` or `// codex-artifact-tool: timeout_ms=15000`."
                .to_string(),
        ));
    }

    let mut args = ArtifactsToolArgs {
        source: input.to_string(),
        timeout_ms: None,
    };

    let mut lines = input.splitn(2, '\n');
    let first_line = lines.next().unwrap_or_default();
    let rest = lines.next().unwrap_or_default();
    let trimmed = first_line.trim_start();
    let Some(pragma) = parse_pragma_prefix(trimmed) else {
        reject_json_or_quoted_source(&args.source)?;
        return Ok(args);
    };

    let mut timeout_ms = None;
    let directive = pragma.trim();
    if !directive.is_empty() {
        for token in directive.split_whitespace() {
            let (key, value) = token.split_once('=').ok_or_else(|| {
                FunctionCallError::RespondToModel(format!(
                    "artifacts pragma expects space-separated key=value pairs (supported keys: timeout_ms); got `{token}`"
                ))
            })?;
            match key {
                "timeout_ms" => {
                    if timeout_ms.is_some() {
                        return Err(FunctionCallError::RespondToModel(
                            "artifacts pragma specifies timeout_ms more than once".to_string(),
                        ));
                    }
                    let parsed = value.parse::<u64>().map_err(|_| {
                        FunctionCallError::RespondToModel(format!(
                            "artifacts pragma timeout_ms must be an integer; got `{value}`"
                        ))
                    })?;
                    timeout_ms = Some(parsed);
                }
                _ => {
                    return Err(FunctionCallError::RespondToModel(format!(
                        "artifacts pragma only supports timeout_ms; got `{key}`"
                    )));
                }
            }
        }
    }

    if rest.trim().is_empty() {
        return Err(FunctionCallError::RespondToModel(
            "artifacts pragma must be followed by JavaScript source on subsequent lines"
                .to_string(),
        ));
    }

    reject_json_or_quoted_source(rest)?;
    args.source = rest.to_string();
    args.timeout_ms = timeout_ms;
    Ok(args)
}

fn reject_json_or_quoted_source(code: &str) -> Result<(), FunctionCallError> {
    let trimmed = code.trim();
    if trimmed.starts_with("```") {
        return Err(FunctionCallError::RespondToModel(
            "artifacts expects raw JavaScript source, not markdown code fences. Resend plain JS only (optional first line `// codex-artifacts: ...` or `// codex-artifact-tool: ...`)."
                .to_string(),
        ));
    }
    let Ok(value) = serde_json::from_str::<JsonValue>(trimmed) else {
        return Ok(());
    };
    match value {
        JsonValue::Object(_) | JsonValue::String(_) => Err(FunctionCallError::RespondToModel(
            "artifacts is a freeform tool and expects raw JavaScript source authored against the preloaded @oai/artifact-tool surface. Resend plain JS only (optional first line `// codex-artifacts: ...` or `// codex-artifact-tool: ...`); do not send JSON (`{\"code\":...}`), quoted code, or markdown fences."
                .to_string(),
        )),
        _ => Ok(()),
    }
}

fn parse_pragma_prefix(line: &str) -> Option<&str> {
    ARTIFACTS_PRAGMA_PREFIXES
        .iter()
        .find_map(|prefix| line.strip_prefix(prefix))
}

async fn prepare_artifact_build(
    session: &crate::codex::Session,
    turn: &crate::codex::TurnContext,
    source: String,
    timeout_ms: u64,
) -> Result<PreparedArtifactBuild, FunctionCallError> {
    let installed_runtime = load_pinned_runtime(turn.config.codex_home.as_path())?;
    let launcher_path = ensure_artifact_build_launcher(turn.config.codex_home.as_path()).await?;
    let source_dir = TempDir::new().map_err(|error| {
        FunctionCallError::RespondToModel(format!(
            "failed to create artifact source staging directory: {error}"
        ))
    })?;
    let source_path = source_dir.path().join("artifact-source.mjs");
    fs::write(&source_path, source).await.map_err(|error| {
        FunctionCallError::RespondToModel(format!(
            "failed to write artifact source at `{}`: {error}",
            source_path.display()
        ))
    })?;

    let js_runtime = installed_runtime
        .resolve_js_runtime()
        .map_err(|error| FunctionCallError::RespondToModel(error.to_string()))?;
    let command =
        build_artifact_build_command(js_runtime.executable_path(), &launcher_path, &source_path);
    let approval_key = ArtifactApprovalKey {
        command_prefix: artifact_prefix_rule(&command),
        cwd: turn.cwd.clone(),
    };
    let escalation_approval_requirement = session
        .services
        .exec_policy
        .create_exec_approval_requirement_for_command(ExecApprovalRequest {
            command: &command,
            approval_policy: turn.approval_policy.value(),
            sandbox_policy: turn.sandbox_policy.get(),
            file_system_sandbox_policy: &turn.file_system_sandbox_policy,
            sandbox_permissions: SandboxPermissions::RequireEscalated,
            prefix_rule: Some(approval_key.command_prefix.clone()),
        })
        .await;

    let env = build_artifact_env(
        &installed_runtime,
        js_runtime.requires_electron_run_as_node(),
    );

    Ok(PreparedArtifactBuild {
        request: ArtifactExecRequest {
            command,
            cwd: turn.cwd.clone(),
            timeout_ms: Some(timeout_ms),
            env,
            approval_key,
            escalation_approval_requirement,
        },
        _source_dir: source_dir,
    })
}

fn load_pinned_runtime(codex_home: &Path) -> Result<InstalledArtifactRuntime, FunctionCallError> {
    let cache_root = codex_home.join(codex_artifacts::DEFAULT_CACHE_ROOT_RELATIVE);
    codex_artifacts::load_cached_runtime(&cache_root, PINNED_ARTIFACT_RUNTIME_VERSION).map_err(
        |error| {
            FunctionCallError::RespondToModel(format!(
                "artifacts runtime {PINNED_ARTIFACT_RUNTIME_VERSION} is not installed locally under `{}`. artifacts only uses cached runtime assets and will not download or install them during tool execution. Preinstall the pinned runtime and retry. {error}",
                cache_root.display()
            ))
        },
    )
}

async fn ensure_artifact_build_launcher(codex_home: &Path) -> Result<PathBuf, FunctionCallError> {
    let launcher_path = artifact_build_launcher_path(codex_home);
    match fs::read_to_string(&launcher_path).await {
        Ok(existing) if existing == ARTIFACT_BUILD_LAUNCHER_SOURCE => return Ok(launcher_path),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(FunctionCallError::RespondToModel(format!(
                "failed to read artifact launcher `{}`: {error}",
                launcher_path.display()
            )));
        }
    }

    if let Some(parent) = launcher_path.parent() {
        fs::create_dir_all(parent).await.map_err(|error| {
            FunctionCallError::RespondToModel(format!(
                "failed to create artifact launcher directory `{}`: {error}",
                parent.display()
            ))
        })?;
    }
    fs::write(&launcher_path, ARTIFACT_BUILD_LAUNCHER_SOURCE)
        .await
        .map_err(|error| {
            FunctionCallError::RespondToModel(format!(
                "failed to write artifact launcher `{}`: {error}",
                launcher_path.display()
            ))
        })?;

    Ok(launcher_path)
}

fn artifact_build_launcher_path(codex_home: &Path) -> PathBuf {
    codex_home.join(ARTIFACT_BUILD_LAUNCHER_RELATIVE)
}

fn build_artifact_build_command(
    executable_path: &Path,
    launcher_path: &Path,
    source_path: &Path,
) -> Vec<String> {
    vec![
        executable_path.display().to_string(),
        launcher_path.display().to_string(),
        source_path.display().to_string(),
    ]
}

fn artifact_prefix_rule(command: &[String]) -> Vec<String> {
    command.iter().take(2).cloned().collect()
}

fn artifact_display_command() -> Vec<String> {
    vec![ARTIFACTS_TOOL_NAME.to_string()]
}

fn build_artifact_env(
    installed_runtime: &codex_artifacts::InstalledArtifactRuntime,
    requires_electron_run_as_node: bool,
) -> HashMap<String, String> {
    let mut env = HashMap::from([
        (
            "CODEX_ARTIFACT_BUILD_ENTRYPOINT".to_string(),
            installed_runtime.build_js_path().display().to_string(),
        ),
        (
            "CODEX_ARTIFACT_RENDER_ENTRYPOINT".to_string(),
            installed_runtime.render_cli_path().display().to_string(),
        ),
    ]);
    if requires_electron_run_as_node {
        env.insert("ELECTRON_RUN_AS_NODE".to_string(), "1".to_string());
    }
    env
}

async fn finish_artifact_execution(
    emitter: &ToolEmitter,
    event_ctx: ToolEventCtx<'_>,
    result: Result<ExecToolCallOutput, ToolError>,
) -> FunctionToolOutput {
    let (body, success, stage) = match result {
        Ok(output) => {
            let success = output.exit_code == 0;
            let body = format_artifact_output(&output);
            let stage = if success {
                ToolEventStage::Success(output)
            } else {
                ToolEventStage::Failure(ToolEventFailure::Output(output))
            };
            (body, success, stage)
        }
        Err(ToolError::Codex(crate::error::CodexErr::Sandbox(
            crate::error::SandboxErr::Timeout { output },
        )))
        | Err(ToolError::Codex(crate::error::CodexErr::Sandbox(
            crate::error::SandboxErr::Denied { output, .. },
        ))) => {
            let output = *output;
            let body = format_artifact_output(&output);
            (
                body,
                false,
                ToolEventStage::Failure(ToolEventFailure::Output(output)),
            )
        }
        Err(ToolError::Codex(error)) => {
            let message = format!("execution error: {error:?}");
            (
                message.clone(),
                false,
                ToolEventStage::Failure(ToolEventFailure::Message(message)),
            )
        }
        Err(ToolError::Rejected(message)) => {
            let normalized = if message == "rejected by user" {
                "artifact command rejected by user".to_string()
            } else {
                message
            };
            (
                normalized.clone(),
                false,
                ToolEventStage::Failure(ToolEventFailure::Rejected(normalized)),
            )
        }
    };
    emitter.emit(event_ctx, stage).await;

    FunctionToolOutput::from_text(body, Some(success))
}

fn format_artifact_output(output: &ExecToolCallOutput) -> String {
    let stdout = output.stdout.text.trim();
    let stderr = format_artifact_stderr(output);
    let mut sections = vec![format!("exit_code: {}", output.exit_code)];
    if !stdout.is_empty() {
        sections.push(format!("stdout:\n{stdout}"));
    }
    if !stderr.is_empty() {
        sections.push(format!("stderr:\n{stderr}"));
    }
    if stdout.is_empty() && stderr.is_empty() && output.exit_code == 0 {
        sections.push("artifact JS completed successfully.".to_string());
    }
    sections.join("\n\n")
}

fn format_artifact_stderr(output: &ExecToolCallOutput) -> String {
    let stderr = output.stderr.text.trim();
    if output.timed_out {
        let timeout_message = format!(
            "command timed out after {} milliseconds",
            output.duration.as_millis()
        );
        if stderr.is_empty() {
            timeout_message
        } else {
            format!("{timeout_message}\n{stderr}")
        }
    } else {
        stderr.to_string()
    }
}

#[cfg(test)]
#[path = "artifacts_tests.rs"]
mod tests;
