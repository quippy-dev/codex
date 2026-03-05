use crate::codex::Session;
use crate::exec::ExecToolCallOutput;
use crate::sandboxing::SandboxPermissions;
use crate::sandboxing::execute_env;
use crate::tools::runtimes::build_command_spec;
use crate::tools::sandboxing::Approvable;
use crate::tools::sandboxing::ApprovalCtx;
use crate::tools::sandboxing::ExecApprovalRequirement;
use crate::tools::sandboxing::SandboxAttempt;
use crate::tools::sandboxing::Sandboxable;
use crate::tools::sandboxing::SandboxablePreference;
use crate::tools::sandboxing::ToolCtx;
use crate::tools::sandboxing::ToolError;
use crate::tools::sandboxing::ToolRuntime;
use crate::tools::sandboxing::with_cached_approval;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::ReviewDecision;
use futures::future::BoxFuture;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub(crate) struct ArtifactApprovalKey {
    pub(crate) command_prefix: Vec<String>,
    pub(crate) cwd: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct ArtifactExecRequest {
    pub(crate) command: Vec<String>,
    pub(crate) cwd: PathBuf,
    pub(crate) timeout_ms: Option<u64>,
    pub(crate) env: HashMap<String, String>,
    pub(crate) approval_key: ArtifactApprovalKey,
    pub(crate) escalation_approval_requirement: ExecApprovalRequirement,
}

#[derive(Default)]
pub(crate) struct ArtifactRuntime;

impl ArtifactRuntime {
    fn stdout_stream(ctx: &ToolCtx) -> Option<crate::exec::StdoutStream> {
        Some(crate::exec::StdoutStream {
            sub_id: ctx.turn.sub_id.clone(),
            call_id: ctx.call_id.clone(),
            tx_event: ctx.session.get_tx_event(),
        })
    }
}

impl Sandboxable for ArtifactRuntime {
    fn sandbox_preference(&self) -> SandboxablePreference {
        SandboxablePreference::Auto
    }
}

impl Approvable<ArtifactExecRequest> for ArtifactRuntime {
    type ApprovalKey = ArtifactApprovalKey;

    fn approval_keys(&self, req: &ArtifactExecRequest) -> Vec<Self::ApprovalKey> {
        vec![req.approval_key.clone()]
    }

    fn start_approval_async<'a>(
        &'a mut self,
        req: &'a ArtifactExecRequest,
        ctx: ApprovalCtx<'a>,
    ) -> BoxFuture<'a, ReviewDecision> {
        let session: &'a Session = ctx.session;
        let turn = ctx.turn;
        let call_id = ctx.call_id.to_string();
        let retry_reason = ctx.retry_reason.clone();
        let command = req.command.clone();
        let cwd = req.cwd.clone();
        let approval_keys = self.approval_keys(req);
        let escalation_approval_requirement = req.escalation_approval_requirement.clone();
        Box::pin(async move {
            if matches!(
                escalation_approval_requirement,
                ExecApprovalRequirement::Forbidden { .. }
            ) {
                return ReviewDecision::Denied;
            }

            if retry_reason.is_some()
                && matches!(
                    escalation_approval_requirement,
                    ExecApprovalRequirement::Skip { .. }
                )
            {
                return ReviewDecision::Approved;
            }

            with_cached_approval(
                &session.services,
                "artifacts",
                approval_keys,
                || async move {
                    session
                        .request_command_approval(
                            turn,
                            call_id,
                            None,
                            command,
                            cwd,
                            retry_reason,
                            None,
                            escalation_approval_requirement
                                .proposed_execpolicy_amendment()
                                .cloned(),
                            None,
                            None,
                        )
                        .await
                },
            )
            .await
        })
    }

    fn wants_no_sandbox_approval(&self, policy: AskForApproval) -> bool {
        match policy {
            AskForApproval::Never => false,
            AskForApproval::Reject(reject_config) => !reject_config.rejects_sandbox_approval(),
            AskForApproval::OnFailure => true,
            AskForApproval::OnRequest => true,
            AskForApproval::UnlessTrusted => true,
        }
    }

    fn exec_approval_requirement(
        &self,
        _req: &ArtifactExecRequest,
    ) -> Option<ExecApprovalRequirement> {
        Some(ExecApprovalRequirement::Skip {
            bypass_sandbox: false,
            proposed_execpolicy_amendment: None,
        })
    }
}

impl ToolRuntime<ArtifactExecRequest, ExecToolCallOutput> for ArtifactRuntime {
    async fn run(
        &mut self,
        req: &ArtifactExecRequest,
        attempt: &SandboxAttempt<'_>,
        ctx: &ToolCtx,
    ) -> Result<ExecToolCallOutput, ToolError> {
        let spec = build_command_spec(
            &req.command,
            &req.cwd,
            &req.env,
            req.timeout_ms.into(),
            SandboxPermissions::UseDefault,
            None,
            None,
        )?;
        let env = attempt
            .env_for(spec, None)
            .map_err(|err| ToolError::Codex(err.into()))?;
        execute_env(env, Self::stdout_stream(ctx))
            .await
            .map_err(ToolError::Codex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codex::make_session_and_context;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn auto_approves_retry_when_exec_policy_already_allows_launcher() {
        let (session, turn) = make_session_and_context().await;
        let mut runtime = ArtifactRuntime;
        let req = ArtifactExecRequest {
            command: vec![
                "/path/to/node".to_string(),
                "/path/to/launcher.mjs".to_string(),
                "/tmp/source.mjs".to_string(),
            ],
            cwd: PathBuf::from("/tmp"),
            timeout_ms: Some(5_000),
            env: HashMap::new(),
            approval_key: ArtifactApprovalKey {
                command_prefix: vec![
                    "/path/to/node".to_string(),
                    "/path/to/launcher.mjs".to_string(),
                ],
                cwd: PathBuf::from("/tmp"),
            },
            escalation_approval_requirement: ExecApprovalRequirement::Skip {
                bypass_sandbox: false,
                proposed_execpolicy_amendment: None,
            },
        };

        let decision = runtime
            .start_approval_async(
                &req,
                ApprovalCtx {
                    session: &session,
                    turn: &turn,
                    call_id: "call_artifact",
                    retry_reason: Some("command failed; retry without sandbox?".to_string()),
                    network_approval_context: None,
                },
            )
            .await;

        assert_eq!(decision, ReviewDecision::Approved);
    }
}
