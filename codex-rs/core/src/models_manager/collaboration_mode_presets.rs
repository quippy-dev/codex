use crate::collaboration_mode_policy::asking_questions_guidance_message;
use crate::collaboration_mode_policy::request_user_input_availability_message;
use crate::collaboration_mode_policy::tui_visible_mode_names;
use codex_protocol::config_types::CollaborationModeMask;
use codex_protocol::config_types::ModeKind;
use codex_protocol::openai_models::ReasoningEffort;

const COLLABORATION_MODE_PLAN: &str = include_str!("../../templates/collaboration_mode/plan.md");
const COLLABORATION_MODE_DEFAULT: &str =
    include_str!("../../templates/collaboration_mode/default.md");
const COLLABORATION_MODE_EXECUTE: &str =
    include_str!("../../templates/collaboration_mode/execute.md");
const KNOWN_MODE_NAMES_PLACEHOLDER: &str = "{{KNOWN_MODE_NAMES}}";
const REQUEST_USER_INPUT_AVAILABILITY_PLACEHOLDER: &str = "{{REQUEST_USER_INPUT_AVAILABILITY}}";
const ASKING_QUESTIONS_GUIDANCE_PLACEHOLDER: &str = "{{ASKING_QUESTIONS_GUIDANCE}}";

/// Stores feature flags that control collaboration-mode behavior.
///
/// Keep mode-related flags here so new collaboration-mode capabilities can be
/// added without large cross-cutting diffs to constructor and call-site
/// signatures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CollaborationModesConfig {
    /// Enables `request_user_input` availability outside Plan mode.
    pub default_mode_request_user_input: bool,
}

pub(crate) fn builtin_collaboration_mode_presets(
    collaboration_modes_config: CollaborationModesConfig,
) -> Vec<CollaborationModeMask> {
    vec![
        plan_preset(),
        default_preset(collaboration_modes_config),
        execute_preset(),
    ]
}

fn plan_preset() -> CollaborationModeMask {
    CollaborationModeMask {
        name: ModeKind::Plan.display_name().to_string(),
        mode: Some(ModeKind::Plan),
        model: None,
        reasoning_effort: Some(Some(ReasoningEffort::Medium)),
        developer_instructions: Some(Some(COLLABORATION_MODE_PLAN.to_string())),
    }
}

fn default_preset(collaboration_modes_config: CollaborationModesConfig) -> CollaborationModeMask {
    CollaborationModeMask {
        name: ModeKind::Default.display_name().to_string(),
        mode: Some(ModeKind::Default),
        model: None,
        reasoning_effort: None,
        developer_instructions: Some(Some(default_mode_instructions(collaboration_modes_config))),
    }
}

fn execute_preset() -> CollaborationModeMask {
    CollaborationModeMask {
        name: ModeKind::Execute.display_name().to_string(),
        mode: Some(ModeKind::Execute),
        model: None,
        reasoning_effort: None,
        developer_instructions: Some(Some(COLLABORATION_MODE_EXECUTE.to_string())),
    }
}

fn default_mode_instructions(collaboration_modes_config: CollaborationModesConfig) -> String {
    let known_mode_names = tui_visible_mode_names();
    let default_mode_request_user_input =
        collaboration_modes_config.default_mode_request_user_input;
    let request_user_input_availability =
        request_user_input_availability_message(ModeKind::Default, default_mode_request_user_input);
    let asking_questions_guidance =
        asking_questions_guidance_message(default_mode_request_user_input);
    COLLABORATION_MODE_DEFAULT
        .replace(KNOWN_MODE_NAMES_PLACEHOLDER, &known_mode_names)
        .replace(
            REQUEST_USER_INPUT_AVAILABILITY_PLACEHOLDER,
            &request_user_input_availability,
        )
        .replace(
            ASKING_QUESTIONS_GUIDANCE_PLACEHOLDER,
            &asking_questions_guidance,
        )
}

#[cfg(test)]
#[path = "collaboration_mode_presets_tests.rs"]
mod tests;
