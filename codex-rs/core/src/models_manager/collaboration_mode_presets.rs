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
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn preset_names_use_mode_display_names() {
        assert_eq!(plan_preset().name, ModeKind::Plan.display_name());
        assert_eq!(
            default_preset(CollaborationModesConfig::default()).name,
            ModeKind::Default.display_name()
        );
        assert_eq!(execute_preset().name, ModeKind::Execute.display_name());
        assert_eq!(
            plan_preset().reasoning_effort,
            Some(Some(ReasoningEffort::Medium))
        );
    }

    #[test]
    fn default_mode_instructions_replace_mode_names_placeholder() {
        let default_instructions = default_preset(CollaborationModesConfig {
            default_mode_request_user_input: true,
        })
        .developer_instructions
        .expect("default preset should include instructions")
        .expect("default instructions should be set");

        assert!(!default_instructions.contains(KNOWN_MODE_NAMES_PLACEHOLDER));
        assert!(!default_instructions.contains(REQUEST_USER_INPUT_AVAILABILITY_PLACEHOLDER));
        assert!(!default_instructions.contains(ASKING_QUESTIONS_GUIDANCE_PLACEHOLDER));

        let known_mode_names = tui_visible_mode_names();
        let expected_snippet = format!("Known mode names are {known_mode_names}.");
        assert!(default_instructions.contains(&expected_snippet));

        let expected_availability_message =
            request_user_input_availability_message(ModeKind::Default, true);
        assert!(default_instructions.contains(&expected_availability_message));
        assert!(default_instructions.contains("prefer using the `request_user_input` tool"));
    }

    #[test]
    fn default_mode_instructions_use_plain_text_questions_when_feature_disabled() {
        let default_instructions = default_preset(CollaborationModesConfig::default())
            .developer_instructions
            .expect("default preset should include instructions")
            .expect("default instructions should be set");

        assert!(!default_instructions.contains("prefer using the `request_user_input` tool"));
        assert!(
            default_instructions
                .contains("ask the user directly with a concise plain-text question")
        );
    }
}
