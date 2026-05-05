use super::*;
use pretty_assertions::assert_eq;

#[test]
fn preset_names_use_mode_display_names() {
    assert_eq!(plan_preset().name, ModeKind::Plan.display_name());
    assert_eq!(
        default_preset(CollaborationModesConfig::default()).name,
        ModeKind::Default.display_name()
    );
    assert_eq!(plan_preset().model, None);
    assert_eq!(
        plan_preset().reasoning_effort,
        Some(Some(ReasoningEffort::Medium))
    );
    assert_eq!(
        default_preset(CollaborationModesConfig::default()).model,
        None
    );
    assert_eq!(
        default_preset(CollaborationModesConfig::default()).reasoning_effort,
        None
    );
}

#[test]
fn default_mode_instructions_replace_mode_names_placeholder() {
    let default_instructions = default_preset(CollaborationModesConfig::default())
        .developer_instructions
        .expect("default preset should include instructions")
        .expect("default instructions should be set");

    assert!(!default_instructions.contains("{{KNOWN_MODE_NAMES}}"));
    assert!(!default_instructions.contains("{{REQUEST_USER_INPUT_AVAILABILITY}}"));
    assert!(!default_instructions.contains("{{ASKING_QUESTIONS_GUIDANCE}}"));

    let known_mode_names = crate::collaboration_mode_policy::tui_visible_mode_names();
    let expected_snippet = format!("Known mode names are {known_mode_names}.");
    assert!(default_instructions.contains(&expected_snippet));

    assert!(
        default_instructions
            .contains("The `request_user_input` tool is unavailable in Default mode.")
    );
    assert!(
        default_instructions.contains("ask the user directly with a concise plain-text question")
    );
}

#[test]
fn default_mode_instructions_reflect_request_user_input_feature_flag() {
    let disabled = default_mode_instructions(CollaborationModesConfig {
        default_mode_request_user_input: false,
    });
    let enabled = default_mode_instructions(CollaborationModesConfig {
        default_mode_request_user_input: true,
    });

    assert!(disabled.contains("The `request_user_input` tool is unavailable in Default mode."));
    assert!(disabled.contains("ask the user directly with a concise plain-text question"));

    assert!(enabled.contains("The `request_user_input` tool is available in Default mode."));
    assert!(enabled.contains("prefer using the `request_user_input` tool"));
}
