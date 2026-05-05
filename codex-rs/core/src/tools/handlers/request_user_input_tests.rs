use super::*;
use crate::collaboration_mode_policy::request_user_input_allowed_for_mode;
use crate::collaboration_mode_policy::request_user_input_tool_description;
use codex_features::Feature;
use codex_features::Features;
use codex_protocol::config_types::ModeKind;
use codex_tools::request_user_input_available_modes;
use pretty_assertions::assert_eq;

#[test]
fn request_user_input_mode_availability_defaults_to_plan_only() {
    assert!(request_user_input_allowed_for_mode(ModeKind::Plan, false));
    assert!(!request_user_input_allowed_for_mode(
        ModeKind::Default,
        false
    ));
    assert!(!request_user_input_allowed_for_mode(
        ModeKind::Execute,
        false
    ));
    assert!(!request_user_input_allowed_for_mode(
        ModeKind::PairProgramming,
        false
    ));
}

#[test]
fn request_user_input_unavailable_messages_respect_default_mode_feature_flag() {
    let default_available_modes = request_user_input_available_modes(&Features::with_defaults());
    let mut default_mode_features = Features::with_defaults();
    default_mode_features.enable(Feature::RequestUserInputOutsidePlanMode);
    let default_mode_available_modes = request_user_input_available_modes(&default_mode_features);

    assert_eq!(
        request_user_input_unavailable_message(ModeKind::Plan, &default_available_modes),
        None
    );
    assert_eq!(
        request_user_input_unavailable_message(ModeKind::Default, &default_available_modes),
        Some("request_user_input is unavailable in Default mode".to_string())
    );
    assert_eq!(
        request_user_input_unavailable_message(ModeKind::Default, &default_mode_available_modes),
        None
    );
    assert_eq!(
        request_user_input_unavailable_message(ModeKind::Execute, &default_available_modes),
        Some("request_user_input is unavailable in Execute mode".to_string())
    );
    assert_eq!(
        request_user_input_unavailable_message(ModeKind::PairProgramming, &default_available_modes),
        Some("request_user_input is unavailable in Pair Programming mode".to_string())
    );
}

#[test]
fn request_user_input_tool_description_mentions_available_modes() {
    assert_eq!(
            request_user_input_tool_description(false),
            "Request user input for one to three short questions and wait for the response. This tool is only available in Plan mode.".to_string()
        );
    assert_eq!(
            request_user_input_tool_description(true),
            "Request user input for one to three short questions and wait for the response. This tool is only available in modes: Default, Plan, Execute, Pair Programming.".to_string()
        );
}
