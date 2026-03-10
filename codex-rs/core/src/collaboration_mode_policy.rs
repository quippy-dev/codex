use codex_protocol::config_types::ModeKind;
use codex_protocol::config_types::TUI_VISIBLE_COLLABORATION_MODES;

pub fn format_mode_names(modes: &[ModeKind]) -> String {
    let mode_names: Vec<&str> = modes.iter().map(|mode| mode.display_name()).collect();
    match mode_names.as_slice() {
        [] => "none".to_string(),
        [mode_name] => (*mode_name).to_string(),
        [first, second] => format!("{first} and {second}"),
        [..] => mode_names.join(", "),
    }
}

pub fn tui_visible_mode_names() -> String {
    format_mode_names(&TUI_VISIBLE_COLLABORATION_MODES)
}

pub fn request_user_input_allowed_for_mode(
    mode: ModeKind,
    request_user_input_outside_plan_mode: bool,
) -> bool {
    mode.allows_request_user_input()
        || (request_user_input_outside_plan_mode
            && matches!(
                mode,
                ModeKind::Default | ModeKind::Execute | ModeKind::PairProgramming
            ))
}

pub fn request_user_input_availability_message(
    mode: ModeKind,
    request_user_input_outside_plan_mode: bool,
) -> String {
    let mode_name = mode.display_name();
    if request_user_input_allowed_for_mode(mode, request_user_input_outside_plan_mode) {
        format!("The `request_user_input` tool is available in {mode_name} mode.")
    } else {
        format!(
            "The `request_user_input` tool is unavailable in {mode_name} mode. If you call it while in {mode_name} mode, it will return an error."
        )
    }
}

pub fn asking_questions_guidance_message(request_user_input_outside_plan_mode: bool) -> String {
    if request_user_input_outside_plan_mode {
        "In Default mode, strongly prefer making reasonable assumptions and executing the user's request rather than stopping to ask questions. If you absolutely must ask a question because the answer cannot be discovered from local context and a reasonable assumption would be risky, prefer using the `request_user_input` tool rather than writing a multiple choice question as a textual assistant message. Never write a multiple choice question as a textual assistant message.".to_string()
    } else {
        "In Default mode, strongly prefer making reasonable assumptions and executing the user's request rather than stopping to ask questions. If you absolutely must ask a question because the answer cannot be discovered from local context and a reasonable assumption would be risky, ask the user directly with a concise plain-text question. Never write a multiple choice question as a textual assistant message.".to_string()
    }
}

pub fn request_user_input_unavailable_message(
    mode: ModeKind,
    request_user_input_outside_plan_mode: bool,
) -> Option<String> {
    (!request_user_input_allowed_for_mode(mode, request_user_input_outside_plan_mode)).then(|| {
        format!(
            "request_user_input is unavailable in {} mode",
            mode.display_name()
        )
    })
}

pub fn request_user_input_tool_description(request_user_input_outside_plan_mode: bool) -> String {
    let mode_names: Vec<&str> = TUI_VISIBLE_COLLABORATION_MODES
        .into_iter()
        .filter(|mode| {
            request_user_input_allowed_for_mode(*mode, request_user_input_outside_plan_mode)
        })
        .map(ModeKind::display_name)
        .collect();
    let allowed_modes = match mode_names.as_slice() {
        [] => "no modes".to_string(),
        [mode] => format!("{mode} mode"),
        [first, second] => format!("{first} and {second} modes"),
        [..] => format!("modes: {}", mode_names.join(", ")),
    };
    format!(
        "Request user input for one to three short questions and wait for the response. This tool is only available in {allowed_modes}."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn request_user_input_mode_availability_is_plan_only_by_default() {
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
            false,
        ));
    }

    #[test]
    fn request_user_input_outside_plan_mode_allows_default_execute_and_pair() {
        assert!(request_user_input_allowed_for_mode(ModeKind::Plan, true));
        assert!(request_user_input_allowed_for_mode(ModeKind::Default, true));
        assert!(request_user_input_allowed_for_mode(ModeKind::Execute, true));
        assert!(request_user_input_allowed_for_mode(
            ModeKind::PairProgramming,
            true,
        ));
    }

    #[test]
    fn request_user_input_tool_description_uses_visible_tui_modes() {
        assert_eq!(
            request_user_input_tool_description(false),
            "Request user input for one to three short questions and wait for the response. This tool is only available in Plan mode.".to_string()
        );
        assert_eq!(
            request_user_input_tool_description(true),
            "Request user input for one to three short questions and wait for the response. This tool is only available in modes: Default, Plan, Execute.".to_string()
        );
    }

    #[test]
    fn request_user_input_messages_use_mode_display_names() {
        assert_eq!(
            request_user_input_availability_message(ModeKind::Default, true),
            "The `request_user_input` tool is available in Default mode.".to_string()
        );
        assert_eq!(
            request_user_input_unavailable_message(ModeKind::Execute, false),
            Some("request_user_input is unavailable in Execute mode".to_string())
        );
    }

    #[test]
    fn asking_questions_guidance_switches_with_feature_gate() {
        assert!(
            asking_questions_guidance_message(true)
                .contains("prefer using the `request_user_input` tool")
        );
        assert!(
            asking_questions_guidance_message(false)
                .contains("ask the user directly with a concise plain-text question")
        );
    }
}
