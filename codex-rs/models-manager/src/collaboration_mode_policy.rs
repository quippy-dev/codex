use codex_protocol::config_types::ModeKind;
use codex_protocol::config_types::TUI_VISIBLE_COLLABORATION_MODES;

fn format_mode_names(modes: &[ModeKind]) -> String {
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

fn request_user_input_allowed_for_mode(
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
