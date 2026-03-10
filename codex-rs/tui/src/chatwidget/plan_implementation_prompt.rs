use codex_core::models_manager::manager::ModelsManager;
use codex_protocol::config_types::ModeKind;

use crate::app_event::AppEvent;
use crate::bottom_pane::SelectionAction;
use crate::bottom_pane::SelectionItem;
use crate::bottom_pane::SelectionViewParams;
use crate::bottom_pane::popup_consts::standard_popup_hint_line;
use crate::collaboration_modes;

pub(crate) const PLAN_IMPLEMENTATION_TITLE: &str = "Implement this plan?";
pub(crate) const PLAN_IMPLEMENTATION_EXECUTE: &str = "Yes, implement in Execute mode";
pub(crate) const PLAN_IMPLEMENTATION_DEFAULT: &str = "Yes, implement in Default mode";
pub(crate) const PLAN_IMPLEMENTATION_NO: &str = "No, stay in Plan mode";
pub(crate) const PLAN_IMPLEMENTATION_CODING_MESSAGE: &str = "Implement the plan.";

pub(crate) fn build_plan_implementation_prompt(
    models_manager: &ModelsManager,
) -> SelectionViewParams {
    let execute_mask = collaboration_modes::mask_for_kind(models_manager, ModeKind::Execute);
    let default_mask = collaboration_modes::default_mode_mask(models_manager);
    let (execute_actions, execute_disabled_reason) =
        build_submit_action(execute_mask, "Execute mode unavailable");
    let (default_actions, default_disabled_reason) =
        build_submit_action(default_mask, "Default mode unavailable");

    SelectionViewParams {
        title: Some(PLAN_IMPLEMENTATION_TITLE.to_string()),
        subtitle: None,
        footer_hint: Some(standard_popup_hint_line()),
        items: vec![
            SelectionItem {
                name: PLAN_IMPLEMENTATION_EXECUTE.to_string(),
                description: Some("Switch to Execute and execute the plan.".to_string()),
                selected_description: None,
                is_current: false,
                actions: execute_actions,
                disabled_reason: execute_disabled_reason,
                dismiss_on_select: true,
                ..Default::default()
            },
            SelectionItem {
                name: PLAN_IMPLEMENTATION_DEFAULT.to_string(),
                description: Some("Switch to Default and start coding.".to_string()),
                selected_description: None,
                is_current: false,
                actions: default_actions,
                disabled_reason: default_disabled_reason,
                dismiss_on_select: true,
                ..Default::default()
            },
            SelectionItem {
                name: PLAN_IMPLEMENTATION_NO.to_string(),
                description: Some("Continue planning with the model.".to_string()),
                selected_description: None,
                is_current: false,
                actions: Vec::new(),
                dismiss_on_select: true,
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

fn build_submit_action(
    mask: Option<codex_protocol::config_types::CollaborationModeMask>,
    unavailable_reason: &str,
) -> (Vec<SelectionAction>, Option<String>) {
    match mask {
        Some(mask) => {
            let user_text = PLAN_IMPLEMENTATION_CODING_MESSAGE.to_string();
            let actions: Vec<SelectionAction> = vec![Box::new(move |tx| {
                tx.send(AppEvent::SubmitUserMessageWithMode {
                    text: user_text.clone(),
                    collaboration_mode: mask.clone(),
                });
            })];
            (actions, None)
        }
        None => (Vec::new(), Some(unavailable_reason.to_string())),
    }
}
