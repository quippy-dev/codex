use codex_models_manager::collaboration_mode_presets::builtin_collaboration_mode_presets;
use codex_protocol::config_types::CollaborationModeMask;
use codex_protocol::config_types::ModeKind;

use crate::model_catalog::ModelCatalog;

fn filtered_presets(_model_catalog: &ModelCatalog) -> Vec<CollaborationModeMask> {
    builtin_collaboration_mode_presets(_model_catalog.collaboration_modes_config())
        .into_iter()
        .filter(|mask| mask.mode.is_some_and(ModeKind::is_tui_visible))
        .collect()
}

pub(crate) fn presets_for_tui(model_catalog: &ModelCatalog) -> Vec<CollaborationModeMask> {
    filtered_presets(model_catalog)
}

pub(crate) fn default_mask(model_catalog: &ModelCatalog) -> Option<CollaborationModeMask> {
    let presets = filtered_presets(model_catalog);
    presets
        .iter()
        .find(|mask| mask.mode == Some(ModeKind::Default))
        .cloned()
        .or_else(|| presets.into_iter().next())
}

pub(crate) fn mask_for_kind(
    model_catalog: &ModelCatalog,
    kind: ModeKind,
) -> Option<CollaborationModeMask> {
    if !kind.is_tui_visible() {
        return None;
    }
    filtered_presets(model_catalog)
        .into_iter()
        .find(|mask| mask.mode == Some(kind))
}

/// Cycle to the next collaboration mode preset in list order.
pub(crate) fn next_mask(
    model_catalog: &ModelCatalog,
    current: Option<&CollaborationModeMask>,
) -> Option<CollaborationModeMask> {
    const CYCLE_ORDER: [ModeKind; 3] = [ModeKind::Default, ModeKind::Execute, ModeKind::Plan];

    let presets = filtered_presets(model_catalog);
    let current_kind = current.and_then(|mask| mask.mode);
    for offset in 1..=CYCLE_ORDER.len() {
        let next_kind = current_kind
            .and_then(|kind| {
                CYCLE_ORDER
                    .iter()
                    .position(|candidate| *candidate == kind)
                    .map(|idx| CYCLE_ORDER[(idx + offset) % CYCLE_ORDER.len()])
            })
            .unwrap_or(CYCLE_ORDER[(offset - 1) % CYCLE_ORDER.len()]);
        if let Some(mask) = presets.iter().find(|mask| mask.mode == Some(next_kind)) {
            return Some(mask.clone());
        }
    }
    None
}

#[cfg(test)]
pub(crate) fn default_mode_mask(model_catalog: &ModelCatalog) -> Option<CollaborationModeMask> {
    mask_for_kind(model_catalog, ModeKind::Default)
}

pub(crate) fn plan_mask(model_catalog: &ModelCatalog) -> Option<CollaborationModeMask> {
    mask_for_kind(model_catalog, ModeKind::Plan)
}
