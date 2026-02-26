# Strict Merge Replay Allowlist (Broad-Coverage, Policy-Gated)

## Purpose

Define a strict-but-broad allowlist for replay/merge audits so we can quickly separate:

- expected branch drift (invariants + intentional branch-owned behavior), from
- changes that require explicit human review before landing.

This document is aligned to `.codex/AGENTS.md` and the `$codex-upstream-merge-replay` skill.

## Policy and Ownership Split

- `.codex/AGENTS.md` is source of truth for branch behavior contracts and escalation authority.
- `$codex-upstream-merge-replay` defines merge mechanics, tier flow, delegation boundaries, and evidence format.
- If this allowlist conflicts with `.codex/AGENTS.md`, follow `.codex/AGENTS.md` (unless user instruction overrides both).

## Delegation Contract (required)

- Root agent owns behavior policy decisions (keep/drop/hybrid) and escalation decisions.
- `git_ops` owns merge mechanics only (preflight, merge-tree/overlap collection, conflict mechanics within provided policy).
- For non-trivial replay/audit work, spawn scoped subagents by default; root should stay focused on policy/integration.
- Any delegated merge-mechanics prompt must include `Using $codex-upstream-merge-replay`.
- Any delegated merge-mechanics prompt must include: protected behavior files/surfaces, escalation triggers, and allowed git operations.
- Delegated agents must not close escalation gates without root/user direction.

## Run-Start Gating (required)

Before merge mechanics or conflict resolution:

1. Detect branch: `git rev-parse --abbrev-ref HEAD`.
2. Load `.codex/AGENTS.md` for active-branch contract (`quip` vs `quip-subagents`).
3. Classify candidate paths against Tier A/B/C/D in this file.
4. If branch is neither `quip` nor `quip-subagents`, ask user which policy profile to apply.

## Design Constraints

- Shared invariants (canonical across `quip` and `quip-subagents`):
  - `--auth-file` end-to-end behavior
  - Execute mode visibility/labels
  - encrypted-content retry-once fallback
  - `ignore_system_requirements` isolation
- `quip` has additional protected behavior contracts:
  - `--auth-file` behavior
  - Execute visibility/labels
  - encrypted-content retry-once fallback
  - `ignore_system_requirements` isolation
  - retained-plan compact/rollback behavior
  - `request_user_input` feature-gated policy
- `quip-subagents` is a superset of `quip` and owns additional multi-agent/runtime/TUI/protocol coupling contracts.
- Default replay policy is hybrid: preserve branch-owned behavior, prefer upstream behavior elsewhere.
- Allowlist should stay broad (path-family based), not commit-specific.

## Evidence Baseline and Maintenance Cadence

- Use a moving baseline per run (merge base or parent baseline), not a fixed historical range.
- Keep recurring churn families in Tier A/B only after repeated replay cycles.
- One-off Tier D files should be tracked as observations; add to allowlist only if they recur.

## Allowlist Tiers

## Tier A: High-Churn Stable Merge Zone (auto-allow, still validate)

- `codex-rs/core/src/**`
- `codex-rs/core/tests/**`
- `codex-rs/tui/src/**`
- `codex-rs/tui/tests/**`
- `codex-rs/app-server/src/**`
- `codex-rs/app-server/tests/**`
- `codex-rs/app-server-protocol/src/**`
- `codex-rs/protocol/src/**`
- `codex-rs/state/src/**`
- `codex-rs/exec/src/**`
- `codex-rs/login/src/**`
- `codex-rs/cli/src/**`
- `codex-rs/config/src/**`
- `docs/**`

## Tier B: Contract-Sensitive Review Zone (always manual review)

Any touched path in this zone is expected but must be explicitly reviewed for contract correctness.

- `codex-rs/app-server-protocol/schema/json/**`
- `codex-rs/app-server-protocol/schema/typescript/**`
- `codex-rs/core/config.schema.json`
- `codex-rs/core/src/config/**`
- `codex-rs/protocol/src/config_types.rs`
- `codex-rs/protocol/src/models.rs`
- `codex-rs/protocol/src/protocol.rs`
- `codex-rs/app-server/src/message_processor.rs`
- `codex-rs/app-server/src/codex_message_processor.rs`
- `codex-rs/core/src/tools/spec.rs`
- `codex-rs/core/src/tools/handlers/multi_agents.rs`
- `codex-rs/core/src/tools/handlers/request_user_input.rs`
- `codex-rs/core/src/rollout/**`
- `codex-rs/core/src/compact.rs`
- `codex-rs/core/src/compact_remote.rs`
- `codex-rs/core/src/context_manager/**`
- `codex-rs/core/src/thread_manager.rs`
- `codex-rs/tui/src/app.rs`
- `codex-rs/tui/src/chatwidget.rs`
- `codex-rs/tui/src/history_cell.rs`

## Tier C: Build/Dependency/Workflow Zone (manual review, separate risk lane)

- `**/Cargo.toml`
- `**/Cargo.lock`
- `MODULE.bazel.lock`
- `MODULE.bazel`
- `.github/workflows/**`

## Tier D: Out-of-Allowlist Zone (overlap-driven escalation)

- Any touched path outside Tier A/B/C is Tier D.
- Tier D is a hard stop only when behavioral overlap can affect stated invariants/contracts.
- Tier D paths that are only new files or markdown files (`*.md`) are report-only and non-blocking unless behavioral overlap is present.

## Invariant Coverage Checklist (must pass when relevant files are touched)

For replay sets touching related surfaces, explicitly confirm:

- `--auth-file` end-to-end behavior remains intact.
- Execute mode visibility/labels remain intact.
- encrypted-content retry-once fallback remains intact.
- `ignore_system_requirements` isolation remains intact.
- retained-plan compact/rollback behavior remains intact.
- `request_user_input` Plan-only baseline + outside-Plan feature gate remains intact.
- On `quip-subagents`, multi-agent/watchdog + identity metadata + protocol/schema/TUI coupling remains intact.

## Modularity and No-Churn Rules (required)

- Prefer extraction-first for branch-local behavior: add/extend branch-owned modules/files; keep shared upstream files as thin adapters.
- Default modular extraction shape should mirror commit `e45548799` (branch-owned modules + thin shared-file hooks).
- Use hard cutover behavior preservation; do not add backward-compat shims unless user explicitly requests.
- If extraction is not feasible, keep shared-file diffs minimal and record rationale in merge/audit report.
- Keep minimal-LOC/no-churn treatment on fresh-upstream overlap surfaces:
  - `codex-rs/core/src/codex/rollout_reconstruction.rs`
  - request-user-input-outside-plan overlap surfaces
  - upstream memory-frequency overlap surfaces (including lineage from `639a648b6aec8f52316be784c2402841679cd382`)
- Reject refactor/style churn on these overlap surfaces unless a correctness-critical hunk is required.

## Decision Rules

1. If all changed files are Tier A only:
   - proceed with replay using targeted validation.
2. If any Tier B file is touched:
   - replay is allowed, but requires explicit contract-review notes.
3. If any Tier C file is touched:
   - treat as infra lane; include explicit rationale and lock/schema checks when relevant.
4. If any Tier D file is touched:
   - evaluate overlap with invariants/contracts first.
   - escalate only when overlap risk exists; otherwise report and continue.

## Mandatory Escalation Gate (hard stop)

Escalate and ask for user direction with a recommendation when upstream introduces significant behavior drift in critical areas (even without textual conflicts), including:

- shared invariant drift
- subagent lifecycle semantic drift
- collab inbox routing/delivery drift
- approval/tool/runtime contract shape drift
- critical TUI behavior drift

Use this format:

- **Observed upstream behavior change:** `<what changed>`
- **Risk if merged as-is:** `<what breaks/regresses>`
- **Recommended action:** `<accept upstream | preserve branch behavior | hybrid>` with one-sentence rationale
- **Verification plan:** `<tests/checks you will run after decision>`

## Suggested Audit Commands (branch-agnostic)

```bash
# 1) define merge roles and baseline
behavior_source=<branch>
incoming_source=<branch>
integration_target=<branch>
BASE=$(git merge-base "$behavior_source" "$incoming_source")

# 2) collect changed paths + overlap-first risk
 git diff --name-status "$BASE..$behavior_source"
 git diff --name-status "$BASE..$incoming_source"
 comm -12 \
   <(git diff --name-only "$BASE..$behavior_source" | sort) \
   <(git diff --name-only "$BASE..$incoming_source" | sort)

# 3) preview conflict/semantic pressure before resolving
 git merge-tree --merge-base "$BASE" --messages "$behavior_source" "$incoming_source"

# 4) inspect intent
 git log --oneline --no-merges "$BASE..$incoming_source"
 git log --oneline --no-merges "$BASE..$behavior_source"
```

## Required Merge/Audit Report Contract

Every replay/merge audit report must include:

- merge role mapping (`behavior_source`, `incoming_source`, `integration_target`)
- allowlist tier summary (Tier A/B/C touched paths + explicit Tier D status)
- explicit keep/drop/hybrid policy by area
- delegation summary (what root retained vs what was delegated)
- explicit statement that behavior-policy/escalation decisions were root-owned
- preserved shared invariants and branch-delta invariants
- escalation decisions (or explicit statement none triggered)
- Tier D report-only items (new files/markdown) and explicit overlap-risk outcome
- command summary for preflight + validation with results
- unresolved/residual risks (if any)

## Validation Guidance (targeted by touched surfaces)

- Start targeted (`cargo nextest` / focused checks) using branch contract priorities.
- For Rust replay/edit flows, run `just fix -p <project>` and `just fmt` after code changes.
- If config types changed, run `just write-config-schema`.
- If app-server/protocol wire shapes changed, run `just write-app-server-schema` (and `--experimental` if needed).
- Expand only if Tier B/C changes are broad or cross multiple contract surfaces.
- Distinguish known baseline noise from regressions introduced by replay work.
- Keep audit evidence in `.codex/SUBAGENT_COMPARISON_FINDINGS_*.md` when needed.

## Why this is strict but not overfit

- Strict: explicit manual gates for contract-sensitive and infra-sensitive surfaces.
- Broad: path-family allowlist across core/app-server/protocol/tui, not brittle commit-specific file lists.
- Durable: overlap-aware Tier D handling avoids unnecessary stops on non-behavioral new docs/files.
