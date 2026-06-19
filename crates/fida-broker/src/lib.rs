//! `fida-broker` — Action_Broker: the orchestration chokepoint that
//! evaluates, applies mode semantics, coordinates approval, dispatches
//! execution, and emits exactly one audit event (see spec tasks 11.x;
//! design "Action_Broker", "Session Modes").
//!
//! Every mediated action — command, file change, network request, MCP tool
//! call — flows through [`Broker::handle`], which is the single place that:
//!
//! 1. evaluates the action with the pure [`fida_policy::evaluate`] pipeline,
//! 2. applies the session [`Mode`]: observe permits all,
//!    enforce applies the decision, dry-run executes nothing,
//! 3. coordinates approval for `ask` decisions — remembered-decision reuse
//!    `--yes` auto-approval limited to `auto_approve`-flagged rules
//!    an interactive prompt, or non-interactive
//!    fail-closed blocking,
//! 4. dispatches permitted actions to an injected [`ActionDispatcher`], and
//! 5. records **exactly one** [`AuditEvent`] per resolved action.
//!
//! # Dependency injection and testability
//!
//! The broker never performs real process execution or audit-file I/O itself.
//! Its collaborators are injected so the orchestration logic can be unit- and
//! property-tested in isolation (design "Testing Strategy"):
//!
//! * the [`ApprovalUi`] (held by the [`Broker`]) — production wires
//!   `fida_approval::TerminalApprovalUi`; tests script outcomes,
//! * an [`AuditStore`] and an [`ActionDispatcher`] — carried on
//!   [`BrokerContext`] because both require `&mut` access per call.
//!
//! The actual command-execution wiring to `fida-exec` lives at the CLI layer
//! (task 19.4); here the [`ActionDispatcher`] is an opaque "perform this
//! permitted action" abstraction returning an exit code.
//!
//! In-memory collaborators for tests live in [`mod@testing`].

use std::collections::HashSet;

use chrono::Utc;

use fida_action::{Action, ActionKind, Decision, DecisionResult, EvalStage, MatchedRule, Mode};
use fida_approval::{ApprovalOutcome, ApprovalPresentation, ApprovalUi};
use fida_audit::{AuditAction, AuditEvent, AuditResult, AuditStore};
use fida_policy::CompiledPolicy;

pub mod testing;

// ---------------------------------------------------------------------------
// Exit codes (design "Error Handling" table)
// ---------------------------------------------------------------------------

/// Normal completion, dry-run, or a permitted action whose dispatcher reported
/// success.
pub const EXIT_SUCCESS: u8 = 0;
/// A mediated action resolved to `deny`.
pub const EXIT_DENY: u8 = 2;
/// An `ask` was required but could not be resolved — non-interactive
/// fail-closed, or a `--yes` run where the rule is not auto-approval eligible
pub const EXIT_APPROVAL_REQUIRED: u8 = 3;
/// A secret exposure was denied.
pub const EXIT_SECRET_BLOCKED: u8 = 6;

// ---------------------------------------------------------------------------
// Dispatch abstraction
// ---------------------------------------------------------------------------

/// The outcome of performing a permitted action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchOutcome {
    /// The exit code the underlying operation reported (`0` on success). For a
    /// `command.run` this is the process exit code; for other kinds it is the
    /// gate/proxy success indicator.
    pub exit_code: u8,
}

impl DispatchOutcome {
    /// A successful dispatch (`exit_code == 0`).
    pub fn success() -> Self {
        DispatchOutcome {
            exit_code: EXIT_SUCCESS,
        }
    }
}

/// Performs an action the broker has decided to permit.
///
/// This is the seam between the broker's policy/mode orchestration and the
/// concrete subsystems (Command_Executor, File_Diff_Gate, proxies). The broker
/// invokes [`dispatch`](ActionDispatcher::dispatch) **only** for permitted
/// actions; it is never called in dry-run mode or for blocked/denied actions,
/// which is what makes "dry-run executes nothing" observable.
pub trait ActionDispatcher {
    /// Perform `action` and report the resulting exit code.
    fn dispatch(&mut self, action: &Action) -> DispatchOutcome;
}

// ---------------------------------------------------------------------------
// Session handle and remembered decisions
// ---------------------------------------------------------------------------

/// Per-session state the broker needs to attribute and order audit events.
///
/// Holds the owning session id and a monotonic counter used to mint unique,
/// append-ordered event ids (`evt_01`, `evt_02`, …) so the one-event-per-action
/// guarantee yields stable identifiers.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    session_id: String,
    event_counter: u32,
}

impl SessionHandle {
    /// Create a handle for `session_id` with the event counter at zero.
    pub fn new(session_id: impl Into<String>) -> Self {
        SessionHandle {
            session_id: session_id.into(),
            event_counter: 0,
        }
    }

    /// The owning session id.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Mint the next unique, append-ordered event id for this session.
    pub fn next_event_id(&mut self) -> String {
        self.event_counter += 1;
        format!("evt_{:02}", self.event_counter)
    }
}

/// The set of approvals the user chose to remember for the current session.
///
/// A remembered decision is keyed on `(action kind, matched rule)`: once the
/// user selects "remember for session" for an `ask`, every subsequent action
/// with the **same kind and same matched rule** is auto-allowed without
/// re-prompting. The matched rule is keyed by its string form so the
/// `NoExplicitRule` sentinel participates like any concrete rule id.
#[derive(Debug, Clone, Default)]
pub struct RememberedDecisions {
    remembered: HashSet<(ActionKind, String)>,
}

impl RememberedDecisions {
    /// An empty set of remembered decisions.
    pub fn new() -> Self {
        RememberedDecisions::default()
    }

    /// Record that `kind` + `rule` should be auto-allowed for the rest of the
    /// session.
    pub fn remember(&mut self, kind: ActionKind, rule: &MatchedRule) {
        self.remembered.insert((kind, rule.as_str().to_string()));
    }

    /// Whether a prior "remember for session" choice covers `kind` + `rule`.
    pub fn contains(&self, kind: ActionKind, rule: &MatchedRule) -> bool {
        self.remembered.contains(&(kind, rule.as_str().to_string()))
    }

    /// Number of distinct remembered `(kind, rule)` pairs.
    pub fn len(&self) -> usize {
        self.remembered.len()
    }

    /// Whether nothing has been remembered yet.
    pub fn is_empty(&self) -> bool {
        self.remembered.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Broker context, result, and outcome
// ---------------------------------------------------------------------------

/// The per-action execution context (design "Action_Broker").
///
/// Carries the compiled policy and the session knobs that determine how a
/// decision is applied. The [`AuditStore`] and [`ActionDispatcher`] live here —
/// rather than on the [`Broker`] — because both need `&mut` access while the
/// broker's [`ActionBroker::handle`] takes `&self`.
pub struct BrokerContext<'a> {
    /// The compiled policy the evaluator runs against.
    pub policy: &'a CompiledPolicy,
    /// The active session mode.
    pub mode: Mode,
    /// Whether an interactive terminal is available for prompts.
    pub interactive: bool,
    /// Whether `--yes` was supplied.
    pub yes: bool,
    /// Per-session id and event counter.
    pub session: &'a mut SessionHandle,
    /// Approvals remembered for the session.
    pub remembered: &'a mut RememberedDecisions,
    /// The append-only audit store; the broker writes exactly one event here
    /// per resolved action.
    pub audit: &'a mut dyn AuditStore,
    /// The dispatcher that performs permitted actions.
    pub dispatcher: &'a mut dyn ActionDispatcher,
}

/// How the broker ultimately resolved an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionResult {
    /// The action was permitted and dispatched (allow, observe, an approved
    /// `ask`, a remembered decision, or a `--yes` auto-approval).
    Permitted,
    /// The action was blocked by a `deny` decision or an interactive deny.
    Denied,
    /// The action was blocked because approval was required but unavailable
    /// (non-interactive fail-closed, or a non-eligible `--yes` ask).
    Blocked,
    /// The decision was recorded but nothing was executed (dry-run).
    WouldRun,
}

/// The broker's verdict for one action: what happened, the exit code the CLI
/// should surface, and the underlying decision for reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerOutcome {
    /// What the broker did with the action.
    pub result: ActionResult,
    /// The exit code the CLI should surface for this action.
    pub exit_code: u8,
    /// The evaluator's decision, retained so the caller can report the matched
    /// rule and reason.
    pub decision: DecisionResult,
}

/// The Action_Broker contract (design "Action_Broker").
pub trait ActionBroker {
    /// Evaluate, apply mode semantics, coordinate approval, dispatch execution,
    /// and emit exactly one audit event, returning the resolved outcome.
    fn handle(&self, ctx: &mut BrokerContext, action: Action) -> BrokerOutcome;
}

// ---------------------------------------------------------------------------
// Broker implementation
// ---------------------------------------------------------------------------

/// The orchestration chokepoint. Holds only the (stateless) approval UI; all
/// mutable per-call collaborators are supplied through [`BrokerContext`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Broker<U: ApprovalUi> {
    ui: U,
}

impl<U: ApprovalUi> Broker<U> {
    /// Construct a broker that prompts through `ui` when an interactive `ask`
    /// needs resolving.
    pub fn new(ui: U) -> Self {
        Broker { ui }
    }
}

impl<U: ApprovalUi> ActionBroker for Broker<U> {
    fn handle(&self, ctx: &mut BrokerContext, action: Action) -> BrokerOutcome {
        let decision = fida_policy::evaluate(ctx.policy, &action);

        match ctx.mode {
            // Observe: evaluate and audit, but permit every action regardless
            // of its decision — never block, never prompt.
            Mode::Observe => {
                let dispatch = ctx.dispatcher.dispatch(&action);
                self.finish(
                    ctx,
                    &action,
                    decision,
                    AuditResult::Allowed,
                    ActionResult::Permitted,
                    dispatch.exit_code,
                )
            }
            // Dry-run: record the decision but execute nothing
            Mode::DryRun => self.finish(
                ctx,
                &action,
                decision,
                AuditResult::WouldRun,
                ActionResult::WouldRun,
                EXIT_SUCCESS,
            ),
            // Enforce: apply the decision in real time.
            Mode::Enforce => self.handle_enforce(ctx, action, decision),
        }
    }
}

impl<U: ApprovalUi> Broker<U> {
    /// Apply a decision in `enforce` mode.
    fn handle_enforce(
        &self,
        ctx: &mut BrokerContext,
        action: Action,
        decision: DecisionResult,
    ) -> BrokerOutcome {
        match decision.decision {
            // allow -> permit and dispatch.
            Decision::Allow => {
                let dispatch = ctx.dispatcher.dispatch(&action);
                self.finish(
                    ctx,
                    &action,
                    decision,
                    AuditResult::Allowed,
                    ActionResult::Permitted,
                    dispatch.exit_code,
                )
            }
            // deny -> block without executing. A secret-stage
            // denial surfaces exit 6; any other deny -> 2.
            Decision::Deny => {
                let exit_code = if decision.stage == EvalStage::SecretDetection {
                    EXIT_SECRET_BLOCKED
                } else {
                    EXIT_DENY
                };
                self.finish(
                    ctx,
                    &action,
                    decision,
                    AuditResult::Denied,
                    ActionResult::Denied,
                    exit_code,
                )
            }
            // dry_run decision -> describe, do not execute.
            Decision::DryRun => self.finish(
                ctx,
                &action,
                decision,
                AuditResult::WouldRun,
                ActionResult::WouldRun,
                EXIT_SUCCESS,
            ),
            // ask -> remembered reuse / --yes / prompt / fail-closed.
            Decision::Ask => self.handle_ask(ctx, action, decision),
        }
    }

    /// Resolve an `ask` decision in `enforce` mode.
    ///
    /// Resolution order: a remembered decision wins first, then
    /// `--yes` auto-approval for `auto_approve`-flagged rules, then
    /// an interactive prompt, and finally non-interactive
    /// fail-closed blocking.
    fn handle_ask(
        &self,
        ctx: &mut BrokerContext,
        action: Action,
        decision: DecisionResult,
    ) -> BrokerOutcome {
        // 1. Remembered-decision reuse: same kind + same matched rule.
        if ctx.remembered.contains(action.kind, &decision.matched_rule) {
            let dispatch = ctx.dispatcher.dispatch(&action);
            return self.finish(
                ctx,
                &action,
                decision,
                AuditResult::AllowedRemembered,
                ActionResult::Permitted,
                dispatch.exit_code,
            );
        }

        // 2. --yes: auto-approve only auto_approve-flagged rules; block every
        // other ask.
        if ctx.yes {
            if rule_is_auto_approve(ctx.policy, &decision.matched_rule) {
                let dispatch = ctx.dispatcher.dispatch(&action);
                return self.finish(
                    ctx,
                    &action,
                    decision,
                    AuditResult::Allowed,
                    ActionResult::Permitted,
                    dispatch.exit_code,
                );
            }
            return self.finish(
                ctx,
                &action,
                decision,
                AuditResult::Blocked,
                ActionResult::Blocked,
                EXIT_APPROVAL_REQUIRED,
            );
        }

        // 3. Interactive prompt.
        if ctx.interactive {
            let presentation = build_presentation(&action, &decision);
            return match self.ui.prompt(&presentation) {
                ApprovalOutcome::Allowed => {
                    let dispatch = ctx.dispatcher.dispatch(&action);
                    self.finish(
                        ctx,
                        &action,
                        decision,
                        AuditResult::AllowedOnce,
                        ActionResult::Permitted,
                        dispatch.exit_code,
                    )
                }
                ApprovalOutcome::AllowedRemembered => {
                    ctx.remembered.remember(action.kind, &decision.matched_rule);
                    let dispatch = ctx.dispatcher.dispatch(&action);
                    self.finish(
                        ctx,
                        &action,
                        decision,
                        AuditResult::AllowedRemembered,
                        ActionResult::Permitted,
                        dispatch.exit_code,
                    )
                }
                ApprovalOutcome::Denied => self.finish(
                    ctx,
                    &action,
                    decision,
                    AuditResult::Denied,
                    ActionResult::Denied,
                    EXIT_DENY,
                ),
            };
        }

        // 4. Non-interactive with no remembered match: fail closed
        self.finish(
            ctx,
            &action,
            decision,
            AuditResult::Blocked,
            ActionResult::Blocked,
            EXIT_APPROVAL_REQUIRED,
        )
    }

    /// Append exactly one audit event for the resolved action and build the
    /// outcome. This is the single audit-write site, so
    /// every control-flow path emits precisely one event.
    fn finish(
        &self,
        ctx: &mut BrokerContext,
        action: &Action,
        decision: DecisionResult,
        result: AuditResult,
        action_result: ActionResult,
        exit_code: u8,
    ) -> BrokerOutcome {
        let event = AuditEvent {
            id: ctx.session.next_event_id(),
            session_id: ctx.session.session_id.to_string(),
            time: Utc::now(),
            actor: action.actor,
            action: AuditAction::from_action(action),
            decision: decision.decision,
            result,
            matched_rule: decision.matched_rule.clone(),
            risk: decision.risk,
            // The broker's per-action event carries only redaction-safe fields
            // (AuditAction is redaction-safe by construction); captured command
            // output is redacted separately by the executor before it is
            // recorded (task 12.1).
            redacted: false,
            metrics: None,
        };
        // Best-effort append: the in-memory and JSONL stores used in practice
        // do not fail here, and the broker has no safe recovery beyond
        // surfacing the resolved outcome.
        let _ = ctx.audit.append(&event);

        BrokerOutcome {
            result: action_result,
            exit_code,
            decision,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Whether the command rule identified by `matched` is flagged for `--yes`
/// auto-approval.
///
/// Only command rules carry an `auto_approve` flag, so the lookup scans the
/// compiled command tiers for a matching `rule_id`. A non-command rule or the
/// `NoExplicitRule` sentinel is never auto-approval eligible.
fn rule_is_auto_approve(policy: &CompiledPolicy, matched: &MatchedRule) -> bool {
    let id = match matched {
        MatchedRule::Rule(id) => id.as_str(),
        MatchedRule::NoExplicitRule => return false,
    };
    policy
        .commands
        .deny
        .iter()
        .chain(policy.commands.allow.iter())
        .chain(policy.commands.ask.iter())
        .any(|rule| rule.rule_id == id && rule.auto_approve)
}

/// Build the human-readable target description shown in an approval prompt.
fn action_target(action: &Action) -> String {
    use fida_action::ActionPayload;
    match &action.payload {
        ActionPayload::Command { argv, .. } => argv.join(" "),
        ActionPayload::File { path } => path.to_string_lossy().into_owned(),
        ActionPayload::Network { target } => match &target.domain {
            Some(domain) => format!("{} ({})", domain, target.host),
            None => target.host.clone(),
        },
        ActionPayload::Mcp { tool_name } => tool_name.clone(),
        ActionPayload::Secret { finding } => finding.pattern_id.clone(),
    }
}

/// Build the full context block revealed on "view context".
fn action_context(action: &Action) -> String {
    use fida_action::ActionPayload;
    match &action.payload {
        ActionPayload::Command { argv, cwd } => {
            format!("argv: {:?}\ncwd: {}", argv, cwd.display())
        }
        ActionPayload::File { path } => format!("path: {}", path.display()),
        ActionPayload::Network { target } => format!(
            "host: {}\nprotocol: {:?}\ndomain: {}",
            target.host,
            target.protocol,
            target.domain.as_deref().unwrap_or("<unknown>")
        ),
        ActionPayload::Mcp { tool_name } => format!("tool: {tool_name}"),
        ActionPayload::Secret { finding } => {
            format!(
                "pattern: {}\nreason: {}",
                finding.pattern_id, finding.reason
            )
        }
    }
}

/// Assemble the [`ApprovalPresentation`] the broker hands to the [`ApprovalUi`]
/// for an interactive `ask`.
fn build_presentation(action: &Action, decision: &DecisionResult) -> ApprovalPresentation {
    ApprovalPresentation {
        kind: action.kind,
        target: action_target(action),
        risk: decision.risk,
        reason: decision.reason.clone(),
        matched_rule: decision.matched_rule.clone(),
        context: action_context(action),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{MemoryAuditStore, RecordingDispatcher, ScriptedApprovalUi};

    use std::path::PathBuf;

    use fida_action::{Action, ActionKind, ActionPayload, Actor, Finding};
    use fida_audit::{AuditResult, AuditStore};
    use fida_policy::{CompiledPolicy, PolicySource, load_source};

    const SESSION: &str = "2026-06-12T070000Z-test01";

    /// A policy with one allow rule, one deny rule, one plain `ask` rule, and
    /// one auto-approval-eligible `ask` rule; global default is `ask`.
    const TEST_POLICY: &str = r#"
version: 1
default_decision: ask

commands:
  allow:
    - exact: git status
  ask:
    - prefix: pnpm install
      reason: installs can run lifecycle scripts
    - prefix: cargo fmt
      reason: formatting is low risk
      auto_approve: true
  deny:
    - regex: "rm\\s+-rf\\s+(/|~|\\.)"
      reason: destructive remove

files:
  read:
    allow: ["**/*"]
  write:
    allow: ["src/**"]

network: {}
mcp: {}
secrets:
  redact: true
  block_in_diffs: true
  patterns: []
audit:
  path: .fida/sessions
  format: jsonl
  redact_stdout: true
  redact_stderr: true
"#;

    fn compile(raw: &str) -> CompiledPolicy {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fida.yaml");
        std::fs::write(&path, raw).unwrap();
        load_source(&PolicySource::Config(path), None).expect("policy compiles")
    }

    fn policy() -> CompiledPolicy {
        compile(TEST_POLICY)
    }

    fn command(cmd: &str) -> Action {
        Action {
            kind: ActionKind::CommandRun,
            actor: Actor::Agent,
            payload: ActionPayload::Command {
                argv: cmd.split_whitespace().map(str::to_string).collect(),
                cwd: PathBuf::from("/repo"),
            },
        }
    }

    fn secret_action() -> Action {
        Action {
            kind: ActionKind::SecretDetected,
            actor: Actor::Agent,
            payload: ActionPayload::Secret {
                finding: Finding {
                    pattern_id: "private_key".to_string(),
                    reason: "PEM header".to_string(),
                },
            },
        }
    }

    struct Harness {
        policy: CompiledPolicy,
        session: SessionHandle,
        remembered: RememberedDecisions,
        audit: MemoryAuditStore,
        dispatcher: RecordingDispatcher,
    }

    impl Harness {
        fn new() -> Self {
            Harness {
                policy: policy(),
                session: SessionHandle::new(SESSION),
                remembered: RememberedDecisions::new(),
                audit: MemoryAuditStore::new(),
                dispatcher: RecordingDispatcher::succeeding(),
            }
        }

        /// Run one action through a broker with the given UI and knobs.
        fn run(
            &mut self,
            ui: &ScriptedApprovalUi,
            mode: Mode,
            interactive: bool,
            yes: bool,
            action: Action,
        ) -> BrokerOutcome {
            let broker = Broker::new(ui);
            let mut ctx = BrokerContext {
                policy: &self.policy,
                mode,
                interactive,
                yes,
                session: &mut self.session,
                remembered: &mut self.remembered,
                audit: &mut self.audit,
                dispatcher: &mut self.dispatcher,
            };
            broker.handle(&mut ctx, action)
        }

        fn events(&self) -> Vec<fida_audit::AuditEvent> {
            self.audit.read(SESSION).unwrap()
        }
    }

    #[test]
    fn allow_in_enforce_permits_dispatches_and_audits_once() {
        let mut h = Harness::new();
        let ui = ScriptedApprovalUi::always_denying();
        let out = h.run(&ui, Mode::Enforce, true, false, command("git status"));

        assert_eq!(out.result, ActionResult::Permitted);
        assert_eq!(out.exit_code, EXIT_SUCCESS);
        assert_eq!(h.dispatcher.count(), 1);
        let events = h.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result, AuditResult::Allowed);
        assert_eq!(events[0].id, "evt_01");
    }

    #[test]
    fn deny_in_enforce_blocks_without_dispatch_exit_2() {
        let mut h = Harness::new();
        let ui = ScriptedApprovalUi::always_denying();
        let out = h.run(&ui, Mode::Enforce, true, false, command("rm -rf /"));

        assert_eq!(out.result, ActionResult::Denied);
        assert_eq!(out.exit_code, EXIT_DENY);
        assert_eq!(h.dispatcher.count(), 0, "deny must not execute");
        let events = h.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result, AuditResult::Denied);
    }

    #[test]
    fn ask_non_interactive_fails_closed_exit_3() {
        let mut h = Harness::new();
        let ui = ScriptedApprovalUi::always_denying();
        let out = h.run(
            &ui,
            Mode::Enforce,
            false,
            false,
            command("pnpm install lodash"),
        );

        assert_eq!(out.result, ActionResult::Blocked);
        assert_eq!(out.exit_code, EXIT_APPROVAL_REQUIRED);
        assert_eq!(h.dispatcher.count(), 0);
        assert_eq!(ui.prompt_count(), 0, "non-interactive never prompts");
        assert_eq!(h.events()[0].result, AuditResult::Blocked);
    }

    #[test]
    fn ask_interactive_allow_once_permits_and_audits_allowed_once() {
        let mut h = Harness::new();
        let ui = ScriptedApprovalUi::new([ApprovalOutcome::Allowed]);
        let out = h.run(
            &ui,
            Mode::Enforce,
            true,
            false,
            command("pnpm install lodash"),
        );

        assert_eq!(out.result, ActionResult::Permitted);
        assert_eq!(out.exit_code, EXIT_SUCCESS);
        assert_eq!(ui.prompt_count(), 1);
        assert_eq!(h.dispatcher.count(), 1);
        assert_eq!(h.events()[0].result, AuditResult::AllowedOnce);
    }

    #[test]
    fn ask_interactive_deny_blocks_exit_2() {
        let mut h = Harness::new();
        let ui = ScriptedApprovalUi::new([ApprovalOutcome::Denied]);
        let out = h.run(
            &ui,
            Mode::Enforce,
            true,
            false,
            command("pnpm install lodash"),
        );

        assert_eq!(out.result, ActionResult::Denied);
        assert_eq!(out.exit_code, EXIT_DENY);
        assert_eq!(h.dispatcher.count(), 0);
        assert_eq!(h.events()[0].result, AuditResult::Denied);
    }

    #[test]
    fn remembered_decision_reused_without_reprompting() {
        let mut h = Harness::new();
        // First ask: user chooses "remember for session".
        let ui = ScriptedApprovalUi::new([ApprovalOutcome::AllowedRemembered]);
        let first = h.run(&ui, Mode::Enforce, true, false, command("pnpm install a"));
        assert_eq!(first.result, ActionResult::Permitted);
        assert_eq!(h.events()[0].result, AuditResult::AllowedRemembered);

        // Second ask, same kind + same matched rule: auto-allowed, no prompt.
        let second = h.run(&ui, Mode::Enforce, true, false, command("pnpm install b"));
        assert_eq!(second.result, ActionResult::Permitted);
        assert_eq!(ui.prompt_count(), 1, "second action must not re-prompt");
        assert_eq!(h.dispatcher.count(), 2);
        assert_eq!(h.events()[1].result, AuditResult::AllowedRemembered);
    }

    #[test]
    fn yes_auto_approves_only_eligible_rules() {
        let mut h = Harness::new();
        let ui = ScriptedApprovalUi::always_denying();

        // cargo fmt is flagged auto_approve -> permitted under --yes.
        let eligible = h.run(&ui, Mode::Enforce, false, true, command("cargo fmt --all"));
        assert_eq!(eligible.result, ActionResult::Permitted);
        assert_eq!(eligible.exit_code, EXIT_SUCCESS);

        // pnpm install is a plain ask -> blocked under --yes.
        let blocked = h.run(&ui, Mode::Enforce, false, true, command("pnpm install x"));
        assert_eq!(blocked.result, ActionResult::Blocked);
        assert_eq!(blocked.exit_code, EXIT_APPROVAL_REQUIRED);

        assert_eq!(ui.prompt_count(), 0, "--yes never prompts");
        assert_eq!(h.dispatcher.count(), 1, "only the eligible action ran");
    }

    #[test]
    fn observe_mode_permits_even_a_deny_decision() {
        let mut h = Harness::new();
        let ui = ScriptedApprovalUi::always_denying();
        let out = h.run(&ui, Mode::Observe, false, false, command("rm -rf /"));

        assert_eq!(out.result, ActionResult::Permitted);
        assert_eq!(out.exit_code, EXIT_SUCCESS);
        assert_eq!(
            out.decision.decision,
            Decision::Deny,
            "decision still recorded"
        );
        assert_eq!(h.dispatcher.count(), 1, "observe permits the action");
        assert_eq!(h.events()[0].result, AuditResult::Allowed);
    }

    #[test]
    fn dry_run_mode_executes_nothing_but_records() {
        let mut h = Harness::new();
        let ui = ScriptedApprovalUi::always_denying();
        let out = h.run(&ui, Mode::DryRun, true, false, command("git status"));

        assert_eq!(out.result, ActionResult::WouldRun);
        assert_eq!(out.exit_code, EXIT_SUCCESS);
        assert_eq!(h.dispatcher.count(), 0, "dry-run must execute nothing");
        assert_eq!(h.events().len(), 1);
        assert_eq!(h.events()[0].result, AuditResult::WouldRun);
    }

    #[test]
    fn secret_stage_deny_surfaces_exit_6() {
        let mut h = Harness::new();
        let ui = ScriptedApprovalUi::always_denying();
        let out = h.run(&ui, Mode::Enforce, true, false, secret_action());

        assert_eq!(out.result, ActionResult::Denied);
        assert_eq!(out.exit_code, EXIT_SECRET_BLOCKED);
        assert_eq!(out.decision.stage, EvalStage::SecretDetection);
        assert_eq!(h.dispatcher.count(), 0);
    }

    #[test]
    fn each_resolved_action_emits_exactly_one_event() {
        let mut h = Harness::new();
        let ui = ScriptedApprovalUi::new([ApprovalOutcome::Allowed]);
        h.run(&ui, Mode::Enforce, true, false, command("git status")); // allow
        h.run(&ui, Mode::Enforce, true, false, command("rm -rf /")); // deny
        h.run(&ui, Mode::Enforce, true, false, command("pnpm install z")); // ask→allow
        assert_eq!(h.events().len(), 3);
        assert_eq!(h.audit.total(), 3);
        // Event ids are unique and append-ordered.
        let ids: Vec<_> = h.events().iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, vec!["evt_01", "evt_02", "evt_03"]);
    }
}
