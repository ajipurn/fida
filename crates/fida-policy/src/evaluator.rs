//! Policy_Evaluator — the deterministic 7-stage evaluation pipeline (task 4.1;
//! design "Policy Evaluation Pipeline").
//!
//! [`evaluate`] is a pure, total function over `(CompiledPolicy, Action)`. It
//! applies the fixed stage order and stops at the first stage
//! that matches:
//!
//! 1. built-in hard denies (unless disabled),
//! 2. secret detection,
//! 3. explicit deny rules,
//! 4. explicit allow rules,
//! 5. explicit ask rules,
//! 6. profile default decision,
//! 7. global default decision.
//!
//! Every returned [`DecisionResult`] is fully populated: a decision, a
//! non-empty reason, the matched rule id (or [`MatchedRule::NoExplicitRule`]),
//! a risk level, and the originating [`EvalStage`].
//!
//! The per-kind matching primitives live in [`crate::matchers`]; the detailed
//! matcher behavior is owned by tasks 4.2 (commands) and 4.3 (file/network/MCP
//! and hard denies). This module owns only the stage orchestration.

use fida_action::{
    Action, ActionKind, ActionPayload, Decision, DecisionResult, EvalStage, MatchedRule, Risk,
};

use crate::compiled::CompiledPolicy;
use crate::matchers::{command, resource};

/// The evaluator interface (design "Policy_Evaluator").
pub trait PolicyEvaluator {
    /// Deterministic 7-stage evaluation; stops at the first matching stage.
    fn evaluate(&self, policy: &CompiledPolicy, action: &Action) -> DecisionResult;
}

/// The staged [`PolicyEvaluator`] implementation. Zero-sized: the evaluator
/// holds no state because [`evaluate`] is referentially transparent.
#[derive(Debug, Clone, Copy, Default)]
pub struct StagedEvaluator;

impl PolicyEvaluator for StagedEvaluator {
    fn evaluate(&self, policy: &CompiledPolicy, action: &Action) -> DecisionResult {
        evaluate(policy, action)
    }
}

/// One of the three explicit-rule tiers, evaluated deny → allow → ask.
#[derive(Clone, Copy)]
enum Tier {
    Deny,
    Allow,
    Ask,
}

/// A matched explicit rule: its stable id and an optional human reason.
struct ExplicitHit {
    rule_id: String,
    reason: Option<String>,
}

/// Evaluate `action` against `policy` through the fixed 7-stage pipeline.
///
/// Pure and total: for any `(policy, action)` it returns exactly one
/// [`DecisionResult`] and never panics (design Property 1).
pub fn evaluate(policy: &CompiledPolicy, action: &Action) -> DecisionResult {
    // Stage 1 — built-in hard denies, skipped entirely when
    // disabled. Network metadata/private-range denies are the
    // only built-in denies that an explicit policy rule can override.
    // Destructive commands and sensitive file writes remain hard stops;
    // sensitive reads continue to the mediated redaction path.
    if !policy.hard_denies_disabled {
        if let Some(hit) = resource::hard_deny_match(policy, action) {
            if !network_hard_deny_is_explicitly_allowed(policy, action) {
                return DecisionResult {
                    decision: Decision::Deny,
                    reason: hit.reason,
                    matched_rule: MatchedRule::Rule(hit.rule_id),
                    risk: Risk::High,
                    stage: EvalStage::HardDeny,
                };
            }
        }
    }

    // Stage 2 — secret detection. A `secret.detected` action carries a finding
    // the Secret_Scanner already produced; the evaluator denies it here so the
    // broker can surface exit-code-6 semantics.
    if let ActionPayload::Secret { finding } = &action.payload {
        let reason = if finding.reason.is_empty() {
            format!("detected secret matching `{}`", finding.pattern_id)
        } else {
            finding.reason.clone()
        };
        return DecisionResult {
            decision: Decision::Deny,
            reason,
            matched_rule: MatchedRule::Rule(format!("secret.{}", finding.pattern_id)),
            risk: Risk::High,
            stage: EvalStage::SecretDetection,
        };
    }

    // Stage 3 — explicit deny rules.
    if let Some(hit) = match_explicit_tier(policy, action, Tier::Deny) {
        return explicit_result(Decision::Deny, EvalStage::ExplicitDeny, hit);
    }

    // Stage 4 — explicit allow rules.
    if let Some(hit) = match_explicit_tier(policy, action, Tier::Allow) {
        return explicit_result(Decision::Allow, EvalStage::ExplicitAllow, hit);
    }

    // Stage 5 — explicit ask rules.
    if let Some(hit) = match_explicit_tier(policy, action, Tier::Ask) {
        return explicit_result(Decision::Ask, EvalStage::ExplicitAsk, hit);
    }

    // Stage 6 — profile default decision.
    if let Some(decision) = policy.profile_default_decision {
        return DecisionResult {
            decision,
            reason: format!("profile default decision (`{}`)", decision_word(decision)),
            matched_rule: MatchedRule::NoExplicitRule,
            risk: risk_for(decision),
            stage: EvalStage::ProfileDefault,
        };
    }

    // Stage 7 — global default decision.
    DecisionResult {
        decision: policy.default_decision,
        reason: format!(
            "global default decision (`{}`)",
            decision_word(policy.default_decision)
        ),
        matched_rule: MatchedRule::NoExplicitRule,
        risk: risk_for(policy.default_decision),
        stage: EvalStage::GlobalDefault,
    }
}

fn network_hard_deny_is_explicitly_allowed(policy: &CompiledPolicy, action: &Action) -> bool {
    matches!(action.payload, ActionPayload::Network { .. })
        && match_explicit_tier(policy, action, Tier::Allow).is_some()
}

/// Build the [`DecisionResult`] for an explicit-rule match, guaranteeing a
/// non-empty reason.
fn explicit_result(decision: Decision, stage: EvalStage, hit: ExplicitHit) -> DecisionResult {
    let reason = non_empty(hit.reason, &hit.rule_id);
    DecisionResult {
        decision,
        reason,
        matched_rule: MatchedRule::Rule(hit.rule_id),
        risk: risk_for(decision),
        stage,
    }
}

/// Find the first rule in the given tier that matches the action, dispatching
/// to the per-kind matcher seam ([`crate::matchers`]). Returns `None` when no
/// rule in that tier matches (or the action kind has no explicit rules).
fn match_explicit_tier(
    policy: &CompiledPolicy,
    action: &Action,
    tier: Tier,
) -> Option<ExplicitHit> {
    match &action.payload {
        ActionPayload::Command { argv, cwd } => {
            let rules = match tier {
                Tier::Deny => &policy.commands.deny,
                Tier::Allow => &policy.commands.allow,
                Tier::Ask => &policy.commands.ask,
            };
            rules
                .iter()
                .find(|rule| command::command_rule_matches(rule, argv, cwd))
                .map(|rule| ExplicitHit {
                    rule_id: rule.rule_id.clone(),
                    reason: rule.reason.clone(),
                })
        }
        ActionPayload::File { path } => {
            let section = match action.kind {
                ActionKind::FileRead => &policy.files.read,
                ActionKind::FileWrite | ActionKind::FileDelete => &policy.files.write,
                // A File payload only appears on file kinds; anything else has
                // no file rules to match.
                _ => return None,
            };
            let rules = match tier {
                Tier::Deny => &section.deny,
                Tier::Allow => &section.allow,
                Tier::Ask => &section.ask,
            };
            rules
                .iter()
                .find(|rule| resource::glob_matches(rule, path))
                .map(|rule| ExplicitHit {
                    rule_id: rule.rule_id.clone(),
                    reason: Some(format!("path matches `{}`", rule.source)),
                })
        }
        ActionPayload::Network { target } => {
            let rules = match tier {
                Tier::Deny => &policy.network.deny,
                Tier::Allow => &policy.network.allow,
                Tier::Ask => &policy.network.ask,
            };
            rules
                .iter()
                .find(|rule| resource::net_matches(rule, target))
                .map(|rule| ExplicitHit {
                    rule_id: rule.rule_id.clone(),
                    reason: rule.reason.clone(),
                })
        }
        ActionPayload::Mcp { tool_name } => {
            let rules = match tier {
                Tier::Deny => &policy.mcp.tools.deny,
                Tier::Allow => &policy.mcp.tools.allow,
                Tier::Ask => &policy.mcp.tools.ask,
            };
            rules
                .iter()
                .find(|rule| resource::tool_matches(rule, tool_name))
                .map(|rule| ExplicitHit {
                    rule_id: rule.rule_id.clone(),
                    reason: rule.reason.clone(),
                })
        }
        // Secrets resolve at stage 2; no explicit-rule tier applies.
        ActionPayload::Secret { .. } => None,
    }
}

/// Coerce an optional reason into a guaranteed non-empty string, falling back
/// to the matched rule id (the reason is always non-empty).
fn non_empty(reason: Option<String>, rule_id: &str) -> String {
    match reason {
        Some(r) if !r.is_empty() => r,
        _ => format!("matched rule `{rule_id}`"),
    }
}

/// Default risk level for a resolved decision. Denies are high-risk, asks are
/// medium, allows/dry-runs are low — a total mapping so every result carries a
/// risk (design Property 4).
fn risk_for(decision: Decision) -> Risk {
    match decision {
        Decision::Deny => Risk::High,
        Decision::Ask => Risk::Medium,
        Decision::Allow | Decision::DryRun => Risk::Low,
    }
}

/// The wire word for a decision, used in generated default reasons.
fn decision_word(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
        Decision::DryRun => "dry_run",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::{PolicySource, load_source};
    use fida_action::{Actor, Finding, NetTarget, Protocol};
    use std::path::PathBuf;

    fn builtin() -> CompiledPolicy {
        load_source(&PolicySource::BuiltinDefault, None).expect("builtin policy compiles")
    }

    fn command_action(parts: &[&str]) -> Action {
        Action {
            kind: ActionKind::CommandRun,
            actor: Actor::Agent,
            payload: ActionPayload::Command {
                argv: parts.iter().map(|s| s.to_string()).collect(),
                cwd: PathBuf::from("/repo"),
            },
        }
    }

    fn network_action(host: &str) -> Action {
        Action {
            kind: ActionKind::NetworkRequest,
            actor: Actor::Agent,
            payload: ActionPayload::Network {
                target: NetTarget {
                    domain: None,
                    host: host.to_string(),
                    protocol: Protocol::Https,
                },
            },
        }
    }

    fn assert_non_empty(result: &DecisionResult) {
        assert!(!result.reason.is_empty(), "reason must be non-empty");
    }

    #[test]
    fn evaluation_is_deterministic() {
        let policy = builtin();
        let action = command_action(&["git", "status"]);
        let a = evaluate(&policy, &action);
        let b = evaluate(&policy, &action);
        assert_eq!(a, b);
    }

    #[test]
    fn explicit_allow_resolves_before_default() {
        let policy = builtin();
        // `git status` is an explicit allow in the builtin policy.
        let result = evaluate(&policy, &command_action(&["git", "status"]));
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.stage, EvalStage::ExplicitAllow);
        assert_eq!(result.risk, Risk::Low);
        assert_non_empty(&result);
    }

    #[test]
    fn hard_deny_dominates_when_enabled() {
        let policy = builtin();
        let result = evaluate(&policy, &command_action(&["rm", "-rf", "/"]));
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.stage, EvalStage::HardDeny);
        assert_eq!(result.risk, Risk::High);
        assert!(matches!(result.matched_rule, MatchedRule::Rule(_)));
        assert_non_empty(&result);
    }

    #[test]
    fn explicit_allow_does_not_override_destructive_command_hard_deny() {
        let yaml = "\
version: 1
default_decision: deny
commands:
  allow:
    - exact: rm -rf /
";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.yaml");
        std::fs::write(&path, yaml).unwrap();
        let policy = load_source(&PolicySource::Config(path), None).unwrap();

        let result = evaluate(&policy, &command_action(&["rm", "-rf", "/"]));
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.stage, EvalStage::HardDeny);
    }

    #[test]
    fn metadata_host_denied_by_default() {
        let policy = builtin();
        // 169.254.169.254 is a built-in hard deny.
        let result = evaluate(&policy, &network_action("169.254.169.254"));
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.stage, EvalStage::HardDeny);
    }

    #[test]
    fn private_cidr_denied_by_default() {
        let policy = builtin();
        // 10.0.0.1 falls inside the built-in 10.0.0.0/8 range.
        let result = evaluate(&policy, &network_action("10.0.0.1"));
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.stage, EvalStage::HardDeny);
    }

    #[test]
    fn secret_detected_denies_at_stage_two() {
        let policy = builtin();
        let action = Action {
            kind: ActionKind::SecretDetected,
            actor: Actor::Agent,
            payload: ActionPayload::Secret {
                finding: Finding {
                    pattern_id: "aws_key".to_string(),
                    reason: "matched AWS key".to_string(),
                },
            },
        };
        let result = evaluate(&policy, &action);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.stage, EvalStage::SecretDetection);
        assert_non_empty(&result);
    }

    #[test]
    fn falls_through_to_global_default() {
        let policy = builtin();
        // An unmatched command falls through to the global default (`allow`).
        let result = evaluate(&policy, &command_action(&["some-unknown-tool", "--flag"]));
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.stage, EvalStage::GlobalDefault);
        assert_eq!(result.matched_rule, MatchedRule::NoExplicitRule);
        assert_non_empty(&result);
    }

    #[test]
    fn hard_deny_skipped_when_disabled() {
        // With hard denies disabled, `rm -rf /` is no longer hard-denied and
        // falls through to the global default (`allow`) — never silently
        // denied (design Property 3).
        let yaml = "version: 1\ndefault_decision: allow\nhard_denies_disabled: true\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.yaml");
        std::fs::write(&path, yaml).unwrap();
        let compiled = load_source(&PolicySource::Config(path), None).unwrap();

        let result = evaluate(&compiled, &command_action(&["rm", "-rf", "/"]));
        assert_ne!(result.stage, EvalStage::HardDeny);
        assert_eq!(result.decision, Decision::Allow);
    }
}
