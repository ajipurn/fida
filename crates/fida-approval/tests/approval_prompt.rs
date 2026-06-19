//! Integration tests for the Approval_UI prompt loop (spec task 10.2).
//!
//! These exercise [`fida_approval::prompt_with_io`] through a *scripted
//! terminal*: input is a [`std::io::Cursor`] over a fixed byte script and
//! output is captured into a `Vec<u8>`. Each test covers one of the behaviors
//! required by the workflow:
//!
//! - allow once → `Allowed`
//! - deny once → `Denied`
//! - remember for session → `AllowedRemembered`
//! - the prompt presents exactly the four choices and the five fields
//!   kind/target/risk/reason/matched_rule
//! - view context displays the full context then re-presents without resolving
//! - unrecognized input re-presents without resolving
//! - EOF before resolution surfaces an error rather than hanging

use std::io::{self, Cursor};

use fida_action::{ActionKind, MatchedRule, Risk};
use fida_approval::{ApprovalOutcome, ApprovalPresentation};

/// Build a representative `ask` presentation for a high-risk command.
fn presentation() -> ApprovalPresentation {
    ApprovalPresentation {
        kind: ActionKind::CommandRun,
        target: "rm -rf build".to_string(),
        risk: Risk::High,
        reason: "matches an ask rule".to_string(),
        matched_rule: MatchedRule::Rule("commands.ask[0]".to_string()),
        context: "argv: [rm, -rf, build]\ncwd: /repo\nprofile: careful".to_string(),
    }
}

/// Drive the prompt loop with a scripted terminal, returning the resolved
/// outcome and everything that was rendered to the output stream.
fn run_script(script: &str) -> io::Result<(ApprovalOutcome, String)> {
    let mut input = Cursor::new(script.as_bytes().to_vec());
    let mut output: Vec<u8> = Vec::new();
    let outcome = fida_approval::prompt_with_io(&presentation(), &mut input, &mut output)?;
    Ok((
        outcome,
        String::from_utf8(output).expect("output is valid UTF-8"),
    ))
}

/// Count how many times the prompt header was re-presented.
fn header_count(rendered: &str) -> usize {
    rendered.matches("Approval required").count()
}

#[test]
fn scripted_allow_once_resolves_allowed() {
    // allow once permits the action exactly once.
    let (outcome, rendered) = run_script("1\n").unwrap();
    assert_eq!(outcome, ApprovalOutcome::Allowed);
    // Resolves on the first prompt — no re-present.
    assert_eq!(header_count(&rendered), 1);
}

#[test]
fn scripted_deny_once_resolves_denied() {
    // deny once blocks the action.
    let (outcome, rendered) = run_script("2\n").unwrap();
    assert_eq!(outcome, ApprovalOutcome::Denied);
    assert_eq!(header_count(&rendered), 1);
}

#[test]
fn scripted_remember_resolves_allowed_remembered() {
    // remember for session permits and signals reuse.
    let (outcome, rendered) = run_script("3\n").unwrap();
    assert_eq!(outcome, ApprovalOutcome::AllowedRemembered);
    assert_eq!(header_count(&rendered), 1);
}

#[test]
fn scripted_word_inputs_resolve_each_choice() {
    // The word mnemonics resolve identically to the numeric indices.
    assert_eq!(run_script("allow\n").unwrap().0, ApprovalOutcome::Allowed);
    assert_eq!(run_script("deny\n").unwrap().0, ApprovalOutcome::Denied);
    assert_eq!(
        run_script("remember for session\n").unwrap().0,
        ApprovalOutcome::AllowedRemembered
    );
}

#[test]
fn scripted_prompt_presents_five_fields_and_exactly_four_choices() {
    // the single prompt shows kind, target, risk, reason, matched rule.
    let (_, rendered) = run_script("1\n").unwrap();
    assert!(rendered.contains("command.run"), "kind field missing");
    assert!(rendered.contains("rm -rf build"), "target field missing");
    assert!(rendered.contains("high"), "risk field missing");
    assert!(
        rendered.contains("matches an ask rule"),
        "reason field missing"
    );
    assert!(rendered.contains("commands.ask[0]"), "matched rule missing");

    // exactly the four choices are offered.
    assert!(rendered.contains("allow once"));
    assert!(rendered.contains("deny once"));
    assert!(rendered.contains("remember for session"));
    assert!(rendered.contains("view context"));
    // No fifth choice slot is rendered.
    assert!(
        !rendered.contains("[5]"),
        "an unexpected fifth choice was offered"
    );
}

#[test]
fn scripted_view_context_displays_context_then_re_presents() {
    // view context shows the full context, then re-presents the same
    // prompt without resolving; the subsequent valid choice resolves it.
    let (outcome, rendered) = run_script("4\n1\n").unwrap();
    assert_eq!(outcome, ApprovalOutcome::Allowed);

    // The full action context is displayed.
    assert!(rendered.contains("Context:"));
    assert!(rendered.contains("cwd: /repo"));
    assert!(rendered.contains("profile: careful"));

    // The prompt header appears twice: the initial prompt and the re-present
    // after viewing context.
    assert_eq!(header_count(&rendered), 2);
}

#[test]
fn scripted_view_context_can_be_repeated_before_resolving() {
    // Viewing context twice re-presents twice more (3 headers total) and never
    // resolves until a real choice is made.
    let (outcome, rendered) = run_script("4\n4\n2\n").unwrap();
    assert_eq!(outcome, ApprovalOutcome::Denied);
    assert_eq!(header_count(&rendered), 3);
    assert_eq!(rendered.matches("Context:").count(), 2);
}

#[test]
fn scripted_invalid_input_re_presents_without_resolving() {
    // two unrecognized inputs each re-present the prompt; the final
    // valid choice resolves. Initial + 2 re-presents = 3 headers.
    let (outcome, rendered) = run_script("huh\nwhat\n2\n").unwrap();
    assert_eq!(outcome, ApprovalOutcome::Denied);
    assert_eq!(header_count(&rendered), 3);
}

#[test]
fn scripted_invalid_then_view_context_then_valid_resolves() {
    // Mixed invalid input and view context before a valid
    // choice. Initial + invalid re-present + view-context re-present = 3.
    let (outcome, rendered) = run_script("nope\n4\n3\n").unwrap();
    assert_eq!(outcome, ApprovalOutcome::AllowedRemembered);
    assert_eq!(header_count(&rendered), 3);
    assert!(rendered.contains("Context:"));
}

#[test]
fn scripted_eof_before_resolution_errors_instead_of_hanging() {
    // EOF after only unrecognized input must surface an error, never hang.
    let err = run_script("nope\n").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn scripted_empty_input_errors_immediately() {
    // An empty script (immediate EOF) also fails closed with an error.
    let err = run_script("").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}
