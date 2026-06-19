//! JSON Schema generation for the version-1 policy document
//! (spec task 3.6; `fida policy schema`).
//!
//! [`policy_json_schema`] returns a JSON Schema (Draft 2020-12) describing the
//! shape of a version-1 `fida.yaml` / `.fida/policy.yaml` document. The CLI
//! prints this verbatim for `fida policy schema`. It is also the canonical,
//! machine-readable contract that `policy check` and the `init` self-check
//! validate against (the actual validation lives in
//! [`crate::loader::validate_raw`], which mirrors the constraints encoded here).
//!
//! The schema is hand-written rather than derived so it stays self-contained
//! within `fida-policy` (no extra workspace dependencies and no derive
//! coupling across crates) while precisely capturing the version-1 contract:
//! `version` must equal `1`, `default_decision` is restricted to the three
//! gate decisions, and the flattened command/network matchers are expressed as
//! `oneOf` alternatives exactly as they appear in YAML.

use serde_json::{Value, json};

/// Decisions valid for a `default_decision` slot: the three
/// concrete gates. `dry_run` is a runtime mode, never a configured default.
pub(crate) const DEFAULT_DECISIONS: [&str; 3] = ["allow", "ask", "deny"];

/// Session modes accepted in a profile `mode` override.
pub(crate) const MODES: [&str; 3] = ["observe", "enforce", "dry-run"];

/// Build the JSON Schema (Draft 2020-12) for the version-1 policy document.
///
/// Printed verbatim by `fida policy schema`.
pub fn policy_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://fida.dev/schemas/policy/v1.json",
        "title": "Fida Policy (version 1)",
        "description": "Schema for a version-1 Fida policy file (fida.yaml / .fida/policy.yaml).",
        "type": "object",
        "required": ["version", "default_decision"],
        "additionalProperties": false,
        "properties": {
            "version": {
                "description": "Declared schema version. Only 1 is supported.",
                "const": 1
            },
            "default_decision": decision_enum_schema(
                "Global default decision applied when no rule matches."
            ),
            "profiles": {
                "description": "Named profiles selectable with --profile.",
                "type": "object",
                "additionalProperties": { "$ref": "#/$defs/profile" }
            },
            "commands": { "$ref": "#/$defs/commandSection" },
            "files": { "$ref": "#/$defs/fileSection" },
            "network": { "$ref": "#/$defs/networkSection" },
            "mcp": { "$ref": "#/$defs/mcpSection" },
            "secrets": { "$ref": "#/$defs/secretSection" },
            "audit": { "$ref": "#/$defs/auditSection" },
            "hard_denies_disabled": {
                "description": "When true, the built-in hard-deny stage is skipped.",
                "type": "boolean",
                "default": false
            },
            "agents": {
                "description": "Configured agent binaries Fida knows how to launch.",
                "type": "array",
                "items": { "type": "string" }
            }
        },
        "$defs": defs()
    })
}

/// An `enum` schema over the three default decisions with a description.
fn decision_enum_schema(description: &str) -> Value {
    json!({
        "description": description,
        "type": "string",
        "enum": DEFAULT_DECISIONS
    })
}

/// All reusable subschemas referenced via `$ref`.
fn defs() -> Value {
    json!({
        "profile": {
            "description": "A named set of overrides layered over the base policy.",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "parent": {
                    "description": "Parent profile to inherit from before applying this profile's overrides.",
                    "type": "string"
                },
                "default_decision": decision_enum_schema(
                    "Profile-level default decision (evaluation stage 6)."
                ),
                "mode": {
                    "description": "Session enforcement mode override.",
                    "type": "string",
                    "enum": MODES
                },
                "commands": { "$ref": "#/$defs/commandSection" },
                "files": { "$ref": "#/$defs/fileSection" },
                "network": { "$ref": "#/$defs/networkSection" },
                "mcp": { "$ref": "#/$defs/mcpSection" },
                "secrets": { "$ref": "#/$defs/secretSection" },
                "audit": { "$ref": "#/$defs/auditSection" },
                "hard_denies_disabled": { "type": "boolean" },
                "agents": { "type": "array", "items": { "type": "string" } }
            }
        },

        "commandSection": {
            "description": "Command rules grouped by decision tier.",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "allow": { "type": "array", "items": { "$ref": "#/$defs/commandRule" } },
                "ask": { "type": "array", "items": { "$ref": "#/$defs/commandRule" } },
                "deny": { "type": "array", "items": { "$ref": "#/$defs/commandRule" } }
            }
        },
        "commandRule": {
            "description": "A single command rule: exactly one matcher plus optional metadata.",
            "type": "object",
            "additionalProperties": false,
            "oneOf": [
                command_matcher_variant("exact", "Full command string equals this value."),
                command_matcher_variant("prefix", "Command string starts with this value on a token boundary."),
                command_matcher_variant("regex", "Regular expression matched against the command string."),
                command_matcher_variant("binary", "First argv token's basename equals this binary name.")
            ],
            "properties": {
                "exact": { "type": "string" },
                "prefix": { "type": "string" },
                "regex": { "type": "string" },
                "binary": { "type": "string" },
                "working_dir": {
                    "description": "Rule applies only when the action cwd equals or nests under this path.",
                    "type": "string"
                },
                "reason": { "type": "string" },
                "auto_approve": {
                    "description": "Eligibility for --yes auto-approval.",
                    "type": "boolean",
                    "default": false
                }
            }
        },

        "fileSection": {
            "description": "File policy split into read and write path rules.",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "read": { "$ref": "#/$defs/pathRules" },
                "write": { "$ref": "#/$defs/pathRules" }
            }
        },
        "pathRules": {
            "description": "Glob path rules grouped by decision tier.",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "allow": { "$ref": "#/$defs/globList" },
                "ask": { "$ref": "#/$defs/globList" },
                "deny": { "$ref": "#/$defs/globList" }
            }
        },
        "globList": {
            "type": "array",
            "items": { "type": "string", "description": "A glob path pattern, e.g. src/** or **/*.pem." }
        },

        "networkSection": {
            "description": "Network rules grouped by decision tier.",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "allow": { "type": "array", "items": { "$ref": "#/$defs/netRule" } },
                "ask": { "type": "array", "items": { "$ref": "#/$defs/netRule" } },
                "deny": { "type": "array", "items": { "$ref": "#/$defs/netRule" } }
            }
        },
        "netRule": {
            "description": "A single network rule: exactly one target plus an optional reason.",
            "type": "object",
            "additionalProperties": false,
            "oneOf": [
                net_target_variant("domain", "Domain match; wildcard * supported."),
                net_target_variant("host", "Exact host (hostname or IP literal)."),
                net_target_variant("cidr", "CIDR membership, e.g. 192.168.0.0/16.")
            ],
            "properties": {
                "domain": { "type": "string" },
                "host": { "type": "string" },
                "cidr": { "type": "string" },
                "reason": { "type": "string" }
            }
        },

        "mcpSection": {
            "description": "MCP policy scoping tools/call gating.",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "tools": { "$ref": "#/$defs/toolRules" }
            }
        },
        "toolRules": {
            "description": "MCP tool-name rules grouped by decision tier.",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "allow": { "type": "array", "items": { "$ref": "#/$defs/toolPattern" } },
                "ask": { "type": "array", "items": { "$ref": "#/$defs/toolPattern" } },
                "deny": { "type": "array", "items": { "$ref": "#/$defs/toolPattern" } }
            }
        },
        "toolPattern": {
            "description": "A glob/prefix pattern over dotted MCP tool names (e.g. browser.*).",
            "type": "object",
            "additionalProperties": false,
            "required": ["pattern"],
            "properties": {
                "pattern": { "type": "string" },
                "reason": { "type": "string" }
            }
        },

        "secretSection": {
            "description": "Secret detection / redaction configuration.",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "redact": {
                    "description": "Enable redaction before any audit write.",
                    "type": "boolean",
                    "default": false
                },
                "block_in_diffs": {
                    "description": "Block applying a diff file that contains a detected secret.",
                    "type": "boolean",
                    "default": false
                },
                "patterns": {
                    "type": "array",
                    "items": { "$ref": "#/$defs/secretPattern" }
                }
            }
        },
        "secretPattern": {
            "description": "A named secret pattern: identifier plus the detection regex.",
            "type": "object",
            "additionalProperties": false,
            "required": ["name", "regex"],
            "properties": {
                "name": { "type": "string" },
                "regex": { "type": "string" }
            }
        },

        "auditSection": {
            "description": "Audit store configuration.",
            "type": "object",
            "additionalProperties": false,
            "required": ["path", "format"],
            "properties": {
                "path": {
                    "description": "Directory under which session audit trails are written.",
                    "type": "string"
                },
                "format": {
                    "description": "On-disk audit format. JSONL is the only supported format.",
                    "type": "string",
                    "enum": ["jsonl"]
                },
                "redact_stdout": { "type": "boolean", "default": true },
                "redact_stderr": { "type": "boolean", "default": true }
            }
        }
    })
}

/// A `oneOf` branch requiring a single command-matcher key.
fn command_matcher_variant(key: &str, description: &str) -> Value {
    json!({
        "required": [key],
        "properties": { key: { "type": "string", "description": description } }
    })
}

/// A `oneOf` branch requiring a single network-target key.
fn net_target_variant(key: &str, description: &str) -> Value {
    json!({
        "required": [key],
        "properties": { key: { "type": "string", "description": description } }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::BUILTIN_DEFAULT_POLICY;

    #[test]
    fn schema_has_expected_top_level_shape() {
        let schema = policy_json_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["version"]["const"], 1);

        let required: Vec<&str> = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(required.contains(&"version"));
        assert!(required.contains(&"default_decision"));
    }

    #[test]
    fn default_decision_enum_excludes_dry_run() {
        let schema = policy_json_schema();
        let values: Vec<&str> = schema["properties"]["default_decision"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(values, vec!["allow", "ask", "deny"]);
        assert!(!values.contains(&"dry_run"));
    }

    #[test]
    fn schema_is_valid_json_object_with_defs() {
        let schema = policy_json_schema();
        assert!(schema["$defs"]["commandRule"].is_object());
        assert!(schema["$defs"]["netRule"].is_object());
        // Serializes cleanly (this is what `policy schema` prints).
        let printed = serde_json::to_string_pretty(&schema).expect("schema serializes");
        assert!(printed.contains("\"version\""));
    }

    #[test]
    fn builtin_default_policy_matches_described_field_names() {
        // Sanity: every top-level key used by the built-in default is a known
        // property in the schema (guards against schema/struct drift).
        let policy: serde_yaml::Value = serde_yaml::from_str(BUILTIN_DEFAULT_POLICY).unwrap();
        let schema = policy_json_schema();
        let props = schema["properties"].as_object().unwrap();
        for key in policy.as_mapping().unwrap().keys() {
            let key = key.as_str().unwrap();
            assert!(
                props.contains_key(key),
                "built-in default uses unknown top-level key `{key}`"
            );
        }
    }
}
