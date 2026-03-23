/// Policy engine: evaluates intercepted requests against Rego policies.
///
/// Policies receive the standard schema as `input` and return:
///   - `{"decision": "allow", "reason": "..."}` — explicit allow
///   - `{"decision": "deny", "reason": "..."}` — explicit deny
///   - undefined (no matching rule) — no opinion, pass through
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use regorus::Engine;
use tracing::{error, info};

use crate::schema::{InterceptedEvent, PolicyDecision};

const QUERY_RULE: &str = "data.agentic.policy.decision";

pub fn build_engine(policy_dir: &Path) -> Engine {
    let mut engine = Engine::new();

    let entries: Vec<_> = fs::read_dir(policy_dir)
        .unwrap_or_else(|e| {
            error!("cannot read policy dir {}: {e}", policy_dir.display());
            std::process::exit(1);
        })
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "rego")
                .unwrap_or(false)
        })
        .collect();

    if entries.is_empty() {
        error!("no .rego files found in {}", policy_dir.display());
        std::process::exit(1);
    }

    for entry in &entries {
        let path = entry.path();
        let content = fs::read_to_string(&path).unwrap_or_else(|e| {
            error!("cannot read {}: {e}", path.display());
            std::process::exit(1);
        });
        engine
            .add_policy(path.display().to_string(), content)
            .unwrap_or_else(|e| {
                error!("policy error in {}: {e}", path.display());
                std::process::exit(1);
            });
        info!("loaded {}", path.display());
    }

    engine
}

/// Evaluate a normalized event against the loaded policies.
pub fn evaluate(engine: &Mutex<Engine>, request: &InterceptedEvent) -> PolicyDecision {
    let input_json = match serde_json::to_string(request) {
        Ok(s) => s,
        Err(e) => {
            error!("failed to serialize request: {e}");
            return PolicyDecision::Deny {
                reason: format!("Internal error: {e}"),
            };
        }
    };

    let input = match regorus::Value::from_json_str(&input_json) {
        Ok(v) => v,
        Err(e) => {
            error!("regorus input conversion failed: {e}");
            return PolicyDecision::Deny {
                reason: format!("Policy engine error: {e}"),
            };
        }
    };

    let mut eng = engine.lock().unwrap_or_else(|e| {
        tracing::warn!("engine mutex poisoned, recovering");
        e.into_inner()
    });
    eng.set_input(input);

    match eng.eval_rule(QUERY_RULE.to_string()) {
        Ok(result) => interpret_result(&result),
        Err(e) => {
            error!("policy evaluation error: {e}");
            PolicyDecision::Deny {
                reason: format!("Policy evaluation error: {e}"),
            }
        }
    }
}

fn interpret_result(value: &regorus::Value) -> PolicyDecision {
    if matches!(value, regorus::Value::Undefined) {
        return PolicyDecision::PassThrough;
    }

    let json_str = match value.to_json_str() {
        Ok(s) => s,
        Err(e) => {
            error!("could not serialize policy result: {e}");
            return PolicyDecision::Deny {
                reason: format!("Could not serialize policy result: {e}"),
            };
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => {
            error!("could not parse policy result as JSON: {e}");
            return PolicyDecision::Deny {
                reason: format!("Policy result parse error: {e}"),
            };
        }
    };

    let decision = parsed
        .get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let reason = parsed
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    match decision {
        "allow" => PolicyDecision::Allow { reason },
        "deny" => PolicyDecision::Deny { reason },
        _ => PolicyDecision::PassThrough,
    }
}
