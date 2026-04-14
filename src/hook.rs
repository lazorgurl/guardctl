use serde_json::Value;
use std::io::Read;

use crate::guards::Decision;

pub fn read_stdin() -> Option<Value> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf).ok()?;
    if buf.trim().is_empty() {
        return None;
    }
    serde_json::from_str(&buf).ok()
}

/// Build the PreToolUse hook JSON response. `decision` is either `Decision::Deny`
/// (hard stop) or `Decision::Ask` (surfaces a confirmation prompt to the user).
pub fn decision_json(decision: Decision, reason: &str) -> String {
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.as_str(),
            "permissionDecisionReason": reason
        }
    })
    .to_string()
}
