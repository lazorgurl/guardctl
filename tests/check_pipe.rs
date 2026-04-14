//! End-to-end tests for `guardctl check <guard>`: spawn the built binary,
//! pipe JSON to stdin, and assert the response the way Claude Code would
//! actually see it.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

/// Path to the built guardctl binary (provided by cargo for integration tests).
fn guardctl_bin() -> &'static str {
    env!("CARGO_BIN_EXE_guardctl")
}

/// Give each test its own isolated HOME/state/log under the target directory
/// so nothing leaks between parallel test processes.
fn fresh_sandbox() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!(
        "guardctl-it-{}-{}-{}",
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&base).expect("create sandbox dir");
    base
}

struct CheckOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_check(guard: &str, stdin_json: &str) -> CheckOutput {
    let sandbox = fresh_sandbox();
    let state_path = sandbox.join("state.json");
    let log_path = sandbox.join("log.jsonl");

    let mut child = Command::new(guardctl_bin())
        .arg("check")
        .arg(guard)
        .env("GUARDCTL_STATE", &state_path)
        .env("GUARDCTL_LOG", &log_path)
        .env("HOME", &sandbox)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn guardctl");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin_json.as_bytes())
        .expect("write stdin");

    let out = child.wait_with_output().expect("wait");
    CheckOutput {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn assert_deny(out: &CheckOutput, needle: &str) {
    assert_eq!(out.code, 0, "exit code: {} stderr={}", out.code, out.stderr);
    let v: serde_json::Value = serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("stdout was not JSON: {e}; body={}", out.stdout));
    let hs = v.get("hookSpecificOutput").expect("hookSpecificOutput missing");
    assert_eq!(
        hs.get("hookEventName").and_then(|v| v.as_str()),
        Some("PreToolUse"),
        "wrong hookEventName in: {}",
        out.stdout
    );
    assert_eq!(
        hs.get("permissionDecision").and_then(|v| v.as_str()),
        Some("deny"),
        "expected deny, got: {}",
        out.stdout
    );
    let reason = hs
        .get("permissionDecisionReason")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        reason.contains(needle),
        "reason {reason:?} did not contain {needle:?}"
    );
}

fn assert_allow_silent(out: &CheckOutput) {
    assert_eq!(out.code, 0, "exit code: {} stderr={}", out.code, out.stderr);
    assert!(
        out.stdout.trim().is_empty(),
        "expected empty stdout on allow, got: {}",
        out.stdout
    );
}

// ---------- bash guard ----------

#[test]
fn bash_blocks_rm_rf() {
    let out = run_check(
        "bash",
        r#"{"tool_input":{"command":"rm -rf /tmp/nope"}}"#,
    );
    assert_deny(&out, "recursive rm");
}

#[test]
fn bash_blocks_force_push() {
    let out = run_check(
        "bash",
        r#"{"tool_input":{"command":"git push origin main --force"}}"#,
    );
    assert_deny(&out, "force");
}

#[test]
fn bash_allows_force_with_lease() {
    // --force-with-lease is the documented exception.
    let out = run_check(
        "bash",
        r#"{"tool_input":{"command":"git push --force-with-lease origin feature"}}"#,
    );
    assert_allow_silent(&out);
}

#[test]
fn bash_allows_benign_ls() {
    let out = run_check(
        "bash",
        r#"{"tool_input":{"command":"ls -la"}}"#,
    );
    assert_allow_silent(&out);
}

// ---------- file-write guard ----------

#[test]
fn file_write_blocks_dotenv() {
    let out = run_check(
        "file-write",
        r#"{"tool_input":{"file_path":"/srv/app/.env"}}"#,
    );
    assert_deny(&out, "secrets");
}

#[test]
fn file_write_allows_source() {
    let out = run_check(
        "file-write",
        r#"{"tool_input":{"file_path":"/srv/app/src/main.rs"}}"#,
    );
    assert_allow_silent(&out);
}

// ---------- mcp guard ----------

#[test]
fn mcp_blocks_cloudflare_delete() {
    let out = run_check(
        "mcp",
        r#"{"tool_name":"mcp__claude_ai_Cloudflare_Developer_Platform__d1_database_delete"}"#,
    );
    assert_deny(&out, "Cloudflare");
}

#[test]
fn mcp_allows_safe_reads() {
    let out = run_check(
        "mcp",
        r#"{"tool_name":"mcp__sentry__list_issues"}"#,
    );
    assert_allow_silent(&out);
}

// ---------- edge cases ----------

#[test]
fn unknown_guard_is_silent_allow() {
    let out = run_check("not-a-guard", r#"{"tool_input":{"command":"rm -rf /"}}"#);
    assert_allow_silent(&out);
}

#[test]
fn invalid_stdin_is_silent_allow() {
    let out = run_check("bash", "not valid json at all");
    assert_allow_silent(&out);
}

#[test]
fn empty_stdin_is_silent_allow() {
    let out = run_check("bash", "");
    assert_allow_silent(&out);
}

#[test]
fn missing_tool_input_is_silent_allow() {
    // Valid JSON but no tool_input/command — bash guard should have nothing to match.
    let out = run_check("bash", r#"{"session_id":"abc"}"#);
    assert_allow_silent(&out);
}

#[test]
fn per_directory_override_disables_guard() {
    // Stand up a state file that disables bash for a specific cwd, then
    // confirm a rm -rf from that cwd is allowed.
    let sandbox = fresh_sandbox();
    let state_path = sandbox.join("state.json");
    let log_path = sandbox.join("log.jsonl");

    let cwd = "/tmp/guardctl-override-zone";
    let state = serde_json::json!({
        "guards": { "bash": true },
        "directories": {
            cwd: { "bash": false }
        }
    });
    std::fs::write(&state_path, state.to_string()).unwrap();

    let stdin = format!(
        r#"{{"cwd":"{cwd}","tool_input":{{"command":"rm -rf /tmp/anything"}}}}"#
    );

    let mut child = Command::new(guardctl_bin())
        .arg("check")
        .arg("bash")
        .env("GUARDCTL_STATE", &state_path)
        .env("GUARDCTL_LOG", &log_path)
        .env("HOME", &sandbox)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child.stdin.as_mut().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();

    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stdout.is_empty(),
        "expected allow for overridden dir, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn audit_log_records_blocks() {
    let sandbox = fresh_sandbox();
    let state_path = sandbox.join("state.json");
    let log_path = sandbox.join("log.jsonl");

    let mut child = Command::new(guardctl_bin())
        .arg("check")
        .arg("bash")
        .env("GUARDCTL_STATE", &state_path)
        .env("GUARDCTL_LOG", &log_path)
        .env("HOME", &sandbox)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"tool_input":{"command":"rm -rf /srv"}}"#)
        .unwrap();
    let _ = child.wait_with_output().unwrap();

    let contents = std::fs::read_to_string(&log_path).expect("log should exist after block");
    assert!(!contents.trim().is_empty(), "log should not be empty");
    // Should be valid JSONL and mention the blocked command.
    let first: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap())
        .expect("log entry should parse as JSON");
    assert_eq!(first.get("guard").and_then(|v| v.as_str()), Some("bash"));
    assert!(first
        .get("blocked")
        .and_then(|v| v.as_str())
        .unwrap()
        .contains("rm -rf"));
}
