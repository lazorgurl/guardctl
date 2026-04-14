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

/// Assert that the response is a PreToolUse decision with the expected
/// `permissionDecision` value (`"deny"` or `"ask"`) and a reason containing
/// `needle`.
fn assert_decision(out: &CheckOutput, expected: &str, needle: &str) {
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
        Some(expected),
        "expected {expected}, got: {}",
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

fn assert_deny(out: &CheckOutput, needle: &str) {
    assert_decision(out, "deny", needle);
}

fn assert_ask(out: &CheckOutput, needle: &str) {
    assert_decision(out, "ask", needle);
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
fn bash_asks_rm_rf() {
    // rm -rf is destructive-but-sometimes-legitimate — surfaces as an "ask"
    // so the user can confirm.
    let out = run_check(
        "bash",
        r#"{"tool_input":{"command":"rm -rf /tmp/nope"}}"#,
    );
    assert_ask(&out, "recursive rm");
}

#[test]
fn bash_asks_force_push() {
    let out = run_check(
        "bash",
        r#"{"tool_input":{"command":"git push origin main --force"}}"#,
    );
    assert_ask(&out, "force");
}

#[test]
fn bash_denies_secret_staging() {
    // Secret staging is a true tripwire — hard deny, no prompt.
    let out = run_check(
        "bash",
        r#"{"tool_input":{"command":"git add .env"}}"#,
    );
    assert_deny(&out, "secrets");
}

#[test]
fn bash_denies_guard_tampering() {
    let out = run_check(
        "bash",
        r#"{"tool_input":{"command":"guardctl off"}}"#,
    );
    assert_deny(&out, "user");
}

#[test]
fn bash_denies_no_verify() {
    let out = run_check(
        "bash",
        r#"{"tool_input":{"command":"git commit --no-verify -m fix"}}"#,
    );
    assert_deny(&out, "no-verify");
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
fn mcp_asks_cloudflare_delete() {
    // Cloudflare deletes are owned-resource destructive — ask.
    let out = run_check(
        "mcp",
        r#"{"tool_name":"mcp__claude_ai_Cloudflare_Developer_Platform__d1_database_delete"}"#,
    );
    assert_ask(&out, "Cloudflare");
}

#[test]
fn mcp_denies_sentry_mutation() {
    // Mutating shared monitoring is a tripwire — hard deny.
    let out = run_check(
        "mcp",
        r#"{"tool_name":"mcp__sentry__update_issue"}"#,
    );
    assert_deny(&out, "Sentry");
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

// ---------- project config (.guardctl.toml) ----------

/// Helper: run `guardctl check <guard>` with a specific cwd and stdin, letting
/// the caller place a `.guardctl.toml` at an ancestor of cwd. HOME is set
/// outside cwd so project discovery walks the whole ancestor chain.
fn run_check_in_project(
    guard: &str,
    project_root: &std::path::Path,
    cwd: &std::path::Path,
    stdin_json: &str,
) -> CheckOutput {
    let sandbox = fresh_sandbox();
    let state_path = sandbox.join("state.json");
    let log_path = sandbox.join("log.jsonl");

    let mut child = Command::new(guardctl_bin())
        .arg("check")
        .arg(guard)
        .env("GUARDCTL_STATE", &state_path)
        .env("GUARDCTL_LOG", &log_path)
        // HOME outside the project tree so discovery walks past the root.
        .env("HOME", &sandbox)
        .current_dir(project_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    // Inject cwd into the hook input so guardctl uses it for discovery.
    let stdin_with_cwd = if stdin_json.contains("\"cwd\"") {
        stdin_json.to_string()
    } else {
        let escaped_cwd = cwd.to_str().unwrap().replace('\\', "\\\\");
        let without_brace = stdin_json.trim_start().trim_start_matches('{');
        format!("{{\"cwd\":\"{escaped_cwd}\",{without_brace}")
    };

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_with_cwd.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    CheckOutput {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

#[test]
fn project_config_allowlist_short_circuits_builtin() {
    let root = fresh_sandbox();
    let project = root.join("project");
    let subdir = project.join("src");
    std::fs::create_dir_all(&subdir).unwrap();

    // Whitelist force-push to the experiment branch. The built-in rule would
    // otherwise ask, but the allow list short-circuits.
    std::fs::write(
        project.join(".guardctl.toml"),
        r#"
[[allow]]
guard = "bash"
pattern = "git push --force origin experiment"
"#,
    )
    .unwrap();

    let out = run_check_in_project(
        "bash",
        &project,
        &subdir,
        r#"{"tool_input":{"command":"git push --force origin experiment"}}"#,
    );
    assert_allow_silent(&out);

    // Sanity: a different force push is NOT allowed.
    let out = run_check_in_project(
        "bash",
        &project,
        &subdir,
        r#"{"tool_input":{"command":"git push --force origin main"}}"#,
    );
    assert_ask(&out, "force");
}

#[test]
fn project_config_extra_rule_adds_project_tripwire() {
    let root = fresh_sandbox();
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();

    std::fs::write(
        project.join(".guardctl.toml"),
        r#"
[[rules]]
guard = "bash"
pattern = "^make deploy-prod"
decision = "ask"
message = "Production deploys need human sign-off"
"#,
    )
    .unwrap();

    let out = run_check_in_project(
        "bash",
        &project,
        &project,
        r#"{"tool_input":{"command":"make deploy-prod --region us"}}"#,
    );
    assert_ask(&out, "Production deploys");

    // Sanity: an unrelated command isn't blocked by the extra rule.
    let out = run_check_in_project(
        "bash",
        &project,
        &project,
        r#"{"tool_input":{"command":"make test"}}"#,
    );
    assert_allow_silent(&out);
}

#[test]
fn project_config_can_disable_guard() {
    let root = fresh_sandbox();
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();

    // Disable the bash guard entirely for this project.
    std::fs::write(
        project.join(".guardctl.toml"),
        r#"
[guards]
bash = false
"#,
    )
    .unwrap();

    // rm -rf would normally ask, but the guard is disabled here.
    let out = run_check_in_project(
        "bash",
        &project,
        &project,
        r#"{"tool_input":{"command":"rm -rf /tmp/scratch"}}"#,
    );
    assert_allow_silent(&out);
}

#[test]
fn project_config_deny_rule_wins_over_ask() {
    let root = fresh_sandbox();
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();

    std::fs::write(
        project.join(".guardctl.toml"),
        r#"
[[rules]]
guard = "file-write"
pattern = "^.*/dist/"
decision = "deny"
message = "dist/ is build output — edit the source"
"#,
    )
    .unwrap();

    let out = run_check_in_project(
        "file-write",
        &project,
        &project,
        r#"{"tool_input":{"file_path":"/srv/app/dist/main.js"}}"#,
    );
    assert_deny(&out, "dist/");
}

#[test]
fn project_config_walk_finds_ancestor() {
    // .guardctl.toml lives at project root; cwd is a subdirectory deep inside.
    let root = fresh_sandbox();
    let project = root.join("monorepo");
    let deep = project.join("services/api/src/handlers");
    std::fs::create_dir_all(&deep).unwrap();

    std::fs::write(
        project.join(".guardctl.toml"),
        r#"
[[rules]]
guard = "bash"
pattern = "^make publish"
decision = "deny"
message = "publish needs manual release"
"#,
    )
    .unwrap();

    let out = run_check_in_project(
        "bash",
        &project,
        &deep,
        r#"{"tool_input":{"command":"make publish"}}"#,
    );
    assert_deny(&out, "publish");
}

// ---------- end project config ----------

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
