use serde_json::{json, Map, Value};
use std::path::PathBuf;

fn settings_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".claude")
        .join("settings.json")
}

fn guardctl_binary() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "guardctl".into())
}

fn desired_hooks(bin: &str) -> Vec<Value> {
    vec![
        json!({ "matcher": "Bash", "command": format!("{bin} check bash") }),
        json!({ "matcher": "Write|Edit", "command": format!("{bin} check file-write") }),
        json!({ "matcher": "mcp__.*", "command": format!("{bin} check mcp") }),
    ]
}

fn has_guardctl_hook(hooks: &[Value], bin: &str) -> Vec<bool> {
    let desired = desired_hooks(bin);
    desired
        .iter()
        .map(|d| {
            let d_matcher = d.get("matcher").and_then(|v| v.as_str()).unwrap_or("");
            hooks.iter().any(|h| {
                let cmd = h.get("command").and_then(|v| v.as_str()).unwrap_or("");
                let matcher = h.get("matcher").and_then(|v| v.as_str()).unwrap_or("");
                matcher == d_matcher && cmd.contains("guardctl check")
            })
        })
        .collect()
}

pub fn install() -> Result<(), String> {
    let path = settings_path();
    let bin = guardctl_binary();

    let mut settings: Map<String, Value> = if path.exists() {
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
        serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse {}: {e}", path.display()))?
    } else {
        Map::new()
    };

    let hooks = settings
        .entry("hooks")
        .or_insert_with(|| json!({}));

    let pre_tool_use = hooks
        .as_object_mut()
        .ok_or("hooks is not an object")?
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));

    let existing = pre_tool_use
        .as_array()
        .cloned()
        .unwrap_or_default();

    let present = has_guardctl_hook(&existing, &bin);
    let desired = desired_hooks(&bin);
    let mut added = 0;

    let arr = pre_tool_use.as_array_mut().ok_or("PreToolUse is not an array")?;
    for (i, hook) in desired.into_iter().enumerate() {
        if !present[i] {
            arr.push(hook);
            added += 1;
        }
    }

    if added == 0 {
        eprintln!("guardctl hooks already installed in {}", path.display());
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let json = serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("Failed to serialize settings: {e}"))?;
    std::fs::write(&path, json)
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;

    eprintln!("Installed {added} guardctl hook(s) into {}", path.display());
    Ok(())
}
