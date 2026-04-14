use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

fn log_path() -> PathBuf {
    if let Ok(p) = std::env::var("GUARDCTL_LOG") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".claude")
        .join("hooks")
        .join(".guardctl-log.jsonl")
}

pub fn record(guard: &str, reason: &str, cwd: Option<&str>, input: &Value) {
    let blocked = match guard {
        "bash" => input
            .pointer("/tool_input/command")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        "file-write" => input
            .pointer("/tool_input/file_path")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        "mcp" => input
            .pointer("/tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        _ => "",
    };

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let entry = serde_json::json!({
        "ts": ts,
        "guard": guard,
        "blocked": blocked,
        "reason": reason,
        "cwd": cwd.unwrap_or(""),
    });

    let path = log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        if writeln!(f, "{}", entry).is_ok() {
            // Ensure the entry hits disk — audit trail must survive crashes.
            let _ = f.sync_all();
        }
    }
}

pub fn read_recent(count: usize) -> Vec<Value> {
    let path = log_path();
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };

    let lines: Vec<String> = BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .collect();

    lines
        .iter()
        .rev()
        .take(count)
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}
