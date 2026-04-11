use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

struct Rule {
    pattern: Regex,
    message: &'static str,
    except: Option<Regex>,
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        // --- Filesystem destruction ---
        Rule {
            pattern: Regex::new(r"(?:^|[;&|]\s*)rm\s+-[a-zA-Z]*r[a-zA-Z]*").unwrap(),
            message: "BLOCKED: recursive rm detected. Use targeted 'rm' on specific files instead.",
            except: None,
        },
        Rule {
            pattern: Regex::new(r"(?:^|[;&|]\s*)rm\s.*(?:\s\*\s|\s/\s|/Users/|~/)").unwrap(),
            message: "BLOCKED: rm targeting broad glob or home/root path. Be more specific.",
            except: None,
        },
        // --- Git destruction ---
        Rule {
            pattern: Regex::new(r"git\s+push\s.*--force(?:$|\s)").unwrap(),
            message: "BLOCKED: git push --force. Use --force-with-lease for safer force push, or push normally.",
            except: Some(Regex::new(r"force-with-lease").unwrap()),
        },
        Rule {
            pattern: Regex::new(r"git\s+reset\s+--hard").unwrap(),
            message: "BLOCKED: git reset --hard discards uncommitted work. Use 'git stash' first, or 'git reset --soft'.",
            except: None,
        },
        Rule {
            pattern: Regex::new(r"git\s+clean\s+-[a-zA-Z]*f").unwrap(),
            message: "BLOCKED: git clean -f deletes untracked files permanently. Use 'git clean -n' (dry run) first.",
            except: None,
        },
        Rule {
            pattern: Regex::new(r"git\s+checkout\s+--\s+\.").unwrap(),
            message: "BLOCKED: 'git checkout -- .' discards all unstaged changes. Restore specific files instead.",
            except: None,
        },
        Rule {
            pattern: Regex::new(r"git\s+branch\s+-D\s").unwrap(),
            message: "BLOCKED: git branch -D force-deletes a branch. Use 'git branch -d' (safe delete) instead.",
            except: None,
        },
        // --- Push to protected branches ---
        Rule {
            pattern: Regex::new(r"git\s+push\s.*\b(main|master|stage|pre-release|release)\b").unwrap(),
            message: "BLOCKED: pushing directly to a protected branch. Push to a feature branch and open a PR.",
            except: None,
        },
        // --- Committing secrets ---
        Rule {
            pattern: Regex::new(r"git\s+add\s.*(\.(env|pem|key|p12|pfx|jks|keystore)|credentials|secrets?\.|\.secret|id_rsa|id_ed25519)").unwrap(),
            message: "BLOCKED: staging a file that likely contains secrets. Never commit credentials.",
            except: None,
        },
        Rule {
            pattern: Regex::new(r"git\s+add\s+(-A\b|\.\s*$|--all)").unwrap(),
            message: "BLOCKED: 'git add -A' / 'git add .' can accidentally stage secrets. Stage specific files by name.",
            except: None,
        },
        // --- Self-modification ---
        Rule {
            pattern: Regex::new(r"(>|>>|tee\s).*\.claude/(settings\.json|hooks/)").unwrap(),
            message: "BLOCKED: shell redirect into Claude config/hooks. Use the Edit tool so the file-write-guard can review.",
            except: None,
        },
        // --- Database destruction ---
        Rule {
            pattern: Regex::new(r"(?i)(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)").unwrap(),
            message: "BLOCKED: destructive SQL (DROP/TRUNCATE). This is irreversible in production.",
            except: None,
        },
        // --- Container/infra destruction ---
        Rule {
            pattern: Regex::new(r"docker\s+system\s+prune").unwrap(),
            message: "BLOCKED: docker system prune removes all unused data. Use targeted docker rm/rmi instead.",
            except: None,
        },
        Rule {
            pattern: Regex::new(r"terraform\s+destroy").unwrap(),
            message: "BLOCKED: terraform destroy tears down infrastructure. This needs manual confirmation.",
            except: None,
        },
        Rule {
            pattern: Regex::new(r"kubectl\s+delete\s+(namespace|ns|deployment|all)").unwrap(),
            message: "BLOCKED: kubectl delete on broad resources. Target specific resources instead.",
            except: None,
        },
        // --- Bypassing safety ---
        Rule {
            pattern: Regex::new(r"git\s+(commit|push|rebase)\s.*--no-verify").unwrap(),
            message: "BLOCKED: --no-verify skips hooks. Fix the underlying hook failure instead.",
            except: None,
        },
    ]
});

pub fn check(input: &Value) -> Option<String> {
    let cmd = input
        .pointer("/tool_input/command")
        .and_then(|v| v.as_str())?;

    let norm: String = cmd.split_whitespace().collect::<Vec<_>>().join(" ");

    for rule in RULES.iter() {
        if rule.pattern.is_match(&norm) {
            if let Some(ref except) = rule.except {
                if except.is_match(&norm) {
                    continue;
                }
            }
            return Some(rule.message.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(cmd: &str) -> Value {
        json!({"tool_input": {"command": cmd}})
    }

    fn blocked(cmd: &str) -> bool {
        check(&input(cmd)).is_some()
    }

    #[test]
    fn blocks_rm_rf() {
        assert!(blocked("rm -rf /tmp/stuff"));
        assert!(blocked("rm -fr ."));
        assert!(blocked("rm -r dir/"));
    }

    #[test]
    fn allows_rm_single_file() {
        assert!(!blocked("rm foo.txt"));
        assert!(!blocked("rm src/old_file.rs"));
    }

    #[test]
    fn blocks_force_push() {
        assert!(blocked("git push --force origin main"));
        assert!(blocked("git push origin feat --force"));
    }

    #[test]
    fn allows_force_with_lease() {
        assert!(!blocked("git push --force-with-lease origin feat/foo"));
    }

    #[test]
    fn blocks_reset_hard() {
        assert!(blocked("git reset --hard HEAD~1"));
        assert!(blocked("git reset --hard"));
    }

    #[test]
    fn blocks_push_to_protected() {
        assert!(blocked("git push origin main"));
        assert!(blocked("git push origin stage"));
        assert!(blocked("git push origin release"));
    }

    #[test]
    fn allows_push_to_feature() {
        assert!(!blocked("git push origin feat/my-fix"));
        assert!(!blocked("git push -u origin ws/jira-bugfix"));
    }

    #[test]
    fn blocks_git_add_dot() {
        assert!(blocked("git add ."));
        assert!(blocked("git add -A"));
        assert!(blocked("git add --all"));
    }

    #[test]
    fn allows_git_add_specific() {
        assert!(!blocked("git add src/main.rs src/lib.rs"));
    }

    #[test]
    fn blocks_git_add_secrets() {
        assert!(blocked("git add .env"));
        assert!(blocked("git add server.pem"));
        assert!(blocked("git add id_rsa"));
    }

    #[test]
    fn blocks_no_verify() {
        assert!(blocked("git commit --no-verify -m fix"));
        assert!(blocked("git push --no-verify"));
    }

    #[test]
    fn allows_normal_git() {
        assert!(!blocked("git status"));
        assert!(!blocked("git diff"));
        assert!(!blocked("git log --oneline -10"));
        assert!(!blocked("git commit -m 'fix bug'"));
        assert!(!blocked("git push -u origin feat/fix"));
    }

    #[test]
    fn blocks_destructive_sql() {
        assert!(blocked("psql -c 'DROP TABLE users'"));
        assert!(blocked("echo 'TRUNCATE TABLE logs' | psql"));
    }

    #[test]
    fn blocks_docker_system_prune() {
        assert!(blocked("docker system prune -a"));
    }

    #[test]
    fn blocks_terraform_destroy() {
        assert!(blocked("terraform destroy -auto-approve"));
    }

    #[test]
    fn allows_safe_commands() {
        assert!(!blocked("dotnet build"));
        assert!(!blocked("./mvnw clean package"));
        assert!(!blocked("go test ./..."));
        assert!(!blocked("gh pr create --title foo --body bar"));
    }
}
