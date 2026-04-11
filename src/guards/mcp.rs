use serde_json::Value;

struct Rule {
    tool_name: &'static str,
    message: &'static str,
}

const RULES: &[Rule] = &[
    // --- Cloudflare ---
    Rule {
        tool_name: "mcp__claude_ai_Cloudflare_Developer_Platform__d1_database_delete",
        message: "BLOCKED: deleting a Cloudflare D1 database. This needs manual confirmation.",
    },
    Rule {
        tool_name: "mcp__claude_ai_Cloudflare_Developer_Platform__kv_namespace_delete",
        message: "BLOCKED: deleting a Cloudflare KV namespace. This needs manual confirmation.",
    },
    Rule {
        tool_name: "mcp__claude_ai_Cloudflare_Developer_Platform__r2_bucket_delete",
        message: "BLOCKED: deleting a Cloudflare R2 bucket. This needs manual confirmation.",
    },
    Rule {
        tool_name: "mcp__claude_ai_Cloudflare_Developer_Platform__hyperdrive_config_delete",
        message: "BLOCKED: deleting a Cloudflare Hyperdrive config. This needs manual confirmation.",
    },
    // --- Supabase ---
    Rule {
        tool_name: "mcp__claude_ai_Supabase__delete_branch",
        message: "BLOCKED: deleting a Supabase branch. This needs manual confirmation.",
    },
    Rule {
        tool_name: "mcp__claude_ai_Supabase__pause_project",
        message: "BLOCKED: pausing a Supabase project takes it offline. This needs manual confirmation.",
    },
    // --- Sentry ---
    Rule {
        tool_name: "mcp__sentry__update_issue",
        message: "BLOCKED: mutating Sentry issues. This needs manual confirmation.",
    },
    Rule {
        tool_name: "mcp__sentry__update_project",
        message: "BLOCKED: mutating Sentry project settings. This needs manual confirmation.",
    },
    // --- Linear ---
    Rule {
        tool_name: "mcp__claude_ai_Linear__delete_comment",
        message: "BLOCKED: deleting a Linear comment. This needs manual confirmation.",
    },
    Rule {
        tool_name: "mcp__claude_ai_Linear__delete_attachment",
        message: "BLOCKED: deleting a Linear attachment. This needs manual confirmation.",
    },
    // --- Atlassian (JIRA) ---
    // Note: editing/transitioning JIRA issues is intentionally ALLOWED for the
    // autonomous bug-fix loop. Only truly destructive or confusing actions are blocked.
    Rule {
        tool_name: "mcp__claude_ai_Atlassian_Rovo__createJiraIssue",
        message: "BLOCKED: creating JIRA issues autonomously can be noisy. This needs manual confirmation.",
    },
    // --- Terraform (MCP) ---
    Rule {
        tool_name: "mcp__plugin_terraform_terraform__create_run",
        message: "BLOCKED: creating a Terraform run can apply infrastructure changes. This needs manual confirmation.",
    },
];

pub fn check(input: &Value) -> Option<String> {
    let tool_name = input
        .pointer("/tool_name")
        .and_then(|v| v.as_str())?;

    for rule in RULES {
        if tool_name == rule.tool_name {
            return Some(rule.message.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(tool: &str) -> Value {
        json!({"tool_name": tool})
    }

    fn blocked(tool: &str) -> bool {
        check(&input(tool)).is_some()
    }

    #[test]
    fn blocks_cloudflare_deletes() {
        assert!(blocked("mcp__claude_ai_Cloudflare_Developer_Platform__d1_database_delete"));
        assert!(blocked("mcp__claude_ai_Cloudflare_Developer_Platform__kv_namespace_delete"));
        assert!(blocked("mcp__claude_ai_Cloudflare_Developer_Platform__r2_bucket_delete"));
    }

    #[test]
    fn allows_cloudflare_reads() {
        assert!(!blocked("mcp__claude_ai_Cloudflare_Developer_Platform__d1_databases_list"));
        assert!(!blocked("mcp__claude_ai_Cloudflare_Developer_Platform__kv_namespaces_list"));
        assert!(!blocked("mcp__claude_ai_Cloudflare_Developer_Platform__workers_list"));
    }

    #[test]
    fn blocks_sentry_mutations() {
        assert!(blocked("mcp__sentry__update_issue"));
        assert!(blocked("mcp__sentry__update_project"));
    }

    #[test]
    fn allows_sentry_reads() {
        assert!(!blocked("mcp__sentry__list_issues"));
        assert!(!blocked("mcp__sentry__find_organizations"));
    }

    #[test]
    fn blocks_jira_create() {
        assert!(blocked("mcp__claude_ai_Atlassian_Rovo__createJiraIssue"));
    }

    #[test]
    fn allows_jira_read_and_transition() {
        assert!(!blocked("mcp__claude_ai_Atlassian_Rovo__getJiraIssue"));
        assert!(!blocked("mcp__claude_ai_Atlassian_Rovo__searchJiraIssuesUsingJql"));
        assert!(!blocked("mcp__claude_ai_Atlassian_Rovo__transitionJiraIssue"));
        assert!(!blocked("mcp__claude_ai_Atlassian_Rovo__editJiraIssue"));
        assert!(!blocked("mcp__claude_ai_Atlassian_Rovo__addCommentToJiraIssue"));
    }

    #[test]
    fn blocks_terraform_run() {
        assert!(blocked("mcp__plugin_terraform_terraform__create_run"));
    }

    #[test]
    fn blocks_linear_deletes() {
        assert!(blocked("mcp__claude_ai_Linear__delete_comment"));
        assert!(blocked("mcp__claude_ai_Linear__delete_attachment"));
    }

    #[test]
    fn allows_linear_reads() {
        assert!(!blocked("mcp__claude_ai_Linear__get_issue"));
        assert!(!blocked("mcp__claude_ai_Linear__list_issues"));
    }
}
