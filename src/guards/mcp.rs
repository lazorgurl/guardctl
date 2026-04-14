use serde_json::Value;

use super::{Block, Decision};

struct Rule {
    tool_name: &'static str,
    message: &'static str,
    decision: Decision,
}

const RULES: &[Rule] = &[
    // --- Cloudflare (ask — owned resources, legit cleanup sometimes) ---
    Rule {
        tool_name: "mcp__claude_ai_Cloudflare_Developer_Platform__d1_database_delete",
        message: "deleting a Cloudflare D1 database. Confirm if intentional.",
        decision: Decision::Ask,
    },
    Rule {
        tool_name: "mcp__claude_ai_Cloudflare_Developer_Platform__kv_namespace_delete",
        message: "deleting a Cloudflare KV namespace. Confirm if intentional.",
        decision: Decision::Ask,
    },
    Rule {
        tool_name: "mcp__claude_ai_Cloudflare_Developer_Platform__r2_bucket_delete",
        message: "deleting a Cloudflare R2 bucket. Confirm if intentional.",
        decision: Decision::Ask,
    },
    Rule {
        tool_name: "mcp__claude_ai_Cloudflare_Developer_Platform__hyperdrive_config_delete",
        message: "deleting a Cloudflare Hyperdrive config. Confirm if intentional.",
        decision: Decision::Ask,
    },
    // --- Supabase (ask — owned resources) ---
    Rule {
        tool_name: "mcp__claude_ai_Supabase__delete_branch",
        message: "deleting a Supabase branch. Confirm if intentional.",
        decision: Decision::Ask,
    },
    Rule {
        tool_name: "mcp__claude_ai_Supabase__pause_project",
        message: "pausing a Supabase project takes it offline. Confirm if intentional.",
        decision: Decision::Ask,
    },
    // --- Sentry (deny — silent mutations of shared monitoring are never wanted) ---
    Rule {
        tool_name: "mcp__sentry__update_issue",
        message: "BLOCKED: mutating Sentry issues from an agent. Ask the user to do this manually.",
        decision: Decision::Deny,
    },
    Rule {
        tool_name: "mcp__sentry__update_project",
        message: "BLOCKED: mutating Sentry project settings from an agent. Ask the user to do this manually.",
        decision: Decision::Deny,
    },
    // --- Linear (deny — destroying shared content) ---
    Rule {
        tool_name: "mcp__claude_ai_Linear__delete_comment",
        message: "BLOCKED: deleting a Linear comment destroys shared content. Ask the user to do this manually.",
        decision: Decision::Deny,
    },
    Rule {
        tool_name: "mcp__claude_ai_Linear__delete_attachment",
        message: "BLOCKED: deleting a Linear attachment destroys shared content. Ask the user to do this manually.",
        decision: Decision::Deny,
    },
    // --- Atlassian (JIRA) (deny — noisy, rarely intended from agent) ---
    // Note: editing/transitioning JIRA issues is intentionally ALLOWED for the
    // autonomous bug-fix loop. Only truly destructive or confusing actions are blocked.
    Rule {
        tool_name: "mcp__claude_ai_Atlassian_Rovo__createJiraIssue",
        message: "BLOCKED: creating JIRA issues autonomously is too noisy. Ask the user to do this manually.",
        decision: Decision::Deny,
    },
    // --- Terraform (MCP) (ask) ---
    Rule {
        tool_name: "mcp__plugin_terraform_terraform__create_run",
        message: "creating a Terraform run can apply infrastructure changes. Confirm if intentional.",
        decision: Decision::Ask,
    },
];

pub fn check(input: &Value) -> Option<Block> {
    let tool_name = input
        .pointer("/tool_name")
        .and_then(|v| v.as_str())?;

    for rule in RULES {
        if tool_name == rule.tool_name {
            return Some(Block {
                decision: rule.decision,
                reason: rule.message.to_string(),
            });
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

    fn decision_for(tool: &str) -> Option<Decision> {
        check(&input(tool)).map(|b| b.decision)
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

    // --- Decision classification ---

    #[test]
    fn sentry_linear_jira_create_are_deny() {
        assert_eq!(decision_for("mcp__sentry__update_issue"), Some(Decision::Deny));
        assert_eq!(
            decision_for("mcp__claude_ai_Linear__delete_comment"),
            Some(Decision::Deny)
        );
        assert_eq!(
            decision_for("mcp__claude_ai_Atlassian_Rovo__createJiraIssue"),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn cloudflare_supabase_terraform_are_ask() {
        assert_eq!(
            decision_for("mcp__claude_ai_Cloudflare_Developer_Platform__d1_database_delete"),
            Some(Decision::Ask)
        );
        assert_eq!(
            decision_for("mcp__claude_ai_Supabase__pause_project"),
            Some(Decision::Ask)
        );
        assert_eq!(
            decision_for("mcp__plugin_terraform_terraform__create_run"),
            Some(Decision::Ask)
        );
    }
}
