use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

use super::{Block, Decision};

struct Rule {
    pattern: Regex,
    message: &'static str,
    decision: Decision,
    except: Option<Regex>,
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        // --- Filesystem destruction ---
        Rule {
            pattern: Regex::new(r"(?:^|[;&|]\s*)rm\s+-[a-zA-Z]*r[a-zA-Z]*").unwrap(),
            message: "recursive rm detected. Confirm only if targeting a scratch directory.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"(?:^|[;&|]\s*)rm\s.*(?:\s\*\s|\s/\s|/Users/|~/)").unwrap(),
            message: "rm targeting a broad glob or home/root path. Confirm or be more specific.",
            decision: Decision::Ask,
            except: None,
        },
        // --- Git destruction ---
        Rule {
            pattern: Regex::new(r"git\s+push\s.*--force(?:$|\s)").unwrap(),
            message: "git push --force. Prefer --force-with-lease; confirm if rewriting history is intended.",
            decision: Decision::Ask,
            except: Some(Regex::new(r"force-with-lease").unwrap()),
        },
        Rule {
            pattern: Regex::new(r"git\s+reset\s+--hard").unwrap(),
            message: "git reset --hard discards uncommitted work. Confirm only if nothing to preserve.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"git\s+clean\s+-[a-zA-Z]*f").unwrap(),
            message: "git clean -f permanently deletes untracked files. Confirm only if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"git\s+checkout\s+--\s+\.").unwrap(),
            message: "'git checkout -- .' discards all unstaged changes. Confirm only if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"git\s+branch\s+-D\s").unwrap(),
            message: "git branch -D force-deletes a branch. Confirm only if the branch is truly disposable.",
            decision: Decision::Ask,
            except: None,
        },
        // --- Push to protected branches ---
        Rule {
            pattern: Regex::new(r"git\s+push\s.*\b(main|master|stage|pre-release|release)\b").unwrap(),
            message: "pushing directly to a protected branch. Confirm only if bypassing PR review is intentional.",
            decision: Decision::Ask,
            except: None,
        },
        // --- Committing secrets (hard deny) ---
        Rule {
            pattern: Regex::new(r"git\s+add\s.*(\.(env|pem|key|p12|pfx|jks|keystore)|credentials|secrets?\.|\.secret|id_rsa|id_ed25519)").unwrap(),
            message: "BLOCKED: staging a file that likely contains secrets. Never commit credentials.",
            decision: Decision::Deny,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"git\s+add\s+(-A\b|\.\s*$|--all)").unwrap(),
            message: "BLOCKED: 'git add -A' / 'git add .' can accidentally stage secrets. Stage specific files by name.",
            decision: Decision::Deny,
            except: None,
        },
        // --- Self-modification (hard deny) ---
        Rule {
            pattern: Regex::new(r"(>|>>|tee\s).*\.claude/(settings\.json|hooks/)").unwrap(),
            message: "BLOCKED: shell redirect into Claude config/hooks. Use the Edit tool so the file-write-guard can review.",
            decision: Decision::Deny,
            except: None,
        },
        // --- Guard tampering (hard deny) ---
        Rule {
            pattern: Regex::new(r"guardctl\s+off").unwrap(),
            message: "BLOCKED: only the user can disable guardctl. Ask them to run 'guardctl off' manually.",
            decision: Decision::Deny,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"(>|>>|tee\s|rm\s).*\.guard-state\.json").unwrap(),
            message: "BLOCKED: direct manipulation of guard state file. Use 'guardctl on/off' (user only).",
            decision: Decision::Deny,
            except: None,
        },
        // --- Database destruction ---
        Rule {
            pattern: Regex::new(r"(?i)(DROP\s+(TABLE|DATABASE|SCHEMA)|TRUNCATE\s+TABLE)").unwrap(),
            message: "destructive SQL (DROP/TRUNCATE). Confirm only if targeting a disposable/test database.",
            decision: Decision::Ask,
            except: None,
        },
        // --- GitHub CLI ---
        Rule {
            pattern: Regex::new(r"gh\s+repo\s+delete").unwrap(),
            message: "gh repo delete destroys an entire repository. Confirm only if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"gh\s+api\s.*-X\s*DELETE").unwrap(),
            message: "raw DELETE via gh api. Prefer a specific gh subcommand; confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"gh\s+release\s+delete").unwrap(),
            message: "gh release delete removes a published release. Confirm only if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"gh\s+pr\s+close").unwrap(),
            message: "closing a PR should be a deliberate decision. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"gh\s+issue\s+close").unwrap(),
            message: "closing an issue should be a deliberate decision. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        // --- GCP (gcloud) ---
        Rule {
            pattern: Regex::new(r"gcloud\s+compute\s+instances\s+delete").unwrap(),
            message: "deleting GCP compute instances. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"gcloud\s+sql\s+instances\s+delete").unwrap(),
            message: "deleting Cloud SQL instances destroys databases. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"gcloud\s+run\s+services\s+delete").unwrap(),
            message: "deleting Cloud Run services takes down live traffic. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"gcloud\s+storage\s+(rm|delete)").unwrap(),
            message: "deleting GCP storage objects/buckets. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"gcloud\s+projects\s+delete").unwrap(),
            message: "deleting a GCP project destroys all resources within it. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"gcloud\s+iam\s+service-accounts\s+delete").unwrap(),
            message: "deleting service accounts can break running services. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"gcloud\s+.*--quiet\s.*delete|gcloud\s+.*delete\s.*--quiet").unwrap(),
            message: "gcloud delete with --quiet skips confirmation. Confirm interactively if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        // --- AWS CLI ---
        Rule {
            pattern: Regex::new(r"aws\s+ec2\s+terminate-instances").unwrap(),
            message: "terminating EC2 instances. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"aws\s+rds\s+delete-db-(instance|cluster)").unwrap(),
            message: "deleting RDS databases. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"aws\s+s3\s+(rb|rm)\s").unwrap(),
            message: "deleting S3 buckets/objects. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"aws\s+s3api\s+delete-bucket").unwrap(),
            message: "deleting S3 bucket. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"aws\s+iam\s+delete-(role|user|policy|group)").unwrap(),
            message: "deleting IAM resources. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"aws\s+lambda\s+delete-function").unwrap(),
            message: "deleting Lambda functions. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"aws\s+cloudformation\s+delete-stack").unwrap(),
            message: "deleting CloudFormation stacks tears down all stack resources. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"aws\s+ecs\s+delete-(service|cluster)").unwrap(),
            message: "deleting ECS services/clusters. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"aws\s+route53\s+delete-hosted-zone").unwrap(),
            message: "deleting Route53 hosted zone destroys DNS records. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        // --- Wrangler (Cloudflare Workers) ---
        Rule {
            pattern: Regex::new(r"wrangler\s+(delete|d1\s+delete|r2\s+bucket\s+delete|kv:namespace\s+delete|queues\s+delete|secret\s+delete)").unwrap(),
            message: "wrangler delete destroys Cloudflare resources. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        // --- Docker ---
        Rule {
            pattern: Regex::new(r"docker\s+system\s+prune").unwrap(),
            message: "docker system prune removes all unused data. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"docker\s+volume\s+(rm|prune)").unwrap(),
            message: "removing docker volumes destroys persistent data. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"docker\s+image\s+prune\s+-a").unwrap(),
            message: "docker image prune -a removes all unused images. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        // --- Terraform ---
        Rule {
            pattern: Regex::new(r"terraform\s+destroy").unwrap(),
            message: "terraform destroy tears down infrastructure. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        Rule {
            pattern: Regex::new(r"terraform\s+apply\s.*-auto-approve").unwrap(),
            message: "terraform apply -auto-approve skips plan review. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        // --- kubectl ---
        Rule {
            pattern: Regex::new(r"kubectl\s+delete\s+(namespace|ns|deployment|all|pvc|pv|svc|service)").unwrap(),
            message: "kubectl delete on broad resources. Confirm if intentional.",
            decision: Decision::Ask,
            except: None,
        },
        // --- Bypassing safety (hard deny) ---
        Rule {
            pattern: Regex::new(r"git\s+(commit|push|rebase)\s.*--no-verify").unwrap(),
            message: "BLOCKED: --no-verify skips hooks. Fix the underlying hook failure instead.",
            decision: Decision::Deny,
            except: None,
        },
    ]
});

pub fn check(input: &Value) -> Option<Block> {
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

    fn input(cmd: &str) -> Value {
        json!({"tool_input": {"command": cmd}})
    }

    fn blocked(cmd: &str) -> bool {
        check(&input(cmd)).is_some()
    }

    fn decision_for(cmd: &str) -> Option<Decision> {
        check(&input(cmd)).map(|b| b.decision)
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
    fn blocks_guardctl_off() {
        assert!(blocked("guardctl off"));
        assert!(blocked("guardctl off --only bash"));
    }

    #[test]
    fn allows_guardctl_read() {
        assert!(!blocked("guardctl status"));
        assert!(!blocked("guardctl list"));
        assert!(!blocked("guardctl check bash"));
    }

    #[test]
    fn blocks_guard_state_tampering() {
        assert!(blocked("rm .guard-state.json"));
        assert!(blocked("echo '{}' > .guard-state.json"));
    }

    // --- GitHub CLI ---

    #[test]
    fn blocks_gh_destructive() {
        assert!(blocked("gh repo delete lazorgurl/foo"));
        assert!(blocked("gh api -X DELETE /repos/lazorgurl/foo"));
        assert!(blocked("gh release delete v1.0.0"));
        assert!(blocked("gh pr close 42"));
        assert!(blocked("gh issue close 99"));
    }

    #[test]
    fn allows_gh_safe() {
        assert!(!blocked("gh pr create --title foo --body bar"));
        assert!(!blocked("gh pr view 42"));
        assert!(!blocked("gh pr list"));
        assert!(!blocked("gh api repos/lazorgurl/foo/pulls"));
        assert!(!blocked("gh issue create --title bug"));
        assert!(!blocked("gh issue list"));
        assert!(!blocked("gh run list"));
    }

    // --- GCP ---

    #[test]
    fn blocks_gcloud_destructive() {
        assert!(blocked("gcloud compute instances delete my-vm --zone us-central1-a"));
        assert!(blocked("gcloud sql instances delete my-db"));
        assert!(blocked("gcloud run services delete my-svc --region us-central1"));
        assert!(blocked("gcloud storage rm gs://my-bucket/file"));
        assert!(blocked("gcloud projects delete my-project"));
        assert!(blocked("gcloud iam service-accounts delete sa@proj.iam.gserviceaccount.com"));
        assert!(blocked("gcloud compute instances delete my-vm --quiet"));
    }

    #[test]
    fn allows_gcloud_safe() {
        assert!(!blocked("gcloud compute instances list"));
        assert!(!blocked("gcloud sql instances describe my-db"));
        assert!(!blocked("gcloud run services list"));
        assert!(!blocked("gcloud storage ls gs://my-bucket"));
        assert!(!blocked("gcloud auth print-access-token"));
        assert!(!blocked("gcloud config get-value project"));
    }

    // --- Docker ---

    #[test]
    fn blocks_docker_destructive() {
        assert!(blocked("docker system prune -a"));
        assert!(blocked("docker volume rm my-vol"));
        assert!(blocked("docker volume prune"));
        assert!(blocked("docker image prune -a"));
    }

    #[test]
    fn allows_docker_safe() {
        assert!(!blocked("docker ps"));
        assert!(!blocked("docker compose up -d"));
        assert!(!blocked("docker logs my-container"));
        assert!(!blocked("docker build -t myimage ."));
    }

    // --- Terraform ---

    #[test]
    fn blocks_terraform_destructive() {
        assert!(blocked("terraform destroy -auto-approve"));
        assert!(blocked("terraform apply -auto-approve"));
    }

    #[test]
    fn allows_terraform_safe() {
        assert!(!blocked("terraform plan"));
        assert!(!blocked("terraform apply")); // without -auto-approve is fine (interactive)
        assert!(!blocked("terraform init"));
        assert!(!blocked("terraform validate"));
    }

    // --- AWS CLI ---

    #[test]
    fn blocks_aws_destructive() {
        assert!(blocked("aws ec2 terminate-instances --instance-ids i-1234"));
        assert!(blocked("aws rds delete-db-instance --db-instance-identifier mydb"));
        assert!(blocked("aws rds delete-db-cluster --db-cluster-identifier mycluster"));
        assert!(blocked("aws s3 rb s3://my-bucket --force"));
        assert!(blocked("aws s3 rm s3://my-bucket --recursive"));
        assert!(blocked("aws s3api delete-bucket --bucket my-bucket"));
        assert!(blocked("aws iam delete-role --role-name my-role"));
        assert!(blocked("aws iam delete-user --user-name my-user"));
        assert!(blocked("aws lambda delete-function --function-name my-fn"));
        assert!(blocked("aws cloudformation delete-stack --stack-name my-stack"));
        assert!(blocked("aws ecs delete-service --service my-svc"));
        assert!(blocked("aws route53 delete-hosted-zone --id Z1234"));
    }

    #[test]
    fn allows_aws_safe() {
        assert!(!blocked("aws ec2 describe-instances"));
        assert!(!blocked("aws s3 ls"));
        assert!(!blocked("aws s3 cp file.txt s3://bucket/"));
        assert!(!blocked("aws rds describe-db-instances"));
        assert!(!blocked("aws iam list-roles"));
        assert!(!blocked("aws sts get-caller-identity"));
    }

    // --- Wrangler ---

    #[test]
    fn blocks_wrangler_destructive() {
        assert!(blocked("wrangler delete"));
        assert!(blocked("wrangler d1 delete my-db"));
        assert!(blocked("wrangler r2 bucket delete my-bucket"));
        assert!(blocked("wrangler kv:namespace delete --namespace-id abc"));
        assert!(blocked("wrangler queues delete my-queue"));
        assert!(blocked("wrangler secret delete MY_SECRET"));
    }

    #[test]
    fn allows_wrangler_safe() {
        assert!(!blocked("wrangler deploy"));
        assert!(!blocked("wrangler dev"));
        assert!(!blocked("wrangler d1 list"));
        assert!(!blocked("wrangler r2 bucket list"));
        assert!(!blocked("wrangler tail"));
    }

    // --- kubectl ---

    #[test]
    fn blocks_kubectl_destructive() {
        assert!(blocked("kubectl delete namespace prod"));
        assert!(blocked("kubectl delete deployment my-app"));
        assert!(blocked("kubectl delete all --all"));
        assert!(blocked("kubectl delete pvc data-volume"));
        assert!(blocked("kubectl delete service my-svc"));
    }

    #[test]
    fn allows_kubectl_safe() {
        assert!(!blocked("kubectl get pods"));
        assert!(!blocked("kubectl describe deployment my-app"));
        assert!(!blocked("kubectl logs my-pod"));
    }

    #[test]
    fn allows_safe_commands() {
        assert!(!blocked("dotnet build"));
        assert!(!blocked("./mvnw clean package"));
        assert!(!blocked("go test ./..."));
    }

    // --- Decision classification ---

    #[test]
    fn secret_staging_is_deny_not_ask() {
        assert_eq!(decision_for("git add .env"), Some(Decision::Deny));
        assert_eq!(decision_for("git add -A"), Some(Decision::Deny));
        assert_eq!(decision_for("git add id_rsa"), Some(Decision::Deny));
    }

    #[test]
    fn guard_tampering_is_deny() {
        assert_eq!(decision_for("guardctl off"), Some(Decision::Deny));
        assert_eq!(decision_for("rm .guard-state.json"), Some(Decision::Deny));
        assert_eq!(
            decision_for("echo '{}' > ~/.claude/settings.json"),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn no_verify_is_deny() {
        assert_eq!(decision_for("git commit --no-verify -m fix"), Some(Decision::Deny));
    }

    #[test]
    fn destructive_ops_are_ask() {
        assert_eq!(decision_for("rm -rf /tmp/stuff"), Some(Decision::Ask));
        assert_eq!(
            decision_for("git push --force origin main"),
            Some(Decision::Ask)
        );
        assert_eq!(decision_for("git reset --hard"), Some(Decision::Ask));
        assert_eq!(decision_for("terraform destroy"), Some(Decision::Ask));
        assert_eq!(
            decision_for("aws ec2 terminate-instances --instance-ids i-1234"),
            Some(Decision::Ask)
        );
        assert_eq!(decision_for("kubectl delete namespace prod"), Some(Decision::Ask));
    }
}
