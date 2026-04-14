# guardctl

Blast-radius guard for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Prevents autonomous agents from running destructive commands, writing to sensitive files, or calling dangerous MCP tools — without slowing down normal work.

guardctl runs as a Claude Code [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks). It reads the tool invocation from stdin, checks it against a set of rules, and either allows it (exit 0, no output) or denies it (prints a JSON deny decision). Claude sees the denial reason and adjusts its approach.

## Guards

| Guard | What it blocks |
|---|---|
| **bash** | `rm -rf`, `git push --force`, `git reset --hard`, `git add .`, staging secrets, destructive SQL, `terraform destroy`, cloud resource deletion (AWS, GCP, Cloudflare), `docker system prune`, and more |
| **file-write** | Writes to generated code, secrets/credentials, lock files, Terraform state, Claude config, and the guard state file itself |
| **mcp** | Destructive MCP tool calls: Cloudflare deletes, Sentry mutations, Linear deletes, JIRA issue creation, Terraform runs |

All guards default to **ON**. guardctl also blocks Claude from disabling its own guards — only the user can run `guardctl off`.

## Install

### Download a release binary

Grab the latest binary for your platform from [Releases](https://github.com/lazorgurl/guardctl/releases):

| Platform | Binary |
|---|---|
| macOS (Apple Silicon) | `guardctl-macos-arm64` |
| Linux (x64) | `guardctl-linux-x64` |
| Windows (x64) | `guardctl-windows-x64.exe` |

```sh
# Example: macOS arm64
curl -L https://github.com/lazorgurl/guardctl/releases/latest/download/guardctl-macos-arm64 -o /usr/local/bin/guardctl
chmod +x /usr/local/bin/guardctl
```

### Build from source

Requires [Rust](https://rustup.rs/).

```sh
git clone https://github.com/lazorgurl/guardctl.git ~/.claude/tools/guardctl
cd ~/.claude/tools/guardctl
cargo build --release
```

The binary is at `target/release/guardctl`. Add it to your PATH or reference it by full path in your hooks.

### Hook setup

```sh
guardctl init
```

This merges the required PreToolUse hooks into `~/.claude/settings.json`. It's idempotent — safe to run again.

<details>
<summary>Manual setup (if you prefer)</summary>

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "guardctl check bash" }
        ]
      },
      {
        "matcher": "Write|Edit",
        "hooks": [
          { "type": "command", "command": "guardctl check file-write" }
        ]
      },
      {
        "matcher": "mcp__.*",
        "hooks": [
          { "type": "command", "command": "guardctl check mcp" }
        ]
      }
    ]
  }
}
```

Note: Claude Code's PreToolUse schema uses an inner `hooks` array with `type: "command"`. A flat `{ "matcher": ..., "command": ... }` entry is silently ignored. `guardctl init` handles this for you; if you previously ran an older `guardctl init` that wrote the flat shape, re-run it to migrate automatically.
</details>

## Usage

Commands default to the current working directory. Use `--global` for global config.

```sh
# Per-directory (default — scoped to $PWD)
guardctl on                         # Enable all guards for current directory
guardctl off                        # Disable all guards for current directory
guardctl on --only bash             # Enable one guard for current directory
guardctl off --only mcp             # Disable one guard for current directory
guardctl status                     # Show resolved status for current directory

# Target a different directory
guardctl on --dir /path/to/project
guardctl off --only bash --dir /path/to/project

# Global
guardctl on --global                # Enable all guards globally
guardctl off --only mcp --global    # Disable one guard globally
guardctl status --global            # Show global status + all directory overrides

# Testing & debugging
guardctl test --bash "rm -rf /"     # Dry-run a command against the bash guard
guardctl test --file-write ".env"   # Dry-run a path against the file-write guard
guardctl test --mcp "mcp__sentry__update_issue"  # Dry-run an MCP tool name
guardctl log                        # Show recent blocks
guardctl log -n 5                   # Show last 5 blocks
guardctl log --json                 # Raw JSONL output

# Other
guardctl init                       # Install hooks into settings.json
guardctl list                       # List available guards
guardctl clear-dir /path/to/project # Remove all directory overrides
```

## Per-directory configuration

Different projects can have different guard settings. When a hook fires, guardctl resolves the working directory and uses **longest-prefix matching** to find the most specific config. Directory-specific settings override global; guards not set for a directory fall through to the global default.

Example state after configuration:

```json
{
  "guards": { "bash": true, "file-write": true, "mcp": true },
  "directories": {
    "/Users/you/code/personal": { "bash": false, "mcp": false },
    "/Users/you/code/project": { "file-write": false }
  }
}
```

With this config:
- In `/Users/you/code/personal`, bash and mcp are off, file-write is on (global default)
- In `/Users/you/code/project`, file-write is off, bash and mcp are on (global default)
- Everywhere else, all guards are on

The working directory is resolved from (in order): the hook input's `cwd` field, `$PWD`, or the process working directory.

State is stored at `~/.claude/hooks/.guard-state.json` (override with `$GUARDCTL_STATE`).

## What gets blocked

### bash guard

**Filesystem:** recursive rm, broad globs targeting home/root

**Git:** force push (allows `--force-with-lease`), `reset --hard`, `clean -f`, `checkout -- .`, `branch -D`, push to protected branches (main/master/stage/release), `git add .`/`-A`, staging secrets (.env, .pem, .key, id_rsa), `--no-verify`

**Cloud:** AWS (terminate instances, delete RDS/S3/IAM/Lambda/ECS/CloudFormation/Route53), GCP (delete compute/SQL/Cloud Run/storage/projects/service accounts, `--quiet` deletes), Cloudflare/Wrangler (delete workers/D1/R2/KV/queues/secrets)

**Other:** destructive SQL (DROP/TRUNCATE), GitHub CLI (repo/release delete, pr/issue close, raw DELETE), Docker (system prune, volume rm, image prune -a), Terraform (destroy, apply -auto-approve), kubectl (delete namespace/deployment/all/pvc/service), shell redirects into Claude config

### file-write guard

Generated files (`.gen.go`, `/Generated/*.cs`), secrets/credentials, lock files, Terraform state, Claude config (`settings.json`, `hooks/`), guard state file

### mcp guard

Cloudflare (D1/KV/R2/Hyperdrive delete), Supabase (delete/pause), Sentry (update issue/project), Linear (delete comment/attachment), Atlassian (create JIRA issue), Terraform (create run)

## Self-protection

guardctl prevents Claude from disabling its own guards:
- The bash guard blocks `guardctl off` and direct manipulation of `.guard-state.json`
- The file-write guard blocks writes to `.guard-state.json` and Claude config files

Only the user can run `guardctl off` from their terminal.

## Known limitations

guardctl is a **guardrail, not a sandbox**. It's designed to catch the dangerous commands an agent is likely to generate, not to defeat a determined attacker. A few things it intentionally does not try to do:

- **Shell evaluation**: rules match against the literal command string after whitespace normalization. Command substitution, unusual quoting, or brace expansion can bypass specific patterns — e.g. `git add $(printf .env)` is not caught by the staging-secrets rule. For project-specific tripwires, add targeted patterns rather than relying solely on the built-ins.
- **Semantic equivalence**: `rm -rf /tmp/x` is blocked, but functionally equivalent constructions using `find … -delete` may not be.
- **MCP tool coverage**: the MCP guard matches exact tool names. New or renamed dangerous MCP tools need a guardctl update.

When it matters, combine `guardctl` with Claude Code's permission prompts and with project-level code review rather than treating it as the last line of defense.

## Development

```sh
cargo test          # Run all tests
cargo build         # Debug build
cargo build --release  # Release build (stripped + LTO)
```

## License

MIT
