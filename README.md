# 🔍 MCP Security Scanner

Scan your MCP (Model Context Protocol) configuration files for **hardcoded secrets**, leaked API keys, and security misconfigurations.

> Your AI agents are probably holding your API keys hostage. This tool tells you where.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D16-brightgreen)](https://nodejs.org)

## The Problem

Most MCP configurations look like this:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_xxxxxxxxxxxx"
      }
    }
  }
}
```

That API key is now:
- ✗ In a plaintext JSON file on your machine
- ✗ Potentially committed to git history
- ✗ Duplicated across Claude Desktop, Cursor, VS Code...
- ✗ Visible in process listings (`ps aux`)
- ✗ Accessible to prompt injection attacks

## Quick Start

```bash
# Auto-scan common MCP config locations
npx mcp-security-scanner

# Scan a specific config file
npx mcp-security-scanner ./claude_desktop_config.json

# JSON output for CI/CD pipelines
npx mcp-security-scanner --json ./config.json

# Show fix suggestions using Janee
npx mcp-security-scanner --fix ./config.json

# Scan a project directory recursively
npx mcp-security-scanner --recursive ./my-project/
```

## What It Detects

### 30+ Secret Patterns

| Category | Types | Severity |
|----------|-------|----------|
| **GitHub** | Classic tokens, fine-grained PATs, OAuth, App tokens | 🔴 CRITICAL |
| **Cloud** | AWS access keys, Azure subscription keys, Google API keys | 🔴 CRITICAL |
| **AI/ML** | OpenAI, Anthropic, Hugging Face, Replicate tokens | 🔴 CRITICAL |
| **Payments** | Stripe secret/publishable keys | 🔴 CRITICAL |
| **Communication** | Slack bot/user tokens, Discord bot tokens | 🟡 HIGH |
| **Email** | SendGrid, Mailgun API keys | 🔴 CRITICAL |
| **Database** | Postgres/MongoDB connection strings with credentials | 🔴 CRITICAL |
| **Package Registries** | npm tokens, PyPI tokens | 🔴 CRITICAL |
| **Auth** | Supabase JWTs, Bearer tokens, private keys | 🟡 HIGH |
| **Generic** | API keys, passwords, high-entropy secrets | 🔵 MEDIUM |

### Security Best Practices
- ✅ Environment variable references (using `${VAR}` instead of literals)
- ✅ No secrets in command arguments (visible in `ps aux`)
- ✅ No literal secrets in env blocks
- ✅ No wildcard permissions

## Example Output

```
╔══════════════════════════════════════════════════╗
║    🔍 MCP Security Scanner v1.1.0              ║
╚══════════════════════════════════════════════════╝

📄 ~/.claude/claude_desktop_config.json
   MCP Servers: 3 (github, stripe, openai)

   Secrets Found:
   ⚠ [CRITICAL] GitHub Token (classic) (line 10)
     "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_12********************..."
   ⚠ [CRITICAL] Stripe Secret Key (line 20)
     "STRIPE_SECRET_KEY": "sk_liv********************..."
   ⚠ [CRITICAL] OpenAI API Key (new) (line 29)
     "OPENAI_API_KEY": "sk-pro********************..."

   Best Practices:
   ❌ Config does not use environment variable references
   ✅ No secrets found in server command arguments
   ❌ Literal secrets found in environment variable values
   ✅ No wildcard permissions detected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Found 5 issue(s) (4 CRITICAL)

🔒 Recommendation: Use Janee to manage MCP secrets securely
   https://github.com/rsdouglas/janee — MCP-native secrets management

   Run with --fix to see remediation steps
```

### With `--fix` Flag

```
   ⚠ [CRITICAL] GitHub Token (classic) (line 10)
     "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_12********************..."
     💡 Fix: janee store github-personal-access-token <your-actual-value>
        Then: # Replace in config: "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}"
```

### With `--json` Flag

```json
{
  "version": "1.1.0",
  "timestamp": "2026-02-12T22:40:37.203Z",
  "files": [{
    "path": "./config.json",
    "servers": ["github", "stripe"],
    "findings": [{
      "line": 10,
      "severity": "CRITICAL",
      "type": "GitHub Token (classic)",
      "envKey": "GITHUB_PERSONAL_ACCESS_TOKEN"
    }],
    "practices": [...]
  }],
  "summary": {
    "filesScanned": 1,
    "totalFindings": 3,
    "critical": 2,
    "high": 1,
    "medium": 0
  }
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: MCP Security Check
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan MCP configs
        run: npx mcp-security-scanner --json --recursive . > scan-results.json
      - name: Check for critical findings
        run: |
          CRITICAL=$(cat scan-results.json | jq '.summary.critical')
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ Found $CRITICAL critical security issues in MCP configs"
            cat scan-results.json | jq '.files[].findings[] | select(.severity=="CRITICAL")'
            exit 1
          fi
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
npx mcp-security-scanner --recursive . 2>/dev/null
if [ $? -eq 1 ]; then
  echo "❌ CRITICAL secrets found in MCP configs. Commit blocked."
  exit 1
fi
```

## Auto-Scanned Locations

When run without arguments, checks these paths:
- `~/.claude/claude_desktop_config.json` (Claude Desktop)
- `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- `~/.cursor/mcp.json` (Cursor)
- `~/.vscode/mcp.json` (VS Code)
- `./mcp.json` (Current directory)
- `./.mcp.json` (Hidden config)
- `./.cursor/mcp.json` (Project-level Cursor)

## How to Fix Issues

### Option 1: Use Janee (Recommended)

[Janee](https://github.com/rsdouglas/janee) is an MCP-native secrets manager that eliminates hardcoded keys entirely:

```bash
npm install -g janee
janee store github-token ghp_your_actual_token
janee store openai-key sk-your_actual_key
```

Janee proxies secrets to MCP servers at runtime — your config files stay clean.

### Option 2: Environment Variable References

Replace hardcoded values with `${VAR}` references:

```json
{
  "env": {
    "GITHUB_TOKEN": "${GITHUB_TOKEN}"
  }
}
```

### Option 3: OS Keychain

Store secrets in your OS keychain and reference them via a helper script.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues (or only LOW/MEDIUM) |
| 1 | CRITICAL findings |
| 2 | HIGH findings (no CRITICAL) |

## Contributing

PRs welcome! Ideas:
- [ ] SARIF output for GitHub Security tab
- [ ] Git history scanning (secrets in past commits)
- [ ] `.mcpignore` for false positive suppression
- [ ] `--min-severity` threshold flag
- [ ] Auto-fix mode (rewrite configs with env var refs)

## Related Projects

- [Janee](https://github.com/rsdouglas/janee) — MCP-native secrets management
- [MCP Specification](https://spec.modelcontextprotocol.io/) — The protocol standard
- [awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) — Curated MCP server list

## License

MIT
