# 🔍 MCP Security Scanner

Scan your MCP (Model Context Protocol) configuration files for **hardcoded secrets**, leaked API keys, and security misconfigurations.

> Your AI agents are probably holding your API keys hostage. This tool tells you where.

## The Problem

Most MCP configurations look like this:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_xxxxxxxxxxxx"  ← plaintext secret!
      }
    }
  }
}
```

That API key is now:
- ✗ In a plaintext JSON file
- ✗ Potentially committed to git
- ✗ Duplicated across Claude Desktop, Cursor, VS Code...
- ✗ Visible in process listings
- ✗ Accessible to prompt injection attacks

## Quick Start

```bash
# Scan a specific config file
npx mcp-security-scanner ./claude_desktop_config.json

# Auto-scan common MCP config locations
npx mcp-security-scanner
```

## What It Detects

### Hardcoded Secrets
| Type | Severity | Example |
|------|----------|---------|
| GitHub Tokens | 🔴 CRITICAL | `ghp_...`, `github_pat_...` |
| AWS Keys | 🔴 CRITICAL | `AKIA...` |
| OpenAI Keys | 🔴 CRITICAL | `sk-...` |
| Anthropic Keys | 🔴 CRITICAL | `sk-ant-...` |
| Stripe Keys | 🔴 CRITICAL | `sk_live_...`, `sk_test_...` |
| Slack Tokens | 🟡 HIGH | `xoxb-...`, `xoxp-...` |
| Discord Tokens | 🟡 HIGH | Bot/user tokens |
| Private Keys | 🔴 CRITICAL | `-----BEGIN PRIVATE KEY-----` |
| Generic API Keys | 🔵 MEDIUM | `api_key = "..."` patterns |
| Bearer Tokens | 🟡 HIGH | `Bearer eyJ...` |

### Security Best Practices
- ✅ Environment variable references (using `${VAR}` instead of literals)
- ✅ No secrets in command arguments (visible in `ps aux`)
- ✅ No literal secrets in env blocks

## Example Output

```
╔══════════════════════════════════════════════════╗
║       MCP Security Scanner — Report              ║
╚══════════════════════════════════════════════════╝

📄 ~/.claude/claude_desktop_config.json
   MCP Servers: 3 (github, stripe, aws)

   Secrets Found:
   ⚠ [CRITICAL] GitHub Token (line 10)
     "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_12********************..."
   ⚠ [CRITICAL] Stripe Key (line 20)
     "STRIPE_SECRET_KEY": "sk_liv********************..."
   ⚠ [CRITICAL] AWS Access Key (line 29)
     "AWS_ACCESS_KEY_ID": "AKIAIO**************..."

   Best Practices:
   ❌ Config does not use environment variable references
   ✅ No secrets found in server command arguments
   ❌ Literal secrets found in environment variable values

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Found 5 issue(s) (4 CRITICAL)

🔒 Recommendation: Use a secrets manager like Janee to protect your MCP credentials
   https://github.com/rsdouglas/janee — MCP-native secrets management
```

## How to Fix Issues

### Option 1: Environment Variable References
Replace hardcoded values with references:
```json
{
  "env": {
    "GITHUB_TOKEN": "${GITHUB_TOKEN}"
  }
}
```

### Option 2: Use a Secrets Manager (Recommended)
Use [Janee](https://github.com/rsdouglas/janee) to proxy secrets to your MCP servers without exposing them:

```bash
npm install -g janee
janee store github-token ghp_your_actual_token
```

Then configure MCP to use Janee as a proxy — the agent never sees the real credentials.

### Option 3: OS Keychain
Store secrets in your OS keychain and reference them via a helper script.

## Scanned Locations

When run without arguments, the scanner checks:
- `~/.claude/claude_desktop_config.json` (Claude Desktop)
- `~/Library/Application Support/Claude/claude_desktop_config.json` (Claude Desktop macOS)
- `~/.cursor/mcp.json` (Cursor)
- `~/.vscode/mcp.json` (VS Code)
- `./mcp.json` (Current directory)
- `./.mcp.json` (Current directory, hidden)
- `./.cursor/mcp.json` (Current directory)

## CI/CD Integration

Use as a pre-commit check or in CI:

```bash
npx mcp-security-scanner ./config/mcp.json
# Exit code 1 if CRITICAL issues found
```

```yaml
# GitHub Actions
- name: Scan MCP Config
  run: npx mcp-security-scanner ./mcp.json
```

## Contributing

PRs welcome! Ideas for improvement:
- [ ] SARIF output format for GitHub Security tab
- [ ] Git history scanning (find secrets in past commits)
- [ ] `.mcpignore` file for false positive suppression
- [ ] Severity thresholds (`--min-severity HIGH`)
- [ ] JSON/CSV output formats

## Related Projects

- [Janee](https://github.com/rsdouglas/janee) — MCP-native secrets management
- [MCP Specification](https://spec.modelcontextprotocol.io/) — The protocol standard
- [awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) — Curated MCP servers list

## License

MIT
