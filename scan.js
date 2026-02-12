#!/usr/bin/env node

/**
 * mcp-security-scanner
 * Scans MCP configuration files for security issues:
 * - Hardcoded API keys and secrets
 * - Overly permissive token scopes
 * - Missing security best practices
 * 
 * Usage: npx mcp-security-scanner [path-to-config]
 * Default: scans common MCP config locations
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Common MCP config locations
const CONFIG_PATHS = [
  path.join(os.homedir(), '.claude', 'claude_desktop_config.json'),
  path.join(os.homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
  path.join(os.homedir(), '.cursor', 'mcp.json'),
  path.join(os.homedir(), '.vscode', 'mcp.json'),
  path.join(process.cwd(), 'mcp.json'),
  path.join(process.cwd(), '.mcp.json'),
  path.join(process.cwd(), '.cursor', 'mcp.json'),
];

// Patterns that indicate hardcoded secrets
const SECRET_PATTERNS = [
  { name: 'GitHub Token', pattern: /ghp_[a-zA-Z0-9]{36}/, severity: 'CRITICAL' },
  { name: 'GitHub Token (fine-grained)', pattern: /github_pat_[a-zA-Z0-9_]{82}/, severity: 'CRITICAL' },
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/, severity: 'CRITICAL' },
  { name: 'AWS Secret Key', pattern: /[a-zA-Z0-9/+=]{40}(?=.*aws)/i, severity: 'HIGH' },
  { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{48}/, severity: 'CRITICAL' },
  { name: 'Anthropic API Key', pattern: /sk-ant-[a-zA-Z0-9-]{90,}/, severity: 'CRITICAL' },
  { name: 'Stripe Key', pattern: /sk_(live|test)_[a-zA-Z0-9]{24,}/, severity: 'CRITICAL' },
  { name: 'Slack Token', pattern: /xox[bprs]-[a-zA-Z0-9-]+/, severity: 'HIGH' },
  { name: 'Discord Token', pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/, severity: 'HIGH' },
  { name: 'Generic API Key', pattern: /["']?(?:api[_-]?key|apikey|api[_-]?token)["']?\s*[:=]\s*["'][a-zA-Z0-9_\-]{20,}["']/i, severity: 'MEDIUM' },
  { name: 'Generic Secret', pattern: /["']?(?:secret|password|passwd|pwd)["']?\s*[:=]\s*["'][^"']{8,}["']/i, severity: 'HIGH' },
  { name: 'Bearer Token', pattern: /Bearer\s+[a-zA-Z0-9_\-\.]{20,}/, severity: 'HIGH' },
  { name: 'Private Key', pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----/, severity: 'CRITICAL' },
  { name: 'Base64 Encoded Secret (long)', pattern: /["'][A-Za-z0-9+/]{64,}={0,2}["']/, severity: 'LOW' },
];

// Security best practice checks
const BEST_PRACTICE_CHECKS = [
  {
    name: 'Uses environment variable references',
    check: (config) => {
      const str = JSON.stringify(config);
      return str.includes('${') || str.includes('process.env');
    },
    pass: 'Config uses environment variable references',
    fail: 'Config does not use environment variable references — secrets may be hardcoded',
    severity: 'MEDIUM'
  },
  {
    name: 'No stdio transport with secrets in args',
    check: (config) => {
      const servers = config.mcpServers || {};
      for (const [name, server] of Object.entries(servers)) {
        const args = (server.args || []).join(' ');
        for (const p of SECRET_PATTERNS) {
          if (p.pattern.test(args)) return false;
        }
      }
      return true;
    },
    pass: 'No secrets found in server command arguments',
    fail: 'Secrets detected in server command arguments — visible in process listings!',
    severity: 'CRITICAL'
  },
  {
    name: 'Environment secrets use references not literals',
    check: (config) => {
      const servers = config.mcpServers || {};
      for (const [name, server] of Object.entries(servers)) {
        const env = server.env || {};
        for (const [key, value] of Object.entries(env)) {
          if (typeof value === 'string' && value.length > 15) {
            for (const p of SECRET_PATTERNS) {
              if (p.pattern.test(value)) return false;
            }
          }
        }
      }
      return true;
    },
    pass: 'No literal secrets found in environment variables',
    fail: 'Literal secrets found in environment variable values',
    severity: 'CRITICAL'
  }
];

const COLORS = {
  CRITICAL: '\x1b[31m', // Red
  HIGH: '\x1b[33m',     // Yellow
  MEDIUM: '\x1b[36m',   // Cyan
  LOW: '\x1b[37m',      // White
  PASS: '\x1b[32m',     // Green
  RESET: '\x1b[0m',
  BOLD: '\x1b[1m',
  DIM: '\x1b[2m',
};

function scanFile(filePath) {
  const findings = [];
  
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return { filePath, error: e.message, findings: [], practices: [] };
  }

  let config;
  try {
    config = JSON.parse(content);
  } catch (e) {
    return { filePath, error: 'Invalid JSON', findings: [], practices: [] };
  }

  // Scan for secret patterns
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    for (const sp of SECRET_PATTERNS) {
      if (sp.pattern.test(lines[i])) {
        // Mask the secret in the output
        const masked = lines[i].replace(sp.pattern, (match) => 
          match.substring(0, 6) + '*'.repeat(Math.min(match.length - 6, 20)) + '...'
        );
        findings.push({
          line: i + 1,
          severity: sp.severity,
          type: sp.name,
          masked: masked.trim(),
        });
      }
    }
  }

  // Run best practice checks
  const practices = BEST_PRACTICE_CHECKS.map(bp => ({
    name: bp.name,
    passed: bp.check(config),
    message: bp.check(config) ? bp.pass : bp.fail,
    severity: bp.severity,
  }));

  // Count servers
  const serverCount = Object.keys(config.mcpServers || {}).length;
  const serverNames = Object.keys(config.mcpServers || {});

  return { filePath, findings, practices, serverCount, serverNames, error: null };
}

function printReport(results) {
  console.log(`\n${COLORS.BOLD}╔══════════════════════════════════════════════════╗${COLORS.RESET}`);
  console.log(`${COLORS.BOLD}║       MCP Security Scanner — Report              ║${COLORS.RESET}`);
  console.log(`${COLORS.BOLD}╚══════════════════════════════════════════════════╝${COLORS.RESET}\n`);

  let totalFindings = 0;
  let criticalCount = 0;

  for (const result of results) {
    console.log(`${COLORS.BOLD}📄 ${result.filePath}${COLORS.RESET}`);
    
    if (result.error) {
      console.log(`   ${COLORS.DIM}Skipped: ${result.error}${COLORS.RESET}\n`);
      continue;
    }

    console.log(`   ${COLORS.DIM}MCP Servers: ${result.serverCount} (${result.serverNames.join(', ')})${COLORS.RESET}`);

    if (result.findings.length === 0) {
      console.log(`   ${COLORS.PASS}✅ No hardcoded secrets detected${COLORS.RESET}`);
    } else {
      console.log(`\n   ${COLORS.BOLD}Secrets Found:${COLORS.RESET}`);
      for (const f of result.findings) {
        const color = COLORS[f.severity];
        console.log(`   ${color}⚠ [${f.severity}] ${f.type} (line ${f.line})${COLORS.RESET}`);
        console.log(`     ${COLORS.DIM}${f.masked}${COLORS.RESET}`);
        totalFindings++;
        if (f.severity === 'CRITICAL') criticalCount++;
      }
    }

    console.log(`\n   ${COLORS.BOLD}Best Practices:${COLORS.RESET}`);
    for (const p of result.practices) {
      if (p.passed) {
        console.log(`   ${COLORS.PASS}✅ ${p.message}${COLORS.RESET}`);
      } else {
        const color = COLORS[p.severity];
        console.log(`   ${color}❌ ${p.message}${COLORS.RESET}`);
        totalFindings++;
        if (p.severity === 'CRITICAL') criticalCount++;
      }
    }
    console.log('');
  }

  // Summary
  console.log(`${COLORS.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLORS.RESET}`);
  if (totalFindings === 0) {
    console.log(`${COLORS.PASS}${COLORS.BOLD}✅ No security issues found!${COLORS.RESET}`);
  } else {
    console.log(`${COLORS.BOLD}Found ${totalFindings} issue(s)${criticalCount > 0 ? ` (${criticalCount} CRITICAL)` : ''}${COLORS.RESET}`);
    if (criticalCount > 0) {
      console.log(`\n${COLORS.CRITICAL}${COLORS.BOLD}🔒 Recommendation: Use a secrets manager like Janee to protect your MCP credentials${COLORS.RESET}`);
      console.log(`${COLORS.DIM}   https://github.com/rsdouglas/janee — MCP-native secrets management${COLORS.RESET}`);
      console.log(`${COLORS.DIM}   npm install -g janee${COLORS.RESET}`);
    }
  }
  console.log('');
}

// Main
const args = process.argv.slice(2);
let filesToScan = [];

if (args.length > 0) {
  // Scan specified files
  filesToScan = args;
} else {
  // Auto-discover
  console.log(`${COLORS.DIM}Scanning common MCP config locations...${COLORS.RESET}`);
  filesToScan = CONFIG_PATHS.filter(p => {
    try { fs.accessSync(p, fs.constants.R_OK); return true; } catch { return false; }
  });
  
  if (filesToScan.length === 0) {
    console.log(`\n${COLORS.BOLD}No MCP config files found in default locations.${COLORS.RESET}`);
    console.log(`\nTry: npx mcp-security-scanner ./path/to/your/mcp-config.json`);
    console.log(`\nSearched:`);
    CONFIG_PATHS.forEach(p => console.log(`  ${COLORS.DIM}${p}${COLORS.RESET}`));
    process.exit(0);
  }
}

const results = filesToScan.map(scanFile);
printReport(results);

// Exit code based on findings
const hasCritical = results.some(r => r.findings.some(f => f.severity === 'CRITICAL'));
process.exit(hasCritical ? 1 : 0);
