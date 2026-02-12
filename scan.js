#!/usr/bin/env node
/**
 * mcp-security-scanner v1.1.0
 * Scans MCP configuration files for security issues
 * 
 * Usage:
 *   npx mcp-security-scanner [options] [path...]
 * 
 * Options:
 *   --json       Output results as JSON
 *   --fix        Show fix suggestions using Janee
 *   --recursive  Scan directories recursively for MCP configs
 *   --version    Show version
 *   --help       Show help
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const VERSION = '1.1.0';

// Parse CLI args
const args = process.argv.slice(2);
const flags = {
  json: args.includes('--json'),
  fix: args.includes('--fix'),
  recursive: args.includes('--recursive') || args.includes('-r'),
  version: args.includes('--version') || args.includes('-v'),
  help: args.includes('--help') || args.includes('-h'),
};
const paths = args.filter(a => !a.startsWith('--') && !a.startsWith('-'));

if (flags.version) { console.log(`mcp-security-scanner v${VERSION}`); process.exit(0); }
if (flags.help) {
  console.log(`
mcp-security-scanner v${VERSION}
Scan MCP configs for hardcoded secrets and security issues.

Usage: npx mcp-security-scanner [options] [path...]

Options:
  --json        Output as JSON (for CI/CD pipelines)
  --fix         Show remediation steps using Janee
  --recursive   Scan directories recursively
  -v, --version Show version
  -h, --help    Show this help

Examples:
  npx mcp-security-scanner                          # Auto-scan common locations
  npx mcp-security-scanner ./config.json             # Scan specific file
  npx mcp-security-scanner --json ./config.json      # JSON output for CI
  npx mcp-security-scanner --fix ./config.json       # Show fix suggestions
  npx mcp-security-scanner --recursive ./projects/   # Scan all configs in dir
`);
  process.exit(0);
}

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

// Secret detection patterns - comprehensive list
const SECRET_PATTERNS = [
  { name: 'GitHub Token (classic)', pattern: /ghp_[a-zA-Z0-9]{36}/, severity: 'CRITICAL' },
  { name: 'GitHub Fine-grained PAT', pattern: /github_pat_[a-zA-Z0-9_]{36,}/, severity: 'CRITICAL' },
  { name: 'GitHub OAuth', pattern: /gho_[a-zA-Z0-9]{36}/, severity: 'CRITICAL' },
  { name: 'GitHub App Token', pattern: /ghu_[a-zA-Z0-9]{36}/, severity: 'CRITICAL' },
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/, severity: 'CRITICAL' },
  { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}/, severity: 'CRITICAL' },
  { name: 'OpenAI API Key (new)', pattern: /sk-proj-[a-zA-Z0-9_-]{40,}/, severity: 'CRITICAL' },
    { name: 'Anthropic API Key', pattern: /sk-ant-api[a-zA-Z0-9-]{20,}/, severity: 'CRITICAL' },
  { name: 'Anthropic API Key', pattern: /sk-ant-[a-zA-Z0-9-]{90,}/, severity: 'CRITICAL' },
  { name: 'Stripe Secret Key', pattern: /sk_(live|test)_[a-zA-Z0-9]{24,}/, severity: 'CRITICAL' },
  { name: 'Stripe Publishable Key', pattern: /pk_(live|test)_[a-zA-Z0-9]{24,}/, severity: 'MEDIUM' },
  { name: 'Slack Bot Token', pattern: /xoxb-[a-zA-Z0-9-]+/, severity: 'HIGH' },
  { name: 'Slack User Token', pattern: /xoxp-[a-zA-Z0-9-]+/, severity: 'HIGH' },
  { name: 'Discord Bot Token', pattern: /[MN][A-Za-z\d]{23,}\.[\\w-]{6}\.[\\w-]{27,}/, severity: 'HIGH' },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/, severity: 'HIGH' },
  { name: 'Google OAuth Client Secret', pattern: /GOCSPX-[a-zA-Z0-9_-]{28}/, severity: 'CRITICAL' },
  { name: 'Azure Subscription Key', pattern: /[a-f0-9]{32}(?=.*(?:azure|microsoft))/i, severity: 'HIGH' },
  { name: 'Twilio API Key', pattern: /SK[a-f0-9]{32}/, severity: 'CRITICAL' },
  { name: 'SendGrid API Key', pattern: /SG\.[a-zA-Z0-9_-]{16,}\.[a-zA-Z0-9_-]{16,}/, severity: 'CRITICAL' },
  { name: 'Mailgun API Key', pattern: /key-[a-zA-Z0-9]{32}/, severity: 'CRITICAL' },
  { name: 'Supabase Key', pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/, severity: 'HIGH' },
  { name: 'Postgres Connection String', pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@/, severity: 'CRITICAL' },
  { name: 'MongoDB Connection String', pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/, severity: 'CRITICAL' },
  { name: 'Bearer Token', pattern: /Bearer\s+[a-zA-Z0-9_\-\.]{20,}/, severity: 'HIGH' },
  { name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/, severity: 'CRITICAL' },
  { name: 'Generic High-Entropy Secret', pattern: /["'](?:api[_-]?key|apikey|api[_-]?token|secret[_-]?key|access[_-]?token)["']?\s*[:=]\s*["'][a-zA-Z0-9_\-]{20,}["']/i, severity: 'MEDIUM' },
  { name: 'Generic Password', pattern: /["']?(?:password|passwd|pwd)["']?\s*[:=]\s*["'][^"']{8,}["']/i, severity: 'HIGH' },
  { name: 'NPM Token', pattern: /npm_[a-zA-Z0-9]{36}/, severity: 'CRITICAL' },
  { name: 'PyPI Token', pattern: /pypi-[a-zA-Z0-9_-]{50,}/, severity: 'CRITICAL' },
  { name: 'Hugging Face Token', pattern: /hf_[a-zA-Z0-9]{34}/, severity: 'HIGH' },
  { name: 'Replicate API Token', pattern: /r8_[a-zA-Z0-9]{40}/, severity: 'HIGH' },
];

// Security best practice checks
const BEST_PRACTICE_CHECKS = [
  {
    name: 'env-var-refs',
    check: (config) => {
      const str = JSON.stringify(config);
      return str.includes('${') || str.includes('process.env');
    },
    pass: 'Config uses environment variable references',
    fail: 'Config does not use environment variable references — secrets may be hardcoded',
    severity: 'MEDIUM'
  },
  {
    name: 'no-secrets-in-args',
    check: (config) => {
      const servers = config.mcpServers || {};
      for (const [, server] of Object.entries(servers)) {
        const args = (server.args || []).join(' ');
        for (const p of SECRET_PATTERNS) {
          if (p.pattern.test(args)) return false;
        }
      }
      return true;
    },
    pass: 'No secrets found in server command arguments',
    fail: 'Secrets detected in command arguments — visible in process listings (ps aux)!',
    severity: 'CRITICAL'
  },
  {
    name: 'no-literal-env-secrets',
    check: (config) => {
      const servers = config.mcpServers || {};
      for (const [, server] of Object.entries(servers)) {
        const env = server.env || {};
        for (const [, value] of Object.entries(env)) {
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
  },
  {
    name: 'no-wildcard-permissions',
    check: (config) => {
      const str = JSON.stringify(config);
      return !/"permissions"\s*:\s*\[?\s*"\*"\s*\]?/.test(str);
    },
    pass: 'No wildcard permissions detected',
    fail: 'Wildcard permissions ("*") detected — follow principle of least privilege',
    severity: 'HIGH'
  }
];

const COLORS = {
  CRITICAL: '\x1b[31m',
  HIGH: '\x1b[33m',
  MEDIUM: '\x1b[36m',
  LOW: '\x1b[37m',
  PASS: '\x1b[32m',
  RESET: '\x1b[0m',
  BOLD: '\x1b[1m',
  DIM: '\x1b[2m',
};

function findConfigsRecursive(dir, depth = 0) {
  if (depth > 5) return [];
  const results = [];
  const configNames = ['mcp.json', '.mcp.json', 'claude_desktop_config.json', 'mcp-config.json'];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isFile() && configNames.includes(entry.name)) {
        results.push(full);
      } else if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
        results.push(...findConfigsRecursive(full, depth + 1));
      }
    }
  } catch {}
  return results;
}

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
    return { filePath, error: 'Invalid JSON: ' + e.message, findings: [], practices: [] };
  }

  // Scan for secret patterns line by line
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    for (const sp of SECRET_PATTERNS) {
      const match = lines[i].match(sp.pattern);
      if (match) {
        const masked = lines[i].replace(sp.pattern, (m) =>
          m.substring(0, Math.min(6, m.length)) + '*'.repeat(Math.min(m.length - 6, 20)) + '...'
        );
        findings.push({
          line: i + 1,
          severity: sp.severity,
          type: sp.name,
          masked: masked.trim(),
          envKey: extractEnvKey(lines[i]),
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

  const serverCount = Object.keys(config.mcpServers || {}).length;
  const serverNames = Object.keys(config.mcpServers || {});

  return { filePath, findings, practices, serverCount, serverNames, error: null };
}

function extractEnvKey(line) {
  const match = line.match(/"([A-Z_][A-Z0-9_]*)"\s*:/);
  return match ? match[1] : null;
}

function generateFix(finding) {
  const key = finding.envKey || 'YOUR_SECRET';
  return {
    step1: `janee store ${key.toLowerCase().replace(/_/g, '-')} <your-actual-value>`,
    step2: `# Replace in config: "${key}": "\${${key}}"`,
    step3: `# Or use Janee as MCP proxy: https://github.com/rsdouglas/janee`,
  };
}

function printReport(results) {
  if (flags.json) {
    const output = {
      version: VERSION,
      timestamp: new Date().toISOString(),
      files: results.map(r => ({
        path: r.filePath,
        error: r.error,
        servers: r.serverNames || [],
        findings: r.findings.map(f => ({
          line: f.line,
          severity: f.severity,
          type: f.type,
          envKey: f.envKey,
          ...(flags.fix ? { fix: generateFix(f) } : {}),
        })),
        practices: r.practices,
      })),
      summary: {
        filesScanned: results.length,
        totalFindings: results.reduce((sum, r) => sum + r.findings.length, 0),
        critical: results.reduce((sum, r) => sum + r.findings.filter(f => f.severity === 'CRITICAL').length, 0),
        high: results.reduce((sum, r) => sum + r.findings.filter(f => f.severity === 'HIGH').length, 0),
        medium: results.reduce((sum, r) => sum + r.findings.filter(f => f.severity === 'MEDIUM').length, 0),
      }
    };
    console.log(JSON.stringify(output, null, 2));
    return;
  }

  console.log(`\n${COLORS.BOLD}╔══════════════════════════════════════════════════╗${COLORS.RESET}`);
  console.log(`${COLORS.BOLD}║    🔍 MCP Security Scanner v${VERSION}              ║${COLORS.RESET}`);
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
        if (flags.fix && f.envKey) {
          const fix = generateFix(f);
          console.log(`     ${COLORS.PASS}💡 Fix: ${fix.step1}${COLORS.RESET}`);
          console.log(`     ${COLORS.PASS}   Then: ${fix.step2}${COLORS.RESET}`);
        }
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

  console.log(`${COLORS.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLORS.RESET}`);
  if (totalFindings === 0) {
    console.log(`${COLORS.PASS}${COLORS.BOLD}✅ No security issues found!${COLORS.RESET}`);
  } else {
    console.log(`${COLORS.BOLD}Found ${totalFindings} issue(s)${criticalCount > 0 ? ` (${criticalCount} CRITICAL)` : ''}${COLORS.RESET}`);
    console.log(`\n${COLORS.BOLD}🔒 Recommendation:${COLORS.RESET} Use Janee to manage MCP secrets securely`);
    console.log(`   ${COLORS.DIM}https://github.com/rsdouglas/janee — MCP-native secrets management${COLORS.RESET}`);
    if (!flags.fix) {
      console.log(`\n   ${COLORS.DIM}Run with --fix to see remediation steps${COLORS.RESET}`);
    }
  }
  console.log('');
}

// Main
let filesToScan = [];

if (paths.length > 0) {
  for (const p of paths) {
    try {
      const stat = fs.statSync(p);
      if (stat.isDirectory()) {
        if (flags.recursive) {
          filesToScan.push(...findConfigsRecursive(p));
        } else {
          console.log(`${COLORS.DIM}${p} is a directory. Use --recursive to scan it.${COLORS.RESET}`);
        }
      } else {
        filesToScan.push(p);
      }
    } catch {
      filesToScan.push(p); // Let scanFile handle the error
    }
  }
} else {
  if (!flags.json) {
    console.log(`${COLORS.DIM}Scanning common MCP config locations...${COLORS.RESET}`);
  }
  filesToScan = CONFIG_PATHS.filter(p => {
    try { fs.accessSync(p, fs.constants.R_OK); return true; } catch { return false; }
  });

  if (filesToScan.length === 0) {
    if (flags.json) {
      console.log(JSON.stringify({ version: VERSION, files: [], summary: { filesScanned: 0, totalFindings: 0 } }));
    } else {
      console.log(`\n${COLORS.BOLD}No MCP config files found in default locations.${COLORS.RESET}`);
      console.log(`\nTry: npx mcp-security-scanner ./path/to/your/mcp-config.json`);
      console.log(`\nSearched:`);
      CONFIG_PATHS.forEach(p => console.log(`  ${COLORS.DIM}${p}${COLORS.RESET}`));
    }
    process.exit(0);
  }
}

if (filesToScan.length === 0) {
  if (!flags.json) console.log('No files to scan.');
  process.exit(0);
}

const results = filesToScan.map(scanFile);
printReport(results);

// Exit code: 1 if CRITICAL findings, 2 if HIGH, 0 if clean
const hasCritical = results.some(r => r.findings.some(f => f.severity === 'CRITICAL'));
const hasHigh = results.some(r => r.findings.some(f => f.severity === 'HIGH'));
process.exit(hasCritical ? 1 : hasHigh ? 2 : 0);
