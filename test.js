#!/usr/bin/env node
/**
 * Test suite for mcp-security-scanner
 * Run: node test.js
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

let passed = 0;
let failed = 0;
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-scan-test-'));

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ❌ ${name}`);
    console.log(`     ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function writeConfig(filename, content) {
  const filepath = path.join(tmpDir, filename);
  fs.writeFileSync(filepath, JSON.stringify(content, null, 2));
  return filepath;
}

function scan(filepath, flags = '') {
  try {
    const result = execSync(`node ${__dirname}/scan.js ${flags} "${filepath}" 2>&1`, {
      encoding: 'utf8',
      timeout: 10000
    });
    return { output: result, exitCode: 0 };
  } catch (e) {
    return { output: e.stdout || e.stderr || '', exitCode: e.status };
  }
}

console.log('\n🔍 MCP Security Scanner — Test Suite\n');

// === Detection Tests ===
console.log('Detection Tests:');

test('Detects GitHub classic token (ghp_)', () => {
  const f = writeConfig('ghp.json', {
    mcpServers: { test: { command: 'test', env: { TOKEN: 'ghp_1234567890abcdef1234567890abcdef12345678' } } }
  });
  const { output, exitCode } = scan(f);
  assert(exitCode === 1, `Expected exit code 1 (CRITICAL), got ${exitCode}`);
  assert(output.includes('GitHub Token (classic)'), 'Should identify as GitHub classic token');
});

test('Detects GitHub fine-grained token (github_pat_)', () => {
  const f = writeConfig('ghpat.json', {
    mcpServers: { test: { command: 'test', env: { TOKEN: 'github_pat_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456' } } }
  });
  const { output, exitCode } = scan(f);
  assert(exitCode === 1, `Expected exit code 1, got ${exitCode}`);
  assert(output.includes('GitHub Fine-grained PAT'), 'Should identify as fine-grained PAT');
});

test('Detects AWS access key', () => {
  const f = writeConfig('aws.json', {
    mcpServers: { test: { command: 'test', env: { AWS_KEY: 'AKIAIOSFODNN7EXAMPLE' } } }
  });
  const { output, exitCode } = scan(f);
  assert(exitCode === 1, `Expected exit code 1, got ${exitCode}`);
  assert(output.includes('AWS Access Key'), 'Should identify as AWS access key');
});

test('Detects OpenAI API key (new format)', () => {
  const f = writeConfig('openai.json', {
    mcpServers: { test: { command: 'test', env: { KEY: 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdefgh' } } }
  });
  const { output, exitCode } = scan(f);
  assert(exitCode === 1, `Expected exit code 1, got ${exitCode}`);
  assert(output.includes('OpenAI'), 'Should identify as OpenAI key');
});

test('Detects Anthropic API key', () => {
  const f = writeConfig('anthropic.json', {
    mcpServers: { test: { command: 'test', env: { KEY: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890' } } }
  });
  const { output, exitCode } = scan(f);
  assert(exitCode === 1, `Expected exit code 1, got ${exitCode}`);
  assert(output.includes('Anthropic'), 'Should identify as Anthropic key');
});

test('Detects Stripe secret key', () => {
  const f = writeConfig('stripe.json', {
    mcpServers: { test: { command: 'test', env: { KEY: 'sk_' + 'live_TESTFAKE00000000000000000' } } }
  });
  const { output, exitCode } = scan(f);
  assert(exitCode === 1, `Expected exit code 1, got ${exitCode}`);
  assert(output.includes('Stripe'), 'Should identify as Stripe key');
});

test('Detects Slack bot token', () => {
  const f = writeConfig('slack.json', {
    mcpServers: { test: { command: 'test', env: { TOKEN: 'xox' + 'b-000000000000-0000000000000-TESTFAKE0000000000000000' } } }
  });
  const { output, exitCode } = scan(f);
  assert(output.includes('Slack'), 'Should identify as Slack token');
});

test('Detects Postgres connection string with password', () => {
  const f = writeConfig('pg.json', {
    mcpServers: { test: { command: 'test', env: { DB: 'postgresql://user:secretpass@localhost:5432/mydb' } } }
  });
  const { output, exitCode } = scan(f);
  assert(exitCode === 1, `Expected exit code 1, got ${exitCode}`);
  assert(output.includes('Postgres'), 'Should identify as Postgres connection string');
});

test('Detects MongoDB connection string with password', () => {
  const f = writeConfig('mongo.json', {
    mcpServers: { test: { command: 'test', env: { DB: 'mongodb+srv://admin:password123@cluster0.abc.mongodb.net/mydb' } } }
  });
  const { output, exitCode } = scan(f);
  assert(exitCode === 1, `Expected exit code 1, got ${exitCode}`);
  assert(output.includes('MongoDB'), 'Should identify as MongoDB connection string');
});

test('Detects SendGrid API key', () => {
  const f = writeConfig('sendgrid.json', {
    mcpServers: { test: { command: 'test', env: { KEY: 'SG.abcdefghijklmnop.qrstuvwxyz1234567890ABCDEFGH' } } }
  });
  const { output, exitCode } = scan(f);
  assert(output.includes('SendGrid'), 'Should identify as SendGrid key');
});

// === Clean Config Tests ===
console.log('\nClean Config Tests:');

test('Clean config with env var references returns exit 0', () => {
  const f = writeConfig('clean.json', {
    mcpServers: { test: { command: 'npx', args: ['-y', 'some-server'], env: { TOKEN: '${MY_TOKEN}' } } }
  });
  const { output, exitCode } = scan(f);
  assert(exitCode === 0, `Expected exit code 0, got ${exitCode}`);
  assert(output.includes('No secrets found') || !output.includes('CRITICAL'), 'Should not flag env var references');
});

test('Config with no env block is clean', () => {
  const f = writeConfig('noenv.json', {
    mcpServers: { test: { command: 'npx', args: ['-y', 'some-server'] } }
  });
  const { exitCode } = scan(f);
  assert(exitCode === 0, `Expected exit code 0, got ${exitCode}`);
});

// === Flag Tests ===
console.log('\nFlag Tests:');

test('--json produces valid JSON output', () => {
  const f = writeConfig('json-test.json', {
    mcpServers: { test: { command: 'test', env: { TOKEN: 'ghp_1234567890abcdef1234567890abcdef12345678' } } }
  });
  const { output } = scan(f, '--json');
  const parsed = JSON.parse(output);
  assert(parsed.version === '1.1.0', 'Should have version');
  assert(parsed.summary, 'Should have summary');
  assert(parsed.summary.critical > 0, 'Should have critical findings');
});

test('--fix shows remediation steps', () => {
  const f = writeConfig('fix-test.json', {
    mcpServers: { test: { command: 'test', env: { MY_TOKEN: 'ghp_1234567890abcdef1234567890abcdef12345678' } } }
  });
  const { output } = scan(f, '--fix');
  assert(output.includes('janee store'), 'Should suggest janee store command');
  assert(output.includes('Fix:'), 'Should show fix label');
});

test('--version shows version', () => {
  const { output } = scan('--version');
  assert(output.includes('1.1.0'), 'Should show version 1.1.0');
});

test('--help shows usage', () => {
  const { output } = scan('--help');
  assert(output.includes('Usage'), 'Should show usage info');
  assert(output.includes('--json'), 'Should mention --json flag');
});

// === Best Practices Tests ===
console.log('\nBest Practices Tests:');

test('Detects secrets in command args', () => {
  const f = writeConfig('args.json', {
    mcpServers: { test: { command: 'server', args: ['--token', 'sk_' + 'live_TESTFAKE00000000000000000'] } }
  });
  const { output } = scan(f);
  assert(output.includes('command arguments') || output.includes('CRITICAL'), 'Should flag secrets in args');
});

test('Detects wildcard permissions', () => {
  const f = writeConfig('wildcard.json', {
    mcpServers: { test: { command: 'test', permissions: '*', env: {} } }
  });
  const { output } = scan(f);
  assert(output.includes('wildcard') || output.includes('permissions'), 'Should check for wildcards');
});

// === Cleanup ===
fs.rmSync(tmpDir, { recursive: true, force: true });

console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) {
  console.log('❌ Some tests failed');
  process.exit(1);
} else {
  console.log('✅ All tests passed!');
  process.exit(0);
}
