const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Create test configs
const testDir = path.join(__dirname, 'test-configs');
fs.mkdirSync(testDir, { recursive: true });

// Test 1: Config with hardcoded secrets (using obviously fake but pattern-matching values)
const badConfig = {
  mcpServers: {
    github: {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-github"],
      env: {
        GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_FAKE0000000000000000000000000000000000"
      }
    },
    aws: {
      command: "node",
      args: ["aws-server.js"],
      env: {
        AWS_ACCESS_KEY_ID: "AKIAFAKEEXAMPLEKEYID"
      }
    }
  }
};
fs.writeFileSync(path.join(testDir, 'bad-config.json'), JSON.stringify(badConfig, null, 2));

// Test 2: Clean config using env var references
const goodConfig = {
  mcpServers: {
    github: {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-github"],
      env: {
        GITHUB_PERSONAL_ACCESS_TOKEN: "${GITHUB_TOKEN}"
      }
    }
  }
};
fs.writeFileSync(path.join(testDir, 'good-config.json'), JSON.stringify(goodConfig, null, 2));

console.log('=== Test 1: Bad config (should find secrets) ===\n');
try {
  execSync(`node scan.js ${path.join(testDir, 'bad-config.json')}`, { stdio: 'inherit' });
} catch (e) {
  console.log('(Exited with error code — expected for configs with CRITICAL findings)\n');
}

console.log('\n=== Test 2: Good config (should pass) ===\n');
execSync(`node scan.js ${path.join(testDir, 'good-config.json')}`, { stdio: 'inherit' });

// Cleanup
fs.rmSync(testDir, { recursive: true });
console.log('\n✅ All tests completed');
