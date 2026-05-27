# mcpguard

Open-source security firewall for MCP (Model Context Protocol) servers. Scan configurations for vulnerabilities, enforce runtime policies on tool calls, and generate compliance-ready audit logs.

Built against the **OWASP MCP Top 10** (2026).

## Why

MCP connects AI agents to tools and data. That connection is powerful — and dangerous. Research shows 82% of MCP implementations have path traversal vulnerabilities, 67% are susceptible to code injection, and 5.5% of servers exhibit tool poisoning.

mcpguard gives you visibility and control:

- **Scan** your MCP configs for known vulnerability patterns
- **Block** dangerous tool calls with policy-as-code rules
- **Detect** tool poisoning in real-time
- **Log** every tool call for audit compliance (EU AI Act, SOC 2)

## Quick Start

```bash
# Install globally
npm install -g mcpguard

# Scan your MCP configuration
mcpguard scan

# Generate a starter policy
mcpguard init

# Start the firewall proxy
mcpguard proxy --policy mcpguard.policy.yaml --port 9090
```

## Commands

### `mcpguard scan [target]`

Scan MCP server configurations against OWASP MCP Top 10 rules.

```bash
# Scan current directory
mcpguard scan

# Scan a specific config file
mcpguard scan claude_desktop_config.json

# Output as JSON
mcpguard scan --format json

# Output as SARIF (for GitHub Code Scanning)
mcpguard scan --format sarif

# CI mode: exit code 1 on critical/high findings
mcpguard scan --ci

# Filter by severity
mcpguard scan --severity high
```

### `mcpguard proxy`

Start a runtime firewall that intercepts MCP tool calls, evaluates them against policies, and detects tool poisoning.

```bash
# Basic proxy
mcpguard proxy --port 9090

# With policy enforcement
mcpguard proxy --policy mcpguard.policy.yaml --port 9090

# With upstream forwarding
mcpguard proxy --policy mcpguard.policy.yaml --upstream http://localhost:3000

# With audit logging to file
mcpguard proxy --policy mcpguard.policy.yaml --audit-file ./audit.log
```

### `mcpguard init`

Generate a default policy file to get started.

```bash
mcpguard init
mcpguard init --output custom-policy.yaml
```

## Policy Format

Policies are YAML files that define allow/deny/audit rules for tool calls:

```yaml
version: "1.0"
name: my-security-policy
description: Custom security rules

rules:
  - id: deny-shell-exec
    name: Block shell execution
    action: deny
    priority: 100
    conditions:
      - field: tool.name
        operator: matches
        value: "(exec|shell|bash|cmd)"

  - id: audit-file-writes
    name: Audit all file writes
    action: audit
    priority: 50
    conditions:
      - field: tool.name
        operator: contains
        value: write
```

### Condition Fields

| Field | Description |
|-------|-------------|
| `tool.name` | Name of the MCP tool being called |
| `tool.description` | Tool's description text |
| `param.name` | Parameter names (comma-separated) |
| `param.value` | Parameter values (comma-separated) |
| `server.name` | MCP server name |
| `server.url` | MCP server URL |

### Operators

| Operator | Description |
|----------|-------------|
| `equals` | Exact string match |
| `contains` | Substring match |
| `matches` | Regular expression match |
| `startsWith` | Prefix match |
| `endsWith` | Suffix match |
| `in` | Value in list |

## OWASP MCP Top 10 Coverage

| ID | Category | Rules |
|----|----------|-------|
| MCP01 | Tool Poisoning | Hidden instruction detection, zero-width character detection |
| MCP02 | Excessive Permissions | Broad file system access checks |
| MCP03 | Insecure Transport | Unencrypted HTTP detection |
| MCP04 | Command Injection | Shell metacharacter detection in args |
| MCP05 | Path Traversal | `..` pattern detection in paths |
| MCP06 | Secret Exposure | API key and token pattern matching |
| MCP07 | Insecure Defaults | Missing security configuration |
| MCP08 | Input Validation | Dangerous command detection |
| MCP09 | Audit Gaps | Missing logging configuration |
| MCP10 | Privilege Escalation | sudo/privileged mode detection |

## GitHub Actions

Add mcpguard to your CI/CD pipeline:

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g mcpguard
      - run: mcpguard scan --ci --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Programmatic API

```typescript
import { Scanner, PolicyEngine, McpFirewall, AuditLogger } from 'mcpguard';

// Scan a config
const scanner = new Scanner();
const results = scanner.scanFile('claude_desktop_config.json');
console.log(results.summary);

// Evaluate a policy
const engine = new PolicyEngine();
engine.loadFromFile('mcpguard.policy.yaml');
const decision = engine.evaluate({
  toolName: 'shell_exec',
  paramNames: ['command'],
  paramValues: ['rm -rf /'],
});
console.log(decision); // { allowed: false, action: 'deny', ... }
```

## Contributing

Contributions welcome. Please open an issue first to discuss what you'd like to change.

```bash
git clone https://github.com/mcpguard/mcpguard.git
cd mcpguard
npm install
npm test
```

## License

MIT
