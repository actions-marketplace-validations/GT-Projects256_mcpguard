/**
 * mcpguard init command
 */

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { colorize } from '../format';

const DEFAULT_POLICY = `# mcpguard policy - security rules for MCP tool calls
# Docs: https://github.com/GT-Projects256/mcpguard#policies

version: "1.0"
name: default
description: Default security policy for MCP tool calls

rules:
  # Block tools that attempt to execute shell commands
  - id: deny-shell-exec
    name: Block shell execution tools
    description: Prevents MCP tools from executing arbitrary shell commands
    action: deny
    priority: 100
    conditions:
      - field: tool.name
        operator: matches
        value: "(exec|shell|bash|cmd|terminal|run_command)"

  # Block tools that access sensitive file paths
  - id: deny-sensitive-paths
    name: Block sensitive path access
    description: Prevents access to system directories and sensitive files
    action: deny
    priority: 90
    conditions:
      - field: param.value
        operator: matches
        value: "(/etc/passwd|/etc/shadow|\\\\.ssh/|\\\\.env|/proc/|/sys/)"

  # Audit all file write operations
  - id: audit-file-writes
    name: Audit file writes
    description: Log all file write operations for compliance
    action: audit
    priority: 50
    conditions:
      - field: tool.name
        operator: matches
        value: "(write|create|save|update)_file"

  # Allow read-only operations
  - id: allow-reads
    name: Allow read operations
    description: Permit read-only tool calls
    action: allow
    priority: 10
    conditions:
      - field: tool.name
        operator: matches
        value: "(read|get|list|search|find)_"
`;

export const initCommand = new Command('init')
  .description('Generate a default mcpguard policy file')
  .option('-o, --output <path>', 'Output file path', 'mcpguard.policy.yaml')
  .action(async (options: any) => {
    const outputPath = path.resolve(options.output);

    if (fs.existsSync(outputPath)) {
      console.error(colorize('yellow', `  File already exists: ${outputPath}`));
      console.error('  Use --output <path> to specify a different location.');
      process.exit(1);
    }

    fs.writeFileSync(outputPath, DEFAULT_POLICY, 'utf-8');

    console.log('');
    console.log(colorize('bold', '  mcpguard - Policy Initialized'));
    console.log(colorize('dim', '  ─────────────────────────────────'));
    console.log(colorize('green', `  ✓ Created ${outputPath}`));
    console.log('');
    console.log('  Next steps:');
    console.log(`    1. Edit ${options.output} to customize rules`);
    console.log(`    2. Run: mcpguard scan --policy ${options.output}`);
    console.log(`    3. Run: mcpguard proxy --policy ${options.output}`);
    console.log('');
  });
