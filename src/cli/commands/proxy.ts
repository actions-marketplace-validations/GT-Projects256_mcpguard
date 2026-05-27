/**
 * mcpguard proxy — Runtime firewall for MCP tool calls
 */

import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { McpFirewall } from '../../proxy/firewall';
import { PolicyEngine } from '../../policy/engine';
import { AuditLogger } from '../../audit/logger';
import { colorize } from '../format';

export const proxyCommand = new Command('proxy')
  .description('Start the MCP firewall proxy to intercept and filter tool calls')
  .option('-p, --port <number>', 'Port to listen on', '9090')
  .option('-h, --host <address>', 'Host to bind to', '127.0.0.1')
  .option('-u, --upstream <url>', 'Upstream MCP server URL to forward requests to')
  .option('--policy <file>', 'Path to policy YAML file')
  .option('--audit-file <path>', 'Path for audit log file')
  .option('--audit-format <fmt>', 'Audit log format (json, ndjson)', 'ndjson')
  .action(async (options: any) => {
    // Load policy if provided
    const policyEngine = new PolicyEngine();
    if (options.policy) {
      const policyPath = path.resolve(options.policy);
      if (!fs.existsSync(policyPath)) {
        console.error(colorize('red', `Policy file not found: ${policyPath}`));
        process.exit(1);
      }
      try {
        policyEngine.loadFromFile(policyPath);
        console.log(colorize('green', `  ✓ Loaded policy: ${policyPath}`));
        console.log(colorize('dim', `    ${policyEngine.getRules().length} rules active`));
      } catch (err: any) {
        console.error(colorize('red', `Error loading policy: ${err.message}`));
        process.exit(1);
      }
    }

    // Set up audit logger
    const auditLogger = new AuditLogger({
      enabled: true,
      output: options.auditFile ? 'both' : 'stdout',
      file: options.auditFile ? path.resolve(options.auditFile) : undefined,
      format: options.auditFormat,
    });

    // Create firewall
    const firewall = new McpFirewall({
      host: options.host,
      port: parseInt(options.port, 10),
      upstream: options.upstream,
      policyEngine,
      auditLogger,
      onBlock: (event) => {
        console.log(colorize('red', `  ✗ BLOCKED: ${event.tool} — ${event.decision?.reason}`));
      },
      onAllow: (event) => {
        console.log(colorize('green', `  ✓ ALLOWED: ${event.tool}`));
      },
      onPoisoning: (event) => {
        console.log(colorize('red', `  ⚠ POISONING DETECTED: ${event.tool}`));
      },
    });

    // Start
    console.log('');
    console.log(colorize('bold', '  mcpguard — MCP Firewall Proxy'));
    console.log(colorize('dim', '  ─────────────────────────────────'));
    console.log(`  Listening on ${options.host}:${options.port}`);
    if (options.upstream) {
      console.log(`  Upstream: ${options.upstream}`);
    }
    console.log('');

    try {
      await firewall.start();
      console.log(colorize('green', '  ✓ Firewall active. Press Ctrl+C to stop.'));
      console.log('');
    } catch (err: any) {
      console.error(colorize('red', `Failed to start: ${err.message}`));
      process.exit(1);
    }

    // Graceful shutdown
    const shutdown = async () => {
      console.log('');
      console.log(colorize('dim', '  Shutting down...'));
      await firewall.stop();
      auditLogger.close();
      process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  });
