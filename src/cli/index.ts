#!/usr/bin/env node

/**
 * mcpguard CLI
 */

import { Command } from 'commander';
import { readFileSync } from 'fs';
import { join } from 'path';
import { scanCommand } from './commands/scan';
import { proxyCommand } from './commands/proxy';
import { initCommand } from './commands/init';

const pkg = JSON.parse(readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf-8'));

const program = new Command();

program
  .name('mcpguard')
  .description('Open-source security firewall for MCP (Model Context Protocol) servers')
  .version(pkg.version);

program.addCommand(scanCommand);
program.addCommand(proxyCommand);
program.addCommand(initCommand);

program.parseAsync().catch((err) => {
  console.error(err);
  process.exit(2);
});
