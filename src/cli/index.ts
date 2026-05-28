#!/usr/bin/env node

/**
 * mcpguard CLI
 */

import { Command } from 'commander';
import { scanCommand } from './commands/scan';
import { proxyCommand } from './commands/proxy';
import { initCommand } from './commands/init';

const program = new Command();

program
  .name('mcpguard')
  .description('Open-source security firewall for MCP (Model Context Protocol) servers')
  .version('0.1.0');

program.addCommand(scanCommand);
program.addCommand(proxyCommand);
program.addCommand(initCommand);

program.parse();
