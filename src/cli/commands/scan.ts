/**
 * mcpguard scan — Scan MCP configs against OWASP MCP Top 10
 */

import { Command } from 'commander';
import * as path from 'path';
import { Scanner } from '../../scanner';
import { ScanResult, ScanFinding, Severity } from '../../types';
import { formatSeverity, formatCategory, colorize } from '../format';

export const scanCommand = new Command('scan')
  .description('Scan MCP server configurations for security issues')
  .argument('[target]', 'File or directory to scan (default: current directory)', '.')
  .option('-s, --severity <level>', 'Minimum severity to report (critical, high, medium, low, info)', 'low')
  .option('-f, --format <type>', 'Output format (text, json, sarif)', 'text')
  .option('--ci', 'CI mode: exit with code 1 if critical or high findings', false)
  .action(async (target: string, options: any) => {
    const scanner = new Scanner({ minSeverity: options.severity as Severity });
    const absTarget = path.resolve(target);

    let results: ScanResult[];

    try {
      // Try as file first
      if (target.endsWith('.json')) {
        results = [scanner.scanFile(absTarget)];
      } else {
        results = scanner.scanDirectory(absTarget);
      }
    } catch (err: any) {
      console.error(colorize('red', `Error: ${err.message}`));
      process.exit(2);
    }

    if (results.length === 0) {
      console.log(colorize('yellow', 'No MCP configuration files found.'));
      console.log('Looked for: claude_desktop_config.json, .mcp.json, mcp.json');
      process.exit(0);
    }

    // Output results
    if (options.format === 'json') {
      console.log(JSON.stringify(results, null, 2));
    } else if (options.format === 'sarif') {
      console.log(JSON.stringify(toSarif(results), null, 2));
    } else {
      printTextReport(results);
    }

    // CI exit code
    if (options.ci) {
      const hasBlocking = results.some(r =>
        r.findings.some(f => f.severity === 'critical' || f.severity === 'high')
      );
      process.exit(hasBlocking ? 1 : 0);
    }
  });

function printTextReport(results: ScanResult[]): void {
  console.log('');
  console.log(colorize('bold', '  mcpguard — MCP Security Scanner'));
  console.log(colorize('dim', '  ─────────────────────────────────'));
  console.log('');

  for (const result of results) {
    console.log(colorize('bold', `  Target: ${result.target}`));
    console.log(colorize('dim', `  Scanned at ${result.timestamp} (${result.duration}ms)`));
    console.log('');

    if (result.findings.length === 0) {
      console.log(colorize('green', '  ✓ No issues found'));
      console.log('');
      continue;
    }

    // Group findings by category
    const grouped = new Map<string, ScanFinding[]>();
    for (const f of result.findings) {
      const key = f.category;
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key)!.push(f);
    }

    for (const [category, findings] of grouped) {
      console.log(`  ${formatCategory(category)}`);
      for (const f of findings) {
        console.log(`    ${formatSeverity(f.severity)} ${f.message}`);
        if (f.evidence) {
          console.log(colorize('dim', `      Evidence: ${f.evidence}`));
        }
        if (f.remediation) {
          console.log(colorize('cyan', `      Fix: ${f.remediation}`));
        }
      }
      console.log('');
    }

    // Summary
    const s = result.summary;
    console.log(colorize('dim', '  ─────────────────────────────────'));
    console.log(
      `  Summary: ` +
      (s.critical > 0 ? colorize('red', `${s.critical} critical `) : '') +
      (s.high > 0 ? colorize('yellow', `${s.high} high `) : '') +
      (s.medium > 0 ? colorize('blue', `${s.medium} medium `) : '') +
      (s.low > 0 ? `${s.low} low ` : '') +
      (s.total === 0 ? colorize('green', '0 issues') : `(${s.total} total)`)
    );
    console.log('');
  }
}

/**
 * Convert results to SARIF format for GitHub Code Scanning
 */
function toSarif(results: ScanResult[]): object {
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'mcpguard',
          version: '0.1.0',
          informationUri: 'https://github.com/mcpguard/mcpguard',
          rules: results.flatMap(r => r.findings).map(f => ({
            id: f.rule,
            shortDescription: { text: f.message },
            helpUri: `https://mcpguard.dev/rules/${f.rule}`,
          })),
        },
      },
      results: results.flatMap(r =>
        r.findings.map(f => ({
          ruleId: f.rule,
          level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning',
          message: { text: f.message },
          locations: f.file ? [{
            physicalLocation: {
              artifactLocation: { uri: f.file },
              region: f.line ? { startLine: f.line } : undefined,
            },
          }] : [],
        }))
      ),
    }],
  };
}
