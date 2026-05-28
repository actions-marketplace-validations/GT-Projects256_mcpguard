/**
 * MCP scanner - checks server configs against OWASP MCP Top 10
 */

import * as fs from 'fs';
import * as path from 'path';
import { ScanResult, ScanFinding, ScanSummary, McpConfigFile, Severity } from '../types';
import { BUILTIN_RULES, ScanRule } from './rules';

export class Scanner {
  private rules: ScanRule[];
  private minSeverity: Severity;

  constructor(opts?: { rules?: ScanRule[]; minSeverity?: Severity }) {
    this.rules = opts?.rules ?? BUILTIN_RULES;
    this.minSeverity = opts?.minSeverity ?? 'low';
  }

  /**
   * Scan an MCP config file (e.g., claude_desktop_config.json, .mcp.json)
   */
  scanFile(filePath: string): ScanResult {
    const start = Date.now();
    const absPath = path.resolve(filePath);

    if (!fs.existsSync(absPath)) {
      throw new Error(`File not found: ${absPath}`);
    }

    const rawContent = fs.readFileSync(absPath, 'utf-8');
    let config: McpConfigFile;

    try {
      config = JSON.parse(rawContent);
    } catch {
      throw new Error(`Invalid JSON in ${absPath}`);
    }

    const findings = this.scanConfig(config, rawContent, absPath);
    const duration = Date.now() - start;

    return {
      target: absPath,
      timestamp: new Date().toISOString(),
      duration,
      findings: this.filterBySeverity(findings),
      summary: this.summarize(findings),
    };
  }

  /**
   * Scan a directory for MCP config files
   */
  scanDirectory(dirPath: string): ScanResult[] {
    const absDir = path.resolve(dirPath);
    const configPatterns = [
      'claude_desktop_config.json',
      '.mcp.json',
      'mcp.json',
      '.cursor/mcp.json',
      '.vscode/mcp.json',
    ];

    const results: ScanResult[] = [];

    for (const pattern of configPatterns) {
      const fullPath = path.join(absDir, pattern);
      if (fs.existsSync(fullPath)) {
        try {
          results.push(this.scanFile(fullPath));
        } catch (err) {
          // Skip files that can't be parsed
        }
      }
    }

    // Also scan subdirectories one level deep
    try {
      const entries = fs.readdirSync(absDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
          for (const pattern of configPatterns) {
            const fullPath = path.join(absDir, entry.name, pattern);
            if (fs.existsSync(fullPath)) {
              try {
                results.push(this.scanFile(fullPath));
              } catch {
                // Skip
              }
            }
          }
        }
      }
    } catch {
      // Skip directory read errors
    }

    return results;
  }

  /**
   * Scan a parsed config object directly
   */
  scanConfig(config: McpConfigFile, rawContent?: string, filePath?: string): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const servers = config.mcpServers ?? {};

    for (const [serverName, serverConfig] of Object.entries(servers)) {
      for (const rule of this.rules) {
        try {
          const ruleFindings = rule.check(serverName, serverConfig, rawContent);
          for (const f of ruleFindings) {
            f.file = filePath;
            findings.push(f);
          }
        } catch {
          // rule threw, skip it
        }
      }
    }

    return findings;
  }

  private filterBySeverity(findings: ScanFinding[]): ScanFinding[] {
    const severityOrder: Record<Severity, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0,
    };
    const minLevel = severityOrder[this.minSeverity];
    return findings.filter(f => severityOrder[f.severity] >= minLevel);
  }

  private summarize(findings: ScanFinding[]): ScanSummary {
    const summary: ScanSummary = {
      total: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      passed: 0,
      failed: 0,
    };

    for (const f of findings) {
      summary[f.severity]++;
    }

    summary.failed = summary.critical + summary.high;
    summary.passed = this.rules.length - summary.failed;

    return summary;
  }
}

export { BUILTIN_RULES } from './rules';
