/**
 * Audit logger - structured JSON logging for compliance
 */

import * as fs from 'fs';
import * as path from 'path';
import { AuditEntry, Severity, McpGuardConfig } from '../types';

export class AuditLogger {
  private outputMode: 'stdout' | 'file' | 'both';
  private filePath?: string;
  private format: 'json' | 'ndjson';
  private stream?: fs.WriteStream;
  private entries: AuditEntry[] = [];

  constructor(config?: McpGuardConfig['audit']) {
    this.outputMode = config?.output ?? 'stdout';
    this.format = config?.format ?? 'ndjson';

    if ((this.outputMode === 'file' || this.outputMode === 'both') && config?.file) {
      this.filePath = config.file;
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      this.stream = fs.createWriteStream(this.filePath, { flags: 'a' });
    }
  }

  log(
    event: AuditEntry['event'],
    severity: Severity,
    details: Record<string, unknown>
  ): AuditEntry {
    const entry: AuditEntry = {
      id: this.generateId(),
      timestamp: new Date().toISOString(),
      event,
      severity,
      details,
    };

    this.entries.push(entry);
    this.write(entry);
    return entry;
  }

  toolCall(server: string, tool: string, params: Record<string, unknown>, allowed: boolean): AuditEntry {
    return this.log('tool_call', allowed ? 'info' : 'high', {
      server,
      tool,
      params,
      allowed,
    });
  }

  policyDecision(
    tool: string,
    action: string,
    rule: string,
    reason: string
  ): AuditEntry {
    const severity: Severity = action === 'deny' ? 'high' : 'info';
    return this.log('policy_decision', severity, {
      tool,
      action,
      rule,
      reason,
    });
  }

  poisoningDetected(server: string, tool: string, details: string): AuditEntry {
    return this.log('poisoning_detected', 'critical', {
      server,
      tool,
      details,
    });
  }

  scanComplete(target: string, findings: number, critical: number, high: number): AuditEntry {
    return this.log('scan_complete', critical > 0 ? 'critical' : high > 0 ? 'high' : 'info', {
      target,
      findings,
      critical,
      high,
    });
  }

  getEntries(): AuditEntry[] {
    return [...this.entries];
  }

  close(): void {
    if (this.stream) {
      this.stream.end();
    }
  }

  private write(entry: AuditEntry): void {
    const line = JSON.stringify(entry);

    if (this.outputMode === 'stdout' || this.outputMode === 'both') {
      // Write to stderr so it doesn't interfere with normal CLI output
      process.stderr.write(line + '\n');
    }

    if ((this.outputMode === 'file' || this.outputMode === 'both') && this.stream) {
      this.stream.write(line + '\n');
    }
  }

  private generateId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
  }
}
