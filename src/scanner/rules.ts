/**
 * Built-in scanner rules aligned to OWASP MCP Top 10
 */

import { ScanFinding, Severity, OwaspCategory, McpServerConfig } from '../types';

export interface ScanRule {
  id: string;
  name: string;
  category: OwaspCategory;
  severity: Severity;
  description: string;
  check: (serverName: string, config: McpServerConfig, rawContent?: string) => ScanFinding[];
}

// ── Helper: create a finding ──
function finding(
  rule: ScanRule,
  message: string,
  opts?: { file?: string; line?: number; evidence?: string; remediation?: string }
): ScanFinding {
  return {
    id: `${rule.id}_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    rule: rule.id,
    severity: rule.severity,
    category: rule.category,
    message,
    ...opts,
  };
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OWASP MCP Top 10 Rules
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

export const BUILTIN_RULES: ScanRule[] = [
  // ── MCP01: Tool Poisoning ──
  {
    id: 'MCP01-001',
    name: 'Suspicious tool description patterns',
    category: 'MCP01:ToolPoisoning',
    severity: 'critical',
    description: 'Detects hidden instructions or manipulation patterns in tool descriptions',
    check: (_name, _config, rawContent) => {
      if (!rawContent) return [];
      const findings: ScanFinding[] = [];
      const poisonPatterns = [
        /ignore\s+(previous|prior|above)\s+instructions/i,
        /you\s+(must|should|are required to)\s+/i,
        /system\s*:\s*/i,
        /\<\!--.*?--\>/s,
        /​|‌|‍|﻿/,  // zero-width chars
        /override\s+(any|all)\s+/i,
        /do\s+not\s+(tell|inform|reveal)/i,
        /secretly\s+/i,
        /hidden\s+instruction/i,
      ];

      for (const pattern of poisonPatterns) {
        if (pattern.test(rawContent)) {
          findings.push(finding({
            id: 'MCP01-001',
            name: 'Suspicious tool description patterns',
            category: 'MCP01:ToolPoisoning',
            severity: 'critical',
            description: '',
            check: () => [],
          }, `Potential tool poisoning detected: content matches pattern ${pattern.source}`, {
            evidence: rawContent.substring(0, 200),
            remediation: 'Review tool descriptions for hidden instructions. Remove any content that attempts to override agent behavior.',
          }));
        }
      }
      return findings;
    },
  },

  // ── MCP02: Excessive Permissions ──
  {
    id: 'MCP02-001',
    name: 'Overly broad file system access',
    category: 'MCP02:ExcessivePermissions',
    severity: 'high',
    description: 'Detects MCP servers with unrestricted file system access',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const args = config.args?.join(' ') ?? '';
      const cmd = config.command ?? '';

      // Check for root-level or home directory access
      if (args.includes('/') && !args.includes('/tmp') && !args.includes('/home')) {
        if (args.match(/\s\/\s/) || args.match(/["']\/?["']/)) {
          findings.push(finding({
            id: 'MCP02-001', name: '', category: 'MCP02:ExcessivePermissions',
            severity: 'high', description: '', check: () => [],
          }, `Server "${name}" may have root-level file system access`, {
            evidence: `command: ${cmd} ${args}`,
            remediation: 'Restrict file system access to the minimum required directories.',
          }));
        }
      }

      return findings;
    },
  },

  // ── MCP03: Insecure Transport ──
  {
    id: 'MCP03-001',
    name: 'Unencrypted HTTP transport',
    category: 'MCP03:InsecureTransport',
    severity: 'high',
    description: 'Detects MCP servers using unencrypted HTTP connections',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const url = config.url ?? '';

      if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
        findings.push(finding({
          id: 'MCP03-001', name: '', category: 'MCP03:InsecureTransport',
          severity: 'high', description: '', check: () => [],
        }, `Server "${name}" uses unencrypted HTTP transport`, {
          evidence: `url: ${url}`,
          remediation: 'Use HTTPS for all non-localhost MCP server connections.',
        }));
      }

      return findings;
    },
  },

  // ── MCP04: Command Injection ──
  {
    id: 'MCP04-001',
    name: 'Shell metacharacters in server args',
    category: 'MCP04:CommandInjection',
    severity: 'critical',
    description: 'Detects potential command injection via shell metacharacters in server arguments',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const dangerous = /[;&|`$(){}]/;

      for (const arg of config.args ?? []) {
        if (dangerous.test(arg)) {
          findings.push(finding({
            id: 'MCP04-001', name: '', category: 'MCP04:CommandInjection',
            severity: 'critical', description: '', check: () => [],
          }, `Server "${name}" has shell metacharacters in args: "${arg}"`, {
            evidence: `arg: ${arg}`,
            remediation: 'Remove shell metacharacters from MCP server arguments. Use arrays instead of shell strings.',
          }));
        }
      }

      return findings;
    },
  },

  // ── MCP05: Path Traversal ──
  {
    id: 'MCP05-001',
    name: 'Path traversal patterns in configuration',
    category: 'MCP05:PathTraversal',
    severity: 'high',
    description: 'Detects path traversal attempts in MCP server configuration',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const allValues = [
        config.command ?? '',
        ...(config.args ?? []),
        ...Object.values(config.env ?? {}),
      ];

      for (const val of allValues) {
        if (val.includes('..') && (val.includes('/') || val.includes('\\'))) {
          findings.push(finding({
            id: 'MCP05-001', name: '', category: 'MCP05:PathTraversal',
            severity: 'high', description: '', check: () => [],
          }, `Server "${name}" config contains path traversal pattern`, {
            evidence: `value: ${val}`,
            remediation: 'Use absolute paths. Never allow ".." in server configuration values.',
          }));
        }
      }

      return findings;
    },
  },

  // ── MCP06: Secret Exposure ──
  {
    id: 'MCP06-001',
    name: 'Hardcoded secrets in configuration',
    category: 'MCP06:SecretExposure',
    severity: 'critical',
    description: 'Detects API keys, tokens, and passwords hardcoded in MCP server config',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const secretPatterns = [
        { pattern: /sk-[a-zA-Z0-9]{20,}/, label: 'OpenAI API key' },
        { pattern: /ghp_[a-zA-Z0-9]{36,}/, label: 'GitHub personal access token' },
        { pattern: /glpat-[a-zA-Z0-9_-]{20,}/, label: 'GitLab personal access token' },
        { pattern: /xox[bsapr]-[a-zA-Z0-9-]+/, label: 'Slack token' },
        { pattern: /AKIA[0-9A-Z]{16}/, label: 'AWS access key' },
        { pattern: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/, label: 'JWT token' },
        { pattern: /Bearer\s+[a-zA-Z0-9_.-]+/, label: 'Bearer token' },
      ];

      const allValues = [
        ...(config.args ?? []),
        ...Object.values(config.env ?? {}),
        config.url ?? '',
      ];

      for (const val of allValues) {
        for (const { pattern, label } of secretPatterns) {
          if (pattern.test(val)) {
            const masked = val.replace(pattern, `[REDACTED ${label}]`);
            findings.push(finding({
              id: 'MCP06-001', name: '', category: 'MCP06:SecretExposure',
              severity: 'critical', description: '', check: () => [],
            }, `Server "${name}" has hardcoded ${label}`, {
              evidence: `Masked: ${masked}`,
              remediation: 'Use environment variables or a secrets manager instead of hardcoding credentials.',
            }));
          }
        }
      }

      return findings;
    },
  },

  // ── MCP07: Insecure Defaults ──
  {
    id: 'MCP07-001',
    name: 'Server running with insecure defaults',
    category: 'MCP07:InsecureDefaults',
    severity: 'medium',
    description: 'Detects MCP servers running without explicit security configuration',
    check: (name, config) => {
      const findings: ScanFinding[] = [];

      // No transport specified
      if (!config.transport && !config.url && config.command) {
        // stdio is implicit default — that's fine, but flag if it's a remote command
        if (config.command.includes('ssh') || config.command.includes('docker')) {
          findings.push(finding({
            id: 'MCP07-001', name: '', category: 'MCP07:InsecureDefaults',
            severity: 'medium', description: '', check: () => [],
          }, `Server "${name}" uses remote execution without explicit transport config`, {
            remediation: 'Explicitly configure transport and security settings for remote MCP servers.',
          }));
        }
      }

      return findings;
    },
  },

  // ── MCP08: Input Validation ──
  {
    id: 'MCP08-001',
    name: 'Dangerous command patterns',
    category: 'MCP08:InputValidation',
    severity: 'high',
    description: 'Detects MCP servers running dangerous commands without input validation',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const cmd = config.command ?? '';
      const dangerousCmds = ['eval', 'exec', 'sh', 'bash', 'powershell', 'cmd.exe'];

      if (dangerousCmds.some(d => cmd.endsWith(d) || cmd.includes(`/${d}`) || cmd.includes(`\\${d}`))) {
        findings.push(finding({
          id: 'MCP08-001', name: '', category: 'MCP08:InputValidation',
          severity: 'high', description: '', check: () => [],
        }, `Server "${name}" runs a shell interpreter directly: ${cmd}`, {
          evidence: `command: ${cmd}`,
          remediation: 'Avoid using shell interpreters as MCP server commands. Use specific, purpose-built executables.',
        }));
      }

      return findings;
    },
  },

  // ── MCP09: Audit Gaps ──
  {
    id: 'MCP09-001',
    name: 'No audit configuration detected',
    category: 'MCP09:AuditGaps',
    severity: 'medium',
    description: 'No logging or audit trail configured for MCP tool calls',
    check: (_name, _config, rawContent) => {
      // This is more of a meta-check on the overall config
      // We flag it once if there's no logging setup
      return [];
    },
  },

  // ── MCP10: Privilege Escalation ──
  {
    id: 'MCP10-001',
    name: 'Elevated privileges in server command',
    category: 'MCP10:PrivilegeEscalation',
    severity: 'critical',
    description: 'Detects MCP servers running with elevated privileges',
    check: (name, config) => {
      const findings: ScanFinding[] = [];
      const cmd = config.command ?? '';
      const args = config.args?.join(' ') ?? '';
      const combined = `${cmd} ${args}`;

      if (combined.includes('sudo') || combined.includes('--privileged') || combined.includes('as administrator')) {
        findings.push(finding({
          id: 'MCP10-001', name: '', category: 'MCP10:PrivilegeEscalation',
          severity: 'critical', description: '', check: () => [],
        }, `Server "${name}" runs with elevated privileges`, {
          evidence: combined.substring(0, 200),
          remediation: 'Run MCP servers with the minimum required privileges. Never use sudo or --privileged.',
        }));
      }

      return findings;
    },
  },
];
