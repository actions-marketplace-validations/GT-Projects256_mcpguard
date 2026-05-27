/**
 * Core types for mcpguard
 */

// ── Severity levels for findings ──
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ── OWASP MCP Top 10 categories ──
export type OwaspCategory =
  | 'MCP01:ToolPoisoning'
  | 'MCP02:ExcessivePermissions'
  | 'MCP03:InsecureTransport'
  | 'MCP04:CommandInjection'
  | 'MCP05:PathTraversal'
  | 'MCP06:SecretExposure'
  | 'MCP07:InsecureDefaults'
  | 'MCP08:InputValidation'
  | 'MCP09:AuditGaps'
  | 'MCP10:PrivilegeEscalation';

// ── Scanner types ──
export interface ScanFinding {
  id: string;
  rule: string;
  severity: Severity;
  category: OwaspCategory;
  message: string;
  file?: string;
  line?: number;
  evidence?: string;
  remediation?: string;
}

export interface ScanResult {
  target: string;
  timestamp: string;
  duration: number;
  findings: ScanFinding[];
  summary: ScanSummary;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  passed: number;
  failed: number;
}

// ── Policy types ──
export interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  action: 'allow' | 'deny' | 'audit';
  priority: number;
  conditions: PolicyCondition[];
}

export interface PolicyCondition {
  field: 'tool.name' | 'tool.description' | 'param.name' | 'param.value' | 'server.name' | 'server.url';
  operator: 'equals' | 'contains' | 'matches' | 'startsWith' | 'endsWith' | 'in';
  value: string | string[];
  negate?: boolean;
}

export interface Policy {
  version: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
}

export interface PolicyDecision {
  allowed: boolean;
  action: 'allow' | 'deny' | 'audit';
  matchedRule?: PolicyRule;
  reason: string;
  timestamp: string;
}

// ── Proxy/Firewall types ──
export interface ToolCallEvent {
  id: string;
  timestamp: string;
  server: string;
  tool: string;
  params: Record<string, unknown>;
  decision?: PolicyDecision;
  response?: ToolCallResponse;
  duration?: number;
}

export interface ToolCallResponse {
  success: boolean;
  content?: unknown;
  error?: string;
  poisoningDetected?: boolean;
  poisoningDetails?: string;
}

// ── Audit types ──
export interface AuditEntry {
  id: string;
  timestamp: string;
  event: 'tool_call' | 'policy_decision' | 'poisoning_detected' | 'scan_complete' | 'proxy_start' | 'proxy_stop';
  severity: Severity;
  details: Record<string, unknown>;
}

// ── Config types ──
export interface McpGuardConfig {
  policies?: string[];
  audit?: {
    enabled: boolean;
    output: 'stdout' | 'file' | 'both';
    file?: string;
    format: 'json' | 'ndjson';
  };
  proxy?: {
    host: string;
    port: number;
    upstream?: string;
  };
  scanner?: {
    rules?: string[];
    exclude?: string[];
    severity?: Severity;
  };
}

// ── MCP Server Config (what we scan) ──
export interface McpServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  transport?: 'stdio' | 'sse' | 'streamable-http';
}

export interface McpConfigFile {
  mcpServers?: Record<string, McpServerConfig>;
}
