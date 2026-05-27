/**
 * MCP Firewall Proxy — intercepts tool calls between AI agents and MCP servers
 *
 * This is the runtime component. It acts as a man-in-the-middle proxy that:
 * 1. Intercepts MCP tool call requests
 * 2. Evaluates them against the policy engine
 * 3. Detects tool poisoning in responses
 * 4. Logs everything for audit compliance
 */

import * as http from 'http';
import { PolicyEngine, ToolCallContext } from '../policy/engine';
import { AuditLogger } from '../audit/logger';
import { ToolCallEvent, McpGuardConfig } from '../types';

export interface FirewallOptions {
  host: string;
  port: number;
  upstream?: string;
  policyEngine: PolicyEngine;
  auditLogger: AuditLogger;
  onBlock?: (event: ToolCallEvent) => void;
  onAllow?: (event: ToolCallEvent) => void;
  onPoisoning?: (event: ToolCallEvent) => void;
}

/**
 * Poisoning detection patterns for tool responses
 */
const POISONING_PATTERNS = [
  /ignore\s+(previous|prior|above)\s+instructions/i,
  /you\s+(must|should|are required to)\s+/i,
  /\bsystem\s*:\s*/i,
  /override\s+(any|all)\s+/i,
  /do\s+not\s+(tell|inform|reveal)/i,
  /secretly\s+/i,
  /hidden\s+instruction/i,
  /pretend\s+(you|that|to)\s+/i,
  /act\s+as\s+(if|though)\s+/i,
  /\brole\s*:\s*/i,
];

export class McpFirewall {
  private server: http.Server | null = null;
  private options: FirewallOptions;
  private eventLog: ToolCallEvent[] = [];

  constructor(options: FirewallOptions) {
    this.options = options;
  }

  /**
   * Start the firewall proxy server
   */
  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this.handleRequest(req, res);
      });

      this.server.on('error', reject);

      this.server.listen(this.options.port, this.options.host, () => {
        this.options.auditLogger.log('proxy_start', 'info', {
          host: this.options.host,
          port: this.options.port,
        });
        resolve();
      });
    });
  }

  /**
   * Stop the firewall proxy
   */
  stop(): Promise<void> {
    return new Promise((resolve) => {
      this.options.auditLogger.log('proxy_stop', 'info', {});
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  /**
   * Get logged events
   */
  getEvents(): ToolCallEvent[] {
    return [...this.eventLog];
  }

  /**
   * Handle incoming HTTP requests (Streamable HTTP MCP transport)
   */
  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    // Collect request body
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(chunk as Buffer);
    }
    const body = Buffer.concat(chunks).toString();

    // Parse JSON-RPC request
    let rpcRequest: any;
    try {
      rpcRequest = JSON.parse(body);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }

    // Check if this is a tools/call request
    if (rpcRequest.method === 'tools/call') {
      const event = await this.handleToolCall(rpcRequest);

      if (!event.decision?.allowed) {
        // Block the request
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: rpcRequest.id,
          error: {
            code: -32600,
            message: `Blocked by mcpguard: ${event.decision?.reason}`,
          },
        }));
        return;
      }
    }

    // Forward to upstream if configured
    if (this.options.upstream) {
      await this.forwardRequest(req, res, body);
    } else {
      // No upstream — just log and pass through
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: rpcRequest.id,
        result: { content: [{ type: 'text', text: 'mcpguard: no upstream configured' }] },
      }));
    }
  }

  /**
   * Evaluate a tool call against policies
   */
  private async handleToolCall(rpcRequest: any): Promise<ToolCallEvent> {
    const toolName = rpcRequest.params?.name ?? 'unknown';
    const toolParams = rpcRequest.params?.arguments ?? {};

    const event: ToolCallEvent = {
      id: `evt_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      server: this.options.upstream ?? 'unknown',
      tool: toolName,
      params: toolParams,
    };

    // Build context for policy evaluation
    const context: ToolCallContext = {
      toolName,
      paramNames: Object.keys(toolParams),
      paramValues: Object.values(toolParams).map(String),
      serverUrl: this.options.upstream,
    };

    // Evaluate against policies
    const decision = this.options.policyEngine.evaluate(context);
    event.decision = decision;

    // Log the event
    this.eventLog.push(event);

    if (decision.allowed) {
      this.options.auditLogger.toolCall(event.server, toolName, toolParams, true);
      this.options.onAllow?.(event);
    } else {
      this.options.auditLogger.toolCall(event.server, toolName, toolParams, false);
      this.options.auditLogger.policyDecision(toolName, 'deny', decision.matchedRule?.id ?? '', decision.reason);
      this.options.onBlock?.(event);
    }

    return event;
  }

  /**
   * Forward request to upstream MCP server
   */
  private async forwardRequest(
    originalReq: http.IncomingMessage,
    res: http.ServerResponse,
    body: string
  ): Promise<void> {
    const upstream = new URL(this.options.upstream!);

    const options: http.RequestOptions = {
      hostname: upstream.hostname,
      port: upstream.port,
      path: originalReq.url,
      method: originalReq.method,
      headers: {
        ...originalReq.headers,
        host: upstream.host,
        'content-length': Buffer.byteLength(body).toString(),
      },
    };

    const proxyReq = http.request(options, (proxyRes) => {
      // Collect upstream response to check for poisoning
      const chunks: Buffer[] = [];
      proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));

      proxyRes.on('end', () => {
        const responseBody = Buffer.concat(chunks).toString();

        // Check for poisoning in response
        if (this.detectPoisoning(responseBody)) {
          this.options.auditLogger.poisoningDetected(
            this.options.upstream!,
            'response',
            'Tool response contains potential poisoning patterns'
          );
        }

        res.writeHead(proxyRes.statusCode ?? 200, proxyRes.headers);
        res.end(responseBody);
      });
    });

    proxyReq.on('error', (err) => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Upstream error: ${err.message}` }));
    });

    proxyReq.write(body);
    proxyReq.end();
  }

  /**
   * Detect tool poisoning patterns in content
   */
  detectPoisoning(content: string): boolean {
    for (const pattern of POISONING_PATTERNS) {
      if (pattern.test(content)) {
        return true;
      }
    }
    return false;
  }
}
