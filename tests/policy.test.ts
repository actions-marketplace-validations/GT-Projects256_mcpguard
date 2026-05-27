import { describe, it, expect } from 'vitest';
import { PolicyEngine, ToolCallContext } from '../src/policy/engine';
import { Policy } from '../src/types';

describe('PolicyEngine', () => {
  it('should allow by default when no rules match', () => {
    const engine = new PolicyEngine();
    const decision = engine.evaluate({
      toolName: 'read_file',
      paramNames: ['path'],
      paramValues: ['/home/user/doc.txt'],
    });

    expect(decision.allowed).toBe(true);
    expect(decision.action).toBe('allow');
  });

  it('should deny when a deny rule matches', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      version: '1.0',
      name: 'test-policy',
      rules: [{
        id: 'deny-shell',
        name: 'Block shell exec',
        action: 'deny',
        priority: 100,
        conditions: [{
          field: 'tool.name',
          operator: 'contains',
          value: 'exec',
        }],
      }],
    });

    const decision = engine.evaluate({
      toolName: 'shell_exec',
      paramNames: ['command'],
      paramValues: ['ls -la'],
    });

    expect(decision.allowed).toBe(false);
    expect(decision.action).toBe('deny');
    expect(decision.matchedRule?.id).toBe('deny-shell');
  });

  it('should support regex matching', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      version: '1.0',
      name: 'test-regex',
      rules: [{
        id: 'deny-sensitive',
        name: 'Block sensitive paths',
        action: 'deny',
        priority: 100,
        conditions: [{
          field: 'param.value',
          operator: 'matches',
          value: '(/etc/passwd|/etc/shadow|\\.ssh/)',
        }],
      }],
    });

    const decision = engine.evaluate({
      toolName: 'read_file',
      paramNames: ['path'],
      paramValues: ['/etc/passwd'],
    });

    expect(decision.allowed).toBe(false);
  });

  it('should support negated conditions', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      version: '1.0',
      name: 'test-negate',
      rules: [{
        id: 'deny-non-read',
        name: 'Only allow reads',
        action: 'deny',
        priority: 100,
        conditions: [{
          field: 'tool.name',
          operator: 'startsWith',
          value: 'read',
          negate: true,
        }],
      }],
    });

    // Write should be denied
    const writeDec = engine.evaluate({ toolName: 'write_file' });
    expect(writeDec.allowed).toBe(false);

    // Read should be allowed
    const readDec = engine.evaluate({ toolName: 'read_file' });
    expect(readDec.allowed).toBe(true);
  });

  it('should evaluate rules in priority order', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      version: '1.0',
      name: 'test-priority',
      rules: [
        {
          id: 'allow-all',
          name: 'Allow everything',
          action: 'allow',
          priority: 10,
          conditions: [{ field: 'tool.name', operator: 'matches', value: '.*' }],
        },
        {
          id: 'deny-exec',
          name: 'But deny exec',
          action: 'deny',
          priority: 100,
          conditions: [{ field: 'tool.name', operator: 'contains', value: 'exec' }],
        },
      ],
    });

    // exec should be denied (higher priority rule)
    const execDec = engine.evaluate({ toolName: 'shell_exec' });
    expect(execDec.allowed).toBe(false);

    // read should be allowed
    const readDec = engine.evaluate({ toolName: 'read_file' });
    expect(readDec.allowed).toBe(true);
  });

  it('should handle audit action (allow but flag)', () => {
    const engine = new PolicyEngine();
    engine.addPolicy({
      version: '1.0',
      name: 'test-audit',
      rules: [{
        id: 'audit-writes',
        name: 'Audit all writes',
        action: 'audit',
        priority: 50,
        conditions: [{ field: 'tool.name', operator: 'contains', value: 'write' }],
      }],
    });

    const decision = engine.evaluate({ toolName: 'write_file' });
    expect(decision.allowed).toBe(true);
    expect(decision.action).toBe('audit');
  });
});
