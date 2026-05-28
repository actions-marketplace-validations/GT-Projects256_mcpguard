/**
 * Policy engine - evaluates YAML rules against tool calls
 */

import * as fs from 'fs';
import * as yaml from 'js-yaml';
import { Policy, PolicyRule, PolicyCondition, PolicyDecision } from '../types';

export class PolicyEngine {
  private policies: Policy[] = [];
  private rules: PolicyRule[] = [];

  loadFromFile(filePath: string): void {
    const content = fs.readFileSync(filePath, 'utf-8');
    const policy = yaml.load(content) as Policy;
    this.addPolicy(policy);
  }

  addPolicy(policy: Policy): void {
    this.policies.push(policy);
    this.rules = this.getAllRulesSorted();
  }

  evaluate(context: ToolCallContext): PolicyDecision {
    // Default: allow (fail-open by default, users can set default-deny in policy)
    let decision: PolicyDecision = {
      allowed: true,
      action: 'allow',
      reason: 'No matching rule - default allow',
      timestamp: new Date().toISOString(),
    };

    for (const rule of this.rules) {
      if (this.matchesAllConditions(rule.conditions, context)) {
        decision = {
          allowed: rule.action === 'allow',
          action: rule.action,
          matchedRule: rule,
          reason: `Matched rule: ${rule.id} (${rule.name})`,
          timestamp: new Date().toISOString(),
        };

        // If it's a deny, stop immediately (deny takes precedence)
        if (rule.action === 'deny') {
          return decision;
        }

        // If it's an audit, continue but record it
        if (rule.action === 'audit') {
          decision.allowed = true; // audit means allow but log
        }

        // If allow, continue checking for higher-priority denies
      }
    }

    return decision;
  }

  getRules(): PolicyRule[] {
    return [...this.rules];
  }

  getPolicies(): Policy[] {
    return [...this.policies];
  }

  private getAllRulesSorted(): PolicyRule[] {
    const allRules: PolicyRule[] = [];
    for (const policy of this.policies) {
      allRules.push(...policy.rules);
    }
    // Higher priority number = evaluated first
    return allRules.sort((a, b) => b.priority - a.priority);
  }

  private matchesAllConditions(conditions: PolicyCondition[], context: ToolCallContext): boolean {
    return conditions.every((cond) => {
      const result = this.matchCondition(cond, context);
      return cond.negate ? !result : result;
    });
  }

  private matchCondition(condition: PolicyCondition, context: ToolCallContext): boolean {
    const fieldValue = this.resolveField(condition.field, context);
    if (fieldValue === undefined) return false;

    const condValue = condition.value;

    switch (condition.operator) {
      case 'equals':
        return fieldValue === condValue;

      case 'contains':
        return typeof condValue === 'string' && fieldValue.includes(condValue);

      case 'matches':
        try {
          return typeof condValue === 'string' && new RegExp(condValue).test(fieldValue);
        } catch {
          return false;
        }

      case 'startsWith':
        return typeof condValue === 'string' && fieldValue.startsWith(condValue);

      case 'endsWith':
        return typeof condValue === 'string' && fieldValue.endsWith(condValue);

      case 'in':
        return Array.isArray(condValue) && condValue.includes(fieldValue);

      default:
        return false;
    }
  }

  private resolveField(field: PolicyCondition['field'], context: ToolCallContext): string | undefined {
    switch (field) {
      case 'tool.name':
        return context.toolName;
      case 'tool.description':
        return context.toolDescription;
      case 'param.name':
        return context.paramNames?.join(',');
      case 'param.value':
        return context.paramValues?.join(',');
      case 'server.name':
        return context.serverName;
      case 'server.url':
        return context.serverUrl;
      default:
        return undefined;
    }
  }
}

export interface ToolCallContext {
  toolName: string;
  toolDescription?: string;
  paramNames?: string[];
  paramValues?: string[];
  serverName?: string;
  serverUrl?: string;
}
