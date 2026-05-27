/**
 * CLI formatting helpers
 */

import { Severity } from '../types';

// Simple colorize without requiring chalk (keeps zero-dep for CLI)
const COLORS: Record<string, string> = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  reset: '\x1b[0m',
};

export function colorize(color: string, text: string): string {
  if (!process.stdout.isTTY) return text;
  return `${COLORS[color] ?? ''}${text}${COLORS.reset}`;
}

export function formatSeverity(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return colorize('red', '● CRITICAL');
    case 'high':
      return colorize('yellow', '● HIGH');
    case 'medium':
      return colorize('blue', '● MEDIUM');
    case 'low':
      return '● LOW';
    case 'info':
      return colorize('dim', '● INFO');
  }
}

export function formatCategory(category: string): string {
  return colorize('bold', `[${category}]`);
}
