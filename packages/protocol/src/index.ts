/**
 * @valutx/protocol
 * Defines typed runtime messages, task events, and IPC contracts for VaultX 2.0.
 */

export * from './generated/types.js';
export * from './validator.js';

export const PROTOCOL_VERSION = '1.0.0';

export const CANONICAL_CAPABILITIES = [
  'project.read',
  'project.write',
  'terminal.execute',
  'process.spawn',
  'network.external',
  'network.lab',
  'cyber.scan',
  'cyber.active_scan',
  'secrets.use',
  'plugin.install',
  'policy.edit',
  'audit.export',
  'checkpoint.restore',
  'background_agent',
  'deploy.execute',
] as const;

export const STABLE_ERROR_CODES = [
  'POLICY_DENIED',
  'SCOPE_DENIED',
  'SANDBOX_UNAVAILABLE',
  'TOOL_NOT_FOUND',
  'APPROVAL_REQUIRED',
  'VERIFICATION_FAILED',
  'RESOURCE_LIMIT',
  'PROTOCOL_VIOLATION',
  'INTERNAL_ERROR',
] as const;

export const PROTOCOL_EVENT_TYPES = [
  'RunCreated',
  'PlanCreated',
  'ApprovalRequested',
  'ApprovalGranted',
  'ToolStarted',
  'ToolOutput',
  'PolicyDenied',
  'SandboxStarted',
  'VerificationStarted',
  'VerificationPassed',
  'VerificationFailed',
  'EvidenceCreated',
  'RunCompleted',
  'RunRolledBack',
] as const;
