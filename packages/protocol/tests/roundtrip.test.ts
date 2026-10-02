import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  ActionRequest,
  AgentRun,
  Approval,
  AuditEvent,
  Checkpoint,
  Decision,
  Evidence,
  Finding,
  ProtocolEnvelope,
  ProtocolError,
  ProtocolEvent,
  SecurityScope,
  ToolPassport,
  VerificationResult,
} from '../src/generated/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FIXTURES_DIR = path.resolve(__dirname, '../../test-fixtures/protocol/valid');

describe('TypeScript Protocol Serialization Round-Trip', () => {
  it('round-trips AgentRun', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'agent_run.json'), 'utf-8')) as AgentRun;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as AgentRun;
    expect(deserialized).toEqual(raw);
    expect(deserialized.status).toBe('RUNNING');
  });

  it('round-trips ActionRequest', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'action_request.json'), 'utf-8')) as ActionRequest;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as ActionRequest;
    expect(deserialized).toEqual(raw);
    expect(deserialized.capability).toBe('project.write');
  });

  it('round-trips Decision', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'decision_allow.json'), 'utf-8')) as Decision;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as Decision;
    expect(deserialized).toEqual(raw);
    expect(deserialized.effect).toBe('ALLOW');
  });

  it('round-trips Approval', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'approval.json'), 'utf-8')) as Approval;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as Approval;
    expect(deserialized).toEqual(raw);
    expect(deserialized.approver_role).toBe('Security Admin');
  });

  it('round-trips SecurityScope', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'security_scope.json'), 'utf-8')) as SecurityScope;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as SecurityScope;
    expect(deserialized).toEqual(raw);
    expect(deserialized.max_depth).toBe(3);
  });

  it('round-trips ToolPassport', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'tool_passport.json'), 'utf-8')) as ToolPassport;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as ToolPassport;
    expect(deserialized).toEqual(raw);
    expect(deserialized.capabilities).toContain('cyber.scan');
  });

  it('round-trips VerificationResult', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'verification_result.json'), 'utf-8')) as VerificationResult;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as VerificationResult;
    expect(deserialized).toEqual(raw);
    expect(deserialized.status).toBe('PASSED');
  });

  it('round-trips Evidence', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'evidence.json'), 'utf-8')) as Evidence;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as Evidence;
    expect(deserialized).toEqual(raw);
  });

  it('round-trips AuditEvent', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'audit_event.json'), 'utf-8')) as AuditEvent;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as AuditEvent;
    expect(deserialized).toEqual(raw);
  });

  it('round-trips Checkpoint', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'checkpoint.json'), 'utf-8')) as Checkpoint;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as Checkpoint;
    expect(deserialized).toEqual(raw);
    expect(deserialized.rollback_point).toBe(true);
  });

  it('round-trips Finding', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'finding.json'), 'utf-8')) as Finding;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as Finding;
    expect(deserialized).toEqual(raw);
    expect(deserialized.severity).toBe('CRITICAL');
  });

  it('round-trips ProtocolError', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'error_policy_denied.json'), 'utf-8')) as ProtocolError;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as ProtocolError;
    expect(deserialized).toEqual(raw);
    expect(deserialized.code).toBe('POLICY_DENIED');
  });

  it('round-trips ProtocolEvent', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'protocol_event.json'), 'utf-8')) as ProtocolEvent;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as ProtocolEvent;
    expect(deserialized).toEqual(raw);
    expect(deserialized.type).toBe('ToolStarted');
  });

  it('round-trips ProtocolEnvelope', () => {
    const raw = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, 'protocol_envelope.json'), 'utf-8')) as ProtocolEnvelope;
    const serialized = JSON.stringify(raw);
    const deserialized = JSON.parse(serialized) as ProtocolEnvelope;
    expect(deserialized).toEqual(raw);
    expect(deserialized.protocol_version).toBe('1.0.0');
    expect(deserialized.negotiation?.status).toBe('ACCEPTED');
  });
});
