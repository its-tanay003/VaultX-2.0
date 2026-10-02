import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateSchema } from '../src/validator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FIXTURES_DIR = path.resolve(__dirname, '../../test-fixtures/protocol');

describe('Protocol Schema Validation - Deny Paths', () => {
  it('denies ActionRequest with unauthorized capability', () => {
    const data = JSON.parse(
      fs.readFileSync(path.join(FIXTURES_DIR, 'invalid/invalid_capability.json'), 'utf-8')
    );
    const result = validateSchema('action.json', data);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('must be equal to one of the allowed values'))).toBe(true);
  });

  it('denies SecurityScope with unknown property (additionalProperties: false)', () => {
    const data = JSON.parse(
      fs.readFileSync(path.join(FIXTURES_DIR, 'invalid/unknown_property.json'), 'utf-8')
    );
    const result = validateSchema('security-scope.json', data);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('must NOT have additional properties'))).toBe(true);
  });

  it('denies Approval with invalid action_hash pattern', () => {
    const data = JSON.parse(
      fs.readFileSync(path.join(FIXTURES_DIR, 'invalid/invalid_hash.json'), 'utf-8')
    );
    const result = validateSchema('approval.json', data);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('must match pattern'))).toBe(true);
  });

  it('denies ProtocolError with unrecognized error code', () => {
    const data = JSON.parse(
      fs.readFileSync(path.join(FIXTURES_DIR, 'invalid/unrecognized_error_code.json'), 'utf-8')
    );
    const result = validateSchema('error.json', data);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('must be equal to one of the allowed values'))).toBe(true);
  });
});

describe('Protocol Schema Validation - Allow Paths', () => {
  const schemaMap: Record<string, string> = {
    'agent_run.json': 'agent-run.json',
    'action_request.json': 'action.json',
    'decision_allow.json': 'decision.json',
    'decision_deny.json': 'decision.json',
    'approval.json': 'approval.json',
    'security_scope.json': 'security-scope.json',
    'tool_passport.json': 'tool-passport.json',
    'verification_result.json': 'verification.json',
    'evidence.json': 'evidence.json',
    'audit_event.json': 'audit-event.json',
    'checkpoint.json': 'checkpoint.json',
    'finding.json': 'finding.json',
    'error_policy_denied.json': 'error.json',
    'protocol_event.json': 'events.json',
    'protocol_envelope.json': 'protocol-envelope.json',
  };

  for (const [fixtureFile, schemaName] of Object.entries(schemaMap)) {
    it(`validates ${fixtureFile} against ${schemaName}`, () => {
      const fixturePath = path.join(FIXTURES_DIR, 'valid', fixtureFile);
      expect(fs.existsSync(fixturePath)).toBe(true);
      const data = JSON.parse(fs.readFileSync(fixturePath, 'utf-8'));
      const result = validateSchema(schemaName, data);
      expect(result.errors).toEqual([]);
      expect(result.valid).toBe(true);
    });
  }
});
