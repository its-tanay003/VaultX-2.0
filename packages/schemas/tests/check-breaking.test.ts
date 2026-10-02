import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { compareSchemas } from '../scripts/check-breaking.ts';

describe('Schema Breaking Change Detector', () => {
  it('detects removed property as a breaking change', () => {
    const baseline = {
      type: 'object',
      properties: {
        id: { type: 'string' },
        name: { type: 'string' },
      },
    };
    const current = {
      type: 'object',
      properties: {
        id: { type: 'string' },
      },
    };

    const diffs = compareSchemas(baseline, current, 'test.json');
    assert.equal(diffs.length, 1);
    assert.equal(diffs[0]?.kind, 'REMOVED_PROPERTY');
    assert.match(diffs[0]?.message ?? '', /Property 'name' was removed/);
  });

  it('detects newly added required property as a breaking change', () => {
    const baseline = {
      type: 'object',
      properties: {
        id: { type: 'string' },
      },
      required: ['id'],
    };
    const current = {
      type: 'object',
      properties: {
        id: { type: 'string' },
        new_field: { type: 'string' },
      },
      required: ['id', 'new_field'],
    };

    const diffs = compareSchemas(baseline, current, 'test.json');
    assert.equal(diffs.length, 1);
    assert.equal(diffs[0]?.kind, 'ADDED_REQUIRED_PROPERTY');
    assert.match(diffs[0]?.message ?? '', /New required property 'new_field'/);
  });

  it('detects removed enum variant as a breaking change', () => {
    const baseline = {
      type: 'string',
      enum: ['ALLOW', 'DENY', 'APPROVAL_REQUIRED'],
    };
    const current = {
      type: 'string',
      enum: ['ALLOW', 'DENY'],
    };

    const diffs = compareSchemas(baseline, current, 'test.json');
    assert.equal(diffs.length, 1);
    assert.equal(diffs[0]?.kind, 'REMOVED_ENUM_VARIANT');
    assert.match(diffs[0]?.message ?? '', /Enum variant 'APPROVAL_REQUIRED' was removed/);
  });

  it('detects type mutation as a breaking change', () => {
    const baseline = {
      type: 'string',
    };
    const current = {
      type: 'number',
    };

    const diffs = compareSchemas(baseline, current, 'test.json');
    assert.equal(diffs.length, 1);
    assert.equal(diffs[0]?.kind, 'TYPE_CHANGED');
  });

  it('permits non-breaking additive changes (optional properties and new enum variants)', () => {
    const baseline = {
      type: 'object',
      properties: {
        id: { type: 'string' },
      },
      required: ['id'],
    };
    const current = {
      type: 'object',
      properties: {
        id: { type: 'string' },
        optional_notes: { type: 'string' },
      },
      required: ['id'],
    };

    const diffs = compareSchemas(baseline, current, 'test.json');
    assert.equal(diffs.length, 0);
  });
});
