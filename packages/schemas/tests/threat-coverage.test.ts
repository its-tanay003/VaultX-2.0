import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCRIPT_PATH = path.resolve(__dirname, '../../../scripts/threat-coverage.ts');

describe('Threat Model CI Coverage Script', () => {
  it('executes threat-coverage script and succeeds on current threat model', () => {
    const output = execSync(`node "${SCRIPT_PATH}"`, { encoding: 'utf-8' });
    assert.match(output, /All \d+ threats have valid standards mappings and test coverage/);
  });
});
