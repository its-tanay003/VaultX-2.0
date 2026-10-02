import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { computeSha256, verifyChecksum } from '../src/checksum.js';

describe('Checksum Verification', () => {
  it('computes correct sha256 hash', () => {
    const hash = computeSha256('hello world');
    assert.equal(hash, 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
  });

  it('verifies valid checksum', () => {
    assert.equal(
      verifyChecksum('hello world', 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'),
      true
    );
    assert.equal(
      verifyChecksum('hello world', 'wrong_hash'),
      false
    );
  });
});
