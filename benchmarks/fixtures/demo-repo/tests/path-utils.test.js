import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { sanitizeRelativePath } from '../src/path-utils.js';

describe('Path Sanitization', () => {
  const base = path.resolve('/mock/project/root');

  it('allows valid relative file paths', () => {
    const res = sanitizeRelativePath(base, 'src/index.js');
    assert.equal(res, path.resolve(base, 'src/index.js'));
  });

  it('blocks directory traversal escape attempts', () => {
    assert.throws(
      () => sanitizeRelativePath(base, '../../etc/passwd'),
      /PATH_TRAVERSAL_DETECTED/
    );
  });
});
