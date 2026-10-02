import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { findUserByEmail } from '../src/user.js';

describe('User Lookup', () => {
  const users = [
    { id: '1', name: 'Alice', email: 'alice@example.com' },
    { id: '2', name: 'Bob', email: 'bob@example.com' },
  ];

  it('finds existing user case-insensitively', () => {
    const user = findUserByEmail(users, 'ALICE@EXAMPLE.COM');
    assert.ok(user);
    assert.equal(user.id, '1');
  });

  it('handles null and missing user cleanly', () => {
    assert.equal(findUserByEmail(users, 'nonexistent@example.com'), null);
    assert.equal(findUserByEmail(null, 'alice@example.com'), null);
    assert.equal(findUserByEmail(users, null), null);
  });
});
