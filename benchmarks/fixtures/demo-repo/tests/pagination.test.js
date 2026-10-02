import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { calculatePageBounds } from '../src/pagination.js';

describe('Pagination Logic', () => {
  it('calculates page bounds correctly', () => {
    const page1 = calculatePageBounds(25, 10, 1);
    assert.equal(page1.totalPages, 3);
    assert.equal(page1.startIndex, 0);
    assert.equal(page1.endIndex, 10);
    assert.equal(page1.hasNext, true);
    assert.equal(page1.hasPrev, false);

    const page3 = calculatePageBounds(25, 10, 3);
    assert.equal(page3.startIndex, 20);
    assert.equal(page3.endIndex, 25);
    assert.equal(page3.hasNext, false);
    assert.equal(page3.hasPrev, true);
  });
});
