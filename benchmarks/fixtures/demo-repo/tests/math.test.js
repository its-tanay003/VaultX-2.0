import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { applyDiscount } from '../src/math.js';

describe('Discount Math', () => {
  it('applies percentage discounts correctly', () => {
    assert.equal(applyDiscount(100, 20), 80);
    assert.equal(applyDiscount(49.99, 10), 44.99);
    assert.equal(applyDiscount(200, 0), 200);
    assert.equal(applyDiscount(200, 100), 0);
  });

  it('rejects invalid percentage ranges', () => {
    assert.throws(() => applyDiscount(100, -5), RangeError);
    assert.throws(() => applyDiscount(100, 150), RangeError);
  });
});
