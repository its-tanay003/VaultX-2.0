export function applyDiscount(subtotal, discountPercent) {
  if (typeof subtotal !== 'number' || typeof discountPercent !== 'number') {
    throw new TypeError('Subtotal and discountPercent must be numbers');
  }
  if (discountPercent < 0 || discountPercent > 100) {
    throw new RangeError('Discount percentage must be between 0 and 100');
  }
  const discountAmount = (subtotal * discountPercent) / 100;
  return Math.round((subtotal - discountAmount) * 100) / 100;
}
