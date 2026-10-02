import crypto from 'node:crypto';

export function computeSha256(content) {
  if (typeof content !== 'string' && !Buffer.isBuffer(content)) {
    throw new TypeError('Content must be string or Buffer');
  }
  return crypto.createHash('sha256').update(content).digest('hex');
}

export function verifyChecksum(content, expectedHash) {
  const actualHash = computeSha256(content);
  return actualHash.toLowerCase() === expectedHash.trim().toLowerCase();
}
