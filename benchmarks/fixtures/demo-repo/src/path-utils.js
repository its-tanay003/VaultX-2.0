import path from 'node:path';

export function sanitizeRelativePath(baseDir, userPath) {
  if (typeof baseDir !== 'string' || typeof userPath !== 'string') {
    throw new TypeError('baseDir and userPath must be strings');
  }
  const resolvedBase = path.resolve(baseDir);
  const resolvedTarget = path.resolve(resolvedBase, userPath);
  
  // Guard against path traversal escaping root boundary
  if (!resolvedTarget.startsWith(resolvedBase + path.sep) && resolvedTarget !== resolvedBase) {
    throw new Error('PATH_TRAVERSAL_DETECTED');
  }
  return resolvedTarget;
}
