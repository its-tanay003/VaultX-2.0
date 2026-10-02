export function findUserByEmail(users, email) {
  if (!users || !Array.isArray(users)) {
    return null;
  }
  if (!email || typeof email !== 'string') {
    return null;
  }
  const normalized = email.trim().toLowerCase();
  const found = users.find((u) => u && u.email && u.email.trim().toLowerCase() === normalized);
  return found ?? null;
}
