export function calculatePageBounds(totalItems, pageSize, currentPage) {
  if (pageSize <= 0 || currentPage <= 0) {
    throw new Error('Page size and current page must be positive');
  }
  const totalPages = Math.ceil(totalItems / pageSize);
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, totalItems);
  return {
    totalPages,
    startIndex,
    endIndex,
    hasNext: currentPage < totalPages,
    hasPrev: currentPage > 1,
  };
}
