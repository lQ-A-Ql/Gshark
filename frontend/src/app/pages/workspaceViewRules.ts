export function getWorkspacePreloadPercent(preloadProcessed: number, preloadTotal: number): number {
  if (preloadTotal <= 0) return 0;
  return Math.max(0, Math.min(100, Math.floor((preloadProcessed / preloadTotal) * 100)));
}

export function getWorkspacePagerItems(currentPage: number, totalPages: number): number[] {
  const pages = new Set<number>([1, totalPages, currentPage - 1, currentPage, currentPage + 1]);
  return Array.from(pages)
    .filter((page) => page >= 1 && page <= totalPages)
    .sort((a, b) => a - b);
}

export function shouldShowWorkspaceFilterLoadingBlankState(
  filteredPacketCount: number,
  isFilterLoading: boolean,
  isPreloadingCapture: boolean,
): boolean {
  return isFilterLoading && !isPreloadingCapture && filteredPacketCount === 0;
}
