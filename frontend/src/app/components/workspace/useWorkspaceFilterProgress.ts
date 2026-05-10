import { useEffect, useState } from "react";

export function useWorkspaceFilterProgress(isFilterLoading: boolean, isPreloadingCapture: boolean) {
  const [filterLoadingProgress, setFilterLoadingProgress] = useState(18);

  useEffect(() => {
    if (!isFilterLoading || isPreloadingCapture) {
      setFilterLoadingProgress(12);
      return;
    }
    setFilterLoadingProgress(18);
    const timer = window.setInterval(() => {
      setFilterLoadingProgress((prev) => {
        if (prev >= 92) return 92;
        const step = Math.max(1, Math.round((96 - prev) * 0.18));
        return Math.min(92, prev + step);
      });
    }, 180);
    return () => window.clearInterval(timer);
  }, [isFilterLoading, isPreloadingCapture]);

  return filterLoadingProgress;
}
