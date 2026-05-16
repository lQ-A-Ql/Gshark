import { useEffect, useState } from "react";

export function usePreloadElapsedMs(isPreloading: boolean, captureKey: string): number {
  const [elapsedMs, setElapsedMs] = useState(0);

  useEffect(() => {
    if (!isPreloading) {
      setElapsedMs(0);
      return;
    }
    const startedAt = Date.now();
    setElapsedMs(0);
    const timer = window.setInterval(() => {
      setElapsedMs(Date.now() - startedAt);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [captureKey, isPreloading]);

  return elapsedMs;
}
