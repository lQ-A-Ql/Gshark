import { useCallback, useEffect, useRef } from "react";
import { PRELOAD_BUDGET } from "./preloadBudget";
import { preloadRouteModule } from "./routePreload";

export function useRoutePreloadIntent() {
  const timersRef = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  const cancelRoutePreloadIntent = useCallback((routePath: string) => {
    const timer = timersRef.current.get(routePath);
    if (timer) {
      clearTimeout(timer);
      timersRef.current.delete(routePath);
    }
  }, []);

  const scheduleRoutePreloadIntent = useCallback((routePath: string, delayMs = PRELOAD_BUDGET.hoverIntentDelayMs) => {
    cancelRoutePreloadIntent(routePath);
    const timer = setTimeout(() => {
      timersRef.current.delete(routePath);
      void preloadRouteModule(routePath, "hover");
    }, delayMs);
    timersRef.current.set(routePath, timer);
  }, [cancelRoutePreloadIntent]);

  const preloadRouteOnFocus = useCallback((routePath: string) => {
    cancelRoutePreloadIntent(routePath);
    void preloadRouteModule(routePath, "focus");
  }, [cancelRoutePreloadIntent]);

  useEffect(() => {
    return () => {
      for (const timer of timersRef.current.values()) {
        clearTimeout(timer);
      }
      timersRef.current.clear();
    };
  }, []);

  return {
    scheduleRoutePreloadIntent,
    cancelRoutePreloadIntent,
    preloadRouteOnFocus,
  };
}
