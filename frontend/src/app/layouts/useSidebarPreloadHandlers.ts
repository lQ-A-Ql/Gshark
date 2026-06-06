import { useCallback } from "react";
import { useRouteHeavyWarmupIntent } from "../preload/useRouteHeavyWarmupIntent";
import { useRoutePreloadIntent } from "../preload/useRoutePreloadIntent";

export function useSidebarPreloadHandlers(pathname: string) {
  const route = useRoutePreloadIntent();
  const heavy = useRouteHeavyWarmupIntent(pathname);

  const onEnter = useCallback((path: string) => {
    route.scheduleRoutePreloadIntent(path);
    heavy.scheduleHeavyWarmupIntent(path);
  }, [heavy, route]);

  const onLeave = useCallback((path: string) => {
    route.cancelRoutePreloadIntent(path);
    heavy.cancelHeavyWarmupIntent();
  }, [heavy, route]);

  return {
    onEnter,
    onLeave,
    onFocus: route.preloadRouteOnFocus,
  };
}
