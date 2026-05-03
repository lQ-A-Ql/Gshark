import { useCallback, useState } from "react";
import {
  DEFAULT_FLOATING_MARGIN,
  getPointerFloatingPosition,
  type FloatingSize,
  type Point,
  type ViewportSize,
} from "../utils/viewportPosition";

export type ViewportSafePositionOptions = {
  floating: FloatingSize;
  margin?: number;
  viewport?: ViewportSize;
};

export type ViewportSafePositionState<TContext = unknown> = Point & {
  context: TContext;
};

export function useViewportSafePosition<TContext = unknown>({
  floating,
  margin = DEFAULT_FLOATING_MARGIN,
  viewport,
}: ViewportSafePositionOptions) {
  const [position, setPosition] = useState<ViewportSafePositionState<TContext> | null>(null);

  const openAtPoint = useCallback(
    (point: Point, context: TContext) => {
      setPosition({
        ...getPointerFloatingPosition(point.x, point.y, floating, { margin, viewport }),
        context,
      });
    },
    [floating, margin, viewport],
  );

  const openAtEvent = useCallback(
    (event: Pick<MouseEvent, "clientX" | "clientY">, context: TContext) => {
      openAtPoint({ x: event.clientX, y: event.clientY }, context);
    },
    [openAtPoint],
  );

  const close = useCallback(() => {
    setPosition(null);
  }, []);

  return {
    position,
    openAtPoint,
    openAtEvent,
    close,
    isOpen: position !== null,
  };
}
