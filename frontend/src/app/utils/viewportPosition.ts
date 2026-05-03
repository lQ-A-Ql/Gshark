export type Point = {
  x: number;
  y: number;
};

export type FloatingSize = {
  width: number;
  height: number;
};

export type ViewportSize = FloatingSize;

export type FloatingPositionOptions = {
  viewport?: ViewportSize;
  margin?: number;
};

const DEFAULT_VIEWPORT: ViewportSize = {
  width: 1024,
  height: 768,
};

export const DEFAULT_FLOATING_MARGIN = 12;

export function getViewportSize(): ViewportSize {
  if (typeof window === "undefined") {
    return DEFAULT_VIEWPORT;
  }

  return {
    width: window.innerWidth,
    height: window.innerHeight,
  };
}

function normalizePositive(value: number, fallback: number): number {
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

export function clampFloatingPoint(
  point: Point,
  floating: FloatingSize,
  viewport: ViewportSize = getViewportSize(),
  margin = DEFAULT_FLOATING_MARGIN,
): Point {
  const safeMargin = Math.max(0, Number.isFinite(margin) ? margin : DEFAULT_FLOATING_MARGIN);
  const safeFloating = {
    width: normalizePositive(floating.width, 1),
    height: normalizePositive(floating.height, 1),
  };
  const safeViewport = {
    width: normalizePositive(viewport.width, safeFloating.width + safeMargin * 2),
    height: normalizePositive(viewport.height, safeFloating.height + safeMargin * 2),
  };

  const maxX = Math.max(safeMargin, safeViewport.width - safeFloating.width - safeMargin);
  const maxY = Math.max(safeMargin, safeViewport.height - safeFloating.height - safeMargin);

  return {
    x: Math.min(Math.max(point.x, safeMargin), maxX),
    y: Math.min(Math.max(point.y, safeMargin), maxY),
  };
}

export function getPointerFloatingPosition(
  clientX: number,
  clientY: number,
  floating: FloatingSize,
  options: FloatingPositionOptions = {},
): Point {
  return clampFloatingPoint(
    { x: clientX, y: clientY },
    floating,
    options.viewport ?? getViewportSize(),
    options.margin ?? DEFAULT_FLOATING_MARGIN,
  );
}
