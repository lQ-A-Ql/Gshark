import { useEffect, useMemo, useRef, useState } from "react";
import { AnalysisEmptyState } from "../../components/analysis/AnalysisPrimitives";
import { normalizeTrafficTimelineBuckets, type TrafficTimelineRangeSelection } from "./trafficTimeline";

const DEFAULT_CHART_WIDTH = 640;

export interface TimelinePoint {
  label: string;
  count: number;
}

interface ChartGeometry {
  path: string;
  areaPath: string;
  points: Array<{ x: number; y: number }>;
  xLabels: Array<{ label: string; x: number }>;
  max: number;
  sampledData: TimelinePoint[];
  viewBoxWidth: number;
  padLeft: number;
  padRight: number;
  padTop: number;
  padBottom: number;
}

interface TrafficAreaChartProps {
  data: TimelinePoint[];
  height?: number;
  color?: string;
  hoveredLabel?: string | null;
  lockedLabel?: string | null;
  selectedRange?: TrafficTimelineRangeSelection | null;
  onHoverPoint?: (point: TimelinePoint | null) => void;
  onSelectPoint?: (point: TimelinePoint) => void;
  onSelectRange?: (range: TrafficTimelineRangeSelection | null) => void;
}

export function TrafficAreaChart({
  data,
  height = 200,
  color = "var(--color-chart-1)",
  hoveredLabel,
  lockedLabel,
  selectedRange,
  onHoverPoint,
  onSelectPoint,
  onSelectRange,
}: TrafficAreaChartProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [chartWidth, setChartWidth] = useState(DEFAULT_CHART_WIDTH);
  const [brushStartIndex, setBrushStartIndex] = useState<number | null>(null);
  const [brushEndIndex, setBrushEndIndex] = useState<number | null>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const updateWidth = () => {
      const nextWidth = Math.round(container.getBoundingClientRect().width);
      if (nextWidth > 0) {
        setChartWidth(nextWidth);
      }
    };

    updateWidth();

    if (typeof ResizeObserver !== "undefined") {
      const observer = new ResizeObserver(updateWidth);
      observer.observe(container);
      return () => observer.disconnect();
    }

    window.addEventListener("resize", updateWidth);
    return () => window.removeEventListener("resize", updateWidth);
  }, []);

  const sanitizedData = useMemo(
    () =>
      normalizeTrafficTimelineBuckets(
        data.map((point) => ({
          label: String(point.label ?? ""),
          count: Number(point.count ?? 0),
        })),
      ).map((point) => ({
        label: point.label,
        count: point.count,
      })),
    [data],
  );

  const { path, areaPath, points, xLabels, max, sampledData, padTop, padBottom } = useMemo<ChartGeometry>(() => {
    if (sanitizedData.length === 0) {
      return {
        path: "",
        areaPath: "",
        points: [],
        xLabels: [],
        max: 1,
        sampledData: [],
        viewBoxWidth: chartWidth,
        padLeft: 14,
        padRight: 14,
        padTop: 12,
        padBottom: 28,
      };
    }

    const MAX_POINTS = 200;
    let sampled = sanitizedData;
    if (sanitizedData.length > MAX_POINTS) {
      const step = sanitizedData.length / MAX_POINTS;
      sampled = [];
      for (let index = 0; index < MAX_POINTS; index += 1) {
        const sampledIndex = Math.min(Math.floor(index * step), sanitizedData.length - 1);
        sampled.push(sanitizedData[sampledIndex]);
      }
      if (sampled[sampled.length - 1] !== sanitizedData[sanitizedData.length - 1]) {
        sampled.push(sanitizedData[sanitizedData.length - 1]);
      }
    }

    const maxValue = Math.max(1, ...sampled.map((point) => point.count));
    const width = chartWidth;
    const chartHeight = height;
    const topPadding = 12;
    const bottomPadding = 28;
    const leftPadding = 14;
    const rightPadding = 14;
    const plotHeight = chartHeight - topPadding - bottomPadding;
    const plotWidth = width - leftPadding - rightPadding;
    const step = sampled.length > 1 ? plotWidth / (sampled.length - 1) : 0;

    const chartPoints = sampled.map((point, index) => ({
      x: sampled.length > 1 ? leftPadding + index * step : leftPadding + plotWidth / 2,
      y: topPadding + plotHeight - (point.count / maxValue) * plotHeight,
    }));

    const linePath =
      chartPoints.length === 1
        ? `M${chartPoints[0].x},${chartPoints[0].y} L${chartPoints[0].x},${chartPoints[0].y}`
        : `M${chartPoints.map((point) => `${point.x},${point.y}`).join(" L")}`;
    const fillPath =
      chartPoints.length === 1
        ? `M${chartPoints[0].x},${chartPoints[0].y} L${chartPoints[0].x},${topPadding + plotHeight} L${chartPoints[0].x},${topPadding + plotHeight} Z`
        : `${linePath} L${chartPoints[chartPoints.length - 1].x},${topPadding + plotHeight} L${chartPoints[0].x},${topPadding + plotHeight} Z`;

    const maxVisibleLabels = Math.max(2, Math.min(6, Math.floor(plotWidth / 96)));
    const labelCount = Math.min(maxVisibleLabels, sampled.length);
    const labelStep = Math.max(1, Math.floor(sampled.length / labelCount));
    const labels = sampled
      .map((point, index) => ({ label: point.label, x: chartPoints[index].x }))
      .filter((_, index) => index % labelStep === 0 || index === sampled.length - 1);

    return {
      path: linePath,
      areaPath: fillPath,
      points: chartPoints,
      xLabels: labels,
      max: maxValue,
      sampledData: sampled,
      viewBoxWidth: width,
      padLeft: leftPadding,
      padRight: rightPadding,
      padTop: topPadding,
      padBottom: bottomPadding,
    };
  }, [chartWidth, height, sanitizedData]);

  if (sanitizedData.length === 0) {
    return <AnalysisEmptyState>暂无时序数据</AnalysisEmptyState>;
  }

  const chartHeight = height - padTop - padBottom;

  function resolveNearestIndex(clientX: number) {
    const container = containerRef.current;
    if (!container || points.length === 0) {
      return null;
    }

    const rect = container.getBoundingClientRect();
    if (rect.width <= 0) {
      return null;
    }

    const localX = ((clientX - rect.left) / rect.width) * chartWidth;
    let nearestIndex = 0;
    let nearestDistance = Number.POSITIVE_INFINITY;
    for (let index = 0; index < points.length; index += 1) {
      const distance = Math.abs(points[index].x - localX);
      if (distance < nearestDistance) {
        nearestDistance = distance;
        nearestIndex = index;
      }
    }
    return nearestIndex;
  }

  function setHoveredPointFromClientX(clientX: number) {
    const nearestIndex = resolveNearestIndex(clientX);
    if (nearestIndex == null) {
      onHoverPoint?.(null);
      return;
    }
    onHoverPoint?.(sampledData[nearestIndex] ?? null);
  }

  function commitRange(startIndex: number | null, endIndex: number | null) {
    if (startIndex == null || endIndex == null) {
      onSelectRange?.(null);
      return;
    }

    const leftIndex = Math.min(startIndex, endIndex);
    const rightIndex = Math.max(startIndex, endIndex);
    if (leftIndex === rightIndex) {
      onSelectRange?.(null);
      return;
    }

    onSelectRange?.({
      startLabel: sampledData[leftIndex].label,
      endLabel: sampledData[rightIndex].label,
    });
  }

  const hoveredIndex = hoveredLabel ? sampledData.findIndex((point) => point.label === hoveredLabel) : -1;
  const lockedIndex = lockedLabel ? sampledData.findIndex((point) => point.label === lockedLabel) : -1;
  const selectedRangeIndices =
    selectedRange == null
      ? null
      : {
          startIndex: sampledData.findIndex((point) => point.label === selectedRange.startLabel),
          endIndex: sampledData.findIndex((point) => point.label === selectedRange.endLabel),
        };
  const activeBrush =
    brushStartIndex != null && brushEndIndex != null
      ? { startIndex: Math.min(brushStartIndex, brushEndIndex), endIndex: Math.max(brushStartIndex, brushEndIndex) }
      : null;
  const committedBrush =
    selectedRangeIndices && selectedRangeIndices.startIndex >= 0 && selectedRangeIndices.endIndex >= 0
      ? {
          startIndex: Math.min(selectedRangeIndices.startIndex, selectedRangeIndices.endIndex),
          endIndex: Math.max(selectedRangeIndices.startIndex, selectedRangeIndices.endIndex),
        }
      : null;
  const visibleBrush = activeBrush ?? committedBrush;
  const rangeOverlay =
    visibleBrush && points[visibleBrush.startIndex] && points[visibleBrush.endIndex]
      ? {
          x: points[visibleBrush.startIndex].x,
          width: Math.max(4, points[visibleBrush.endIndex].x - points[visibleBrush.startIndex].x),
        }
      : null;

  return (
    <div ref={containerRef} className="relative w-full">
      <svg
        data-testid="traffic-area-chart"
        width="100%"
        height={height}
        viewBox={`0 0 ${chartWidth} ${height}`}
        preserveAspectRatio="xMinYMin meet"
        className="w-full"
        style={{ height }}
        onMouseMove={(event) => {
          setHoveredPointFromClientX(event.clientX);
          if (brushStartIndex != null) {
            const nearestIndex = resolveNearestIndex(event.clientX);
            if (nearestIndex != null) {
              setBrushEndIndex(nearestIndex);
            }
          }
        }}
        onMouseLeave={() => {
          onHoverPoint?.(null);
          setBrushStartIndex(null);
          setBrushEndIndex(null);
        }}
        onMouseDown={(event) => {
          const nearestIndex = resolveNearestIndex(event.clientX);
          if (nearestIndex == null) {
            return;
          }
          setBrushStartIndex(nearestIndex);
          setBrushEndIndex(nearestIndex);
        }}
        onMouseUp={(event) => {
          if (brushStartIndex == null) {
            return;
          }
          const nearestIndex = resolveNearestIndex(event.clientX);
          commitRange(brushStartIndex, nearestIndex ?? brushEndIndex);
          setBrushStartIndex(null);
          setBrushEndIndex(null);
        }}
      >
        {[0.25, 0.5, 0.75].map((ratio) => (
          <line
            key={ratio}
            x1={0}
            y1={padTop + chartHeight * (1 - ratio)}
            x2={chartWidth}
            y2={padTop + chartHeight * (1 - ratio)}
            stroke="var(--border)"
            strokeWidth={0.3}
            vectorEffect="non-scaling-stroke"
          />
        ))}

        {rangeOverlay ? (
          <rect
            data-testid="traffic-area-selected-range"
            x={rangeOverlay.x}
            y={padTop}
            width={rangeOverlay.width}
            height={chartHeight}
            fill="var(--color-chart-2)"
            fillOpacity={0.12}
          />
        ) : null}

        <path data-testid="traffic-area-fill" d={areaPath} fill={color} fillOpacity={0.12} />

        <path
          data-testid="traffic-area-line"
          d={path}
          fill="none"
          stroke={color}
          strokeWidth={1.5}
          vectorEffect="non-scaling-stroke"
        />

        {points.map((point, index) => {
          const isHovered = hoveredIndex === index;
          const isLocked = lockedIndex === index;
          return (
            <circle
              key={sampledData[index].label}
              data-testid={isLocked ? "traffic-area-locked-point" : undefined}
              cx={point.x}
              cy={point.y}
              r={isLocked ? 4.5 : isHovered ? 3.2 : sanitizedData.length <= 30 ? 2 : 0.8}
              fill={isLocked ? "white" : color}
              stroke={color}
              strokeWidth={isLocked ? 1.8 : isHovered ? 1.1 : 0.5}
              vectorEffect="non-scaling-stroke"
              className={onSelectPoint ? "cursor-pointer" : ""}
              onMouseEnter={() => onHoverPoint?.(sampledData[index])}
              onMouseLeave={() => onHoverPoint?.(null)}
              onClick={() => onSelectPoint?.(sampledData[index])}
            />
          );
        })}

        {xLabels.map((label, index) => (
          <text
            key={`${label.label}-${index}`}
            x={label.x}
            y={height - 4}
            textAnchor="middle"
            fontSize={7}
            fill="var(--muted-foreground)"
            vectorEffect="non-scaling-stroke"
          >
            {label.label}
          </text>
        ))}
      </svg>

      <div className="text-muted-foreground absolute left-1 top-0 text-[10px] font-mono">{max}</div>
      {hoveredIndex >= 0 ? (
        <div className="pointer-events-none absolute right-2 top-2 rounded-sm border border-[var(--meow-tile-divider)] bg-white/90 px-2 py-1 text-[11px] text-slate-600 shadow-sm">
          <span className="font-mono text-slate-400">{sampledData[hoveredIndex].label}</span>
          <span className="ml-2 font-semibold text-slate-800">{sampledData[hoveredIndex].count} pkt</span>
        </div>
      ) : null}
    </div>
  );
}
