import { useMemo } from "react";
import { AnalysisEmptyState } from "../../components/analysis/AnalysisPrimitives";

export interface TimelinePoint {
  label: string;
  count: number;
}

interface TrafficAreaChartProps {
  data: TimelinePoint[];
  height?: number;
  color?: string;
  onSelect?: (point: TimelinePoint) => void;
}

export function TrafficAreaChart({ data, height = 200, color = "#3b82f6", onSelect }: TrafficAreaChartProps) {
  const { path, areaPath, points, xLabels, max, sampleIndices } = useMemo(() => {
    if (data.length === 0) return { path: "", areaPath: "", points: [], xLabels: [], max: 1 };

    // Downsample if too many points (keep every Nth point + first/last)
    const MAX_POINTS = 200;
    let sampled = data;
    let sampleIndices: number[] | null = null;
    if (data.length > MAX_POINTS) {
      const step = data.length / MAX_POINTS;
      sampled = [];
      sampleIndices = [];
      for (let i = 0; i < MAX_POINTS; i++) {
        const idx = Math.min(Math.floor(i * step), data.length - 1);
        sampled.push(data[idx]);
        sampleIndices.push(idx);
      }
      if (sampleIndices[sampleIndices.length - 1] !== data.length - 1) {
        sampled.push(data[data.length - 1]);
        sampleIndices.push(data.length - 1);
      }
    }

    const m = Math.max(1, ...sampled.map((d) => d.count));
    const w = 100;
    const h = height;
    const padTop = 8;
    const padBottom = 28;
    const padLeft = 0;
    const padRight = 0;
    const chartH = h - padTop - padBottom;
    const chartW = w - padLeft - padRight;
    const step = sampled.length > 1 ? chartW / (sampled.length - 1) : chartW;

    const pts = sampled.map((d, i) => ({
      x: padLeft + i * step,
      y: padTop + chartH - (d.count / m) * chartH,
    }));

    // Catmull-Rom to Bezier conversion for smooth curves
    const buildSmoothPath = (pts: { x: number; y: number }[]) => {
      if (pts.length < 2) return "";
      if (pts.length === 2) return `M${pts[0].x},${pts[0].y} L${pts[1].x},${pts[1].y}`;

      let d = `M${pts[0].x},${pts[0].y}`;
      for (let i = 0; i < pts.length - 1; i++) {
        const p0 = pts[Math.max(0, i - 1)];
        const p1 = pts[i];
        const p2 = pts[i + 1];
        const p3 = pts[Math.min(pts.length - 1, i + 2)];

        const cp1x = p1.x + (p2.x - p0.x) / 6;
        const cp1y = p1.y + (p2.y - p0.y) / 6;
        const cp2x = p2.x - (p3.x - p1.x) / 6;
        const cp2y = p2.y - (p3.y - p1.y) / 6;

        d += ` C${cp1x},${cp1y} ${cp2x},${cp2y} ${p2.x},${p2.y}`;
      }
      return d;
    };

    const linePath = buildSmoothPath(pts);
    const area = `${linePath} L${pts[pts.length - 1].x},${padTop + chartH} L${pts[0].x},${padTop + chartH} Z`;

    // X-axis labels: pick ~6 evenly spaced
    const labelCount = Math.min(6, sampled.length);
    const labelStep = Math.max(1, Math.floor(sampled.length / labelCount));
    const xl = sampled
      .map((d, i) => ({ label: d.label, x: pts[i].x }))
      .filter((_, i) => i % labelStep === 0 || i === sampled.length - 1);

    return { path: linePath, areaPath: area, points: pts, xLabels: xl, max: m, sampleIndices };
  }, [data, height]);

  if (data.length === 0) {
    return <AnalysisEmptyState>暂无时序数据</AnalysisEmptyState>;
  }

  const padTop = 8;
  const padBottom = 28;
  const chartH = height - padTop - padBottom;

  return (
    <div className="relative">
      <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" className="w-full" style={{ height }}>
        {/* Grid lines */}
        {[0.25, 0.5, 0.75].map((ratio) => (
          <line
            key={ratio}
            x1={0}
            y1={padTop + chartH * (1 - ratio)}
            x2={100}
            y2={padTop + chartH * (1 - ratio)}
            stroke="#e2e8f0"
            strokeWidth={0.3}
            vectorEffect="non-scaling-stroke"
          />
        ))}

        {/* Area fill */}
        <path d={areaPath} fill={color} fillOpacity={0.1} />

        {/* Line */}
        <path d={path} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />

        {/* Data points */}
        {points.map((pt, i) => (
          <circle
            key={i}
            cx={pt.x}
            cy={pt.y}
            r={data.length <= 30 ? 2 : 0.8}
            fill={color}
            stroke="white"
            strokeWidth={0.5}
            vectorEffect="non-scaling-stroke"
            className={onSelect ? "cursor-pointer" : ""}
            onClick={() => onSelect?.(data[sampleIndices ? sampleIndices[i] : i])}
          />
        ))}

        {/* X-axis labels */}
        {xLabels.map((xl, i) => (
          <text
            key={i}
            x={xl.x}
            y={height - 4}
            textAnchor="middle"
            fontSize={7}
            fill="#94a3b8"
            vectorEffect="non-scaling-stroke"
          >
            {xl.label}
          </text>
        ))}
      </svg>

      {/* Y-axis max label */}
      <div className="absolute top-0 left-1 text-[10px] font-mono text-slate-400">{max}</div>
    </div>
  );
}
