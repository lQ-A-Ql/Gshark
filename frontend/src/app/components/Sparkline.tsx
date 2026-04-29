import { useMemo } from "react";

interface SparklineProps {
  values: number[];
  width?: number;
  height?: number;
  className?: string;
  color?: string;
}

export function Sparkline({ values, width = 120, height = 24, className = "", color = "stroke-rose-500" }: SparklineProps) {
  const path = useMemo(() => {
    if (values.length < 2) return "";
    const min = Math.min(...values);
    const max = Math.max(...values);
    const range = max - min || 1;
    const stepX = width / (values.length - 1);
    const points = values.map((v, i) => {
      const x = i * stepX;
      const y = height - ((v - min) / range) * (height - 4) - 2;
      return `${x},${y}`;
    });
    return `M${points.join(" L")}`;
  }, [values, width, height]);

  if (values.length < 2) {
    return (
      <div className={`text-[10px] text-slate-400 ${className}`}>--</div>
    );
  }

  return (
    <svg width={width} height={height} className={className}>
      <path d={path} fill="none" className={color} strokeWidth="1.5" />
    </svg>
  );
}
