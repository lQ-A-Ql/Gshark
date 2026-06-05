import { useMemo, useRef, useState } from "react";
import { AnalysisEmptyState } from "../../components/analysis/AnalysisPrimitives";

export interface TopologyEdge {
  src: string;
  dst: string;
  count: number;
}

interface TrafficTopologyGraphProps {
  edges: TopologyEdge[];
  maxNodes?: number;
  height?: number;
  linkedContextLabel?: string | null;
  onSelect?: (edge: TopologyEdge) => void;
}

interface LayoutNode {
  id: string;
  x: number;
  y: number;
  radius: number;
  isSrc: boolean;
}

interface LayoutEdge {
  src: LayoutNode;
  dst: LayoutNode;
  count: number;
  width: number;
}

interface ViewTransform {
  scale: number;
  translateX: number;
  translateY: number;
}

const MIN_SCALE = 0.6;
const MAX_SCALE = 3;
const ZOOM_STEP = 1.12;

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

export function TrafficTopologyGraph({ edges, maxNodes = 16, height = 320, linkedContextLabel, onSelect }: TrafficTopologyGraphProps) {
  const [view, setView] = useState<ViewTransform>({ scale: 1, translateX: 0, translateY: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const dragStateRef = useRef<{ startX: number; startY: number; originX: number; originY: number } | null>(null);
  const { nodes, layoutEdges, linkedNodeIds, linkedEdgeKey } = useMemo(() => {
    if (edges.length === 0) return { nodes: [], layoutEdges: [], linkedNodeIds: new Set<string>(), linkedEdgeKey: "" };

    // Count node occurrences
    const nodeCounts = new Map<string, { src: number; dst: number }>();
    for (const e of edges) {
      const sc = nodeCounts.get(e.src) ?? { src: 0, dst: 0 };
      sc.src += e.count;
      nodeCounts.set(e.src, sc);
      const dc = nodeCounts.get(e.dst) ?? { src: 0, dst: 0 };
      dc.dst += e.count;
      nodeCounts.set(e.dst, dc);
    }

    // Pick top nodes by total traffic
    const sorted = Array.from(nodeCounts.entries())
      .map(([id, c]) => ({ id, src: c.src, dst: c.dst }))
      .sort((a, b) => (b.src + b.dst) - (a.src + a.dst))
      .slice(0, maxNodes);

    const nodeSet = new Set(sorted.map((n) => n.id));
    const maxTotal = Math.max(1, sorted[0] ? sorted[0].src + sorted[0].dst : 1);

    // Layout: sources on left, sinks on right
    const srcNodes = sorted.filter((n) => n.src >= n.dst);
    const dstNodes = sorted.filter((n) => n.src < n.dst);
    const w = 100;
    const h = height;
    const padX = 12;
    const padY = 20;

    const layoutNode = (id: string, isSrc: boolean, idx: number): LayoutNode => {
      const arr = isSrc ? srcNodes : dstNodes;
      const t = arr.length > 1 ? idx / (arr.length - 1) : 0.5;
      const nc = nodeCounts.get(id);
      const nodeTotal = nc ? nc.src + nc.dst : 0;
      return {
        id,
        x: isSrc ? padX : w - padX,
        y: padY + t * (h - 2 * padY),
        radius: 2 + (nodeTotal / maxTotal) * 5,
        isSrc,
      };
    };

    const nodeMap = new Map<string, LayoutNode>();
    srcNodes.forEach((n, i) => nodeMap.set(n.id, layoutNode(n.id, true, i)));
    dstNodes.forEach((n, i) => nodeMap.set(n.id, layoutNode(n.id, false, i)));

    // Filter edges to only include top nodes, compute max count safely
    let mc = 1;
    for (const e of edges) {
      if (nodeSet.has(e.src) && nodeSet.has(e.dst) && e.src !== e.dst && e.count > mc) {
        mc = e.count;
      }
    }
    const le: LayoutEdge[] = [];
    for (const e of edges) {
      if (e.src === e.dst) continue;
      const s = nodeMap.get(e.src);
      const d = nodeMap.get(e.dst);
      if (s && d) {
        le.push({ src: s, dst: d, count: e.count, width: 0.3 + (e.count / mc) * 2.5 });
      }
    }

    const primaryEdge = le.reduce<LayoutEdge | null>((best, edge) => {
      if (!best || edge.count > best.count) return edge;
      return best;
    }, null);
    const primaryNodeIds = new Set<string>();
    if (primaryEdge) {
      primaryNodeIds.add(primaryEdge.src.id);
      primaryNodeIds.add(primaryEdge.dst.id);
    }

    return {
      nodes: Array.from(nodeMap.values()),
      layoutEdges: le,
      linkedNodeIds: primaryNodeIds,
      linkedEdgeKey: primaryEdge ? `${primaryEdge.src.id}\u0000${primaryEdge.dst.id}` : "",
    };
  }, [edges, maxNodes, height]);

  if (edges.length === 0) {
    return <AnalysisEmptyState>暂无会话拓扑数据</AnalysisEmptyState>;
  }

  const transform = `translate(${view.translateX} ${view.translateY}) scale(${view.scale})`;

  const zoomAroundPoint = (focusX: number, focusY: number, nextScale: number) => {
    setView((current) => {
      const scale = clamp(nextScale, MIN_SCALE, MAX_SCALE);
      if (scale === current.scale) return current;
      const worldX = (focusX - current.translateX) / current.scale;
      const worldY = (focusY - current.translateY) / current.scale;
      return {
        scale,
        translateX: focusX - worldX * scale,
        translateY: focusY - worldY * scale,
      };
    });
  };

  const stopDragging = () => {
    dragStateRef.current = null;
    setIsDragging(false);
  };

  return (
    <div className="relative">
      <div className="pointer-events-none absolute left-3 top-3 z-10 max-w-[14rem] rounded-sm border border-[var(--meow-control-border)] bg-white/80 px-2 py-1 text-[10px] text-slate-500 shadow-sm backdrop-blur-sm">
        滚轮缩放，按住左键拖动画布，使用“重置视图”恢复初始位置。
      </div>
      {linkedContextLabel ? (
        <div
          data-testid="traffic-topology-linked-context"
          className="pointer-events-none absolute left-3 top-12 z-10 max-w-[18rem] rounded-sm border border-cyan-200 bg-cyan-50/90 px-2 py-1 text-[10px] leading-5 text-cyan-800 shadow-sm"
        >
          联动时间：{linkedContextLabel}。当前拓扑仍为全局会话，已高亮全局 Top 会话作为参考。
        </div>
      ) : null}
      <button
        type="button"
        aria-label="重置拓扑视图"
        className="absolute right-3 top-3 z-10 rounded-sm border border-[var(--meow-control-border)] bg-white/85 px-2 py-1 text-[10px] font-medium text-slate-600 shadow-sm transition hover:border-[var(--meow-control-hover-border)] hover:text-slate-900"
        onClick={() => setView({ scale: 1, translateX: 0, translateY: 0 })}
      >
        重置视图
      </button>
      <svg
        data-testid="traffic-topology-viewport"
        viewBox={`0 0 100 ${height}`}
        className={`w-full ${isDragging ? "cursor-grabbing" : "cursor-grab"}`}
        style={{ height, touchAction: "none" }}
        onWheel={(event) => {
          event.preventDefault();
          const rect = event.currentTarget.getBoundingClientRect();
          const focusX = rect.width > 0 ? ((event.clientX - rect.left) / rect.width) * 100 : 50;
          const focusY = rect.height > 0 ? ((event.clientY - rect.top) / rect.height) * height : height / 2;
          const factor = event.deltaY < 0 ? ZOOM_STEP : 1 / ZOOM_STEP;
          zoomAroundPoint(focusX, focusY, view.scale * factor);
        }}
        onMouseDown={(event) => {
          if (event.button !== 0) return;
          event.preventDefault();
          dragStateRef.current = {
            startX: event.clientX,
            startY: event.clientY,
            originX: view.translateX,
            originY: view.translateY,
          };
          setIsDragging(true);
        }}
        onMouseMove={(event) => {
          const dragState = dragStateRef.current;
          if (!dragState) return;
          event.preventDefault();
          const rect = event.currentTarget.getBoundingClientRect();
          const deltaX = rect.width > 0 ? ((event.clientX - dragState.startX) / rect.width) * 100 : 0;
          const deltaY = rect.height > 0 ? ((event.clientY - dragState.startY) / rect.height) * height : 0;
          setView((current) => ({
            ...current,
            translateX: dragState.originX + deltaX,
            translateY: dragState.originY + deltaY,
          }));
        }}
        onMouseUp={stopDragging}
        onMouseLeave={stopDragging}
      >
        <defs>
          <marker id="topo-arrow" viewBox="0 0 6 4" refX={6} refY={2} markerWidth={4} markerHeight={3} orient="auto">
            <path d="M0,0 L6,2 L0,4 Z" fill="var(--muted-foreground)" />
          </marker>
        </defs>

        <g data-testid="traffic-topology-content" transform={transform}>
          {/* Edges */}
          {layoutEdges.map((e, i) => {
            const midX = (e.src.x + e.dst.x) / 2;
            const curveOffset = (e.dst.y - e.src.y) * 0.15;
            const isLinkedEdge = linkedContextLabel && `${e.src.id}\u0000${e.dst.id}` === linkedEdgeKey;
            return (
              <path
                key={i}
                data-testid={isLinkedEdge ? "traffic-topology-linked-edge" : undefined}
                d={`M${e.src.x},${e.src.y} C${midX},${e.src.y + curveOffset} ${midX},${e.dst.y - curveOffset} ${e.dst.x},${e.dst.y}`}
                fill="none"
                stroke={isLinkedEdge ? "var(--color-chart-2)" : "var(--border)"}
                strokeWidth={isLinkedEdge ? e.width + 1 : e.width}
                strokeDasharray={isLinkedEdge ? "4 2" : undefined}
                opacity={linkedContextLabel && !isLinkedEdge ? 0.42 : 1}
                vectorEffect="non-scaling-stroke"
                markerEnd="url(#topo-arrow)"
                className={onSelect ? "cursor-pointer hover:stroke-amber-400" : ""}
                onClick={() => onSelect?.({ src: e.src.id, dst: e.dst.id, count: e.count })}
              />
            );
          })}

          {/* Nodes */}
          {nodes.map((n) => (
            <g key={n.id}>
              {linkedContextLabel && linkedNodeIds.has(n.id) ? (
                <circle
                  data-testid="traffic-topology-linked-node"
                  cx={n.x}
                  cy={n.y}
                  r={n.radius + 2.2}
                  fill="none"
                  stroke="var(--color-chart-2)"
                  strokeWidth={1.1}
                  strokeDasharray="2 1.5"
                  vectorEffect="non-scaling-stroke"
                />
              ) : null}
              <circle
                cx={n.x}
                cy={n.y}
                r={n.radius}
                fill={n.isSrc ? "var(--color-chart-1)" : "var(--color-chart-2)"}
                stroke="white"
                strokeWidth={0.8}
                vectorEffect="non-scaling-stroke"
              />
              <text
                x={n.isSrc ? n.x - n.radius - 1.5 : n.x + n.radius + 1.5}
                y={n.y + 1}
                textAnchor={n.isSrc ? "end" : "start"}
                fontSize={6}
                fill="var(--foreground)"
                vectorEffect="non-scaling-stroke"
              >
                {n.id}
              </text>
            </g>
          ))}
        </g>
      </svg>

      {/* Legend */}
      <div className="absolute bottom-1 right-2 flex gap-3 text-[10px] text-slate-400">
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-indigo-500" /> 源
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded-full bg-cyan-500" /> 目标
        </span>
      </div>
    </div>
  );
}
