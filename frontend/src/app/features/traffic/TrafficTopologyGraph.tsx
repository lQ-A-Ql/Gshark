import { useMemo } from "react";
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

export function TrafficTopologyGraph({ edges, maxNodes = 16, height = 320, onSelect }: TrafficTopologyGraphProps) {
  const { nodes, layoutEdges } = useMemo(() => {
    if (edges.length === 0) return { nodes: [], layoutEdges: [] };

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

    return { nodes: Array.from(nodeMap.values()), layoutEdges: le };
  }, [edges, maxNodes, height]);

  if (edges.length === 0) {
    return <AnalysisEmptyState>暂无会话拓扑数据</AnalysisEmptyState>;
  }

  return (
    <div className="relative">
      <svg viewBox={`0 0 100 ${height}`} className="w-full" style={{ height }}>
        <defs>
          <marker id="topo-arrow" viewBox="0 0 6 4" refX={6} refY={2} markerWidth={4} markerHeight={3} orient="auto">
            <path d="M0,0 L6,2 L0,4 Z" fill="#94a3b8" />
          </marker>
        </defs>

        {/* Edges */}
        {layoutEdges.map((e, i) => {
          const midX = (e.src.x + e.dst.x) / 2;
          const curveOffset = (e.dst.y - e.src.y) * 0.15;
          return (
            <path
              key={i}
              d={`M${e.src.x},${e.src.y} C${midX},${e.src.y + curveOffset} ${midX},${e.dst.y - curveOffset} ${e.dst.x},${e.dst.y}`}
              fill="none"
              stroke="#cbd5e1"
              strokeWidth={e.width}
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
            <circle
              cx={n.x}
              cy={n.y}
              r={n.radius}
              fill={n.isSrc ? "#6366f1" : "#06b6d4"}
              stroke="white"
              strokeWidth={0.8}
              vectorEffect="non-scaling-stroke"
            />
            <text
              x={n.isSrc ? n.x - n.radius - 1.5 : n.x + n.radius + 1.5}
              y={n.y + 1}
              textAnchor={n.isSrc ? "end" : "start"}
              fontSize={6}
              fill="#475569"
              vectorEffect="non-scaling-stroke"
            >
              {n.id}
            </text>
          </g>
        ))}
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
