import { useMemo, useState } from "react";
import { ChevronRight, ChevronDown } from "lucide-react";
import { AnalysisEmptyState } from "../../components/analysis/AnalysisPrimitives";
import type { TrafficProtocolTreeNode } from "../../core/types";

interface TrafficProtocolTreeProps {
  data: TrafficProtocolTreeNode[];
  maxDepth?: number;
}

interface TreeNodeProps {
  node: TrafficProtocolTreeNode;
  depth: number;
  maxCount: number;
  maxDepth: number;
}

function TreeNode({ node, depth, maxCount, maxDepth }: TreeNodeProps) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = (node.children?.length ?? 0) > 0 && depth < maxDepth;
  const pct = Math.max(2, (node.count / maxCount) * 100);

  return (
    <div>
      <button
        type="button"
        onClick={() => hasChildren && setExpanded(!expanded)}
        className="flex w-full items-center gap-1.5 px-1 py-0.5 text-left text-xs hover:bg-amber-50/60"
        style={{ paddingLeft: `${depth * 14}px` }}
      >
        <span className="flex h-3.5 w-3.5 items-center justify-center">
          {hasChildren ? (
            expanded ? (
              <ChevronDown className="h-3 w-3 text-slate-400" />
            ) : (
              <ChevronRight className="h-3 w-3 text-slate-400" />
            )
          ) : (
            <span className="h-1 w-1 rounded-full bg-slate-300" />
          )}
        </span>
        <span className="w-20 truncate font-medium text-slate-600">{node.name}</span>
        <span className="h-1.5 flex-1 bg-slate-100">
          <span
            className="block h-1.5 bg-emerald-400"
            style={{ width: `${pct}%` }}
          />
        </span>
        <span className="w-14 text-right font-mono text-slate-500">{node.count}</span>
      </button>
      {expanded && hasChildren && (
        <div>
          {node.children!.map((child) => (
            <TreeNode
              key={child.name}
              node={child}
              depth={depth + 1}
              maxCount={maxCount}
              maxDepth={maxDepth}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function safeMax(values: number[]): number {
  let m = 1;
  for (const v of values) {
    if (v > m) m = v;
  }
  return m;
}

export function TrafficProtocolTree({ data, maxDepth = 3 }: TrafficProtocolTreeProps) {
  const maxCount = useMemo(() => safeMax(flattenTree(data).map((n) => n.count)), [data]);

  if (data.length === 0) {
    return <AnalysisEmptyState>暂无协议层级数据</AnalysisEmptyState>;
  }

  return (
    <div className="max-h-[480px] overflow-auto">
      {data.map((node) => (
        <TreeNode
          key={node.name}
          node={node}
          depth={0}
          maxCount={maxCount}
          maxDepth={maxDepth}
        />
      ))}
    </div>
  );
}

function flattenTree(nodes: TrafficProtocolTreeNode[]): TrafficProtocolTreeNode[] {
  const result: TrafficProtocolTreeNode[] = [];
  const stack = [...nodes];
  while (stack.length > 0) {
    const n = stack.pop()!;
    result.push(n);
    if (n.children?.length) {
      for (let i = n.children.length - 1; i >= 0; i--) {
        stack.push(n.children[i]);
      }
    }
  }
  return result;
}
