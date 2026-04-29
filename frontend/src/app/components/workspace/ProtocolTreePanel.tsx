import { useState } from "react";
import { Panel } from "react-resizable-panels";
import { ChevronDown, ChevronRight, Network } from "lucide-react";
import type { ProtocolTreeNode } from "../../core/types";

export function ProtocolTreePanel({
  nodes,
  selectedId,
  onSelect,
  registerNodeRef,
}: {
  nodes: ProtocolTreeNode[];
  selectedId: string;
  onSelect: (nodeId: string) => void;
  registerNodeRef: (id: string, el: HTMLDivElement | null) => void;
}) {
  return (
    <Panel defaultSize={50} minSize={20} className="flex flex-col border-r border-border bg-card">
      <div className="flex shrink-0 items-center gap-2 border-b border-border bg-accent/40 px-3 py-1.5 text-xs font-semibold text-foreground">
        <Network className="h-4 w-4 text-emerald-600" /> 协议解析树
      </div>
      <div className="flex-1 overflow-auto p-2 font-mono text-xs">
        {nodes.length === 0 ? (
          <div className="px-2 py-2 text-muted-foreground">暂无数据包，无法显示协议树</div>
        ) : (
          nodes.map((node) => (
            <TreeNode
              key={node.id}
              node={node}
              selectedId={selectedId}
              onSelect={onSelect}
              registerNodeRef={registerNodeRef}
            />
          ))
        )}
      </div>
    </Panel>
  );
}

function TreeNode({
  node,
  depth = 0,
  selectedId,
  onSelect,
  registerNodeRef,
}: {
  node: ProtocolTreeNode;
  depth?: number;
  selectedId: string;
  onSelect: (id: string) => void;
  registerNodeRef: (id: string, el: HTMLDivElement | null) => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = (node.children?.length ?? 0) > 0;
  const selected = selectedId === node.id;

  return (
    <div className="flex flex-col">
      <div
        ref={(el) => registerNodeRef(node.id, el)}
        className={`group flex cursor-pointer items-start rounded-sm border-l px-1.5 py-0.5 ${selected ? "border-l-blue-600 bg-blue-50 text-blue-700" : "border-l-transparent text-foreground hover:border-l-blue-300 hover:bg-accent/60"}`}
        style={{ paddingLeft: `${depth * 14 + 4}px` }}
        onClick={() => {
          onSelect(node.id);
          if (hasChildren) setExpanded((value) => !value);
        }}
      >
        <span className="mr-1 mt-0.5 flex h-4 w-4 shrink-0 select-none items-center justify-center text-muted-foreground">
          {hasChildren ? (
            expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />
          ) : (
            <span className="h-1.5 w-1.5 rounded-full bg-border" />
          )}
        </span>
        <div className="flex min-w-0 flex-1 items-start justify-between gap-3">
          <span className="break-all leading-5">{node.label}</span>
          {node.byteRange && (
            <span className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] ${selected ? "border-blue-200 bg-white/80 text-blue-700" : "border-border/70 bg-background/80 text-muted-foreground"}`}>
              {node.byteRange[0]}-{node.byteRange[1]}
            </span>
          )}
        </div>
      </div>
      {expanded && hasChildren && (
        <div className="flex flex-col">
          {node.children?.map((child) => (
            <TreeNode
              key={child.id}
              node={child}
              depth={depth + 1}
              selectedId={selectedId}
              onSelect={onSelect}
              registerNodeRef={registerNodeRef}
            />
          ))}
        </div>
      )}
    </div>
  );
}
