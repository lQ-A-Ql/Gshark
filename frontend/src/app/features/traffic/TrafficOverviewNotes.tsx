export function TrafficOverviewNotes() {
  return (
    <div className="meow-tile p-5">
      <div className="grid gap-2 text-sm text-slate-600 md:grid-cols-3">
        <div className="rounded-sm border border-[var(--meow-tile-divider)] bg-white/70 px-3 py-2">
          当前流量图按分析视图拆分，避免一次性渲染全部重型卡片。
        </div>
        <div className="rounded-sm border border-[var(--meow-tile-divider)] bg-white/70 px-3 py-2">
          每秒趋势按可解析秒级时间排序，过滤空值与异常时间点。
        </div>
        <div className="rounded-sm border border-[var(--meow-tile-divider)] bg-white/70 px-3 py-2">
          拓扑关系仅来自 `topConversations`，不会回退解析端点标签伪造边。
        </div>
      </div>
    </div>
  );
}
