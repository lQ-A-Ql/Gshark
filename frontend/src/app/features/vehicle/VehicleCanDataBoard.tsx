import type { VehicleAnalysis as VehicleAnalysisData } from "../../core/types";

const MAX_CAN_DATA_LINES_PER_ID = 12;

interface CanIdDataLine {
  packetId: number;
  label: string;
  value: string;
  meta: string;
}

export interface CanIdDataGroup {
  identifier: string;
  busId: string;
  total: number;
  observedCount: number;
  hiddenCount: number;
  items: CanIdDataLine[];
}

export function CanIdDataBoard({ groups }: { groups: CanIdDataGroup[] }) {
  if (groups.length === 0) {
    return (
      <div className="px-3 py-6 text-center text-xs text-muted-foreground">
        暂无可展示的 CAN ID 数据
      </div>
    );
  }

  return (
    <div className="max-h-[520px] overflow-auto pr-1">
      <div className="space-y-3">
        {groups.map((group) => (
          <div
            key={`${group.identifier}-${group.busId}`}
            className="gshark-soft-fill overflow-hidden"
          >
            <div className="grid grid-cols-[156px_1fr]">
              <div className="border-r border-border bg-accent/20 px-3 py-3">
                <div className="text-[11px] text-muted-foreground">CAN ID</div>
                <div className="mt-1 font-mono text-sm font-semibold text-foreground">{group.identifier}</div>
                <div className="mt-2 text-[11px] text-muted-foreground">Bus {group.busId || "--"}</div>
                <div className="mt-1 text-[11px] text-muted-foreground">唯一 DATA {group.total} 条</div>
                <div className="mt-1 text-[11px] text-muted-foreground">原始帧 {group.observedCount} 条</div>
              </div>
              <div className="divide-y divide-border/70">
                {group.items.map((item) => (
                  <div key={`${group.identifier}-${item.packetId}-${item.label}`} className="px-3 py-2">
                    <div className="text-[11px] text-muted-foreground">
                      {item.label} · {item.meta}
                    </div>
                    <div className="mt-1 break-all font-mono text-xs text-foreground">{item.value}</div>
                  </div>
                ))}
                {group.hiddenCount > 0 && (
                  <div className="px-3 py-2 text-[11px] text-muted-foreground">
                    还有 {group.hiddenCount} 条数据未展开，保留在原始 CAN Payload / DBC 区域中查看。
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function buildCanIdDataGroups(analysis: VehicleAnalysisData): CanIdDataGroup[] {
  const grouped = new Map<
    string,
    {
      identifier: string;
      busId: string;
      observedCount: number;
      items: CanIdDataLine[];
      seenValues: Set<string>;
    }
  >();
  const orderedKeys: string[] = [];

  for (const frame of analysis.can.frames) {
    const identifier = frame.identifier?.trim() || "--";
    const busId = frame.busId?.trim() || "--";
    const rawData = frame.rawData?.trim() || "";
    if (!rawData) {
      continue;
    }
    const key = `${identifier}@@${busId}`;
    if (!grouped.has(key)) {
      grouped.set(key, {
        identifier,
        busId,
        observedCount: 0,
        items: [],
        seenValues: new Set<string>(),
      });
      orderedKeys.push(key);
    }

    const group = grouped.get(key)!;
    group.observedCount += 1;
    if (group.seenValues.has(rawData)) {
      continue;
    }
    group.seenValues.add(rawData);

    const meta = [
      frame.time?.trim(),
      frame.length > 0 ? `len=${frame.length}` : "",
      frame.packetId ? `#${frame.packetId}` : "",
    ]
      .filter(Boolean)
      .join(" · ");

    group.items.push({
      packetId: frame.packetId,
      label: `DATA${group.items.length + 1}`,
      value: rawData,
      meta: meta || "--",
    });
  }

  return orderedKeys.map((key) => {
    const group = grouped.get(key)!;
    const total = group.items.length;
    return {
      identifier: group.identifier,
      busId: group.busId,
      total,
      observedCount: group.observedCount,
      hiddenCount: Math.max(0, total - MAX_CAN_DATA_LINES_PER_ID),
      items: group.items.slice(0, MAX_CAN_DATA_LINES_PER_ID),
    };
  });
}
