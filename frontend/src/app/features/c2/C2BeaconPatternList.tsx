import type { C2FamilyAnalysis } from "../../core/types";
import type { C2Tab } from "./C2DecryptWorkbench";

export function C2BeaconPatternList({
  family,
  patterns,
}: {
  family: C2Tab;
  patterns: NonNullable<C2FamilyAnalysis["beaconPatterns"]>;
}) {
  if (patterns.length === 0) {
    return (
      <div className="px-4 py-6 text-xs leading-6 text-slate-500">
        {family === "cs"
          ? "当前抓包未形成 CS sleep / jitter / DNS beacon / SMB pivot 行为画像。"
          : "当前抓包未形成 VShell TCP 心跳、短长包交替、WebSocket 参数或 listener presence 行为画像。"}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {patterns.map((item) => (
        <div
          key={`${item.name}-${item.value}`}
          className="gshark-tile border-slate-100 bg-slate-50/70 px-3 py-2 text-xs"
        >
          <div className="flex items-center justify-between gap-3">
            <span className="font-semibold text-slate-800">{item.name}</span>
            <span className="font-mono text-slate-500">{item.value}</span>
          </div>
          <div className="mt-1 leading-5 text-slate-500">{item.summary}</div>
        </div>
      ))}
    </div>
  );
}
