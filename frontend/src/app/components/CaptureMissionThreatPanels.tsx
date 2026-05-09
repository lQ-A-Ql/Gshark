import type { ThreatHit } from "../core/types";

type CaptureSuspiciousHitsPanelProps = {
  hits: ThreatHit[];
  pendingAction: string;
  onOpenAll: () => void;
  onJumpToPacket: (packetId: number) => Promise<void>;
  onOpenStream: (packetId: number) => Promise<void>;
};

export function CaptureSuspiciousHitsPanel({
  hits,
  pendingAction,
  onOpenAll,
  onJumpToPacket,
  onOpenStream,
}: CaptureSuspiciousHitsPanelProps) {
  return (
    <div className="rounded-[24px] border border-slate-200 bg-slate-50 p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="text-sm font-semibold text-slate-900">优先处理的命中</div>
        <button onClick={onOpenAll} className="text-xs font-medium text-blue-700 hover:text-blue-800">
          打开全部
        </button>
      </div>
      {hits.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-slate-200 bg-white px-4 py-6 text-center text-xs leading-5 text-slate-500">
          当前默认规则还没有给出明显命中，可以先从推荐过滤器和协议分布切入，再按需要重跑狩猎。
        </div>
      ) : (
        <div className="space-y-3">
          {hits.map((hit) => (
            <div key={hit.id} className="rounded-2xl border border-slate-200 bg-white px-4 py-3">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] text-slate-600">
                      #{hit.packetId}
                    </span>
                    <span className="rounded-full border border-rose-200 bg-rose-50 px-2 py-0.5 text-[11px] font-medium text-rose-700">
                      {hit.rule}
                    </span>
                    <span className="rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] text-slate-600">
                      {hit.level}
                    </span>
                  </div>
                  <div className="mt-2 text-sm font-medium text-slate-900">
                    {hit.preview || hit.match || "可疑命中"}
                  </div>
                  <div className="mt-1 line-clamp-2 font-mono text-[11px] leading-5 text-slate-500">{hit.match}</div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <button
                    onClick={() => void onJumpToPacket(hit.packetId)}
                    disabled={pendingAction.length > 0}
                    className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {pendingAction === `packet:${hit.packetId}` ? "定位中" : "定位到包"}
                  </button>
                  <button
                    onClick={() => void onOpenStream(hit.packetId)}
                    disabled={pendingAction.length > 0}
                    className="rounded-xl border border-blue-200 bg-blue-50 px-3 py-2 text-xs font-medium text-blue-700 hover:bg-blue-100 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {pendingAction === `stream:${hit.packetId}` ? "打开中" : "打开关联流"}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
