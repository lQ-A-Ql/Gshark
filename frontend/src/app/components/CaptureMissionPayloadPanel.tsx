import { ArrowRight } from "lucide-react";
import type { Packet } from "../core/types";

type CapturePayloadShortcutPanelProps = {
  selectedPacket: Packet | null;
  onOpenCurrentStream: () => Promise<void>;
  onOpenMisc: () => void;
};

export function CapturePayloadShortcutPanel({
  selectedPacket,
  onOpenCurrentStream,
  onOpenMisc,
}: CapturePayloadShortcutPanelProps) {
  return (
    <div className="border-t border-slate-200 p-4 sm:p-5">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-slate-900">Payload 快速解码</div>
          <div className="mt-1 text-xs text-slate-500">
            解码与 WebShell 候选识别已收敛到 MISC 工具箱；首屏仅保留当前包上下文和跳转入口，避免工作区过载。
          </div>
        </div>
        {selectedPacket && (
          <div className="flex flex-wrap items-center gap-2">
            <div className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-[11px] text-slate-600">
              Packet #{selectedPacket.id} / {selectedPacket.displayProtocol || selectedPacket.proto}
            </div>
            {selectedPacket.streamId != null && selectedPacket.streamId >= 0 && (
              <button
                onClick={() => void onOpenCurrentStream()}
                className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
              >
                打开当前关联流
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            )}
            <button
              onClick={onOpenMisc}
              className="inline-flex items-center gap-2 rounded-full border border-cyan-200 bg-cyan-50 px-3 py-1.5 text-xs font-medium text-cyan-700 hover:bg-cyan-100"
            >
              打开 MISC 解码工作台
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
      </div>

      {selectedPacket ? (
        <div className="grid gap-3 xl:grid-cols-[minmax(320px,0.82fr)_minmax(0,1.18fr)]">
          <div className="gshark-tile border-slate-200 bg-slate-50/80 p-3.5">
            <div className="text-sm font-semibold text-slate-900">当前数据包上下文</div>
            <div className="mt-2.5 space-y-2 text-xs">
              <InfoRow
                label="端点"
                value={`${selectedPacket.src}:${selectedPacket.srcPort} -> ${selectedPacket.dst}:${selectedPacket.dstPort}`}
                mono
              />
              <InfoRow label="协议" value={selectedPacket.displayProtocol || selectedPacket.proto} />
              <InfoRow label="长度" value={`${selectedPacket.length} bytes`} />
              <InfoRow label="说明" value={selectedPacket.info || "(no info)"} />
            </div>
          </div>
          <div className="gshark-tile border-cyan-100 bg-cyan-50/60 p-3.5">
            <div className="flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-semibold text-slate-900">Payload 预览</div>
                <div className="mt-1 text-xs text-slate-500">
                  如需识别候选或尝试解码，请在 MISC 工作台中手动粘贴该 payload。
                </div>
              </div>
              <button
                onClick={onOpenMisc}
                className="shrink-0 rounded-full border border-cyan-200 bg-white px-3 py-1.5 text-xs font-semibold text-cyan-700 shadow-sm transition hover:border-cyan-300 hover:bg-cyan-50"
              >
                去 MISC
              </button>
            </div>
            <pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-xl border border-cyan-100 bg-white/90 px-3 py-2 font-mono text-[11px] leading-5 text-slate-600">
              {selectedPacket.payload || "(empty payload)"}
            </pre>
          </div>
        </div>
      ) : (
        <div className="gshark-tile border-dashed border-slate-200 bg-slate-50 px-4 py-6 text-center text-xs leading-5 text-slate-500">
          选中一条数据包后，这里会展示 payload 预览；完整解码请前往 MISC 工具箱。
        </div>
      )}
    </div>
  );
}

function InfoRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white px-3 py-2">
      <div className="text-[11px] font-medium tracking-[0.12em] text-slate-500">{label}</div>
      <div className={`mt-1 break-all text-sm text-slate-900 ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}
