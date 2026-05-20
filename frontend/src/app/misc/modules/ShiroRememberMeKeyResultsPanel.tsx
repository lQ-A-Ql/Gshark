import { ShieldAlert, ShieldCheck } from "lucide-react";
import type { ShiroRememberMeCandidate } from "../../core/types";
import { EvidenceActions } from "../EvidenceActions";
import { MetaChip, NotesList } from "../ui";

interface ShiroRememberMeKeyResultsPanelProps {
  selectedCandidate: ShiroRememberMeCandidate | null;
}

export function ShiroRememberMeKeyResultsPanel({ selectedCandidate }: ShiroRememberMeKeyResultsPanelProps) {
  return (
    <div className="space-y-4">
      <div className="gshark-tile border-slate-200 p-4">
        <div className="mb-3 flex items-center justify-between gap-2">
          <div>
            <div className="text-sm font-semibold text-slate-800">候选详情</div>
            <div className="text-[12px] text-slate-500">查看 Cookie 来源、长度特征、AES 模式判断与候选密钥结果。</div>
          </div>
        </div>
        {!selectedCandidate ? (
          <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
            请选择左侧的一条 rememberMe 候选。
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              <MetaChip label="包号" value={selectedCandidate.packetId} color="slate" />
              <MetaChip label="流" value={selectedCandidate.streamId ?? "--"} color="slate" />
              <MetaChip label="Host" value={selectedCandidate.host || "--"} color="slate" />
              <MetaChip label="Path" value={selectedCandidate.path || "/"} color="slate" />
              <MetaChip label="长度" value={selectedCandidate.encryptedLength ?? "--"} color="slate" />
              <MetaChip
                label="CBC"
                value={selectedCandidate.possibleCBC ? "可能" : "否"}
                color={selectedCandidate.possibleCBC ? "sky" : "slate"}
              />
              <MetaChip
                label="GCM"
                value={selectedCandidate.possibleGCM ? "可能" : "否"}
                color={selectedCandidate.possibleGCM ? "sky" : "slate"}
              />
            </div>
            <EvidenceActions packetId={selectedCandidate.packetId} preferredProtocol="HTTP" />

            <div className="gshark-tile border-slate-200 bg-slate-50/70 p-3">
              <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                Cookie Value
              </div>
              <div className="break-all font-mono text-xs text-slate-700">
                {selectedCandidate.cookiePreview || "--"}
              </div>
            </div>

            <NotesList
              notes={selectedCandidate.notes}
              itemClassName="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-[12px] text-slate-600"
            />
          </div>
        )}
      </div>

      <div className="gshark-tile border-slate-200 p-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="text-sm font-semibold text-slate-800">密钥测试结果</div>
          <div className="text-[11px] text-slate-500">{selectedCandidate?.keyResults?.length ?? 0} 个 key</div>
        </div>
        <div className="space-y-2">
          {(selectedCandidate?.keyResults?.length ?? 0) === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50 px-3 py-8 text-center text-[13px] text-slate-500">
              暂无可展示的密钥测试结果。
            </div>
          ) : (
            selectedCandidate!.keyResults!.map((item) => (
              <div
                key={`${item.label}-${item.base64}`}
                className={`gshark-tile p-3 ${item.hit ? "border-rose-200 bg-rose-50/70" : "border-slate-200 bg-slate-50/70"}`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  {item.hit ? (
                    <ShieldAlert className="h-4 w-4 text-rose-600" />
                  ) : (
                    <ShieldCheck className="h-4 w-4 text-slate-400" />
                  )}
                  <span className="font-mono text-xs font-semibold text-slate-800">{item.label || "custom"}</span>
                  {item.algorithm ? (
                    <span className="rounded-sm bg-slate-100 px-2 py-0.5 text-[11px] text-slate-600">
                      {item.algorithm}
                    </span>
                  ) : null}
                  {item.hit ? (
                    <span className="rounded bg-rose-100 px-2 py-0.5 text-[11px] font-semibold text-rose-700">
                      命中 Java 序列化
                    </span>
                  ) : null}
                </div>
                {item.payloadClass ? (
                  <div className="mt-2 break-all text-xs text-slate-700">Payload: {item.payloadClass}</div>
                ) : null}
                {item.preview ? (
                  <div className="mt-2 break-all font-mono text-[11px] text-slate-600">{item.preview}</div>
                ) : null}
                {!item.hit && item.reason ? (
                  <div className="mt-2 break-all text-[11px] text-slate-500">{item.reason}</div>
                ) : null}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
