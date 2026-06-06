import { EmptyState, StatusHint, SurfacePanel } from "../../components/DesignSystem";
import { AnalysisBadge } from "../../components/analysis/AnalysisPrimitives";
import { EvidenceActions } from "../../misc/EvidenceActions";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import {
  confidenceLabel,
  evidenceFamilyLabel,
  evidenceIocLabel,
  evidenceLocationValue,
  evidencePlaybookLabel,
  evidenceProtocolLabel,
  evidenceRuleLabel,
  evidenceSourceTypeLabel,
  evidenceVersionLabel,
  hasValidPacketId,
  hasValidStreamId,
  missingEvidenceContext,
  moduleLabel,
  severityLabel,
  severityTone,
} from "./evidencePanelRules";
import { DetailSection, FieldGrid, MetadataBlock } from "./EvidenceDetailFields";

export function EvidenceDetailPanel({ record }: { record: UnifiedEvidenceRecord | null }) {
  if (!record) {
    return (
      <SurfacePanel title="详细面板" description="选择一条证据后查看完整上下文。" className="h-full" bodyClassName="p-0">
        <EmptyState>当前没有可选证据，详情面板保持空白且不会生成虚构记录。</EmptyState>
      </SurfacePanel>
    );
  }

  const familyLabel = evidenceFamilyLabel(record);
  const showActions = hasValidPacketId(record.packetId) || (hasValidPacketId(record.packetId) && hasValidStreamId(record.streamId));

  return (
    <SurfacePanel
      title={record.displayName || record.summary}
      description={`${moduleLabel(record.module)} / ${record.sourceType}`}
      className="h-full"
      bodyClassName="space-y-3"
      actions={<AnalysisBadge tone={severityTone(record.severity)}>{severityLabel(record.severity)}</AnalysisBadge>}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="meow-diffuse-chip px-2 py-1 text-[10px] font-semibold text-slate-600">ID {record.id}</span>
        <span className="meow-diffuse-chip px-2 py-1 text-[10px] font-semibold text-slate-600">
          {record.confidence != null ? `confidence ${record.confidence}%` : `confidence ${confidenceLabel(record.confidenceLabel)}`}
        </span>
        {(record.tags ?? []).slice(0, 4).map((tag) => (
          <span key={tag} className="meow-diffuse-chip px-2 py-1 text-[10px] text-slate-500">{tag}</span>
        ))}
      </div>
      <MissingContextNotice record={record} />
      <DetailSection title="Overview">
        <FieldGrid fields={[
          ["摘要", record.summary], ["显示名", record.displayName], ["模块", moduleLabel(record.module)],
          ["来源类型", evidenceSourceTypeLabel(record.sourceType)], ["特征", record.feature], ["实体", record.entityType],
          ["WebShell family", familyLabel], ["version unavailable", evidenceVersionLabel(record)],
          ["协议", evidenceProtocolLabel(record)], ["值", record.value],
        ]} />
      </DetailSection>
      <DetailSection title="Context">
        <FieldGrid fields={[
          ["Packet ID", record.packetId != null ? String(record.packetId) : undefined],
          ["Stream ID", record.streamId != null ? String(record.streamId) : undefined],
          ["Host / URI", record.host || record.uri ? evidenceLocationValue(record) : undefined],
          ["Source", record.source], ["Destination", record.destination], ["Source Module", record.sourceModule],
          ["JA3", record.ja3Hash], ["JA3S", record.ja3sHash], ["IOC", evidenceIocLabel(record)],
          ["Tags", record.tags.length > 0 ? record.tags.join(", ") : undefined],
        ]} />
      </DetailSection>
      <DetailSection title="Detection">
        <FieldGrid fields={[
          ["Rule", evidenceRuleLabel(record)], ["Playbook", evidencePlaybookLabel(record)],
          ["置信标签", confidenceLabel(record.confidenceLabel)], ["Severity", severityLabel(record.severity)],
        ]} />
        <MetadataBlock metadata={record.metadata} />
      </DetailSection>
      <DetailSection title="Actions">
        <EvidenceRecordActions record={record} showActions={showActions} />
      </DetailSection>
    </SurfacePanel>
  );
}

function MissingContextNotice({ record }: { record: UnifiedEvidenceRecord }) {
  const missingContext = missingEvidenceContext(record);
  if (missingContext.length === 0) return null;
  return <StatusHint tone="amber">当前记录仅提供部分调查上下文: {missingContext.join("；")}。</StatusHint>;
}

function EvidenceRecordActions({ record, showActions }: { record: UnifiedEvidenceRecord; showActions: boolean }) {
  return (
    <div className="space-y-3">
      {showActions ? <EvidenceActions packetId={record.packetId} streamId={record.streamId} preferredProtocol="TCP" /> : null}
      {!showActions ? <div className="text-xs text-slate-500">当前记录未提供有效的包号或关联流 ID，因此不显示跳转操作。</div> : null}
      {record.caveats.length > 0 ? (
        <div className="space-y-1.5">
          {record.caveats.map((caveat) => (
            <div key={caveat} className="meow-soft-fill px-3 py-2 text-xs leading-5 text-amber-800">{caveat}</div>
          ))}
        </div>
      ) : (
        <div className="text-xs text-slate-500">当前记录没有额外 caveat。</div>
      )}
    </div>
  );
}
