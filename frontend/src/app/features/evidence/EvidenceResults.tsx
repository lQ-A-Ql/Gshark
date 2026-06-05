import type { ReactNode } from "react";
import { AlertCircle } from "lucide-react";
import { EmptyState, StatusHint, SurfacePanel } from "../../components/DesignSystem";
import { AnalysisBadge, AnalysisDataTable } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import { EvidenceActions } from "../../misc/EvidenceActions";
import type { EvidenceMetadataValue } from "../../core/evidenceTypes";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import {
  confidenceColor,
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

interface EvidenceStatusMessageProps {
  error: string | null;
  loading: boolean;
  onRetry?: () => void;
}

export function EvidenceStatusMessage({ error, loading, onRetry }: EvidenceStatusMessageProps) {
  if (loading) {
    return (
      <div className="meow-tile mb-3 border-indigo-100 bg-indigo-50/60 px-3 py-2.5 text-xs font-medium text-slate-500">
        正在聚合跨模块证据...
      </div>
    );
  }

  if (error) {
    return (
      <div className="meow-tile mb-3 flex items-center gap-2 border-amber-200 bg-amber-50/80 px-3 py-2.5 text-xs text-amber-700">
        <span>{error}</span>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="ml-auto shrink-0 rounded border border-amber-300 px-2 py-0.5 text-xs font-medium text-amber-700 hover:bg-amber-100"
          >
            重试
          </button>
        )}
      </div>
    );
  }

  return null;
}

interface EvidenceTableProps {
  loading: boolean;
  records: UnifiedEvidenceRecord[];
  selectedId: string | null;
  onSelect: (recordId: string) => void;
}

export function EvidenceTable({ loading, records, selectedId, onSelect }: EvidenceTableProps) {
  return (
    <AnalysisDataTable
      columns={[
        {
          key: "severity",
          header: "等级",
          widthClassName: "w-20",
          render: (item) => (
            <AnalysisBadge tone={severityTone(item.severity)}>{severityLabel(item.severity)}</AnalysisBadge>
          ),
        },
        {
          key: "module",
          header: "模块 / 类型",
          widthClassName: "w-32",
          render: (item) => (
            <div className="min-w-0">
              <div className="text-[11px] font-semibold text-slate-700">{moduleLabel(item.module)}</div>
              <div className="truncate font-mono text-[10px] text-slate-500">{item.sourceType || "--"}</div>
            </div>
          ),
        },
        {
          key: "summary",
          header: "调查摘要",
          render: (item) => (
            <div className="min-w-0">
              <div className="truncate text-[13px] font-medium text-slate-900">{item.summary || "--"}</div>
              <div className="mt-0.5 truncate text-[11px] text-slate-500">
                {item.value || evidenceLocationValue(item)}
              </div>
            </div>
          ),
        },
        {
          key: "context",
          header: "上下文",
          widthClassName: "w-44",
          render: (item) => (
            <div className="space-y-0.5 text-[11px] text-slate-500">
              <div>{item.feature || item.entityType || "--"}</div>
              <div className="font-mono">
                pkt {item.packetId ?? "--"} / str {item.streamId ?? "--"}
              </div>
            </div>
          ),
        },
        {
          key: "confidence",
          header: "置信",
          widthClassName: "w-20",
          render: (item) => (
            <div className="space-y-0.5 text-[11px]">
              <div
                className={cn(
                  "font-semibold",
                  item.confidence != null ? confidenceColor(item.confidence) : "text-slate-400",
                )}
              >
                {item.confidence != null ? `${item.confidence}%` : "--"}
              </div>
              <div className="text-slate-400">{confidenceLabel(item.confidenceLabel)}</div>
            </div>
          ),
        },
      ]}
      data={records}
      rowKey={(item) => item.id}
      onRowClick={(item) => onSelect(item.id)}
      rowClassName={(item) =>
        cn(
          "border-l-2 border-l-transparent",
          selectedId === item.id && "border-l-indigo-400 bg-[var(--meow-table-selected-bg)]",
        )
      }
      maxHeightClassName="max-h-[720px]"
      tableClassName="min-w-[760px]"
      emptyText={loading ? "正在加载..." : "当前抓包未产生证据记录"}
    />
  );
}

interface EvidenceDetailPanelProps {
  record: UnifiedEvidenceRecord | null;
}

export function EvidenceDetailPanel({ record }: EvidenceDetailPanelProps) {
  if (!record) {
    return (
      <SurfacePanel
        title="详细面板"
        description="选择一条证据后查看完整上下文。"
        className="h-full"
        bodyClassName="p-0"
      >
        <EmptyState>当前没有可选证据，详情面板保持空白且不会生成虚构记录。</EmptyState>
      </SurfacePanel>
    );
  }

  const missingContext = missingEvidenceContext(record);
  const familyLabel = evidenceFamilyLabel(record);
  const versionLabel = evidenceVersionLabel(record);
  const protocolLabel = evidenceProtocolLabel(record);
  const iocLabel = evidenceIocLabel(record);
  const playbookLabel = evidencePlaybookLabel(record);
  const ruleLabel = evidenceRuleLabel(record);
  const sourceTypeLabel = evidenceSourceTypeLabel(record.sourceType);
  const hasPacketAction = hasValidPacketId(record.packetId);
  const hasStreamAction = hasValidPacketId(record.packetId) && hasValidStreamId(record.streamId);
  const showActions = hasPacketAction || hasStreamAction;

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
          {record.confidence != null
            ? `confidence ${record.confidence}%`
            : `confidence ${confidenceLabel(record.confidenceLabel)}`}
        </span>
        {(record.tags ?? []).slice(0, 4).map((tag) => (
          <span key={tag} className="meow-diffuse-chip px-2 py-1 text-[10px] text-slate-500">
            {tag}
          </span>
        ))}
      </div>

      {missingContext.length > 0 ? (
        <StatusHint tone="amber">当前记录仅提供部分调查上下文: {missingContext.join("；")}。</StatusHint>
      ) : null}

      <DetailSection title="Overview">
        <FieldGrid
          fields={[
            ["摘要", record.summary],
            ["显示名", record.displayName],
            ["模块", moduleLabel(record.module)],
            ["来源类型", sourceTypeLabel],
            ["特征", record.feature],
            ["实体", record.entityType],
            ["WebShell family", familyLabel],
            ["version unavailable", versionLabel],
            ["协议", protocolLabel],
            ["值", record.value],
          ]}
        />
      </DetailSection>

      <DetailSection title="Context">
        <FieldGrid
          fields={[
            ["Packet ID", record.packetId != null ? String(record.packetId) : undefined],
            ["Stream ID", record.streamId != null ? String(record.streamId) : undefined],
            ["Host / URI", record.host || record.uri ? evidenceLocationValue(record) : undefined],
            ["Source", record.source],
            ["Destination", record.destination],
            ["Source Module", record.sourceModule],
            ["JA3", record.ja3Hash],
            ["JA3S", record.ja3sHash],
            ["IOC", iocLabel],
            ["Tags", record.tags.length > 0 ? record.tags.join(", ") : undefined],
          ]}
        />
      </DetailSection>

      <DetailSection title="Detection">
        <FieldGrid
          fields={[
            ["Rule", ruleLabel],
            ["Playbook", playbookLabel],
            ["置信标签", confidenceLabel(record.confidenceLabel)],
            ["Severity", severityLabel(record.severity)],
          ]}
        />
        <MetadataBlock metadata={record.metadata} />
      </DetailSection>

      <DetailSection title="Actions">
        <div className="space-y-3">
          {showActions ? (
            <EvidenceActions packetId={record.packetId} streamId={record.streamId} preferredProtocol="TCP" />
          ) : null}
          {!showActions ? (
            <div className="text-xs text-slate-500">当前记录未提供有效的包号或关联流 ID，因此不显示跳转操作。</div>
          ) : null}
          {record.caveats.length > 0 ? (
            <div className="space-y-1.5">
              {record.caveats.map((caveat) => (
                <div key={caveat} className="meow-soft-fill px-3 py-2 text-xs leading-5 text-amber-800">
                  {caveat}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-500">当前记录没有额外 caveat。</div>
          )}
        </div>
      </DetailSection>
    </SurfacePanel>
  );
}

function DetailSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">{title}</div>
      <div className="meow-soft-fill space-y-2 px-3 py-3">{children}</div>
    </section>
  );
}

function FieldGrid({ fields }: { fields: Array<[string, string | undefined]> }) {
  return (
    <div className="grid gap-2 md:grid-cols-2">
      {fields.map(([label, value]) => (
        <div key={label} className="min-w-0">
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">{label}</div>
          <div className="break-words text-xs leading-5 text-slate-700">{value && value.trim() ? value : "--"}</div>
        </div>
      ))}
    </div>
  );
}

function MetadataBlock({ metadata }: { metadata?: UnifiedEvidenceRecord["metadata"] }) {
  const entries = Object.entries(metadata ?? {});
  if (entries.length === 0) {
    return <div className="text-xs text-slate-500">元数据未提供。</div>;
  }

  return (
    <div className="grid gap-2 md:grid-cols-2">
      {entries.map(([key, value]) => (
        <div key={key} className="min-w-0">
          <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">{key}</div>
          <div className="break-words text-xs leading-5 text-slate-700">{formatMetadataValue(value)}</div>
        </div>
      ))}
    </div>
  );
}

function formatMetadataValue(value: EvidenceMetadataValue) {
  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(", ") : "--";
  }
  if (value == null || value === "") return "--";
  return String(value);
}

export function EvidenceDetailEmptyNotice() {
  return (
    <div className="meow-soft-fill flex items-start gap-2 px-3 py-2 text-xs text-slate-500">
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
      详情面板仅展示当前证据实际提供的字段，缺失内容会显示 `--` 或提示未提供。
    </div>
  );
}
