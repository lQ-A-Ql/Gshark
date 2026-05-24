import { Bot, Copy, RefreshCw } from "lucide-react";

import type { MCPStatus } from "../core/types";
import { RuntimeSettingsSectionShell, RuntimeSettingsSectionTitle } from "./RuntimeSettingsSectionShell";

type InfoCardTone = "default" | "ok" | "muted";

type MCPSettingsSectionProps = {
  backendConnected: boolean;
  busy: boolean;
  mcpBusy: boolean;
  mcpStatus: MCPStatus | null;
  mcpNotice: string;
  authToken: string;
  tokenAvailable: boolean;
  tokenBusy: boolean;
  onRefresh: () => void;
  onToggleEnabled: (enabled: boolean) => void;
  onCopyEndpoint: () => void;
  onCopyToken: () => void;
};

export function MCPSettingsSection({
  backendConnected,
  busy,
  mcpBusy,
  mcpStatus,
  mcpNotice,
  authToken,
  tokenAvailable,
  tokenBusy,
  onRefresh,
  onToggleEnabled,
  onCopyEndpoint,
  onCopyToken,
}: MCPSettingsSectionProps) {
  const enabled = Boolean(mcpStatus?.config.enabled);
  const endpoint = mcpStatus?.endpoint || "http://127.0.0.1:17891/api/mcp";
  const statusText = !backendConnected ? "后端未连接" : mcpStatus?.enabled ? "本地 MCP 已启用" : "本地 MCP 已关闭";
  const transportText = mcpStatus?.transport || "streamable-http";
  const tokenPreview = authToken ? maskToken(authToken) : "桌面 token 暂不可用";
  const stateCards: Array<{ label: string; value: string; tone?: InfoCardTone }> = [
    { label: "运行状态", value: statusText, tone: mcpStatus?.enabled ? "ok" : "muted" },
    { label: "传输层", value: transportText },
    { label: "鉴权要求", value: mcpStatus?.authRequired ? "Bearer token" : "未启用" },
    { label: "访问范围", value: "仅本机 loopback" },
    { label: "写入能力", value: mcpStatus?.readOnly ? "只读分析" : "未知" },
    {
      label: "远程 / stdio",
      value: `${mcpStatus?.remoteSupported ? "remote:on" : "remote:off"} / ${mcpStatus?.stdioSupported ? "stdio:on" : "stdio:off"}`,
    },
  ];

  return (
    <RuntimeSettingsSectionShell>
      <RuntimeSettingsSectionTitle Icon={Bot} iconClassName="bg-emerald-50 text-emerald-600">
        MCP 本地接口
      </RuntimeSettingsSectionTitle>

      <div className="flex items-center justify-between rounded-sm border border-slate-200 bg-slate-50 px-3 py-2.5">
        <div>
          <div className="text-xs font-semibold text-slate-800">启用本机只读 MCP</div>
          <div className="mt-0.5 text-[11px] text-slate-500">
            仅监听 127.0.0.1，复用当前后端 bearer token，不提供远程绑定和 stdio bridge。
          </div>
        </div>
        <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700">
          <input
            type="checkbox"
            checked={enabled}
            disabled={!backendConnected || busy || mcpBusy}
            onChange={(event) => onToggleEnabled(event.target.checked)}
          />
          已启用
        </label>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {stateCards.map((card) => (
          <InfoCard key={card.label} label={card.label} value={card.value} tone={card.tone} />
        ))}
      </div>

      <CopyValueCard
        label="MCP 端点"
        value={endpoint}
        buttonLabel="复制端点"
        disabled={!backendConnected}
        onCopy={onCopyEndpoint}
      />
      <CopyValueCard
        label="Bearer Token"
        value={tokenPreview}
        buttonLabel="复制 Token"
        disabled={!tokenAvailable || tokenBusy}
        onCopy={onCopyToken}
      />

      {mcpStatus?.lastError ? (
        <div className="rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-[11px] leading-5 text-rose-700">
          最近错误：<span className="break-all">{mcpStatus.lastError}</span>
        </div>
      ) : null}

      {mcpNotice ? (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-[11px] leading-5 text-emerald-700">
          {mcpNotice}
        </div>
      ) : null}

      <div className="flex justify-end">
        <button
          type="button"
          onClick={onRefresh}
          disabled={!backendConnected || mcpBusy}
          className="gshark-control inline-flex h-9 items-center gap-2 px-3 text-xs font-medium text-slate-700 transition disabled:cursor-not-allowed disabled:opacity-60"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${mcpBusy ? "animate-spin" : ""}`} />
          刷新 MCP 状态
        </button>
      </div>
    </RuntimeSettingsSectionShell>
  );
}

function InfoCard({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: string;
  tone?: InfoCardTone;
}) {
  const toneClass =
    tone === "ok"
      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
      : tone === "muted"
        ? "border-slate-200 bg-slate-50 text-slate-600"
        : "border-slate-200 bg-white text-slate-700";
  return (
    <div className={`rounded-xl border px-3 py-2 ${toneClass}`}>
      <div className="text-[11px] font-semibold uppercase tracking-[0.14em]">{label}</div>
      <div className="mt-1 break-all text-xs leading-5">{value}</div>
    </div>
  );
}

type CopyValueCardProps = {
  label: string;
  value: string;
  buttonLabel: string;
  disabled: boolean;
  onCopy: () => void;
};

function CopyValueCard({ label, value, buttonLabel, disabled, onCopy }: CopyValueCardProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white px-3 py-3">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-xs font-semibold text-slate-800">{label}</div>
          <div className="mt-1 break-all text-[11px] leading-5 text-slate-600">{value}</div>
        </div>
        <button
          type="button"
          onClick={onCopy}
          disabled={disabled}
          className="gshark-control inline-flex h-9 items-center gap-2 px-3 text-xs font-medium text-slate-700 transition disabled:cursor-not-allowed disabled:opacity-60"
        >
          <Copy className="h-3.5 w-3.5" />
          {buttonLabel}
        </button>
      </div>
    </div>
  );
}

function maskToken(token: string): string {
  const trimmed = token.trim();
  if (trimmed.length <= 10) return trimmed;
  return `${trimmed.slice(0, 6)}...${trimmed.slice(-4)}`;
}
