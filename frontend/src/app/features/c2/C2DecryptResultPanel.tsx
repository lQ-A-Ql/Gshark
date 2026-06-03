import { Info } from "lucide-react";
import { useMemo, useState } from "react";
import { EmptyState } from "../../components/DesignSystem";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import { Button } from "../../components/ui/button";
import { cn } from "../../components/ui/utils";
import type { C2DecryptResult } from "../../core/types";
import { C2NotesPanel } from "./C2DisplayComponents";

const C2_DECRYPT_TABLE_WRAPPER_CLASS = "overflow-auto";
const C2_DECRYPT_TABLE_HEADER_CLASS = "meow-tile-header text-slate-700";
const C2_DECRYPT_TABLE_ROW_CLASS = "last:border-b-0 odd:bg-transparent even:bg-[var(--meow-table-selected-bg)]";
const C2_DECRYPT_MONO_CELL_CLASS = "font-mono text-slate-700";

export function C2DecryptResultPanel({ result }: { result: C2DecryptResult | null }) {
  const [recordQuery, setRecordQuery] = useState("");
  const filteredRecords = useMemo(() => {
    if (!result) return [];
    const query = recordQuery.trim().toLowerCase();
    if (!query) return result.records;
    return result.records.filter((record) => {
      const searchable = [
        record.plaintextPreview ?? "",
        record.error ?? "",
        record.algorithm ?? "",
        record.keyStatus ?? "",
        record.direction ?? "",
        record.packetId != null ? String(record.packetId) : "",
        record.streamId != null ? String(record.streamId) : "",
        ...(record.tags ?? []),
      ]
        .join(" ")
        .toLowerCase();
      return searchable.includes(query);
    });
  }, [recordQuery, result]);
  const visibleRecords = filteredRecords;

  if (!result) {
    return (
      <EmptyState className="text-left">
        提交 key material 后，这里会展示批量解密结果、明文预览、验证状态与失败原因。
      </EmptyState>
    );
  }

  const exportJson = () =>
    exportTextFile(`c2-decrypt-${result.family}.json`, JSON.stringify(result, null, 2), "application/json");
  const exportCsv = () => exportTextFile(`c2-decrypt-${result.family}.csv`, c2DecryptResultToCsv(result), "text/csv");

  return (
    <div className="meow-tile min-w-0 space-y-3 overflow-hidden border-slate-100 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-sm font-semibold text-slate-900">解密结果 · {result.status}</div>
          <div className="text-xs text-slate-500">
            候选 {result.totalCandidates} · 成功 {result.decryptedCount} · 失败 {result.failedCount}
          </div>
        </div>
        <div className="flex gap-2">
          <Button type="button" variant="outline" onClick={exportJson} className="meow-control h-8 text-xs">
            导出 JSON
          </Button>
          <Button type="button" variant="outline" onClick={exportCsv} className="meow-control h-8 text-xs">
            导出 CSV
          </Button>
        </div>
      </div>
      {result.notes.length > 0 ? <C2NotesPanel notes={result.notes} emptyText="" /> : null}
      {result.family === "cs" ? (
        <div className="meow-tile border-sky-100 bg-sky-50/80 px-3 py-2 text-xs leading-5 text-sky-900">
          <div className="mb-1 flex items-center gap-1.5 font-semibold">
            <Info className="h-3.5 w-3.5" />
            CS 解密阅读提示
          </div>
          <p>
            verified 表示 payload HMAC 已通过；failed 通常表示该记录是 GET metadata、心跳/空响应、profile transform
            未还原，或 Raw key 不匹配。Raw key 不是 PCAP 直接字段，通常要用 TeamServer
            <span className="font-mono"> .cobaltstrike.beacon_keys </span>/ RSA private key 解 GET Cookie/URI metadata
            后得到；POST 和 HTTP 200 才作为任务/回传密文解。
          </p>
        </div>
      ) : null}
      <div className="meow-tile-toolbar flex flex-col gap-2 p-2 sm:flex-row sm:items-center sm:justify-between">
        <label className="min-w-0 flex-1">
          <span className="sr-only">搜索解密结果</span>
          <input
            value={recordQuery}
            onChange={(event) => setRecordQuery(event.target.value)}
            className="meow-soft-fill h-9 w-full px-3 text-xs text-slate-700 outline-none focus:border-rose-300 focus:ring-4 focus:ring-rose-100"
            placeholder="搜索明文、算法、stream、packet"
          />
        </label>
        <div className="flex shrink-0 items-center justify-between gap-2 text-xs text-slate-500 sm:justify-end">
          <span>
            展示 {visibleRecords.length} / {filteredRecords.length} 条
          </span>
        </div>
      </div>
      <DataTable
        data={visibleRecords}
        rowKey={(item, index) => `${item.packetId ?? 0}-${item.streamId ?? 0}-${index}`}
        emptyText="没有匹配的解密记录"
        maxHeightClassName="max-h-[520px]"
        wrapperClassName={cn(C2_DECRYPT_TABLE_WRAPPER_CLASS, "max-w-full")}
        headerClassName={C2_DECRYPT_TABLE_HEADER_CLASS}
        tableClassName="min-w-[720px]"
        rowClassName={C2_DECRYPT_TABLE_ROW_CLASS}
        columns={[
          {
            key: "where",
            header: "Packet / Stream",
            widthClassName: "w-32",
            cellClassName: C2_DECRYPT_MONO_CELL_CLASS,
            render: (item) => (
              <>
                <div>#{item.packetId ?? "--"}</div>
                <div>stream {item.streamId ?? "--"}</div>
              </>
            ),
          },
          {
            key: "algo",
            header: "算法 / 验证",
            widthClassName: "w-44",
            render: (item) => (
              <>
                <div className="font-mono text-slate-700">{item.algorithm || "--"}</div>
                <DecryptTagLine values={[item.keyStatus || "", `conf:${item.confidence}`].filter(Boolean)} />
              </>
            ),
          },
          {
            key: "preview",
            header: "Plaintext / Error",
            cellClassName: "min-w-0 space-y-1",
            render: (item) =>
              item.error ? (
                <div className="meow-tile max-w-full overflow-auto break-words border-amber-100 bg-amber-50/70 p-2 text-amber-700">
                  {item.error}
                </div>
              ) : (
                <div className="min-w-0 space-y-1">
                  {/* Protocol badge */}
                  <ProtocolBadge tags={item.tags} algorithm={item.algorithm} />
                  <pre className="meow-tile max-h-72 max-w-full overflow-x-auto overflow-y-auto whitespace-pre-wrap break-words border-slate-700 bg-slate-900 p-3 font-mono text-xs leading-relaxed text-slate-50 shadow-inner">
                    {item.plaintextPreview || "--"}
                  </pre>
                  <DecryptTagLine
                    values={[
                      item.rawLength ? `raw:${item.rawLength}B` : "",
                      item.decryptedLength ? `dec:${item.decryptedLength}B` : "",
                      ...(item.tags ?? []).slice(0, 3),
                    ].filter(Boolean)}
                  />
                </div>
              ),
          },
        ]}
      />
    </div>
  );
}

function exportTextFile(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function c2DecryptResultToCsv(result: C2DecryptResult) {
  const rows = [
    ["packet", "stream", "time", "direction", "algorithm", "key_status", "confidence", "plaintext", "error"],
  ];
  for (const record of result.records) {
    rows.push([
      String(record.packetId ?? ""),
      String(record.streamId ?? ""),
      record.time ?? "",
      record.direction ?? "",
      record.algorithm ?? "",
      record.keyStatus ?? "",
      String(record.confidence ?? 0),
      record.plaintextPreview ?? "",
      record.error ?? "",
    ]);
  }
  return rows.map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(",")).join("\n");
}

function DecryptTagLine({ values }: { values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <span key={value} className="meow-diffuse-chip px-2 py-0.5 text-[10px] font-semibold text-slate-500">
          {value}
        </span>
      ))}
    </div>
  );
}

function ProtocolBadge({ tags, algorithm }: { tags?: string[]; algorithm?: string }) {
  const searchText = [...(tags ?? []), algorithm ?? ""].join(" ").toLowerCase();

  // Detect protocol type from tags/algorithm
  let protocol: { label: string; icon: React.ReactNode; colors: string } | null = null;

  if (searchText.includes("websocket")) {
    protocol = {
      label: "WebSocket",
      icon: (
        <svg className="h-3 w-3" fill="currentColor" viewBox="0 0 20 20">
          <path d="M2 5a2 2 0 012-2h12a2 2 0 012 2v10a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm3.293 1.293a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 01-1.414-1.414L7.586 10 5.293 7.707a1 1 0 010-1.414zM11 12a1 1 0 100 2h3a1 1 0 100-2h-3z" />
        </svg>
      ),
      colors: "bg-indigo-100 text-indigo-700",
    };
  } else if (searchText.includes("http") || searchText.includes("tshark")) {
    protocol = {
      label: "HTTP",
      icon: (
        <svg className="h-3 w-3" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M12.586 4.586a2 2 0 112.828 2.828l-3 3a2 2 0 01-2.828 0 1 1 0 00-1.414 1.414 4 4 0 005.656 0l3-3a4 4 0 00-5.656-5.656l-1.5 1.5a1 1 0 101.414 1.414l1.5-1.5zm-5 5a2 2 0 012.828 0 1 1 0 101.414-1.414 4 4 0 00-5.656 0l-3 3a4 4 0 105.656 5.656l1.5-1.5a1 1 0 10-1.414-1.414l-1.5 1.5a2 2 0 11-2.828-2.828l3-3z" clipRule="evenodd" />
        </svg>
      ),
      colors: "bg-blue-100 text-blue-700",
    };
  } else if (searchText.includes("stream") || searchText.includes("tcp")) {
    protocol = {
      label: "TCP Stream",
      icon: (
        <svg className="h-3 w-3" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clipRule="evenodd" />
        </svg>
      ),
      colors: "bg-emerald-100 text-emerald-700",
    };
  } else if (searchText.includes("dns")) {
    protocol = {
      label: "DNS",
      icon: (
        <svg className="h-3 w-3" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M5 2a1 1 0 011 1v1h1a1 1 0 010 2H6v1a1 1 0 01-2 0V6H3a1 1 0 010-2h1V3a1 1 0 011-1zm0 10a1 1 0 011 1v1h1a1 1 0 110 2H6v1a1 1 0 11-2 0v-1H3a1 1 0 110-2h1v-1a1 1 0 011-1zM12 2a1 1 0 01.967.744L14.146 7.2 17.5 9.134a1 1 0 010 1.732l-3.354 1.935-1.18 4.455a1 1 0 01-1.933 0L9.854 12.8 6.5 10.866a1 1 0 010-1.732l3.354-1.935 1.18-4.455A1 1 0 0112 2z" clipRule="evenodd" />
        </svg>
      ),
      colors: "bg-purple-100 text-purple-700",
    };
  }

  if (!protocol) return null;

  return (
    <div className={cn("mb-1 inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[10px] font-semibold", protocol.colors)}>
      {protocol.icon}
      {protocol.label}
    </div>
  );
}
