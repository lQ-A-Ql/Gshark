import { Bug, FileKey2, Info, KeyRound, Radio, Server, Shield, Unlock, Workflow } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { AnalysisHero } from "../components/AnalysisHero";
import { CaptureWelcomePanel } from "../components/CaptureWelcomePanel";
import { EmptyState, MetricCard, StatusHint } from "../components/DesignSystem";
import { AnalysisBucketChart, AnalysisList } from "../components/analysis/AnalysisPrimitives";
import { PageShell } from "../components/PageShell";
import { Button } from "../components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import type { C2DecryptRequest, C2DecryptResult, C2FamilyAnalysis } from "../core/types";
import { CSDNSAggregates, CSHostURIAggregates, VShellStreamAggregates } from "../features/c2/C2AggregateTables";
import { C2CandidateTable } from "../features/c2/C2CandidateTable";
import { C2DecryptResultPanel } from "../features/c2/C2DecryptResultPanel";
import { C2AptHandoffNotes, C2FeatureCard, C2FamilyTabButton, C2NotesPanel, C2Panel, VShellEvidenceSummaryGrid } from "../features/c2/C2DisplayComponents";
import { C2_APT_HANDOFF_NOTES, CS_EVIDENCE_CARDS, VSHELL_EVIDENCE_CARDS, buildVShellEvidenceSummary } from "../features/c2/c2EvidenceModel";
import { useC2Analysis } from "../features/c2/useC2Analysis";
import { bridge } from "../integrations/wailsBridge";
import { useSentinel } from "../state/SentinelContext";

type C2Tab = "cs" | "vshell";

export default function C2Analysis() {
  const { backendConnected, isPreloadingCapture, fileMeta, totalPackets, captureRevision } = useSentinel();
  const [activeTab, setActiveTab] = useState<C2Tab>("cs");
  const { analysis, loading, error, refreshAnalysis } = useC2Analysis({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });

  const vshellEvidenceSummary = useMemo(() => buildVShellEvidenceSummary(analysis.vshell), [analysis.vshell]);

  if (!fileMeta.path) {
    return <CaptureWelcomePanel />;
  }

  const family = activeTab === "cs" ? analysis.cs : analysis.vshell;
  const baseline = activeTab === "cs" ? CS_EVIDENCE_CARDS : VSHELL_EVIDENCE_CARDS;
  const familyLabel = activeTab === "cs" ? "CS / Cobalt Strike" : "VShell";
  const hasVShellCandidateEvidence = (analysis.vshell.candidates?.length ?? 0) > 0;

  return (
    <PageShell innerClassName="max-w-7xl px-6 py-6">
      <AnalysisHero
        icon={<Bug className="h-5 w-5" />}
        title="C2 样本分析"
        subtitle="C2 SAMPLE ANALYSIS"
        description="围绕 Cobalt Strike 与 VShell 汇总 Beacon、Listener、WebSocket、DNS、stream 聚合和 APT 归因线索；弱信号只作为复核提示，不直接包装成强结论。"
        tags={["Cobalt Strike", "VShell", "Beacon", "Tunnel"]}
        tagsLabel="样本域"
        theme="rose"
        onRefresh={() => refreshAnalysis(true)}
      />

      {loading && <StatusHint tone="rose" className="mb-3">正在加载 C2 样本分析...</StatusHint>}

      {!loading && error && <StatusHint tone="amber" className="mb-3">{error}</StatusHint>}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <MetricCard label="命中包" value={analysis.totalMatchedPackets.toLocaleString()} icon={<Shield className="h-4 w-4" />} tone="rose" />
        <MetricCard label="CS 候选" value={analysis.cs.candidateCount.toLocaleString()} icon={<Radio className="h-4 w-4" />} tone="blue" />
        <MetricCard label="VShell 候选" value={analysis.vshell.candidateCount.toLocaleString()} icon={<Server className="h-4 w-4" />} tone="cyan" />
        <MetricCard label="归因线索" value={String((analysis.cs.relatedActors?.length ?? 0) + (analysis.vshell.relatedActors?.length ?? 0))} icon={<Workflow className="h-4 w-4" />} tone="amber" />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title="Family 分布">
          <AnalysisBucketChart data={analysis.families} emptyText="当前抓包未形成 CS / VShell 命中，家族分布会在出现可复核候选后汇总。" barClassName="bg-rose-500" labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]" />
        </C2Panel>
        <C2Panel title="会话概览">
          <AnalysisList items={analysis.conversations.map((item) => ({ label: item.protocol ? `${item.protocol} · ${item.label}` : item.label, count: item.count }))} emptyText="当前抓包未形成 C2 会话聚合；命中后会按 Host / URI / Channel / stream 归并候选通信。" />
        </C2Panel>
      </div>

      <div className="mt-4 rounded-[28px] border border-white/80 bg-white/90 p-2 shadow-[0_24px_80px_-54px_rgba(15,23,42,0.45)] backdrop-blur">
        <div className="grid gap-2 md:grid-cols-2">
          <C2FamilyTabButton active={activeTab === "cs"} onClick={() => setActiveTab("cs")} icon={<Radio className="h-4 w-4" />} title="CS" description="HTTP/HTTPS、DNS、SMB Beacon 证据聚合" />
          <C2FamilyTabButton active={activeTab === "vshell"} onClick={() => setActiveTab("vshell")} icon={<Server className="h-4 w-4" />} title="VShell" description="TCP、WebSocket、DNS/DoH/DoT listener 证据聚合" />
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-4">
        <MetricCard label={`${familyLabel} 候选`} value={family.candidateCount.toLocaleString()} />
        <MetricCard label="规则位" value={family.matchedRuleCount.toLocaleString()} />
        <MetricCard label="通道种类" value={String(family.channels.length)} />
        <MetricCard label="周期画像" value={String(family.beaconPatterns?.length ?? 0)} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        {baseline.map((item) => (
          <C2FeatureCard key={item.title} title={item.title} text={item.text} />
        ))}
      </div>

      {activeTab === "vshell" && (
        <>
          {hasVShellCandidateEvidence ? (
            <StatusHint tone="cyan" className="mt-4">
              已形成 VShell candidates 候选证据；摘要卡片会并列融合 stream 聚合与候选弱信号，短长包、心跳、listener hint 仍需结合候选证据表人工复核。
            </StatusHint>
          ) : null}
          <VShellEvidenceSummaryGrid items={vshellEvidenceSummary} />
        </>
      )}

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title={`${familyLabel} Channel 分布`}>
          <AnalysisBucketChart data={family.channels} emptyText="当前抓包未形成可复核 channel 命中。" barClassName={activeTab === "cs" ? "bg-rose-500" : "bg-cyan-500"} labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]" />
        </C2Panel>
        <C2Panel title={`${familyLabel} 指标类型`}>
          <AnalysisBucketChart data={family.indicators} emptyText="当前抓包未形成 indicator 统计；低置信观察会保留在候选证据表中复核。" barClassName="bg-indigo-500" labelWidthClassName="grid-cols-[minmax(0,1fr)_minmax(96px,1.2fr)_72px]" />
        </C2Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title="Beacon / Heartbeat 模式">
          <BeaconPatternList family={activeTab} patterns={family.beaconPatterns ?? []} />
        </C2Panel>
        <C2Panel title="APT 兼容扩展口">
          <C2AptHandoffNotes notes={C2_APT_HANDOFF_NOTES} />
        </C2Panel>
      </div>

      {activeTab === "cs" && (
        <C2Panel title="CS Host / URI 聚合画像" className="mt-4">
          <CSHostURIAggregates items={analysis.cs.hostUriAggregates ?? []} />
        </C2Panel>
      )}

      {activeTab === "cs" && (
        <C2Panel title="CS DNS Beacon 聚合画像" className="mt-4">
          <CSDNSAggregates items={analysis.cs.dnsAggregates ?? []} />
        </C2Panel>
      )}

      {activeTab === "vshell" && (
        <C2Panel title="VShell Stream 聚合画像" className="mt-4">
          <VShellStreamAggregates items={analysis.vshell.streamAggregates ?? []} />
        </C2Panel>
      )}

      <C2Panel title="流量解密工作台" className="mt-4">
        <C2DecryptWorkbench family={activeTab} familyAnalysis={family} captureRevision={captureRevision} />
      </C2Panel>

      <C2Panel title={`${familyLabel} 候选证据表`} className="mt-4">
        <C2CandidateTable candidates={family.candidates} />
      </C2Panel>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <C2Panel title={`${familyLabel} Notes`}>
          <C2NotesPanel notes={family.notes} emptyText="当前 family 暂无补充说明；命中后会输出强信号、中弱信号与样本特别说明。" />
        </C2Panel>
        <C2Panel title="全局 Notes">
          <C2NotesPanel notes={analysis.notes} emptyText="当前抓包暂未生成全局说明。" />
        </C2Panel>
      </div>
    </PageShell>
  );
}

function C2DecryptWorkbench({ family, familyAnalysis, captureRevision }: { family: C2Tab; familyAnalysis: C2FamilyAnalysis; captureRevision: number }) {
  const [vshellVKey, setVShellVKey] = useState("");
  const [vshellSalt, setVShellSalt] = useState("");
  const [vshellMode, setVShellMode] = useState<NonNullable<NonNullable<C2DecryptRequest["vshell"]>["mode"]>>("auto");
  const [csKeyMode, setCSKeyMode] = useState<NonNullable<NonNullable<C2DecryptRequest["cs"]>["keyMode"]>>("aes_hmac");
  const [csAESKey, setCSAESKey] = useState("");
  const [csHMACKey, setCSHMACKey] = useState("");
  const [csAESRand, setCSAESRand] = useState("");
  const [csRSAPrivateKey, setCSRSAPrivateKey] = useState("");
  const [csTransformMode, setCSTransformMode] = useState<NonNullable<NonNullable<C2DecryptRequest["cs"]>["transformMode"]>>("auto");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<C2DecryptResult | null>(null);

  useEffect(() => {
    setResult(null);
    setError("");
    setLoading(false);
  }, [family, captureRevision]);

  const candidateCount = (familyAnalysis.candidates?.length ?? 0)
    + (familyAnalysis.streamAggregates?.length ?? 0)
    + (familyAnalysis.hostUriAggregates?.length ?? 0);
  const hasCandidates = candidateCount > 0;

  async function runDecrypt() {
    setError("");
    if (!hasCandidates) {
      setError("当前无可解密候选流量。");
      return;
    }
    const request: C2DecryptRequest = {
      family,
      scope: { useCandidates: true, useAggregates: true },
    };
    if (family === "vshell") {
      if (!vshellSalt.trim()) {
        setError("VShell 解密需要输入 salt；vkey 用于验证，不作为默认 AES key。");
        return;
      }
      request.vshell = { vkey: vshellVKey, salt: vshellSalt, mode: vshellMode };
    } else if (csKeyMode === "aes_hmac") {
      if (!csAESKey.trim()) {
        setError("CS AES/HMAC 模式至少需要 AES key。");
        return;
      }
      request.cs = { keyMode: csKeyMode, aesKey: csAESKey, hmacKey: csHMACKey, transformMode: csTransformMode };
    } else if (csKeyMode === "aes_rand") {
      if (!csAESRand.trim()) {
        setError("CS AES rand 模式需要 16-byte AES rand。");
        return;
      }
      request.cs = { keyMode: csKeyMode, aesRand: csAESRand, transformMode: csTransformMode };
    } else {
      if (!csRSAPrivateKey.trim()) {
        setError("CS RSA private key 模式需要 Team Server RSA private key PEM。");
        return;
      }
      request.cs = { keyMode: csKeyMode, rsaPrivateKey: csRSAPrivateKey, transformMode: csTransformMode };
    }
    setLoading(true);
    try {
      const next = await bridge.decryptC2Traffic(request);
      setResult(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : "C2 流量解密失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-slate-100 bg-slate-50/70 px-4 py-3 text-xs leading-6 text-slate-600">
        解密结果仅作为衍生视图展示，不覆盖原始 payload，不写回 packet store，也不改变 C2 detection 结果。当前候选来源：candidates / aggregates / 关联 stream 与 packet。
      </div>
      {!hasCandidates ? (
        <EmptyState className="text-left">当前无可解密候选流量；请先确认 {family === "cs" ? "CS" : "VShell"} 已形成 candidates 或聚合画像。</EmptyState>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
          <div className="space-y-3 rounded-2xl border border-slate-100 bg-white p-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <KeyRound className="h-4 w-4 text-rose-500" />
              {family === "cs" ? "CS keyed offline decrypt" : "VShell vkey / salt decrypt"}
            </div>
            {family === "vshell" ? (
              <div className="space-y-3">
                <LabeledInput label="vkey（验证用，可空）" value={vshellVKey} onChange={setVShellVKey} placeholder="VerifyKey / VKey" />
                <LabeledInput label="salt（必填）" value={vshellSalt} onChange={setVShellSalt} placeholder="qwe123qwe" />
                <LabeledSelect label="模式" value={vshellMode} onChange={(value) => setVShellMode(value as typeof vshellMode)} options={[
                  ["auto", "auto：三 KDF + GCM/CBC 自动尝试"],
                  ["aes_gcm_md5_salt", "AES-GCM / 三 KDF"],
                  ["aes_cbc_md5_salt", "AES-CBC / 三 KDF"],
                ]} />
              </div>
            ) : (
              <div className="space-y-3">
                <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-xs leading-5 text-amber-900">
                  <div className="mb-1 flex items-center gap-1.5 font-semibold">
                    <Info className="h-3.5 w-3.5" />
                    Raw key 来源说明
                  </div>
                  <p>CS Raw key 通常不是从 PCAP 直接算出。PCAP 只能提供 GET Cookie/URI 中的 RSA-encrypted metadata；需要 TeamServer 的 <span className="font-mono">.cobaltstrike.beacon_keys</span> 或 RSA private key 解 metadata 后恢复 Raw key，再派生 AES/HMAC 解 POST 与 200 response。</p>
                </div>
                <LabeledSelect label="Key material" value={csKeyMode} onChange={(value) => setCSKeyMode(value as typeof csKeyMode)} options={[
                  ["aes_hmac", "AES/HMAC keys"],
                  ["aes_rand", "Raw key / AES rand 派生"],
                  ["rsa_private_key", "RSA private key 恢复 Raw key"],
                ]} />
                {csKeyMode === "aes_hmac" ? (
                  <KeyModeHint icon="AES/HMAC">
                    直接输入已知 session AES key/HMAC key。未填 HMAC key 时只能尝试 AES-CBC，结果会标记为 unverified。
                  </KeyModeHint>
                ) : null}
                {csKeyMode === "aes_rand" ? (
                  <KeyModeHint icon="Raw">
                    输入 cs-decrypt-metadata.py 这类工具输出的 Raw key。后端会按 SHA256(Raw key) 派生 AES/HMAC，只解 POST 与 HTTP 200 响应候选。
                  </KeyModeHint>
                ) : null}
                {csKeyMode === "rsa_private_key" ? (
                  <KeyModeHint icon="RSA">
                    输入 TeamServer RSA private key PEM。后端会优先尝试 GET Cookie/URI metadata，恢复 Raw key 后再解任务/回传。
                  </KeyModeHint>
                ) : null}
                {csKeyMode === "aes_hmac" && (
                  <>
                    <LabeledInput label="AES key" value={csAESKey} onChange={setCSAESKey} placeholder="hex / base64 / raw" />
                    <LabeledInput label="HMAC key（可空）" value={csHMACKey} onChange={setCSHMACKey} placeholder="hex / base64 / raw" />
                  </>
                )}
                {csKeyMode === "aes_rand" && <LabeledInput label="Raw key / AES rand" value={csAESRand} onChange={setCSAESRand} placeholder="16-byte hex / base64 / raw，例如 a4553a..." />}
                {csKeyMode === "rsa_private_key" && (
                  <label className="block text-xs">
                    <span className="mb-1 block font-semibold text-slate-600">RSA private key PEM</span>
                    <textarea value={csRSAPrivateKey} onChange={(event) => setCSRSAPrivateKey(event.target.value)} className="min-h-28 w-full rounded-xl border border-slate-200 bg-white px-3 py-2 font-mono text-[11px] text-slate-700 outline-none focus:border-rose-300 focus:ring-4 focus:ring-rose-100" placeholder="-----BEGIN RSA PRIVATE KEY-----" />
                  </label>
                )}
                <LabeledSelect label="Transform" value={csTransformMode} onChange={(value) => setCSTransformMode(value as typeof csTransformMode)} options={[
                  ["auto", "auto"],
                  ["raw", "raw"],
                  ["base64", "base64"],
                  ["base64url", "base64url"],
                  ["netbios", "netbios"],
                  ["netbiosu", "netbiosu"],
                ]} />
              </div>
            )}
            {error ? <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-xs font-medium text-amber-800">{error}</div> : null}
            <Button type="button" onClick={runDecrypt} disabled={loading} className="h-9 gap-2 bg-rose-600 text-xs text-white hover:bg-rose-700">
              <Unlock className="h-3.5 w-3.5" />
              {loading ? "正在解密..." : "批量解密候选流量"}
            </Button>
          </div>
          <C2DecryptResultPanel result={result} />
        </div>
      )}
    </div>
  );
}

function LabeledInput({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string }) {
  return (
    <label className="block text-xs">
      <span className="mb-1 block font-semibold text-slate-600">{label}</span>
      <input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className="h-9 w-full rounded-xl border border-slate-200 bg-white px-3 font-mono text-[11px] text-slate-700 outline-none focus:border-rose-300 focus:ring-4 focus:ring-rose-100" />
    </label>
  );
}

function KeyModeHint({ icon, children }: { icon: string; children: ReactNode }) {
  return (
    <div className="flex gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs leading-5 text-slate-600">
      <FileKey2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-500" />
      <div><span className="font-semibold text-slate-800">{icon}</span>：{children}</div>
    </div>
  );
}

function LabeledSelect({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: Array<[string, string]> }) {
  return (
    <div className="block text-xs">
      <div className="mb-1 block font-semibold text-slate-600">{label}</div>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger aria-label={label}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map(([optionValue, optionLabel]) => (
            <SelectItem key={optionValue} value={optionValue}>{optionLabel}</SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function BeaconPatternList({ family, patterns }: { family: C2Tab; patterns: NonNullable<C2FamilyAnalysis["beaconPatterns"]> }) {
  if (patterns.length === 0) {
    return (
      <div className="rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-6 text-xs leading-6 text-slate-500">
        {family === "cs"
          ? "当前抓包未形成 CS sleep / jitter / DNS beacon / SMB pivot 行为画像。"
          : "当前抓包未形成 VShell TCP 心跳、短长包交替、WebSocket 参数或 listener presence 行为画像。"}
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {patterns.map((item) => (
        <div key={`${item.name}-${item.value}`} className="rounded-2xl border border-slate-100 bg-slate-50/70 px-3 py-2 text-xs">
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
