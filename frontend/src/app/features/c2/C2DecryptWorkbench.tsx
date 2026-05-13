/**
 * Stability: experimental
 *
 * The C2 decryption workbench covers VShell (triple-KDF) and Cobalt Strike
 * keyed offline paths. Decryption heuristics have been validated against
 * public reference samples but may produce false positives or fail on novel
 * loaders. Expect input fields and backend contract to evolve; treat decrypt
 * output as advisory evidence rather than authoritative.
 */
import { KeyRound, Unlock } from "lucide-react";
import { useEffect, useState } from "react";
import { EmptyState } from "../../components/DesignSystem";
import { Button } from "../../components/ui/button";
import type { C2DecryptRequest, C2DecryptResult, C2FamilyAnalysis } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import { CSDecryptForm, VShellDecryptForm } from "./C2DecryptFormControls";
import { C2DecryptResultPanel } from "./C2DecryptResultPanel";

export type C2Tab = "cs" | "vshell";

export function C2DecryptWorkbench({
  family,
  familyAnalysis,
  captureRevision,
}: {
  family: C2Tab;
  familyAnalysis: C2FamilyAnalysis;
  captureRevision: number;
}) {
  const [vshellVKey, setVShellVKey] = useState("");
  const [vshellSalt, setVShellSalt] = useState("");
  const [vshellMode, setVShellMode] = useState<NonNullable<NonNullable<C2DecryptRequest["vshell"]>["mode"]>>("auto");
  const [csKeyMode, setCSKeyMode] = useState<NonNullable<NonNullable<C2DecryptRequest["cs"]>["keyMode"]>>("aes_hmac");
  const [csAESKey, setCSAESKey] = useState("");
  const [csHMACKey, setCSHMACKey] = useState("");
  const [csAESRand, setCSAESRand] = useState("");
  const [csRSAPrivateKey, setCSRSAPrivateKey] = useState("");
  const [csTransformMode, setCSTransformMode] =
    useState<NonNullable<NonNullable<C2DecryptRequest["cs"]>["transformMode"]>>("auto");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<C2DecryptResult | null>(null);

  useEffect(() => {
    setResult(null);
    setError("");
    setLoading(false);
  }, [family, captureRevision]);

  const candidateCount =
    (familyAnalysis.candidates?.length ?? 0) +
    (familyAnalysis.streamAggregates?.length ?? 0) +
    (familyAnalysis.hostUriAggregates?.length ?? 0);
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
      const next = await backendClients.analysis.decryptC2Traffic(request);
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
        解密结果仅作为衍生视图展示，不覆盖原始 payload，不写回 packet store，也不改变 C2 detection
        结果。当前候选来源：candidates / aggregates / 关联 stream 与 packet。
      </div>
      {!hasCandidates ? (
        <EmptyState className="text-left">
          当前无可解密候选流量；请先确认 {family === "cs" ? "CS" : "VShell"} 已形成 candidates 或聚合画像。
        </EmptyState>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
          <div className="space-y-3 rounded-2xl border border-slate-100 bg-white p-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <KeyRound className="h-4 w-4 text-rose-500" />
              {family === "cs" ? "CS keyed offline decrypt" : "VShell vkey / salt decrypt"}
            </div>
            {family === "vshell" ? (
              <VShellDecryptForm
                mode={vshellMode}
                salt={vshellSalt}
                vkey={vshellVKey}
                onModeChange={setVShellMode}
                onSaltChange={setVShellSalt}
                onVKeyChange={setVShellVKey}
              />
            ) : (
              <CSDecryptForm
                aesKey={csAESKey}
                aesRand={csAESRand}
                hmacKey={csHMACKey}
                keyMode={csKeyMode}
                rsaPrivateKey={csRSAPrivateKey}
                transformMode={csTransformMode}
                onAESKeyChange={setCSAESKey}
                onAESRandChange={setCSAESRand}
                onHMACKeyChange={setCSHMACKey}
                onKeyModeChange={setCSKeyMode}
                onRSAPrivateKeyChange={setCSRSAPrivateKey}
                onTransformModeChange={setCSTransformMode}
              />
            )}
            {error ? (
              <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-xs font-medium text-amber-800">
                {error}
              </div>
            ) : null}
            <Button
              type="button"
              onClick={runDecrypt}
              disabled={loading}
              className="h-9 gap-2 bg-rose-600 text-xs text-white hover:bg-rose-700"
            >
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
