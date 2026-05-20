import { Key } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { backendClients } from "../../integrations/backendClients";
import { useSentinel } from "../../state/SentinelContext";
import type { SMB3RandomSessionKeyResult, SMB3SessionCandidate } from "../../core/types";
import type { MiscModuleRendererProps } from "../types";
import { copyTextToClipboard } from "../../utils/browserFile";
import { SMB3SessionCandidateSelector } from "./SMB3SessionCandidateSelector";
import { SMB3SessionKeyInputForm } from "./SMB3SessionKeyInputForm";
import { SMB3SessionKeyResultPanel } from "./SMB3SessionKeyResultPanel";
import { buildSMB3CandidateSummary, createSMB3KeyRequest, findSMB3CandidateByFrame } from "./SMB3SessionKeyUtils";
import { MiscModuleSurface } from "./MiscModuleSurface";

export function SMB3SessionKeyModule({ module, surfaceVariant = "card" }: MiscModuleRendererProps) {
  const { fileMeta } = useSentinel();
  const [smbUser, setSmbUser] = useState("");
  const [smbDomain, setSmbDomain] = useState("");
  const [smbHash, setSmbHash] = useState("");
  const [smbProof, setSmbProof] = useState("");
  const [smbKey, setSmbKey] = useState("");
  const [smbCandidates, setSmbCandidates] = useState<SMB3SessionCandidate[]>([]);
  const [smbCandidatesLoading, setSmbCandidatesLoading] = useState(false);
  const [smbCandidatesError, setSmbCandidatesError] = useState("");
  const [smbSelectedCandidateFrame, setSmbSelectedCandidateFrame] = useState("");
  const [smbLoading, setSmbLoading] = useState(false);
  const [smbError, setSmbError] = useState("");
  const [smbResult, setSmbResult] = useState<SMB3RandomSessionKeyResult | null>(null);
  const embedded = surfaceVariant === "embedded";

  const hasCapture = Boolean(fileMeta.path);
  const smbCandidateSummary = useMemo(
    () =>
      buildSMB3CandidateSummary({
        candidates: smbCandidates,
        error: smbCandidatesError,
        hasCapture,
        loading: smbCandidatesLoading,
      }),
    [hasCapture, smbCandidates, smbCandidatesError, smbCandidatesLoading],
  );

  async function fetchSMB3Candidates() {
    if (!hasCapture) {
      setSmbCandidates([]);
      setSmbCandidatesLoading(false);
      setSmbCandidatesError("");
      setSmbSelectedCandidateFrame("");
      return;
    }
    setSmbCandidatesLoading(true);
    setSmbCandidatesError("");
    try {
      const rows = await backendClients.securityMaterial.listSMB3SessionCandidates();
      setSmbCandidates(rows);
      setSmbSelectedCandidateFrame("");
    } catch (error) {
      setSmbCandidates([]);
      setSmbSelectedCandidateFrame("");
      setSmbCandidatesError(error instanceof Error ? error.message : "加载 SMB3 Session 候选失败");
    } finally {
      setSmbCandidatesLoading(false);
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function loadSMB3Candidates() {
      try {
        if (!hasCapture) {
          setSmbCandidates([]);
          setSmbCandidatesLoading(false);
          setSmbCandidatesError("");
          setSmbSelectedCandidateFrame("");
          return;
        }
        setSmbCandidatesLoading(true);
        setSmbCandidatesError("");
        const rows = await backendClients.securityMaterial.listSMB3SessionCandidates();
        if (cancelled) return;
        setSmbCandidates(rows);
        setSmbSelectedCandidateFrame("");
      } catch (error) {
        if (cancelled) return;
        setSmbCandidates([]);
        setSmbSelectedCandidateFrame("");
        setSmbCandidatesError(error instanceof Error ? error.message : "加载 SMB3 Session 候选失败");
      } finally {
        if (!cancelled) {
          setSmbCandidatesLoading(false);
        }
      }
    }

    void loadSMB3Candidates();
    return () => {
      cancelled = true;
    };
  }, [hasCapture, fileMeta.path]);

  async function runSMB() {
    setSmbLoading(true);
    setSmbError("");
    try {
      const result = await backendClients.securityMaterial.generateSMB3RandomSessionKey(
        createSMB3KeyRequest({
          domain: smbDomain,
          encryptedSessionKey: smbKey,
          ntlmHash: smbHash,
          ntProofStr: smbProof,
          username: smbUser,
        }),
      );
      setSmbResult(result);
    } catch (error) {
      setSmbError(error instanceof Error ? error.message : "SMB3 Session Key 生成失败");
      setSmbResult(null);
    } finally {
      setSmbLoading(false);
    }
  }

  async function copySMBResult() {
    if (!smbResult?.randomSessionKey) return;
    await copyTextToClipboard(smbResult.randomSessionKey);
  }

  async function refreshSMB3Candidates() {
    if (!hasCapture) {
      setSmbCandidates([]);
      setSmbCandidatesError("请先在主工作区导入抓包文件");
      return;
    }
    await fetchSMB3Candidates();
  }

  function applySMB3Candidate(frameNumber: string) {
    setSmbSelectedCandidateFrame(frameNumber);
    const candidate = findSMB3CandidateByFrame(smbCandidates, frameNumber);
    if (!candidate) return;
    setSmbUser(candidate.username);
    setSmbDomain(candidate.domain);
    setSmbProof(candidate.ntProofStr);
    setSmbKey(candidate.encryptedSessionKey);
    setSmbResult(null);
    setSmbError("");
  }

  return (
    <MiscModuleSurface
      module={module}
      embedded={embedded}
      icon={<Key className="h-4 w-4" />}
      tone="indigo"
      bodyClassName="space-y-6"
    >
      <div className="grid gap-4">
        <SMB3SessionCandidateSelector
          candidates={smbCandidates}
          error={smbCandidatesError}
          hasCapture={hasCapture}
          loading={smbCandidatesLoading}
          onRefresh={refreshSMB3Candidates}
          onSelectCandidate={applySMB3Candidate}
          selectedFrame={smbSelectedCandidateFrame}
          summary={smbCandidateSummary}
        />
        <SMB3SessionKeyInputForm
          domain={smbDomain}
          encryptedSessionKey={smbKey}
          ntProofStr={smbProof}
          ntlmHash={smbHash}
          onDomainChange={setSmbDomain}
          onEncryptedSessionKeyChange={setSmbKey}
          onNtProofStrChange={setSmbProof}
          onNtlmHashChange={setSmbHash}
          onUsernameChange={setSmbUser}
          username={smbUser}
        />
      </div>

      <SMB3SessionKeyResultPanel
        error={smbError}
        loading={smbLoading}
        onClearResult={() => {
          setSmbResult(null);
          setSmbError("");
        }}
        onCopyResult={copySMBResult}
        onRun={runSMB}
        result={smbResult}
      />
    </MiscModuleSurface>
  );
}
