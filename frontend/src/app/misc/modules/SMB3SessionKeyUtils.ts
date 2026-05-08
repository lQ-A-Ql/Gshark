import type { SMB3SessionCandidate, SMB3RandomSessionKeyRequest } from "../../core/types";

export function buildSMB3CandidateSummary({
  candidates,
  error,
  hasCapture,
  loading,
}: {
  candidates: SMB3SessionCandidate[];
  error: string;
  hasCapture: boolean;
  loading: boolean;
}) {
  if (loading) return "正在扫描当前抓包中的 SMB3 Session 候选...";
  if (!hasCapture) return "未加载抓包，请先在主工作区导入文件";
  if (error) return "";
  if (candidates.length === 0) return "未在当前抓包中发现可用的 SMB3 Session 候选";
  const completeCount = candidates.filter((candidate) => candidate.complete).length;
  return `已发现 ${candidates.length} 条候选，其中 ${completeCount} 条材料完整`;
}

export function getSMB3CandidateSessionLabel(candidate: SMB3SessionCandidate) {
  return candidate.sessionId || "未知 SessionId";
}

export function getSMB3CandidateUserLabel(candidate: SMB3SessionCandidate) {
  if (candidate.domain) {
    return `${candidate.domain}\\${candidate.username || "未知用户"}`;
  }
  return candidate.username || "未知用户";
}

export function createSMB3KeyRequest({
  domain,
  encryptedSessionKey,
  ntlmHash,
  ntProofStr,
  username,
}: {
  domain: string;
  encryptedSessionKey: string;
  ntlmHash: string;
  ntProofStr: string;
  username: string;
}): SMB3RandomSessionKeyRequest {
  return {
    username,
    domain,
    ntlmHash,
    ntProofStr,
    encryptedSessionKey,
  };
}

export function findSMB3CandidateByFrame(candidates: SMB3SessionCandidate[], frameNumber: string) {
  return candidates.find((item) => item.frameNumber === frameNumber) ?? null;
}
