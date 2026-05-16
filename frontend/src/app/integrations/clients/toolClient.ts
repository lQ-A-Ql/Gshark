import type {
  HTTPLoginAnalysis,
  MiscModuleImportResult,
  MiscModuleManifest,
  MiscModuleRunResult,
  MySQLAnalysis,
  NTLMSessionMaterial,
  ShiroRememberMeAnalysis,
  SMB3RandomSessionKeyRequest,
  SMB3RandomSessionKeyResult,
  SMB3SessionCandidate,
  SMTPAnalysis,
  WinRMDecryptRequest,
  WinRMDecryptResult,
} from "../../core/types";
import { downloadBlob } from "../../utils/browserFile";
import {
  asHTTPLoginAnalysis,
  asMySQLAnalysis,
  asShiroRememberMeAnalysis,
  asSMTPAnalysis,
} from "../mappers/protocolToolMapper";
import {
  asMiscModuleImportResult,
  asMiscModuleManifests,
  asMiscModuleRunResult,
  asNTLMSessionMaterials,
  asSMB3RandomSessionKeyResult,
  asSMB3SessionCandidates,
  asWinRMDecryptResult,
} from "../mappers/toolMapper";
import type {
  HTTPLoginAnalysisWireDTO,
  MySQLAnalysisWireDTO,
  ShiroRememberMeAnalysisWireDTO,
  SMTPAnalysisWireDTO,
} from "../wire/protocolToolWireDtos";
import type {
  MiscModuleImportResultWireDTO,
  MiscModuleManifestWireDTO,
  MiscModuleRunResultWireDTO,
} from "../wire/miscModuleWireDtos";
import type {
  NTLMSessionMaterialWireDTO,
  SMB3RandomSessionKeyResultWireDTO,
  SMB3SessionCandidateWireDTO,
} from "../wire/sessionMaterialWireDtos";
import type { WinRMDecryptResultWireDTO } from "../wire/toolWireDtos";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;
type BlobRequest = (path: string, init?: RequestInit) => Promise<Blob>;
type TextRequest = (path: string, init?: RequestInit) => Promise<string>;

export interface ToolClient {
  runWinRMDecrypt(req: WinRMDecryptRequest): Promise<WinRMDecryptResult>;
  getWinRMDecryptResultText(resultId: string): Promise<string>;
  exportWinRMDecryptResult(resultId: string, filename: string): Promise<void>;
  listMiscModules(): Promise<MiscModuleManifest[]>;
  importMiscModulePackage(file: File): Promise<MiscModuleImportResult>;
  deleteMiscModule(id: string): Promise<void>;
  runMiscModule(id: string, values: Record<string, string>): Promise<MiscModuleRunResult>;
  listSMB3SessionCandidates(): Promise<SMB3SessionCandidate[]>;
  generateSMB3RandomSessionKey(req: SMB3RandomSessionKeyRequest): Promise<SMB3RandomSessionKeyResult>;
  listNTLMSessionMaterials(): Promise<NTLMSessionMaterial[]>;
  getHTTPLoginAnalysis(signal?: AbortSignal): Promise<HTTPLoginAnalysis>;
  getSMTPAnalysis(signal?: AbortSignal): Promise<SMTPAnalysis>;
  getMySQLAnalysis(signal?: AbortSignal): Promise<MySQLAnalysis>;
  getShiroRememberMeAnalysis(candidateKeys?: string[], signal?: AbortSignal): Promise<ShiroRememberMeAnalysis>;
}

export function createToolClient(request: JsonRequest, requestText: TextRequest, requestBlob: BlobRequest): ToolClient {
  return {
    async runWinRMDecrypt(req: WinRMDecryptRequest) {
      const payload = await request<WinRMDecryptResultWireDTO>("/api/tools/winrm-decrypt", {
        method: "POST",
        body: JSON.stringify({
          port: req.port,
          auth_mode: req.authMode,
          password: req.password ?? "",
          nt_hash: req.ntHash ?? "",
          preview_lines: req.previewLines ?? 0,
          include_error_frames: Boolean(req.includeErrorFrames),
          extract_command_output: Boolean(req.extractCommandOutput),
        }),
      });
      return asWinRMDecryptResult(payload, req.port);
    },

    async getWinRMDecryptResultText(resultId: string) {
      const path = `/api/tools/winrm-decrypt/export?result_id=${encodeURIComponent(resultId)}`;
      return await requestText(path);
    },

    async exportWinRMDecryptResult(resultId: string, filename: string) {
      const path = `/api/tools/winrm-decrypt/export?result_id=${encodeURIComponent(resultId)}`;
      downloadBlob(filename, await requestBlob(path));
    },

    async listMiscModules() {
      const rows = await request<MiscModuleManifestWireDTO[]>("/api/tools/misc/modules");
      return asMiscModuleManifests(rows);
    },

    async importMiscModulePackage(file: File) {
      const form = new FormData();
      form.append("file", file);
      const payload = await request<MiscModuleImportResultWireDTO>("/api/tools/misc/import", {
        method: "POST",
        body: form,
      });
      return asMiscModuleImportResult(payload);
    },

    async deleteMiscModule(id: string) {
      await request<unknown>(`/api/tools/misc/packages/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
    },

    async runMiscModule(id: string, values: Record<string, string>) {
      const payload = await request<MiscModuleRunResultWireDTO>(
        `/api/tools/misc/packages/${encodeURIComponent(id)}/invoke`,
        {
          method: "POST",
          body: JSON.stringify({ values }),
        },
      );
      return asMiscModuleRunResult(payload);
    },

    async listSMB3SessionCandidates() {
      const rows = await request<SMB3SessionCandidateWireDTO[]>("/api/tools/smb3-session-candidates");
      return asSMB3SessionCandidates(rows);
    },

    async generateSMB3RandomSessionKey(req: SMB3RandomSessionKeyRequest) {
      const payload = await request<SMB3RandomSessionKeyResultWireDTO>("/api/tools/smb3-random-session-key", {
        method: "POST",
        body: JSON.stringify({
          username: req.username,
          domain: req.domain,
          ntlm_hash: req.ntlmHash,
          nt_proof_str: req.ntProofStr,
          encrypted_session_key: req.encryptedSessionKey,
        }),
      });
      return asSMB3RandomSessionKeyResult(payload);
    },

    async listNTLMSessionMaterials() {
      const payload = await request<NTLMSessionMaterialWireDTO[]>("/api/tools/ntlm-sessions");
      return asNTLMSessionMaterials(payload);
    },

    async getHTTPLoginAnalysis(signal?: AbortSignal) {
      const payload = await request<HTTPLoginAnalysisWireDTO>("/api/tools/http-login-analysis", { signal });
      return asHTTPLoginAnalysis(payload);
    },

    async getSMTPAnalysis(signal?: AbortSignal) {
      const payload = await request<SMTPAnalysisWireDTO>("/api/tools/smtp-analysis", { signal });
      return asSMTPAnalysis(payload);
    },

    async getMySQLAnalysis(signal?: AbortSignal) {
      const payload = await request<MySQLAnalysisWireDTO>("/api/tools/mysql-analysis", { signal });
      return asMySQLAnalysis(payload);
    },

    async getShiroRememberMeAnalysis(candidateKeys?: string[], signal?: AbortSignal) {
      const payload = await request<ShiroRememberMeAnalysisWireDTO>("/api/tools/shiro-rememberme", {
        method: "POST",
        signal,
        body: JSON.stringify({
          candidate_keys: Array.isArray(candidateKeys) ? candidateKeys : [],
        }),
      });
      return asShiroRememberMeAnalysis(payload);
    },
  };
}
