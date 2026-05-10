import type { NTLMSessionMaterial, SMB3RandomSessionKeyResult, SMB3SessionCandidate } from "../../core/types";
import { optionalString } from "./mapperPrimitives";

export function asSMB3SessionCandidate(input: any): SMB3SessionCandidate {
  return {
    sessionId: String(input.session_id ?? ""),
    username: String(input.username ?? ""),
    domain: String(input.domain ?? ""),
    ntProofStr: String(input.nt_proof_str ?? ""),
    encryptedSessionKey: String(input.encrypted_session_key ?? ""),
    src: String(input.src ?? ""),
    dst: String(input.dst ?? ""),
    frameNumber: String(input.frame_number ?? ""),
    timestamp: String(input.timestamp ?? ""),
    complete: Boolean(input.complete),
    displayLabel: String(input.display_label ?? ""),
  };
}

export function asSMB3SessionCandidates(input: any): SMB3SessionCandidate[] {
  return Array.isArray(input) ? input.map(asSMB3SessionCandidate) : [];
}

export function asSMB3RandomSessionKeyResult(input: any): SMB3RandomSessionKeyResult {
  return {
    randomSessionKey: String(input.random_session_key ?? ""),
    message: String(input.message ?? ""),
  };
}

export function asNTLMSessionMaterial(input: any): NTLMSessionMaterial {
  return {
    protocol: String(input.protocol ?? ""),
    transport: optionalString(input.transport),
    frameNumber: String(input.frame_number ?? ""),
    timestamp: optionalString(input.timestamp),
    src: optionalString(input.src),
    dst: optionalString(input.dst),
    srcPort: optionalString(input.src_port),
    dstPort: optionalString(input.dst_port),
    direction: optionalString(input.direction),
    username: optionalString(input.username),
    domain: optionalString(input.domain),
    userDisplay: optionalString(input.user_display),
    challenge: optionalString(input.challenge),
    ntProofStr: optionalString(input.nt_proof_str),
    encryptedSessionKey: optionalString(input.encrypted_session_key),
    sessionId: optionalString(input.session_id),
    authHeader: optionalString(input.auth_header),
    wwwAuthenticate: optionalString(input.www_authenticate),
    info: optionalString(input.info),
    complete: Boolean(input.complete),
    displayLabel: String(input.display_label ?? ""),
  };
}

export function asNTLMSessionMaterials(input: any): NTLMSessionMaterial[] {
  return Array.isArray(input) ? input.map(asNTLMSessionMaterial) : [];
}
