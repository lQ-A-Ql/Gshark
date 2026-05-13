import type { NTLMSessionMaterial, SMB3RandomSessionKeyResult, SMB3SessionCandidate } from "../../core/types";
import { asArray, asPlainObject, optionalString } from "./mapperPrimitives";

export function asSMB3SessionCandidate(input: unknown): SMB3SessionCandidate {
  const payload = asPlainObject(input) ?? {};
  return {
    sessionId: String(payload.session_id ?? ""),
    username: String(payload.username ?? ""),
    domain: String(payload.domain ?? ""),
    ntProofStr: String(payload.nt_proof_str ?? ""),
    encryptedSessionKey: String(payload.encrypted_session_key ?? ""),
    src: String(payload.src ?? ""),
    dst: String(payload.dst ?? ""),
    frameNumber: String(payload.frame_number ?? ""),
    timestamp: String(payload.timestamp ?? ""),
    complete: Boolean(payload.complete),
    displayLabel: String(payload.display_label ?? ""),
  };
}

export function asSMB3SessionCandidates(input: unknown): SMB3SessionCandidate[] {
  return asArray(input).map(asSMB3SessionCandidate);
}

export function asSMB3RandomSessionKeyResult(input: unknown): SMB3RandomSessionKeyResult {
  const payload = asPlainObject(input) ?? {};
  return {
    randomSessionKey: String(payload.random_session_key ?? ""),
    message: String(payload.message ?? ""),
  };
}

export function asNTLMSessionMaterial(input: unknown): NTLMSessionMaterial {
  const payload = asPlainObject(input) ?? {};
  return {
    protocol: String(payload.protocol ?? ""),
    transport: optionalString(payload.transport),
    frameNumber: String(payload.frame_number ?? ""),
    timestamp: optionalString(payload.timestamp),
    src: optionalString(payload.src),
    dst: optionalString(payload.dst),
    srcPort: optionalString(payload.src_port),
    dstPort: optionalString(payload.dst_port),
    direction: optionalString(payload.direction),
    username: optionalString(payload.username),
    domain: optionalString(payload.domain),
    userDisplay: optionalString(payload.user_display),
    challenge: optionalString(payload.challenge),
    ntProofStr: optionalString(payload.nt_proof_str),
    encryptedSessionKey: optionalString(payload.encrypted_session_key),
    sessionId: optionalString(payload.session_id),
    authHeader: optionalString(payload.auth_header),
    wwwAuthenticate: optionalString(payload.www_authenticate),
    info: optionalString(payload.info),
    complete: Boolean(payload.complete),
    displayLabel: String(payload.display_label ?? ""),
  };
}

export function asNTLMSessionMaterials(input: unknown): NTLMSessionMaterial[] {
  return asArray(input).map(asNTLMSessionMaterial);
}
