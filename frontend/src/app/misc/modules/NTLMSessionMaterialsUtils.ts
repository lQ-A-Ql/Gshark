import type { NTLMSessionMaterial } from "../../core/types";
import type { NTLMSessionProtocolFilter } from "./NTLMSessionMaterialsToolbar";

export function filterNTLMSessionMaterials(
  materials: NTLMSessionMaterial[],
  protocolFilter: NTLMSessionProtocolFilter,
  query: string,
) {
  const keyword = query.trim().toLowerCase();
  return materials.filter((item) => {
    if (protocolFilter !== "ALL" && item.protocol !== protocolFilter) {
      return false;
    }
    if (!keyword) {
      return true;
    }
    return getNTLMSessionMaterialSearchText(item).includes(keyword);
  });
}

export function selectNTLMSessionMaterial(
  materials: NTLMSessionMaterial[],
  selectedFrame: string,
): NTLMSessionMaterial | null {
  return materials.find((item) => item.frameNumber === selectedFrame) ?? materials[0] ?? null;
}

export function countCompleteNTLMSessionMaterials(materials: NTLMSessionMaterial[]) {
  return materials.filter((item) => item.complete).length;
}

export function renderNTLMSessionMaterialText(item: NTLMSessionMaterial) {
  return [
    `Display: ${item.displayLabel}`,
    `Protocol: ${item.protocol}`,
    `Direction: ${item.direction || ""}`,
    `Frame: ${item.frameNumber}`,
    `Timestamp: ${item.timestamp || ""}`,
    `Transport: ${item.transport || ""}`,
    `Source: ${item.src || ""}${item.srcPort ? `:${item.srcPort}` : ""}`,
    `Destination: ${item.dst || ""}${item.dstPort ? `:${item.dstPort}` : ""}`,
    `User: ${item.userDisplay || item.username || ""}`,
    `Domain: ${item.domain || ""}`,
    `Challenge: ${item.challenge || ""}`,
    `NTProofStr: ${item.ntProofStr || ""}`,
    `EncryptedSessionKey: ${item.encryptedSessionKey || ""}`,
    `SessionID: ${item.sessionId || ""}`,
    `Authorization: ${item.authHeader || ""}`,
    `WWW-Authenticate: ${item.wwwAuthenticate || ""}`,
    `Info: ${item.info || ""}`,
    `Complete: ${item.complete ? "true" : "false"}`,
  ].join("\n");
}

export function renderNTLMSessionMaterialsText(rows: NTLMSessionMaterial[]) {
  return rows.map(renderNTLMSessionMaterialText).join("\n\n" + "-".repeat(80) + "\n\n");
}

function getNTLMSessionMaterialSearchText(item: NTLMSessionMaterial) {
  return [
    item.displayLabel,
    item.protocol,
    item.transport,
    item.userDisplay,
    item.username,
    item.domain,
    item.src,
    item.dst,
    item.challenge,
    item.ntProofStr,
    item.encryptedSessionKey,
    item.sessionId,
    item.info,
  ]
    .join(" ")
    .toLowerCase();
}
