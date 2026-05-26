import type { C2DecryptRequest, C2DecryptResult, USBHIDSourceMode } from "../core/types";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { LONG_TYPED_IPC_TIMEOUT_MS, typedCall } from "./desktopTypedBridgeCore";
import { asAPTAnalysis } from "./mappers/aptMapper";
import { asC2SampleAnalysis } from "./mappers/c2SampleMapper";
import { normalizeC2DecryptResultForDisplay } from "./mappers/c2DecryptDisplayMapper";
import { asC2DecryptedRecord } from "./mappers/c2DecryptMapper";
import { parseEvidenceRecords } from "./mappers/evidenceMapper";
import { asIndustrialAnalysis } from "./mappers/industrialMapper";
import { asArray, asPlainObject, asStringList } from "./mappers/mapperPrimitives";
import { asGlobalTrafficStats } from "./mappers/trafficMapper";
import { asUSBAnalysis } from "./mappers/usbMapper";
import { asVehicleAnalysis } from "./mappers/vehicleMapper";
import type { C2DecryptResultWireDTO } from "./wire/c2DecryptWireDtos";

export function createAnalysisEvidenceTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async getGlobalTrafficStats(signal) {
      return asGlobalTrafficStats(
        await typedCall(() => desktopApp.GetGlobalTrafficStats!(), "DesktopApp.GetGlobalTrafficStats", signal),
      );
    },
    async getIndustrialAnalysis(signal) {
      return asIndustrialAnalysis(
        await typedCall(() => desktopApp.GetIndustrialAnalysis!(), "DesktopApp.GetIndustrialAnalysis", signal),
      );
    },
    async getVehicleAnalysis(signal) {
      return asVehicleAnalysis(
        await typedCall(() => desktopApp.GetVehicleAnalysis!(), "DesktopApp.GetVehicleAnalysis", signal),
      );
    },
    async getUSBAnalysis(signal, hidSource: USBHIDSourceMode = "auto", hidEventLimit = 20000) {
      return asUSBAnalysis(
        await typedCall(
          () => desktopApp.GetUSBAnalysis!(hidSource, hidEventLimit),
          "DesktopApp.GetUSBAnalysis",
          signal,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
      );
    },
    async getC2SampleAnalysis(signal) {
      return asC2SampleAnalysis(
        await typedCall(() => desktopApp.GetC2SampleAnalysis!(), "DesktopApp.GetC2SampleAnalysis", signal),
      );
    },
    async decryptC2Traffic(req, signal) {
      return asC2DecryptResult(
        await typedCall(
          () => desktopApp.DecryptC2Traffic!(toC2DecryptRequest(req)),
          "DesktopApp.DecryptC2Traffic",
          signal,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
        req.family,
      );
    },
    async getAPTAnalysis(signal) {
      return asAPTAnalysis(await typedCall(() => desktopApp.GetAPTAnalysis!(), "DesktopApp.GetAPTAnalysis", signal));
    },
    async getEvidence(signal) {
      return parseEvidenceRecords(await typedCall(() => desktopApp.GetEvidence!(), "DesktopApp.GetEvidence", signal));
    },
    async getEvidenceWithFilter(modules, signal) {
      return parseEvidenceRecords(
        await typedCall(
          () => desktopApp.GetEvidenceWithFilter!(Array.isArray(modules) ? modules : []),
          "DesktopApp.GetEvidenceWithFilter",
          signal,
        ),
      );
    },
  };
}

function asC2DecryptResult(input: unknown, requestedFamily: C2DecryptRequest["family"]): C2DecryptResult {
  const payload = (asPlainObject(input) ?? {}) as C2DecryptResultWireDTO;
  return normalizeC2DecryptResultForDisplay({
    family: String(payload.family ?? requestedFamily) === "vshell" ? "vshell" : "cs",
    status: String(payload.status ?? "failed"),
    totalCandidates: Number(payload.total_candidates ?? 0),
    decryptedCount: Number(payload.decrypted_count ?? 0),
    failedCount: Number(payload.failed_count ?? 0),
    records: asArray(payload.records).map(asC2DecryptedRecord),
    notes: asStringList(payload.notes),
  });
}

function toC2DecryptRequest(req: C2DecryptRequest) {
  return {
    family: req.family,
    scope: req.scope
      ? {
          packet_ids: req.scope.packetIds ?? [],
          stream_ids: req.scope.streamIds ?? [],
          use_candidates: Boolean(req.scope.useCandidates),
          use_aggregates: Boolean(req.scope.useAggregates),
        }
      : undefined,
    vshell: req.vshell
      ? {
          vkey: req.vshell.vkey,
          salt: req.vshell.salt,
          mode: req.vshell.mode,
        }
      : undefined,
    cs: req.cs
      ? {
          key_mode: req.cs.keyMode,
          aes_key: req.cs.aesKey,
          hmac_key: req.cs.hmacKey,
          aes_rand: req.cs.aesRand,
          rsa_private_key: req.cs.rsaPrivateKey,
          transform_mode: req.cs.transformMode,
        }
      : undefined,
  };
}
