import type { ToolRuntimeSnapshot } from "../../core/types";
import type { ToolRuntimeConfigWireDTO, ToolRuntimeSnapshotWireDTO } from "../wire/runtimeWireDtos";
import { asPlainObject } from "./mapperPrimitives";
import { asFFmpegStatus, asRuntimeConfig, asSpeechStatus, asYaraStatus } from "./runtimeComponentMapper";
import { asNumberRecord, asStringRecord } from "./runtimeDiagnosticsMapper";
import { asTSharkStatus } from "./tsharkStatusMapper";
export { asSpeechBatchTaskStatus } from "./speechBatchMapper";

export function asToolRuntimeSnapshot(input: unknown): ToolRuntimeSnapshot {
  const payload: ToolRuntimeSnapshotWireDTO = asPlainObject(input) ?? {};
  const config: ToolRuntimeConfigWireDTO = asPlainObject(payload.config) ?? {};
  return {
    config: asRuntimeConfig(config),
    tshark: asTSharkStatus(payload.tshark),
    ffmpeg: asFFmpegStatus(asPlainObject(payload.ffmpeg) ?? {}),
    speech: asSpeechStatus(asPlainObject(payload.speech) ?? {}),
    yara: asYaraStatus(asPlainObject(payload.yara) ?? {}),
    probeMode: String(payload.probe_mode ?? "") || undefined,
    probeState: String(payload.probe_state ?? "") || undefined,
    probeTimings: asNumberRecord(payload.probe_timings),
    probeErrors: asStringRecord(payload.probe_errors),
    cached: payload.cached === undefined ? undefined : Boolean(payload.cached),
    updatedAt: String(payload.updated_at ?? "") || undefined,
  };
}
