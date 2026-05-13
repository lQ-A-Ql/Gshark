import type { ToolRuntimeSnapshot } from "../../core/types";
import { asPlainObject } from "./mapperPrimitives";
import { asTSharkStatus } from "./tsharkStatusMapper";

export { asSpeechBatchTaskStatus } from "./speechBatchMapper";

export function asToolRuntimeSnapshot(input: unknown): ToolRuntimeSnapshot {
  const payload = asPlainObject(input) ?? {};
  const config = asPlainObject(payload.config) ?? {};
  const ffmpeg = asPlainObject(payload.ffmpeg) ?? {};
  const speech = asPlainObject(payload.speech) ?? {};
  const yara = asPlainObject(payload.yara) ?? {};
  return {
    config: {
      tsharkPath: String(config.tshark_path ?? ""),
      ffmpegPath: String(config.ffmpeg_path ?? ""),
      pythonPath: String(config.python_path ?? ""),
      voskModelPath: String(config.vosk_model_path ?? ""),
      yaraEnabled: Boolean(config.yara_enabled),
      yaraBin: String(config.yara_bin ?? ""),
      yaraRules: String(config.yara_rules ?? ""),
      yaraTimeoutMs: Number(config.yara_timeout_ms ?? 0) || 25000,
    },
    tshark: asTSharkStatus(payload.tshark),
    ffmpeg: {
      available: Boolean(ffmpeg.available),
      path: String(ffmpeg.path ?? ""),
      message: String(ffmpeg.message ?? ""),
      customPath: String(ffmpeg.custom_path ?? "") || undefined,
      usingCustomPath: Boolean(ffmpeg.using_custom_path),
    },
    speech: {
      available: Boolean(speech.available),
      engine: String(speech.engine ?? ""),
      language: String(speech.language ?? ""),
      pythonAvailable: Boolean(speech.python_available),
      pythonCommand: String(speech.python_command ?? "") || undefined,
      ffmpegAvailable: Boolean(speech.ffmpeg_available),
      voskAvailable: Boolean(speech.vosk_available),
      modelAvailable: Boolean(speech.model_available),
      modelPath: String(speech.model_path ?? "") || undefined,
      message: String(speech.message ?? ""),
    },
    yara: {
      available: Boolean(yara.available),
      enabled: Boolean(yara.enabled),
      path: String(yara.path ?? "") || undefined,
      rulePath: String(yara.rule_path ?? "") || undefined,
      message: String(yara.message ?? ""),
      lastScanMessage: String(yara.last_scan_message ?? "") || undefined,
      customBin: String(yara.custom_bin ?? "") || undefined,
      customRules: String(yara.custom_rules ?? "") || undefined,
      usingCustomBin: Boolean(yara.using_custom_bin),
      usingCustomRules: Boolean(yara.using_custom_rules),
      timeoutMs: Number(yara.timeout_ms ?? 0) || 25000,
    },
  };
}
