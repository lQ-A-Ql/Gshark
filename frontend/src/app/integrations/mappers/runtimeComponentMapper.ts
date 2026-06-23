import type { SpeechStatusWireDTO, ToolPathStatusWireDTO, YaraStatusWireDTO } from "../wire/runtimeWireDtos";
import { optionalString } from "./mapperPrimitives";

export function asFFmpegStatus(ffmpeg: ToolPathStatusWireDTO) {
  return {
    available: Boolean(ffmpeg.available),
    path: String(ffmpeg.path ?? ""),
    message: String(ffmpeg.message ?? ""),
    customPath: optionalString(ffmpeg.custom_path),
    usingCustomPath: Boolean(ffmpeg.using_custom_path),
    pathWarning: optionalString(ffmpeg.path_warning),
    extraAllowedDir: optionalString(ffmpeg.extra_allowed_dir),
  };
}
export function asSpeechStatus(speech: SpeechStatusWireDTO) {
  return {
    available: Boolean(speech.available),
    engine: String(speech.engine ?? ""),
    language: String(speech.language ?? ""),
    pythonAvailable: Boolean(speech.python_available),
    pythonCommand: optionalString(speech.python_command),
    pythonPathWarning: optionalString(speech.python_path_warning),
    pythonExtraAllowedDir: optionalString(speech.python_extra_allowed_dir),
    ffmpegAvailable: Boolean(speech.ffmpeg_available),
    voskAvailable: Boolean(speech.vosk_available),
    modelAvailable: Boolean(speech.model_available),
    modelPath: optionalString(speech.model_path),
    message: String(speech.message ?? ""),
  };
}
export function asYaraStatus(yara: YaraStatusWireDTO) {
  return {
    available: Boolean(yara.available),
    enabled: Boolean(yara.enabled),
    path: optionalString(yara.path),
    rulePath: optionalString(yara.rule_path),
    message: String(yara.message ?? ""),
    lastScanMessage: optionalString(yara.last_scan_message),
    customBin: optionalString(yara.custom_bin),
    customRules: optionalString(yara.custom_rules),
    usingCustomBin: Boolean(yara.using_custom_bin),
    usingCustomRules: Boolean(yara.using_custom_rules),
    timeoutMs: Number(yara.timeout_ms ?? 0) || 25000,
    pathWarning: optionalString(yara.path_warning),
    extraAllowedDir: optionalString(yara.extra_allowed_dir),
  };
}
