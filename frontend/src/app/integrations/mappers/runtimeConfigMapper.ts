import type { ToolRuntimeConfigWireDTO } from "../wire/runtimeWireDtos";
import { asStringList } from "./mapperPrimitives";

export function asRuntimeConfig(config: ToolRuntimeConfigWireDTO) {
  return {
    tsharkPath: String(config.tshark_path ?? ""),
    tsharkAllowedDirs: asStringList(config.tshark_allowed_dirs),
    ffmpegPath: String(config.ffmpeg_path ?? ""),
    ffmpegAllowedDirs: asStringList(config.ffmpeg_allowed_dirs),
    pythonPath: String(config.python_path ?? ""),
    pythonAllowedDirs: asStringList(config.python_allowed_dirs),
    voskModelPath: String(config.vosk_model_path ?? ""),
    yaraEnabled: Boolean(config.yara_enabled),
    yaraBin: String(config.yara_bin ?? ""),
    yaraAllowedDirs: asStringList(config.yara_allowed_dirs),
    yaraRules: String(config.yara_rules ?? ""),
    yaraTimeoutMs: Number(config.yara_timeout_ms ?? 0) || 25000,
  };
}
