import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";
import {
  CaptureSettingsSection,
  MediaSettingsSection,
  SpeechSettingsSection,
  YaraSettingsSection,
} from "./RuntimeSettingsSections";

const form: ToolRuntimeConfig = {
  tsharkPath: "tshark.exe",
  ffmpegPath: "ffmpeg.exe",
  pythonPath: "python.exe",
  voskModelPath: "C:\\models\\vosk",
  yaraEnabled: true,
  yaraBin: "yara64.exe",
  yaraRules: "rules.yar",
  yaraTimeoutMs: 25000,
};

const snapshot = {
  tshark: { available: true, message: "ok", path: form.tsharkPath },
  ffmpeg: { available: true, message: "ok", path: form.ffmpegPath },
  yara: {
    available: true,
    enabled: true,
    message: "ok",
    path: form.yaraBin,
    rulePath: form.yaraRules,
    lastScanMessage: "warning",
  },
  speech: {
    available: false,
    pythonAvailable: true,
    pythonCommand: form.pythonPath,
    modelAvailable: false,
    modelPath: "",
  },
} as ToolRuntimeSnapshot;

function setup() {
  return { backendConnected: true, form, snapshot, setForm: vi.fn() };
}

describe("RuntimeSettingsSections", () => {
  it("renders capture, media, and yara settings with status details", () => {
    const props = setup();

    render(
      <>
        <CaptureSettingsSection {...props} />
        <MediaSettingsSection {...props} />
        <YaraSettingsSection {...props} />
      </>,
    );

    expect(screen.getByText("抓包与解析")).toBeInTheDocument();
    expect(screen.getByText("媒体播放与转码")).toBeInTheDocument();
    expect(screen.getByText("YARA 狩猎")).toBeInTheDocument();
    expect(screen.getByText(/当前使用的规则文件/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("YARA 可执行路径"), { target: { value: "new-yara.exe" } });
    const update = props.setForm.mock.calls[0][0] as (prev: ToolRuntimeConfig) => ToolRuntimeConfig;
    expect(update(form).yaraBin).toBe("new-yara.exe");
  });

  it("renders speech dependency summary and missing issue chips", () => {
    render(
      <SpeechSettingsSection
        form={form}
        snapshot={snapshot}
        speechIssues={["Vosk 模型目录缺失"]}
        speechSummary="当前未就绪项：Vosk 模型目录缺失"
        setForm={vi.fn()}
      />,
    );

    expect(screen.getByText("离线语音转写")).toBeInTheDocument();
    expect(screen.getByText("缺少：Vosk 模型目录缺失")).toBeInTheDocument();
    expect(screen.getByText("python.exe")).toBeInTheDocument();
  });
});
