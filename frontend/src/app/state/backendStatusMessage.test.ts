import { describe, expect, it } from "vitest";
import {
  isCaptureLifecycleMessage,
  isProgressStatusMessage,
  shouldIgnoreCaptureErrorWithoutActiveCapture,
  shouldIgnoreCaptureStatusWithoutActiveCapture,
  shouldMarkParseErrorFromStatus,
  shouldMarkParseFinishedFromStatus,
  shouldResetMediaAnalysisFromError,
  shouldResetMediaAnalysisFromStatus,
  shouldResetThreatAnalysisFromError,
  shouldResetThreatAnalysisFromStatus,
} from "./backendStatusMessage";

describe("backendStatusMessage helpers", () => {
  it("detects progress and capture lifecycle status messages", () => {
    expect(isProgressStatusMessage("__progress__:counting:1:10")).toBe(true);
    expect(isCaptureLifecycleMessage("正在预加载全部数据")).toBe(true);
    expect(isCaptureLifecycleMessage("__progress__:media:1:2:test")).toBe(true);
    expect(isCaptureLifecycleMessage("后端已连接")).toBe(false);
  });

  it("ignores capture status and errors when no active capture exists", () => {
    expect(shouldIgnoreCaptureStatusWithoutActiveCapture("威胁分析完成", false)).toBe(true);
    expect(shouldIgnoreCaptureStatusWithoutActiveCapture("后端运行中", false)).toBe(false);
    expect(shouldIgnoreCaptureStatusWithoutActiveCapture("威胁分析完成", true)).toBe(false);

    expect(shouldIgnoreCaptureErrorWithoutActiveCapture("媒体流分析失败", false)).toBe(true);
    expect(shouldIgnoreCaptureErrorWithoutActiveCapture("数据库连接失败", false)).toBe(false);
    expect(shouldIgnoreCaptureErrorWithoutActiveCapture("解析失败", true)).toBe(false);
  });

  it("marks parse completion and parse error statuses", () => {
    expect(shouldMarkParseFinishedFromStatus("解析完成")).toBe(true);
    expect(shouldMarkParseFinishedFromStatus("解析被取消")).toBe(true);
    expect(shouldMarkParseFinishedFromStatus("预加载中")).toBe(false);

    expect(shouldMarkParseErrorFromStatus("解析失败: tshark error")).toBe(true);
    expect(shouldMarkParseErrorFromStatus("解析完成")).toBe(false);
  });

  it("resets media and threat progress from status and error messages", () => {
    expect(shouldResetMediaAnalysisFromStatus("媒体流分析完成")).toBe(true);
    expect(shouldResetMediaAnalysisFromStatus("媒体流分析失败")).toBe(true);
    expect(shouldResetMediaAnalysisFromStatus("媒体流解析中")).toBe(false);

    expect(shouldResetThreatAnalysisFromStatus("威胁分析完成")).toBe(true);
    expect(shouldResetThreatAnalysisFromStatus("威胁分析失败")).toBe(true);
    expect(shouldResetThreatAnalysisFromStatus("威胁分析中")).toBe(false);

    expect(shouldResetMediaAnalysisFromError("媒体流分析失败: ffmpeg")).toBe(true);
    expect(shouldResetMediaAnalysisFromError("威胁分析失败")).toBe(false);
    expect(shouldResetThreatAnalysisFromError("威胁分析失败")).toBe(true);
    expect(shouldResetThreatAnalysisFromError("媒体流分析失败")).toBe(false);
  });
});
