import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AntSwordSettingsSection, BehinderSettingsSection, GodzillaSettingsSection } from "./StreamDecoderSettingsSections";
import { DEFAULT_SETTINGS, type DecoderSettings } from "./StreamDecoderWorkbenchUtils";

function setup() {
  return {
    settings: structuredClone(DEFAULT_SETTINGS),
    setSettings: vi.fn(),
    onClose: vi.fn(),
  };
}

function applyUpdate(update: unknown, settings: DecoderSettings) {
  expect(update).toEqual(expect.any(Function));
  return (update as (prev: DecoderSettings) => DecoderSettings)(settings);
}

describe("StreamDecoderSettingsSections", () => {
  it("updates Behinder fields and shows IV for CBC mode", () => {
    const props = setup();
    props.settings.behinder.cipherMode = "cbc";

    render(<BehinderSettingsSection {...props} />);

    fireEvent.change(screen.getByLabelText("URL 解码轮数"), { target: { value: "2x" } });
    fireEvent.click(screen.getByLabelText("自动从 pass 派生 key"));

    expect(screen.getByLabelText("IV (留空则全零)")).toBeInTheDocument();
    expect(applyUpdate(props.setSettings.mock.calls[0][0], props.settings).behinder.urlDecodeRounds).toBe(2);
    expect(applyUpdate(props.setSettings.mock.calls[1][0], props.settings).behinder.deriveKeyFromPass).toBe(false);
  });

  it("updates AntSword pass extraction and clamps decode rounds", () => {
    const props = setup();

    render(<AntSwordSettingsSection {...props} />);

    fireEvent.click(screen.getByLabelText("从表单中提取 pass 参数"));
    fireEvent.change(screen.getByLabelText("URL 解码轮数"), { target: { value: "abc" } });

    expect(applyUpdate(props.setSettings.mock.calls[0][0], props.settings).antsword.extractParam).toBe(false);
    expect(applyUpdate(props.setSettings.mock.calls[1][0], props.settings).antsword.urlDecodeRounds).toBe(0);
  });

  it("updates Godzilla key and marker stripping", () => {
    const props = setup();

    render(<GodzillaSettingsSection {...props} />);

    fireEvent.change(screen.getByLabelText("Key"), { target: { value: "new-key" } });
    fireEvent.click(screen.getByLabelText("剥离 MD5 头尾标记"));

    expect(applyUpdate(props.setSettings.mock.calls[0][0], props.settings).godzilla.key).toBe("new-key");
    expect(applyUpdate(props.setSettings.mock.calls[1][0], props.settings).godzilla.stripMarkers).toBe(false);
  });
});
