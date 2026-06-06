import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { expandModule, resetMiscToolsMocks } from "./MiscTools.testFixtures";
import { getMiscToolsMocks } from "./MiscTools.testHarness";
import MiscTools from "./MiscTools";

const mocks = getMiscToolsMocks();
const SAMPLE_BASE64_PAYLOAD = "YXNzZXJ0KCRfUE9TVFsnY21kJ10pOw==";

describe("MiscTools payload decode workflow", () => {
  beforeEach(() => {
    resetMiscToolsMocks(mocks);
  });

  it("decodes a Base64 candidate from the payload decoder workbench", async () => {
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByRole("button", { name: "识别候选" })).toBeInTheDocument();
    });

    fireEvent.click(await screen.findByRole("button", { name: "示例" }, { timeout: 10000 }));
    fireEvent.click(await screen.findByRole("button", { name: "识别候选" }, { timeout: 5000 }));

    await waitFor(() => {
      expect(mocks.inspectStreamPayload).toHaveBeenCalledWith(`pass=${SAMPLE_BASE64_PAYLOAD}`, expect.any(AbortSignal));
    });
    expect(await screen.findByText("参数 pass")).toBeInTheDocument();
    expect(screen.getByText("无需抓包")).toBeInTheDocument();
    expect(screen.getByText("可取消")).toBeInTheDocument();
    expect(screen.getAllByText("支持导出").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("实验性")).toBeInTheDocument();
    expect(screen.getByText("候选可疑与低置信结果需要人工确认")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Base64" }));

    await waitFor(() => {
      expect(mocks.decodeStreamPayload).toHaveBeenCalledWith("base64", SAMPLE_BASE64_PAYLOAD, {}, expect.any(AbortSignal));
    });
    expect(await screen.findByText("assert($_POST['cmd']);")).toBeInTheDocument();
    expect(screen.getByText("置信度 96%")).toBeInTheDocument();
    expect(screen.getByText("keyword:assert")).toBeInTheDocument();
    expect(screen.getByText("Behinder (ECB): AES-ECB 密文长度非法")).toBeInTheDocument();
  }, 30000);

  it("re-runs payload inspection when the same input is submitted again", async () => {
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByPlaceholderText(/POST \/shell\.php/)).toBeInTheDocument();
    });

    fireEvent.change(await screen.findByPlaceholderText(/POST \/shell\.php/), {
      target: { value: `pass=${SAMPLE_BASE64_PAYLOAD}` },
    });

    fireEvent.click(screen.getByRole("button", { name: "识别候选" }));
    await waitFor(() => {
      expect(mocks.inspectStreamPayload).toHaveBeenCalledTimes(1);
    });

    fireEvent.click(screen.getByRole("button", { name: "识别候选" }));
    await waitFor(() => {
      expect(mocks.inspectStreamPayload).toHaveBeenCalledTimes(2);
    });
  });

  it("shows an immediate hint and skips inspect for empty payload input", async () => {
    render(<MiscTools />);

    await expandModule("payload-webshell-decoder", () => {
      expect(screen.getByRole("button", { name: "识别候选" })).toBeInTheDocument();
    });

    fireEvent.click(await screen.findByRole("button", { name: "识别候选" }));

    expect(await screen.findByText("请输入 payload 后再识别候选。")).toBeInTheDocument();
    expect(mocks.inspectStreamPayload).not.toHaveBeenCalled();
  });
});
