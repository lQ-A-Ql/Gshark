import { describe, expect, it } from "vitest";
import { parseWinRMExtractEntries, renderWinRMPreviewMode } from "./WinRMPreviewUtils";

describe("WinRMPreviewUtils", () => {
  it("parses extract blocks and renders focused preview modes", () => {
    const entries = parseWinRMExtractEntries(
      [
        "No: 42 stream 7",
        "[extract]",
        "command:",
        "  whoami",
        "stdout:",
        "  desktop\\\\qa",
        "stderr:",
        "",
        "No: 43 stream 7",
        "[extract]",
        "stdout:",
        "  line one",
        "  line two",
      ].join("\n"),
    );

    expect(entries).toEqual([
      {
        command: "whoami",
        header: "No: 42 stream 7",
        stdin: "",
        stdout: "desktop\\\\qa",
        stderr: "",
      },
      {
        command: "",
        header: "No: 43 stream 7",
        stdin: "",
        stdout: "line one\nline two",
        stderr: "",
      },
    ]);
    expect(renderWinRMPreviewMode(entries, "command")).toBe("No: 42 stream 7\ncommand:\n  whoami");
    expect(renderWinRMPreviewMode(entries, "stdout")).toContain("No: 43 stream 7\nstdout:\n  line one\n  line two");
  });

  it("returns an explicit empty-state message when a mode has no content", () => {
    expect(renderWinRMPreviewMode([], "stdout")).toContain("没有可展示的提取块");
    expect(
      renderWinRMPreviewMode(
        [
          {
            command: "whoami",
            header: "No: 42",
            stdin: "",
            stdout: "",
            stderr: "",
          },
        ],
        "stderr",
      ),
    ).toBe("当前结果里没有可展示的 仅看 Stderr 内容。");
  });
});
