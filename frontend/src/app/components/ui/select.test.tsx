import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SelectControl, SelectField } from "./select";

async function chooseOption(label: string) {
  const trigger = screen.getByRole("combobox");
  fireEvent.pointerDown(trigger, { button: 0, ctrlKey: false, pointerType: "mouse" });
  const option = await screen.findByRole("option", { name: label });
  fireEvent.keyDown(option, { key: "Enter" });
}

describe("global Select controls", () => {
  it("renders field labels, options, help text, and selected values", async () => {
    const onValueChange = vi.fn();
    render(
      <SelectField
        label="协议"
        value="tcp"
        onValueChange={onValueChange}
        help="选择协议视图"
        options={[
          { value: "tcp", label: "TCP", description: "Transmission Control Protocol" },
          { value: "udp", label: "UDP" },
        ]}
      />,
    );

    expect(screen.getByText("协议")).toBeInTheDocument();
    expect(screen.getByText("选择协议视图")).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "协议" })).toHaveTextContent("TCP");

    await chooseOption("UDP");

    expect(onValueChange).toHaveBeenCalledWith("udp");
  });

  it("maps empty string values through the Radix-safe sentinel", async () => {
    const onValueChange = vi.fn();
    render(
      <SelectControl
        aria-label="可选 key"
        value="secret"
        onValueChange={onValueChange}
        options={[
          { value: "", label: "不使用 key" },
          { value: "secret", label: "secret" },
        ]}
      />,
    );

    fireEvent.pointerDown(screen.getByRole("combobox", { name: "可选 key" }), {
      button: 0,
      ctrlKey: false,
      pointerType: "mouse",
    });
    const emptyOption = await screen.findByRole("option", { name: "不使用 key" });
    fireEvent.keyDown(emptyOption, { key: "Enter" });

    expect(onValueChange).toHaveBeenCalledWith("");
  });

  it("does not select disabled options", async () => {
    const onValueChange = vi.fn();
    render(
      <SelectControl
        aria-label="模式"
        value="safe"
        onValueChange={onValueChange}
        options={[
          { value: "safe", label: "安全模式" },
          { value: "disabled", label: "禁用模式", disabled: true },
        ]}
      />,
    );

    fireEvent.pointerDown(screen.getByRole("combobox", { name: "模式" }), {
      button: 0,
      ctrlKey: false,
      pointerType: "mouse",
    });
    const disabledOption = await screen.findByRole("option", { name: "禁用模式" });
    fireEvent.keyDown(disabledOption, { key: "Enter" });

    await waitFor(() => {
      expect(onValueChange).not.toHaveBeenCalled();
    });
  });
});
