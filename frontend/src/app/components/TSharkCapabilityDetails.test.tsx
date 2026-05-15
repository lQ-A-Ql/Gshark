import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { TSharkCapabilityDetails } from "./TSharkCapabilityDetails";

describe("TSharkCapabilityDetails", () => {
  it("renders version, field profile, and missing field diagnostics", () => {
    render(
      <TSharkCapabilityDetails
        status={{
          available: true,
          path: "tshark.exe",
          message: "ok",
          usingCustomPath: false,
          version: "TShark 4.6.5",
          fieldProfile: "compat",
          fieldCount: 4321,
          missingRequiredFields: ["frame.protocols"],
          missingOptionalFields: ["usb.capdata", "modbus.func_code"],
          capabilityMessage: "optional tshark fields are unavailable; some analyses will degrade",
        }}
      />,
    );

    expect(screen.getByText("版本: TShark 4.6.5")).toBeInTheDocument();
    expect(screen.getByText("字段档案: compat")).toBeInTheDocument();
    expect(screen.getByText("字段数: 4321")).toBeInTheDocument();
    expect(screen.getByText(/能力探测：optional tshark fields/)).toBeInTheDocument();
    expect(screen.getByText("缺少必需字段：frame.protocols")).toBeInTheDocument();
    expect(screen.getByText("部分分析降级字段：usb.capdata, modbus.func_code")).toBeInTheDocument();
  });

  it("stays hidden when no capability details are available", () => {
    const { container } = render(
      <TSharkCapabilityDetails
        status={{
          available: true,
          path: "tshark.exe",
          message: "ok",
          usingCustomPath: false,
        }}
      />,
    );

    expect(container).toBeEmptyDOMElement();
  });
});
