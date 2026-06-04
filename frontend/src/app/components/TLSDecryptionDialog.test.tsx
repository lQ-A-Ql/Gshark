import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  updateTLSConfig: vi.fn(),
  onOpenChange: vi.fn(),
  sentinelState: {
    decryptionConfig: {
      sslKeyLogPath: "C:/keys/sslkeylog.log",
      privateKeyPath: "",
      privateKeyIpPort: "",
    },
    updateDecryptionConfig: vi.fn(),
    fileMeta: {
      name: "capture.pcapng",
      sizeBytes: 1024,
      path: "C:/captures/capture.pcapng",
    },
    openCapture: vi.fn(),
    displayFilter: "http",
    setDisplayFilter: vi.fn(),
    applyFilter: vi.fn(),
  },
}));

vi.mock("../state/contexts/BackendContext", () => ({
  useBackend: () => ({
    decryptionConfig: mocks.sentinelState.decryptionConfig,
    updateDecryptionConfig: mocks.sentinelState.updateDecryptionConfig,
  }),
}));

vi.mock("../state/contexts/CaptureContext", () => ({
  useCapture: () => ({
    fileMeta: mocks.sentinelState.fileMeta,
    openCapture: mocks.sentinelState.openCapture,
  }),
}));

vi.mock("../state/contexts/FilterContext", () => ({
  useFilter: () => ({
    displayFilter: mocks.sentinelState.displayFilter,
    setDisplayFilter: mocks.sentinelState.setDisplayFilter,
    applyFilter: mocks.sentinelState.applyFilter,
  }),
}));

vi.mock("../integrations/backendClients", () => ({
  backendClients: { securityMaterial: { updateTLSConfig: mocks.updateTLSConfig } },
}));

import { TLSDecryptionDialog } from "./TLSDecryptionDialog";

describe("TLSDecryptionDialog", () => {
  beforeEach(() => {
    mocks.updateTLSConfig.mockReset();
    mocks.onOpenChange.mockReset();
    mocks.sentinelState.openCapture.mockReset();
    mocks.sentinelState.setDisplayFilter.mockReset();
    mocks.sentinelState.applyFilter.mockReset();
    mocks.sentinelState.updateDecryptionConfig.mockReset();
    mocks.updateTLSConfig.mockResolvedValue(undefined);
    mocks.sentinelState.openCapture.mockResolvedValue(undefined);
    mocks.sentinelState.displayFilter = "http";
    mocks.sentinelState.fileMeta.path = "C:/captures/capture.pcapng";
  });

  it("reloads the current capture after applying TLS config", async () => {
    render(<TLSDecryptionDialog open onOpenChange={mocks.onOpenChange} />);

    fireEvent.click(screen.getByTestId("tls-apply-button"));

    await waitFor(() => {
      expect(mocks.updateTLSConfig).toHaveBeenCalledWith(mocks.sentinelState.decryptionConfig);
    });
    expect(mocks.sentinelState.openCapture).toHaveBeenCalledWith("C:/captures/capture.pcapng");
    expect(mocks.sentinelState.setDisplayFilter).toHaveBeenCalledWith("http");
    expect(mocks.sentinelState.applyFilter).toHaveBeenCalledWith("http");
  });

  it("saves config without reopening when no capture is active", async () => {
    mocks.sentinelState.fileMeta.path = "";

    render(<TLSDecryptionDialog open onOpenChange={mocks.onOpenChange} />);

    fireEvent.click(screen.getByTestId("tls-apply-button"));

    await waitFor(() => {
      expect(mocks.updateTLSConfig).toHaveBeenCalledWith(mocks.sentinelState.decryptionConfig);
    });
    expect(mocks.sentinelState.openCapture).not.toHaveBeenCalled();
    expect(mocks.sentinelState.applyFilter).not.toHaveBeenCalled();
  });
});
