type ResettableMock = {
  mockReset: () => void;
};

type ResettableResolvedMock = ResettableMock & {
  mockResolvedValue: (value: unknown) => void;
};

export type C2AnalysisTestHarness = {
  getC2SampleAnalysis: ResettableMock;
  decryptC2Traffic: ResettableMock;
  navigate?: ResettableMock;
  clipboardWriteText?: ResettableMock;
  sentinelState: {
    backendConnected: boolean;
    isPreloadingCapture: boolean;
    fileMeta: {
      path: string;
      name: string;
      sizeBytes: number;
    };
    totalPackets: number;
    captureRevision: number;
    locatePacketById: ResettableResolvedMock;
    preparePacketStream: ResettableResolvedMock;
  };
};

export function seedC2AnalysisTestState(
  harness: C2AnalysisTestHarness,
  seed: number,
  filePrefix: string,
  preparePacketStreamResult: { packet: null; protocol: string; streamId: number },
) {
  harness.sentinelState.backendConnected = true;
  harness.sentinelState.isPreloadingCapture = false;
  harness.sentinelState.totalPackets = 256 + seed;
  harness.sentinelState.captureRevision = seed;
  harness.sentinelState.fileMeta = {
    path: `C:/captures/${filePrefix}-${seed}.pcapng`,
    name: `${filePrefix}-${seed}.pcapng`,
    sizeBytes: 4096,
  };
  harness.getC2SampleAnalysis.mockReset();
  harness.decryptC2Traffic.mockReset();
  harness.navigate?.mockReset();
  harness.clipboardWriteText?.mockReset();
  harness.sentinelState.locatePacketById.mockReset();
  harness.sentinelState.preparePacketStream.mockReset();
  harness.sentinelState.locatePacketById.mockResolvedValue(null);
  harness.sentinelState.preparePacketStream.mockResolvedValue(preparePacketStreamResult);
}
