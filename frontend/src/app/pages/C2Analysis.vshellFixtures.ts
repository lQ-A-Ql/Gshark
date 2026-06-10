import type { C2SampleAnalysis } from "../core/types";
import { createAnalysis } from "./C2Analysis.testFixtures";

export function createVShellListenerAnalysis(): C2SampleAnalysis {
  return createAnalysis({
    totalMatchedPackets: 1,
    families: [{ label: "VShell", count: 1 }],
    conversations: [{ label: "10.0.0.5 -> 10.0.0.8", protocol: "TCP", count: 2 }],
    vshell: {
      ...createAnalysis().vshell,
      candidateCount: 1,
      matchedRuleCount: 1,
      channels: [{ label: "tcp", count: 1 }],
      streamAggregates: [
        {
          streamId: 9,
          protocol: "TCP",
          totalPackets: 6,
          archMarkers: [{ label: "l64", count: 1 }],
          lengthPrefixCount: 3,
          shortPackets: 4,
          longPackets: 1,
          transitions: 2,
          heartbeatAvg: "10.0s",
          heartbeatJitter: "0%",
          intervals: [10, 10, 10],
          hasWebSocket: false,
          listenerHints: [{ label: "vshell-listener-port", count: 1 }],
          packets: [81, 82, 83],
          confidence: 74,
          summary: "VShell stream-level 候选",
        },
      ],
      notes: ["VShell listener 证据已汇总"],
    },
    notes: ["C2 evidence model ready"],
  });
}

export function createVShellDecryptAnalysis(): C2SampleAnalysis {
  return createAnalysis({
    totalMatchedPackets: 1,
    families: [{ label: "VShell", count: 1 }],
    conversations: [{ label: "10.0.0.5 -> 10.0.0.8", protocol: "TCP", count: 2 }],
    vshell: {
      ...createAnalysis().vshell,
      candidateCount: 1,
      matchedRuleCount: 1,
      channels: [{ label: "tcp", count: 1 }],
      streamAggregates: [
        {
          streamId: 9,
          protocol: "TCP",
          totalPackets: 6,
          archMarkers: [{ label: "l64", count: 1 }],
          lengthPrefixCount: 3,
          shortPackets: 4,
          longPackets: 1,
          transitions: 2,
          heartbeatAvg: "10.0s",
          heartbeatJitter: "0%",
          intervals: [10, 10, 10],
          hasWebSocket: false,
          listenerHints: [{ label: "vshell-listener-port", count: 1 }],
          packets: [81, 82, 83],
          confidence: 74,
          summary: "VShell stream-level 候选",
        },
      ],
      notes: ["VShell listener 证据已汇总"],
    },
    notes: ["C2 evidence model ready"],
  });
}

export function createVShellCandidateFallbackAnalysis(): C2SampleAnalysis {
  return createAnalysis({
    totalMatchedPackets: 1,
    families: [{ label: "VShell", count: 1 }],
    conversations: [{ label: "10.0.0.5 -> 10.0.0.8", protocol: "TCP", count: 2 }],
    vshell: {
      ...createAnalysis().vshell,
      candidateCount: 1,
      matchedRuleCount: 1,
      channels: [{ label: "websocket", count: 1 }],
      indicators: [{ label: "websocket-listener", count: 1 }],
      streamAggregates: [],
      candidates: [
        {
          packetId: 81,
          streamId: 9,
          time: "2026-05-02T12:00:00Z",
          family: "vshell",
          channel: "websocket",
          source: "10.0.0.5:51234",
          destination: "10.0.0.8:443",
          indicatorType: "websocket-listener",
          indicatorValue: "ws_ listener / l64",
          confidence: 62,
          summary: "VShell WebSocket 候选，包含 ws_ 参数与 l64 marker",
          evidence: "length prefix and listener port hint",
          tags: ["websocket", "l64", "listener"],
          transportTraits: ["length-prefix"],
          infrastructureHints: ["listener-port"],
          ttpTags: ["heartbeat-like"],
        },
      ],
      notes: ["VShell 候选尚未形成 stream 聚合"],
    },
  });
}

export function createVShellCandidateMergeAnalysis(): C2SampleAnalysis {
  return createAnalysis({
    totalMatchedPackets: 2,
    families: [{ label: "VShell", count: 2 }],
    vshell: {
      ...createAnalysis().vshell,
      candidateCount: 2,
      matchedRuleCount: 2,
      streamAggregates: [
        {
          streamId: 9,
          protocol: "TCP",
          totalPackets: 8,
          archMarkers: [{ label: "l64", count: 1 }],
          lengthPrefixCount: 2,
          shortPackets: 4,
          longPackets: 2,
          transitions: 3,
          heartbeatAvg: "10.0s",
          heartbeatJitter: "4%",
          intervals: [10, 11, 9],
          hasWebSocket: true,
          wsParams: "a=l64&t=ws_",
          listenerHints: [{ label: "vshell-listener-port", count: 1 }],
          packets: [81, 82, 83],
          confidence: 70,
          summary: "stream aggregate with websocket",
        },
      ],
      candidates: [
        {
          packetId: 81,
          streamId: 9,
          family: "vshell",
          channel: "websocket",
          indicatorType: "websocket-listener",
          indicatorValue: "ws_ listener / l64",
          confidence: 66,
          summary: "VShell candidate websocket listener",
          evidence: "length prefix and listener hint",
          tags: ["websocket", "l64", "listener"],
          transportTraits: ["length-prefix", "heartbeat"],
          infrastructureHints: ["listener-port"],
          ttpTags: ["heartbeat-like"],
        },
      ],
    },
  });
}

export function createVShellCandidateNoSignalAnalysis(): C2SampleAnalysis {
  return createAnalysis({
    totalMatchedPackets: 1,
    families: [{ label: "VShell", count: 1 }],
    vshell: {
      ...createAnalysis().vshell,
      candidateCount: 1,
      matchedRuleCount: 1,
      streamAggregates: [
        {
          streamId: 17,
          protocol: "TCP",
          totalPackets: 2,
          archMarkers: [],
          lengthPrefixCount: 0,
          shortPackets: 2,
          longPackets: 0,
          transitions: 0,
          heartbeatAvg: "",
          heartbeatJitter: "",
          intervals: [],
          hasWebSocket: false,
          listenerHints: [],
          packets: [171, 172],
          confidence: 28,
          summary: "低样本 stream，暂未形成聚合画像",
        },
      ],
      candidates: [
        {
          packetId: 171,
          streamId: 17,
          time: "2026-05-02T12:30:00Z",
          family: "vshell",
          channel: "tcp",
          source: "10.0.0.5:51234",
          destination: "10.0.0.8:443",
          indicatorType: "tcp-listener",
          indicatorValue: "listener port with length prefix",
          confidence: 54,
          summary: "VShell TCP 候选，包含 length prefix listener hint",
          evidence: "length prefix / listener",
          tags: ["listener"],
          transportTraits: ["length-prefix"],
          infrastructureHints: ["listener-port"],
          ttpTags: [],
        },
      ],
    },
  });
}
