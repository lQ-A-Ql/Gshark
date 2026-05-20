import type { NavigateFunction } from "react-router";
import type { CaptureRecommendation } from "../core/captureOverview";

type OpenCaptureRecommendationOptions = {
  item: CaptureRecommendation;
  streamIds: { http: number[]; tcp: number[]; udp: number[] };
  setDisplayFilter: (filter: string) => void;
  setActiveStream: (protocol: "HTTP" | "TCP" | "UDP", streamId: number) => Promise<void>;
  applyWorkspaceFilter: (filter: string) => void;
  navigate: NavigateFunction;
};

export async function openCaptureRecommendation({
  item,
  streamIds,
  setDisplayFilter,
  setActiveStream,
  applyWorkspaceFilter,
  navigate,
}: OpenCaptureRecommendationOptions) {
  if (item.filter) setDisplayFilter(item.filter);

  if (item.route === "/http-stream" && streamIds.http.length > 0) {
    await openStreamRoute({
      protocol: "HTTP",
      route: "/http-stream",
      streamId: streamIds.http[0],
      setActiveStream,
      navigate,
    });
    return;
  }
  if (item.route === "/tcp-stream" && streamIds.tcp.length > 0) {
    await openStreamRoute({
      protocol: "TCP",
      route: "/tcp-stream",
      streamId: streamIds.tcp[0],
      setActiveStream,
      navigate,
    });
    return;
  }
  if (item.route === "/udp-stream" && streamIds.udp.length > 0) {
    await openStreamRoute({
      protocol: "UDP",
      route: "/udp-stream",
      streamId: streamIds.udp[0],
      setActiveStream,
      navigate,
    });
    return;
  }
  if ((item.route === "/http-stream" || item.route === "/tcp-stream" || item.route === "/udp-stream") && item.filter) {
    applyWorkspaceFilter(item.filter);
    return;
  }
  navigate(item.route);
}

async function openStreamRoute({
  protocol,
  route,
  streamId,
  setActiveStream,
  navigate,
}: {
  protocol: "HTTP" | "TCP" | "UDP";
  route: "/http-stream" | "/tcp-stream" | "/udp-stream";
  streamId: number;
  setActiveStream: (protocol: "HTTP" | "TCP" | "UDP", streamId: number) => Promise<void>;
  navigate: NavigateFunction;
}) {
  await setActiveStream(protocol, streamId);
  navigate(route, { state: { streamId } });
}
