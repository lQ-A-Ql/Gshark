import type { ComponentType } from "react";
import { createBrowserRouter } from "react-router";
import { MainLayout } from "./layouts/MainLayout";

function lazyPage<T extends { default: ComponentType }>(loader: () => Promise<T>) {
  return async () => {
    const mod = await loader();
    return { Component: mod.default };
  };
}

export const router = createBrowserRouter([
  {
    path: "/",
    Component: MainLayout,
    children: [
      { index: true, lazy: lazyPage(() => import("./pages/Workspace")) },
      { path: "http-stream", lazy: lazyPage(() => import("./pages/HttpStream")) },
      { path: "tcp-stream", lazy: lazyPage(() => import("./pages/TcpStream")) },
      { path: "udp-stream", lazy: lazyPage(() => import("./pages/UdpStream")) },
      { path: "hunting", lazy: lazyPage(() => import("./pages/ThreatHunting")) },
      { path: "objects", lazy: lazyPage(() => import("./pages/ObjectExport")) },
      { path: "decryption", lazy: lazyPage(() => import("./pages/Decryption")) },
      { path: "plugins", lazy: lazyPage(() => import("./pages/Plugins")) },
      { path: "audit-logs", lazy: lazyPage(() => import("./pages/AuditLogs")) },
      { path: "traffic-graph", lazy: lazyPage(() => import("./pages/TrafficGraph")) },
      { path: "industrial-analysis", lazy: lazyPage(() => import("./pages/IndustrialAnalysis")) },
      { path: "vehicle-analysis", lazy: lazyPage(() => import("./pages/VehicleAnalysis")) },
      { path: "media-analysis", lazy: lazyPage(() => import("./pages/MediaAnalysis")) },
    ],
  },
]);
