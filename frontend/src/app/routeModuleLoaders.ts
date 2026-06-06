import type { ComponentType } from "react";

export type RouteModule = { default: ComponentType };
export type RouteModuleLoader = () => Promise<RouteModule>;

export const routeModuleLoaders: Record<string, RouteModuleLoader> = {
  "/": () => import("./pages/Workspace"),
  "/analysis-cockpit": () => import("./pages/AnalysisCockpit"),
  "/http-stream": () => import("./pages/HttpStream"),
  "/tcp-stream": () => import("./pages/TcpStream"),
  "/udp-stream": () => import("./pages/UdpStream"),
  "/hunting": () => import("./pages/ThreatHunting"),
  "/objects": () => import("./pages/ObjectExport"),
  "/misc": () => import("./pages/MiscTools"),
  "/updates": () => import("./pages/UpdateCenter"),
  "/traffic-graph": () => import("./pages/TrafficGraph"),
  "/c2-analysis": () => import("./pages/C2Analysis"),
  "/apt-analysis": () => import("./pages/AptAnalysis"),
  "/industrial-analysis": () => import("./pages/IndustrialAnalysis"),
  "/vehicle-analysis": () => import("./pages/VehicleAnalysis"),
  "/media-analysis": () => import("./pages/MediaAnalysis"),
  "/usb-analysis": () => import("./pages/UsbAnalysis"),
  "/evidence": () => import("./pages/EvidencePanel"),
  "/rules": () => import("./pages/RuleManagement"),
};
