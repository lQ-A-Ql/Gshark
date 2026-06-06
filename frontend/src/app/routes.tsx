import type { ComponentType } from "react";
import { createBrowserRouter } from "react-router";
import { MainLayout } from "./layouts/MainLayout";
import { routeModuleLoaders, type RouteModuleLoader } from "./routeModuleLoaders";

function lazyPage<T extends { default: ComponentType }>(loader: () => Promise<T>) {
  return async () => {
    const mod = await loader();
    return { Component: mod.default };
  };
}

function routeLazy(path: string) {
  return lazyPage(routeModuleLoaders[path] as RouteModuleLoader);
}

export const router = createBrowserRouter([
  {
    path: "/",
    Component: MainLayout,
    children: [
      { index: true, lazy: routeLazy("/") },
      { path: "analysis-cockpit", lazy: routeLazy("/analysis-cockpit") },
      { path: "http-stream", lazy: routeLazy("/http-stream") },
      { path: "tcp-stream", lazy: routeLazy("/tcp-stream") },
      { path: "udp-stream", lazy: routeLazy("/udp-stream") },
      { path: "hunting", lazy: routeLazy("/hunting") },
      { path: "objects", lazy: routeLazy("/objects") },
      { path: "misc", lazy: routeLazy("/misc") },
      { path: "updates", lazy: routeLazy("/updates") },
      { path: "traffic-graph", lazy: routeLazy("/traffic-graph") },
      { path: "c2-analysis", lazy: routeLazy("/c2-analysis") },
      { path: "apt-analysis", lazy: routeLazy("/apt-analysis") },
      { path: "industrial-analysis", lazy: routeLazy("/industrial-analysis") },
      { path: "vehicle-analysis", lazy: routeLazy("/vehicle-analysis") },
      { path: "media-analysis", lazy: routeLazy("/media-analysis") },
      { path: "usb-analysis", lazy: routeLazy("/usb-analysis") },
      { path: "evidence", lazy: routeLazy("/evidence") },
      { path: "rules", lazy: routeLazy("/rules") },
    ],
  },
]);
