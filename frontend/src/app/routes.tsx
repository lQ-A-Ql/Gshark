import { createBrowserRouter } from "react-router";
import { MainLayout } from "./layouts/MainLayout";
import Workspace from "./pages/Workspace";
import HttpStream from "./pages/HttpStream";
import TcpStream from "./pages/TcpStream";
import UdpStream from "./pages/UdpStream";
import ThreatHunting from "./pages/ThreatHunting";
import ObjectExport from "./pages/ObjectExport";
import Decryption from "./pages/Decryption";
import Plugins from "./pages/Plugins";
import TrafficGraph from "./pages/TrafficGraph";
import IndustrialAnalysis from "./pages/IndustrialAnalysis";
import VehicleAnalysis from "./pages/VehicleAnalysis";
import MediaAnalysis from "./pages/MediaAnalysis";

export const router = createBrowserRouter([
  {
    path: "/",
    Component: MainLayout,
    children: [
      { index: true, Component: Workspace },
      { path: "http-stream", Component: HttpStream },
      { path: "tcp-stream", Component: TcpStream },
      { path: "udp-stream", Component: UdpStream },
      { path: "hunting", Component: ThreatHunting },
      { path: "objects", Component: ObjectExport },
      { path: "decryption", Component: Decryption },
      { path: "plugins", Component: Plugins },
      { path: "traffic-graph", Component: TrafficGraph },
      { path: "industrial-analysis", Component: IndustrialAnalysis },
      { path: "vehicle-analysis", Component: VehicleAnalysis },
      { path: "media-analysis", Component: MediaAnalysis },
    ],
  },
]);
