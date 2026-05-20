import {
  BarChart3,
  Bug,
  Car,
  Clapperboard,
  Crosshair,
  Factory,
  FileDown,
  LayoutDashboard,
  Radar,
  RefreshCw,
  Shield,
  ShieldAlert,
  Usb,
  Wrench,
  type LucideIcon,
} from "lucide-react";

export const PAGE_THEMES = {
  blue: {
    base: "239 246 255",
    top: "248 250 252",
    bottom: "241 245 249",
    accent: "59 130 246",
    accent2: "14 165 233",
    active: "text-blue-600",
    bar: "bg-blue-600",
  },
  indigo: {
    base: "238 242 255",
    top: "248 250 252",
    bottom: "245 243 255",
    accent: "99 102 241",
    accent2: "59 130 246",
    active: "text-indigo-600",
    bar: "bg-indigo-600",
  },
  amber: {
    base: "255 251 235",
    top: "255 253 244",
    bottom: "248 250 252",
    accent: "245 158 11",
    accent2: "251 191 36",
    active: "text-amber-600",
    bar: "bg-amber-500",
  },
  emerald: {
    base: "236 253 245",
    top: "248 250 252",
    bottom: "240 253 244",
    accent: "16 185 129",
    accent2: "20 184 166",
    active: "text-emerald-600",
    bar: "bg-emerald-500",
  },
  rose: {
    base: "255 241 242",
    top: "255 251 252",
    bottom: "248 250 252",
    accent: "244 63 94",
    accent2: "251 113 133",
    active: "text-rose-600",
    bar: "bg-rose-500",
  },
  cyan: {
    base: "236 254 255",
    top: "248 250 252",
    bottom: "240 249 255",
    accent: "6 182 212",
    accent2: "14 165 233",
    active: "text-cyan-600",
    bar: "bg-cyan-500",
  },
} as const;

export type PageThemeName = keyof typeof PAGE_THEMES;
export type PageTheme = (typeof PAGE_THEMES)[PageThemeName];

export type MainNavItem = {
  path: string;
  icon: LucideIcon;
  label: string;
  theme: PageThemeName;
};

export const NAV_ITEMS: MainNavItem[] = [
  { path: "/", icon: LayoutDashboard, label: "主工作区", theme: "blue" },
  { path: "/analysis-cockpit", icon: Radar, label: "分析驾驶舱", theme: "indigo" },
  { path: "/c2-analysis", icon: Bug, label: "C2 样本分析", theme: "rose" },
  { path: "/apt-analysis", icon: Crosshair, label: "APT 组织画像", theme: "indigo" },
  { path: "/evidence", icon: Shield, label: "证据链总览", theme: "indigo" },
  { path: "/traffic-graph", icon: BarChart3, label: "流量图", theme: "amber" },
  { path: "/industrial-analysis", icon: Factory, label: "工控分析", theme: "blue" },
  { path: "/vehicle-analysis", icon: Car, label: "车机分析", theme: "emerald" },
  { path: "/media-analysis", icon: Clapperboard, label: "媒体流还原", theme: "rose" },
  { path: "/usb-analysis", icon: Usb, label: "USB 分析", theme: "cyan" },
  { path: "/hunting", icon: ShieldAlert, label: "威胁狩猎中心", theme: "rose" },
  { path: "/objects", icon: FileDown, label: "附件提取", theme: "amber" },
  { path: "/misc", icon: Wrench, label: "MISC 工具箱", theme: "cyan" },
  { path: "/updates", icon: RefreshCw, label: "检查更新", theme: "blue" },
];

export function themeForPath(pathname: string): PageTheme {
  const navTheme = NAV_ITEMS.find((item) => item.path !== "/" && pathname.startsWith(item.path))?.theme;
  const fallbackTheme: PageThemeName = pathname.includes("stream") ? "cyan" : "blue";
  return PAGE_THEMES[navTheme ?? fallbackTheme];
}
