import type { APTActorProfile, TrafficBucket } from "../../core/types";

export type APTActorFrameworkStatus = "implemented" | "framework" | "needs-sample" | "excluded";
export type APTActorStatusTone = "emerald" | "amber" | "slate" | "rose";

export interface APTActorRegistryProfile {
  id: string;
  name: string;
  aliases: string[];
  regions: string[];
  families: string[];
  ttpTags: string[];
  frameworkStatus: APTActorFrameworkStatus;
  statusLabel: string;
  statusTone: APTActorStatusTone;
  summary: string;
  caveats: string[];
  evidenceNeeds: string[];
}

export interface APTDisplayProfile extends APTActorProfile {
  registry: APTActorRegistryProfile;
  frameworkOnly: boolean;
}

const EMPTY_BUCKETS: TrafficBucket[] = [];

export const APT_ACTOR_REGISTRY: APTActorRegistryProfile[] = [
  {
    id: "silver-fox",
    name: "Silver Fox / 银狐",
    aliases: ["Swimming Snake", "银狐"],
    regions: ["East Asia"],
    families: ["ValleyRAT", "Winos 4.0", "Gh0st variants"],
    ttpTags: ["multi-stage-delivery", "hfs-download-chain", "https-c2", "fallback-c2"],
    frameworkStatus: "implemented",
    statusLabel: "已接入检测",
    statusTone: "emerald",
    summary: "当前作为已接入样例 actor，消费 C2、投递链、样本家族和基础设施线索；仍避免由单一端口或 IOC 直接强归因。",
    caveats: ["样本家族和端口仅为观察信号，需要与投递链、C2 形态和对象证据交叉验证。"],
    evidenceNeeds: ["ValleyRAT / Winos / Gh0st 证据", "HFS 或下载器链路", "HTTPS/TCP C2 与 fallback 观察", "对象或威胁狩猎证据"],
  },
  {
    id: "apt28",
    name: "APT28 / Fancy Bear",
    aliases: ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
    regions: ["Eastern Europe", "Global"],
    families: ["X-Agent", "Zebrocy", "Komplex"],
    ttpTags: ["phishing", "credential-access", "custom-loader", "c2-infrastructure"],
    frameworkStatus: "framework",
    statusLabel: "框架预置",
    statusTone: "amber",
    summary: "预置组织画像与证据需求，当前不参与本轮评分，也不输出强归因。",
    caveats: ["尚未接入本项目样本验证规则。"],
    evidenceNeeds: ["投递邮件与诱饵文档", "已知 loader / malware family", "认证窃取或 OAuth 滥用证据", "基础设施复用证据"],
  },
  {
    id: "apt29",
    name: "APT29 / Cozy Bear",
    aliases: ["Cozy Bear", "Nobelium", "The Dukes"],
    regions: ["Eastern Europe", "Global"],
    families: ["WellMess", "WellMail", "SUNBURST-related tradecraft"],
    ttpTags: ["stealthy-c2", "cloud-abuse", "supply-chain", "living-off-the-land"],
    frameworkStatus: "framework",
    statusLabel: "框架预置",
    statusTone: "amber",
    summary: "规划云服务滥用、隐蔽 C2、供应链和长期潜伏证据位，等待样本与规则接入。",
    caveats: ["公开 TTP 与真实样本差异较大，不能仅凭云服务或低频通信归因。"],
    evidenceNeeds: ["云服务 API 访问模式", "低频长周期 C2", "供应链投递证据", "主机侧行为证据"],
  },
  {
    id: "lazarus",
    name: "Lazarus Group",
    aliases: ["Hidden Cobra", "ZINC", "Labyrinth Chollima"],
    regions: ["Korean Peninsula", "Global"],
    families: ["Dtrack", "Manuscrypt", "AppleJeus"],
    ttpTags: ["financial-theft", "wiper", "custom-c2", "crypto-targeting"],
    frameworkStatus: "needs-sample",
    statusLabel: "待样本验证",
    statusTone: "slate",
    summary: "预置金融、加密货币和破坏性活动画像，本轮仅展示框架，不参与评分。",
    caveats: ["需要真实 payload、钱包/交易所相关流量或主机证据才能进入评分。"],
    evidenceNeeds: ["金融/加密业务目标", "AppleJeus 或 Manuscrypt 家族证据", "自定义 C2 协议", "破坏性操作或横向移动证据"],
  },
  {
    id: "apt41",
    name: "APT41",
    aliases: ["Barium", "Winnti", "Double Dragon"],
    regions: ["East Asia", "Global"],
    families: ["Winnti", "ShadowPad", "PlugX"],
    ttpTags: ["supply-chain", "webshell", "credential-access", "shadowpad"],
    frameworkStatus: "framework",
    statusLabel: "框架预置",
    statusTone: "amber",
    summary: "规划供应链、WebShell、ShadowPad/Winnti 类证据位；当前不做自动归因。",
    caveats: ["WebShell 或 PlugX 形态广泛复用，不能直接映射到单一组织。"],
    evidenceNeeds: ["WebShell 管理流量", "ShadowPad / Winnti 样本特征", "供应链投递线索", "多阶段 C2"],
  },
  {
    id: "turla",
    name: "Turla",
    aliases: ["Snake", "Venomous Bear", "Waterbug"],
    regions: ["Europe", "Central Asia"],
    families: ["Snake", "ComRAT", "Kazuar"],
    ttpTags: ["satellite-c2", "proxy-chain", "stealth", "long-term-access"],
    frameworkStatus: "needs-sample",
    statusLabel: "待样本验证",
    statusTone: "slate",
    summary: "规划代理链、隐蔽 C2 和长期访问画像，等待真实流量样本接入。",
    caveats: ["仅凭代理链或低频通信不足以支撑组织级归因。"],
    evidenceNeeds: ["Snake/Kazuar 家族线索", "代理链或卫星 C2 特征", "长期低频通信", "主机侧持久化证据"],
  },
  {
    id: "mustang-panda",
    name: "Mustang Panda",
    aliases: ["Bronze President", "RedDelta", "TA416"],
    regions: ["East Asia", "Southeast Asia", "Europe"],
    families: ["PlugX", "Toneshell"],
    ttpTags: ["archive-lure", "plugx", "spearphishing", "regional-targeting"],
    frameworkStatus: "framework",
    statusLabel: "框架预置",
    statusTone: "amber",
    summary: "规划区域目标、诱饵压缩包和 PlugX 证据需求，本轮不参与强归因。",
    caveats: ["PlugX 被多组织复用，需要投递链和目标上下文支持。"],
    evidenceNeeds: ["诱饵压缩包/快捷方式", "PlugX/Toneshell 样本", "区域目标上下文", "C2 域名与路径复用"],
  },
  {
    id: "kimsuky",
    name: "Kimsuky",
    aliases: ["Velvet Chollima", "Thallium", "Black Banshee"],
    regions: ["Korean Peninsula", "Global"],
    families: ["BabyShark", "AppleSeed"],
    ttpTags: ["credential-phishing", "macro-lure", "mail-collection", "scripted-loader"],
    frameworkStatus: "needs-sample",
    statusLabel: "待样本验证",
    statusTone: "slate",
    summary: "预置钓鱼、凭据收集和脚本加载器画像，等待邮件/HTTP/样本证据接入。",
    caveats: ["钓鱼和脚本加载器信号通用性强，必须结合目标与基础设施。"],
    evidenceNeeds: ["邮件投递证据", "凭据收集页面或 POST", "BabyShark/AppleSeed 线索", "目标主题上下文"],
  },
  {
    id: "fin7",
    name: "FIN7",
    aliases: ["Carbanak Group", "Navigator Group"],
    regions: ["Global"],
    families: ["Carbanak", "Griffon", "DiceLoader"],
    ttpTags: ["pos-targeting", "financial-crime", "phishing", "c2-loader"],
    frameworkStatus: "framework",
    statusLabel: "框架预置",
    statusTone: "amber",
    summary: "规划金融犯罪、POS 目标与 loader C2 证据位，当前只作为画像框架。",
    caveats: ["金融行业目标和 loader 行为需要与样本家族、命令链和基础设施共同验证。"],
    evidenceNeeds: ["POS/支付系统目标", "Carbanak/DiceLoader 家族证据", "钓鱼投递链", "命令执行和数据外传证据"],
  },
  {
    id: "equation-group",
    name: "Equation Group",
    aliases: ["Equation", "EQGRP"],
    regions: ["Global"],
    families: ["DoubleFantasy", "EquationDrug", "GrayFish"],
    ttpTags: ["high-end-implant", "stealth", "firmware", "custom-c2"],
    frameworkStatus: "excluded",
    statusLabel: "不参与本轮评分",
    statusTone: "rose",
    summary: "作为高门槛画像占位，仅用于规划字段，不参与当前评分与自动归因。",
    caveats: ["缺少固件、植入体和专用 C2 样本时不应展示自动命中。"],
    evidenceNeeds: ["高端植入体样本", "固件/驱动层证据", "专用 C2 协议", "长期目标上下文"],
  },
  {
    id: "sidewinder",
    name: "SideWinder",
    aliases: ["Rattlesnake", "T-APT-04"],
    regions: ["South Asia", "Central Asia"],
    families: ["SideWinder loaders", "custom script chains"],
    ttpTags: ["spearphishing", "document-exploit", "regional-targeting", "scripted-c2"],
    frameworkStatus: "needs-sample",
    statusLabel: "待样本验证",
    statusTone: "slate",
    summary: "规划区域诱饵、文档漏洞和脚本链画像，等待样本接入后再评分。",
    caveats: ["区域诱饵与脚本链不足以独立归因。"],
    evidenceNeeds: ["文档投递证据", "脚本链/下载器", "区域目标上下文", "C2 路径和基础设施复用"],
  },
];

const REGISTRY_BY_ID = new Map(APT_ACTOR_REGISTRY.map((profile) => [profile.id, profile]));

export function getAPTActorRegistryProfile(actorId: string) {
  return REGISTRY_BY_ID.get(actorId);
}

export function buildAPTDisplayProfiles(backendProfiles: APTActorProfile[]): APTDisplayProfile[] {
  const backendById = new Map(backendProfiles.map((profile) => [profile.id, profile]));
  const merged = APT_ACTOR_REGISTRY.map((registry) => {
    const backend = backendById.get(registry.id);
    if (backend) {
      return {
        ...backend,
        registry,
        frameworkOnly: false,
      };
    }
    return buildFrameworkOnlyProfile(registry);
  });

  const extraProfiles = backendProfiles
    .filter((profile) => !REGISTRY_BY_ID.has(profile.id))
    .map((profile) => ({
      ...profile,
      registry: buildAdhocRegistryProfile(profile),
      frameworkOnly: false,
    }));

  return [...merged, ...extraProfiles];
}

function buildFrameworkOnlyProfile(registry: APTActorRegistryProfile): APTDisplayProfile {
  const isImplemented = registry.frameworkStatus === "implemented";
  return {
    id: registry.id,
    name: registry.name,
    aliases: registry.aliases,
    summary: registry.summary,
    confidence: undefined,
    evidenceCount: 0,
    sampleFamilies: bucketsFromLabels(registry.families),
    campaignStages: EMPTY_BUCKETS,
    transportTraits: EMPTY_BUCKETS,
    infrastructureHints: EMPTY_BUCKETS,
    relatedC2Families: EMPTY_BUCKETS,
    ttpTags: bucketsFromLabels(registry.ttpTags),
    scoreFactors: [],
    notes: isImplemented
      ? [
          `${registry.statusLabel}：检测框架已接入，当前抓包暂未形成该 actor 的候选证据。`,
          ...registry.caveats,
        ]
      : [
          `${registry.statusLabel}：当前不参与本轮评分，不产生强归因。`,
          ...registry.caveats,
        ],
    registry,
    frameworkOnly: !isImplemented,
  };
}

function buildAdhocRegistryProfile(profile: APTActorProfile): APTActorRegistryProfile {
  return {
    id: profile.id,
    name: profile.name,
    aliases: profile.aliases ?? [],
    regions: [],
    families: profile.sampleFamilies.map((item) => item.label),
    ttpTags: profile.ttpTags.map((item) => item.label),
    frameworkStatus: "implemented",
    statusLabel: "后端返回画像",
    statusTone: "emerald",
    summary: "该 actor 由后端分析返回，当前 registry 未内置其静态画像。",
    caveats: ["请结合后端证据表和 score factors 复核。"],
    evidenceNeeds: ["后端证据表", "score factors", "packet 定位"],
  };
}

function bucketsFromLabels(labels: string[]): TrafficBucket[] {
  return labels.map((label) => ({ label, count: 0 }));
}
