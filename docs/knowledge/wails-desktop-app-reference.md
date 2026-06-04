# Wails 桌面应用技术参考

> 基于 meow~traffic 项目的 Wails v2 桌面应用架构，整理的相关技术资料。

## 1. Wails v2 高级模式 — IPC、事件、窗口管理

### 官方文档

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **事件系统 (v2)** | [wails.io](https://wails.io/docs/v2.11.0/reference/runtime/events/) | Go 和 JS 之间的统一 pub/sub。`EventsOn`, `EventsEmit`, `EventsOnce`, `EventsOff` API。 | **直接** — SSE 转发使用此事件总线 |
| **IPC 和通信 (DeepWiki)** | [deepwiki.com](https://deepwiki.com/wailsapp/wails/5.3-ipc-and-communication) | 消息格式路由（`W*` 窗口, `C*` 调用, `EE` 事件发出, `EX` 事件清理）。平台特定桥接。 | **直接** — 理解 IPC 前缀帮助调试 |
| **事件系统 (DeepWiki)** | [deepwiki.com](https://deepwiki.com/wailsapp/wails/5.4-events-system) | 双向事件总线架构。IPC 消息协议：`'EE'` 前端→后端, `'EX'` 清理, `'n'` 后端→前端通知。 | **直接** — 事件转发内部机制 |
| **前端运行时 (DeepWiki)** | [deepwiki.com](https://deepwiki.com/wailsapp/wails/5-frontend-runtime) | `window.runtime` 对象结构，回调注册，生产模式混淆调用。 | **高** — React 前端的运行时 API |

### 关键架构洞察

**IPC 消息协议：**
```
前缀 → 处理器 → 用途
W*     → 窗口    → 窗口操作（标题、大小、状态）
C*     → 调用    → 带 JSON 负载的方法调用
EE     → 事件    → 从前端发出事件
EX     → 事件    → 注销事件监听器
BO     → 浏览器  → 在系统浏览器中打开 URL
```

**开发 vs 生产 IPC：**
- 生产：平台原生 WebView API（最快）
- 开发：WebSocket at `/wails/ipc`（支持热重载）

---

## 2. Go-React 集成 — 类型化绑定、状态同步、错误处理

### 官方文档

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **方法绑定 (v3)** | [v3.wails.io](https://v3.wails.io/features/bindings/methods/) | 从 Go 结构体自动生成 TypeScript 绑定。有状态的服务，互斥锁模式，错误处理。 | **高** — 绑定模式适用于 v2 |
| **Go-前端桥接** | [v3.wails.io](https://v3.wails.io/concepts/bridge/) | 内存桥接，零 HTTP 开销。类型映射：`string→string`, `int→number`, `struct→interface`, `error→exception`。 | **直接** — 解释应用依赖的桥接 |
| **TypeScript 运行时定义** | [GitHub](https://github.com/wailsapp/wails/blob/4d0abeb3/v2/internal/frontend/runtime/wrapper/runtime.d.ts) | `EventsEmit`, `EventsOn`, `EventsOnMultiple`, `EventsOnce`, `EventsOff`, `EventsOffAll` 的官方 TypeScript 类型定义。 | **直接** — 复制这些类型到前端 |

### 类型映射参考

```
Go 类型                → TypeScript 类型
─────────────────────────────────────────
string                 → string
int, int32, int64      → number
float32, float64       → number
bool                   → boolean
[]T                    → T[]
map[string]T           → Record<string, T>
struct                 → interface
time.Time              → Date
error                  → Exception (thrown)
```

### 生产模板

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Orion-Wails 模板** | [github.com/ITSHahrad](https://github.com/ITSHahrad/orion-wails) | React 19 + Wails v2 + Tailwind CSS v4 启动器。干净的 `/backend` 模块结构，Vite HMR。 | **高** — 项目堆栈的参考架构 |

---

## 3. 桌面应用安全 — 沙箱、更新、崩溃报告

### 安全模型

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Wails 安全模型** | [v3.wails.io](https://v3.wails.io/concepts/architecture/) | 方法白名单（仅导出方法可调用），类型验证，无 eval()，每窗口上下文。 | **直接** — 应用安全基础 |
| **IPC 源验证** | [deepwiki.com](https://deepwiki.com/wailsapp/wails/5.3-ipc-and-communication) | 所有 IPC 消息针对允许的源验证。默认：`wails://wails/`。可通过 `BindingsAllowedOrigins` 配置。 | **高** — 防止未授权跨源请求 |

### 更新机制

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Wails 更新器 (v3)** | [v3.wails.io](https://v3.wails.io/guides/updater/) | 状态机：idle→checking→available→downloading→verifying→installing→ready。提供者：GitHub Releases, keygen.sh。Ed25519 签名验证。 | **直接** — 生产更新机制 |
| **wails-kit 更新服务** | [GitHub](https://github.com/jrschumacher/wails-kit/blob/main/updates/README.md) | 零依赖 GitHub Releases 更新器。Ed25519 验证，归档提取，事件驱动。 | **高** — v2 的替代实现 |

### 更新事件流

```
updates:available  → {Version, ReleaseNotes, ReleaseURL}
updates:downloading → {Version, Progress, Downloaded, Total}
updates:ready      → {Version}
updates:error      → {Message, Code}
```

---

## 4. 桌面应用中的 SSE — 实时流、重连

### Go SSE 库

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **tmaxmax/go-sse** | [github.com/tmaxmax](https://github.com/tmaxmax/go-sse) | 符合规范的 SSE 库。服务器 + 客户端。自动重连与 `cenkalti/backoff`。`Last-Event-ID` 支持。 | **高** — 生产就绪 |
| **apt304/sse-go** | [github.com/apt304](https://github.com/apt304/sse-go) | 基于主题的广播，心跳支持，生命周期钩子。客户端指数退避 + 抖动。 | **高** — 基于主题的 pub/sub |
| **coregx/stream** | [github.com/coregx](https://github.com/coregx/stream) | Go 1.25+ 的 SSE + WebSocket。RFC 兼容，零依赖，92.3% 测试覆盖率。 | **高** — 如果同时需要 SSE 和 WebSocket |

### SSE vs WebSocket 权衡

| 方面 | SSE | WebSocket |
|------|-----|-----------|
| 方向 | 服务器→客户端（单向） | 双向 |
| 协议 | HTTP（支持 HTTP/2） | 升级的 HTTP |
| 重连 | 内置（`Last-Event-ID`） | 手动实现 |
| 调试 | 纯文本，`curl` 友好 | 二进制帧 |
| 浏览器支持 | 除 IE 外全部 | 通用 |

---

## 5. 嵌入式资产服务 — Vite 构建集成、热重载

### 官方文档

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **应用开发（资产）** | [wails.io](https://wails.io/docs/guides/application-development) | `embed.FS` 方法。`wails.json` 键：`frontend:install`, `frontend:build`。 | **直接** — 构建管道配置 |
| **静态和动态资产 (DeepWiki)** | [deepwiki.com](https://deepwiki.com/wailsapp/wails/9.2-static-and-dynamic-assets) | 请求链：中间件 → 资产 → 处理器 → 默认错误。开发模式：热重载 + Vite 代理。 | **高** — 资产服务内部机制 |

### Vite 集成模式

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Vite + Wails HMR 问题** | [GitHub](https://github.com/wailsapp/wails/issues/3240) | Vite 5+ 在开发模式下破坏了动态资产。修复：vite.config 中的 `appType: 'custom'`。 | **高** — 如果使用 Vite 5+ |
| **Wails + PrimeVue 模板** | [GitHub](https://github.com/sacha09/wails-template-primevue-sakai) | 三种 HMR 策略：(1) Vite HMR, (2) Wails 自动重载, (3) Vite `build --watch` 模式。 | **高** — 全面的 HMR 配置 |

### wails.json 配置示例

**Vite HMR 模式（推荐）：**
```json
{
  "frontend:dev:watcher": "npm run dev",
  "frontend:dev:serverUrl": "auto",
  "debounceMS": 500
}
```

**Vite 构建监视模式（后备）：**
```json
{
  "frontend:dev:build": "npm run dev-build",
  "frontend:dev:watcher": "npm run dev-build-watch",
  "debounceMS": 2000
}
```
