# 日期: 2026-05-05 19:06:40 +08:00
# 署名: Codex

# 主线收口：Evidence 范围澄清、车机 / USB 证据接入与验证报告

## 一、本轮目标

本轮执行“聚焦主线，收口为入侵检测与威胁流量分析工作台”的实施计划，核心目标不是继续扩张页面，而是把统一证据链真正收束到主分析模块：

- 明确 **MISC 不进入 Evidence**，避免实验性或手工解码结果污染全局证据总览。
- 将 **Vehicle / USB** 中足够稳定、可复核、可定位的高价值信号接入统一 Evidence。
- 校正前端 Evidence 模块语义，避免把 `industrial / vehicle / usb` 错归到 `misc`。
- 为新增主线证据补充测试与文档，验证没有偏离“入侵检测与威胁流量分析工具”定位。

## 二、已完成改动

### 1. 后端 Evidence 聚合范围收口

- `backend/internal/engine/evidence.go`
  - 保持 **MISC / WebShell / WinRM / SMB3 / NTLM / Shiro** 不接入 `GatherEvidence()`。
  - 新增 `vehicle` 与 `usb` 两个主线模块聚合分支。
  - 新增 `gatherVehicleEvidence()`：
    - 基于 UDS 事务构造证据。
    - 重点覆盖负响应、孤立响应、请求未配对，以及 `0x27 / 0x2e / 0x2f / 0x31 / 0x34 / 0x36 / 0x37 / 0x10` 等高价值诊断服务。
    - 输出统一 `packetId / summary / value / confidence / severity / tags / caveats`。
  - 新增 `gatherUSBEvidence()`：
    - 仅从 **Mass Storage 写操作** 提取主线证据。
    - 对非正常状态、Data Residue 等情况提升置信度。
    - 不把键盘回放、鼠标行为、手工工作台结果写进统一 Evidence。

### 2. 前端 Evidence 模块语义校正

- `frontend/src/app/features/evidence/evidenceSchema.ts`
  - 统一模块名为：`hunting / c2 / apt / industrial / object / vehicle / usb / misc / stream / unknown`。
  - 弃用旧的 `c2-analysis / apt-analysis / threat-hunting / object-export` 风格模块值，避免前后端两套口径。
- `frontend/src/app/integrations/wailsBridge.ts`
  - 修复 `normalizeEvidenceModule()`，不再把 `industrial / vehicle / usb` 归到 `misc`。
  - 收敛 `/api/evidence` 响应解析，统一走 `parseEvidenceRecords()`。
- `frontend/src/app/pages/EvidencePanel.tsx`
  - 模块过滤新增 **车机分析 / USB 分析**。
  - 总览文案与标签同步更新。
  - 证据面板继续保持主线调查总览定位，不引入 MISC 过滤入口。

### 3. 测试补齐

- 新增 `backend/internal/engine/evidence_test.go`
  - 验证 `GatherEvidence()` 可按模块过滤并保持 **MISC 不入 Evidence**。
  - 验证 hunting / c2 / industrial / object 主链证据字段完整性。
  - 验证 `ExtractObjects()` 的 magic bytes 检测与 MIME 回推。
- 新增 `frontend/src/app/pages/EvidencePanel.test.tsx`
  - 验证 Evidence 面板包含 vehicle / usb 过滤项且无 MISC 过滤项。
  - 验证搜索、severity 过滤、module 过滤与 JSON 导出链路。
- 更新 `frontend/src/app/features/evidence/evidenceSchema.test.ts`
  - 对齐新的模块命名。
- 微调 `frontend/src/app/pages/MiscTools.test.tsx`
  - 延长 payload workbench 懒加载等待窗口，降低全量测试下的偶发抖动。

## 三、验证记录

本轮执行并通过：

- `cd backend && go test ./...`
- `cd frontend && pnpm run test`
- `cd frontend && npx tsc --noEmit --noUnusedLocals --noUnusedParameters`
- `cd frontend && pnpm run build`

当前结果：

- Backend：全部通过
- Frontend：19 个测试文件、87 个测试通过
- TypeScript 严格检查：通过
- Vite 生产构建：通过

## 四、当前结论

本轮改动后，Evidence 总览与项目主定位更一致：

- **Evidence 只承载主线、稳定、可复核信号**。
- **MISC 保持辅助工作台，不再抢主叙事**。
- Vehicle / USB 已从“仅页面展示”更进一步进入调查链，能参与统一搜索、过滤、导出与跳包。
- 前端模块语义从“展示名驱动”修正为“主线模块驱动”，减少后续误分类风险。

## 五、对最新开发文档的评审

本轮开发前已复核 `docs/README.md` 与 `docs/audit-development-report-archive-2026-05-02/c2-apt-misc-productization-report-2026-05-02.md`。评审结论如下：

### 优点

- 最新文档对 C2 / APT / MISC / 前端模块化的事实描述基本与代码一致。
- 文档已经明确提出“把主线重新放回证据 schema、真实样本验证和误报抑制”，方向判断正确。

### 问题

- 最新开发事实已经续写到 2026-05-04，但仍挂在 `2026-05-02` 归档标题下，**日期语义滞后**。
- 文档曾提及 `/api/evidence` 继续扩主线，但未明确写死 “MISC 不接入 Evidence”，本轮已在代码上落实该边界。
- 部分历史描述仍保留 “可继续把 WebShell 接入统一 evidence” 的自然延伸路径；结合本轮策略，应改为 **保留在 MISC，本页内解释，不入总览**。

### 本轮评审处理

- 已新建 `docs/audit-development-report-archive-2026-05-05/`，将本轮主线收口内容按新日期归档。
- 已更新文档总入口，使最新阅读顺序先指向 2026-05-05。

## 六、下一步建议

1. 继续补 **真实样本验证**：
   - C2：VShell / Cobalt Strike / 弱信号回退
   - Vehicle：UDS 正常 / 负响应 / 安全访问异常
   - Industrial：Modbus 可疑写与设备行为解释
   - Object：magic bytes 对伪装文件和 office / archive / executable 的准确率
2. 继续扩主线 Evidence，但仍遵守边界：
   - 优先协议主链、Vehicle、Industrial、USB 中稳定信号
   - 明确 **不从 MISC 反灌 Evidence**
3. 后续新增能力默认先问：
   - 是否直接提升检测、还原、定位、导出、解释？
   - 若不能，降级为支线或放入 MISC 辅助台
