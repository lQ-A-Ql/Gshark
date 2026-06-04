# YARA 与威胁狩猎技术参考

> 基于 meow~traffic 项目的 YARA 集成和威胁狩猎功能，整理的相关技术资料。

## 1. YARA 规则编写最佳实践

### 核心参考

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Trail of Bits YARA 编写指南** | [trailofbits-skills.mintlify.app](https://trailofbits-skills.mintlify.app/plugins/yara-authoring) | 专家级 YARA-X 指导：决策树、原子质量、短路条件、命名约定、goodware 语料库验证。比传统 YARA 快 5-10 倍。 | **高** — 生产级模式，性能优化 |
| **Neo23x0 YARA 性能指南** | [github.com/Neo23x0](https://github.com/Neo23x0/YARA-Performance-Guidelines) | 涵盖原子提取、Aho-Corasick 搜索、条件短路、模块开销。关键洞察：`filesize` 检查即时，正则很慢。 | **高** — 直接适用于扫描引擎 |
| **YARA 官方文档** | [yara.readthedocs.io](https://yara.readthedocs.io/en/stable/writingrules.html) | 规范参考：字符串类型（text/hex/regex）、条件逻辑、全局规则、私有规则、标签、元数据、外部变量、模块。 | **高** — 基础参考 |
| **Gen Digital — YARA 规则优化** | [gendigital.com](https://www.gendigital.com/blog/insights/research/know-your-yara-rules-series-2-rewrite-your-rules) | 微优化：`uintXY()` vs 十六进制模式（快 50%）、拆分交替以改善原子选择、正则收窄。 | **高** — 实用重写技巧 |
| **Intezer — 减少误报** | [intezer.com](https://intezer.com/blog/yara-rules-minimize-false-positives/) | 代码复用分析方法：将二进制分解为"基因"以识别恶意 vs 可信代码。 | **中** — 新颖的误报减少方法 |

### 性能层次（快 → 慢）

```
1. Filesize 检查（即时）
2. uint16(0) == 0x5A4D（几乎即时）
3. 固定十六进制模式（非常快）
4. 锚定文本字符串（快）
5. PE 模块检查（中等）
6. 非锚定文本字符串（慢）
7. 正则表达式（非常慢）
8. math.entropy()（CPU 密集型）
```

### 关键反模式

- 字符串 < 4 字节（强制慢速验证）
- 无界正则（`.*`, `.+`）
- `nocase` 使原子生成翻倍
- `wide` 使字符串匹配翻倍
- 没有 `filesize` 边界的循环

---

## 2. 威胁狩猎框架

### 核心参考

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **MITRE TTP 狩猎方法论** | [mitre.org](https://www.mitre.org/news-insights/publication/ttp-based-hunting) | 基础论文："V 图"方法论 — 恶意活动表征（左侧）+ 狩猎执行（右侧）。使用 ATT&CK + CAR 数据模型。 | **高** — 规范方法论 |
| **MITRE ATT&CK 培训** | [attack.mitre.org](https://attack.mitre.org/resources/learn-more-about-attack/training/threat-hunting/) | 6 模块培训：基础 → 假设 → 数据需求 → 差距分析 → 实现分析 → 狩猎和调查。 | **高** — 官方培训课程 |
| **Google Cloud ATT&CK 指南** | [security.googlecloudcommunity.com](https://security.googlecloudcommunity.com/google-threat-intelligence-67/adoption-guide-threat-hunting-using-mitre-att-ck-6388) | Google TI 集成：`attack_tactic:`, `attack_technique:` 搜索修饰符。6 个用例。 | **中** — 厂商特定但技术示例好 |

### 狩猎假设模板

```
"使用 [ATT&CK 技术 ID] 的对手可能存在于我们的环境中，
证据是 [日志/遥测中的特定可观察数据]。"

示例："使用 T1055（进程注入）的对手可能存在，证据是
浏览器进程生成命令 shell 的非标准父子进程关系。"
```

---

## 3. APT 检测技术

### 核心参考

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **CPD — 持久性检测** | [arxiv.org](https://www.arxiv.org/pdf/2407.18832) | 通过溯源分析检测持久性。关键洞察：持久性有两个阶段（"设置" + "执行"）。APT29、Wizard Spider、Sandworm 案例研究。 | **高** — 直接相关于持久性检测 |
| **TAPAS — 在线 APT 检测** | [usenix.org](https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-bo-tapas) | 生产级：存储减少 1806 倍，99.99% 准确率，每 GB 12.78 秒检测时间。 | **高** — 经过验证的可扩展方法 |
| **增强横向移动检测** | [techscience.com](https://www.techscience.com/cmc/v83n1/60072) | 轻量级 ML 用于 LAN 中的 APT 横向移动检测。99.95% 检测率。 | **高** — 实用网络级检测 |

### APT 检测模式

**横向移动指标：**
- 远程连接前的远程系统发现（T1018）
- 域加入计算机之间的入口工具传输（T1105）
- 横向移动前的凭据访问
- 横向移动期间/之后的本地帐户创建
- 到多个主机的 SMB/RDP/WinRM 连接

**持久性机制：**
- 注册表运行键（T1547.001）
- 计划任务（T1053）
- Windows 服务（T1543.003）
- DLL 劫持（T1574）
- COM 对象劫持（T1546）

---

## 4. 内存取证中的 YARA

### 核心参考

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Volatility 3 Malfind 插件** | [volatility3.readthedocs.io](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/plugins/windows/malware/malfind.html) | 列出具有注入代码的进程内存范围。检测标准：`PAGE_EXECUTE_READWRITE` + 私有内存。 | **高** — YARA 引擎集成参考 |
| **Volatility 3 VadYaraScan 插件** | [volatility3.readthedocs.io](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/plugins/windows/vadyarascan.html) | 使用 YARA 扫描所有 VAD 内存映射。遍历 VAD 树，分块读取内存，应用 YARA 规则。 | **高** — 内存 YARA 扫描实现参考 |
| **Malhunt** | [github.com/andreafortuna](https://github.com/andreafortuna/malhunt) | 自动化工作流：YARA 扫描（3310+ 规则）→ malfind 注入检测 → 网络分析 → ClamAV 确认。 | **高** — 系统集成模式 |

### 内存扫描检测逻辑

```python
# 来自 Volatility malfind - 关键检测标准
def is_suspicious(vad, proc_layer):
    protection = vad.get_protection()
    
    # 红旗：可执行 + 可写
    write_exec = "EXECUTE" in protection and "WRITE" in protection
    
    # 检查不可写 EXECUTE 区域中的脏页
    if "EXECUTE" in protection and not write_exec:
        for page in range(vad.get_start(), vad.get_end(), page_size):
            if proc_layer.is_dirty(page):
                return True  # 检测到提升的 WriteProcessMemory()
    
    # VadS 标签的私有内存 + EXECUTE
    if vad.get_private_memory() == 1 and vad.get_tag() == "VadS":
        if write_exec:
            return True
    
    return write_exec
```

**注入检测模式：**
- 私有内存中的 `PAGE_EXECUTE_READWRITE` → 高度可疑
- `PAGE_EXECUTE_READ` 区域中的脏页 → 提升的 WriteProcessMemory
- VAD 开头的 MZ 头（`4D 5A`）→ 反射 PE 注入
- 非图像内存中的函数序言（`55 8b`, `55 48`）→ Shellcode

---

## 5. 社区 YARA 规则与工具

### 核心仓库

| 资源 | URL | 摘要 | 相关度 |
|------|-----|------|--------|
| **Neo23x0/signature-base** | [github.com/Neo23x0](https://github.com/Neo23x0/signature-base) | 2903★ — YARA 签名 + IOC 数据库。高质量规则，最小误报，一致格式。 | **高** — 主要社区规则源 |
| **Yara-Rules/rules** | [github.com/Yara-Rules](https://github.com/Yara-Rules/rules) | 社区维护的 YARA 规则仓库。按恶意软件类型分类。 | **高** — 广泛覆盖 |
| **Elastic Protections** | [github.com/elastic](https://github.com/elastic/protections) | Elastic Security 的端点检测 YARA 规则。 | **中** — 厂商生产级规则 |
| **Malhunt** | [github.com/andreafortuna](https://github.com/andreafortuna/malhunt) | 自动化内存取证：Volatility3 + YARA + ClamAV。 | **高** — 集成模式 |

### 规则质量检查清单（来自 Trail of Bits）

```markdown
部署任何规则前：
- [ ] 名称遵循 {CATEGORY}_{PLATFORM}_{FAMILY}_{VARIANT}_{DATE}
- [ ] 描述以 "Detects" 开头并解释什么/如何
- [ ] 所有必需元数据存在（作者、参考、日期）
- [ ] 字符串是唯一的（不是 API 名称、常见路径、格式字符串）
- [ ] 所有字符串有 4+ 字节且原子潜力好
- [ ] Base64 修饰符仅用于 3+ 字符的字符串
- [ ] 条件以廉价检查开始（filesize, magic bytes）
- [ ] 规则匹配所有目标样本
- [ ] 规则在 goodware 语料库上产生零匹配
- [ ] yr check / yr fmt --check 通过
- [ ] 同行评审完成
```

### 字符串选择优先级（层级系统）

```
金级:   互斥体名称、PDB 路径、堆栈字符串（几乎总是唯一）
银级:   唯一配置标记、自定义协议字符串
铜级:   常见 API + 行为上下文的组合
避免:   单独的通用 API 名称、常见路径、格式字符串
```
