// GShark-Sentinel 高置信度流量特征规则包
// 说明：
// 1. 这份规则优先覆盖 2024-2026 年间“能在网络流量中稳定留下 URI / 参数 / 载荷特征”的高危 CVE。
// 2. 同时补充常见 WebShell / 隧道 / 管理后门的流量侧特征。
// 3. 这不是“所有 CVE”的数学完备集合，而是偏实战、偏高信噪比的网络侧命中集合，适合在 HTTP / TCP 重组内容中使用。

rule TRAFFIC_CVE_2024_1709_SCREENCONNECT_SETUPWIZARD_AUTH_BYPASS
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2024"
    cve = "CVE-2024-1709"
    severity = "critical"
    description = "ConnectWise ScreenConnect SetupWizard 认证绕过常见请求路径"
  strings:
    $u1 = "/SetupWizard.aspx" nocase
    $u2 = "GET /SetupWizard.aspx" nocase
    $u3 = "POST /SetupWizard.aspx" nocase
  condition:
    any of them
}

rule TRAFFIC_CVE_2024_27198_TEAMCITY_AUTH_BYPASS
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2024"
    cve = "CVE-2024-27198"
    severity = "critical"
    description = "JetBrains TeamCity 身份绕过相关探测与利用路径"
  strings:
    $u1 = "/app/rest/server;.jsp" nocase
    $u2 = "/hax?jsp=/app/rest/server" nocase
    $u3 = "/app/rest/users/id:1/tokens" nocase
  condition:
    any of them
}

rule TRAFFIC_CVE_2024_3400_PANOS_GLOBALPROTECT_RCE
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2024"
    cve = "CVE-2024-3400"
    severity = "critical"
    description = "Palo Alto PAN-OS GlobalProtect / hipreport.esp 利用与后续投递线索"
  strings:
    $u1 = "/ssl-vpn/hipreport.esp" nocase
    $u2 = "SESSID=" nocase
    $u3 = "cmd=install" nocase
    $u4 = "curl " nocase
    $u5 = "wget " nocase
  condition:
    $u1 and 1 of ($u2, $u3, $u4, $u5)
}

rule TRAFFIC_CVE_2024_36401_GEOSERVER_PROPERTY_RCE
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2024"
    cve = "CVE-2024-36401"
    severity = "critical"
    description = "GeoServer / GeoTools 属性表达式远程代码执行常见请求特征"
  strings:
    $u1 = "/geoserver/wfs" nocase
    $u2 = "/geoserver/ows" nocase
    $p1 = "valueReference=" nocase
    $p2 = "propertyName=" nocase
    $x1 = "exec(" nocase
    $x2 = "java.lang.Runtime" nocase
    $x3 = "ProcessBuilder" nocase
  condition:
    1 of ($u*) and 1 of ($p*) and 1 of ($x*)
}

rule TRAFFIC_CVE_2024_4577_PHP_CGI_ARGUMENT_INJECTION
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2024"
    cve = "CVE-2024-4577"
    severity = "critical"
    description = "PHP CGI 参数注入常见利用片段"
  strings:
    $q1 = /%[aA][dD]d\+auto_prepend_file=php:\/\/input/
    $q2 = /%[aA][dD]d\+allow_url_include=1/
    $q3 = "-d auto_prepend_file=php://input" nocase
    $q4 = "php://input" nocase
    $q5 = "allow_url_include=1" nocase
  condition:
    any of ($q1, $q2, $q3) or ($q4 and $q5)
}

rule TRAFFIC_CVE_2025_24813_TOMCAT_PARTIAL_PUT_RCE
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    cve = "CVE-2025-24813"
    severity = "high"
    description = "Apache Tomcat Partial PUT / session 反序列化利用线索"
  strings:
    $m1 = "PUT /" nocase
    $h1 = "Content-Range:" nocase
    $s1 = ".session" nocase
    $s2 = "JSESSIONID" nocase
  condition:
    $m1 and $h1 and 1 of ($s*)
}

rule TRAFFIC_CVE_2025_49704_49706_SHAREPOINT_TOOLSHELL
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    cve = "CVE-2025-49704/CVE-2025-49706"
    severity = "critical"
    description = "SharePoint ToolShell 利用与探测常见路径"
  strings:
    $u1 = "/_layouts/15/ToolPane.aspx" nocase
    $u2 = "DisplayMode=Edit" nocase
    $u3 = "a=/ToolPane.aspx" nocase
    $u4 = "/_layouts/SignOut.aspx" nocase
    $u5 = "X-RequestDigest:" nocase
  condition:
    $u1 and 1 of ($u2, $u3, $u4, $u5)
}

rule TRAFFIC_CVE_2025_53770_SHAREPOINT_TOOLSHELL_PATCH_BYPASS
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    cve = "CVE-2025-53770"
    severity = "critical"
    description = "SharePoint ToolShell 补丁绕过与后续落地 WebShell 常见文件线索"
  strings:
    $u1 = "/_layouts/15/ToolPane.aspx" nocase
    $f1 = "spinstall0.aspx" nocase
    $f2 = "spinstall1.aspx" nocase
    $f3 = "debug_dev.js" nocase
  condition:
    $u1 or any of ($f*)
}

rule TRAFFIC_CVE_2025_47952_TRAEFIK_URLENCODED_TRAVERSAL
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    cve = "CVE-2025-47952"
    severity = "medium"
    description = "Traefik 编码路径穿越，常见利用为 /%2e%2e/ 绕过 PathPrefix / PathRegex"
  strings:
    $t1 = "/%2e%2e/" nocase
    $t2 = "/public/%2e%2e/private" nocase
    $t3 = "/service/%2e%2e/" nocase
  condition:
    any of them
}

rule TRAFFIC_CVE_2025_55752_TOMCAT_REWRITEVALVE_TRAVERSAL
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    cve = "CVE-2025-55752"
    severity = "high"
    description = "Tomcat RewriteValve 路径穿越，常见表现为 path 参数访问 WEB-INF / 上传目录"
  strings:
    $u1 = "GET /download?path=%2FWEB-INF%2Fweb.xml" nocase
    $u2 = "GET /download?path=%2Fuploads%2Fshell.jsp" nocase
    $u3 = "path=%2FWEB-INF%2F" nocase
    $u4 = "path=%2Fuploads%2F" nocase
    $u5 = "WEB-INF/web.xml" nocase
  condition:
    any of them
}

rule TRAFFIC_CVE_2025_24893_XWIKI_SOLRSEARCH_RCE
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    cve = "CVE-2025-24893"
    severity = "critical"
    description = "XWiki SolrSearch 未授权 RCE 常见请求片段"
  strings:
    $x1 = "Main.SolrSearch" nocase
    $x2 = "media=rss" nocase
    $x3 = "outputSyntax=plain" nocase
    $x4 = "{{groovy}}" nocase
    $x5 = "{{async async=false}}" nocase
  condition:
    ($x1 and 1 of ($x2, $x3, $x4, $x5)) or (all of ($x2, $x3, $x4))
}

rule TRAFFIC_CVE_2025_64111_GOGS_SYMLINK_SHIMMY_RCE
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    cve = "CVE-2025-64111"
    severity = "critical"
    description = "Gogs API 借助 symlink 写入 .git/config 并注入 core.sshCommand 的高危特征"
  strings:
    $g1 = "/api/v1/repos/" nocase
    $g2 = "/contents/" nocase
    $g3 = ".git/config" nocase
    $g4 = "core.sshCommand" nocase
    $g5 = "core.editor" nocase
    $g6 = "\"content\":" nocase
  condition:
    ($g1 and $g2 and 1 of ($g3, $g4, $g5)) or (all of ($g3, $g4, $g6))
}

rule TRAFFIC_CVE_2025_GIT_CONFIG_QUOTING_RCE_CLONE_CHAIN
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    cve = "GHSA-vwqx-4fm8-6qc9"
    severity = "high"
    description = "Git 2025 配置引用缺陷相关的 HTTP clone / submodule 可疑链路片段"
  strings:
    $c1 = ".gitmodules" nocase
    $c2 = "submodule" nocase
    $c3 = "git-upload-pack" nocase
    $c4 = "bundle-uri" nocase
    $c5 = "core.sshCommand" nocase
  condition:
    3 of them
}

rule TRAFFIC_CVE_2025_6466_RUOYI_AI_AUDIO_UPLOAD
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    project = "ruoyi-ai"
    cve = "CVE-2025-6466"
    severity = "high"
    confidence = "medium"
    description = "ruoyi-ai 任意文件上传链路，重点关注 /audio 音频转文字上传接口与危险文件名"
  strings:
    $r1 = "POST /audio" nocase
    $r2 = "multipart/form-data" nocase
    $r3 = "filename=\"" nocase
    $r4 = ".jsp" nocase
    $r5 = ".jspx" nocase
    $r6 = ".php" nocase
    $r7 = ".ashx" nocase
    $r8 = ".aspx" nocase
  condition:
    $r1 and $r2 and $r3 and 1 of ($r4, $r5, $r6, $r7, $r8)
}

rule TRAFFIC_CVE_2025_51825_JEECGBOOT_PARSESQL_SQLI
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    project = "JeecgBoot"
    cve = "CVE-2025-51825"
    severity = "medium"
    confidence = "high"
    description = "JeecgBoot /jeecg-boot/online/cgreport/head/parseSql SQL 注入"
  strings:
    $j1 = "/jeecg-boot/online/cgreport/head/parseSql" nocase
    $j2 = "select " nocase
    $j3 = " union " nocase
    $j4 = "information_schema" nocase
    $j5 = "sleep(" nocase
    $j6 = "benchmark(" nocase
  condition:
    $j1 and 1 of ($j2, $j3, $j4, $j5, $j6)
}

rule TRAFFIC_CVE_2025_7787_XXLJOB_HTTPJOBHANDLER_SSRF
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    project = "XXL-JOB"
    cve = "CVE-2025-7787"
    severity = "medium"
    confidence = "low"
    description = "XXL-JOB httpJobHandler SSRF，常见于任务参数中直接出现 httpJobHandler 与外部 URL"
  strings:
    $x1 = "httpJobHandler" nocase
    $x2 = "executorHandler=httpJobHandler" nocase
    $x3 = "http://127.0.0.1" nocase
    $x4 = "http://169.254.169.254" nocase
    $x5 = "http://localhost" nocase
    $x6 = "https://" nocase
  condition:
    1 of ($x1, $x2) and 1 of ($x3, $x4, $x5, $x6)
}

rule TRAFFIC_CVE_2025_XXLJOB_COMMANDJOBHANDLER_RCE
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "CVE"
    year = "2025"
    project = "XXL-JOB"
    issue = "xuxueli/xxl-job#3750"
    severity = "high"
    confidence = "low"
    description = "XXL-JOB commandJobHandler 命令注入，常见表现为任务参数中带 commandJobHandler 与系统命令"
  strings:
    $c1 = "commandJobHandler" nocase
    $c2 = "executorHandler=commandJobHandler" nocase
    $c3 = "cmd.exe /c" nocase
    $c4 = "/bin/sh -c" nocase
    $c5 = "powershell " nocase
    $c6 = "bash -c " nocase
  condition:
    1 of ($c1, $c2) and 1 of ($c3, $c4, $c5, $c6)
}

rule TRAFFIC_WEBSHELL_CHINA_CHOPPER
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "webshell"
    description = "中国菜刀 / 一句话木马常见流量与载荷片段"
  strings:
    $a1 = "@eval($_POST" nocase
    $a2 = "@eval($_REQUEST" nocase
    $a3 = "assert($_POST" nocase
    $a4 = "base64_decode($_POST" nocase
    $a5 = "echo(md5(" nocase
  condition:
    any of them
}

rule TRAFFIC_WEBSHELL_BEHINDER
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "webshell"
    aliases = "冰蝎,Behinder"
    description = "Behinder / 冰蝎常见会话标记与载荷片段"
  strings:
    $b1 = "X-Requested-With: XMLHttpRequest" nocase
    $b2 = "AES/ECB/PKCS5Padding" ascii
    $b3 = "Class.forName(\"java.lang.ProcessBuilder\")" ascii
    $b4 = "pass=" nocase
    $b5 = "eval(base64_decode(" nocase
  condition:
    2 of them
}

rule TRAFFIC_WEBSHELL_GODZILLA
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "webshell"
    aliases = "哥斯拉,Godzilla"
    description = "Godzilla 常见加密载荷 / 参数拼接痕迹"
  strings:
    $g1 = "pass=" nocase
    $g2 = "payload=" nocase
    $g3 = "xc=" nocase
    $g4 = "base64_decode" nocase
    $g5 = "md5(pass" nocase
    $g6 = "gzip" nocase
  condition:
    3 of them
}

rule TRAFFIC_WEBSHELL_ANTSWORD_GENERIC
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "webshell"
    aliases = "蚁剑,AntSword"
    description = "蚁剑 / AntSword 常见管理请求与载荷片段"
  strings:
    $a1 = "antSword" nocase
    $a2 = "eval(base64_decode" nocase
    $a3 = "system($_POST" nocase
    $a4 = "shell_exec($_POST" nocase
    $a5 = "passthru($_POST" nocase
  condition:
    2 of them
}

rule TRAFFIC_WEBSHELL_REGEORG_TUNNEL
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "tunnel"
    aliases = "reGeorg,neo-reGeorg"
    description = "reGeorg / neo-reGeorg 常见隧道通信头和控制参数"
  strings:
    $r1 = "X-CMD:" nocase
    $r2 = "X-TARGET:" nocase
    $r3 = "X-STATUS:" nocase
    $r4 = "X-ERROR:" nocase
    $r5 = "CONNECT " nocase
    $r6 = "FORWARD " nocase
  condition:
    2 of ($r1, $r2, $r3, $r4) or ($r5 and $r6)
}

rule TRAFFIC_C2_VSHELL_WEBSOCKET_LISTENER
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "c2"
    tool = "Vshell"
    description = "Vshell WebSocket 监听器上线流量，常见路径为 /?a=l64|w64&h=<host>&t=ws_&p=<port>"
  strings:
    $v1 = "Upgrade: websocket" nocase
    $v2 = "GET /?a=l64&h=" nocase
    $v3 = "GET /?a=w64&h=" nocase
    $v4 = "&t=ws_" nocase
    $v6 = "GET /ws " nocase
  condition:
    ($v1 and 1 of ($v2, $v3) and $v4) or ($v6 and $v1)
}

rule TRAFFIC_C2_VSHELL_TCP_ONLINE_MARKER
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "c2"
    tool = "Vshell"
    description = "Vshell TCP 监听器常见上线短标记，客户端架构常见为 l64 / w64"
  strings:
    $t1 = "l64"
    $t2 = "w64"
  condition:
    any of them
}

rule TRAFFIC_C2_VSHELL_DOH_TASKING
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "c2"
    tool = "Vshell"
    description = "Vshell DoH / DNS 任务分发常见特征，含 api 前缀与 0.0.0.242/243 任务信号"
  strings:
    $d1 = "api" nocase
    $d2 = "0.0.0.242"
    $d3 = "0.0.0.243"
    $d4 = "type\":\"A\"" nocase
    $d5 = "type\":\"TXT\"" nocase
  condition:
    ($d1 and 1 of ($d2, $d3)) or ($d1 and $d4 and $d5)
}

rule TRAFFIC_WEBSHELL_GENERIC_PHP_JSP_CMD_EXEC
{
  meta:
    author = "Codex"
    language = "zh-CN"
    family = "webshell"
    description = "通用 PHP / JSP 命令执行型 WebShell 片段"
  strings:
    $p1 = "cmd.exe /c" nocase
    $p2 = "/bin/sh -c" nocase
    $p3 = "Runtime.getRuntime().exec" nocase
    $p4 = "ProcessBuilder(" nocase
    $p5 = "shell_exec(" nocase
    $p6 = "passthru(" nocase
    $p7 = "system(" nocase
  condition:
    any of them
}
