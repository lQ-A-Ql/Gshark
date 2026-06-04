// Community YARA rules - WebShell signatures
// Based on Neo23x0/signature-base patterns
// Source: https://github.com/Neo23x0/signature-base

rule COMMUNITY_WEBSHELL_ChinaChopper_Generic {
  meta:
    description = "Detects China Chopper webshell"
    author = "Neo23x0"
    date = "2023-01-01"
    severity = "critical"
    family = "ChinaChopper"
  strings:
    $s1 = "eval(Request" ascii
    $s2 = "eval($_POST" ascii
    $s3 = "eval($_GET" ascii
    $s4 = "eval($_REQUEST" ascii
    $s5 = "assert($_POST" ascii
    $s6 = "assert($_GET" ascii
    $s7 = "Execute(Request" ascii
    $password = "123456" ascii
    $delimiter = "z1" ascii
    $param = "action" ascii
  condition:
    any of ($s*) and ($password or ($delimiter and $param))
}

rule COMMUNITY_WEBSHELL_Webshell_Generic_PHP {
  meta:
    description = "Detects generic PHP webshell patterns"
    author = "Neo23x0"
    date = "2023-01-01"
    severity = "high"
    family = "WebShell"
  strings:
    $s1 = "eval(gzinflate(base64_decode(" ascii
    $s2 = "eval(base64_decode(" ascii
    $s3 = "eval(gzuncompress(" ascii
    $s4 = "eval(gzdecode(" ascii
    $s5 = "assert(gzinflate(base64_decode(" ascii
    $s6 = "preg_replace(\"/.*/e\"" ascii
    $s7 = "create_function(" ascii
    $s8 = "call_user_func(" ascii
    $s9 = "$_FILES" ascii
    $s10 = "move_uploaded_file" ascii
    $backconnect1 = "fsockopen(" ascii
    $backconnect2 = "socket_create(" ascii
    $backconnect3 = "stream_socket_client(" ascii
  condition:
    (any of ($s1, $s2, $s3, $s4, $s5, $s6, $s7)) or
    ($s8 and any of ($s9, $s10)) or
    (any of ($s1, $s2, $s3) and any of ($backconnect*))
}

rule COMMUNITY_WEBSHELL_Behinder_Shell {
  meta:
    description = "Detects Behinder/冰蝎 encrypted webshell"
    author = "Neo23x0"
    date = "2023-01-01"
    severity = "critical"
    family = "Behinder"
  strings:
    $java1 = "java.lang.Runtime" ascii
    $java2 = "java.io.ByteArrayOutputStream" ascii
    $java3 = "javax.crypto.Cipher" ascii
    $java4 = "javax.crypto.spec.SecretKeySpec" ascii
    $php1 = "openssl_decrypt" ascii
    $php2 = "aes-128-ecb" ascii
    $php3 = "base64_decode" ascii
    $aspx1 = "System.Security.Cryptography.RijndaelManaged" ascii
    $aspx2 = "System.IO.MemoryStream" ascii
    $key1 = "e45e329feb5d925b" ascii
    $key2 = "rebeyond" ascii
    $key3 = "webshell" ascii
  condition:
    (all of ($java*) and any of ($key*)) or
    (all of ($php*) and any of ($key*)) or
    (all of ($aspx*) and any of ($key*))
}

rule COMMUNITY_WEBSHELL_Godzilla_Webshell {
  meta:
    description = "Detects Godzilla/哥斯拉 webshell"
    author = "Neo23x0"
    date = "2023-01-01"
    severity = "critical"
    family = "Godzilla"
  strings:
    $java1 = "ClassLoader" ascii
    $java2 = "URLClassLoader" ascii
    $java3 = "defineClass" ascii
    $php1 = "call_user_func_array" ascii
    $php2 = "preg_replace" ascii
    $php3 = "create_function" ascii
    $aspx1 = "Assembly.Load" ascii
    $aspx2 = "System.Reflection.Assembly" ascii
    $crypto1 = "AES" ascii
    $crypto2 = "ECB" ascii
    $crypto3 = "PKCS5Padding" ascii
    $cookie1 = "PHPSESSID" ascii
    $key = "3c6e0b8a9c15224a8228b9a98ca1531d" ascii
  condition:
    (all of ($java*) and any of ($crypto*)) or
    (2 of ($php*) and any of ($crypto*)) or
    (all of ($aspx*) and any of ($crypto*)) or
    ($key and any of ($java*, $php*, $aspx*))
}

rule COMMUNITY_WEBSHELL_AntSword_Shell {
  meta:
    description = "Detects AntSword/蚁剑 webshell"
    author = "Neo23x0"
    date = "2023-01-01"
    severity = "critical"
    family = "AntSword"
  strings:
    $php1 = "@ini_set(\"display_errors\"" ascii
    $php2 = "set_time_limit(0)" ascii
    $php3 = "$_POST['ant]" ascii
    $php4 = "eval(" ascii
    $asp1 = "execute(request" ascii
    $asp2 = "Response.Write" ascii
    $asp3 = "Server.CreateObject" ascii
    $j1 = "Runtime.getRuntime().exec" ascii
    $j2 = "ProcessBuilder" ascii
    $key1 = "ant" ascii
    $key2 = "sword" ascii
    $key3 = "chr(" ascii
    $encoder1 = "base64_decode" ascii
    $encoder2 = "rot13" ascii
  condition:
    (2 of ($php*) and any of ($key*)) or
    (2 of ($asp*) and any of ($key*)) or
    (any of ($j*) and any of ($encoder*, $key*))
}

rule COMMUNITY_WEBSHELL_Weevely_Stealth {
  meta:
    description = "Detects Weevely stealth webshell"
    author = "Neo23x0"
    date = "2023-01-01"
    severity = "high"
    family = "Weevely"
  strings:
    $s1 = "preg_replace(\"/.*/e" ascii
    $s2 = "str_replace(" ascii
    $s3 = "create_function(" ascii
    $s4 = "base64_decode(" ascii
    $s5 = "gzinflate(" ascii
    $obf1 = "$_" ascii
    $obf2 = "chr(" ascii
    $cond = "preg_replace" ascii
  condition:
    $s1 and any of ($s2, $s3) and any of ($s4, $s5) and any of ($obf*)
}

rule COMMUNITY_WEBSHELL_FileManager_Generic {
  meta:
    description = "Detects generic file manager webshell"
    author = "Neo23x0"
    date = "2023-01-01"
    severity = "high"
    family = "FileManager"
  strings:
    $fm1 = "file_get_contents" ascii
    $fm2 = "file_put_contents" ascii
    $fm3 = "fopen(" ascii
    $fm4 = "fwrite(" ascii
    $fm5 = "unlink(" ascii
    $fm6 = "rmdir(" ascii
    $fm7 = "mkdir(" ascii
    $fm8 = "copy(" ascii
    $fm9 = "rename(" ascii
    $fm10 = "chmod(" ascii
    $html1 = "<title>File Manager" ascii nocase
    $html2 = "File Manager</title>" ascii nocase
    $html3 = "filemanager" ascii nocase
  condition:
    (5 of ($fm*) and any of ($html*)) or
    (all of ($html*) and 3 of ($fm*))
}

rule COMMUNITY_WEBSHELL_SQLShell_Generic {
  meta:
    description = "Detects SQL shell/SQL admin webshell"
    author = "Neo23x0"
    date = "2023-01-01"
    severity = "high"
    family = "SQLShell"
  strings:
    $sql1 = "mysql_connect" ascii
    $sql2 = "mysqli_connect" ascii
    $sql3 = "pg_connect" ascii
    $sql4 = "mssql_connect" ascii
    $sql5 = "sqlite_open" ascii
    $exec1 = "mysql_query" ascii
    $exec2 = "mysqli_query" ascii
    $exec3 = "pg_query" ascii
    $shell1 = "SHOW DATABASES" ascii nocase
    $shell2 = "SHOW TABLES" ascii nocase
    $shell3 = "SELECT * FROM" ascii nocase
    $shell4 = "UNION SELECT" ascii nocase
    $ui1 = "SQL Shell" ascii nocase
    $ui2 = "Database Manager" ascii nocase
    $ui3 = "phpMyAdmin" ascii nocase
  condition:
    (any of ($sql*) and any of ($exec*) and any of ($shell*)) or
    (any of ($ui*) and 2 of ($sql*, $exec*))
}
