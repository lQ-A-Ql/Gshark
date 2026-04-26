rule OWASP_SQL_INJECTION {
  strings:
    $s1 = "union select" nocase
    $s2 = "information_schema" nocase
    $s3 = "' or '" nocase
    $s4 = "sleep(" nocase
    $s5 = "extractvalue(" nocase
  condition:
    any of them
}

rule OWASP_XSS {
  strings:
    $x1 = "<script" nocase
    $x2 = "onerror=" nocase
    $x3 = "javascript:" nocase
  condition:
    any of them
}

rule OWASP_RCE {
  strings:
    $r1 = "whoami" nocase
    $r2 = "/etc/passwd" nocase
    $r3 = "cmd.exe" nocase
    $r4 = "powershell" nocase
  condition:
    any of them
}

rule OWASP_WEBSHELL {
  strings:
    $w1 = "eval(base64_decode" nocase
    $w2 = "@eval($_post" nocase
    $w3 = "assert($_post" nocase
    $w4 = "shell_exec(" nocase
    $w5 = "passthru(" nocase
    $w6 = "php://input" nocase
  condition:
    any of them
}

rule SENSITIVE_CREDENTIAL {
  strings:
    $c1 = /AKIA[0-9A-Z]{16}/ nocase
    $c2 = /eyJ[A-Za-z0-9_-]+\./ nocase
  condition:
    any of them
}
