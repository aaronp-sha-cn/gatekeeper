"""
GateKeeper - 本地入侵检测与防御引擎 (IDS/IPS)
实现实时流量监控、攻击检测和自动阻断功能
"""

import re
import time
import json
import socket
import struct
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
from enum import Enum

from config.logging_config import get_logger
from core.database import db_manager
from core.models import AttackLog, AttackType, AttackSeverity

logger = get_logger("ids_engine")


class AttackSignature:
    """攻击特征签名"""
    
    def __init__(self, name: str, pattern: str, attack_type: AttackType, 
                 severity: AttackSeverity, description: str):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.attack_type = attack_type
        self.severity = severity
        self.description = description


class IDSEngine:
    """入侵检测引擎"""
    
    # 内置攻击特征库
    SIGNATURES = [
        # SQL注入
        AttackSignature(
            "SQL Injection - Union",
            r"union\s+select|union\s+all\s+select",
            AttackType.SQL_INJECTION,
            AttackSeverity.HIGH,
            "检测到SQL注入攻击 - UNION查询"
        ),
        AttackSignature(
            "SQL Injection - Error Based",
            r"'|\"|\%27|\%22|--|\%2D\%2D|/\*|\*/",
            AttackType.SQL_INJECTION,
            AttackSeverity.MEDIUM,
            "检测到SQL注入攻击 - 错误注入"
        ),
        # XSS攻击
        AttackSignature(
            "XSS - Script Tag",
            r"<script[^>]*>|</script>|javascript:|on\w+\s*=",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测到XSS跨站脚本攻击"
        ),
        # 路径遍历
        AttackSignature(
            "Path Traversal",
            r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.MEDIUM,
            "检测到目录遍历攻击"
        ),
        # 命令注入
        AttackSignature(
            "Command Injection",
            r";\s*\w+|\|\s*\w+|`\w+`|\$\(\w+\)",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测到命令注入攻击"
        ),
        # 暴力破解
        AttackSignature(
            "Brute Force - Login",
            r"/login|/admin|/wp-login|/phpmyadmin",
            AttackType.BRUTE_FORCE,
            AttackSeverity.MEDIUM,
            "检测到可能的暴力破解尝试"
        ),
        # 扫描行为
        AttackSignature(
            "Port Scan - Nmap",
            r"nmap|masscan|zgrab",
            AttackType.PORT_SCAN,
            AttackSeverity.LOW,
            "检测到端口扫描工具特征"
        ),
        # 常见漏洞利用
        AttackSignature(
            "Exploit - CVE Pattern",
            r"eval\(|assert\(|system\(|exec\(|passthru\(|shell_exec\(",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测到代码执行漏洞利用"
        ),
        # 恶意User-Agent
        AttackSignature(
            "Malicious User-Agent",
            r"sqlmap|nikto|burp|metasploit|nessus|acunetix",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.MEDIUM,
            "检测到恶意扫描工具"
        ),
        # ============================================================
        # 扩充规则 - SQL注入
        # ============================================================
        AttackSignature(
            "SQL注入 - UNION SELECT变体",
            r"union\s+(all\s+)?select\s+",
            AttackType.SQL_INJECTION,
            AttackSeverity.CRITICAL,
            "检测UNION SELECT注入变体"
        ),
        AttackSignature(
            "SQL注入 - OR布尔盲注",
            r"'\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            AttackType.SQL_INJECTION,
            AttackSeverity.HIGH,
            "检测OR布尔盲注"
        ),
        AttackSignature(
            "SQL注入 - AND布尔盲注",
            r"'\s*and\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            AttackType.SQL_INJECTION,
            AttackSeverity.HIGH,
            "检测AND布尔盲注"
        ),
        AttackSignature(
            "SQL注入 - 注释符注入",
            r"('--'|'#'|'/\*'|'\*/')",
            AttackType.SQL_INJECTION,
            AttackSeverity.MEDIUM,
            "检测SQL注释符注入"
        ),
        AttackSignature(
            "SQL注入 - information_schema",
            r"information_schema\.\w+",
            AttackType.SQL_INJECTION,
            AttackSeverity.CRITICAL,
            "检测information_schema元数据访问"
        ),
        AttackSignature(
            "SQL注入 - mysql系统库",
            r"mysql\.(user|db|tables_priv|columns_priv)",
            AttackType.SQL_INJECTION,
            AttackSeverity.CRITICAL,
            "检测MySQL系统库访问"
        ),
        AttackSignature(
            "SQL注入 - SLEEP时间盲注",
            r"\bsleep\s*\(\s*\d+\s*\)",
            AttackType.SQL_INJECTION,
            AttackSeverity.HIGH,
            "检测SLEEP时间盲注"
        ),
        AttackSignature(
            "SQL注入 - BENCHMARK时间盲注",
            r"\bbenchmark\s*\(\s*\d+\s*,",
            AttackType.SQL_INJECTION,
            AttackSeverity.HIGH,
            "检测BENCHMARK时间盲注"
        ),
        AttackSignature(
            "SQL注入 - WAITFOR延迟注入",
            r"\bwaitfor\s+(delay|time)\s+",
            AttackType.SQL_INJECTION,
            AttackSeverity.HIGH,
            "检测MSSQL WAITFOR延迟注入"
        ),
        AttackSignature(
            "SQL注入 - PG_SLEEP延迟注入",
            r"\bpg_sleep\s*\(",
            AttackType.SQL_INJECTION,
            AttackSeverity.HIGH,
            "检测PostgreSQL pg_sleep延迟注入"
        ),
        AttackSignature(
            "SQL注入 - LOAD_FILE读取",
            r"\bload_file\s*\(",
            AttackType.SQL_INJECTION,
            AttackSeverity.CRITICAL,
            "检测MySQL LOAD_FILE文件读取"
        ),
        AttackSignature(
            "SQL注入 - INTO OUTFILE写文件",
            r"\binto\s+(out|dump)file\s+",
            AttackType.SQL_INJECTION,
            AttackSeverity.CRITICAL,
            "检测INTO OUTFILE/DUMPFILE写文件"
        ),
        AttackSignature(
            "SQL注入 - EXEC存储过程",
            r"\bexec\s+(master|xp_|sp_)",
            AttackType.SQL_INJECTION,
            AttackSeverity.CRITICAL,
            "检测MSSQL存储过程执行"
        ),
        AttackSignature(
            "SQL注入 - xp_cmdshell",
            r"\bxp_cmdshell\s*\(",
            AttackType.SQL_INJECTION,
            AttackSeverity.CRITICAL,
            "检测xp_cmdshell系统命令执行"
        ),
        AttackSignature(
            "SQL注入 - ORDER BY探测",
            r"\border\s+by\s+\d+\s*--",
            AttackType.SQL_INJECTION,
            AttackSeverity.MEDIUM,
            "检测ORDER BY列数探测"
        ),
        AttackSignature(
            "SQL注入 - GROUP BY注入",
            r"\bgroup\s+by\s+\d+\s*--",
            AttackType.SQL_INJECTION,
            AttackSeverity.MEDIUM,
            "检测GROUP BY注入探测"
        ),
        AttackSignature(
            "SQL注入 - HAVING子句注入",
            r"\bhaving\s+\d+\s*=\s*\d+",
            AttackType.SQL_INJECTION,
            AttackSeverity.MEDIUM,
            "检测HAVING子句注入"
        ),
        AttackSignature(
            "SQL注入 - 堆叠查询",
            r";\s*(select|insert|update|delete|drop|alter|create)\s+",
            AttackType.SQL_INJECTION,
            AttackSeverity.CRITICAL,
            "检测SQL堆叠查询"
        ),
        AttackSignature(
            "SQL注入 - HEX编码注入",
            r"0x[0-9a-f]{6,}",
            AttackType.SQL_INJECTION,
            AttackSeverity.MEDIUM,
            "检测HEX编码SQL注入"
        ),
        AttackSignature(
            "SQL注入 - CHAR函数编码",
            r"\bchar\s*\(\s*\d+\s*(,\s*\d+\s*)+\)",
            AttackType.SQL_INJECTION,
            AttackSeverity.MEDIUM,
            "检测CHAR函数编码注入"
        ),
        # ============================================================
        # 扩充规则 - XSS跨站脚本
        # ============================================================
        AttackSignature(
            "XSS - script标签注入",
            r"<\s*script\b",
            AttackType.XSS,
            AttackSeverity.CRITICAL,
            "检测script标签注入"
        ),
        AttackSignature(
            "XSS - javascript协议",
            r"javascript\s*:",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测javascript:协议执行"
        ),
        AttackSignature(
            "XSS - vbscript协议",
            r"vbscript\s*:",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测vbscript:协议执行"
        ),
        AttackSignature(
            "XSS - onerror事件",
            r"onerror\s*=\s*['\"]?",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测onerror事件处理器"
        ),
        AttackSignature(
            "XSS - onload事件",
            r"onload\s*=\s*['\"]?",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测onload事件处理器"
        ),
        AttackSignature(
            "XSS - onmouseover事件",
            r"onmouseover\s*=\s*['\"]?",
            AttackType.XSS,
            AttackSeverity.MEDIUM,
            "检测onmouseover事件处理器"
        ),
        AttackSignature(
            "XSS - onclick事件",
            r"onclick\s*=\s*['\"]?",
            AttackType.XSS,
            AttackSeverity.MEDIUM,
            "检测onclick事件处理器"
        ),
        AttackSignature(
            "XSS - onfocus事件",
            r"onfocus\s*=\s*['\"]?",
            AttackType.XSS,
            AttackSeverity.MEDIUM,
            "检测onfocus事件处理器"
        ),
        AttackSignature(
            "XSS - onblur事件",
            r"onblur\s*=\s*['\"]?",
            AttackType.XSS,
            AttackSeverity.MEDIUM,
            "检测onblur事件处理器"
        ),
        AttackSignature(
            "XSS - onchange事件",
            r"onchange\s*=\s*['\"]?",
            AttackType.XSS,
            AttackSeverity.MEDIUM,
            "检测onchange事件处理器"
        ),
        AttackSignature(
            "XSS - iframe标签注入",
            r"<\s*iframe\b",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测iframe标签注入"
        ),
        AttackSignature(
            "XSS - object标签注入",
            r"<\s*object\b",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测object标签注入"
        ),
        AttackSignature(
            "XSS - embed标签注入",
            r"<\s*embed\b",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测embed标签注入"
        ),
        AttackSignature(
            "XSS - svg事件注入",
            r"<\s*svg\b[^>]*on\w+\s*=",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测SVG标签事件注入"
        ),
        AttackSignature(
            "XSS - img onerror注入",
            r"<\s*img\b[^>]*onerror\s*=",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测img标签onerror注入"
        ),
        AttackSignature(
            "XSS - body事件注入",
            r"<\s*body\b[^>]*on\w+\s*=",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测body标签事件注入"
        ),
        AttackSignature(
            "XSS - input事件注入",
            r"<\s*input\b[^>]*on\w+\s*=",
            AttackType.XSS,
            AttackSeverity.MEDIUM,
            "检测input标签事件注入"
        ),
        AttackSignature(
            "XSS - eval函数调用",
            r"\beval\s*\(",
            AttackType.XSS,
            AttackSeverity.HIGH,
            "检测eval函数调用"
        ),
        AttackSignature(
            "XSS - document.cookie",
            r"document\.cookie",
            AttackType.XSS,
            AttackSeverity.MEDIUM,
            "检测cookie窃取尝试"
        ),
        AttackSignature(
            "XSS - 弹窗函数调用",
            r"\b(alert|prompt|confirm)\s*\(",
            AttackType.XSS,
            AttackSeverity.MEDIUM,
            "检测弹窗函数调用"
        ),
        # ============================================================
        # 扩充规则 - RCE/命令注入
        # ============================================================
        AttackSignature(
            "命令注入 - 分号命令",
            r";\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)\b",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测分号命令注入"
        ),
        AttackSignature(
            "命令注入 - 管道符命令",
            r"\|\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)\b",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测管道符命令注入"
        ),
        AttackSignature(
            "命令注入 - 反引号执行",
            r"`[^`]*`",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测反引号命令执行"
        ),
        AttackSignature(
            "命令注入 - $()命令替换",
            r"\$\([^)]*\)",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测$()命令替换"
        ),
        AttackSignature(
            "命令注入 - system()函数",
            r"\bsystem\s*\(",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测system函数调用"
        ),
        AttackSignature(
            "命令注入 - exec()函数",
            r"\bexec\s*\(",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测exec函数调用"
        ),
        AttackSignature(
            "命令注入 - passthru()函数",
            r"\bpassthru\s*\(",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测passthru函数调用"
        ),
        AttackSignature(
            "命令注入 - shell_exec()函数",
            r"\bshell_exec\s*\(",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测shell_exec函数调用"
        ),
        AttackSignature(
            "命令注入 - popen()函数",
            r"\bpopen\s*\(",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.HIGH,
            "检测popen函数调用"
        ),
        AttackSignature(
            "命令注入 - proc_open()函数",
            r"\bproc_open\s*\(",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.HIGH,
            "检测proc_open函数调用"
        ),
        AttackSignature(
            "命令注入 - pcntl_exec()函数",
            r"\bpcntl_exec\s*\(",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测pcntl_exec函数调用"
        ),
        AttackSignature(
            "命令注入 - os.system()调用",
            r"os\.\s*system\s*\(",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测os.system调用"
        ),
        AttackSignature(
            "命令注入 - os.popen()调用",
            r"os\.\s*popen\s*\(",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.HIGH,
            "检测os.popen调用"
        ),
        AttackSignature(
            "命令注入 - subprocess调用",
            r"subprocess\.\s*(call|run|Popen)\s*\(",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.HIGH,
            "检测subprocess模块调用"
        ),
        AttackSignature(
            "命令注入 - &&链式命令",
            r"&&\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测&&链式命令注入"
        ),
        AttackSignature(
            "命令注入 - ||链式命令",
            r"\|\|\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测||链式命令注入"
        ),
        AttackSignature(
            "命令注入 - base64解码执行",
            r"\bbase64\s+-d\s+\|",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.HIGH,
            "检测base64解码后执行"
        ),
        AttackSignature(
            "命令注入 - wget下载执行",
            r"\bwget\s+.*(-O|-o)\s*/",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.HIGH,
            "检测wget下载恶意文件"
        ),
        AttackSignature(
            "命令注入 - curl下载执行",
            r"\bcurl\s+.*(-o|-O)\s*/",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.HIGH,
            "检测curl下载恶意文件"
        ),
        AttackSignature(
            "命令注入 - nc反弹Shell",
            r"\bnc\s+(-e|-c)\s+/bin/(ba)?sh",
            AttackType.COMMAND_INJECTION,
            AttackSeverity.CRITICAL,
            "检测nc反弹Shell"
        ),
        # ============================================================
        # 扩充规则 - 路径遍历
        # ============================================================
        AttackSignature(
            "路径遍历 - ../",
            r"\.\./",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测../路径遍历"
        ),
        AttackSignature(
            "路径遍历 - ..\\\\",
            r"\.\.\\\\",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测..\\路径遍历"
        ),
        AttackSignature(
            "路径遍历 - URL编码../",
            r"%2e%2e%2f|%2e%2e/",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测URL编码的路径遍历"
        ),
        AttackSignature(
            "路径遍历 - 双重URL编码",
            r"%252e%252e%252f",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测双重URL编码路径遍历"
        ),
        AttackSignature(
            "路径遍历 - /etc/passwd",
            r"/etc/passwd",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.CRITICAL,
            "检测/etc/passwd文件访问"
        ),
        AttackSignature(
            "路径遍历 - /etc/shadow",
            r"/etc/shadow",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.CRITICAL,
            "检测/etc/shadow文件访问"
        ),
        AttackSignature(
            "路径遍历 - /proc/self",
            r"/proc/self/",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测/proc/self目录访问"
        ),
        AttackSignature(
            "路径遍历 - /proc/version",
            r"/proc/version",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.MEDIUM,
            "检测/proc/version信息泄露"
        ),
        AttackSignature(
            "路径遍历 - /proc/cmdline",
            r"/proc/cmdline",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测/proc/cmdline信息泄露"
        ),
        AttackSignature(
            "路径遍历 - Windows系统目录",
            r"[Ww]indows/[Ss]ystem32",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测Windows系统目录访问"
        ),
        AttackSignature(
            "路径遍历 - win.ini",
            r"[Ww]in\.ini",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.MEDIUM,
            "检测win.ini配置文件访问"
        ),
        AttackSignature(
            "路径遍历 - /var/log",
            r"/var/log/\w+",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测日志目录遍历访问"
        ),
        AttackSignature(
            "路径遍历 - /var/www",
            r"/var/www/\w+",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测Web目录遍历访问"
        ),
        AttackSignature(
            "路径遍历 - .ssh密钥",
            r"\.ssh/(id_rsa|authorized_keys|config)",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.CRITICAL,
            "检测SSH密钥文件访问"
        ),
        AttackSignature(
            "路径遍历 - .htaccess",
            r"\.htaccess",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.MEDIUM,
            "检测Apache配置文件访问"
        ),
        AttackSignature(
            "路径遍历 - .env文件",
            r"\.env\b",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测.env环境配置文件访问"
        ),
        AttackSignature(
            "路径遍历 - .git目录",
            r"\.git/(config|HEAD|objects|refs)",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测.git目录遍历"
        ),
        AttackSignature(
            "路径遍历 - .svn目录",
            r"\.svn/(entries|wc\.db)",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.MEDIUM,
            "检测.svn目录遍历"
        ),
        AttackSignature(
            "路径遍历 - web.config",
            r"[Ww]eb\.config",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测IIS配置文件访问"
        ),
        AttackSignature(
            "路径遍历 - null字节注入",
            r"%00(\.\./|/etc/|/proc/)",
            AttackType.PATH_TRAVERSAL,
            AttackSeverity.HIGH,
            "检测null字节截断路径遍历"
        ),
        # ============================================================
        # 扩充规则 - LFI本地文件包含
        # ============================================================
        AttackSignature(
            "LFI - PHP动态文件包含",
            r"(include|require)(_once)?\s*\(\s*['\"]?\$",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测PHP动态文件包含"
        ),
        AttackSignature(
            "LFI - php://filter",
            r"php://filter",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测php://filter协议利用"
        ),
        AttackSignature(
            "LFI - php://input",
            r"php://input",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测php://input协议利用"
        ),
        AttackSignature(
            "LFI - data://协议",
            r"data://(text/plain|application)",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测data://协议利用"
        ),
        AttackSignature(
            "LFI - expect://协议",
            r"expect://",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测expect://命令执行"
        ),
        AttackSignature(
            "LFI - zip://协议",
            r"zip://",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测zip://协议文件包含"
        ),
        AttackSignature(
            "LFI - phar://协议",
            r"phar://",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测phar://协议反序列化利用"
        ),
        AttackSignature(
            "LFI - glob://协议",
            r"glob://",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测glob://目录列举"
        ),
        AttackSignature(
            "LFI - /proc/self/environ",
            r"/proc/self/environ",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测proc环境变量文件包含"
        ),
        AttackSignature(
            "LFI - /var/log/auth.log",
            r"/var/log/(auth|syslog)\.log",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测日志文件包含利用"
        ),
        AttackSignature(
            "LFI - /proc/self/fd",
            r"/proc/self/fd/\d+",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测文件描述符包含利用"
        ),
        AttackSignature(
            "LFI - session文件包含",
            r"/tmp/sess_\w+",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测PHP session文件包含"
        ),
        AttackSignature(
            "LFI - 深度路径截断",
            r"(\.\./){5,}",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测深度路径截断绕过"
        ),
        AttackSignature(
            "LFI - PHP wrappers组合",
            r"(php://|data://|expect://|zip://|phar://).*(include|require)",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测PHP wrappers组合利用"
        ),
        AttackSignature(
            "LFI - 日志污染包含",
            r"(access|error|apache2)\.log.*(/etc/|/proc/)",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测日志污染文件包含"
        ),
        # ============================================================
        # 扩充规则 - RFI远程文件包含
        # ============================================================
        AttackSignature(
            "RFI - HTTP协议包含",
            r"(include|require)(_once)?\s*\(\s*['\"]?https?://",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测远程HTTP文件包含"
        ),
        AttackSignature(
            "RFI - FTP协议包含",
            r"(include|require)(_once)?\s*\(\s*['\"]?ftp://",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测远程FTP文件包含"
        ),
        AttackSignature(
            "RFI - allow_url_include",
            r"allow_url_include\s*=\s*1",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测allow_url_include配置探测"
        ),
        AttackSignature(
            "RFI - 远程脚本下载执行",
            r"(wget|curl)\s+https?://.*\|\s*(bash|sh|python)",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测远程脚本下载执行"
        ),
        AttackSignature(
            "RFI - 远程PHP文件包含",
            r"(include|require)(_once)?\s*\(\s*['\"]?\s*\$\w+\s*\.\s*['\"]?https?://",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测变量拼接远程包含"
        ),
        AttackSignature(
            "RFI - base64远程包含",
            r"(include|require)(_once)?\s*\(\s*base64_decode\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测base64解码远程包含"
        ),
        AttackSignature(
            "RFI - 远程图片马包含",
            r"(include|require)(_once)?\s*\(\s*['\"].*\.(jpg|png|gif|bmp)['\"]",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测图片马文件包含"
        ),
        AttackSignature(
            "RFI - 动态变量包含",
            r"(include|require)(_once)?\s*\(\s*\$\{?(GET|POST|REQUEST|COOKIE)",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测用户输入动态包含"
        ),
        AttackSignature(
            "RFI - SMB协议包含",
            r"(include|require)(_once)?\s*\(\s*['\"]?smb://",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测SMB协议远程包含"
        ),
        AttackSignature(
            "RFI - UNC路径包含",
            r'(include|require)(_once)?\s*\(\s*["\x27]\\\\',
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测UNC路径远程包含"
        ),
        # ============================================================
        # 扩充规则 - SSRF服务端请求伪造
        # ============================================================
        AttackSignature(
            "SSRF - 内网IP请求",
            r"(https?://)?(127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测内网IP地址请求"
        ),
        AttackSignature(
            "SSRF - localhost请求",
            r"https?://localhost\b",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测localhost请求"
        ),
        AttackSignature(
            "SSRF - 0.0.0.0请求",
            r"https?://0\.0\.0\.0\b",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测0.0.0.0请求"
        ),
        AttackSignature(
            "SSRF - file://协议",
            r"file:///",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测file://协议读取"
        ),
        AttackSignature(
            "SSRF - gopher://协议",
            r"gopher://",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测gopher协议利用"
        ),
        AttackSignature(
            "SSRF - dict://协议",
            r"dict://",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测dict协议利用"
        ),
        AttackSignature(
            "SSRF - ftp内网请求",
            r"ftp://(127|10|172|192)\.",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测FTP内网请求"
        ),
        AttackSignature(
            "SSRF - IP进制转换",
            r"https?://0x[0-9a-f]+",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测IP进制转换绕过"
        ),
        AttackSignature(
            "SSRF - DNS重绑定",
            r"(a]b|nip\.io|sslip\.io)",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测DNS重绑定服务"
        ),
        AttackSignature(
            "SSRF - URL解析差异",
            r"https?://@[^/]+@",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测URL解析差异绕过"
        ),
        AttackSignature(
            "SSRF - 云元数据请求",
            r"169\.254\.169\.254",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测云服务元数据请求"
        ),
        AttackSignature(
            "SSRF - AWS元数据",
            r"169\.254\.169\.254/latest/meta-data/",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测AWS元数据接口访问"
        ),
        AttackSignature(
            "SSRF - X-Forwarded-Host注入",
            r"X-Forwarded-Host\s*:\s*(127|10|172|192)\.",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测X-Forwarded-Host头注入"
        ),
        AttackSignature(
            "SSRF - SSRF参数探测",
            r"(url|uri|path|dest|redirect|target|rurl|src|source)\s*=\s*https?://",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测常见SSRF参数名"
        ),
        AttackSignature(
            "SSRF - 云元数据v2",
            r"169\.254\.169\.254/latest/api/",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测云元数据API v2访问"
        ),
        # ============================================================
        # 扩充规则 - XXE XML外部实体注入
        # ============================================================
        AttackSignature(
            "XXE - DOCTYPE声明",
            r"<!DOCTYPE\b",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测XML DOCTYPE声明"
        ),
        AttackSignature(
            "XXE - 外部实体声明",
            r"<!ENTITY\b[^>]+SYSTEM\b",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测外部实体声明"
        ),
        AttackSignature(
            "XXE - 外部DTD引用",
            r"<!DOCTYPE\b[^>]+\s+SYSTEM\s+['\"]",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测外部DTD引用"
        ),
        AttackSignature(
            "XXE - PUBLIC实体",
            r"<!ENTITY\b[^>]+PUBLIC\b",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测PUBLIC外部实体"
        ),
        AttackSignature(
            "XXE - 参数实体",
            r"<!ENTITY\s+%\s+\w+",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测参数实体声明"
        ),
        AttackSignature(
            "XXE - XInclude包含",
            r"<xi:include\b",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测XInclude外部包含"
        ),
        AttackSignature(
            "XXE - DTD内部子集",
            r"<!DOCTYPE\s+\w+\s*\[",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测DTD内部子集定义"
        ),
        AttackSignature(
            "XXE - file协议XXE",
            r"SYSTEM\s+['\"]file://",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测file协议XXE读取"
        ),
        AttackSignature(
            "XXE - expect协议XXE",
            r"SYSTEM\s+['\"]expect://",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测expect协议XXE命令执行"
        ),
        AttackSignature(
            "XXE - http协议XXE",
            r"SYSTEM\s+['\"]https?://",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测HTTP外带数据XXE"
        ),
        AttackSignature(
            "XXE - gopher协议XXE",
            r"SYSTEM\s+['\"]gopher://",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测gopher协议XXE"
        ),
        AttackSignature(
            "XXE - ftp协议XXE",
            r"SYSTEM\s+['\"]ftp://",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测FTP协议XXE"
        ),
        AttackSignature(
            "XXE - netdoc协议XXE",
            r"SYSTEM\s+['\"](netdoc|jar|zip)://",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Java特定协议XXE"
        ),
        AttackSignature(
            "XXE - Blind XXE OOB",
            r"<!ENTITY\s+\w+\s+SYSTEM\s+['\"][^'\"]*%[^'\"]*['\"]",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测Blind XXE OOB外带"
        ),
        AttackSignature(
            "XXE - CDATA XXE",
            r"<!\[CDATA\[.*<!ENTITY",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测CDATA段中的XXE实体"
        ),
        # ============================================================
        # 扩充规则 - SSTI服务端模板注入
        # ============================================================
        AttackSignature(
            "SSTI - Jinja2模板注入",
            r"\{\{.*\}\}",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Jinja2模板表达式"
        ),
        AttackSignature(
            "SSTI - Mako模板注入",
            r"\$\{.*\}",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Mako模板表达式"
        ),
        AttackSignature(
            "SSTI - __class__链",
            r"\.\_\_class\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测Python类继承链利用"
        ),
        AttackSignature(
            "SSTI - __mro__链",
            r"\.\_\_mro\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测Python MRO链利用"
        ),
        AttackSignature(
            "SSTI - __subclasses__",
            r"\.\_\_subclasses\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测Python子类遍历"
        ),
        AttackSignature(
            "SSTI - __init__调用",
            r"\.\_\_init\_\_\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测__init__全局变量访问"
        ),
        AttackSignature(
            "SSTI - __globals__访问",
            r"\.\_\_globals\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测全局变量访问"
        ),
        AttackSignature(
            "SSTI - __builtins__访问",
            r"\.\_\_builtins\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测内建函数访问"
        ),
        AttackSignature(
            "SSTI - config对象访问",
            r"\.\s*config\b",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Flask config对象访问"
        ),
        AttackSignature(
            "SSTI - self对象访问",
            r"\.\s*self\b.*\.\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测self对象属性遍历"
        ),
        AttackSignature(
            "SSTI - request对象访问",
            r"\.\s*request\b\.(args|form|values|cookies)",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测request对象参数访问"
        ),
        AttackSignature(
            "SSTI - lipsum利用",
            r"\blipsum\b.*\.\_\_globals\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测lipsum对象利用"
        ),
        AttackSignature(
            "SSTI - cycler利用",
            r"\bcycler\b.*\.\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测cycler对象利用"
        ),
        AttackSignature(
            "SSTI - Tornado模板注入",
            r"\{\%\s*raw\s*\%\}|\{\%\s*autoescape\s*\%\}",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Tornado模板指令注入"
        ),
        AttackSignature(
            "SSTI - namespace利用",
            r"\bnamespace\b.*\.\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测namespace对象利用"
        ),
        # ============================================================
        # 扩充规则 - LDAP注入
        # ============================================================
        AttackSignature(
            "LDAP注入 - OR条件",
            r"\)\s*\(\s*\|\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测LDAP OR条件注入"
        ),
        AttackSignature(
            "LDAP注入 - 通配符枚举",
            r"\*\)\s*\(\s*\|\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测LDAP通配符枚举"
        ),
        AttackSignature(
            "LDAP注入 - 空密码绕过",
            r"\)\s*\(\s*uid\s*=\s*\*\s*\)",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测LDAP空密码绕过"
        ),
        AttackSignature(
            "LDAP注入 - 属性枚举",
            r"\*\)\s*\(\s*\w+\s*=\s*\*\s*\)",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测LDAP属性枚举"
        ),
        AttackSignature(
            "LDAP注入 - 分号注入",
            r";\s*\w+\s*=\s*",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测LDAP分号注入"
        ),
        AttackSignature(
            "LDAP注入 - 括号闭合",
            r"\)\s*\(\s*\w+\s*=\s*[^)]*\)\s*\(\s*\w+\s*=\s*",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测LDAP括号闭合注入"
        ),
        AttackSignature(
            "LDAP注入 - DN逃逸",
            r"dn\s*=\s*[^,]*,\s*cn\s*=\s*",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测LDAP DN逃逸"
        ),
        AttackSignature(
            "LDAP注入 - &运算符",
            r"&\s*\(\s*\w+\s*=\s*",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测LDAP AND运算符注入"
        ),
        AttackSignature(
            "LDAP注入 - !运算符",
            r"!\s*\(\s*\w+\s*=\s*",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测LDAP NOT运算符注入"
        ),
        AttackSignature(
            "LDAP注入 - 注释绕过",
            r"\|\s*\(\s*\w+\s*=\s*\*\s*\)",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测LDAP注释绕过"
        ),
        # ============================================================
        # 扩充规则 - XPath注入
        # ============================================================
        AttackSignature(
            "XPath注入 - OR条件",
            r"'\s+or\s+'",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测XPath OR条件注入"
        ),
        AttackSignature(
            "XPath注入 - AND条件",
            r"'\s+and\s+'",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测XPath AND条件注入"
        ),
        AttackSignature(
            "XPath注入 - 父轴遍历",
            r"/parent::",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测XPath父轴遍历"
        ),
        AttackSignature(
            "XPath注入 - 子轴遍历",
            r"/child::",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测XPath子轴遍历"
        ),
        AttackSignature(
            "XPath注入 - 文档根访问",
            r"/\.\./",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测XPath文档根节点遍历"
        ),
        AttackSignature(
            "XPath注入 - string()函数",
            r"string\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测XPath string函数利用"
        ),
        AttackSignature(
            "XPath注入 - concat()函数",
            r"concat\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测XPath concat函数利用"
        ),
        AttackSignature(
            "XPath注入 - count()函数",
            r"count\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.LOW,
            "检测XPath count函数探测"
        ),
        AttackSignature(
            "XPath注入 - 轴步骤遍历",
            r"::\w+node\(\)",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测XPath轴步骤遍历"
        ),
        AttackSignature(
            "XPath注入 - 谓词闭合注入",
            r"'\]\s*\|\s*\[",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测XPath谓词闭合注入"
        ),
        # ============================================================
        # 扩充规则 - 反序列化攻击
        # ============================================================
        AttackSignature(
            "反序列化 - Java序列化数据",
            r"rO0AB|aced0005",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测Java序列化数据"
        ),
        AttackSignature(
            "反序列化 - Python pickle",
            r"\.pickle\.\s*(load|loads)\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测Python pickle反序列化"
        ),
        AttackSignature(
            "反序列化 - PHP unserialize",
            r"\bunserialize\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测PHP反序列化函数"
        ),
        AttackSignature(
            "反序列化 - PHP对象注入",
            r"O:\d+:\"[^\"]+\":\d+:\{",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测PHP对象注入"
        ),
        AttackSignature(
            "反序列化 - YAML不安全加载",
            r"\.yaml\.\s*(load|unsafe_load)\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测YAML不安全加载"
        ),
        AttackSignature(
            "反序列化 - __reduce__利用",
            r"\_\_reduce\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Python __reduce__魔术方法"
        ),
        AttackSignature(
            "反序列化 - __reduce_ex__利用",
            r"\_\_reduce_ex\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Python __reduce_ex__魔术方法"
        ),
        AttackSignature(
            "反序列化 - __setstate__利用",
            r"\_\_setstate\_\_",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Python __setstate__魔术方法"
        ),
        AttackSignature(
            "反序列化 - Apache Commons",
            r"org\.apache\.commons\.(collections|beanutils)",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测Apache Commons反序列化链"
        ),
        AttackSignature(
            "反序列化 - Fastjson利用",
            r'@type\s*:\s*"com\.',
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测Fastjson @type反序列化利用"
        ),
        AttackSignature(
            "反序列化 - Jackson利用",
            r'\[\s*"com\.\w+\.\w+",',
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Jackson多态反序列化"
        ),
        AttackSignature(
            "反序列化 - Node.js原型污染",
            r'(__proto__|constructor\.prototype)\s*\[',
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Node.js原型链污染"
        ),
        AttackSignature(
            "反序列化 - Ruby Marshal",
            r"\bMarshal\.\s*load\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Ruby Marshal反序列化"
        ),
        AttackSignature(
            "反序列化 - PHP魔术方法链",
            r"(__wakeup|__destruct|__toString|__call)\s*\(",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测PHP反序列化魔术方法链"
        ),
        AttackSignature(
            "反序列化 - .NET BinaryFormatter",
            r"Type\s*:\s*System\.",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测.NET反序列化类型信息"
        ),
        # ============================================================
        # 扩充规则 - 认证绕过
        # ============================================================
        AttackSignature(
            "认证绕过 - SQL注入登录",
            r"'\s*(or|OR)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+.*--",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测SQL注入认证绕过"
        ),
        AttackSignature(
            "认证绕过 - 空密码登录",
            r"(password|passwd|pwd)\s*=\s*['\"]?\s*['\"]",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测空密码绕过"
        ),
        AttackSignature(
            "认证绕过 - 万能密码",
            r"(admin|root|test)\s*--",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测万能密码登录"
        ),
        AttackSignature(
            "认证绕过 - Basic Auth注入",
            r"Authorization\s*:\s*Basic\s+[A-Za-z0-9+/=]*admin",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Basic Auth管理员注入"
        ),
        AttackSignature(
            "认证绕过 - JWT none算法",
            r'"alg"\s*:\s*"none"',
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测JWT none算法签名绕过"
        ),
        AttackSignature(
            "认证绕过 - JWT空签名",
            r"\.eyJ[A-Za-z0-9_-]+\.",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测JWT空签名绕过"
        ),
        AttackSignature(
            "认证绕过 - JWT算法混淆",
            r'"alg"\s*:\s*"HS256".*"kty"\s*:\s*"RSA"',
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测JWT RS256->HS256算法混淆"
        ),
        AttackSignature(
            "认证绕过 - Cookie注入",
            r"(session|token|auth)\s*=\s*admin",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Cookie会话注入"
        ),
        AttackSignature(
            "认证绕过 - X-Forwarded-For伪造",
            r"X-Forwarded-For\s*:\s*(127\.0\.0\.1|localhost)",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测X-Forwarded-For内网IP伪造"
        ),
        AttackSignature(
            "认证绕过 - X-Real-IP伪造",
            r"X-Real-IP\s*:\s*(127\.0\.0\.1|localhost)",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测X-Real-IP伪造"
        ),
        AttackSignature(
            "认证绕过 - Referer头绕过",
            r"Referer\s*:\s*https?://[^/]*admin",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测Referer头管理员绕过"
        ),
        AttackSignature(
            "认证绕过 - HTTP方法覆盖",
            r"X-HTTP-Method-Override\s*:\s*(PUT|DELETE|PATCH)",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测HTTP方法覆盖"
        ),
        AttackSignature(
            "认证绕过 - 多重URL编码绕过",
            r"%25[0-9a-fA-F]{2}%25[0-9a-fA-F]{2}",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测多重URL编码绕过"
        ),
        AttackSignature(
            "认证绕过 - H2默认账户",
            r"sa\s*--\s*(H2|POSTGRESQL|MYSQL)",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测数据库默认账户绕过"
        ),
        AttackSignature(
            "认证绕过 - 目录穿越认证",
            r"/admin/\.*/\.\./",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测目录穿越认证绕过"
        ),
        # ============================================================
        # 扩充规则 - 暴力破解
        # ============================================================
        AttackSignature(
            "暴力破解 - 登录页面探测",
            r"/(login|signin|auth|authenticate)\b",
            AttackType.BRUTE_FORCE,
            AttackSeverity.LOW,
            "检测登录页面访问"
        ),
        AttackSignature(
            "暴力破解 - 管理后台探测",
            r"/(admin|administrator|backend|manage|manager)\b",
            AttackType.BRUTE_FORCE,
            AttackSeverity.MEDIUM,
            "检测管理后台探测"
        ),
        AttackSignature(
            "暴力破解 - wp-login探测",
            r"/wp-login\.php",
            AttackType.BRUTE_FORCE,
            AttackSeverity.MEDIUM,
            "检测WordPress登录页面探测"
        ),
        AttackSignature(
            "暴力破解 - phpMyAdmin探测",
            r"/phpmyadmin|/pma\b",
            AttackType.BRUTE_FORCE,
            AttackSeverity.MEDIUM,
            "检测phpMyAdmin探测"
        ),
        AttackSignature(
            "暴力破解 - 常见用户名",
            r"(user|username|login)\s*=\s*(admin|root|test|guest)",
            AttackType.BRUTE_FORCE,
            AttackSeverity.MEDIUM,
            "检测常见用户名登录尝试"
        ),
        AttackSignature(
            "暴力破解 - 常见密码",
            r"(pass|password|pwd)\s*=\s*(123456|password|admin|root|test)",
            AttackType.BRUTE_FORCE,
            AttackSeverity.MEDIUM,
            "检测常见弱密码尝试"
        ),
        AttackSignature(
            "暴力破解 - SSH爆破特征",
            r"Failed password for (root|admin|user)",
            AttackType.BRUTE_FORCE,
            AttackSeverity.HIGH,
            "检测SSH登录失败"
        ),
        AttackSignature(
            "暴力破解 - RDP爆破特征",
            r"Login Failed.*RDP|Terminal Server",
            AttackType.BRUTE_FORCE,
            AttackSeverity.HIGH,
            "检测RDP登录失败"
        ),
        AttackSignature(
            "暴力破解 - FTP爆破特征",
            r"530.*Login incorrect|FTP LOGIN FAILED",
            AttackType.BRUTE_FORCE,
            AttackSeverity.HIGH,
            "检测FTP登录失败"
        ),
        AttackSignature(
            "暴力破解 - SMTP爆破特征",
            r"535.*authentication failed|AUTH FAILED",
            AttackType.BRUTE_FORCE,
            AttackSeverity.HIGH,
            "检测SMTP认证失败"
        ),
        AttackSignature(
            "暴力破解 - 验证码绕过",
            r"(captcha|verify)\s*=\s*['\"]?\s*['\"]",
            AttackType.BRUTE_FORCE,
            AttackSeverity.MEDIUM,
            "检测验证码参数为空绕过"
        ),
        AttackSignature(
            "暴力破解 - 多次登录失败",
            r"(login|auth).*failed.*attempt",
            AttackType.BRUTE_FORCE,
            AttackSeverity.MEDIUM,
            "检测多次登录失败特征"
        ),
        AttackSignature(
            "暴力破解 - 密码喷洒攻击",
            r"password_reset.*multiple.*accounts",
            AttackType.BRUTE_FORCE,
            AttackSeverity.MEDIUM,
            "检测密码喷洒攻击"
        ),
        AttackSignature(
            "暴力破解 - 凭证填充",
            r"Authorization\s*:\s*Basic\s+[A-Za-z0-9+/=]{20,}",
            AttackType.BRUTE_FORCE,
            AttackSeverity.MEDIUM,
            "检测Basic Auth凭证填充"
        ),
        AttackSignature(
            "暴力破解 - API密钥枚举",
            r"(api[_-]?key|token)\s*=\s*[A-Za-z0-9]{32,}",
            AttackType.BRUTE_FORCE,
            AttackSeverity.LOW,
            "检测API密钥暴力枚举"
        ),
        # ============================================================
        # 扩充规则 - 扫描检测
        # ============================================================
        AttackSignature(
            "扫描检测 - Nmap特征",
            r"\bnmap\b",
            AttackType.PORT_SCAN,
            AttackSeverity.MEDIUM,
            "检测Nmap扫描工具"
        ),
        AttackSignature(
            "扫描检测 - Masscan特征",
            r"\bmasscan\b",
            AttackType.PORT_SCAN,
            AttackSeverity.MEDIUM,
            "检测Masscan扫描工具"
        ),
        AttackSignature(
            "扫描检测 - Zgrab特征",
            r"\bzgrab\b",
            AttackType.PORT_SCAN,
            AttackSeverity.MEDIUM,
            "检测Zgrab扫描工具"
        ),
        AttackSignature(
            "扫描检测 - Nikto特征",
            r"\bnikto\b",
            AttackType.PORT_SCAN,
            AttackSeverity.MEDIUM,
            "检测Nikto Web扫描"
        ),
        AttackSignature(
            "扫描检测 - DirBuster特征",
            r"\bdirbuster\b",
            AttackType.PORT_SCAN,
            AttackSeverity.LOW,
            "检测DirBuster目录扫描"
        ),
        AttackSignature(
            "扫描检测 - Gobuster特征",
            r"\bgobuster\b",
            AttackType.PORT_SCAN,
            AttackSeverity.LOW,
            "检测Gobuster目录扫描"
        ),
        AttackSignature(
            "扫描检测 - SQLMap特征",
            r"\bsqlmap\b",
            AttackType.PORT_SCAN,
            AttackSeverity.HIGH,
            "检测SQLMap注入工具"
        ),
        AttackSignature(
            "扫描检测 - Burp Suite特征",
            r"\bburp\s*suite\b",
            AttackType.PORT_SCAN,
            AttackSeverity.LOW,
            "检测Burp Suite代理"
        ),
        AttackSignature(
            "扫描检测 - Acunetix特征",
            r"\bacunetix\b",
            AttackType.PORT_SCAN,
            AttackSeverity.LOW,
            "检测Acunetix扫描器"
        ),
        AttackSignature(
            "扫描检测 - Nessus特征",
            r"\bnessus\b",
            AttackType.PORT_SCAN,
            AttackSeverity.LOW,
            "检测Nessus漏洞扫描"
        ),
        AttackSignature(
            "扫描检测 - OpenVAS特征",
            r"\bopenvas\b",
            AttackType.PORT_SCAN,
            AttackSeverity.LOW,
            "检测OpenVAS扫描器"
        ),
        AttackSignature(
            "扫描检测 - WPScan特征",
            r"\bwpscan\b",
            AttackType.PORT_SCAN,
            AttackSeverity.MEDIUM,
            "检测WPScan WordPress扫描"
        ),
        AttackSignature(
            "扫描检测 - Shodan User-Agent",
            r"Shodan\.io|\bshodan\b",
            AttackType.PORT_SCAN,
            AttackSeverity.MEDIUM,
            "检测Shodan扫描器"
        ),
        AttackSignature(
            "扫描检测 - Censys扫描",
            r"\bcensys\b|CensysInspect",
            AttackType.PORT_SCAN,
            AttackSeverity.MEDIUM,
            "检测Censys扫描器"
        ),
        AttackSignature(
            "扫描检测 - ZAP特征",
            r"\b(owasp[\s-]*zap|zaproxy)\b",
            AttackType.PORT_SCAN,
            AttackSeverity.LOW,
            "检测OWASP ZAP扫描器"
        ),
        # ============================================================
        # 扩充规则 - DoS攻击
        # ============================================================
        AttackSignature(
            "DoS - Slowloris特征",
            r"X-a:\s*b$",
            AttackType.DOS,
            AttackSeverity.MEDIUM,
            "检测Slowloris慢速连接攻击"
        ),
        AttackSignature(
            "DoS - HTTP慢速POST",
            r"Content-Length\s*:\s*\d{7,}",
            AttackType.DOS,
            AttackSeverity.MEDIUM,
            "检测HTTP慢速POST攻击"
        ),
        AttackSignature(
            "DoS - SYN Flood特征",
            r"\bSYN\b.*\bACK\b.*\bRST\b",
            AttackType.DOS,
            AttackSeverity.HIGH,
            "检测SYN Flood攻击"
        ),
        AttackSignature(
            "DoS - UDP Flood特征",
            r"\bUDP\b.*length\s*:\s*\d{4,}",
            AttackType.DOS,
            AttackSeverity.HIGH,
            "检测UDP Flood攻击"
        ),
        AttackSignature(
            "DoS - ICMP Flood特征",
            r"\bICMP\b.*(Echo\s+Request|Type\s*:\s*8)",
            AttackType.DOS,
            AttackSeverity.MEDIUM,
            "检测ICMP Flood攻击"
        ),
        AttackSignature(
            "DoS - R.U.D.Y.攻击",
            r"Content-Length\s*:\s*\d{8,}",
            AttackType.DOS,
            AttackSeverity.MEDIUM,
            "检测R.U.D.Y.慢速攻击"
        ),
        AttackSignature(
            "DoS - Hping3特征",
            r"\bhping[23]?\b",
            AttackType.DOS,
            AttackSeverity.HIGH,
            "检测Hping3工具"
        ),
        AttackSignature(
            "DoS - LOIC特征",
            r"\bLOIC\b|\bLow\s+Orbit\s+Ion\s+Cannon\b",
            AttackType.DOS,
            AttackSeverity.HIGH,
            "检测LOIC DDoS工具"
        ),
        AttackSignature(
            "DoS - HOIC特征",
            r"\bHOIC\b|\bHigh\s+Orbit\s+Ion\s+Cannon\b",
            AttackType.DOS,
            AttackSeverity.HIGH,
            "检测HOIC DDoS工具"
        ),
        AttackSignature(
            "DoS - Slowhttptest",
            r"\bslowhttptest\b",
            AttackType.DOS,
            AttackSeverity.MEDIUM,
            "检测Slowhttptest工具"
        ),
        AttackSignature(
            "DoS - CL-TE请求走私",
            r"Content-Length\s*:\s*\d+.*Transfer-Encoding\s*:\s*chunked",
            AttackType.DOS,
            AttackSeverity.HIGH,
            "检测CL-TE请求走私"
        ),
        AttackSignature(
            "DoS - TE-CL请求走私",
            r"Transfer-Encoding\s*:\s*chunked.*Content-Length\s*:\s*\d+",
            AttackType.DOS,
            AttackSeverity.HIGH,
            "检测TE-CL请求走私"
        ),
        AttackSignature(
            "DoS - TE-TE请求走私",
            r"Transfer-Encoding\s*:\s*[Cc]hunked\s*,\s*[Tt]ransfer-Encoding",
            AttackType.DOS,
            AttackSeverity.HIGH,
            "检测TE-TE请求走私"
        ),
        AttackSignature(
            "DoS - Ping of Death",
            r"ICMP.*\blength\s*:\s*65535\b",
            AttackType.DOS,
            AttackSeverity.HIGH,
            "检测Ping of Death超大ICMP包"
        ),
        AttackSignature(
            "DoS - Fraggle攻击",
            r"\bUDP\b.*\bdest\s*:\s*7\b",
            AttackType.DOS,
            AttackSeverity.MEDIUM,
            "检测Fraggle UDP echo攻击"
        ),
        # ============================================================
        # 扩充规则 - 数据泄露
        # ============================================================
        AttackSignature(
            "数据泄露 - 密码明文传输",
            r"password\s*[:=]\s*['\"][^'\"]{4,}['\"]",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测密码明文传输"
        ),
        AttackSignature(
            "数据泄露 - API密钥泄露",
            r"(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9]{16,}['\"]",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测API密钥泄露"
        ),
        AttackSignature(
            "数据泄露 - 私钥泄露",
            r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s*PRIVATE\s+KEY-----",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测私钥文件泄露"
        ),
        AttackSignature(
            "数据泄露 - AWS密钥泄露",
            r"AKIA[0-9A-Z]{16}",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测AWS Access Key泄露"
        ),
        AttackSignature(
            "数据泄露 - 数据库连接串",
            r"(mysql|postgres|mongodb|redis)://\w+:\w+@",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测数据库连接字符串泄露"
        ),
        AttackSignature(
            "数据泄露 - JWT密钥泄露",
            r"(jwt[_-]?secret|token[_-]?secret)\s*[:=]\s*['\"][^'\"]+['\"]",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测JWT密钥泄露"
        ),
        AttackSignature(
            "数据泄露 - 邮箱批量导出",
            r"[\w.-]+@[\w.-]+\.\w{2,}.*[\w.-]+@[\w.-]+\.\w{2,}",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测邮箱批量数据泄露"
        ),
        AttackSignature(
            "数据泄露 - 身份证号",
            r"\b[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测中国身份证号泄露"
        ),
        AttackSignature(
            "数据泄露 - 手机号批量",
            r"1[3-9]\d{9}.*1[3-9]\d{9}",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测手机号批量泄露"
        ),
        AttackSignature(
            "数据泄露 - GitHub Token",
            r"gh[pousr]_[A-Za-z0-9_]{36,}",
            AttackType.EXPLOIT,
            AttackSeverity.CRITICAL,
            "检测GitHub Token泄露"
        ),
        AttackSignature(
            "数据泄露 - Slack Token",
            r"xox[baprs]-[0-9]{10,13}-[A-Za-z0-9]{24,}",
            AttackType.EXPLOIT,
            AttackSeverity.HIGH,
            "检测Slack Token泄露"
        ),
        AttackSignature(
            "数据泄露 - Bearer Token",
            r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测Bearer Token传输"
        ),
        AttackSignature(
            "数据泄露 - 敏感版本信息",
            r"Server\s*:\s*(Apache/2\.2|nginx/0\.|PHP/5\.)",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测敏感版本信息泄露"
        ),
        AttackSignature(
            "数据泄露 - 加密货币地址",
            r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测比特币地址泄露"
        ),
        AttackSignature(
            "数据泄露 - 敏感响应头",
            r"X-Debug-Info|X-Profiler|X-Powered-By\s*:\s*(PHP|ASP\.NET|Express)",
            AttackType.EXPLOIT,
            AttackSeverity.MEDIUM,
            "检测敏感响应头信息泄露"
        ),
        # ============================================================
        # 扩充规则 - 协议异常
        # ============================================================
        AttackSignature(
            "协议异常 - 非法HTTP方法",
            r"\b(TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\b\s+/",
            AttackType.OTHER,
            AttackSeverity.MEDIUM,
            "检测非法HTTP方法"
        ),
        AttackSignature(
            "协议异常 - HTTP协议版本异常",
            r"HTTP/(0\.9|3\.0)",
            AttackType.OTHER,
            AttackSeverity.LOW,
            "检测异常HTTP协议版本"
        ),
        AttackSignature(
            "协议异常 - 超长URL",
            r"GET\s+/[^\s]{2048,}\s+HTTP",
            AttackType.OTHER,
            AttackSeverity.MEDIUM,
            "检测超长URL请求"
        ),
        AttackSignature(
            "协议异常 - 超长Header",
            r"[A-Za-z-]+:\s*[^\r\n]{4096,}",
            AttackType.OTHER,
            AttackSeverity.MEDIUM,
            "检测超长Header头"
        ),
        AttackSignature(
            "协议异常 - 多Host头",
            r"Host\s*:[^\r\n]+.*Host\s*:",
            AttackType.OTHER,
            AttackSeverity.HIGH,
            "检测HTTP请求走私多Host头"
        ),
        AttackSignature(
            "协议异常 - CRLF注入",
            r"\r\n\s*\r\n\s*(GET|POST|HTTP)",
            AttackType.OTHER,
            AttackSeverity.HIGH,
            "检测CRLF注入攻击"
        ),
        AttackSignature(
            "协议异常 - 双URL编码",
            r"%25[0-9a-fA-F]{2}",
            AttackType.OTHER,
            AttackSeverity.MEDIUM,
            "检测双重URL编码"
        ),
        AttackSignature(
            "协议异常 - 分块传输异常",
            r"Transfer-Encoding\s*:\s*chunked.*\b0\b\s*\r\n\r\n",
            AttackType.OTHER,
            AttackSeverity.MEDIUM,
            "检测分块传输编码异常"
        ),
        AttackSignature(
            "协议异常 - 可疑Content-Type",
            r"Content-Type\s*:\s*multipart/form-data.*boundary=",
            AttackType.OTHER,
            AttackSeverity.LOW,
            "检测可疑Content-Type"
        ),
        AttackSignature(
            "协议异常 - 空字节注入",
            r"%00",
            AttackType.OTHER,
            AttackSeverity.MEDIUM,
            "检测空字节注入"
        ),
        # ============================================================
        # 扩充规则 - 后门/木马
        # ============================================================
        AttackSignature(
            "后门 - Web Shell特征",
            r"\b(eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测PHP Web Shell后门"
        ),
        AttackSignature(
            "后门 - 中国菜刀特征",
            r"ZWNH[A-Za-z0-9+/=]+",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测中国菜刀WebShell通信"
        ),
        AttackSignature(
            "后门 - 蚁剑特征",
            r"antSword|ant\.sword",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测蚁剑WebShell管理工具"
        ),
        AttackSignature(
            "后门 - 冰蝎特征",
            r"behinder|net\.rebeyond",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测冰蝎动态加密WebShell"
        ),
        AttackSignature(
            "后门 - 哥斯拉特征",
            r"godzilla|Godzilla",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测哥斯拉WebShell管理工具"
        ),
        AttackSignature(
            "后门 - 反弹Shell Bash",
            r"\bbash\s+-i\s+>&\s*/dev/tcp/",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测Bash反弹Shell"
        ),
        AttackSignature(
            "后门 - 反弹Shell Python",
            r"python\s+-c\s+['\"]import\s+socket",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测Python反弹Shell"
        ),
        AttackSignature(
            "后门 - 反弹Shell PHP",
            r"\bphp\s+-r\s+['\"]\$sock",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测PHP反弹Shell"
        ),
        AttackSignature(
            "后门 - Netcat反弹",
            r"\bnc\s+(-e|-c)\s+/bin/(ba)?sh",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测Netcat反弹Shell"
        ),
        AttackSignature(
            "后门 - 计划任务持久化",
            r"\b(crontab|at\s+|schtasks)\s+.*\b(bash|sh|python|perl|powershell)\b",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.HIGH,
            "检测计划任务持久化后门"
        ),
        # ============================================================
        # 扩充规则 - Web Shell检测
        # ============================================================
        AttackSignature(
            "WebShell - PHP一句话",
            r"<\?php\s+@\s*eval\s*\(\s*\$_POST",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测PHP一句话木马"
        ),
        AttackSignature(
            "WebShell - PHP assert木马",
            r"<\?php\s+assert\s*\(\s*\$_(GET|POST|REQUEST)",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测PHP assert木马"
        ),
        AttackSignature(
            "WebShell - PHP base64木马",
            r"<\?php\s+eval\s*\(\s*base64_decode\s*\(",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测PHP base64编码木马"
        ),
        AttackSignature(
            "WebShell - PHP gzinflate木马",
            r"<\?php\s+eval\s*\(\s*gzinflate\s*\(",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测PHP gzinflate压缩木马"
        ),
        AttackSignature(
            "WebShell - PHP str_rot13木马",
            r"<\?php\s+eval\s*\(\s*str_rot13\s*\(",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测PHP rot13编码木马"
        ),
        AttackSignature(
            "WebShell - JSP一句话",
            r"<%\s*Runtime\.getRuntime\(\)\.exec\s*\(",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测JSP命令执行木马"
        ),
        AttackSignature(
            "WebShell - ASP一句话",
            r"<%\s*execute\s*\(\s*request\s*\(",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.CRITICAL,
            "检测ASP一句话木马"
        ),
        AttackSignature(
            "WebShell - ASPX特征",
            r"<%@?\s*Page\s+Language.*CodeBehind.*\.cs",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.HIGH,
            "检测ASPX WebShell特征"
        ),
        AttackSignature(
            "WebShell - 文件管理器",
            r"(file_manager|directory_list|upload_file)\s*\(",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.HIGH,
            "检测WebShell文件管理功能"
        ),
        AttackSignature(
            "WebShell - 隐藏文件上传",
            r"\$_FILES\s*\[\s*['\"]?\w+['\"]?\s*\]\s*\[\s*['\"]?tmp_name",
            AttackType.MALICIOUS_TOOL,
            AttackSeverity.HIGH,
            "检测WebShell文件上传功能"
        ),
    ]
    
    def __init__(self, auto_block: bool = True, block_threshold: int = 3,
                 block_duration: int = 3600):
        """
        初始化IDS引擎
        
        Args:
            auto_block: 是否自动阻断攻击IP
            block_threshold: 触发阻断的攻击次数阈值
            block_duration: 阻断持续时间（秒）
        """
        self.auto_block = auto_block
        self.block_threshold = block_threshold
        self.block_duration = block_duration
        
        # 攻击计数器 {ip: [(timestamp, count)]}
        self.attack_counter = defaultdict(lambda: deque(maxlen=100))
        
        # 已阻断IP列表 {ip: unblock_time}
        self.blocked_ips = {}
        
        # 运行状态
        self._running = False
        self._thread = None
        
        # 外部规则（从 Emerging Threats 等导入的 Suricata 规则）
        self._external_rules = []
        
        # 统计信息
        self.stats = {
            'total_attacks': 0,
            'blocked_ips': 0,
            'attacks_by_type': defaultdict(int),
            'attacks_by_hour': defaultdict(int)
        }
        
        logger.info("IDS引擎初始化完成")
    
    def start(self):
        """启动IDS引擎"""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        
        # 启动清理线程
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        
        logger.info("IDS引擎已启动")
    
    def stop(self):
        """停止IDS引擎"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("IDS引擎已停止")
    
    def _monitor_loop(self):
        """监控循环"""
        while self._running:
            try:
                # 检查并清理过期阻断
                self._check_expired_blocks()
                
                # 更新统计
                self._update_stats()
                
                time.sleep(10)
            except Exception as e:
                logger.error(f"IDS监控循环错误: {e}")
                time.sleep(30)
    
    def _cleanup_loop(self):
        """清理循环 - 清理旧数据"""
        while self._running:
            try:
                # 清理24小时前的攻击计数
                cutoff = time.time() - 86400
                for ip in list(self.attack_counter.keys()):
                    queue = self.attack_counter[ip]
                    while queue and queue[0][0] < cutoff:
                        queue.popleft()
                    if not queue:
                        del self.attack_counter[ip]
                
                time.sleep(3600)  # 每小时清理一次
            except Exception as e:
                logger.error(f"IDS清理循环错误: {e}")
                time.sleep(3600)
    
    def analyze_packet(self, src_ip: str, dst_ip: str, dst_port: int,
                       payload: bytes, protocol: str = "TCP") -> Optional[Dict]:
        """
        分析数据包，检测攻击
        
        Returns:
            如果检测到攻击，返回攻击信息字典；否则返回None
        """
        # 检查IP是否已被阻断
        if self._is_blocked(src_ip):
            return None
        
        # 解码payload
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except:
            payload_str = str(payload)
        
        # 匹配攻击特征（内置 + 外部规则）
        all_signatures = list(self.SIGNATURES) + self._external_rules
        for signature in all_signatures:
            if signature.pattern.search(payload_str):
                attack_info = {
                    'signature': signature.name,
                    'attack_type': signature.attack_type,
                    'severity': signature.severity,
                    'description': signature.description,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'payload_preview': payload_str[:200],
                    'timestamp': datetime.now()
                }
                
                # 处理检测到的攻击
                self._handle_attack(attack_info)
                
                return attack_info
        
        return None
    
    def analyze_http_request(self, src_ip: str, method: str, path: str,
                            headers: Dict, body: str = "") -> Optional[Dict]:
        """分析HTTP请求，检测Web攻击"""
        # 检查IP是否已被阻断
        if self._is_blocked(src_ip):
            return None
        
        # 组合请求内容进行分析
        request_content = f"{method} {path} {json.dumps(headers)} {body}"
        
        # 匹配攻击特征（内置 + 外部规则）
        all_signatures = list(self.SIGNATURES) + self._external_rules
        for signature in all_signatures:
            if signature.pattern.search(request_content):
                attack_info = {
                    'signature': signature.name,
                    'attack_type': signature.attack_type,
                    'severity': signature.severity,
                    'description': signature.description,
                    'src_ip': src_ip,
                    'dst_ip': 'local',
                    'dst_port': 80,
                    'protocol': 'HTTP',
                    'payload_preview': f"{method} {path}",
                    'timestamp': datetime.now()
                }
                
                self._handle_attack(attack_info)
                return attack_info
        
        return None
    
    def _handle_attack(self, attack_info: Dict):
        """处理检测到的攻击"""
        src_ip = attack_info['src_ip']
        
        # 记录到数据库
        self._log_attack(attack_info)
        
        # 更新计数器
        now = time.time()
        self.attack_counter[src_ip].append((now, 1))
        
        # 更新统计
        self.stats['total_attacks'] += 1
        self.stats['attacks_by_type'][attack_info['attack_type'].value] += 1
        self.stats['attacks_by_hour'][datetime.now().hour] += 1
        
        # 检查是否需要阻断
        if self.auto_block:
            self._check_and_block(src_ip, attack_info['severity'])
        
        logger.warning(f"检测到攻击: {attack_info['signature']} from {src_ip}")
    
    def _log_attack(self, attack_info: Dict):
        """记录攻击到数据库"""
        try:
            with db_manager.get_session() as session:
                log = AttackLog(
                    timestamp=attack_info['timestamp'],
                    src_ip=attack_info['src_ip'],
                    dst_ip=attack_info['dst_ip'],
                    dst_port=attack_info['dst_port'],
                    attack_type=attack_info['attack_type'],
                    severity=attack_info['severity'],
                    signature=attack_info['signature'],
                    description=attack_info['description'],
                    payload_preview=attack_info['payload_preview'],
                    protocol=attack_info['protocol'],
                    is_blocked=False
                )
                session.add(log)
                session.commit()
        except Exception as e:
            logger.error(f"记录攻击日志失败: {e}")
    
    def _check_and_block(self, src_ip: str, severity: AttackSeverity):
        """检查并阻断攻击IP"""
        # 严重攻击立即阻断
        if severity == AttackSeverity.CRITICAL:
            self._block_ip(src_ip, "严重级别攻击")
            return
        
        # 计算该IP在阻断窗口期内的攻击次数
        window_start = time.time() - 300  # 5分钟窗口
        attack_count = sum(1 for ts, _ in self.attack_counter[src_ip] if ts > window_start)
        
        # 超过阈值则阻断
        if attack_count >= self.block_threshold:
            self._block_ip(src_ip, f"{attack_count}次攻击/5分钟")
    
    def _block_ip(self, src_ip: str, reason: str):
        """阻断IP地址"""
        if src_ip in self.blocked_ips:
            return
        
        try:
            # 使用iptables阻断
            import subprocess
            
            # 添加到INPUT链
            subprocess.run([
                'iptables', '-I', 'INPUT', '1',
                '-s', src_ip,
                '-j', 'DROP',
                '-m', 'comment', '--comment', f'GK_IDS_BLOCK:{reason}'
            ], check=True, capture_output=True, timeout=10)

            # 添加到FORWARD链（如果是网关）
            subprocess.run([
                'iptables', '-I', 'FORWARD', '1',
                '-s', src_ip,
                '-j', 'DROP',
                '-m', 'comment', '--comment', f'GK_IDS_BLOCK:{reason}'
            ], check=False, capture_output=True, timeout=10)
            
            # 记录阻断
            unblock_time = datetime.now() + timedelta(seconds=self.block_duration)
            self.blocked_ips[src_ip] = unblock_time
            self.stats['blocked_ips'] += 1
            
            # 更新数据库
            with db_manager.get_session() as session:
                # 更新该IP的所有攻击记录为已阻断
                session.query(AttackLog).filter(
                    AttackLog.src_ip == src_ip,
                    AttackLog.is_blocked == False
                ).update({'is_blocked': True})
                session.commit()
            
            logger.warning(f"已阻断IP {src_ip}, 原因: {reason}, 解除时间: {unblock_time}")
            
        except Exception as e:
            logger.error(f"阻断IP {src_ip} 失败: {e}")
    
    def _is_blocked(self, src_ip: str) -> bool:
        """检查IP是否已被阻断"""
        if src_ip not in self.blocked_ips:
            return False
        
        # 检查是否过期
        if datetime.now() > self.blocked_ips[src_ip]:
            self._unblock_ip(src_ip)
            return False
        
        return True
    
    def _unblock_ip(self, src_ip: str):
        """解除IP阻断"""
        try:
            import subprocess
            
            # 从iptables移除INPUT链规则 - 使用完整匹配参数
            subprocess.run([
                'iptables', '-D', 'INPUT',
                '-s', src_ip,
                '-j', 'DROP',
                '-m', 'comment', '--comment', 'GK_IDS_BLOCK:'
            ], check=False, capture_output=True, timeout=10)

            # 从iptables移除FORWARD链规则
            subprocess.run([
                'iptables', '-D', 'FORWARD',
                '-s', src_ip,
                '-j', 'DROP',
                '-m', 'comment', '--comment', 'GK_IDS_BLOCK:'
            ], check=False, capture_output=True, timeout=10)
            
            # 从列表移除
            if src_ip in self.blocked_ips:
                del self.blocked_ips[src_ip]
            
            logger.info(f"已解除IP {src_ip} 的阻断")
            
        except Exception as e:
            logger.error(f"解除阻断 {src_ip} 失败: {e}")
    
    def _check_expired_blocks(self):
        """检查并解除过期的阻断"""
        now = datetime.now()
        expired_ips = [ip for ip, unblock_time in self.blocked_ips.items() if now > unblock_time]
        for ip in expired_ips:
            self._unblock_ip(ip)
    
    def _update_stats(self):
        """更新统计信息"""
        # 可以在这里添加更多统计逻辑
        pass
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return {
            'total_attacks': self.stats['total_attacks'],
            'blocked_ips': len(self.blocked_ips),
            'attacks_by_type': dict(self.stats['attacks_by_type']),
            'attacks_by_hour': dict(self.stats['attacks_by_hour']),
            'current_blocked_ips': list(self.blocked_ips.keys())
        }
    
    def unblock_ip_manual(self, src_ip: str) -> bool:
        """手动解除IP阻断"""
        if src_ip in self.blocked_ips:
            self._unblock_ip(src_ip)
            return True
        return False
    
    def block_ip_manual(self, src_ip: str, duration: int = 3600, reason: str = "手动阻断") -> bool:
        """手动阻断IP"""
        self.block_duration = duration
        self._block_ip(src_ip, reason)
        return True

    def load_external_rules(self, rules_list: list) -> int:
        """
        加载外部 Suricata 规则到 IDS 引擎

        将从 rule_updater 解析后的规则列表转换为内部 AttackSignature，
        使用 Suricata 规则的 msg 作为签名名称，优先使用 content/pcre 字段
        作为匹配模式，若无则使用 msg 中的关键词。

        Args:
            rules_list: 从 rule_updater._parse_suricata_rule() 解析后的规则字典列表

        Returns:
            成功加载的规则数量
        """
        loaded = 0
        # 用于去重的 sid 集合
        existing_sids = {getattr(r, '_external_sid', None) for r in self._external_rules}

        for rule in rules_list:
            if not isinstance(rule, dict):
                continue
            sid = rule.get("sid")
            if sid and sid in existing_sids:
                continue

            name = rule.get("name", "unknown")
            severity_str = rule.get("severity", "medium")
            raw_rule = rule.get("raw_rule", "")

            # 提取 content 和 pcre 字段作为匹配模式
            pattern = self._extract_pattern_from_rule(raw_rule)
            if not pattern:
                # 回退：使用 msg 中的关键词
                pattern = re.escape(name)

            # 映射严重程度
            severity = self._map_external_severity(severity_str)

            # 映射攻击类型（基于 classtype）
            attack_type = self._map_classtype_to_attack_type(rule.get("classtype", ""))

            # 映射攻击类型枚举
            attack_type_enum = self._str_to_attack_type(attack_type)

            try:
                sig = AttackSignature(
                    name="ET-{} (sid:{})".format(name, sid) if sid else "ET-{}".format(name),
                    pattern=pattern,
                    attack_type=attack_type_enum,
                    severity=severity,
                    description="外部规则: {}".format(name),
                )
                sig._external_sid = sid  # 标记为外部规则并记录 sid
                self._external_rules.append(sig)
                existing_sids.add(sid)
                loaded += 1
            except Exception as e:
                logger.warning("加载外部规则失败 (sid=%s): %s", sid, e)

        logger.info("IDS引擎加载外部规则完成，新增 %d 条，总计 %d 条", loaded, len(self._external_rules))
        return loaded

    @staticmethod
    def _extract_pattern_from_rule(raw_rule: str) -> str:
        """
        从 Suricata 原始规则中提取 content/pcre 字段，组合为正则表达式

        Args:
            raw_rule: Suricata 原始规则字符串

        Returns:
            组合后的正则表达式字符串，若无匹配字段则返回空字符串
        """
        import re as _re

        patterns = []

        # 提取 pcre 字段
        pcre_matches = _re.findall(r'pcre\s*:\s*"/([^/]+)/[a-z]*"', raw_rule)
        for p in pcre_matches:
            patterns.append(p)

        # 提取 content 字段并转换为正则
        content_matches = _re.findall(r'content\s*:\s*"([^"]*)"', raw_rule)
        for c in content_matches:
            # 将 content 中的十六进制转义转换为正则
            escaped = ""
            i = 0
            while i < len(c):
                if c[i] == '|' and i + 1 < len(c):
                    # 处理 |XX| 十六进制格式
                    end = c.find('|', i + 1)
                    if end != -1:
                        hex_str = c[i + 1:end].strip()
                        hex_parts = hex_str.split()
                        for hp in hex_parts:
                            try:
                                escaped += r"\x{:02x}".format(int(hp, 16))
                            except ValueError:
                                escaped += _re.escape(hp)
                        i = end + 1
                    else:
                        escaped += _re.escape(c[i])
                        i += 1
                else:
                    escaped += _re.escape(c[i])
                    i += 1
            patterns.append(escaped)

        if not patterns:
            return ""

        # 用 .* 连接多个模式
        return r".*".join(patterns)

    @staticmethod
    def _map_external_severity(severity_str: str):
        """将外部规则的严重程度字符串映射为 AttackSeverity 枚举"""
        mapping = {
            "critical": AttackSeverity.CRITICAL,
            "high": AttackSeverity.HIGH,
            "medium": AttackSeverity.MEDIUM,
            "low": AttackSeverity.LOW,
        }
        return mapping.get(severity_str.lower(), AttackSeverity.MEDIUM)

    @staticmethod
    def _map_classtype_to_attack_type(classtype: str) -> str:
        """将 Suricata classtype 映射为攻击类型字符串"""
        mapping = {
            "web-application-attack": "web_attack",
            "shellcode-detect": "exploit",
            "successful-admin": "exploit",
            "successful-user": "exploit",
            "trojan-activity": "malware",
            "malware-cnc": "malware",
            "attempted-dos": "dos",
            "denial-of-service": "dos",
            "attempted-recon": "recon",
            "network-scan": "recon",
            "attempted-admin": "exploit",
            "attempted-user": "brute_force",
            "default-login-attempt": "brute_force",
            "suspicious-login": "brute_force",
            "bad-unknown": "unknown",
            "misc-attack": "unknown",
            "protocol-command-decode": "unknown",
            "misc-activity": "unknown",
        }
        return mapping.get(classtype, "unknown")

    @staticmethod
    def _str_to_attack_type(attack_type_str: str) -> AttackType:
        """将攻击类型字符串映射为 AttackType 枚举"""
        mapping = {
            "sql_injection": AttackType.SQL_INJECTION,
            "xss": AttackType.XSS,
            "command_injection": AttackType.COMMAND_INJECTION,
            "path_traversal": AttackType.PATH_TRAVERSAL,
            "brute_force": AttackType.BRUTE_FORCE,
            "port_scan": AttackType.PORT_SCAN,
            "exploit": AttackType.EXPLOIT,
            "malware": AttackType.MALICIOUS_TOOL,
            "dos": AttackType.EXPLOIT,
            "recon": AttackType.PORT_SCAN,
            "web_attack": AttackType.XSS,
            "unknown": AttackType.EXPLOIT,
        }
        return mapping.get(attack_type_str, AttackType.EXPLOIT)

    def get_external_rules_count(self) -> int:
        """返回当前加载的外部规则数量"""
        return len(self._external_rules)


# 全局IDS引擎实例
_ids_engine = None
_ids_engine_lock = threading.Lock()


def get_ids_engine() -> IDSEngine:
    """获取IDS引擎实例（单例）"""
    global _ids_engine
    if _ids_engine is None:
        with _ids_engine_lock:
            if _ids_engine is None:
                _ids_engine = IDSEngine()
    return _ids_engine
