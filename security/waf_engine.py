"""
GateKeeper - Web应用防火墙引擎 (WAF)
实现HTTP请求/响应检测、规则管理和攻击拦截功能
"""

import re
import time
import json
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
from enum import Enum

from config.logging_config import get_logger
from core.database import db_manager

logger = get_logger("waf_engine")


class WAFRuleType(str, Enum):
    """WAF规则类型"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD = "file_upload"
    RCE = "rce"
    BOT = "bot"
    RATE_LIMIT = "rate_limit"
    CUSTOM = "custom"


class WAFAction(str, Enum):
    """WAF动作"""
    BLOCK = "block"
    LOG = "log"
    ALLOW = "allow"


class WAFSeverity(str, Enum):
    """WAF严重程度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WAFDecision:
    """WAF决策结果"""

    def __init__(self, allowed: bool = True, rule_id: int = None,
                 reason: str = "", action: str = "allow"):
        self.allowed = allowed
        self.rule_id = rule_id
        self.reason = reason
        self.action = action

    def to_dict(self) -> Dict:
        return {
            "allowed": self.allowed,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "action": self.action,
        }


class WAFRule:
    """WAF规则"""

    def __init__(self, name: str, rule_type: str, pattern: str,
                 action: str = "block", severity: str = "medium",
                 enabled: bool = True, description: str = "",
                 rule_id: int = None):
        self.id = rule_id
        self.name = name
        self.rule_type = rule_type
        self.pattern = pattern
        self.action = action
        self.severity = severity
        self.enabled = enabled
        self.description = description
        self.hit_count = 0
        self.created_at = datetime.now()
        self._compiled = None

        # 编译正则表达式
        try:
            self._compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            logger.warning(f"WAF规则 '{name}' 正则编译失败: {e}")
            self._compiled = None

    def match(self, text: str) -> bool:
        """检查文本是否匹配规则"""
        if not self.enabled or not self._compiled:
            return False
        try:
            return bool(self._compiled.search(text))
        except Exception:
            return False

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "rule_type": self.rule_type,
            "pattern": self.pattern,
            "action": self.action,
            "severity": self.severity,
            "enabled": self.enabled,
            "description": self.description,
            "hit_count": self.hit_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class WAFLog:
    """WAF日志记录"""

    def __init__(self, client_ip: str, method: str, url: str,
                 rule_name: str, rule_type: str, action: str,
                 severity: str, reason: str = ""):
        self.timestamp = datetime.now()
        self.client_ip = client_ip
        self.method = method
        self.url = url
        self.rule_name = rule_name
        self.rule_type = rule_type
        self.action = action
        self.severity = severity
        self.reason = reason

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "client_ip": self.client_ip,
            "method": self.method,
            "url": self.url,
            "rule_name": self.rule_name,
            "rule_type": self.rule_type,
            "action": self.action,
            "severity": self.severity,
            "reason": self.reason,
        }


class WAFEngine:
    """WAF引擎"""

    # 内置规则集
    BUILTIN_RULES = [
        # ---- SQL注入 ----
        {
            "name": "SQL注入 - UNION SELECT",
            "rule_type": "sql_injection",
            "pattern": r"union\s+(all\s+)?select",
            "action": "block",
            "severity": "critical",
            "description": "检测UNION SELECT注入",
        },
        {
            "name": "SQL注入 - OR条件注入",
            "rule_type": "sql_injection",
            "pattern": r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+",
            "action": "block",
            "severity": "high",
            "description": "检测OR 1=1等布尔注入",
        },
        {
            "name": "SQL注入 - information_schema",
            "rule_type": "sql_injection",
            "pattern": r"information_schema",
            "action": "block",
            "severity": "critical",
            "description": "检测information_schema访问",
        },
        {
            "name": "SQL注入 - 时间盲注 SLEEP",
            "rule_type": "sql_injection",
            "pattern": r"\bSLEEP\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测SLEEP时间盲注",
        },
        {
            "name": "SQL注入 - BENCHMARK",
            "rule_type": "sql_injection",
            "pattern": r"\bBENCHMARK\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测BENCHMARK时间盲注",
        },
        # ---- XSS ----
        {
            "name": "XSS - script标签",
            "rule_type": "xss",
            "pattern": r"<\s*script",
            "action": "block",
            "severity": "critical",
            "description": "检测script标签注入",
        },
        {
            "name": "XSS - javascript协议",
            "rule_type": "xss",
            "pattern": r"javascript\s*:",
            "action": "block",
            "severity": "high",
            "description": "检测javascript:协议",
        },
        {
            "name": "XSS - onerror事件",
            "rule_type": "xss",
            "pattern": r"onerror\s*=",
            "action": "block",
            "severity": "high",
            "description": "检测onerror事件处理器",
        },
        {
            "name": "XSS - onmouseover事件",
            "rule_type": "xss",
            "pattern": r"onmouseover\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测onmouseover事件处理器",
        },
        {
            "name": "XSS - iframe标签",
            "rule_type": "xss",
            "pattern": r"<\s*iframe",
            "action": "block",
            "severity": "high",
            "description": "检测iframe标签注入",
        },
        {
            "name": "XSS - eval函数",
            "rule_type": "xss",
            "pattern": r"\beval\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测eval函数调用",
        },
        # ---- 路径遍历 ----
        {
            "name": "路径遍历 - ../",
            "rule_type": "path_traversal",
            "pattern": r"\.\./",
            "action": "block",
            "severity": "high",
            "description": "检测../路径遍历",
        },
        {
            "name": "路径遍历 - ..\\",
            "rule_type": "path_traversal",
            "pattern": r"\.\.\\",
            "action": "block",
            "severity": "high",
            "description": "检测..\\路径遍历",
        },
        {
            "name": "路径遍历 - /etc/passwd",
            "rule_type": "path_traversal",
            "pattern": r"/etc/passwd",
            "action": "block",
            "severity": "critical",
            "description": "检测/etc/passwd文件访问",
        },
        {
            "name": "路径遍历 - /proc/",
            "rule_type": "path_traversal",
            "pattern": r"/proc/",
            "action": "block",
            "severity": "high",
            "description": "检测/proc/目录访问",
        },
        # ---- 命令注入 (RCE) ----
        {
            "name": "命令注入 - 分号管道",
            "rule_type": "rce",
            "pattern": r";\s*(cat|ls|id|whoami|uname|pwd|wget|curl)\b",
            "action": "block",
            "severity": "critical",
            "description": "检测分号命令注入",
        },
        {
            "name": "命令注入 - 管道符",
            "rule_type": "rce",
            "pattern": r"\|\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh)\b",
            "action": "block",
            "severity": "critical",
            "description": "检测管道符命令注入",
        },
        {
            "name": "命令注入 - 反引号",
            "rule_type": "rce",
            "pattern": r"`[^`]+`",
            "action": "block",
            "severity": "critical",
            "description": "检测反引号命令执行",
        },
        {
            "name": "命令注入 - $()",
            "rule_type": "rce",
            "pattern": r"\$\([^)]+\)",
            "action": "block",
            "severity": "critical",
            "description": "检测$()命令替换",
        },
        # ---- 文件上传 ----
        {
            "name": "文件上传 - PHP文件",
            "rule_type": "file_upload",
            "pattern": r"\.(php\d*|phtml)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "critical",
            "description": "检测PHP文件上传",
        },
        {
            "name": "文件上传 - JSP文件",
            "rule_type": "file_upload",
            "pattern": r"\.(jsp|jspx|jspa)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "critical",
            "description": "检测JSP文件上传",
        },
        {
            "name": "文件上传 - ASPX文件",
            "rule_type": "file_upload",
            "pattern": r"\.(aspx|ashx|asmx|ascx)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "critical",
            "description": "检测ASPX文件上传",
        },
        {
            "name": "文件上传 - 可执行文件",
            "rule_type": "file_upload",
            "pattern": r"\.(exe|sh|bat|cmd|msi|dll)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "critical",
            "description": "检测可执行文件上传",
        },
        # ---- 恶意Bot ----
        {
            "name": "Bot - sqlmap",
            "rule_type": "bot",
            "pattern": r"\bsqlmap\b",
            "action": "block",
            "severity": "critical",
            "description": "检测sqlmap扫描工具",
        },
        {
            "name": "Bot - nikto",
            "rule_type": "bot",
            "pattern": r"\bnikto\b",
            "action": "block",
            "severity": "high",
            "description": "检测nikto扫描工具",
        },
        {
            "name": "Bot - nmap",
            "rule_type": "bot",
            "pattern": r"\bnmap\b",
            "action": "block",
            "severity": "high",
            "description": "检测nmap扫描工具",
        },
        {
            "name": "Bot - masscan",
            "rule_type": "bot",
            "pattern": r"\bmasscan\b",
            "action": "block",
            "severity": "high",
            "description": "检测masscan扫描工具",
        },
        {
            "name": "Bot - dirbuster",
            "rule_type": "bot",
            "pattern": r"\bdirbuster\b",
            "action": "block",
            "severity": "medium",
            "description": "检测dirbuster目录扫描",
        },
        {
            "name": "Bot - gobuster",
            "rule_type": "bot",
            "pattern": r"\bgobuster\b",
            "action": "block",
            "severity": "medium",
            "description": "检测gobuster目录扫描",
        },
{
            "name": "SQL注入 - DROP TABLE",
            "rule_type": "sql_injection",
            "pattern": r"\bdrop\s+table\b",
            "action": "block",
            "severity": "critical",
            "description": "检测DROP TABLE语句",
        },
        {
            "name": "SQL注入 - DELETE FROM",
            "rule_type": "sql_injection",
            "pattern": r"\bdelete\s+from\b",
            "action": "block",
            "severity": "critical",
            "description": "检测DELETE FROM语句",
        },
        {
            "name": "SQL注入 - INSERT INTO",
            "rule_type": "sql_injection",
            "pattern": r"\binsert\s+into\b",
            "action": "block",
            "severity": "high",
            "description": "检测INSERT INTO语句",
        },
        {
            "name": "SQL注入 - UPDATE SET",
            "rule_type": "sql_injection",
            "pattern": r"\bupdate\s+\w+\s+set\s+",
            "action": "block",
            "severity": "high",
            "description": "检测UPDATE SET语句",
        },
        {
            "name": "SQL注入 - ALTER TABLE",
            "rule_type": "sql_injection",
            "pattern": r"\balter\s+table\b",
            "action": "block",
            "severity": "critical",
            "description": "检测ALTER TABLE语句",
        },
        {
            "name": "SQL注入 - CREATE TABLE",
            "rule_type": "sql_injection",
            "pattern": r"\bcreate\s+table\b",
            "action": "block",
            "severity": "critical",
            "description": "检测CREATE TABLE语句",
        },
        {
            "name": "SQL注入 - GRANT ALL",
            "rule_type": "sql_injection",
            "pattern": r"\bgrant\s+all\b",
            "action": "block",
            "severity": "critical",
            "description": "检测GRANT权限提升",
        },
        {
            "name": "SQL注入 - TRUNCATE TABLE",
            "rule_type": "sql_injection",
            "pattern": r"\btruncate\s+table\b",
            "action": "block",
            "severity": "critical",
            "description": "检测TRUNCATE TABLE语句",
        },
        {
            "name": "SQL注入 - EXEC sp_",
            "rule_type": "sql_injection",
            "pattern": r"\bexec\s+sp_\w+",
            "action": "block",
            "severity": "critical",
            "description": "检测MSSQL存储过程执行",
        },
        {
            "name": "SQL注入 - CONVERT函数",
            "rule_type": "sql_injection",
            "pattern": r"\bconvert\s*\(",
            "action": "block",
            "severity": "medium",
            "description": "检测CONVERT函数SQL注入",
        },
        {
            "name": "SQL注入 - CAST函数",
            "rule_type": "sql_injection",
            "pattern": r"\bcast\s*\(",
            "action": "block",
            "severity": "medium",
            "description": "检测CAST函数SQL注入",
        },
        {
            "name": "SQL注入 - COALESCE函数",
            "rule_type": "sql_injection",
            "pattern": r"\bcoalesce\s*\(",
            "action": "block",
            "severity": "medium",
            "description": "检测COALESCE函数利用",
        },
        {
            "name": "SQL注入 - IFNULL函数",
            "rule_type": "sql_injection",
            "pattern": r"\bifnull\s*\(",
            "action": "block",
            "severity": "medium",
            "description": "检测IFNULL函数利用",
        },
        {
            "name": "SQL注入 - GROUP_CONCAT",
            "rule_type": "sql_injection",
            "pattern": r"\bgroup_concat\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测GROUP_CONCAT数据提取",
        },
        {
            "name": "SQL注入 - CONCAT_WS",
            "rule_type": "sql_injection",
            "pattern": r"\bconcat_ws\s*\(",
            "action": "block",
            "severity": "medium",
            "description": "检测CONCAT_WS数据拼接",
        },
        {
            "name": "SQL注入 - LOAD DATA",
            "rule_type": "sql_injection",
            "pattern": r"\bload\s+data\s+(local\s+)?infile\b",
            "action": "block",
            "severity": "critical",
            "description": "检测LOAD DATA INFILE文件读取",
        },
        {
            "name": "SQL注入 - INTO DUMPFILE",
            "rule_type": "sql_injection",
            "pattern": r"\binto\s+dumpfile\b",
            "action": "block",
            "severity": "critical",
            "description": "检测INTO DUMPFILE写文件",
        },
        {
            "name": "SQL注入 - EXTRACTVALUE",
            "rule_type": "sql_injection",
            "pattern": r"\bextractvalue\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测EXTRACTVALUE报错注入",
        },
        {
            "name": "SQL注入 - UPDATEXML",
            "rule_type": "sql_injection",
            "pattern": r"\bupdatexml\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测UPDATEXML报错注入",
        },
        {
            "name": "SQL注入 - XMLTYPE",
            "rule_type": "sql_injection",
            "pattern": r"\bxmltype\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测Oracle XMLTYPE报错注入",
        },
        {
            "name": "SQL注入 - HEX编码",
            "rule_type": "sql_injection",
            "pattern": r"\bx\s*['\"]?[0-9a-f]{8,}['\"]?",
            "action": "block",
            "severity": "medium",
            "description": "检测HEX编码SQL注入",
        },
        {
            "name": "SQL注入 - WAITFOR DELAY",
            "rule_type": "sql_injection",
            "pattern": r"\bwaitfor\s+delay\b",
            "action": "block",
            "severity": "high",
            "description": "检测MSSQL WAITFOR延迟注入",
        },
        {
            "name": "SQL注入 - DBMS_PIPE",
            "rule_type": "sql_injection",
            "pattern": r"\bdbms_pipe\.\s*receive_message\b",
            "action": "block",
            "severity": "high",
            "description": "检测Oracle DBMS_PIPE延迟注入",
        },
        {
            "name": "SQL注入 - pg_sleep",
            "rule_type": "sql_injection",
            "pattern": r"\bpg_sleep\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测PostgreSQL延迟注入",
        },
        {
            "name": "SQL注入 - RLIKE正则",
            "rule_type": "sql_injection",
            "pattern": r"\brlike\s+['\"]",
            "action": "block",
            "severity": "medium",
            "description": "检测RLIKE正则盲注",
        },
        {
            "name": "SQL注入 - REGEXP正则",
            "rule_type": "sql_injection",
            "pattern": r"\bregexp\s+['\"]",
            "action": "block",
            "severity": "medium",
            "description": "检测REGEXP正则盲注",
        },
        {
            "name": "XSS - form标签action",
            "rule_type": "xss",
            "pattern": r"<\s*form\b[^>]*action\s*=\s*['\"]?javascript:",
            "action": "block",
            "severity": "high",
            "description": "检测form标签javascript action",
        },
        {
            "name": "XSS - a标签href",
            "rule_type": "xss",
            "pattern": r"<\s*a\b[^>]*href\s*=\s*['\"]?javascript:",
            "action": "block",
            "severity": "high",
            "description": "检测a标签javascript href",
        },
        {
            "name": "XSS - div标签事件",
            "rule_type": "xss",
            "pattern": r"<\s*div\b[^>]*on\w+\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测div标签事件注入",
        },
        {
            "name": "XSS - video标签事件",
            "rule_type": "xss",
            "pattern": r"<\s*video\b[^>]*on\w+\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测video标签事件注入",
        },
        {
            "name": "XSS - audio标签事件",
            "rule_type": "xss",
            "pattern": r"<\s*audio\b[^>]*on\w+\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测audio标签事件注入",
        },
        {
            "name": "XSS - details标签事件",
            "rule_type": "xss",
            "pattern": r"<\s*details\b[^>]*ontoggle\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测details标签ontoggle",
        },
        {
            "name": "XSS - marquee标签事件",
            "rule_type": "xss",
            "pattern": r"<\s*marquee\b[^>]*on\w+\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测marquee标签事件注入",
        },
        {
            "name": "XSS - isindex标签",
            "rule_type": "xss",
            "pattern": r"<\s*isindex\b",
            "action": "block",
            "severity": "medium",
            "description": "检测isindex标签注入",
        },
        {
            "name": "XSS - table标签背景",
            "rule_type": "xss",
            "pattern": r"<\s*table\b[^>]*background\s*=\s*['\"]?javascript:",
            "action": "block",
            "severity": "medium",
            "description": "检测table标签背景注入",
        },
        {
            "name": "XSS - bgsound标签",
            "rule_type": "xss",
            "pattern": r"<\s*bgsound\b[^>]*src\s*=\s*['\"]?javascript:",
            "action": "block",
            "severity": "medium",
            "description": "检测bgsound标签注入",
        },
        {
            "name": "XSS - link标签",
            "rule_type": "xss",
            "pattern": r"<\s*link\b[^>]*rel\s*=\s*['\"]?import\b[^>]*href\s*=\s*['\"]?javascript:",
            "action": "block",
            "severity": "high",
            "description": "检测link标签CSS注入",
        },
        {
            "name": "XSS - style标签",
            "rule_type": "xss",
            "pattern": r"<\s*style\b[^>]*>.*expression\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测style标签CSS表达式注入",
        },
        {
            "name": "XSS - expression()",
            "rule_type": "xss",
            "pattern": r"expression\s*\(\s*['\"]?",
            "action": "block",
            "severity": "high",
            "description": "检测CSS expression表达式",
        },
        {
            "name": "XSS - -moz-binding",
            "rule_type": "xss",
            "pattern": r"-moz-binding\s*:",
            "action": "block",
            "severity": "high",
            "description": "检测Firefox CSS XBL绑定",
        },
        {
            "name": "XSS - @import",
            "rule_type": "xss",
            "pattern": r"@import\s+['\"]",
            "action": "block",
            "severity": "medium",
            "description": "检测CSS @import注入",
        },
        {
            "name": "XSS - data URI",
            "rule_type": "xss",
            "pattern": r"data\s*:\s*text/html\s*;",
            "action": "block",
            "severity": "high",
            "description": "检测data URI HTML注入",
        },
        {
            "name": "XSS - onanimationend",
            "rule_type": "xss",
            "pattern": r"onanimationend\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测CSS动画事件注入",
        },
        {
            "name": "XSS - ontransitionend",
            "rule_type": "xss",
            "pattern": r"ontransitionend\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测CSS过渡事件注入",
        },
        {
            "name": "XSS - onpointerover",
            "rule_type": "xss",
            "pattern": r"onpointer\w+\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测Pointer事件注入",
        },
        {
            "name": "XSS - ondrag事件",
            "rule_type": "xss",
            "pattern": r"ondrag\w+\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测拖拽事件注入",
        },
        {
            "name": "XSS - onwheel事件",
            "rule_type": "xss",
            "pattern": r"onwheel\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测滚轮事件注入",
        },
        {
            "name": "XSS - oncut事件",
            "rule_type": "xss",
            "pattern": r"on(cut|copy|paste)\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测剪贴板事件注入",
        },
        {
            "name": "XSS - onscroll事件",
            "rule_type": "xss",
            "pattern": r"onscroll\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测滚动事件注入",
        },
        {
            "name": "XSS - onresize事件",
            "rule_type": "xss",
            "pattern": r"onresize\s*=",
            "action": "block",
            "severity": "medium",
            "description": "检测窗口缩放事件注入",
        },
        {
            "name": "XSS - setTimeout字符串",
            "rule_type": "xss",
            "pattern": r"setTimeout\s*\(\s*['\"]",
            "action": "block",
            "severity": "high",
            "description": "检测setTimeout字符串注入",
        },
        {
            "name": "XSS - setInterval字符串",
            "rule_type": "xss",
            "pattern": r"setInterval\s*\(\s*['\"]",
            "action": "block",
            "severity": "high",
            "description": "检测setInterval字符串注入",
        },
        {
            "name": "XSS - Function构造器",
            "rule_type": "xss",
            "pattern": r"\bFunction\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测Function构造器注入",
        },
        {
            "name": "路径遍历 - /etc/hosts",
            "rule_type": "path_traversal",
            "pattern": r"/etc/hosts",
            "action": "block",
            "severity": "high",
            "description": "检测/etc/hosts文件访问",
        },
        {
            "name": "路径遍历 - /etc/crontab",
            "rule_type": "path_traversal",
            "pattern": r"/etc/crontab",
            "action": "block",
            "severity": "high",
            "description": "检测/etc/crontab文件访问",
        },
        {
            "name": "路径遍历 - /boot.ini",
            "rule_type": "path_traversal",
            "pattern": r"/boot\.ini",
            "action": "block",
            "severity": "medium",
            "description": "检测boot.ini文件访问",
        },
        {
            "name": "路径遍历 - .bash_history",
            "rule_type": "path_traversal",
            "pattern": r"\.bash_history",
            "action": "block",
            "severity": "medium",
            "description": "检测bash历史文件访问",
        },
        {
            "name": "路径遍历 - .bashrc",
            "rule_type": "path_traversal",
            "pattern": r"\.bashrc",
            "action": "block",
            "severity": "medium",
            "description": "检测bashrc配置文件访问",
        },
        {
            "name": "路径遍历 - .mysql_history",
            "rule_type": "path_traversal",
            "pattern": r"\.mysql_history",
            "action": "block",
            "severity": "medium",
            "description": "检测MySQL历史文件访问",
        },
        {
            "name": "路径遍历 - /root/.ssh",
            "rule_type": "path_traversal",
            "pattern": r"/root/\.ssh/",
            "action": "block",
            "severity": "critical",
            "description": "检测root SSH目录访问",
        },
        {
            "name": "路径遍历 - /home/*/.ssh",
            "rule_type": "path_traversal",
            "pattern": r"/home/\w+/\.ssh/",
            "action": "block",
            "severity": "critical",
            "description": "检测用户SSH目录访问",
        },
        {
            "name": "路径遍历 - /tmp/",
            "rule_type": "path_traversal",
            "pattern": r"/tmp/.*\.\w+",
            "action": "block",
            "severity": "medium",
            "description": "检测/tmp目录文件访问",
        },
        {
            "name": "路径遍历 - /opt/",
            "rule_type": "path_traversal",
            "pattern": r"\.\./\.\./opt/",
            "action": "block",
            "severity": "medium",
            "description": "检测/opt目录遍历",
        },
        {
            "name": "路径遍历 - /usr/local/",
            "rule_type": "path_traversal",
            "pattern": r"\.\./\.\./usr/local/",
            "action": "block",
            "severity": "medium",
            "description": "检测/usr/local目录遍历",
        },
        {
            "name": "命令注入 - perl命令",
            "rule_type": "rce",
            "pattern": r";\s*perl\s+-e\s+'",
            "action": "block",
            "severity": "critical",
            "description": "检测perl命令注入",
        },
        {
            "name": "命令注入 - ruby命令",
            "rule_type": "rce",
            "pattern": r";\s*ruby\s+-e\s+'",
            "action": "block",
            "severity": "critical",
            "description": "检测ruby命令注入",
        },
        {
            "name": "命令注入 - php命令",
            "rule_type": "rce",
            "pattern": r";\s*php\s+-r\s+'",
            "action": "block",
            "severity": "critical",
            "description": "检测php命令注入",
        },
        {
            "name": "命令注入 - python命令",
            "rule_type": "rce",
            "pattern": r";\s*python[23]?\s+-c\s+'",
            "action": "block",
            "severity": "critical",
            "description": "检测python命令注入",
        },
        {
            "name": "命令注入 - awk命令",
            "rule_type": "rce",
            "pattern": r"\|\s*awk\s+'",
            "action": "block",
            "severity": "high",
            "description": "检测awk命令注入",
        },
        {
            "name": "命令注入 - sed命令",
            "rule_type": "rce",
            "pattern": r"\|\s*sed\s+'",
            "action": "block",
            "severity": "high",
            "description": "检测sed命令注入",
        },
        {
            "name": "命令注入 - find命令",
            "rule_type": "rce",
            "pattern": r";\s*find\s+/-exec\s+",
            "action": "block",
            "severity": "critical",
            "description": "检测find -exec命令注入",
        },
        {
            "name": "命令注入 - xargs命令",
            "rule_type": "rce",
            "pattern": r"\|\s*xargs\s+",
            "action": "block",
            "severity": "high",
            "description": "检测xargs命令注入",
        },
        {
            "name": "命令注入 - tee命令",
            "rule_type": "rce",
            "pattern": r"\|\s*tee\s+/",
            "action": "block",
            "severity": "high",
            "description": "检测tee写文件注入",
        },
        {
            "name": "命令注入 - dd命令",
            "rule_type": "rce",
            "pattern": r";\s*dd\s+if=",
            "action": "block",
            "severity": "high",
            "description": "检测dd命令磁盘操作",
        },
        {
            "name": "命令注入 - mkfifo",
            "rule_type": "rce",
            "pattern": r";\s*mkfifo\s+",
            "action": "block",
            "severity": "high",
            "description": "检测mkfifo命名管道",
        },
        {
            "name": "命令注入 - socat反弹",
            "rule_type": "rce",
            "pattern": r"\bsocat\s+(tcp|exec)",
            "action": "block",
            "severity": "critical",
            "description": "检测socat反弹Shell",
        },
        {
            "name": "命令注入 - powershell",
            "rule_type": "rce",
            "pattern": r"\bpowershell\s+-",
            "action": "block",
            "severity": "critical",
            "description": "检测PowerShell命令执行",
        },
        {
            "name": "命令注入 - cmd.exe",
            "rule_type": "rce",
            "pattern": r"\bcmd\s*(\.exe)?\s*/c\s+",
            "action": "block",
            "severity": "critical",
            "description": "检测cmd.exe命令执行",
        },
        {
            "name": "命令注入 - chmod",
            "rule_type": "rce",
            "pattern": r";\s*chmod\s+777\s+",
            "action": "block",
            "severity": "high",
            "description": "检测chmod权限修改",
        },
        {
            "name": "命令注入 - chown",
            "rule_type": "rce",
            "pattern": r";\s*chown\s+",
            "action": "block",
            "severity": "high",
            "description": "检测chown属主修改",
        },
        {
            "name": "命令注入 - crontab",
            "rule_type": "rce",
            "pattern": r";\s*crontab\s+",
            "action": "block",
            "severity": "high",
            "description": "检测crontab持久化",
        },
        {
            "name": "命令注入 - at命令",
            "rule_type": "rce",
            "pattern": r";\s*at\s+\w+\s+;",
            "action": "block",
            "severity": "high",
            "description": "检测at定时任务",
        },
        {
            "name": "命令注入 - nohup",
            "rule_type": "rce",
            "pattern": r";\s*nohup\s+",
            "action": "block",
            "severity": "high",
            "description": "检测nohup后台执行",
        },
        {
            "name": "命令注入 - screen/tmux",
            "rule_type": "rce",
            "pattern": r";\s*(screen|tmux)\s+",
            "action": "block",
            "severity": "medium",
            "description": "检测screen/tmux会话持久化",
        },
        {
            "name": "命令注入 - tftp下载",
            "rule_type": "rce",
            "pattern": r"\btftp\s+",
            "action": "block",
            "severity": "high",
            "description": "检测tftp文件下载",
        },
        {
            "name": "命令注入 - scp传输",
            "rule_type": "rce",
            "pattern": r"\bscp\s+",
            "action": "block",
            "severity": "medium",
            "description": "检测scp文件传输",
        },
        {
            "name": "命令注入 - ncat",
            "rule_type": "rce",
            "pattern": r"\bncat\s+(-e|--sh-exec)",
            "action": "block",
            "severity": "critical",
            "description": "检测ncat反弹Shell",
        },
        {
            "name": "文件上传 - CGI脚本",
            "rule_type": "file_upload",
            "pattern": r"\.(cgi|pl)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "high",
            "description": "检测CGI/Perl脚本上传",
        },
        {
            "name": "文件上传 - Python脚本",
            "rule_type": "file_upload",
            "pattern": r"\.(py|pyw)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "high",
            "description": "检测Python脚本上传",
        },
        {
            "name": "文件上传 - Ruby脚本",
            "rule_type": "file_upload",
            "pattern": r"\.(rb)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "high",
            "description": "检测Ruby脚本上传",
        },
        {
            "name": "文件上传 - Shell脚本",
            "rule_type": "file_upload",
            "pattern": r"\.(sh|ksh|csh|bash)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "critical",
            "description": "检测Shell脚本上传",
        },
        {
            "name": "文件上传 - 配置文件",
            "rule_type": "file_upload",
            "pattern": r"\.(htaccess|htpasswd|ini|conf|cfg)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "high",
            "description": "检测配置文件上传",
        },
        {
            "name": "文件上传 - SSI文件",
            "rule_type": "file_upload",
            "pattern": r"\.(shtml|shtm|stm)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "high",
            "description": "检测SSI文件上传",
        },
        {
            "name": "文件上传 - 模板文件",
            "rule_type": "file_upload",
            "pattern": r"\.(phtml|php\d|inc|module)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "critical",
            "description": "检测PHP模板文件上传",
        },
        {
            "name": "文件上传 - WAR包",
            "rule_type": "file_upload",
            "pattern": r"\.(war|ear|jar)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "critical",
            "description": "检测Java WAR包上传",
        },
        {
            "name": "文件上传 - MSI安装包",
            "rule_type": "file_upload",
            "pattern": r"\.(msi|msp)(\s|$|\?|#|&)",
            "action": "block",
            "severity": "critical",
            "description": "检测Windows安装包上传",
        },
        {
            "name": "文件上传 - 双重扩展名",
            "rule_type": "file_upload",
            "pattern": r"\.\w+\.(php|jsp|asp|aspx|cgi)\.\w+(\s|$)",
            "action": "block",
            "severity": "high",
            "description": "检测双重扩展名绕过",
        },
        {
            "name": "文件上传 - 空字节绕过",
            "rule_type": "file_upload",
            "pattern": r"\.(php|jsp|asp|aspx|sh)\s*%00",
            "action": "block",
            "severity": "critical",
            "description": "检测空字节截断绕过",
        },
        {
            "name": "Bot - wfuzz",
            "rule_type": "bot",
            "pattern": r"\bwfuzz\b",
            "action": "block",
            "severity": "medium",
            "description": "检测wfuzz模糊测试工具",
        },
        {
            "name": "Bot - ffuf",
            "rule_type": "bot",
            "pattern": r"\bffuf\b",
            "action": "block",
            "severity": "medium",
            "description": "检测ffuf模糊测试工具",
        },
        {
            "name": "Bot - feroxbuster",
            "rule_type": "bot",
            "pattern": r"\bferoxbuster\b",
            "action": "block",
            "severity": "medium",
            "description": "检测feroxbuster扫描工具",
        },
        {
            "name": "Bot - httpx",
            "rule_type": "bot",
            "pattern": r"\bhttpx\b.*projectdiscovery",
            "action": "block",
            "severity": "medium",
            "description": "检测httpx探测工具",
        },
        {
            "name": "Bot - subfinder",
            "rule_type": "bot",
            "pattern": r"\bsubfinder\b",
            "action": "block",
            "severity": "medium",
            "description": "检测subfinder子域名枚举",
        },
        {
            "name": "Bot - nuclei",
            "rule_type": "bot",
            "pattern": r"\bnuclei\b",
            "action": "block",
            "severity": "medium",
            "description": "检测nuclei漏洞扫描",
        },
        {
            "name": "Bot - amass",
            "rule_type": "bot",
            "pattern": r"\bamass\b",
            "action": "block",
            "severity": "medium",
            "description": "检测amass子域名枚举",
        },
        {
            "name": "Bot - theHarvester",
            "rule_type": "bot",
            "pattern": r"\btheHarvester\b",
            "action": "block",
            "severity": "medium",
            "description": "检测theHarvester信息收集",
        },
        {
            "name": "Bot - maltego",
            "rule_type": "bot",
            "pattern": r"\bmaltego\b",
            "action": "block",
            "severity": "medium",
            "description": "检测Maltego侦察工具",
        },
        {
            "name": "Bot - recon-ng",
            "rule_type": "bot",
            "pattern": r"\brecon-ng\b",
            "action": "block",
            "severity": "medium",
            "description": "检测recon-ng侦察框架",
        },
        {
            "name": "Bot - spiderfoot",
            "rule_type": "bot",
            "pattern": r"\bspiderfoot\b",
            "action": "block",
            "severity": "medium",
            "description": "检测SpiderFoot OSINT工具",
        },
        {
            "name": "Bot - metasploit",
            "rule_type": "bot",
            "pattern": r"\bmetasploit\b",
            "action": "block",
            "severity": "critical",
            "description": "检测Metasploit框架",
        },
        {
            "name": "Bot - hydra",
            "rule_type": "bot",
            "pattern": r"\bhydra\b",
            "action": "block",
            "severity": "high",
            "description": "检测Hydra暴力破解工具",
        },
        {
            "name": "Bot - medusa",
            "rule_type": "bot",
            "pattern": r"\bmedusa\b",
            "action": "block",
            "severity": "high",
            "description": "检测Medusa暴力破解工具",
        },
        {
            "name": "SSRF - 内网IP 127.0.0.1",
            "rule_type": "ssrf",
            "pattern": r"https?://127\.0\.0\.1\b",
            "action": "block",
            "severity": "critical",
            "description": "检测127.0.0.1内网请求",
        },
        {
            "name": "SSRF - 内网IP 10段",
            "rule_type": "ssrf",
            "pattern": r"https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "action": "block",
            "severity": "critical",
            "description": "检测10段内网IP请求",
        },
        {
            "name": "SSRF - 内网IP 172段",
            "rule_type": "ssrf",
            "pattern": r"https?://172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
            "action": "block",
            "severity": "critical",
            "description": "检测172段内网IP请求",
        },
        {
            "name": "SSRF - 内网IP 192段",
            "rule_type": "ssrf",
            "pattern": r"https?://192\.168\.\d{1,3}\.\d{1,3}\b",
            "action": "block",
            "severity": "critical",
            "description": "检测192.168段内网IP请求",
        },
        {
            "name": "SSRF - localhost",
            "rule_type": "ssrf",
            "pattern": r"https?://localhost\b",
            "action": "block",
            "severity": "critical",
            "description": "检测localhost请求",
        },
        {
            "name": "SSRF - 0.0.0.0",
            "rule_type": "ssrf",
            "pattern": r"https?://0\.0\.0\.0\b",
            "action": "block",
            "severity": "critical",
            "description": "检测0.0.0.0请求",
        },
        {
            "name": "SSRF - 云元数据",
            "rule_type": "ssrf",
            "pattern": r"169\.254\.169\.254",
            "action": "block",
            "severity": "critical",
            "description": "检测云服务元数据请求",
        },
        {
            "name": "SSRF - file协议",
            "rule_type": "ssrf",
            "pattern": r"file:///",
            "action": "block",
            "severity": "critical",
            "description": "检测file协议读取",
        },
        {
            "name": "SSRF - gopher协议",
            "rule_type": "ssrf",
            "pattern": r"gopher://",
            "action": "block",
            "severity": "critical",
            "description": "检测gopher协议利用",
        },
        {
            "name": "SSRF - dict协议",
            "rule_type": "ssrf",
            "pattern": r"dict://",
            "action": "block",
            "severity": "high",
            "description": "检测dict协议利用",
        },
        {
            "name": "SSRF - IP进制转换",
            "rule_type": "ssrf",
            "pattern": r"https?://0x[0-9a-f]{4,}",
            "action": "block",
            "severity": "high",
            "description": "检测IP十六进制转换绕过",
        },
        {
            "name": "SSRF - IP十进制转换",
            "rule_type": "ssrf",
            "pattern": r"https?://\d{8,10}\b",
            "action": "block",
            "severity": "high",
            "description": "检测IP十进制转换绕过",
        },
        {
            "name": "SSRF - DNS重绑定nip.io",
            "rule_type": "ssrf",
            "pattern": r"\.nip\.io\b",
            "action": "block",
            "severity": "medium",
            "description": "检测nip.io DNS重绑定",
        },
        {
            "name": "SSRF - URL解析差异",
            "rule_type": "ssrf",
            "pattern": r"https?://@[^/]+@",
            "action": "block",
            "severity": "high",
            "description": "检测URL认证绕过",
        },
        {
            "name": "SSRF - 常见SSRF参数",
            "rule_type": "ssrf",
            "pattern": r"(url|src|dest|redirect|next|data|reference|site)=https?://(127|10|172|192|localhost)",
            "action": "block",
            "severity": "high",
            "description": "检测常见SSRF参数内网请求",
        },
        {
            "name": "XXE - DOCTYPE声明",
            "rule_type": "xxe",
            "pattern": r"<!DOCTYPE\b",
            "action": "block",
            "severity": "high",
            "description": "检测XML DOCTYPE声明",
        },
        {
            "name": "XXE - 外部实体SYSTEM",
            "rule_type": "xxe",
            "pattern": r"<!ENTITY\b[^>]+SYSTEM\b",
            "action": "block",
            "severity": "critical",
            "description": "检测外部实体SYSTEM声明",
        },
        {
            "name": "XXE - 外部实体PUBLIC",
            "rule_type": "xxe",
            "pattern": r"<!ENTITY\b[^>]+PUBLIC\b",
            "action": "block",
            "severity": "critical",
            "description": "检测外部实体PUBLIC声明",
        },
        {
            "name": "XXE - 参数实体",
            "rule_type": "xxe",
            "pattern": r"<!ENTITY\s+%\s+\w+",
            "action": "block",
            "severity": "critical",
            "description": "检测参数实体声明",
        },
        {
            "name": "XXE - XInclude",
            "rule_type": "xxe",
            "pattern": r"<xi:include\b",
            "action": "block",
            "severity": "high",
            "description": "检测XInclude外部包含",
        },
        {
            "name": "XXE - DTD内部子集",
            "rule_type": "xxe",
            "pattern": r"<!DOCTYPE\s+\w+\s*\[",
            "action": "block",
            "severity": "high",
            "description": "检测DTD内部子集",
        },
        {
            "name": "XXE - file协议",
            "rule_type": "xxe",
            "pattern": r"SYSTEM\s+['\"]file://",
            "action": "block",
            "severity": "critical",
            "description": "检测file协议XXE",
        },
        {
            "name": "XXE - expect协议",
            "rule_type": "xxe",
            "pattern": r"SYSTEM\s+['\"]expect://",
            "action": "block",
            "severity": "critical",
            "description": "检测expect协议XXE",
        },
        {
            "name": "XXE - gopher协议",
            "rule_type": "xxe",
            "pattern": r"SYSTEM\s+['\"]gopher://",
            "action": "block",
            "severity": "critical",
            "description": "检测gopher协议XXE",
        },
        {
            "name": "XXE - http外带",
            "rule_type": "xxe",
            "pattern": r"SYSTEM\s+['\"]https?://",
            "action": "block",
            "severity": "high",
            "description": "检测HTTP外带数据XXE",
        },
        {
            "name": "SSTI - Jinja2表达式",
            "rule_type": "ssti",
            "pattern": r"\{\{.*\}\}",
            "action": "block",
            "severity": "high",
            "description": "检测Jinja2模板表达式",
        },
        {
            "name": "SSTI - __class__链",
            "rule_type": "ssti",
            "pattern": r"\.\_\_class\_\_",
            "action": "block",
            "severity": "critical",
            "description": "检测Python类继承链",
        },
        {
            "name": "SSTI - __subclasses__",
            "rule_type": "ssti",
            "pattern": r"\.\_\_subclasses\_\_",
            "action": "block",
            "severity": "critical",
            "description": "检测Python子类遍历",
        },
        {
            "name": "SSTI - __globals__",
            "rule_type": "ssti",
            "pattern": r"\.\_\_globals\_\_",
            "action": "block",
            "severity": "critical",
            "description": "检测全局变量访问",
        },
        {
            "name": "SSTI - __builtins__",
            "rule_type": "ssti",
            "pattern": r"\.\_\_builtins\_\_",
            "action": "block",
            "severity": "critical",
            "description": "检测内建函数访问",
        },
        {
            "name": "SSTI - __mro__",
            "rule_type": "ssti",
            "pattern": r"\.\_\_mro\_\_",
            "action": "block",
            "severity": "critical",
            "description": "检测Python MRO链",
        },
        {
            "name": "SSTI - __init__",
            "rule_type": "ssti",
            "pattern": r"\.\_\_init\_\_\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测__init__访问",
        },
        {
            "name": "SSTI - config对象",
            "rule_type": "ssti",
            "pattern": r"\.\s*config\b.*\.\_\_",
            "action": "block",
            "severity": "high",
            "description": "检测Flask config对象",
        },
        {
            "name": "SSTI - request对象",
            "rule_type": "ssti",
            "pattern": r"\.\s*request\b\.(args|form|values|cookies)",
            "action": "block",
            "severity": "high",
            "description": "检测request对象访问",
        },
        {
            "name": "SSTI - Tornado raw",
            "rule_type": "ssti",
            "pattern": r"\{\%\s*raw\s*\%\}",
            "action": "block",
            "severity": "high",
            "description": "检测Tornado raw模板注入",
        },
        {
            "name": "协议滥用 - HTTP请求走私CL-TE",
            "rule_type": "protocol_abuse",
            "pattern": r"Content-Length\s*:\s*\d+.*Transfer-Encoding\s*:\s*chunked",
            "action": "block",
            "severity": "critical",
            "description": "检测CL-TE请求走私",
        },
        {
            "name": "协议滥用 - HTTP请求走私TE-CL",
            "rule_type": "protocol_abuse",
            "pattern": r"Transfer-Encoding\s*:\s*chunked.*Content-Length\s*:\s*\d+",
            "action": "block",
            "severity": "critical",
            "description": "检测TE-CL请求走私",
        },
        {
            "name": "协议滥用 - Host头注入",
            "rule_type": "protocol_abuse",
            "pattern": r"Host\s*:[^\r\n]+.*Host\s*:",
            "action": "block",
            "severity": "high",
            "description": "检测多Host头注入",
        },
        {
            "name": "协议滥用 - CRLF注入",
            "rule_type": "protocol_abuse",
            "pattern": r"%0d%0a|%0D%0A",
            "action": "block",
            "severity": "high",
            "description": "检测CRLF注入编码",
        },
        {
            "name": "协议滥用 - WebSocket劫持",
            "rule_type": "protocol_abuse",
            "pattern": r"Origin\s*:\s*null",
            "action": "block",
            "severity": "medium",
            "description": "检测WebSocket Origin null劫持",
        },
        {
            "name": "协议滥用 - X-Forwarded-Host",
            "rule_type": "protocol_abuse",
            "pattern": r"X-Forwarded-Host\s*:\s*[^/\r\n]+@[^/\r\n]+",
            "action": "block",
            "severity": "medium",
            "description": "检测X-Forwarded-Host滥用",
        },
        {
            "name": "协议滥用 - 超长URL",
            "rule_type": "protocol_abuse",
            "pattern": r"^GET\s+/[^\s]{8192,}\s+HTTP",
            "action": "block",
            "severity": "medium",
            "description": "检测超长URL请求",
        },
        {
            "name": "协议滥用 - 分块传输异常",
            "rule_type": "protocol_abuse",
            "pattern": r"Transfer-Encoding\s*:\s*[Cc]hunked\s*,\s*[Tt]ransfer-Encoding",
            "action": "block",
            "severity": "critical",
            "description": "检测TE-TE请求走私",
        },
        {
            "name": "协议滥用 - HTTP/0.9",
            "rule_type": "protocol_abuse",
            "pattern": r"HTTP/0\.9",
            "action": "block",
            "severity": "medium",
            "description": "检测HTTP/0.9协议异常",
        },
        {
            "name": "协议滥用 - 空字节",
            "rule_type": "protocol_abuse",
            "pattern": r"%00",
            "action": "block",
            "severity": "medium",
            "description": "检测空字节注入",
        },
        {
            "name": "信息泄露 - 源码泄露.git",
            "rule_type": "information_disclosure",
            "pattern": r"/\.git/",
            "action": "block",
            "severity": "high",
            "description": "检测.git目录泄露",
        },
        {
            "name": "信息泄露 - 源码泄露.svn",
            "rule_type": "information_disclosure",
            "pattern": r"/\.svn/",
            "action": "block",
            "severity": "high",
            "description": "检测.svn目录泄露",
        },
        {
            "name": "信息泄露 - 备份文件",
            "rule_type": "information_disclosure",
            "pattern": r"\.(bak|backup|old|orig|save|swp|dist)(\s|$|\?)",
            "action": "block",
            "severity": "medium",
            "description": "检测备份文件访问",
        },
        {
            "name": "信息泄露 - 压缩包",
            "rule_type": "information_disclosure",
            "pattern": r"\.(zip|tar|gz|rar|7z)(\s|$|\?)",
            "action": "block",
            "severity": "medium",
            "description": "检测压缩包文件访问",
        },
        {
            "name": "信息泄露 - SQL文件",
            "rule_type": "information_disclosure",
            "pattern": r"\.(sql|mdb|db)(\s|$|\?)",
            "action": "block",
            "severity": "high",
            "description": "检测数据库文件访问",
        },
        {
            "name": "信息泄露 - 日志文件",
            "rule_type": "information_disclosure",
            "pattern": r"/\w+\.log(\s|$|\?)",
            "action": "block",
            "severity": "medium",
            "description": "检测日志文件访问",
        },
        {
            "name": "信息泄露 - 调试接口",
            "rule_type": "information_disclosure",
            "pattern": r"/(debug|trace|actuator|env|info|health)\b",
            "action": "block",
            "severity": "medium",
            "description": "检测调试/管理接口暴露",
        },
        {
            "name": "信息泄露 - phpinfo",
            "rule_type": "information_disclosure",
            "pattern": r"phpinfo\s*\(",
            "action": "block",
            "severity": "high",
            "description": "检测phpinfo信息泄露",
        },
        {
            "name": "信息泄露 - .env文件",
            "rule_type": "information_disclosure",
            "pattern": r"/\.env(\s|$|\?)",
            "action": "block",
            "severity": "high",
            "description": "检测.env环境文件泄露",
        },
        {
            "name": "信息泄露 - API文档",
            "rule_type": "information_disclosure",
            "pattern": r"/(swagger|api-docs|graphql|playground)\b",
            "action": "block",
            "severity": "low",
            "description": "检测API文档暴露",
        },
        {
            "name": "CSRF - 缺少Origin头POST",
            "rule_type": "csrf",
            "pattern": r"POST\s+/\S+\s+HTTP.*\n(?!.*Origin:)",
            "action": "log",
            "severity": "medium",
            "description": "检测POST请求缺少Origin头",
        },
        {
            "name": "CSRF - JSON Content-Type",
            "rule_type": "csrf",
            "pattern": r"POST\s+/\S+\s+HTTP.*Content-Type\s*:\s*application/json.*\n(?!.*Origin:)",
            "action": "log",
            "severity": "medium",
            "description": "检测JSON POST缺少Origin头",
        },
        {
            "name": "CSRF - 敏感操作无Token",
            "rule_type": "csrf",
            "pattern": r"POST\s+/\S*(transfer|delete|update|password|admin)\S*\s+HTTP(?!.*X-CSRF)",
            "action": "log",
            "severity": "high",
            "description": "检测敏感操作缺少CSRF Token",
        },
        {
            "name": "CSRF - 跨域POST",
            "rule_type": "csrf",
            "pattern": r"Origin\s*:\s*https?://[^/]+(?<!\blocalhost\b)(?<!127\.0\.0\.1).*Referer\s*:\s*https?://[^/]+(?<!\blocalhost\b)(?<!127\.0\.0\.1)",
            "action": "log",
            "severity": "medium",
            "description": "检测Origin与Referer不匹配",
        },
        {
            "name": "CSRF - 缺少Referer",
            "rule_type": "csrf",
            "pattern": r"(PUT|DELETE|PATCH)\s+/\S+\s+HTTP.*\n(?!.*Referer:)(?!.*Origin:)",
            "action": "log",
            "severity": "medium",
            "description": "检测状态变更请求缺少Referer和Origin",
        },

    ]

    def __init__(self):
        """初始化WAF引擎"""
        self._rules: Dict[int, WAFRule] = {}
        self._next_id = 1
        self._lock = threading.Lock()

        # WAF日志缓存
        self._logs: deque = deque(maxlen=10000)

        # 速率限制 {ip: [(timestamp,)]}
        self._rate_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._rate_limit = 60  # 每分钟最大请求数
        self._rate_window = 60  # 时间窗口（秒）

        # 统计信息
        self._stats = {
            "total_inspected": 0,
            "total_blocked": 0,
            "total_logged": 0,
            "by_type": defaultdict(int),
            "by_severity": defaultdict(int),
        }

        # 加载内置规则
        self._load_builtin_rules()
        logger.info("WAF引擎初始化完成，已加载{}条内置规则".format(len(self._rules)))

    def _load_builtin_rules(self):
        """加载内置规则集"""
        for rule_def in self.BUILTIN_RULES:
            rule = WAFRule(
                name=rule_def["name"],
                rule_type=rule_def["rule_type"],
                pattern=rule_def["pattern"],
                action=rule_def["action"],
                severity=rule_def["severity"],
                description=rule_def["description"],
                enabled=True,
                rule_id=self._next_id,
            )
            self._rules[self._next_id] = rule
            self._next_id += 1

    def inspect_request(self, method: str, url: str, headers: Dict,
                        body: str = "", client_ip: str = "") -> WAFDecision:
        """
        检查HTTP请求

        Args:
            method: HTTP方法
            url: 请求URL
            headers: 请求头字典
            body: 请求体
            client_ip: 客户端IP

        Returns:
            WAFDecision 决策结果
        """
        with self._lock:
            self._stats["total_inspected"] += 1

        # 组合检查内容
        check_text = "{} {} ".format(method, url)
        if body:
            check_text += body + " "
        # 检查User-Agent等头部
        user_agent = headers.get("User-Agent", "") or headers.get("user-agent", "")
        if user_agent:
            check_text += user_agent + " "
        referer = headers.get("Referer", "") or headers.get("referer", "")
        if referer:
            check_text += referer + " "
        origin = headers.get("Origin", "") or headers.get("origin", "")
        if origin:
            check_text += origin + " "

        # CSRF检测
        csrf_decision = self._check_csrf(method, headers, url)
        if csrf_decision and not csrf_decision.allowed:
            self._record_log(client_ip, method, url, csrf_decision)
            return csrf_decision

        # 速率限制检测
        rate_decision = self._check_rate_limit(client_ip)
        if rate_decision and not rate_decision.allowed:
            self._record_log(client_ip, method, url, rate_decision)
            return rate_decision

        # 规则匹配
        with self._lock:
            for rule in self._rules.values():
                if not rule.enabled:
                    continue
                if rule.rule_type == "csrf" or rule.rule_type == "rate_limit":
                    continue  # 已单独处理
                if rule.match(check_text):
                    rule.hit_count += 1
                    self._stats["total_blocked"] += 1
                    self._stats["by_type"][rule.rule_type] += 1
                    self._stats["by_severity"][rule.severity] += 1

                    decision = WAFDecision(
                        allowed=(rule.action == "allow"),
                        rule_id=rule.id,
                        reason="匹配规则: {} - {}".format(rule.name, rule.description),
                        action=rule.action,
                    )

                    if rule.action == "log":
                        self._stats["total_logged"] += 1

                    self._record_log(client_ip, method, url, decision, rule)
                    return decision

        return WAFDecision(allowed=True, reason="请求通过")

    def inspect_response(self, status_code: int, headers: Dict,
                         body: str = "") -> WAFDecision:
        """
        检查HTTP响应（数据泄露检测）

        Args:
            status_code: HTTP状态码
            headers: 响应头字典
            body: 响应体

        Returns:
            WAFDecision 决策结果
        """
        # 检查敏感数据泄露
        sensitive_patterns = [
            (r"password\s*[:=]\s*['\"][^'\"]+['\"]", "密码泄露"),
            (r"api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]", "API密钥泄露"),
            (r"secret[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]", "密钥泄露"),
            (r"private[_-]?key\s*[:=]\s*-----BEGIN", "私钥泄露"),
            (r"access[_-]?token\s*[:=]\s*['\"][^'\"]+['\"]", "访问令牌泄露"),
        ]
        # 检查敏感数据
        for pattern, desc in sensitive_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                self._stats["total_blocked"] += 1
                return WAFDecision(
                    allowed=False,
                    reason=f"响应数据泄露: {desc}",
                    action="block"
                )

        return WAFDecision(allowed=True, reason="响应检查通过")

    def _check_csrf(self, method: str, headers: Dict, url: str) -> Optional[WAFDecision]:
        """CSRF检测"""
        if method.upper() not in ("POST", "PUT", "DELETE", "PATCH"):
            return None

        origin = headers.get("Origin", "") or headers.get("origin", "")
        referer = headers.get("Referer", "") or headers.get("referer", "")

        if not origin and not referer:
            return WAFDecision(
                allowed=False,
                reason="CSRF: POST请求缺少Origin和Referer头",
                action="block"
            )

        return None

    def _check_rate_limit(self, client_ip: str) -> Optional[WAFDecision]:
        """速率限制检测"""
        if not client_ip:
            return None
        current_time = time.time()
        with self._lock:
            tracker = self._rate_tracker[client_ip]

            # 清理过期记录
            while tracker and current_time - tracker[0] > self._rate_window:
                tracker.popleft()

            if len(tracker) >= self._rate_limit:
                self._stats["total_blocked"] += 1
                return WAFDecision(
                    allowed=False,
                    reason=f"速率限制: IP {client_ip} 请求过于频繁",
                    action="block"
                )

            tracker.append(current_time)

        return None

    def _record_log(self, client_ip: str, method: str, url: str,
                    decision: WAFDecision, rule: Optional['WAFRule'] = None):
        """记录WAF日志"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "client_ip": client_ip,
            "method": method,
            "url": url,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "action": decision.action,
        }
        if rule:
            log_entry["rule_name"] = rule.name
            log_entry["rule_type"] = rule.rule_type
            log_entry["severity"] = rule.severity

        self._logs.append(log_entry)

    def add_rule(self, name: str, rule_type: str, pattern: str,
                 action: str = "block", severity: str = "high",
                 description: str = "", enabled: bool = True) -> WAFRule:
        """
        添加自定义WAF规则

        Args:
            name: 规则名称
            rule_type: 规则类型
            pattern: 正则表达式
            action: 动作 (block/allow/log)
            severity: 严重程度
            description: 描述
            enabled: 是否启用

        Returns:
            WAFRule 创建的规则
        """
        rule = WAFRule(
            name=name,
            rule_type=rule_type,
            pattern=pattern,
            action=action,
            severity=severity,
            description=description,
            enabled=enabled,
            rule_id=self._next_id,
        )
        with self._lock:
            self._rules[self._next_id] = rule
            self._next_id += 1
        return rule

    def remove_rule(self, rule_id: int) -> bool:
        """移除规则"""
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                return True
        return False

    def get_stats(self) -> Dict:
        """获取WAF统计信息"""
        with self._lock:
            total = len(self._rules)
            enabled = sum(1 for r in self._rules.values() if r.enabled)
            inspected = self._stats["total_inspected"]
            blocked = self._stats["total_blocked"]
            return {
                "total_inspected": inspected,
                "total_blocked": blocked,
                "total_logged": self._stats["total_logged"],
                "by_type": dict(self._stats["by_type"]),
                "by_severity": dict(self._stats["by_severity"]),
                "rules_count": total,
                "total_rules": total,
                "enabled_rules": enabled,
                "block_rate": round(blocked / inspected * 100, 1) if inspected > 0 else 0.0,
                "logs_count": len(self._logs),
            }

    def clear_stats(self):
        """清除统计信息"""
        with self._lock:
            self._stats = {
                "total_inspected": 0,
                "total_blocked": 0,
                "total_logged": 0,
                "by_type": defaultdict(int),
                "by_severity": defaultdict(int),
            }

    def get_rules(self) -> List[WAFRule]:
        """获取所有规则"""
        with self._lock:
            return list(self._rules.values())

    def get_rule(self, rule_id: int) -> Optional[WAFRule]:
        """获取指定规则"""
        with self._lock:
            return self._rules.get(rule_id)

    def enable_rule(self, rule_id: int) -> bool:
        """启用规则"""
        with self._lock:
            if rule_id in self._rules:
                self._rules[rule_id].enabled = True
                return True
        return False

    def disable_rule(self, rule_id: int) -> bool:
        """禁用规则"""
        with self._lock:
            if rule_id in self._rules:
                self._rules[rule_id].enabled = False
                return True
        return False

    def toggle_rule(self, rule_id: int, enabled: bool) -> bool:
        """切换规则启用/禁用状态"""
        with self._lock:
            if rule_id in self._rules:
                self._rules[rule_id].enabled = enabled
                return True
        return False

    def update_rule(self, rule_id: int, **kwargs) -> bool:
        """更新规则属性"""
        with self._lock:
            if rule_id not in self._rules:
                return False
            rule = self._rules[rule_id]
            for key, value in kwargs.items():
                if hasattr(rule, key) and key != "rule_id":
                    setattr(rule, key, value)
            return True


# 全局WAF引擎实例
_waf_engine = None
_waf_engine_lock = threading.Lock()


def get_waf_engine() -> WAFEngine:
    """获取全局WAF引擎实例"""
    global _waf_engine
    if _waf_engine is None:
        with _waf_engine_lock:
            if _waf_engine is None:
                _waf_engine = WAFEngine()
    return _waf_engine
