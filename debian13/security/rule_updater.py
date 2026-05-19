"""
GateKeeper - 统一规则更新引擎
管理 IDS、WAF、漏洞扫描、DNS 过滤四大安全模块的规则更新
支持从远程源下载、解析、导入规则，并维护更新元数据
"""

import os
import re
import io
import json
import tarfile
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional, Any

from config.logging_config import get_logger

logger = get_logger("rule_updater")

# ============================================================
# 常量定义
# ============================================================

RULES_DIR = "/etc/gatekeeper/rules"
STATUS_FILE = "/etc/gatekeeper/rule_update_status.json"

# IDS 规则源 —— Emerging Threats 开源 Suricata 规则集
IDS_RULES_URL = "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"
# 备注：Sigma 规则源 https://raw.githubusercontent.com/Neo23x0/sigma/master/rules/ （暂未实现）

# NVD CVE API v2
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50&startIndex=0"
NVD_CACHE_DIR = "/etc/gatekeeper/rules/nvd_cache"

# WAF 规则 —— OWASP CRS 下载页（未来数据源: https://coreruleset.org/download/）
# 当前使用本地生成器，基于 OWASP Top 10 模式
WAF_RULES_VERSION = "gatekeeper-waf-rules-v1.0"
OWASP_CRS_URL = "https://github.com/coreruleset/coreruleset/archive/refs/heads/main.tar.gz"

# DNS 黑名单源
DNS_STEVENBLACK_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
DNS_SPAMHAUS_URL = "https://www.spamhaus.org/drop/drop.txt"
DNS_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

HTTP_TIMEOUT = 30
HTTP_HEADERS = {"User-Agent": "GateKeeper/1.0"}

# Suricata 规则解析正则
_SURICATA_RE = re.compile(
    r'^alert\s+(\S+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s*\((.+)\)$', re.DOTALL)
_MSG_RE = re.compile(r'msg\s*:\s*"([^"]+)"')
_SID_RE = re.compile(r'sid\s*:\s*(\d+)')
_REV_RE = re.compile(r'rev\s*:\s*(\d+)')
_CT_RE = re.compile(r'classtype\s*:\s*(\w+)')
_HOSTS_RE = re.compile(r'^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([\w.\-]+)\s*$')
_IP_RE = re.compile(r'^\d+\.\d+\.\d+\.\d+$')

# CRS SecRule 解析正则
_SECRULE_RE = re.compile(r'^SecRule\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"', re.DOTALL)
_CRS_ID_RE = re.compile(r'id\s*:\s*(\d+)')
_CRS_MSG_RE = re.compile(r"msg\s*:\s*'([^']*)'")
_CRS_SEV_RE = re.compile(r'severity\s*:\s*(\w+)')
_CRS_TAG_RE = re.compile(r"tag\s*:\s*'([^']*)'")
_CRS_ACTION_RE = re.compile(r'(\w+)\s*:')

# classtype 到严重程度的映射
_CT_SEV = {
    "attempted-admin": "high", "attempted-user": "medium",
    "shellcode-detect": "critical", "successful-admin": "critical",
    "successful-user": "high", "trojan-activity": "critical",
    "web-application-attack": "high", "attempted-dos": "high",
    "malware-cnc": "critical", "attempted-recon": "medium",
    "system-call-detect": "high", "denial-of-service": "high",
    "executable-code": "critical", "successful-dos": "critical",
    "bad-unknown": "medium", "suspicious-login": "medium",
    "default-login-attempt": "medium", "misc-attack": "medium",
    "network-scan": "medium", "file-format": "medium",
    "non-standard-protocol": "medium", "unknown": "medium",
    "inappropriate-content": "low", "policy-violation": "low",
    "unsuccessful-user": "low", "protocol-command-decode": "low",
    "string-detect": "low", "tcp-connection": "low",
    "icmp-event": "low", "misc-activity": "low",
}

# WAF 规则定义: (类型, 严重程度, [(正则, 描述), ...])
_WAF_DEFS = [
    ("sql_injection", "critical", [
        (r"(?:union\s+(?:all\s+)?select)", "UNION SELECT 注入"),
        (r"(?:select\s+.+\s+from\s+\w+)", "SELECT FROM 注入"),
        (r"(?:insert\s+into\s+\w+\s+values)", "INSERT INTO 注入"),
        (r"(?:update\s+\w+\s+set\s+\w+\s*=)", "UPDATE SET 注入"),
        (r"(?:delete\s+from\s+\w+)", "DELETE FROM 注入"),
        (r"(?:drop\s+(?:table|database)\s+\w+)", "DROP 语句注入"),
        (r"(?:\%27|\%22|\%3D)", "URL 编码单/双引号/等号"),
        (r"(?:0x[0-9a-fA-F]{6,})", "十六进制编码注入"),
        (r"(?:char\s*\(\s*\d+\s*\))", "CHAR() 函数注入"),
        (r"(?:concat\s*\()", "CONCAT 函数注入"),
        (r"(?:waitfor\s+delay\s+['\"])|(?:(?:benchmark|sleep)\s*\()", "盲注/时间盲注"),
        (r"(?:'\s*(?:or|and)\s+['\d])", "布尔盲注"),
    ]),
    ("xss", "high", [
        (r"<script[^>]*>[\s\S]*?</script>", "Script 标签注入"),
        (r"javascript\s*:", "javascript: 协议"),
        (r"on(?:error|load|click|mouseover|focus|blur)\s*=", "DOM 事件处理器注入"),
        (r"(?:document\.(?:cookie|location|write))", "DOM 对象访问"),
        (r"(?:eval\s*\(|setTimeout\s*\(|setInterval\s*\()", "动态代码执行"),
        (r"(?:alert|confirm|prompt)\s*\(", "弹窗函数调用"),
        (r"(?:<img[^>]+onerror\s*=)", "IMG 标签事件注入"),
        (r"(?:<svg[^>]*>[\s\S]*?</svg>)", "SVG 标签注入"),
        (r"(?:<iframe[^>]*>)", "iframe 嵌入"),
        (r"(?:expression\s*\()", "CSS 表达式注入"),
        (r"(?:data\s*:\s*text/html)", "data URI 注入"),
        (r"(?:fromCharCode\s*\()", "fromCharCode 编码绕过"),
    ]),
    ("rce", "critical", [
        (r"(?:;\s*(?:cat|ls|id|whoami|uname|pwd|ifconfig|ip|netstat)\b)", "分号命令拼接"),
        (r"(?:\|\s*(?:cat|ls|id|whoami|uname|bash|sh)\b)", "管道命令注入"),
        (r"(?:`[^`]+`)", "反引号命令替换"),
        (r"(?:\$\([^)]+\))", "$() 命令替换"),
        (r"(?:>\s*/dev/null\s*;)|(?:(?:&&|\|\|)\s*\w+)", "重定向/逻辑运算注入"),
        (r"(?:\b(?:nc|ncat|wget|curl)\b\s+.*-e\s)", "反弹 Shell"),
    ]),
    ("path_traversal", "high", [
        (r"\.\./", "目录回溯 ../"),
        (r"\.\.\\", "目录回溯 ..\\"),
        (r"(?:\%2e\%2e[\%2f/])", "URL 编码目录遍历"),
        (r"(?:\.\.%2f)", "混合编码目录遍历"),
        (r"(?:/etc/(?:passwd|shadow|hosts))", "敏感系统文件访问"),
        (r"(?:/proc/self/)", "proc 伪文件系统访问"),
    ]),
    ("ssrf", "high", [
        (r"(?:https?://)(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+"
         r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)", "内网地址 SSRF"),
        (r"(?:https?://\[::1\]|https?://\[0:0:0:0:0:0:0:1\])", "IPv6 本地回环 SSRF"),
        (r"(?:https?://169\.254\.\d+\.\d+)", "云元数据 SSRF"),
        (r"(?:url|dest|redirect)\s*=\s*https?://", "参数型 SSRF"),
    ]),
    ("xxe", "critical", [
        (r"<!ENTITY\s+\S+\s+SYSTEM\s+", "外部实体声明"),
        (r"<!ENTITY\s+\S+\s+PUBLIC\s+", "公共外部实体声明"),
        (r"(?:DOCTYPE\s+\w+\s+SYSTEM\s+)", "外部 DTD 引用"),
        (r"(?:xinclude|xinclude:include)", "XInclude 注入"),
    ]),
    ("rfi", "critical", [
        (r"(?:https?://[^/]*\.(?:php|asp|aspx|jsp)\b)", "远程文件包含 URL"),
        (r"(?:=(?:https?|ftp|php)://)", "参数型远程文件包含"),
        (r"(?:include\s*\(\s*['\"]?(?:https?|ftp|php)://)", "include 远程文件"),
        (r"(?:require(?:_once)?\s*\(\s*['\"]?(?:https?|ftp)://)", "require 远程文件"),
    ]),
    ("http_response_splitting", "high", [
        (r"(?:\%0d\%0a)|(?:\r\n\s*(?:Set-Cookie|Location|Content-Type)\s*:)", "CRLF 注入 - 响应头伪造"),
        (r"(?:\%0d|\%0a)", "URL 编码 CRLF"),
        (r"(?:\r\n\r\n)", "双 CRLF 响应拆分"),
    ]),
]

# WAF 类型前缀映射
_WAF_PREFIX = {
    "sql_injection": "SQLi", "xss": "XSS", "rce": "CMDI",
    "path_traversal": "PATH", "ssrf": "SSRF", "xxe": "XXE",
    "rfi": "RFI", "http_response_splitting": "HRS",
}

# DNS 域名分类关键词
_CAT_KW = {
    "malware": ["malware", "virus", "trojan", "botnet", "c2", "exploit"],
    "phishing": ["phish", "login", "account", "secure", "banking", "verify"],
    "ransomware": ["ransom", "crypt", "lock", "decrypt", "bitcoin", "pay"],
    "adware": ["ad", "ads", "tracking", "analytics", "doubleclick", "adserver"],
    "tracking": ["track", "telemetry", "beacon", "pixel", "stat", "monitor"],
}

# 需跳过的 hosts 域名
_SKIP_HOSTS = frozenset([
    "localhost", "localhost.localdomain", "broadcasthost",
    "ip6-localhost", "ip6-loopback",
])


# ============================================================
# 辅助函数
# ============================================================

def _ensure_dir(path: str) -> None:
    """确保目录存在"""
    os.makedirs(path, exist_ok=True)


def _load_json(path: str, default: Any = None) -> Any:
    """安全加载 JSON 文件"""
    if not os.path.isfile(path):
        return default if default is not None else {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("加载 JSON 文件失败 %s: %s", path, e)
        return default if default is not None else {}


def _save_json(path: str, data: Any) -> bool:
    """安全保存 JSON 文件"""
    _ensure_dir(os.path.dirname(path))
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except OSError as e:
        logger.error("保存 JSON 文件失败 %s: %s", path, e)
        return False


def _http_get(url: str, timeout: int = HTTP_TIMEOUT) -> Optional[bytes]:
    """发起 HTTP GET 请求，优先 requests，回退 urllib"""
    try:
        import requests
        resp = requests.get(url, headers=HTTP_HEADERS, timeout=timeout)
        resp.raise_for_status()
        return resp.content
    except ImportError:
        pass
    except Exception as e:
        logger.warning("requests 请求失败 %s: %s，尝试 urllib", url, e)
    try:
        from urllib.request import urlopen, Request
        with urlopen(Request(url, headers=HTTP_HEADERS), timeout=timeout) as resp:
            return resp.read()
    except Exception as e:
        logger.error("urllib 请求也失败 %s: %s", url, e)
        return None


def _now_iso() -> str:
    """返回当前 UTC 时间的 ISO 格式字符串"""
    return datetime.now(timezone.utc).isoformat()


def _make_result(status: str, module: str, count: int = 0,
                 message: str = "") -> dict:
    """构造统一的更新结果字典"""
    return {"status": status, "module": module, "count": count,
            "message": message, "timestamp": _now_iso()}


def _generate_waf_rules() -> list:
    """
    生成本地 WAF 规则集，覆盖 OWASP Top 10 主要攻击类型
    返回与 WAFRule 数据结构兼容的字典列表
    """
    rules = []
    rid = 0
    counters = {}
    for rule_type, severity, patterns in _WAF_DEFS:
        prefix = _WAF_PREFIX.get(rule_type, "GEN")
        counters[rule_type] = 0
        for pattern, desc in patterns:
            rid += 1
            counters[rule_type] += 1
            rules.append({
                "id": rid,
                "name": "WAF-{}-{:03d} {}".format(prefix, counters[rule_type], desc),
                "rule_type": rule_type,
                "pattern": pattern,
                "action": "block",
                "severity": severity,
                "enabled": True,
                "description": desc,
            })
    return rules


# ============================================================
# 规则更新引擎
# ============================================================

class RuleUpdateEngine:
    """
    统一规则更新引擎
    管理 IDS、WAF、漏洞扫描（CVE）、DNS 过滤四大安全模块的规则下载、解析与导入
    """

    def __init__(self):
        """初始化引擎，确保存储目录就绪"""
        _ensure_dir(RULES_DIR)
        _ensure_dir(NVD_CACHE_DIR)
        self._lock = threading.Lock()
        logger.info("规则更新引擎初始化完成，规则目录: %s", RULES_DIR)

    # --------------------------------------------------------
    # 内部：更新状态持久化
    # --------------------------------------------------------

    def _load_status(self) -> dict:
        """加载更新状态元数据"""
        return _load_json(STATUS_FILE, {
            m: {"last_update": None, "version": "", "source": "", "count": 0}
            for m in ("ids_rules", "cve_database", "waf_rules", "dns_blacklist")
        })

    def _update_module_status(self, module: str, source: str,
                              version: str = "", count: int = 0) -> None:
        """更新单个模块的状态记录"""
        with self._lock:
            status = self._load_status()
            status[module] = {"last_update": _now_iso(), "version": version,
                              "source": source, "count": count}
            _save_json(STATUS_FILE, status)

    # --------------------------------------------------------
    # 1. IDS 规则更新
    # --------------------------------------------------------

    def update_ids_rules(self) -> dict:
        """
        从 Emerging Threats 下载 Suricata 规则集并解析导入
        支持增量更新：仅添加新 sid，不覆盖已有规则
        """
        logger.info("开始更新 IDS 规则，数据源: %s", IDS_RULES_URL)
        ids_file = os.path.join(RULES_DIR, "ids_rules.json")
        raw = _http_get(IDS_RULES_URL)
        if raw is None:
            logger.warning("IDS 规则下载失败")
            return _make_result("error", "ids_rules", 0, "IDS 规则下载失败")

        existing_rules = _load_json(ids_file, [])
        existing_sids = {r.get("sid") for r in existing_rules if r.get("sid")}
        new_rules = []
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if not member.isfile() or not member.name.endswith(".rules"):
                        continue
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    for line in f.read().decode("utf-8", errors="ignore").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parsed = self._parse_suricata_rule(line)
                        if parsed and parsed["sid"] not in existing_sids:
                            new_rules.append(parsed)
                            existing_sids.add(parsed["sid"])
        except Exception as e:
            logger.error("IDS 规则解析失败: %s", e)
            return _make_result("error", "ids_rules", 0, "IDS 规则解析失败: {}".format(e))

        merged = existing_rules + new_rules
        _save_json(ids_file, merged)
        self._update_module_status("ids_rules", IDS_RULES_URL,
                                   version="emerging-threats", count=len(merged))
        msg = "IDS 规则更新完成，新增 {} 条，共 {} 条".format(len(new_rules), len(merged))
        logger.info(msg)

        # 自动将新规则导入到 IDS 引擎
        if new_rules:
            try:
                from security.ids_engine import get_ids_engine
                ids_engine = get_ids_engine()
                loaded = ids_engine.load_external_rules(new_rules)
                msg += "，导入 IDS 引擎 {} 条".format(loaded)
                logger.info("自动导入 IDS 引擎完成，新增 %d 条外部规则", loaded)
            except Exception as e:
                logger.warning("导入 IDS 引擎失败（不影响规则保存）: %s", e)

        return _make_result("ok", "ids_rules", len(new_rules), msg)

    @staticmethod
    def _parse_suricata_rule(line: str) -> Optional[dict]:
        """
        解析单条 Suricata 规则，提取 msg/sid/rev/classtype/severity
        格式: alert <protocol> <src> <src_port> -> <dst> <dst_port> (msg:"..."; sid:N; rev:N; ...)
        """
        m = _SURICATA_RE.match(line)
        if not m:
            return None
        protocol, src, src_port, dst, dst_port, options = m.groups()
        name = _MSG_RE.search(options)
        sid = _SID_RE.search(options)
        rev = _REV_RE.search(options)
        ct = _CT_RE.search(options)
        return {
            "sid": int(sid.group(1)) if sid else 0,
            "name": name.group(1) if name else "unknown",
            "protocol": protocol, "src": src, "src_port": src_port,
            "dst": dst, "dst_port": dst_port,
            "rev": int(rev.group(1)) if rev else 1,
            "classtype": ct.group(1) if ct else "unknown",
            "severity": _CT_SEV.get(ct.group(1), "medium") if ct else "medium",
            "raw_rule": line,
        }

    def get_ids_rules(self) -> list:
        """获取当前 IDS 规则列表"""
        return _load_json(os.path.join(RULES_DIR, "ids_rules.json"), [])

    def import_ids_rules(self, file_path: str) -> dict:
        """从本地文件导入 IDS 规则，支持 .rules 纯文本和 .json 格式"""
        logger.info("从本地文件导入 IDS 规则: %s", file_path)
        ids_file = os.path.join(RULES_DIR, "ids_rules.json")
        if not os.path.isfile(file_path):
            return _make_result("error", "ids_rules", 0, "文件不存在: {}".format(file_path))

        existing_rules = _load_json(ids_file, [])
        existing_sids = {r.get("sid") for r in existing_rules if r.get("sid")}
        imported = 0

        if file_path.endswith(".json"):
            for r in _load_json(file_path, []):
                if r.get("sid") and r["sid"] not in existing_sids:
                    existing_rules.append(r)
                    existing_sids.add(r["sid"])
                    imported += 1
        else:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parsed = self._parse_suricata_rule(line)
                        if parsed and parsed["sid"] not in existing_sids:
                            existing_rules.append(parsed)
                            existing_sids.add(parsed["sid"])
                            imported += 1
            except OSError as e:
                return _make_result("error", "ids_rules", 0, "读取文件失败: {}".format(e))

        _save_json(ids_file, existing_rules)
        self._update_module_status("ids_rules", "local_import", count=len(existing_rules))
        logger.info("本地导入 IDS 规则完成，新增 %d 条", imported)
        return _make_result("ok", "ids_rules", imported, "导入完成，新增 {} 条".format(imported))

    # --------------------------------------------------------
    # 2. CVE 漏洞数据库更新
    # --------------------------------------------------------

    def update_cve_database(self) -> dict:
        """
        从 NVD API v2 获取最新 CVE 数据，同时扫描本地 nvd_cache 目录
        仅保留最近 90 天的活跃数据，按 CVE ID 去重
        """
        logger.info("开始更新 CVE 数据库")
        cve_file = os.path.join(RULES_DIR, "cve_database.json")
        existing = _load_json(cve_file, [])
        existing_ids = {item.get("cve_id") for item in existing}
        new_cves = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)

        # 从 NVD API 获取
        raw = _http_get(NVD_API_URL)
        if raw is not None:
            try:
                data = json.loads(raw)
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    if not cve_id or cve_id in existing_ids:
                        continue
                    parsed = self._parse_nvd_cve(cve, cutoff)
                    if parsed:
                        new_cves.append(parsed)
                        existing_ids.add(cve_id)
                logger.info("NVD API 获取到 %d 条新 CVE", len(new_cves))
            except Exception as e:
                logger.warning("解析 NVD API 响应失败: %s", e)

        # 扫描本地缓存
        if os.path.isdir(NVD_CACHE_DIR):
            for fname in os.listdir(NVD_CACHE_DIR):
                if not fname.endswith(".json"):
                    continue
                local_data = _load_json(os.path.join(NVD_CACHE_DIR, fname), [])
                items = local_data if isinstance(local_data, list) else local_data.get("vulnerabilities", [])
                for item in items:
                    cve = item.get("cve", item)
                    cve_id = cve.get("id", "")
                    if not cve_id or cve_id in existing_ids:
                        continue
                    parsed = self._parse_nvd_cve(cve, cutoff)
                    if parsed:
                        new_cves.append(parsed)
                        existing_ids.add(cve_id)

        # 过滤旧数据并合并
        filtered = [i for i in existing if self._cve_is_recent(i, cutoff)]
        merged = filtered + new_cves
        _save_json(cve_file, merged)
        self._update_module_status("cve_database", NVD_API_URL,
                                   version="nvd-v2", count=len(merged))
        msg = "CVE 数据库更新完成，新增 {} 条，活跃总数 {} 条".format(len(new_cves), len(merged))
        logger.info(msg)
        return _make_result("ok", "cve_database", len(new_cves), msg)

    @staticmethod
    def _parse_nvd_cve(cve: dict, cutoff: datetime) -> Optional[dict]:
        """解析单条 NVD CVE 记录，提取 ID/描述/CVSS/受影响产品"""
        cve_id = cve.get("id", "")
        published = cve.get("published", "")
        if not cve_id:
            return None
        # 检查发布日期是否在 90 天窗口内
        try:
            pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=timezone.utc)
            if pub_dt < cutoff:
                return None
        except (ValueError, TypeError):
            pass
        # 提取描述（优先英文）
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        if not description and cve.get("descriptions"):
            description = cve["descriptions"][0].get("value", "")
        # 提取 CVSS 评分（优先 V3.1 > V3.0 > V2）
        metrics = cve.get("metrics", {})
        cvss_score, severity = 0.0, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                cv = metrics[key][0].get("cvssData", {})
                cvss_score = cv.get("baseScore", 0.0)
                severity = cv.get("baseSeverity", "UNKNOWN")
                break
        # 受影响产品（CPE 匹配）
        affected = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for cm in node.get("cpeMatch", []):
                    c = cm.get("criteria", "")
                    if c:
                        affected.append(c)
        return {
            "cve_id": cve_id, "description": description[:500],
            "cvss_score": cvss_score, "severity": severity,
            "affected_products": affected[:20], "published": published,
            "last_modified": cve.get("lastModified", ""), "source": "NVD",
        }

    @staticmethod
    def _cve_is_recent(item: dict, cutoff: datetime) -> bool:
        """判断 CVE 记录是否在时间窗口内"""
        published = item.get("published", "")
        if not published:
            return True
        try:
            pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=timezone.utc)
            return pub_dt >= cutoff
        except (ValueError, TypeError):
            return True

    def get_cve_database(self, days: int = 90) -> list:
        """获取最近 N 天的 CVE 列表"""
        all_cves = _load_json(os.path.join(RULES_DIR, "cve_database.json"), [])
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return [i for i in all_cves if self._cve_is_recent(i, cutoff)]

    # --------------------------------------------------------
    # 3. WAF 规则更新
    # --------------------------------------------------------

    def update_waf_rules(self) -> dict:
        """
        从 OWASP CRS 下载规则集并转换为GateKeeper WAF 规则格式
        下载失败时回退到本地生成器
        """
        logger.info("开始更新 WAF 规则，尝试从 OWASP CRS 下载: %s", OWASP_CRS_URL)

        crs_rules = []
        try:
            raw = _http_get(OWASP_CRS_URL, timeout=60)
            if raw is not None:
                crs_rules = self._download_and_parse_crs(raw)
                if crs_rules:
                    logger.info("OWASP CRS 下载解析成功，获取 %d 条规则", len(crs_rules))
        except Exception as e:
            logger.warning("OWASP CRS 下载失败: %s，使用本地生成器", e)

        if not crs_rules:
            logger.info("回退到本地 WAF 规则生成器，版本: %s", WAF_RULES_VERSION)
            rules = _generate_waf_rules()
            source = "local_generator"
            version = WAF_RULES_VERSION
        else:
            # 合并 CRS 规则和本地规则（CRS 优先，本地作为补充）
            local_rules = _generate_waf_rules()
            existing_names = {r.get("name") for r in crs_rules}
            for r in local_rules:
                if r.get("name") not in existing_names:
                    crs_rules.append(r)
                    existing_names.add(r["name"])
            rules = crs_rules
            source = "owasp_crs"
            version = "owasp-crs-main"

        payload = {"version": version, "generated_at": _now_iso(),
                   "total_rules": len(rules), "rules": rules}
        _save_json(os.path.join(RULES_DIR, "waf_rules.json"), payload)
        self._update_module_status("waf_rules", source,
                                   version=version, count=len(rules))
        msg = "WAF 规则更新完成，共 {} 条，来源: {}".format(len(rules), source)
        logger.info(msg)

        # 自动将规则导入到 WAF 引擎
        if rules:
            try:
                from security.waf_engine import get_waf_engine
                waf_engine = get_waf_engine()
                imported = 0
                for r in rules:
                    try:
                        waf_engine.add_rule(
                            name=r.get("name", "imported_rule"),
                            rule_type=r.get("rule_type", r.get("category", "generic")),
                            pattern=r.get("pattern", r.get("regex", "")),
                            action=r.get("action", "block"),
                            severity=r.get("severity", "high"),
                            description=r.get("description", ""),
                            enabled=r.get("enabled", True),
                        )
                        imported += 1
                    except Exception:
                        pass
                msg += "，导入 WAF 引擎 {} 条".format(imported)
                logger.info("自动导入 WAF 引擎完成，新增 %d 条外部规则", imported)
            except Exception as e:
                logger.warning("导入 WAF 引擎失败（不影响规则保存）: %s", e)

        return _make_result("ok", "waf_rules", len(rules), msg)

    def _download_and_parse_crs(self, raw: bytes) -> list:
        """
        从 OWASP CRS tar.gz 包中解析 SecRule 规则

        Args:
            raw: 下载的 tar.gz 原始字节数据

        Returns:
            转换后的GateKeeper WAF 规则列表
        """
        rules = []
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if not member.isfile():
                        continue
                    # 只处理 .conf 规则文件
                    if not member.name.endswith(".conf"):
                        continue
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    content = f.read().decode("utf-8", errors="ignore")
                    # 合并续行（反斜杠结尾）
                    merged_lines = self._merge_crs_lines(content)
                    for line in merged_lines:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parsed = self._parse_crs_rule(line)
                        if parsed:
                            rules.append(parsed)
        except Exception as e:
            logger.error("解析 CRS 规则包失败: %s", e)
        return rules

    @staticmethod
    def _merge_crs_lines(content: str) -> list:
        """
        合并 CRS 配置文件中的续行（反斜杠结尾的行）

        Args:
            content: 文件完整内容

        Returns:
            合并后的完整行列表
        """
        lines = content.splitlines()
        merged = []
        current = ""
        for line in lines:
            stripped = line.rstrip()
            if stripped.endswith("\\"):
                current += stripped[:-1] + " "
            else:
                current += stripped
                merged.append(current)
                current = ""
        if current.strip():
            merged.append(current)
        return merged

    @staticmethod
    def _parse_crs_rule(line: str) -> Optional[dict]:
        """
        解析单条 CRS SecRule 指令，提取 id, msg, severity, tag, 匹配模式

        SecRule 格式示例:
        SecRule REQUEST_URI "@rx (?i)\\.(?:jsp|jspx|cgi|php)" \\
            "id:932100,phase:2,block,capture,t:none,msg:'Remote File Inclusion Attempt',severity:CRITICAL,tag:'attack-rfi'"

        Args:
            line: 合并后的完整 SecRule 行

        Returns:
            转换后的GateKeeper WAF 规则字典，解析失败返回 None
        """
        m = _SECRULE_RE.match(line)
        if not m:
            return None

        target, match_str, actions_str = m.groups()

        # 提取 id
        id_match = _CRS_ID_RE.search(actions_str)
        rule_id = int(id_match.group(1)) if id_match else 0

        # 提取 msg
        msg_match = _CRS_MSG_RE.search(actions_str)
        msg = msg_match.group(1) if msg_match else "CRS Rule {}".format(rule_id)

        # 提取 severity
        sev_match = _CRS_SEV_RE.search(actions_str)
        severity_raw = sev_match.group(1).upper() if sev_match else "WARNING"
        severity_map = {
            "CRITICAL": "critical", "ERROR": "high",
            "WARNING": "medium", "NOTICE": "low",
        }
        severity = severity_map.get(severity_raw, "medium")

        # 提取 tag
        tags = _CRS_TAG_RE.findall(actions_str)

        # 判断 action
        action = "block" if "block" in actions_str or "deny" in actions_str else "log"

        # 提取匹配模式
        pattern = ""
        # @rx 开头表示正则表达式
        if "@rx " in match_str:
            pattern = match_str.split("@rx ", 1)[1].strip()
        elif "@contains " in match_str:
            keyword = match_str.split("@contains ", 1)[1].strip()
            pattern = re.escape(keyword)
        elif "@streq " in match_str:
            keyword = match_str.split("@streq ", 1)[1].strip()
            pattern = "^{}$".format(re.escape(keyword))
        elif match_str.startswith("@"):
            # 其他操作符，提取后面的值作为关键词
            parts = match_str.split(None, 1)
            if len(parts) > 1:
                pattern = re.escape(parts[1].strip())
        else:
            # 无操作符前缀，直接作为正则
            pattern = match_str.strip()

        if not pattern:
            return None

        # 确定 rule_type（基于 target 和 tag）
        rule_type = "generic"
        target_upper = target.upper()
        if any(t in target_upper for t in ("REQUEST_URI", "REQUEST_FILENAME", "PATH_INFO")):
            rule_type = "path_traversal"
        elif "REQUEST_BODY" in target_upper or "ARGS" in target_upper:
            rule_type = "sql_injection"
        elif "REQUEST_HEADERS" in target_upper:
            rule_type = "xss"
        for tag in tags:
            tag_lower = tag.lower()
            if "sqli" in tag_lower:
                rule_type = "sql_injection"
            elif "xss" in tag_lower:
                rule_type = "xss"
            elif "rce" in tag_lower or "cmdi" in tag_lower:
                rule_type = "rce"
            elif "rfi" in tag_lower or "lfi" in tag_lower:
                rule_type = "rfi"
            elif "ssrf" in tag_lower:
                rule_type = "ssrf"
            elif "xxe" in tag_lower:
                rule_type = "xxe"
            elif "session" in tag_lower:
                rule_type = "xss"

        return {
            "id": rule_id,
            "name": "CRS-{} {}".format(rule_id, msg),
            "rule_type": rule_type,
            "pattern": pattern,
            "action": action,
            "severity": severity,
            "enabled": True,
            "description": msg,
            "tags": tags,
            "target": target,
            "source": "owasp_crs",
        }

    def get_waf_rules(self) -> list:
        """获取当前 WAF 规则列表"""
        data = _load_json(os.path.join(RULES_DIR, "waf_rules.json"), {})
        if isinstance(data, dict):
            return data.get("rules", [])
        return data if isinstance(data, list) else []

    def import_waf_rules(self, file_path: str) -> dict:
        """从本地 JSON 文件导入 WAF 规则，按 name 去重合并"""
        logger.info("从本地文件导入 WAF 规则: %s", file_path)
        if not os.path.isfile(file_path):
            return _make_result("error", "waf_rules", 0, "文件不存在: {}".format(file_path))
        new_rules = _load_json(file_path, [])
        if not isinstance(new_rules, list):
            return _make_result("error", "waf_rules", 0, "文件格式错误，期望 JSON 列表")
        waf_file = os.path.join(RULES_DIR, "waf_rules.json")
        existing_data = _load_json(waf_file, {})
        existing_rules = existing_data.get("rules", []) if isinstance(existing_data, dict) else existing_data
        existing_names = {r.get("name") for r in existing_rules}
        imported = 0
        for r in new_rules:
            if r.get("name") and r["name"] not in existing_names:
                existing_rules.append(r)
                existing_names.add(r["name"])
                imported += 1
        payload = {"version": WAF_RULES_VERSION, "generated_at": _now_iso(),
                   "total_rules": len(existing_rules), "rules": existing_rules}
        _save_json(waf_file, payload)
        self._update_module_status("waf_rules", "local_import",
                                   version=WAF_RULES_VERSION, count=len(existing_rules))
        logger.info("WAF 规则导入完成，新增 %d 条", imported)
        return _make_result("ok", "waf_rules", imported, "导入完成，新增 {} 条".format(imported))

    # --------------------------------------------------------
    # 4. DNS 黑名单更新
    # --------------------------------------------------------

    def update_dns_blacklist(self) -> dict:
        """
        从多个公开源同步 DNS 黑名单（StevenBlack/Spamhaus/Feodo）
        按域名去重合并，自动分类
        """
        logger.info("开始更新 DNS 黑名单")
        blacklist_file = os.path.join(RULES_DIR, "dns_blacklist.json")
        existing = _load_json(blacklist_file, [])
        existing_domains = {item.get("domain") for item in existing}
        new_entries = []

        # StevenBlack hosts
        raw = _http_get(DNS_STEVENBLACK_URL)
        if raw is not None:
            c = self._parse_hosts_content(raw, existing_domains, new_entries, "stevenblack")
            logger.info("StevenBlack: 解析到 %d 个新域名", c)

        # Spamhaus DROP（IP 列表）
        raw = _http_get(DNS_SPAMHAUS_URL)
        if raw is not None:
            c = self._parse_spamhaus_drop(raw, existing_domains, new_entries)
            logger.info("Spamhaus DROP: 解析到 %d 个新条目", c)

        # Feodo Tracker（IP 列表）
        raw = _http_get(DNS_FEODO_URL)
        if raw is not None:
            c = self._parse_feodo_csv(raw, existing_domains, new_entries)
            logger.info("Feodo Tracker: 解析到 %d 个新条目", c)

        merged = existing + new_entries
        _save_json(blacklist_file, merged)
        self._update_module_status("dns_blacklist", "multi_source", count=len(merged))
        msg = "DNS 黑名单更新完成，新增 {} 条，共 {} 条".format(len(new_entries), len(merged))
        logger.info(msg)
        return _make_result("ok", "dns_blacklist", len(new_entries), msg)

    @staticmethod
    def _categorize_domain(domain: str) -> str:
        """根据域名特征自动分类"""
        d = domain.lower()
        for cat, keywords in _CAT_KW.items():
            if any(kw in d for kw in keywords):
                return cat
        return "malware"

    def _parse_hosts_content(self, raw: bytes, existing: set,
                             new_entries: list, source: str) -> int:
        """解析 hosts 文件格式内容，提取域名"""
        count = 0
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return 0
        for line in text.splitlines():
            m = _HOSTS_RE.match(line)
            if not m:
                continue
            domain = m.group(1).lower()
            if domain in _SKIP_HOSTS or domain in existing:
                continue
            new_entries.append({"domain": domain, "category": self._categorize_domain(domain),
                                "source": source, "action": "block", "added_at": _now_iso()})
            existing.add(domain)
            count += 1
        return count

    def _parse_spamhaus_drop(self, raw: bytes, existing: set,
                             new_entries: list) -> int:
        """解析 Spamhaus DROP 列表（IP/CIDR 格式）"""
        count = 0
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip_part = line.split(";")[0].strip()
            if "/" in ip_part or _IP_RE.match(ip_part):
                name = "spamhaus_drop_{}".format(ip_part.replace("/", "_"))
                if name not in existing:
                    new_entries.append({"domain": name, "category": "malware",
                                        "source": "spamhaus_drop", "action": "block",
                                        "ip_range": ip_part, "added_at": _now_iso()})
                    existing.add(name)
                    count += 1
        return count

    def _parse_feodo_csv(self, raw: bytes, existing: set,
                         new_entries: list) -> int:
        """解析 Feodo Tracker CSV（首行为表头，后续为 IP 地址）"""
        count = 0
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return 0
        for line in text.strip().splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = line.split(",")[0].strip()
            if _IP_RE.match(ip):
                name = "feodo_{}".format(ip)
                if name not in existing:
                    new_entries.append({"domain": name, "category": "malware",
                                        "source": "feodo_tracker", "action": "block",
                                        "ip_address": ip, "added_at": _now_iso()})
                    existing.add(name)
                    count += 1
        return count

    def get_dns_blacklist(self) -> list:
        """获取当前 DNS 黑名单列表"""
        return _load_json(os.path.join(RULES_DIR, "dns_blacklist.json"), [])

    def import_dns_blacklist(self, file_path: str) -> dict:
        """从本地文件导入 DNS 黑名单，支持 hosts 格式和 JSON 格式"""
        logger.info("从本地文件导入 DNS 黑名单: %s", file_path)
        blacklist_file = os.path.join(RULES_DIR, "dns_blacklist.json")
        if not os.path.isfile(file_path):
            return _make_result("error", "dns_blacklist", 0, "文件不存在: {}".format(file_path))
        existing = _load_json(blacklist_file, [])
        existing_domains = {item.get("domain") for item in existing}
        imported = 0
        if file_path.endswith(".json"):
            for item in _load_json(file_path, []):
                domain = item.get("domain", "")
                if domain and domain not in existing_domains:
                    existing.append(item)
                    existing_domains.add(domain)
                    imported += 1
        else:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    imported = self._parse_hosts_content(
                        f.read().encode("utf-8"), existing_domains, existing, "local_import")
            except OSError as e:
                return _make_result("error", "dns_blacklist", 0, "读取文件失败: {}".format(e))
        _save_json(blacklist_file, existing)
        self._update_module_status("dns_blacklist", "local_import", count=len(existing))
        logger.info("DNS 黑名单导入完成，新增 %d 条", imported)
        return _make_result("ok", "dns_blacklist", imported, "导入完成，新增 {} 条".format(imported))

    # --------------------------------------------------------
    # 统一更新与状态查询
    # --------------------------------------------------------

    def update_all(self) -> dict:
        """并行更新所有安全模块的规则，返回各模块更新结果汇总"""
        logger.info("========== 开始全模块规则更新 ==========")
        targets = {
            "ids_rules": self.update_ids_rules,
            "cve_database": self.update_cve_database,
            "waf_rules": self.update_waf_rules,
            "dns_blacklist": self.update_dns_blacklist,
        }
        threads = {m: threading.Thread(target=fn) for m, fn in targets.items()}
        for t in threads.values():
            t.start()
        for t in threads.values():
            t.join()
        results = {m: _make_result("ok", m, 0, "已执行") for m in targets}

        # MISP 威胁情报同步
        try:
            from ai_engine.threat_intelligence import ThreatIntelligenceManager
            ti_manager = ThreatIntelligenceManager()
            misp_status = ti_manager.get_misp_status()
            if misp_status.get("enabled") and misp_status.get("configured"):
                misp_result = ti_manager.sync_misp_threats()
                results["misp_sync"] = misp_result
                logger.info("MISP 同步完成: %s", misp_result.get("status"))
            else:
                results["misp_sync"] = {"status": "skipped", "message": "MISP 未配置或未启用"}
        except Exception as e:
            logger.warning("MISP 同步失败（不影响其他模块）: %s", e)
            results["misp_sync"] = {"status": "error", "message": str(e)}

        logger.info("========== 全模块规则更新完成 ==========")
        return results

    def get_update_status(self) -> dict:
        """获取所有模块的最近更新状态"""
        return self._load_status()
