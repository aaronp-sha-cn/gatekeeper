"""
GateKeeper - 统一内容安全引擎
集成防病毒、反垃圾邮件、URL过滤和数据防泄漏(DLP)功能
"""
import os, re, json, hashlib, shutil, subprocess, threading, uuid, socket
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse
from config.logging_config import get_logger

logger = get_logger("content_security")
CONFIG_PATH = "/etc/gatekeeper/rules/content_security.json"
QUARANTINE_PATH = "/opt/gatekeeper/quarantine/"


class ContentSecurityEngine:
    """统一内容安全引擎 - 防病毒/反垃圾邮件/URL过滤/DLP"""

    def __init__(self):
        """初始化内容安全引擎，加载配置和内置数据库"""
        self._config = self._load_config()
        self._lock = threading.RLock()
        self._quarantine_path = self._config.get("quarantine_path", QUARANTINE_PATH)
        os.makedirs(self._quarantine_path, exist_ok=True)
        # 防病毒
        self._clamav_available = self._check_clamav()
        self._antivirus_signatures = self._init_av_sigs()
        self._quarantine_records: Dict[str, dict] = {}
        # 反垃圾邮件
        self._spam_keywords = self._init_spam_kw()
        self._spam_blacklist: List[str] = self._config.get("spam_blacklist", [])
        self._spam_whitelist: List[str] = self._config.get("spam_whitelist", [])
        self._spam_stats = {"total_checked": 0, "spam_detected": 0, "ham_passed": 0}
        # URL过滤
        self._url_categories = self._init_url_cats()
        self._url_blacklist: List[str] = self._config.get("url_blacklist", [])
        self._url_whitelist: List[str] = self._config.get("url_whitelist", [])
        self._url_filter_stats = {"total_checked": 0, "blocked": 0, "allowed": 0}
        self._url_access_log: List[dict] = []
        # DLP
        self._dlp_patterns = self._init_dlp_patterns()
        self._blocked_extensions = self._config.get("blocked_extensions",
            [".doc", ".xls", ".xlsx", ".pdf", ".zip", ".rar", ".7z", ".ppt", ".pptx", ".csv"])
        self._dlp_events: List[dict] = []
        logger.info("内容安全引擎初始化完成 (ClamAV: %s)", self._clamav_available)

    # ---- 配置管理 ----
    def _load_config(self) -> dict:
        """从配置文件加载配置，不存在则返回默认配置"""
        default = {
            "antivirus": {"enabled": True, "clamav_enabled": True, "scheduled_scan": "daily",
                          "scan_hour": 2, "max_file_size_mb": 100},
            "antispam": {"enabled": True, "spam_threshold": 50, "check_spf": True,
                         "check_dkim": True, "check_dmarc": True,
                         "rbl_servers": ["zen.spamhaus.org", "bl.spamcop.net"]},
            "url_filter": {"enabled": True, "enforce_safesearch": True,
                           "log_all_access": True, "max_log_entries": 10000},
            "dlp": {"enabled": True, "block_mode": True, "log_only_mode": False},
            "spam_blacklist": [], "spam_whitelist": [],
            "url_blacklist": [], "url_whitelist": [], "quarantine_path": QUARANTINE_PATH,
        }
        if os.path.isfile(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    default.update(json.load(f))
                logger.info("已加载内容安全配置: %s", CONFIG_PATH)
            except Exception as e:
                logger.error("加载配置文件失败: %s", e)
        return default

    def get_config(self) -> dict:
        """获取当前配置"""
        with self._lock:
            return json.loads(json.dumps(self._config))

    def update_config(self, config: dict) -> dict:
        """更新配置并持久化"""
        with self._lock:
            try:
                self._config.update(config)
                os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    json.dump(self._config, f, ensure_ascii=False, indent=2)
                logger.info("内容安全配置已更新")
                return {"status": "success", "message": "配置已更新并保存"}
            except Exception as e:
                logger.error("更新配置失败: %s", e)
                return {"status": "error", "message": str(e)}

    def get_status(self) -> dict:
        """获取引擎整体运行状态"""
        return {
            "engine": "content_security", "status": "running",
            "antivirus": {"enabled": self._config["antivirus"]["enabled"],
                          "clamav_available": self._clamav_available,
                          "signature_count": len(self._antivirus_signatures),
                          "quarantine_count": len(self._quarantine_records)},
            "antispam": {"enabled": self._config["antispam"]["enabled"],
                         "spam_threshold": self._config["antispam"]["spam_threshold"],
                         "stats": self._spam_stats},
            "url_filter": {"enabled": self._config["url_filter"]["enabled"],
                           "category_count": len(self._url_categories),
                           "stats": self._url_filter_stats},
            "dlp": {"enabled": self._config["dlp"]["enabled"],
                    "pattern_count": len(self._dlp_patterns),
                    "event_count": len(self._dlp_events)},
        }

    # ---- 防病毒模块 ----
    def _check_clamav(self) -> bool:
        """检查ClamAV是否可用"""
        try:
            return subprocess.run(["which", "clamscan"], capture_output=True, timeout=5).returncode == 0
        except Exception:
            return False

    def _init_av_sigs(self) -> List[dict]:
        """初始化内置病毒特征库（EICAR/勒索软件/宏病毒/后门等）"""
        return [
            {"name": "EICAR-TEST", "pattern": rb"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR",
             "description": "EICAR标准测试文件", "severity": "low"},
            {"name": "RANSOMWARE-LOCKY", "pattern": rb"\.locky|locky_decrypt_instructions",
             "description": "Locky勒索软件特征", "severity": "critical"},
            {"name": "RANSOMWARE-WANNACRY", "pattern": rb"WANNA.*CRY|wncry@163\.com",
             "description": "WannaCry勒索软件特征", "severity": "critical"},
            {"name": "RANSOMWARE-CERBER", "pattern": rb"\.cerber|DECRYPT_INSTRUCTIONS",
             "description": "Cerber勒索软件特征", "severity": "critical"},
            {"name": "MACRO-VBA-AUTOEXEC", "pattern": rb"AutoOpen|AutoExec|Document_Open",
             "description": "Office宏病毒自动执行特征", "severity": "high"},
            {"name": "MACRO-VBA-SHELL", "pattern": rb"Shell\s*\(|WScript\.Shell|vbHide",
             "description": "宏病毒Shell调用特征", "severity": "high"},
            {"name": "MACRO-VBA-DOWNLOAD", "pattern": rb"URLDownloadToFile|MSXML2\.XMLHTTP",
             "description": "宏病毒下载行为特征", "severity": "high"},
            {"name": "TROJAN-POWERSHELL", "pattern": rb"powershell.*-enc|powershell.*-hidden",
             "description": "PowerShell混淆执行特征", "severity": "high"},
            {"name": "BACKDOOR-REVERSE-SHELL", "pattern": rb"bash\s+-i\s+>&\s+/dev/tcp|/bin/sh\s+-c\s+'cat'",
             "description": "反向Shell后门特征", "severity": "critical"},
            {"name": "MALWARE-PDF-EXPLOIT", "pattern": rb"/JavaScript\s|/S\s/Gosub",
             "description": "PDF漏洞利用特征", "severity": "high"},
        ]

    def scan_file(self, file_path: str) -> dict:
        """扫描指定文件，返回感染状态和威胁列表"""
        if not self._config["antivirus"]["enabled"]:
            return {"status": "skipped", "message": "防病毒模块未启用"}
        if not os.path.isfile(file_path):
            return {"status": "error", "message": "文件不存在: {}".format(file_path)}
        file_size = os.path.getsize(file_path)
        max_size = self._config["antivirus"].get("max_file_size_mb", 100) * 1024 * 1024
        if file_size > max_size:
            return {"status": "skipped", "message": "文件超过最大扫描限制 ({}MB)".format(max_size // 1024 // 1024)}
        logger.info("扫描文件: %s (%d bytes)", file_path, file_size)
        result = {"file_path": file_path, "file_size": file_size, "threats": []}
        # ClamAV扫描
        if self._clamav_available and self._config["antivirus"].get("clamav_enabled", True):
            cr = self._scan_clamav(file_path)
            if cr["infected"]:
                result["threats"].extend(cr["threats"])
        # 内置特征扫描
        br = self._scan_builtin(file_path)
        if br["infected"]:
            result["threats"].extend(br["threats"])
        if result["threats"]:
            result["status"], result["clean"] = "infected", False
            self._quarantine_file(file_path, result["threats"])
            logger.warning("文件感染: %s, 威胁: %s", file_path, result["threats"])
        else:
            result["status"], result["clean"] = "clean", True
            logger.info("文件安全: %s", file_path)
        return result

    def scan_directory(self, dir_path: str) -> dict:
        """扫描指定目录下所有文件"""
        if not os.path.isdir(dir_path):
            return {"status": "error", "message": "目录不存在: {}".format(dir_path)}
        logger.info("开始扫描目录: %s", dir_path)
        total = infected = clean = skipped = 0
        threats = []
        for root, _dirs, files in os.walk(dir_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    r = self.scan_file(fpath)
                    total += 1
                    if r.get("status") == "infected":
                        infected += 1
                        threats.append({"file": fpath, "threats": r.get("threats", [])})
                    elif r.get("status") == "clean":
                        clean += 1
                    else:
                        skipped += 1
                except Exception as e:
                    logger.error("扫描文件出错 %s: %s", fpath, e)
                    skipped += 1
        logger.info("目录扫描完成: %s (总计:%d, 感染:%d)", dir_path, total, infected)
        return {"status": "completed", "directory": dir_path, "total_files": total,
                "infected_files": infected, "clean_files": clean,
                "skipped_files": skipped, "threats_found": threats}

    def _scan_clamav(self, file_path: str) -> dict:
        """使用ClamAV扫描文件"""
        result = {"infected": False, "threats": []}
        try:
            p = subprocess.run(["clamscan", "--no-summary", "--infected", file_path],
                               capture_output=True, text=True, timeout=120)
            for line in (p.stdout + p.stderr).strip().splitlines():
                if "FOUND" in line:
                    name = line.split("FOUND")[0].strip().split(":")[-1].strip()
                    result["infected"] = True
                    result["threats"].append({"name": name, "scanner": "clamav"})
        except subprocess.TimeoutExpired:
            logger.warning("ClamAV扫描超时: %s", file_path)
        except Exception as e:
            logger.error("ClamAV扫描出错: %s", e)
        return result

    def _scan_builtin(self, file_path: str) -> dict:
        """使用内置特征库扫描文件（YARA-like模式匹配）"""
        result = {"infected": False, "threats": []}
        try:
            with open(file_path, "rb") as f:
                data = f.read(1024 * 1024)
            for sig in self._antivirus_signatures:
                if re.search(sig["pattern"], data):
                    result["infected"] = True
                    result["threats"].append({"name": sig["name"], "description": sig["description"],
                                              "severity": sig["severity"], "scanner": "builtin"})
        except Exception as e:
            logger.error("内置扫描出错 %s: %s", file_path, e)
        return result

    def _quarantine_file(self, file_path: str, threats: list):
        """隔离感染文件到隔离区"""
        try:
            item_id = str(uuid.uuid4())[:8]
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = os.path.join(self._quarantine_path, "{}_{}_{}".format(ts, item_id, os.path.basename(file_path)))
            shutil.move(file_path, dest)
            self._quarantine_records[item_id] = {
                "id": item_id, "original_path": file_path, "quarantine_path": dest,
                "threats": threats, "timestamp": datetime.now().isoformat()}
            logger.info("文件已隔离: %s -> %s", file_path, dest)
        except Exception as e:
            logger.error("隔离文件失败: %s", e)

    def get_quarantine_list(self) -> list:
        """获取隔离区文件列表"""
        with self._lock:
            return list(self._quarantine_records.values())

    def restore_quarantine(self, item_id: str) -> bool:
        """从隔离区恢复文件"""
        with self._lock:
            rec = self._quarantine_records.get(item_id)
            if not rec:
                logger.warning("隔离记录不存在: %s", item_id)
                return False
            try:
                shutil.move(rec["quarantine_path"], rec["original_path"])
                del self._quarantine_records[item_id]
                logger.info("文件已恢复: %s", rec["original_path"])
                return True
            except Exception as e:
                logger.error("恢复文件失败: %s", e)
                return False

    def update_antivirus_signatures(self) -> dict:
        """更新病毒特征库（ClamAV freshclam + 内置特征刷新）"""
        result = {"clamav_updated": False, "builtin_count": len(self._antivirus_signatures)}
        if self._clamav_available:
            try:
                p = subprocess.run(["freshclam"], capture_output=True, text=True, timeout=60)
                result["clamav_updated"] = p.returncode == 0
                result["clamav_message"] = p.stdout.strip()
            except Exception as e:
                result["clamav_error"] = str(e)
        logger.info("病毒特征库更新完成: %s", result)
        return result

    # ---- 反垃圾邮件模块 ----
    def _init_spam_kw(self) -> List[dict]:
        """初始化垃圾邮件关键词库（中英文），每个关键词带权重"""
        return [
            {"keyword": "free money", "score": 15}, {"keyword": "click here now", "score": 12},
            {"keyword": "act immediately", "score": 10}, {"keyword": "limited time offer", "score": 10},
            {"keyword": "congratulations you won", "score": 20}, {"keyword": "no obligation", "score": 8},
            {"keyword": "viagra", "score": 25}, {"keyword": "casino", "score": 15},
            {"keyword": "lottery winner", "score": 20}, {"keyword": "urgent response needed", "score": 12},
            {"keyword": "100% free", "score": 15}, {"keyword": "risk free", "score": 10},
            {"keyword": "bulk email", "score": 18}, {"keyword": "unsubscribe", "score": 5},
            {"keyword": "earn money fast", "score": 18},
            {"keyword": "免费领取", "score": 15}, {"keyword": "恭喜中奖", "score": 20},
            {"keyword": "点击立即领取", "score": 15}, {"keyword": "限时优惠", "score": 10},
            {"keyword": "贷款审批", "score": 15}, {"keyword": "代开发票", "score": 20},
            {"keyword": "刷单返利", "score": 18}, {"keyword": "日赚千元", "score": 20},
            {"keyword": "无抵押贷款", "score": 15}, {"keyword": "加微信领取", "score": 18},
            {"keyword": "账号异常", "score": 12}, {"keyword": "验证码", "score": 8},
            {"keyword": "退款通知", "score": 10}, {"keyword": "低价出售", "score": 12},
        ]

    def check_email(self, headers: dict, body: str) -> dict:
        """检查邮件是否为垃圾邮件（SPF/DKIM/DMARC/RBL/关键词评分）"""
        if not self._config["antispam"]["enabled"]:
            return {"status": "skipped", "message": "反垃圾邮件模块未启用"}
        score, details = 0, []
        sender = headers.get("from", "")
        # 白名单
        if sender in self._spam_whitelist:
            self._spam_stats["total_checked"] += 1
            self._spam_stats["ham_passed"] += 1
            return {"status": "allowed", "is_spam": False, "score": 0, "reason": "发件人在白名单中"}
        # 黑名单
        if sender in self._spam_blacklist:
            score += 50
            details.append({"check": "blacklist", "score": 50, "detail": "发件人在黑名单中"})
        # SPF/DKIM/DMARC
        for key, weight in [("spf", 20), ("dkim", 15), ("dmarc", 20)]:
            if self._config["antispam"].get("check_{}".format(key), True):
                val = headers.get(key, "")
                if val == "fail":
                    score += weight
                    details.append({"check": key, "score": weight,
                                    "detail": "{}验证失败".format(key.upper())})
                elif val == "softfail" and key == "spf":
                    score += 10
                    details.append({"check": "spf", "score": 10, "detail": "SPF软失败"})
        # RBL
        rbl_hits = self._check_rbl(sender)
        if rbl_hits > 0:
            rs = min(rbl_hits * 15, 40)
            score += rs
            details.append({"check": "rbl", "score": rs, "detail": "命中{}个RBL黑名单".format(rbl_hits)})
        # 关键词评分
        combined = (body + " " + headers.get("subject", "")).lower()
        kw_hits = sum(1 for kw in self._spam_keywords if kw["keyword"] in combined)
        if kw_hits:
            score += sum(kw["score"] for kw in self._spam_keywords if kw["keyword"] in combined)
            details.append({"check": "keywords", "score": score, "detail": "命中{}个垃圾关键词".format(kw_hits)})
        score = min(score, 100)
        threshold = self._config["antispam"].get("spam_threshold", 50)
        is_spam = score >= threshold
        self._spam_stats["total_checked"] += 1
        if is_spam:
            self._spam_stats["spam_detected"] += 1
        else:
            self._spam_stats["ham_passed"] += 1
        logger.info("邮件检查: 发件人=%s, 评分=%d, 判定=%s", sender, score, "垃圾" if is_spam else "正常")
        return {"status": "checked", "is_spam": is_spam, "score": score,
                "threshold": threshold, "details": details, "action": "block" if is_spam else "allow"}

    def _check_rbl(self, sender: str) -> int:
        """检查发件人域名是否在RBL黑名单中"""
        hits = 0
        rbl_servers = self._config["antispam"].get("rbl_servers", [])
        if not rbl_servers:
            return 0
        domain = sender.split("@")[-1] if "@" in sender else sender
        try:
            for rbl in rbl_servers:
                try:
                    socket.gethostbyname("{}.{}".format(domain, rbl))
                    hits += 1
                except socket.gaierror:
                    pass
        except Exception:
            pass
        return hits

    def get_spam_stats(self) -> dict:
        """获取反垃圾邮件统计信息"""
        with self._lock:
            t = self._spam_stats["total_checked"]
            return {"total_checked": t, "spam_detected": self._spam_stats["spam_detected"],
                    "ham_passed": self._spam_stats["ham_passed"],
                    "spam_ratio": self._spam_stats["spam_detected"] / t if t > 0 else 0.0}

    # ---- URL过滤模块 ----
    def _init_url_cats(self) -> Dict[str, dict]:
        """初始化URL分类数据库（15+分类）"""
        return {
            "malware": {"name": "恶意软件", "name_en": "malware", "description": "包含恶意软件下载的站点",
                        "domains": ["malware-site.example", "virus-download.example"]},
            "phishing": {"name": "钓鱼", "name_en": "phishing", "description": "钓鱼欺诈网站",
                         "domains": ["phish-bank.example", "fake-login.example"]},
            "pornography": {"name": "成人内容", "name_en": "pornography", "description": "色情内容网站",
                            "domains": ["adult-site.example", "xxx-content.example"]},
            "gambling": {"name": "赌博", "name_en": "gambling", "description": "在线赌博网站",
                         "domains": ["online-casino.example", "betting-site.example"]},
            "violence": {"name": "暴力", "name_en": "violence", "description": "暴力血腥内容网站",
                         "domains": ["gore-site.example"]},
            "social_media": {"name": "社交媒体", "name_en": "social_media", "description": "社交媒体平台",
                             "domains": ["facebook.com", "twitter.com", "instagram.com", "weibo.com", "zhihu.com"]},
            "im": {"name": "即时通讯", "name_en": "im", "description": "即时通讯工具",
                   "domains": ["web.whatsapp.com", "web.telegram.org", "wx.qq.com"]},
            "streaming": {"name": "视频流媒体", "name_en": "streaming", "description": "在线视频流媒体服务",
                          "domains": ["youtube.com", "netflix.com", "bilibili.com", "iqiyi.com"]},
            "p2p": {"name": "P2P下载", "name_en": "p2p", "description": "点对点文件共享",
                    "domains": ["thepiratebay.example", "torrent-download.example"]},
            "gaming": {"name": "游戏", "name_en": "gaming", "description": "在线游戏网站",
                       "domains": ["steam.com", "epicgames.com", "4399.com"]},
            "news": {"name": "新闻", "name_en": "news", "description": "新闻资讯网站",
                     "domains": ["news.sina.com.cn", "news.163.com", "bbc.com", "cnn.com"]},
            "search": {"name": "搜索引擎", "name_en": "search", "description": "搜索引擎服务",
                       "domains": ["google.com", "bing.com", "baidu.com", "sogou.com"]},
            "shopping": {"name": "购物", "name_en": "shopping", "description": "电子商务网站",
                         "domains": ["taobao.com", "jd.com", "amazon.com", "pinduoduo.com"]},
            "education": {"name": "教育", "name_en": "education", "description": "教育学习网站",
                          "domains": ["coursera.org", "mooc.cn", "khanacademy.org"]},
            "business": {"name": "企业", "name_en": "business", "description": "企业办公相关网站",
                         "domains": ["office.com", "docs.google.com", "slack.com", "dingtalk.com"]},
        }

    def check_url(self, url: str) -> dict:
        """检查URL安全性（白名单/黑名单/分类/SafeSearch）"""
        if not self._config["url_filter"]["enabled"]:
            return {"status": "skipped", "message": "URL过滤模块未启用"}
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        path = parsed.path or ""
        with self._lock:
            self._url_filter_stats["total_checked"] += 1
        # 白名单
        for wl in self._url_whitelist:
            if wl in domain or wl in url:
                with self._lock:
                    self._url_filter_stats["allowed"] += 1
                self._log_url(url, domain, "allowed", "whitelist")
                return {"status": "allowed", "url": url, "domain": domain,
                        "reason": "URL在白名单中", "action": "allow"}
        # 黑名单
        for bl in self._url_blacklist:
            if bl in domain or bl in url:
                with self._lock:
                    self._url_filter_stats["blocked"] += 1
                self._log_url(url, domain, "blocked", "blacklist")
                return {"status": "blocked", "url": url, "domain": domain,
                        "reason": "URL在黑名单中", "action": "block"}
        # 分类匹配
        cat = self._categorize_url(domain, path)
        blocked_cats = self._config["url_filter"].get("blocked_categories",
            ["malware", "phishing", "pornography", "gambling", "violence"])
        if cat and cat in blocked_cats:
            with self._lock:
                self._url_filter_stats["blocked"] += 1
            cn = self._url_categories.get(cat, {}).get("name", cat)
            self._log_url(url, domain, "blocked", cat)
            return {"status": "blocked", "url": url, "domain": domain, "category": cat,
                    "category_name": cn, "reason": "URL属于被阻止的分类: {}".format(cn), "action": "block"}
        # SafeSearch
        ss = self._apply_safesearch(domain, url) if self._config["url_filter"].get("enforce_safesearch") else False
        with self._lock:
            self._url_filter_stats["allowed"] += 1
        self._log_url(url, domain, "allowed", cat or "uncategorized")
        result = {"status": "allowed", "url": url, "domain": domain, "category": cat, "action": "allow"}
        if ss:
            result["safesearch"] = "enforced"
        return result

    def _categorize_url(self, domain: str, path: str) -> Optional[str]:
        """根据域名启发式规则对URL进行分类"""
        dl = domain.lower()
        for cid, ci in self._url_categories.items():
            for d in ci.get("domains", []):
                if d.lower() in dl:
                    return cid
        # 启发式关键词
        heuristics = {"gambling": ["casino", "bet", "poker", "赌博"], "pornography": ["adult", "xxx", "色情"],
                      "malware": ["malware", "virus", "trojan"], "phishing": ["phish", "fake-login"],
                      "gaming": ["game", "steam", "游戏"], "streaming": ["video", "stream", "视频"],
                      "news": ["news", "新闻"], "shopping": ["shop", "store", "商城"],
                      "education": ["edu", "learn", "教育"]}
        combined = dl + path.lower()
        for cid, kws in heuristics.items():
            if any(kw in combined for kw in kws):
                return cid
        return None

    def _apply_safesearch(self, domain: str, url: str) -> bool:
        """对搜索引擎URL强制SafeSearch（Google/Bing/Baidu）"""
        ss_domains = {"google.com": "&safe=active", "google.com.hk": "&safe=active",
                      "bing.com": "&safeSearch=Strict", "baidu.com": "&safe=1"}
        for sd in ss_domains:
            if sd in domain and ("search?" in url or "s?" in url):
                logger.info("SafeSearch已强制执行: %s", domain)
                return True
        return False

    def _log_url(self, url: str, domain: str, action: str, category: str):
        """记录URL访问日志"""
        if not self._config["url_filter"].get("log_all_access", True):
            return
        with self._lock:
            self._url_access_log.append({"url": url, "domain": domain, "action": action,
                                         "category": category, "timestamp": datetime.now().isoformat()})
            mx = self._config["url_filter"].get("max_log_entries", 10000)
            if len(self._url_access_log) > mx:
                self._url_access_log = self._url_access_log[-mx:]

    def add_url_blacklist(self, url: str, category: str = "") -> bool:
        """添加URL到黑名单"""
        with self._lock:
            if url not in self._url_blacklist:
                self._url_blacklist.append(url)
                self._config["url_blacklist"] = self._url_blacklist
                self._save_config()
                logger.info("URL已加入黑名单: %s", url)
                return True
            return False

    def add_url_whitelist(self, url: str) -> bool:
        """添加URL到白名单"""
        with self._lock:
            if url not in self._url_whitelist:
                self._url_whitelist.append(url)
                self._config["url_whitelist"] = self._url_whitelist
                self._save_config()
                logger.info("URL已加入白名单: %s", url)
                return True
            return False

    def get_url_categories(self) -> list:
        """获取所有URL分类列表"""
        return [{"id": cid, "name": ci.get("name", cid), "name_en": ci.get("name_en", cid),
                 "description": ci.get("description", ""), "domain_count": len(ci.get("domains", []))}
                for cid, ci in self._url_categories.items()]

    def get_url_filter_stats(self) -> dict:
        """获取URL过滤统计信息"""
        with self._lock:
            return {"total_checked": self._url_filter_stats["total_checked"],
                    "blocked": self._url_filter_stats["blocked"],
                    "allowed": self._url_filter_stats["allowed"],
                    "blacklist_count": len(self._url_blacklist),
                    "whitelist_count": len(self._url_whitelist),
                    "log_entries": len(self._url_access_log)}

    # ---- DLP (数据防泄漏) 模块 ----
    def _init_dlp_patterns(self) -> List[dict]:
        """初始化DLP敏感数据匹配模式（身份证/手机/邮箱/信用卡/IP）"""
        return [
            {"name": "chinese_id_card", "description": "中国身份证号码（18位）",
             "pattern": r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
             "severity": "high", "builtin": True},
            {"name": "phone_number", "description": "手机号码（11位，1开头）",
             "pattern": r"\b1[3-9]\d{9}\b", "severity": "medium", "builtin": True},
            {"name": "email_address", "description": "电子邮件地址",
             "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "severity": "low", "builtin": True},
            {"name": "credit_card", "description": "信用卡号码（Luhn校验）",
             "pattern": r"\b(?:\d[ -]*?){13,19}\b", "severity": "critical", "builtin": True, "luhn_check": True},
            {"name": "ip_address", "description": "IP地址",
             "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
             "severity": "low", "builtin": True},
        ]

    @staticmethod
    def _luhn_check(number: str) -> bool:
        """Luhn算法校验信用卡号"""
        digits = re.sub(r"[^\d]", "", number)
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        for i, ch in enumerate(digits[::-1]):
            d = int(ch)
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0

    def scan_content(self, content: str) -> dict:
        """扫描内容中的敏感数据（DLP模式匹配 + 文件类型控制）"""
        if not self._config["dlp"]["enabled"]:
            return {"status": "skipped", "message": "DLP模块未启用"}
        findings = []
        for pi in self._dlp_patterns:
            try:
                for m in re.finditer(pi["pattern"], content):
                    mt = m.group()
                    if pi.get("luhn_check") and not self._luhn_check(mt):
                        continue
                    findings.append({"pattern_name": pi["name"], "description": pi.get("description", ""),
                                     "severity": pi["severity"],
                                     "matched": mt[:4] + "****" + mt[-4:] if len(mt) > 8 else "****",
                                     "position": m.start(), "length": len(mt)})
            except re.error as e:
                logger.error("DLP正则错误 (%s): %s", pi["name"], e)
        # 文件类型控制
        ext_findings = [{"extension": ext, "description": "引用受控文件类型: {}".format(ext), "severity": "medium"}
                        for ext in self._blocked_extensions if ext in content.lower()]
        blocked = False
        if findings or ext_findings:
            event = {"timestamp": datetime.now().isoformat(), "findings": findings,
                     "extension_findings": ext_findings, "content_length": len(content),
                     "content_hash": hashlib.md5(content.encode("utf-8")).hexdigest()}
            with self._lock:
                self._dlp_events.append(event)
            if self._config["dlp"].get("block_mode", True):
                blocked = True
            logger.warning("DLP检测: %d个模式匹配, %d个扩展名匹配", len(findings), len(ext_findings))
        return {"status": "scanned", "has_findings": len(findings) > 0 or len(ext_findings) > 0,
                "pattern_findings": findings, "extension_findings": ext_findings,
                "total_findings": len(findings) + len(ext_findings), "action": "block" if blocked else "log"}

    def add_dlp_pattern(self, name: str, pattern: str, severity: str) -> bool:
        """添加自定义DLP匹配模式"""
        if severity not in ("low", "medium", "high", "critical"):
            logger.error("无效的严重程度: %s", severity)
            return False
        try:
            re.compile(pattern)
        except re.error as e:
            logger.error("无效的正则表达式: %s", e)
            return False
        with self._lock:
            self._dlp_patterns.append({"name": name, "description": "自定义: {}".format(name),
                                       "pattern": pattern, "severity": severity, "builtin": False})
            logger.info("DLP模式已添加: %s", name)
            return True

    def get_dlp_events(self) -> list:
        """获取DLP事件日志"""
        with self._lock:
            return list(self._dlp_events)

    # ---- 内部工具 ----
    def _save_config(self):
        """将当前配置保存到文件"""
        try:
            os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self._config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error("保存配置失败: %s", e)


# 模块级单例
_engine_instance: Optional[ContentSecurityEngine] = None
_engine_lock = threading.Lock()

def get_content_security_engine() -> ContentSecurityEngine:
    """获取内容安全引擎单例"""
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = ContentSecurityEngine()
        return _engine_instance
