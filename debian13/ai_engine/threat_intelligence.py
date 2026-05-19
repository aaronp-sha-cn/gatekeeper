"""
GateKeeper - 威胁情报管理
收集、管理和分析威胁情报数据，支持多种情报源
"""

import threading
import time
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict

from config.settings import settings
from config.logging_config import get_logger
from core.database import db_manager
from core.models import ThreatIntel, ThreatLevel

logger = get_logger("threat_intelligence")


class ThreatIntelligenceManager:
    """
    威胁情报管理器
    管理威胁情报的收集、存储、查询和分析
    """

    def __init__(self):
        self._lock = threading.Lock()

        # 内存缓存（快速查询）
        self._ip_cache: Dict[str, Dict] = {}
        self._domain_cache: Dict[str, Dict] = {}
        self._hash_cache: Dict[str, Dict] = {}

        # 缓存过期时间（秒）
        self._cache_ttl = 300

        # 情报源配置
        self._sources = {
            "local_database": {"enabled": True, "priority": 1},
            "abuse_ch": {"enabled": True, "priority": 2, "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"},
            "alienvault_otx": {"enabled": False, "priority": 3, "url": "https://otx.alienvault.com/api/v1/"},
            "spamhaus_drop": {"enabled": True, "priority": 2, "url": "https://www.spamhaus.org/drop/drop.txt"},
            "misp": {"enabled": False, "priority": 1, "url": "", "api_key": "", "verify_ssl": True},
        }

        # MISP 增量同步时间戳
        self._misp_last_timestamp = 0
        self._misp_sync_stats = {
            "total_synced": 0,
            "last_sync": None,
            "last_event_id": 0,
            "errors": 0,
        }

        # 统计
        self._stats = {
            "total_indicators": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "last_update": None,
            "sources_updated": {},
        }

        logger.info("威胁情报管理器初始化完成")

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        检查IP地址是否在威胁情报库中

        Args:
            ip_address: 要查询的IP地址

        Returns:
            威胁情报查询结果
        """
        # 先查缓存
        cached = self._ip_cache.get(ip_address)
        if cached and (time.time() - cached.get("cached_at", 0)) < self._cache_ttl:
            self._stats["cache_hits"] += 1
            return cached

        self._stats["cache_misses"] += 1

        # 查询数据库
        result = self._query_database("ip", ip_address)

        # 更新缓存
        result["cached_at"] = time.time()
        self._ip_cache[ip_address] = result

        return result

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """检查域名是否在威胁情报库中"""
        cached = self._domain_cache.get(domain)
        if cached and (time.time() - cached.get("cached_at", 0)) < self._cache_ttl:
            self._stats["cache_hits"] += 1
            return cached

        self._stats["cache_misses"] += 1
        result = self._query_database("domain", domain)
        result["cached_at"] = time.time()
        self._domain_cache[domain] = result
        return result

    def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """检查文件哈希是否在威胁情报库中"""
        cached = self._hash_cache.get(file_hash)
        if cached and (time.time() - cached.get("cached_at", 0)) < self._cache_ttl:
            self._stats["cache_hits"] += 1
            return cached

        self._stats["cache_misses"] += 1
        result = self._query_database("hash", file_hash)
        result["cached_at"] = time.time()
        self._hash_cache[file_hash] = result
        return result

    def _query_database(
        self, indicator_type: str, indicator_value: str
    ) -> Dict[str, Any]:
        """
        从数据库查询威胁情报

        Args:
            indicator_type: 指标类型 (ip/domain/url/hash)
            indicator_value: 指标值

        Returns:
            查询结果
        """
        try:
            with db_manager.get_session() as session:
                intel = (
                    session.query(ThreatIntel)
                    .filter_by(
                        indicator_type=indicator_type,
                        indicator_value=indicator_value,
                        is_active=True,
                    )
                    .first()
                )

                if intel:
                    return {
                        "found": True,
                        "indicator_type": intel.indicator_type,
                        "indicator_value": intel.indicator_value,
                        "threat_type": intel.threat_type,
                        "threat_level": intel.threat_level.value,
                        "confidence": intel.confidence,
                        "source": intel.source,
                        "description": intel.description,
                        "first_seen": str(intel.first_seen) if intel.first_seen else None,
                        "last_seen": str(intel.last_seen) if intel.last_seen else None,
                    }
        except Exception as e:
            logger.error("查询威胁情报失败: {}".format(e))

        return {
            "found": False,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
        }

    def add_intel(
        self,
        indicator_type: str,
        indicator_value: str,
        threat_type: str,
        threat_level: str = "medium",
        confidence: float = 0.5,
        source: str = "manual",
        description: str = "",
    ) -> Dict[str, Any]:
        """
        添加威胁情报

        Args:
            indicator_type: 指标类型 (ip/domain/url/hash/email)
            indicator_value: 指标值
            threat_type: 威胁类型 (malware/phishing/c2/botnet/spam)
            threat_level: 威胁级别 (low/medium/high/critical)
            confidence: 置信度 (0.0-1.0)
            source: 情报来源
            description: 描述

        Returns:
            添加结果
        """
        try:
            # 检查是否已存在
            with db_manager.get_session() as session:
                existing = (
                    session.query(ThreatIntel)
                    .filter_by(
                        indicator_type=indicator_type,
                        indicator_value=indicator_value,
                    )
                    .first()
                )

                if existing:
                    # 更新现有记录
                    existing.threat_type = threat_type
                    existing.threat_level = ThreatLevel(threat_level)
                    existing.confidence = max(existing.confidence, confidence)
                    existing.last_seen = datetime.now()
                    existing.is_active = True
                    logger.info(
                        "更新威胁情报: {}={}".format(indicator_type, indicator_value)
                    )
                    return {"status": "updated", "id": existing.id}

                # 创建新记录
                intel = ThreatIntel(
                    indicator_type=indicator_type,
                    indicator_value=indicator_value,
                    threat_type=threat_type,
                    threat_level=ThreatLevel(threat_level),
                    confidence=confidence,
                    source=source,
                    description=description,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    is_active=True,
                )
                session.add(intel)
                session.flush()

                # 更新缓存
                if indicator_type == "ip":
                    self._ip_cache[indicator_value] = {
                        "found": True,
                        "indicator_type": indicator_type,
                        "indicator_value": indicator_value,
                        "threat_type": threat_type,
                        "threat_level": threat_level,
                        "confidence": confidence,
                        "source": source,
                        "cached_at": time.time(),
                    }

                logger.info(
                    "添加威胁情报: {}={}, level={}, type={}".format(
                        indicator_type, indicator_value, threat_level, threat_type
                    )
                )
                return {"status": "created", "id": intel.id}

        except Exception as e:
            logger.error("添加威胁情报失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def remove_intel(self, intel_id: int) -> Dict[str, Any]:
        """移除威胁情报（标记为非活跃）"""
        try:
            with db_manager.get_session() as session:
                intel = session.query(ThreatIntel).filter_by(id=intel_id).first()
                if intel:
                    intel.is_active = False
                    logger.info("移除威胁情报: id={}".format(intel_id))
                    return {"status": "ok", "id": intel_id}
                return {"status": "not_found", "id": intel_id}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def update_intelligence(self) -> Dict[str, Any]:
        """
        从配置的情报源更新威胁情报
        执行定期的情报同步

        Returns:
            更新结果
        """
        logger.info("开始更新威胁情报...")
        total_added = 0
        source_results = {}

        for source_name, source_config in self._sources.items():
            if not source_config.get("enabled", False):
                continue

            try:
                if source_name == "local_database":
                    continue  # 本地数据库不需要更新

                count = self._fetch_from_source(source_name, source_config)
                source_results[source_name] = {
                    "status": "ok",
                    "indicators_added": count,
                }
                total_added += count
                self._stats["sources_updated"][source_name] = datetime.now().isoformat()

            except Exception as e:
                logger.error("从 {} 更新情报失败: {}".format(source_name, e))
                source_results[source_name] = {
                    "status": "error",
                    "message": str(e),
                }

        # 更新统计
        self._stats["last_update"] = datetime.now().isoformat()
        try:
            with db_manager.get_session() as session:
                self._stats["total_indicators"] = (
                    session.query(ThreatIntel)
                    .filter_by(is_active=True)
                    .count()
                )
        except Exception:
            pass

        # 清理过期缓存
        self._cleanup_cache()

        result = {
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "total_added": total_added,
            "sources": source_results,
        }

        logger.info("威胁情报更新完成: 新增 {} 条".format(total_added))
        return result

    def _fetch_from_source(
        self, source_name: str, source_config: Dict
    ) -> int:
        """
        从指定情报源获取数据

        Args:
            source_name: 情报源名称
            source_config: 情报源配置

        Returns:
            新增指标数量
        """
        import urllib.request

        url = source_config.get("url", "")
        if not url:
            return 0

        count = 0
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "GateKeeper/1.0"},
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read().decode("utf-8", errors="replace")

                # 解析CSV格式的威胁情报
                if source_name == "abuse_ch":
                    count = self._parse_abuse_ch(data)
                elif source_name == "spamhaus_drop":
                    count = self._parse_spamhaus(data)

        except Exception as e:
            logger.warning("获取 {} 数据失败: {}".format(source_name, e))

        return count

    def _parse_abuse_ch(self, data: str) -> int:
        """解析 Abuse.ch 的IP黑名单"""
        count = 0
        for line in data.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(",")
            if len(parts) >= 1:
                ip = parts[0].strip()
                if ip and self._is_valid_ip(ip):
                    self.add_intel(
                        indicator_type="ip",
                        indicator_value=ip,
                        threat_type="malware",
                        threat_level="high",
                        confidence=0.7,
                        source="abuse_ch",
                        description="Feodo Tracker C2 server",
                    )
                    count += 1
        return count

    def _parse_spamhaus(self, data: str) -> int:
        """解析 Spamhaus DROP 列表"""
        count = 0
        for line in data.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            parts = line.split(";")
            if parts:
                ip_or_cidr = parts[0].strip()
                if "/" not in ip_or_cidr and self._is_valid_ip(ip_or_cidr):
                    self.add_intel(
                        indicator_type="ip",
                        indicator_value=ip_or_cidr,
                        threat_type="spam",
                        threat_level="high",
                        confidence=0.9,
                        source="spamhaus",
                        description="Spamhaus DROP list",
                    )
                    count += 1
        return count

    def _is_valid_ip(self, ip: str) -> bool:
        """验证IP地址格式"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _cleanup_cache(self):
        """清理过期的缓存条目"""
        now = time.time()
        expired = 0

        for cache in [self._ip_cache, self._domain_cache, self._hash_cache]:
            keys_to_remove = [
                k for k, v in cache.items()
                if now - v.get("cached_at", 0) > self._cache_ttl
            ]
            for key in keys_to_remove:
                del cache[key]
                expired += 1

        if expired > 0:
            logger.debug("清理过期缓存: {} 条".format(expired))

    def search(
        self,
        query: str,
        indicator_type: Optional[str] = None,
        threat_level: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        搜索威胁情报

        Args:
            query: 搜索关键词
            indicator_type: 指标类型过滤
            threat_level: 威胁级别过滤
            limit: 最大返回数量

        Returns:
            匹配的威胁情报列表
        """
        try:
            with db_manager.get_session() as session:
                q = session.query(ThreatIntel).filter_by(is_active=True)

                if indicator_type:
                    q = q.filter(ThreatIntel.indicator_type == indicator_type)
                if threat_level:
                    q = q.filter(ThreatIntel.threat_level == ThreatLevel(threat_level))
                if query:
                    q = q.filter(
                        ThreatIntel.indicator_value.contains(query) |
                        ThreatIntel.description.contains(query)
                    )

                results = q.order_by(ThreatIntel.created_at.desc()).limit(limit).all()

                return [
                    {
                        "id": intel.id,
                        "indicator_type": intel.indicator_type,
                        "indicator_value": intel.indicator_value,
                        "threat_type": intel.threat_type,
                        "threat_level": intel.threat_level.value,
                        "confidence": intel.confidence,
                        "source": intel.source,
                        "description": intel.description,
                        "first_seen": str(intel.first_seen) if intel.first_seen else None,
                        "last_seen": str(intel.last_seen) if intel.last_seen else None,
                    }
                    for intel in results
                ]
        except Exception as e:
            logger.error("搜索威胁情报失败: {}".format(e))
            return []

    def get_statistics(self) -> Dict[str, Any]:
        """获取威胁情报统计"""
        try:
            with db_manager.get_session() as session:
                total = session.query(ThreatIntel).filter_by(is_active=True).count()

                from sqlalchemy import func
                by_type = (
                    session.query(
                        ThreatIntel.indicator_type,
                        func.count(ThreatIntel.id),
                    )
                    .filter_by(is_active=True)
                    .group_by(ThreatIntel.indicator_type)
                    .all()
                )
                by_level = (
                    session.query(
                        ThreatIntel.threat_level,
                        func.count(ThreatIntel.id),
                    )
                    .filter_by(is_active=True)
                    .group_by(ThreatIntel.threat_level)
                    .all()
                )

                return {
                    **self._stats,
                    "total_indicators": total,
                    "by_type": {t: c for t, c in by_type},
                    "by_level": {l.value: c for l, c in by_level},
                    "cache_size": (
                        len(self._ip_cache)
                        + len(self._domain_cache)
                        + len(self._hash_cache)
                    ),
                }
        except Exception as e:
            logger.error("获取威胁情报统计失败: {}".format(e))
            return self._stats

    # --------------------------------------------------------
    # MISP 威胁情报集成
    # --------------------------------------------------------

    def configure_misp(self, url: str, api_key: str, verify_ssl: bool = True) -> Dict[str, Any]:
        """
        配置 MISP 情报源连接参数

        Args:
            url: MISP 实例 URL（如 https://misp.example.com）
            api_key: MISP API 密钥
            verify_ssl: 是否验证 SSL 证书

        Returns:
            配置结果
        """
        if not url or not api_key:
            return {"status": "error", "message": "URL 和 API Key 不能为空"}

        # 去除末尾斜杠
        url = url.rstrip("/")
        self._sources["misp"] = {
            "enabled": True,
            "priority": 1,
            "url": url,
            "api_key": api_key,
            "verify_ssl": verify_ssl,
        }
        logger.info("MISP 情报源已配置: %s", url)
        return {"status": "ok", "message": "MISP 情报源配置成功", "url": url}

    def _misp_request(self, path: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """
        发送 MISP API 请求

        Args:
            path: API 路径（如 /events）
            params: 查询参数

        Returns:
            API 响应的 JSON 字典，失败返回 None
        """
        misp_config = self._sources.get("misp", {})
        url = misp_config.get("url", "")
        api_key = misp_config.get("api_key", "")
        verify_ssl = misp_config.get("verify_ssl", True)

        if not url or not api_key:
            logger.warning("MISP 未配置，跳过请求")
            return None

        full_url = "{}{}".format(url, path)
        headers = {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "GateKeeper/1.0",
        }

        try:
            import requests
            resp = requests.get(
                full_url, headers=headers, params=params,
                timeout=30, verify=verify_ssl,
            )
            resp.raise_for_status()
            return resp.json()
        except ImportError:
            logger.error("requests 库未安装，无法请求 MISP API")
            return None
        except Exception as e:
            logger.error("MISP API 请求失败 %s: %s", full_url, e)
            self._misp_sync_stats["errors"] += 1
            return None

    def sync_misp_threats(self) -> Dict[str, Any]:
        """
        从 MISP 拉取威胁情报并导入数据库
        支持增量同步：仅拉取上次同步之后新增/修改的事件

        MISP API 响应格式:
        {"Event": [{"id": "1", "info": "malware", "timestamp": "1234567890",
          "Attribute": [{"type": "ip-dst", "value": "1.2.3.4"}]}]}

        Returns:
            同步结果统计
        """
        misp_config = self._sources.get("misp", {})
        if not misp_config.get("enabled", False):
            return {"status": "error", "message": "MISP 情报源未启用"}

        logger.info("开始从 MISP 同步威胁情报...")

        # 构建查询参数，支持增量同步
        params = {"limit": 100, "published": 1}
        if self._misp_last_timestamp > 0:
            params["timestamp"] = self._misp_last_timestamp

        data = self._misp_request("/events", params=params)
        if data is None:
            return {"status": "error", "message": "MISP API 请求失败"}

        events = data.get("Event", [])
        if not events:
            logger.info("MISP 无新事件")
            return {"status": "ok", "message": "无新事件", "synced": 0}

        synced = 0
        max_timestamp = self._misp_last_timestamp
        max_event_id = self._misp_sync_stats.get("last_event_id", 0)

        # MISP Attribute type 到 indicator_type 的映射
        type_mapping = {
            "ip-dst": "ip", "ip-src": "ip", "ip": "ip",
            "domain": "domain", "hostname": "domain",
            "md5": "hash", "sha1": "hash", "sha256": "hash",
            "sha224": "hash", "sha384": "hash", "sha512": "hash",
            "ssdeep": "hash", "imphash": "hash",
            "url": "url", "uri": "url",
            "filename": "hash", "email": "email",
            "email-src": "email", "email-dst": "email",
        }

        for event in events:
            event_id = int(event.get("id", 0))
            event_info = event.get("info", "")
            event_timestamp = int(event.get("timestamp", 0))
            attributes = event.get("Attribute", [])

            if event_timestamp > max_timestamp:
                max_timestamp = event_timestamp
            if event_id > max_event_id:
                max_event_id = event_id

            for attr in attributes:
                attr_type = attr.get("type", "")
                attr_value = attr.get("value", "")
                attr_category = attr.get("category", "")
                attr_comment = attr.get("comment", "")

                if not attr_value:
                    continue

                indicator_type = type_mapping.get(attr_type)
                if not indicator_type:
                    continue

                # 跳过包含多个值的复合属性（如 "1.2.3.4|5.6.7.8"）
                if "|" in attr_value and indicator_type == "ip":
                    attr_value = attr_value.split("|")[0]

                # 推断威胁类型
                threat_type = self._infer_misp_threat_type(attr_category, event_info)

                # 推断威胁级别（基于事件标签或分类）
                threat_level = self._infer_misp_threat_level(event, attr_category)

                description = "MISP Event #{}: {}".format(event_id, event_info)
                if attr_comment:
                    description += " | {}".format(attr_comment)

                result = self.add_intel(
                    indicator_type=indicator_type,
                    indicator_value=attr_value,
                    threat_type=threat_type,
                    threat_level=threat_level,
                    confidence=0.7,
                    source="misp",
                    description=description,
                )
                if result.get("status") in ("created", "updated"):
                    synced += 1

        # 更新增量同步时间戳
        self._misp_last_timestamp = max_timestamp
        self._misp_sync_stats["total_synced"] += synced
        self._misp_sync_stats["last_sync"] = datetime.now().isoformat()
        self._misp_sync_stats["last_event_id"] = max_event_id

        logger.info("MISP 同步完成，处理 %d 个事件，导入 %d 条情报", len(events), synced)
        return {
            "status": "ok",
            "events_processed": len(events),
            "indicators_synced": synced,
            "last_timestamp": max_timestamp,
            "last_event_id": max_event_id,
        }

    @staticmethod
    def _infer_misp_threat_type(category: str, event_info: str) -> str:
        """根据 MISP 属性分类和事件信息推断威胁类型"""
        cat_lower = category.lower()
        info_lower = event_info.lower()

        mapping = {
            "payload delivery": "malware",
            "artifacts dropped": "malware",
            "payload installation": "malware",
            "persistent mechanism": "malware",
            "network activity": "c2",
            "c2": "c2",
            "command and control": "c2",
            "external analysis": "malware",
            "attribution": "malware",
            "financial fraud": "phishing",
            "social engineering": "phishing",
            "phishing": "phishing",
            "intellectual property": "espionage",
            "other": "unknown",
        }

        for key, threat_type in mapping.items():
            if key in cat_lower:
                return threat_type

        # 根据事件信息关键词推断
        for keyword, threat_type in [
            ("malware", "malware"), ("phishing", "phishing"),
            ("c2", "c2"), ("botnet", "botnet"), ("spam", "spam"),
            ("exploit", "exploit"), ("ransomware", "malware"),
            ("trojan", "malware"), ("backdoor", "malware"),
            ("apt", "espionage"), ("spear", "phishing"),
        ]:
            if keyword in info_lower:
                return threat_type

        return "unknown"

    @staticmethod
    def _infer_misp_threat_level(event: Dict, category: str) -> str:
        """根据 MISP 事件标签和属性分类推断威胁级别"""
        tags = event.get("Tag", [])
        tag_names = []
        for tag in tags:
            if isinstance(tag, dict):
                tag_names.append(tag.get("name", "").lower())
            elif isinstance(tag, str):
                tag_names.append(tag.lower())

        tag_str = " ".join(tag_names)

        # 根据标签判断
        if any(kw in tag_str for kw in ("tlp:red", "critical", "high")):
            return "critical"
        if any(kw in tag_str for kw in ("tlp:amber", "medium")):
            return "high"

        # 根据分类判断
        cat_lower = category.lower()
        if any(kw in cat_lower for kw in ("payload delivery", "payload installation")):
            return "high"
        if any(kw in cat_lower for kw in ("network activity", "c2")):
            return "high"
        if any(kw in cat_lower for kw in ("attribution", "external analysis")):
            return "medium"

        return "medium"

    def get_misp_status(self) -> Dict[str, Any]:
        """
        获取 MISP 连接状态和同步统计

        Returns:
            MISP 状态信息字典
        """
        misp_config = self._sources.get("misp", {})
        url = misp_config.get("url", "")
        enabled = misp_config.get("enabled", False)
        has_api_key = bool(misp_config.get("api_key", ""))

        status = {
            "enabled": enabled,
            "configured": bool(url and has_api_key),
            "url": url,
            "has_api_key": has_api_key,
            "verify_ssl": misp_config.get("verify_ssl", True),
            "sync_stats": self._misp_sync_stats,
            "last_timestamp": self._misp_last_timestamp,
            "connected": False,
        }

        # 测试连接
        if enabled and url and has_api_key:
            try:
                result = self._misp_request("/servers/getVersion")
                if result and result.get("version"):
                    status["connected"] = True
                    status["misp_version"] = result.get("version")
                elif result is not None:
                    # 请求成功但无 version 字段，也认为连接正常
                    status["connected"] = True
            except Exception:
                status["connected"] = False

        return status
