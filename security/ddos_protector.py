"""
GateKeeper - DDoS防护引擎
实现多类型DDoS攻击检测、流量限速和自动拉黑功能
"""

import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from config.logging_config import get_logger

logger = get_logger("ddos_protector")


# ============================================================
# DDoS防护规则
# ============================================================

@dataclass
class DDoSRule:
    """DDoS防护规则"""
    id: int = 0
    name: str = ""
    rule_type: str = "rate_limit"  # syn_flood/udp_flood/icmp_flood/connection_limit/
                                   # rate_limit/bandwidth_limit/fragment_flood
    enabled: bool = True
    params: dict = field(default_factory=lambda: {
        "threshold": 100,
        "action": "block",
        "duration": 3600,
        "burst_size": 10,
    })
    hit_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "rule_type": self.rule_type,
            "enabled": self.enabled,
            "params": self.params,
            "hit_count": self.hit_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ============================================================
# IP流量计数器
# ============================================================

class IPCounter:
    """IP流量计数器"""

    def __init__(self, ip: str):
        self.ip = ip
        self.syn_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.conn_count = 0
        self.bytes_sent = 0
        self.fragment_count = 0
        self.first_seen: datetime = datetime.now()
        self.last_seen: datetime = datetime.now()
        # 滑动窗口计数 (用于速率计算)
        self._syn_timestamps: deque = deque(maxlen=10000)
        self._udp_timestamps: deque = deque(maxlen=10000)
        self._icmp_timestamps: deque = deque(maxlen=10000)
        self._fragment_timestamps: deque = deque(maxlen=10000)
        self._packet_timestamps: deque = deque(maxlen=10000)
        self._bytes_timestamps: deque = deque(maxlen=10000)  # (timestamp, bytes)

    def get_syn_rate(self, window: float = 1.0) -> int:
        """获取每秒SYN包速率"""
        now = time.time()
        cutoff = now - window
        while self._syn_timestamps and self._syn_timestamps[0] < cutoff:
            self._syn_timestamps.popleft()
        return len(self._syn_timestamps)

    def get_udp_rate(self, window: float = 1.0) -> int:
        """获取每秒UDP包速率"""
        now = time.time()
        cutoff = now - window
        while self._udp_timestamps and self._udp_timestamps[0] < cutoff:
            self._udp_timestamps.popleft()
        return len(self._udp_timestamps)

    def get_icmp_rate(self, window: float = 1.0) -> int:
        """获取每秒ICMP包速率"""
        now = time.time()
        cutoff = now - window
        while self._icmp_timestamps and self._icmp_timestamps[0] < cutoff:
            self._icmp_timestamps.popleft()
        return len(self._icmp_timestamps)

    def get_fragment_rate(self, window: float = 1.0) -> int:
        """获取每秒碎片包速率"""
        now = time.time()
        cutoff = now - window
        while self._fragment_timestamps and self._fragment_timestamps[0] < cutoff:
            self._fragment_timestamps.popleft()
        return len(self._fragment_timestamps)

    def get_packet_rate(self, window: float = 1.0) -> int:
        """获取每秒总包速率"""
        now = time.time()
        cutoff = now - window
        while self._packet_timestamps and self._packet_timestamps[0] < cutoff:
            self._packet_timestamps.popleft()
        return len(self._packet_timestamps)

    def get_bandwidth_rate(self, window: float = 1.0) -> int:
        """获取每秒带宽(bytes/s)"""
        now = time.time()
        cutoff = now - window
        while self._bytes_timestamps and self._bytes_timestamps[0][0] < cutoff:
            self._bytes_timestamps.popleft()
        return sum(b for _, b in self._bytes_timestamps)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "syn_count": self.syn_count,
            "udp_count": self.udp_count,
            "icmp_count": self.icmp_count,
            "conn_count": self.conn_count,
            "bytes_sent": self.bytes_sent,
            "fragment_count": self.fragment_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "syn_rate": self.get_syn_rate(),
            "udp_rate": self.get_udp_rate(),
            "icmp_rate": self.get_icmp_rate(),
            "fragment_rate": self.get_fragment_rate(),
            "packet_rate": self.get_packet_rate(),
            "bandwidth_rate": self.get_bandwidth_rate(),
        }


# ============================================================
# DDoS防护引擎
# ============================================================

class DDoSProtector:
    """DDoS防护引擎"""

    def __init__(self):
        """初始化防护引擎"""
        self._lock = threading.Lock()
        self._next_rule_id = 1

        # IP计数器 {ip: IPCounter}
        self._ip_counters: Dict[str, IPCounter] = {}

        # 防护规则
        self._rules: Dict[int, DDoSRule] = {}

        # 黑名单 {ip: {"reason": str, "added_at": datetime, "expires_at": datetime}}
        self._blacklist: Dict[str, dict] = {}

        # 白名单
        self._whitelist: set = set()

        # 统计信息
        self._stats = {
            "total_inspected": 0,
            "total_blocked": 0,
            "total_throttled": 0,
            "total_logged": 0,
            "by_type": defaultdict(int),
            "by_protocol": defaultdict(int),
        }

        # 初始化内置规则
        self._init_default_rules()

        # 启动清理线程
        self._running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

        logger.info("DDoS防护引擎初始化完成，已加载 {} 条内置规则".format(len(self._rules)))

    def _init_default_rules(self):
        """初始化内置防护规则"""
        default_rules = [
            {
                "name": "SYN Flood 防护",
                "rule_type": "syn_flood",
                "params": {
                    "threshold": 100,
                    "action": "block",
                    "duration": 3600,
                    "burst_size": 10,
                },
            },
            {
                "name": "UDP Flood 防护",
                "rule_type": "udp_flood",
                "params": {
                    "threshold": 200,
                    "action": "block",
                    "duration": 3600,
                    "burst_size": 20,
                },
            },
            {
                "name": "ICMP Flood 防护",
                "rule_type": "icmp_flood",
                "params": {
                    "threshold": 50,
                    "action": "block",
                    "duration": 3600,
                    "burst_size": 5,
                },
            },
            {
                "name": "连接数限制",
                "rule_type": "connection_limit",
                "params": {
                    "threshold": 200,
                    "action": "throttle",
                    "duration": 1800,
                    "burst_size": 0,
                },
            },
            {
                "name": "碎片包检测",
                "rule_type": "fragment_flood",
                "params": {
                    "threshold": 100,
                    "action": "block",
                    "duration": 3600,
                    "burst_size": 10,
                },
            },
        ]
        for rule_def in default_rules:
            rule = DDoSRule(
                id=self._next_rule_id,
                name=rule_def["name"],
                rule_type=rule_def["rule_type"],
                enabled=True,
                params=rule_def["params"],
            )
            self._rules[rule.id] = rule
            self._next_rule_id += 1

    def inspect_packet(self, src_ip: str, dst_ip: str, src_port: int,
                       dst_port: int, protocol: str, size: int,
                       is_fragment: bool = False) -> dict:
        """
        检查数据包，返回检测结果

        Args:
            src_ip: 源IP
            dst_ip: 目标IP
            src_port: 源端口
            dst_port: 目标端口
            protocol: 协议 (TCP/UDP/ICMP)
            size: 数据包大小(bytes)
            is_fragment: 是否为碎片包

        Returns:
            {"allowed": bool, "action": str, "reason": str, "rule": str}
        """
        with self._lock:
            self._stats["total_inspected"] += 1
            self._stats["by_protocol"][protocol.upper()] += 1

            # 白名单检查
            if self._is_whitelisted(src_ip):
                return {"allowed": True, "action": "allow", "reason": "白名单", "rule": ""}

            # 黑名单检查
            if self._is_blacklisted(src_ip):
                self._stats["total_blocked"] += 1
                return {"allowed": False, "action": "block", "reason": "黑名单", "rule": ""}

            # 更新计数器
            counter = self._update_counters(src_ip, protocol, size, is_fragment)

            # 遍历启用的规则进行检测
            for rule in self._rules.values():
                if not rule.enabled:
                    continue

                result = self._check_rule(rule, counter, protocol, size, is_fragment)
                if result:
                    rule.hit_count += 1
                    self._stats["by_type"][rule.rule_type] += 1

                    action = rule.params.get("action", "log")
                    if action == "block":
                        self._stats["total_blocked"] += 1
                        self._auto_blacklist(src_ip, rule.name)
                        return {
                            "allowed": False,
                            "action": "block",
                            "reason": result,
                            "rule": rule.name,
                        }
                    elif action == "throttle":
                        self._stats["total_throttled"] += 1
                        return {
                            "allowed": True,
                            "action": "throttle",
                            "reason": result,
                            "rule": rule.name,
                        }
                    else:
                        self._stats["total_logged"] += 1
                        return {
                            "allowed": True,
                            "action": "log",
                            "reason": result,
                            "rule": rule.name,
                        }

            return {"allowed": True, "action": "allow", "reason": "", "rule": ""}

    def _check_rule(self, rule: DDoSRule, counter: IPCounter,
                    protocol: str, size: int, is_fragment: bool) -> Optional[str]:
        """检查单条规则"""
        threshold = rule.params.get("threshold", 100)
        burst_size = rule.params.get("burst_size", 10)

        if rule.rule_type == "syn_flood":
            if protocol.upper() == "TCP":
                rate = counter.get_syn_rate()
                if rate > threshold:
                    return "SYN Flood检测: {} SYN/s (阈值: {})".format(rate, threshold)

        elif rule.rule_type == "udp_flood":
            if protocol.upper() == "UDP":
                rate = counter.get_udp_rate()
                if rate > threshold:
                    return "UDP Flood检测: {} UDP/s (阈值: {})".format(rate, threshold)

        elif rule.rule_type == "icmp_flood":
            if protocol.upper() == "ICMP":
                rate = counter.get_icmp_rate()
                if rate > threshold:
                    return "ICMP Flood检测: {} ICMP/s (阈值: {})".format(rate, threshold)

        elif rule.rule_type == "connection_limit":
            if counter.conn_count > threshold:
                return "连接数超限: {} 并发连接 (阈值: {})".format(
                    counter.conn_count, threshold)

        elif rule.rule_type == "rate_limit":
            rate = counter.get_packet_rate()
            if rate > threshold:
                return "速率超限: {} pkt/s (阈值: {})".format(rate, threshold)

        elif rule.rule_type == "bandwidth_limit":
            bw = counter.get_bandwidth_rate()
            if bw > threshold:
                return "带宽超限: {} B/s (阈值: {})".format(bw, threshold)

        elif rule.rule_type == "fragment_flood":
            if is_fragment:
                rate = counter.get_fragment_rate()
                if rate > threshold:
                    return "碎片包Flood: {} frag/s (阈值: {})".format(rate, threshold)

        return None

    def _update_counters(self, src_ip: str, protocol: str,
                         size: int, is_fragment: bool) -> IPCounter:
        """更新IP计数器"""
        now = time.time()

        if src_ip not in self._ip_counters:
            self._ip_counters[src_ip] = IPCounter(src_ip)

        counter = self._ip_counters[src_ip]
        counter.last_seen = datetime.now()
        counter.bytes_sent += size
        counter._packet_timestamps.append(now)
        counter._bytes_timestamps.append((now, size))

        proto_upper = protocol.upper()
        if proto_upper == "TCP":
            counter.syn_count += 1
            counter._syn_timestamps.append(now)
        elif proto_upper == "UDP":
            counter.udp_count += 1
            counter._udp_timestamps.append(now)
        elif proto_upper == "ICMP":
            counter.icmp_count += 1
            counter._icmp_timestamps.append(now)

        if is_fragment:
            counter.fragment_count += 1
            counter._fragment_timestamps.append(now)

        return counter

    def _is_blacklisted(self, ip: str) -> bool:
        """检查IP是否在黑名单"""
        if ip not in self._blacklist:
            return False
        entry = self._blacklist[ip]
        if datetime.now() > entry["expires_at"]:
            del self._blacklist[ip]
            logger.info("IP {} 黑名单已过期，自动移除".format(ip))
            return False
        return True

    def _is_whitelisted(self, ip: str) -> bool:
        """检查IP是否在白名单"""
        return ip in self._whitelist

    def _auto_blacklist(self, ip: str, reason: str):
        """自动拉黑IP"""
        if ip in self._whitelist or ip in self._blacklist:
            return
        # 查找匹配规则的duration
        duration = 3600
        for rule in self._rules.values():
            if rule.enabled and rule.name == reason:
                duration = rule.params.get("duration", 3600)
                break

        self._blacklist[ip] = {
            "reason": reason,
            "added_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(seconds=duration),
            "auto": True,
        }
        logger.warning("IP {} 已自动拉黑，原因: {}，有效期: {}s".format(ip, reason, duration))

    # ---- 规则管理 ----

    def add_rule(self, name: str, rule_type: str, params: dict = None,
                 enabled: bool = True) -> DDoSRule:
        """添加防护规则"""
        with self._lock:
            rule = DDoSRule(
                id=self._next_rule_id,
                name=name,
                rule_type=rule_type,
                enabled=enabled,
                params=params or {
                    "threshold": 100,
                    "action": "block",
                    "duration": 3600,
                    "burst_size": 10,
                },
            )
            self._rules[rule.id] = rule
            self._next_rule_id += 1
            logger.info("添加DDoS防护规则: {} (类型: {})".format(name, rule_type))
            return rule

    def remove_rule(self, rule_id: int) -> bool:
        """删除规则"""
        with self._lock:
            if rule_id in self._rules:
                rule = self._rules.pop(rule_id)
                logger.info("删除DDoS防护规则: {} (ID: {})".format(rule.name, rule_id))
                return True
            return False

    def toggle_rule(self, rule_id: int, enabled: bool) -> bool:
        """启用/禁用规则"""
        with self._lock:
            if rule_id in self._rules:
                self._rules[rule_id].enabled = enabled
                state = "启用" if enabled else "禁用"
                logger.info("{}DDoS防护规则 (ID: {})".format(state, rule_id))
                return True
            return False

    def get_rules(self) -> List[dict]:
        """获取所有规则"""
        with self._lock:
            return [rule.to_dict() for rule in self._rules.values()]

    # ---- 统计 ----

    def get_stats(self) -> dict:
        """获取统计信息"""
        with self._lock:
            return {
                "total_inspected": self._stats["total_inspected"],
                "total_blocked": self._stats["total_blocked"],
                "total_throttled": self._stats["total_throttled"],
                "total_logged": self._stats["total_logged"],
                "by_type": dict(self._stats["by_type"]),
                "by_protocol": dict(self._stats["by_protocol"]),
                "blacklist_count": len(self._blacklist),
                "whitelist_count": len(self._whitelist),
                "active_trackers": len(self._ip_counters),
                "rules_count": len(self._rules),
            }

    # ---- 黑名单管理 ----

    def get_blacklist(self) -> List[dict]:
        """获取黑名单列表"""
        with self._lock:
            # 清理过期条目
            now = datetime.now()
            expired = [ip for ip, entry in self._blacklist.items()
                       if now > entry["expires_at"]]
            for ip in expired:
                del self._blacklist[ip]

            return [
                {
                    "ip": ip,
                    "reason": entry["reason"],
                    "added_at": entry["added_at"].isoformat() if entry.get("added_at") else None,
                    "expires_at": entry["expires_at"].isoformat() if entry.get("expires_at") else None,
                    "auto": entry.get("auto", False),
                }
                for ip, entry in self._blacklist.items()
            ]

    def add_to_blacklist(self, ip: str, reason: str = "手动拉黑",
                         duration: int = 3600) -> bool:
        """手动添加IP到黑名单"""
        with self._lock:
            if ip in self._whitelist:
                return False
            self._blacklist[ip] = {
                "reason": reason,
                "added_at": datetime.now(),
                "expires_at": datetime.now() + timedelta(seconds=duration),
                "auto": False,
            }
            logger.info("IP {} 已手动拉黑，原因: {}，有效期: {}s".format(ip, reason, duration))
            return True

    def remove_blacklist(self, ip: str) -> bool:
        """从黑名单移除"""
        with self._lock:
            if ip in self._blacklist:
                del self._blacklist[ip]
                logger.info("IP {} 已从黑名单移除".format(ip))
                return True
            return False

    # ---- 白名单管理 ----

    def whitelist_ip(self, ip: str) -> bool:
        """加入白名单"""
        with self._lock:
            # 如果在黑名单中，先移除
            if ip in self._blacklist:
                del self._blacklist[ip]
            self._whitelist.add(ip)
            logger.info("IP {} 已加入白名单".format(ip))
            return True

    def remove_whitelist(self, ip: str) -> bool:
        """从白名单移除"""
        with self._lock:
            if ip in self._whitelist:
                self._whitelist.discard(ip)
                logger.info("IP {} 已从白名单移除".format(ip))
                return True
            return False

    def get_whitelist(self) -> List[str]:
        """获取白名单列表"""
        with self._lock:
            return list(self._whitelist)

    # ---- 攻击者排行 ----

    def get_top_attackers(self, limit: int = 20) -> List[dict]:
        """获取攻击者TOP榜"""
        with self._lock:
            attackers = []
            for ip, counter in self._ip_counters.items():
                total_packets = counter.syn_count + counter.udp_count + counter.icmp_count
                if total_packets > 0:
                    # 判断主要攻击类型
                    attack_type = "unknown"
                    max_count = 0
                    if counter.syn_count > max_count:
                        max_count = counter.syn_count
                        attack_type = "SYN Flood"
                    if counter.udp_count > max_count:
                        max_count = counter.udp_count
                        attack_type = "UDP Flood"
                    if counter.icmp_count > max_count:
                        max_count = counter.icmp_count
                        attack_type = "ICMP Flood"
                    if counter.fragment_count > max_count:
                        max_count = counter.fragment_count
                        attack_type = "Fragment Flood"

                    attackers.append({
                        "ip": ip,
                        "total_packets": total_packets,
                        "attack_type": attack_type,
                        "syn_count": counter.syn_count,
                        "udp_count": counter.udp_count,
                        "icmp_count": counter.icmp_count,
                        "fragment_count": counter.fragment_count,
                        "bytes_sent": counter.bytes_sent,
                        "conn_count": counter.conn_count,
                        "first_seen": counter.first_seen.isoformat() if counter.first_seen else None,
                        "last_seen": counter.last_seen.isoformat() if counter.last_seen else None,
                        "is_blacklisted": ip in self._blacklist,
                    })

            # 按总包数排序
            attackers.sort(key=lambda x: x["total_packets"], reverse=True)
            return attackers[:limit]

    # ---- 清理 ----

    def _cleanup_loop(self):
        """定期清理过期数据"""
        while self._running:
            try:
                self._cleanup_stale_counters()
                time.sleep(300)  # 每5分钟清理一次
            except Exception as e:
                logger.error("DDoS清理循环错误: {}".format(e))
                time.sleep(60)

    def _cleanup_stale_counters(self):
        """清理长时间不活跃的IP计数器"""
        with self._lock:
            cutoff = datetime.now() - timedelta(hours=1)
            stale_ips = [
                ip for ip, counter in self._ip_counters.items()
                if counter.last_seen < cutoff
            ]
            for ip in stale_ips:
                del self._ip_counters[ip]
            if stale_ips:
                logger.debug("清理了 {} 个不活跃的IP计数器".format(len(stale_ips)))

    def stop(self):
        """停止防护引擎"""
        self._running = False
        logger.info("DDoS防护引擎已停止")


# ============================================================
# 单例管理
# ============================================================

_ddos_protector: Optional[DDoSProtector] = None
_ddos_protector_lock = threading.Lock()


def get_ddos_protector() -> DDoSProtector:
    """获取DDoS防护引擎单例"""
    global _ddos_protector
    if _ddos_protector is None:
        with _ddos_protector_lock:
            if _ddos_protector is None:
                _ddos_protector = DDoSProtector()
    return _ddos_protector
