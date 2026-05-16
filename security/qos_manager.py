"""
GateKeeper - QoS流量整形管理器
实现基于tc(Linux Traffic Control)的流量整形、优先级调度和带宽限制功能
"""

import time
import threading
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from config.logging_config import get_logger

logger = get_logger("qos_manager")


# ============================================================
# QoS规则
# ============================================================

@dataclass
class QoSRule:
    """QoS规则"""
    id: int = 0
    name: str = ""
    interface: str = "eth0"
    direction: str = "egress"          # ingress / egress
    match_type: str = "ip"             # ip / port / protocol / mac / app
    match_value: str = ""              # 匹配值
    priority: int = 50                 # 0-100, 数字越小优先级越高
    bandwidth_limit: float = 0.0       # Mbps, 0表示不限速
    burst_limit: float = 0.0           # Mbps, 突发限制
    latency_ms: float = 0.0            # 延迟限制(ms)
    action: str = "shape"              # shape / prioritize / block
    enabled: bool = True
    hit_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "interface": self.interface,
            "direction": self.direction,
            "match_type": self.match_type,
            "match_value": self.match_value,
            "priority": self.priority,
            "bandwidth_limit": self.bandwidth_limit,
            "burst_limit": self.burst_limit,
            "latency_ms": self.latency_ms,
            "action": self.action,
            "enabled": self.enabled,
            "hit_count": self.hit_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ============================================================
# QoS统计
# ============================================================

@dataclass
class QoSStats:
    """QoS统计"""
    interface: str = ""
    direction: str = "egress"
    current_bandwidth_mbps: float = 0.0
    total_bytes: int = 0
    total_packets: int = 0
    shaped_bytes: int = 0
    dropped_bytes: int = 0

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "direction": self.direction,
            "current_bandwidth_mbps": round(self.current_bandwidth_mbps, 3),
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "shaped_bytes": self.shaped_bytes,
            "dropped_bytes": self.dropped_bytes,
        }


# ============================================================
# 预设策略定义
# ============================================================

PRESET_POLICIES = {
    "office": {
        "name": "办公网络策略",
        "description": "VoIP最高优先级，视频会议次之，普通浏览第三，下载最低",
        "rules": [
            {
                "name": "VoIP语音优先",
                "match_type": "port",
                "match_value": "5060,5061,10000-20000",
                "priority": 5,
                "bandwidth_limit": 10,
                "burst_limit": 15,
                "action": "prioritize",
            },
            {
                "name": "视频会议优先",
                "match_type": "port",
                "match_value": "80,443,3478,3479",
                "priority": 10,
                "bandwidth_limit": 50,
                "burst_limit": 80,
                "action": "prioritize",
            },
            {
                "name": "HTTP/HTTPS浏览",
                "match_type": "port",
                "match_value": "80,443",
                "priority": 30,
                "bandwidth_limit": 100,
                "burst_limit": 150,
                "action": "shape",
            },
            {
                "name": "邮件服务",
                "match_type": "port",
                "match_value": "25,110,143,465,587,993,995",
                "priority": 40,
                "bandwidth_limit": 20,
                "burst_limit": 30,
                "action": "shape",
            },
            {
                "name": "下载限速",
                "match_type": "port",
                "match_value": "21,22,873,6881-6999",
                "priority": 80,
                "bandwidth_limit": 30,
                "burst_limit": 50,
                "action": "shape",
            },
        ],
    },
    "gaming": {
        "name": "游戏加速策略",
        "description": "游戏流量最高优先级，确保低延迟",
        "rules": [
            {
                "name": "游戏流量最高优先",
                "match_type": "port",
                "match_value": "80,443,27015-27030,7777-7780",
                "priority": 1,
                "bandwidth_limit": 50,
                "burst_limit": 80,
                "latency_ms": 5,
                "action": "prioritize",
            },
            {
                "name": "语音聊天",
                "match_type": "port",
                "match_value": "5060,5061,10000-20000",
                "priority": 5,
                "bandwidth_limit": 10,
                "burst_limit": 15,
                "action": "prioritize",
            },
            {
                "name": "系统更新限速",
                "match_type": "port",
                "match_value": "80,443",
                "priority": 60,
                "bandwidth_limit": 20,
                "burst_limit": 30,
                "action": "shape",
            },
            {
                "name": "下载限速",
                "match_type": "port",
                "match_value": "21,22,873,6881-6999",
                "priority": 90,
                "bandwidth_limit": 10,
                "burst_limit": 20,
                "action": "shape",
            },
        ],
    },
    "balanced": {
        "name": "均衡策略",
        "description": "各类流量均衡分配带宽",
        "rules": [
            {
                "name": "交互式流量",
                "match_type": "protocol",
                "match_value": "tcp",
                "priority": 20,
                "bandwidth_limit": 200,
                "burst_limit": 300,
                "action": "shape",
            },
            {
                "name": "UDP流量",
                "match_type": "protocol",
                "match_value": "udp",
                "priority": 40,
                "bandwidth_limit": 100,
                "burst_limit": 150,
                "action": "shape",
            },
            {
                "name": "ICMP流量",
                "match_type": "protocol",
                "match_value": "icmp",
                "priority": 70,
                "bandwidth_limit": 10,
                "burst_limit": 20,
                "action": "shape",
            },
        ],
    },
    "strict": {
        "name": "严格限速策略",
        "description": "严格限制所有流量，适合带宽有限的场景",
        "rules": [
            {
                "name": "全局入站限速",
                "direction": "ingress",
                "match_type": "ip",
                "match_value": "0.0.0.0/0",
                "priority": 10,
                "bandwidth_limit": 50,
                "burst_limit": 70,
                "action": "shape",
            },
            {
                "name": "全局出站限速",
                "direction": "egress",
                "match_type": "ip",
                "match_value": "0.0.0.0/0",
                "priority": 10,
                "bandwidth_limit": 50,
                "burst_limit": 70,
                "action": "shape",
            },
            {
                "name": "P2P阻断",
                "match_type": "port",
                "match_value": "6881-6999",
                "priority": 1,
                "action": "block",
            },
        ],
    },
}


# ============================================================
# QoS管理器
# ============================================================

class QoSManager:
    """QoS流量整形管理器"""

    def __init__(self):
        """初始化QoS管理器"""
        self._lock = threading.Lock()
        self._next_rule_id = 1

        # QoS规则 {id: QoSRule}
        self._rules: Dict[int, QoSRule] = {}

        # 接口统计缓存 {interface: QoSStats}
        self._stats_cache: Dict[str, QoSStats] = {}

        # 上次统计采集时间
        self._last_stats_time: Dict[str, float] = {}

        # tc命令执行历史（用于审计）
        self._tc_history: List[dict] = []

        logger.info("QoS流量整形管理器初始化完成")

    # ---- 规则管理 ----

    def add_rule(self, rule: QoSRule) -> QoSRule:
        """
        添加QoS规则

        Args:
            rule: QoSRule实例

        Returns:
            添加后的规则（含ID）
        """
        with self._lock:
            rule.id = self._next_rule_id
            rule.created_at = datetime.now()
            self._rules[rule.id] = rule
            self._next_rule_id += 1
            logger.info(
                "添加QoS规则: {} (接口: {}, 方向: {}, 匹配: {}:{}, 优先级: {}, 限制: {}Mbps, 动作: {})".format(
                    rule.name, rule.interface, rule.direction,
                    rule.match_type, rule.match_value, rule.priority,
                    rule.bandwidth_limit, rule.action,
                )
            )
            return rule

    def remove_rule(self, rule_id: int) -> bool:
        """
        删除QoS规则

        Args:
            rule_id: 规则ID

        Returns:
            是否删除成功
        """
        with self._lock:
            if rule_id in self._rules:
                rule = self._rules.pop(rule_id)
                logger.info("删除QoS规则: {} (ID: {})".format(rule.name, rule_id))
                return True
            return False

    def toggle_rule(self, rule_id: int, enabled: bool) -> bool:
        """
        启用/禁用规则

        Args:
            rule_id: 规则ID
            enabled: 是否启用

        Returns:
            是否操作成功
        """
        with self._lock:
            if rule_id in self._rules:
                self._rules[rule_id].enabled = enabled
                state = "启用" if enabled else "禁用"
                logger.info("{}QoS规则 (ID: {})".format(state, rule_id))
                return True
            return False

    def get_rules(self) -> List[dict]:
        """获取所有规则列表"""
        with self._lock:
            return [rule.to_dict() for rule in self._rules.values()]

    def get_rule(self, rule_id: int) -> Optional[dict]:
        """获取单条规则"""
        with self._lock:
            rule = self._rules.get(rule_id)
            return rule.to_dict() if rule else None

    # ---- tc命令操作 ----

    def apply_rules(self) -> dict:
        """
        应用所有启用的规则到系统（tc命令）

        Returns:
            执行结果
        """
        with self._lock:
            enabled_rules = [r for r in self._rules.values() if r.enabled]
            if not enabled_rules:
                return {"success": True, "message": "没有启用的规则", "applied": 0}

            # 按接口分组
            interfaces = {}
            for rule in enabled_rules:
                if rule.interface not in interfaces:
                    interfaces[rule.interface] = []
                interfaces[rule.interface].append(rule)

            applied_count = 0
            errors = []

            for iface, rules in interfaces.items():
                # 先清除该接口的tc规则
                try:
                    self._exec_tc("qdisc del dev {} root 2>/dev/null".format(iface))
                    self._exec_tc("qdisc del dev {} ingress 2>/dev/null".format(iface))
                except Exception:
                    pass

                # 按方向分组
                egress_rules = [r for r in rules if r.direction == "egress"]
                ingress_rules = [r for r in rules if r.direction == "ingress"]

                # 应用egress规则
                if egress_rules:
                    result = self._apply_egress(iface, egress_rules)
                    if result["success"]:
                        applied_count += result["applied"]
                    else:
                        errors.append(result["error"])

                # 应用ingress规则
                if ingress_rules:
                    result = self._apply_ingress(iface, ingress_rules)
                    if result["success"]:
                        applied_count += result["applied"]
                    else:
                        errors.append(result["error"])

            msg = "已应用 {} 条规则".format(applied_count)
            if errors:
                msg += "，{} 个错误".format(len(errors))

            logger.info(msg)
            return {
                "success": len(errors) == 0,
                "message": msg,
                "applied": applied_count,
                "errors": errors,
            }

    def remove_tc_rules(self) -> dict:
        """
        清除所有tc规则

        Returns:
            执行结果
        """
        with self._lock:
            interfaces = set(r.interface for r in self._rules.values())
            cleared = 0
            errors = []

            for iface in interfaces:
                try:
                    self._exec_tc("qdisc del dev {} root 2>/dev/null".format(iface))
                    self._exec_tc("qdisc del dev {} ingress 2>/dev/null".format(iface))
                    cleared += 1
                    logger.info("已清除接口 {} 的tc规则".format(iface))
                except Exception as e:
                    errors.append("接口 {}: {}".format(iface, str(e)))

            return {
                "success": len(errors) == 0,
                "message": "已清除 {} 个接口的tc规则".format(cleared),
                "cleared": cleared,
                "errors": errors,
            }

    def _apply_egress(self, interface: str, rules: List[QoSRule]) -> dict:
        """应用出站规则"""
        try:
            # 排序：优先级数字小的先应用
            sorted_rules = sorted(rules, key=lambda r: r.priority)

            # 创建根队列 (HTB)
            self._exec_tc(
                "qdisc add dev {} root handle 1: htb default 999".format(interface)
            )

            # 创建根分类（总带宽上限取所有规则中最大的）
            max_bw = max(
                (r.bandwidth_limit for r in sorted_rules if r.bandwidth_limit > 0),
                default=1000,
            )
            self._exec_tc(
                "class add dev {} parent 1: classid 1:1 htb rate {}mbit ceil {}mbit".format(
                    interface, max_bw, max_bw * 1.2
                )
            )

            # 默认分类（低优先级）
            self._exec_tc(
                "class add dev {} parent 1:1 classid 1:999 htb rate 1mbit ceil 10mbit".format(
                    interface
                )
            )

            # 为每条规则创建分类和过滤器
            for idx, rule in enumerate(sorted_rules):
                class_id = 10 + idx
                parent_class = "1:1"
                rate = rule.bandwidth_limit if rule.bandwidth_limit > 0 else max_bw
                ceil = rule.burst_limit if rule.burst_limit > 0 else rate * 1.5

                if rule.action == "block":
                    # 阻断：分配极小带宽
                    self._exec_tc(
                        "class add dev {} parent {} classid 1:{} htb rate 1kbit ceil 1kbit".format(
                            interface, parent_class, class_id
                        )
                    )
                else:
                    self._exec_tc(
                        "class add dev {} parent {} classid 1:{} htb rate {}mbit ceil {}mbit".format(
                            interface, parent_class, class_id, rate, ceil
                        )
                    )

                # 添加延迟（使用netem）
                if rule.latency_ms > 0 and rule.action != "block":
                    self._exec_tc(
                        "qdisc add dev {} parent 1:{} handle {}: netem delay {}ms".format(
                            interface, class_id, class_id * 10, int(rule.latency_ms)
                        )
                    )

                # 添加过滤器
                filter_cmd = self._build_filter_cmd(interface, rule, class_id)
                if filter_cmd:
                    self._exec_tc(filter_cmd)

            return {"success": True, "applied": len(sorted_rules)}
        except Exception as e:
            logger.error("应用egress规则失败 (接口: {}): {}".format(interface, e))
            return {"success": False, "error": str(e), "applied": 0}

    def _apply_ingress(self, interface: str, rules: List[QoSRule]) -> dict:
        """应用入站规则"""
        try:
            sorted_rules = sorted(rules, key=lambda r: r.priority)

            # 创建ingress qdisc
            self._exec_tc(
                "qdisc add dev {} handle ffff: ingress".format(interface)
            )

            for idx, rule in enumerate(sorted_rules):
                if rule.action == "block" or rule.bandwidth_limit > 0:
                    rate = rule.bandwidth_limit if rule.bandwidth_limit > 0 else 0.001
                    rate_kbit = int(rate * 1000)

                    # 使用ifb进行ingress限速
                    filter_cmd = self._build_ingress_filter(
                        interface, rule, rate_kbit
                    )
                    if filter_cmd:
                        self._exec_tc(filter_cmd)

            return {"success": True, "applied": len(sorted_rules)}
        except Exception as e:
            logger.error("应用ingress规则失败 (接口: {}): {}".format(interface, e))
            return {"success": False, "error": str(e), "applied": 0}

    def _build_filter_cmd(self, interface: str, rule: QoSRule,
                          class_id: int) -> Optional[str]:
        """构建tc filter命令"""
        flowid = "1:{}".format(class_id)

        if rule.match_type == "ip":
            if "/" in rule.match_value:
                return (
                    "filter add dev {} protocol ip parent 1:0 prio {} "
                    "u32 match ip dst {} flowid {}".format(
                        interface, rule.priority, rule.match_value, flowid
                    )
                )
            else:
                return (
                    "filter add dev {} protocol ip parent 1:0 prio {} "
                    "u32 match ip dst {} flowid {}".format(
                        interface, rule.priority, rule.match_value, flowid
                    )
                )

        elif rule.match_type == "port":
            ports = self._parse_port_range(rule.match_value)
            cmds = []
            for port in ports:
                cmds.append(
                    "filter add dev {} protocol ip parent 1:0 prio {} "
                    "u32 match ip dport {} 0xffff flowid {}".format(
                        interface, rule.priority, port, flowid
                    )
                )
            return " && ".join(cmds) if cmds else None

        elif rule.match_type == "protocol":
            proto_num = self._protocol_to_num(rule.match_value)
            if proto_num:
                return (
                    "filter add dev {} protocol ip parent 1:0 prio {} "
                    "u32 match ip protocol {} 0xff flowid {}".format(
                        interface, rule.priority, proto_num, flowid
                    )
                )

        elif rule.match_type == "mac":
            return (
                "filter add dev {} protocol ip parent 1:0 prio {} "
                "u32 match u16 0x0800 0xffff at -2 match u48 {} 0xffffffffffff at -14 flowid {}".format(
                    interface, rule.priority,
                    rule.match_value.replace(":", "").lower(),
                    flowid,
                )
            )

        elif rule.match_type == "app":
            # 基于端口的简单应用匹配
            app_ports = self._app_to_ports(rule.match_value)
            if app_ports:
                ports_str = ",".join(str(p) for p in app_ports)
                return self._build_filter_cmd(
                    interface,
                    QoSRule(match_type="port", match_value=ports_str,
                            priority=rule.priority),
                    class_id,
                )

        return None

    def _build_ingress_filter(self, interface: str, rule: QoSRule,
                              rate_kbit: int) -> Optional[str]:
        """构建ingress filter命令"""
        if rule.match_type == "ip":
            return (
                "filter add dev {} parent ffff: protocol ip prio {} "
                "u32 match ip src {} police rate {}kbit burst 10k drop flowid :1".format(
                    interface, rule.priority, rule.match_value, rate_kbit
                )
            )
        elif rule.match_type == "port":
            ports = self._parse_port_range(rule.match_value)
            if ports:
                return (
                    "filter add dev {} parent ffff: protocol ip prio {} "
                    "u32 match ip sport {} 0xffff police rate {}kbit burst 10k drop flowid :1".format(
                        interface, rule.priority, ports[0], rate_kbit
                    )
                )
        return None

    def _apply_tc_rule(self, rule: QoSRule) -> dict:
        """
        应用单条tc规则

        Args:
            rule: QoSRule实例

        Returns:
            执行结果
        """
        commands = self._gen_tc_commands(rule)
        if not commands:
            return {"success": False, "message": "无法生成tc命令"}

        errors = []
        for cmd in commands:
            try:
                self._exec_tc(cmd)
            except Exception as e:
                errors.append(str(e))

        if errors:
            return {"success": False, "message": "部分命令执行失败", "errors": errors}
        return {"success": True, "message": "规则已应用", "commands": commands}

    def _gen_tc_commands(self, rule: QoSRule) -> List[str]:
        """
        生成tc命令字符串列表

        Args:
            rule: QoSRule实例

        Returns:
            tc命令列表
        """
        commands = []
        iface = rule.interface

        if rule.direction == "egress":
            commands.append(
                "tc qdisc add dev {} root handle 1: htb default 999".format(iface)
            )
            rate = rule.bandwidth_limit if rule.bandwidth_limit > 0 else 1000
            ceil = rule.burst_limit if rule.burst_limit > 0 else rate * 1.2
            commands.append(
                "tc class add dev {} parent 1: classid 1:1 htb rate {}mbit ceil {}mbit".format(
                    iface, rate, ceil
                )
            )
            commands.append(
                "tc class add dev {} parent 1:1 classid 1:10 htb rate {}mbit ceil {}mbit".format(
                    iface, rate, ceil
                )
            )
            if rule.latency_ms > 0:
                commands.append(
                    "tc qdisc add dev {} parent 1:10 handle 100: netem delay {}ms".format(
                        iface, int(rule.latency_ms)
                    )
                )
        elif rule.direction == "ingress":
            commands.append(
                "tc qdisc add dev {} handle ffff: ingress".format(iface)
            )
            if rule.bandwidth_limit > 0:
                rate_kbit = int(rule.bandwidth_limit * 1000)
                commands.append(
                    "tc filter add dev {} parent ffff: protocol ip prio {} "
                    "u32 match ip src 0.0.0.0/0 police rate {}kbit burst 10k drop flowid :1".format(
                        iface, rule.priority, rate_kbit
                    )
                )

        return commands

    # ---- 统计 ----

    def get_stats(self, interface: str = None) -> List[dict]:
        """
        获取流量统计

        Args:
            interface: 指定接口，None表示所有接口

        Returns:
            统计信息列表
        """
        with self._lock:
            if interface:
                stats = self._collect_stats(interface)
                return [stats.to_dict()] if stats else []
            else:
                interfaces = set(r.interface for r in self._rules.values())
                results = []
                for iface in interfaces:
                    stats = self._collect_stats(iface)
                    if stats:
                        results.append(stats.to_dict())
                return results

    def get_bandwidth_usage(self, interface: str) -> dict:
        """
        获取接口带宽使用情况

        Args:
            interface: 网络接口名

        Returns:
            带宽使用信息
        """
        try:
            # 从 /proc/net/dev 读取接口统计
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()

            for line in lines[2:]:
                parts = line.split()
                if not parts:
                    continue
                iface_name = parts[0].rstrip(":")
                if iface_name == interface:
                    rx_bytes = int(parts[1])
                    tx_bytes = int(parts[9])
                    rx_packets = int(parts[2])
                    tx_packets = int(parts[10])

                    # 计算带宽使用率
                    now = time.time()
                    last_time = self._last_stats_time.get(interface, 0)
                    if last_time > 0:
                        elapsed = now - last_time
                        if elapsed > 0:
                            last_stats = self._stats_cache.get(interface)
                            if last_stats:
                                rx_rate = (rx_bytes - last_stats.total_bytes) / elapsed * 8 / 1e6
                                tx_rate = (tx_bytes - last_stats.shaped_bytes) / elapsed * 8 / 1e6
                            else:
                                rx_rate = 0.0
                                tx_rate = 0.0
                        else:
                            rx_rate = 0.0
                            tx_rate = 0.0
                    else:
                        rx_rate = 0.0
                        tx_rate = 0.0

                    self._last_stats_time[interface] = now
                    self._stats_cache[interface] = QoSStats(
                        interface=interface,
                        total_bytes=rx_bytes,
                        total_packets=rx_packets,
                        shaped_bytes=tx_bytes,
                        dropped_bytes=tx_packets,
                        current_bandwidth_mbps=rx_rate + tx_rate,
                    )

                    return {
                        "interface": interface,
                        "rx_bytes": rx_bytes,
                        "tx_bytes": tx_bytes,
                        "rx_packets": rx_packets,
                        "tx_packets": tx_packets,
                        "rx_rate_mbps": round(rx_rate, 3),
                        "tx_rate_mbps": round(tx_rate, 3),
                        "total_rate_mbps": round(rx_rate + tx_rate, 3),
                    }

            return {"interface": interface, "error": "接口未找到"}

        except Exception as e:
            logger.error("获取带宽使用失败 (接口: {}): {}".format(interface, e))
            return {"interface": interface, "error": str(e)}

    def _collect_stats(self, interface: str) -> Optional[QoSStats]:
        """收集单个接口的tc统计"""
        try:
            result = self._exec_tc(
                " -s class show dev {}".format(interface)
            )
            stats = QoSStats(interface=interface)

            # 解析tc输出
            for line in result.split("\n"):
                line = line.strip()
                if "Sent" in line:
                    # 提取字节数
                    byte_match = re.search(r"Sent (\d+)", line)
                    if byte_match:
                        stats.shaped_bytes += int(byte_match.group(1))
                    # 提取丢包数
                    drop_match = re.search(r"dropped (\d+)", line)
                    if drop_match:
                        stats.dropped_bytes += int(drop_match.group(1))

            # 获取总流量
            bw_info = self.get_bandwidth_usage(interface)
            if "error" not in bw_info:
                stats.total_bytes = bw_info.get("rx_bytes", 0) + bw_info.get("tx_bytes", 0)
                stats.total_packets = bw_info.get("rx_packets", 0) + bw_info.get("tx_packets", 0)
                stats.current_bandwidth_mbps = bw_info.get("total_rate_mbps", 0.0)

            return stats

        except Exception as e:
            logger.debug("收集tc统计失败 (接口: {}): {}".format(interface, e))
            return None

    def get_tc_status(self, interface: str = None) -> dict:
        """
        获取tc规则状态

        Args:
            interface: 指定接口

        Returns:
            tc状态信息
        """
        try:
            if interface:
                qdisc_result = self._exec_tc(
                    "qdisc show dev {}".format(interface)
                )
                class_result = self._exec_tc(
                    " -s class show dev {}".format(interface)
                )
                filter_result = self._exec_tc(
                    "filter show dev {}".format(interface)
                )
                return {
                    "interface": interface,
                    "qdisc": qdisc_result.strip(),
                    "classes": class_result.strip(),
                    "filters": filter_result.strip(),
                }
            else:
                interfaces = set(r.interface for r in self._rules.values())
                result = {}
                for iface in interfaces:
                    result[iface] = self.get_tc_status(iface)
                return result

        except Exception as e:
            logger.error("获取tc状态失败: {}".format(e))
            return {"error": str(e)}

    # ---- 预设策略 ----

    def apply_preset(self, preset_name: str, interface: str = "eth0") -> dict:
        """
        应用预设策略

        Args:
            preset_name: 预设策略名称 (office/gaming/balanced/strict)
            interface: 目标接口

        Returns:
            执行结果
        """
        if preset_name not in PRESET_POLICIES:
            return {
                "success": False,
                "message": "未知预设策略: {}，可选: {}".format(
                    preset_name, ", ".join(PRESET_POLICIES.keys())
                ),
            }

        preset = PRESET_POLICIES[preset_name]

        with self._lock:
            # 清除现有规则
            self._rules.clear()
            self._next_rule_id = 1

            # 添加预设规则
            for rule_def in preset["rules"]:
                rule = QoSRule(
                    name=rule_def["name"],
                    interface=interface,
                    direction=rule_def.get("direction", "egress"),
                    match_type=rule_def["match_type"],
                    match_value=rule_def["match_value"],
                    priority=rule_def.get("priority", 50),
                    bandwidth_limit=rule_def.get("bandwidth_limit", 0),
                    burst_limit=rule_def.get("burst_limit", 0),
                    latency_ms=rule_def.get("latency_ms", 0),
                    action=rule_def.get("action", "shape"),
                    enabled=True,
                )
                rule.id = self._next_rule_id
                rule.created_at = datetime.now()
                self._rules[rule.id] = rule
                self._next_rule_id += 1

            logger.info(
                "已应用预设策略 '{}' ({}), 共 {} 条规则".format(
                    preset_name, preset["name"], len(preset["rules"])
                )
            )

            return {
                "success": True,
                "message": "已应用预设策略: {}".format(preset["name"]),
                "preset": preset_name,
                "description": preset["description"],
                "rules_count": len(preset["rules"]),
            }

    def get_presets(self) -> dict:
        """获取所有预设策略列表"""
        return {
            name: {
                "name": preset["name"],
                "description": preset["description"],
                "rules_count": len(preset["rules"]),
            }
            for name, preset in PRESET_POLICIES.items()
        }

    # ---- 辅助方法 ----

    def _exec_tc(self, cmd: str, shell: bool = False) -> str:
        """
        执行tc命令

        Args:
            cmd: 命令字符串
            shell: 是否使用shell执行

        Returns:
            命令输出
        """
        full_cmd = "tc {}".format(cmd) if not cmd.startswith("tc ") else cmd
        self._tc_history.append({
            "command": full_cmd,
            "timestamp": datetime.now().isoformat(),
        })
        # 保留最近100条历史
        if len(self._tc_history) > 100:
            self._tc_history = self._tc_history[-100:]

        # 安全修复：将命令字符串解析为列表，避免 shell=True 的命令注入风险
        cmd_parts = full_cmd.split()
        
        result = subprocess.run(
            cmd_parts,
            shell=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        # tc命令返回非0不一定表示错误（如删除不存在的qdisc）
        return result.stdout + result.stderr

    def _parse_port_range(self, port_str: str) -> List[int]:
        """解析端口范围字符串，返回端口列表"""
        ports = []
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-")
                    ports.extend(range(int(start), int(end) + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    continue
        return ports[:20]  # 限制最多20个端口

    def _protocol_to_num(self, protocol: str) -> Optional[int]:
        """协议名转数字"""
        proto_map = {
            "tcp": 6,
            "udp": 17,
            "icmp": 1,
            "gre": 47,
            "esp": 50,
            "ah": 51,
            "sctp": 132,
        }
        return proto_map.get(protocol.lower())

    def _app_to_ports(self, app_name: str) -> Optional[List[int]]:
        """应用名转端口列表"""
        app_ports = {
            "ssh": [22],
            "http": [80],
            "https": [443],
            "ftp": [20, 21],
            "dns": [53],
            "smtp": [25, 587],
            "pop3": [110],
            "imap": [143],
            "sip": [5060, 5061],
            "rtp": list(range(10000, 20001)),
            "torrent": list(range(6881, 7000)),
        }
        return app_ports.get(app_name.lower())

    def get_tc_history(self) -> List[dict]:
        """获取tc命令执行历史"""
        with self._lock:
            return list(self._tc_history)

    def get_available_interfaces(self) -> List[str]:
        """获取可用网络接口列表"""
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            interfaces = []
            for line in lines[2:]:
                parts = line.split()
                if parts:
                    iface = parts[0].rstrip(":")
                    if iface != "lo":
                        interfaces.append(iface)
            return interfaces
        except Exception as e:
            logger.error("获取网络接口列表失败: {}".format(e))
            return ["eth0"]


# ============================================================
# 单例管理
# ============================================================

_qos_manager: Optional[QoSManager] = None
_qos_manager_lock = threading.Lock()


def get_qos_manager() -> QoSManager:
    """获取QoS管理器单例"""
    global _qos_manager
    if _qos_manager is None:
        with _qos_manager_lock:
            if _qos_manager is None:
                _qos_manager = QoSManager()
    return _qos_manager
