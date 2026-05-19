"""
GateKeeper - DHCP 监控模块
提供 DHCP 地址分配监控、异常检测与非法 DHCP 服务器告警功能
"""

import re
import os
import json
import socket
import struct
import threading
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

from config.logging_config import get_logger

logger = get_logger("dhcp_monitor")

# DHCP 消息类型
DHCP_MSG_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}

# DHCP 选项代码
DHCP_OPTIONS = {
    1: "Subnet Mask",
    3: "Router",
    6: "DNS Server",
    12: "Hostname",
    15: "Domain Name",
    51: "Lease Time",
    53: "DHCP Message Type",
    54: "DHCP Server Identifier",
    55: "Parameter Request List",
    58: "Renewal Time",
    59: "Rebinding Time",
    61: "Client Identifier",
    82: "Relay Agent Information",
}

# 已知合法 DHCP 服务器 MAC 前缀（用于初步判断）
KNOWN_DHCP_VENDOR_PREFIXES = [
    "00:1A:2B",  # Cisco
    "00:0C:29",  # VMware
    "00:15:5D",  # Microsoft
    "F8:FF:0A",  # Apple
    "D8:32:14",  # Netgear
    "C0:25:E9",  # TP-Link
    "AC:87:A3",  # Huawei
    "B0:F1:EC",  # TP-Link
]


class DHCPMonitor:
    """DHCP 监控器 - DHCP 地址分配监控与异常告警"""

    def __init__(self):
        """初始化 DHCP 监控器"""
        self._leases: Dict[str, dict] = {}
        self._rogue_servers: List[dict] = []
        self._alerts: List[dict] = []
        self._known_servers: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._monitor_thread: Optional[threading.Thread] = None
        self._running = False
        self._interface = ""
        self._stats = {
            "total_dhcp_packets": 0,
            "total_leases_granted": 0,
            "total_leases_released": 0,
            "total_rogue_detected": 0,
            "total_alerts": 0,
            "monitor_start_time": None,
            "monitor_uptime": 0,
        }
        self._load_known_servers()
        logger.info("DHCP 监控器初始化完成")

    def start_monitor(self, interface: str) -> dict:
        """
        启动 DHCP 监控

        Args:
            interface: 监控的网络接口名称

        Returns:
            启动结果字典
        """
        with self._lock:
            if self._running:
                return {"status": "error", "message": "DHCP 监控已在运行中"}

            # 验证接口是否存在
            if not self._interface_exists(interface):
                return {"status": "error", "message": "网络接口不存在: {}".format(interface)}

            self._interface = interface
            self._running = True
            self._stats["monitor_start_time"] = datetime.now().isoformat()

            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                name="dhcp_monitor",
                daemon=True,
            )
            self._monitor_thread.start()

            logger.info("DHCP 监控已启动，接口: {}".format(interface))
            return {
                "status": "ok",
                "message": "DHCP 监控已启动",
                "interface": interface,
            }

    def stop_monitor(self) -> dict:
        """
        停止 DHCP 监控

        Returns:
            停止结果字典
        """
        with self._lock:
            if not self._running:
                return {"status": "error", "message": "DHCP 监控未在运行"}

            self._running = False
            interface = self._interface

            if self._monitor_thread and self._monitor_thread.is_alive():
                self._monitor_thread.join(timeout=5)

            self._stats["monitor_uptime"] = 0
            logger.info("DHCP 监控已停止，接口: {}".format(interface))
            return {
                "status": "ok",
                "message": "DHCP 监控已停止",
                "interface": interface,
            }

    def get_leases(self) -> list:
        """
        获取当前 DHCP 租约列表

        Returns:
            DHCP 租约信息列表
        """
        with self._lock:
            return list(self._leases.values())

    def detect_rogue_server(self) -> list:
        """
        检测非法 DHCP 服务器

        Returns:
            检测到的非法 DHCP 服务器列表
        """
        with self._lock:
            # 从告警中筛选非法服务器相关告警
            rogue = []
            seen_servers = set()
            for alert in self._alerts:
                if alert.get("type") == "rogue_server":
                    server_mac = alert.get("server_mac", "")
                    if server_mac and server_mac not in seen_servers:
                        seen_servers.add(server_mac)
                        rogue.append({
                            "server_mac": server_mac,
                            "server_ip": alert.get("server_ip", ""),
                            "detected_at": alert.get("timestamp", ""),
                            "confidence": alert.get("confidence", "medium"),
                            "reason": alert.get("reason", ""),
                        })
            return rogue

    def get_stats(self) -> dict:
        """
        获取监控统计信息

        Returns:
            统计信息字典
        """
        with self._lock:
            stats = dict(self._stats)
            stats["current_leases"] = len(self._leases)
            stats["rogue_servers_count"] = len(self._rogue_servers)
            stats["alerts_count"] = len(self._alerts)
            stats["is_running"] = self._running
            stats["interface"] = self._interface
            return stats

    def add_known_server(self, mac: str, label: str = "",
                         ip: str = "") -> dict:
        """
        添加已知合法 DHCP 服务器

        Args:
            mac: 服务器 MAC 地址
            label: 服务器标签/描述
            ip: 服务器 IP 地址（可选）

        Returns:
            操作结果
        """
        with self._lock:
            mac_upper = mac.upper()
            self._known_servers[mac_upper] = {
                "mac": mac_upper,
                "label": label,
                "ip": ip,
                "added_at": datetime.now().isoformat(),
            }
            self._save_known_servers()
            logger.info("添加已知 DHCP 服务器: {} ({})".format(mac_upper, label))
            return {"status": "ok", "message": "已添加已知服务器"}

    def remove_known_server(self, mac: str) -> dict:
        """
        移除已知合法 DHCP 服务器

        Args:
            mac: 服务器 MAC 地址

        Returns:
            操作结果
        """
        with self._lock:
            mac_upper = mac.upper()
            if mac_upper in self._known_servers:
                del self._known_servers[mac_upper]
                self._save_known_servers()
                logger.info("移除已知 DHCP 服务器: {}".format(mac_upper))
                return {"status": "ok", "message": "已移除"}
            return {"status": "error", "message": "服务器不在已知列表中"}

    def get_known_servers(self) -> list:
        """
        获取已知合法 DHCP 服务器列表

        Returns:
            已知服务器列表
        """
        with self._lock:
            return list(self._known_servers.values())

    def get_alerts(self, limit: int = 100) -> list:
        """
        获取告警记录

        Args:
            limit: 最大返回数量

        Returns:
            告警列表
        """
        with self._lock:
            return list(self._alerts[-limit:])

    def clear_alerts(self) -> dict:
        """
        清除告警记录

        Returns:
            操作结果
        """
        with self._lock:
            count = len(self._alerts)
            self._alerts.clear()
            logger.info("已清除 {} 条告警记录".format(count))
            return {"status": "ok", "cleared": count}

    # ----------------------------------------------------------
    # 内部方法
    # ----------------------------------------------------------

    def _monitor_loop(self):
        """DHCP 监控主循环"""
        logger.info("DHCP 监控线程已启动")
        while self._running:
            try:
                self._capture_dhcp_packets()
            except Exception as e:
                logger.error("DHCP 监控循环异常: {}".format(e))
            time.sleep(2)

    def _capture_dhcp_packets(self):
        """捕获并分析 DHCP 数据包"""
        try:
            # 使用 tcpdump 捕获 DHCP 流量
            cmd = [
                "tcpdump", "-i", self._interface,
                "-n", "-l", "-c", "10",
                "-s", "1500",
                "port 67 or port 68",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15
            )
            output = result.stdout

            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                self._parse_dhcp_packet_line(line)

        except FileNotFoundError:
            logger.warning("tcpdump 未安装，DHCP 监控需要 tcpdump 支持")
            self._running = False
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            logger.debug("DHCP 包捕获异常: {}".format(e))

    def _parse_dhcp_packet_line(self, line: str):
        """
        解析 tcpdump 输出的 DHCP 数据包行

        Args:
            line: tcpdump 输出的一行
        """
        with self._lock:
            self._stats["total_dhcp_packets"] += 1

        # 尝试从 tcpdump 输出中提取 DHCP 信息
        # 典型格式: IP 0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from aa:bb:cc:dd:ee:ff
        # 或: IP 192.168.1.1.67 > 192.168.1.100.68: BOOTP/DHCP, Reply from aa:bb:cc:dd:ee:ff

        try:
            # 提取 MAC 地址
            mac_match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', line)
            if not mac_match:
                return

            mac_addr = mac_match.group(1).upper()

            # 提取 IP 地址
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)', line)
            if not ip_match:
                return

            src_ip = ip_match.group(1)
            src_port = int(ip_match.group(2))
            dst_ip = ip_match.group(3)
            dst_port = int(ip_match.group(4))

            # DHCP 服务器响应 (端口 67 -> 68)
            if src_port == 67 and dst_port == 68:
                self._handle_dhcp_offer(src_ip, mac_addr, line)
            # DHCP 客户端请求 (端口 68 -> 67)
            elif src_port == 68 and dst_port == 67:
                self._handle_dhcp_request(src_ip, mac_addr, line)

        except Exception as e:
            logger.debug("解析 DHCP 行失败: {}".format(e))

    def _handle_dhcp_offer(self, server_ip: str, mac: str,
                           raw_line: str):
        """
        处理 DHCP OFFER/ACK 响应

        Args:
            server_ip: DHCP 服务器 IP
            mac: 服务器 MAC 地址
            raw_line: 原始数据包行
        """
        with self._lock:
            # 检查是否为已知服务器
            is_known = mac in self._known_servers

            if not is_known:
                # 检测非法 DHCP 服务器
                self._check_rogue_server(server_ip, mac)

            # 尝试提取分配的 IP
            client_ip_match = re.search(r'for\s+(\d+\.\d+\.\d+\.\d+)', raw_line)
            if client_ip_match:
                client_ip = client_ip_match.group(1)
                self._leases[client_ip] = {
                    "ip": client_ip,
                    "mac": mac,
                    "server_ip": server_ip,
                    "server_known": is_known,
                    "lease_time": None,
                    "acquired_at": datetime.now().isoformat(),
                    "expires_at": None,
                }
                self._stats["total_leases_granted"] += 1
                logger.info("DHCP 租约: {} -> {} (服务器: {})".format(
                    client_ip, mac, server_ip))

    def _handle_dhcp_request(self, client_ip: str, mac: str,
                             raw_line: str):
        """
        处理 DHCP REQUEST 消息

        Args:
            client_ip: 客户端 IP
            mac: 客户端 MAC 地址
            raw_line: 原始数据包行
        """
        with self._lock:
            # 检查是否有异常的 DHCP 请求模式（可能是 DHCP 饥饿攻击）
            recent_requests = [
                a for a in self._alerts[-20:]
                if a.get("type") == "rapid_request" and a.get("mac") == mac
            ]
            if len(recent_requests) >= 5:
                self._add_alert({
                    "type": "dhcp_starvation",
                    "mac": mac,
                    "ip": client_ip,
                    "reason": "检测到来自 {} 的异常大量 DHCP 请求，可能为 DHCP 饥饿攻击".format(mac),
                    "severity": "high",
                })

    def _check_rogue_server(self, server_ip: str, mac: str):
        """
        检查是否为非法 DHCP 服务器

        Args:
            server_ip: 服务器 IP
            mac: 服务器 MAC
        """
        # 检查 MAC 前缀是否为已知网络设备厂商
        mac_prefix = mac[:8].upper()
        is_known_vendor = any(
            mac_prefix.startswith(prefix) for prefix in KNOWN_DHCP_VENDOR_PREFIXES
        )

        # 检查是否已有该服务器的告警
        recent_rogue = [
            a for a in self._alerts
            if a.get("type") == "rogue_server" and a.get("server_mac") == mac
        ]

        if not recent_rogue:
            confidence = "high" if not is_known_vendor else "medium"
            reason = "未知 MAC 前缀的设备响应了 DHCP 请求" if not is_known_vendor \
                else "该 MAC 地址不在已知 DHCP 服务器列表中"

            self._add_alert({
                "type": "rogue_server",
                "server_ip": server_ip,
                "server_mac": mac,
                "confidence": confidence,
                "reason": reason,
                "severity": "critical" if confidence == "high" else "high",
            })

            self._rogue_servers.append({
                "mac": mac,
                "ip": server_ip,
                "detected_at": datetime.now().isoformat(),
                "confidence": confidence,
            })
            self._stats["total_rogue_detected"] += 1

            logger.warning("检测到疑似非法 DHCP 服务器: {} (IP: {}, 置信度: {})".format(
                mac, server_ip, confidence))

    def _add_alert(self, alert: dict):
        """
        添加告警记录

        Args:
            alert: 告警信息字典
        """
        alert["timestamp"] = datetime.now().isoformat()
        self._alerts.append(alert)
        self._stats["total_alerts"] += 1

        # 限制告警数量
        max_alerts = 10000
        if len(self._alerts) > max_alerts:
            self._alerts = self._alerts[-max_alerts:]

    def _interface_exists(self, interface: str) -> bool:
        """
        检查网络接口是否存在

        Args:
            interface: 接口名称

        Returns:
            接口是否存在
        """
        try:
            with open("/proc/net/dev", "r") as f:
                for line in f.readlines()[2:]:
                    if interface in line:
                        return True
            return False
        except Exception:
            return False

    def _load_known_servers(self):
        """从文件加载已知服务器列表"""
        try:
            data_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data"
            )
            os.makedirs(data_dir, exist_ok=True)
            path = os.path.join(data_dir, "dhcp_known_servers.json")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for server in data.get("servers", []):
                    mac = server.get("mac", "")
                    if mac:
                        self._known_servers[mac.upper()] = server
                logger.info("已加载 {} 个已知 DHCP 服务器".format(
                    len(self._known_servers)))
        except Exception as e:
            logger.debug("加载已知 DHCP 服务器失败: {}".format(e))

    def _save_known_servers(self):
        """保存已知服务器列表到文件"""
        try:
            data_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data"
            )
            os.makedirs(data_dir, exist_ok=True)
            path = os.path.join(data_dir, "dhcp_known_servers.json")
            data = {"servers": list(self._known_servers.values())}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error("保存已知 DHCP 服务器失败: {}".format(e))

    def _read_system_leases(self) -> List[dict]:
        """
        从系统 DHCP 租约文件读取当前租约

        Returns:
            系统租约列表
        """
        leases = []
        lease_files = [
            "/var/lib/dhcp/dhcpd.leases",
            "/var/lib/dhcpd/dhcpd.leases",
            "/var/lib/misc/dnsmasq.leases",
        ]

        for lease_file in lease_files:
            try:
                if not os.path.exists(lease_file):
                    continue
                with open(lease_file, "r") as f:
                    content = f.read()

                # 解析 ISC DHCP 格式
                lease_blocks = re.findall(
                    r'lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)\}',
                    content, re.DOTALL
                )
                for ip, block in lease_blocks:
                    lease_info = {"ip": ip, "source": lease_file}
                    starts_match = re.search(r'starts\s+\d+\s+([\d/]+\s+[\d:]+)', block)
                    ends_match = re.search(r'ends\s+\d+\s+([\d/]+\s+[\d:]+)', block)
                    hw_match = re.search(r'hardware ethernet\s+([0-9A-Fa-f:]+)', block)
                    hostname_match = re.search(r'client-hostname\s+"([^"]+)"', block)

                    if starts_match:
                        lease_info["starts"] = starts_match.group(1)
                    if ends_match:
                        lease_info["ends"] = ends_match.group(1)
                    if hw_match:
                        lease_info["mac"] = hw_match.group(1).upper()
                    if hostname_match:
                        lease_info["hostname"] = hostname_match.group(1)

                    leases.append(lease_info)

            except Exception as e:
                logger.debug("读取租约文件 {} 失败: {}".format(lease_file, e))

        return leases


# ============================================================
# 单例
# ============================================================

_instance: Optional[DHCPMonitor] = None


def get_dhcp_monitor() -> DHCPMonitor:
    """获取 DHCP 监控器单例"""
    global _instance
    if _instance is None:
        _instance = DHCPMonitor()
    return _instance
