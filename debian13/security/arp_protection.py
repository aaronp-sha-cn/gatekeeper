"""
GateKeeper - ARP 防护模块
提供 ARP 欺骗检测、防御与 ARP 表监控功能
"""

import re
import os
import json
import time
import threading
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any

from config.logging_config import get_logger

logger = get_logger("arp_protection")

# ARP 欺骗检测阈值
MAX_MAC_CHANGES_PER_IP = 3          # 同一 IP 的 MAC 变更次数阈值
MAC_CHANGE_WINDOW = 60              # MAC 变更检测窗口（秒）
GRATUITOUS_ARP_THRESHOLD = 10       # 免费ARP包频率阈值（次/分钟）
ARP_TABLE_CHECK_INTERVAL = 10       # ARP 表检查间隔（秒）

# 已知网关配置默认值
DEFAULT_GATEWAY_IP = ""
DEFAULT_GATEWAY_MAC = ""


class ARPProtection:
    """ARP 防护器 - ARP 欺骗检测与防御"""

    def __init__(self):
        """初始化 ARP 防护器"""
        self._arp_table: Dict[str, dict] = {}
        self._mac_history: Dict[str, List[dict]] = {}
        self._spoofing_events: List[dict] = []
        self._trusted_macs: Dict[str, str] = {}
        self._gateway_ip: str = DEFAULT_GATEWAY_IP
        self._gateway_mac: str = DEFAULT_GATEWAY_MAC
        self._lock = threading.Lock()
        self._protection_thread: Optional[threading.Thread] = None
        self._running = False
        self._interface = ""
        self._stats = {
            "total_arp_packets": 0,
            "total_mac_changes": 0,
            "total_spoofing_detected": 0,
            "total_blocked": 0,
            "total_gratuitous_arp": 0,
            "protection_start_time": None,
            "gateway_spoof_attempts": 0,
        }
        self._load_config()
        logger.info("ARP 防护器初始化完成")

    def start_protection(self, interface: str) -> dict:
        """
        启动 ARP 防护

        Args:
            interface: 要防护的网络接口名称

        Returns:
            启动结果字典
        """
        with self._lock:
            if self._running:
                return {"status": "error", "message": "ARP 防护已在运行中"}

            if not self._interface_exists(interface):
                return {"status": "error", "message": "网络接口不存在: {}".format(interface)}

            self._interface = interface
            self._running = True
            self._stats["protection_start_time"] = datetime.now().isoformat()

            # 初始加载 ARP 表
            self._refresh_arp_table()

            self._protection_thread = threading.Thread(
                target=self._protection_loop,
                name="arp_protection",
                daemon=True,
            )
            self._protection_thread.start()

            logger.info("ARP 防护已启动，接口: {}".format(interface))
            return {
                "status": "ok",
                "message": "ARP 防护已启动",
                "interface": interface,
            }

    def stop_protection(self) -> dict:
        """
        停止 ARP 防护

        Returns:
            停止结果字典
        """
        with self._lock:
            if not self._running:
                return {"status": "error", "message": "ARP 防护未在运行"}

            self._running = False
            interface = self._interface

            if self._protection_thread and self._protection_thread.is_alive():
                self._protection_thread.join(timeout=5)

            logger.info("ARP 防护已停止，接口: {}".format(interface))
            return {
                "status": "ok",
                "message": "ARP 防护已停止",
                "interface": interface,
            }

    def get_arp_table(self) -> list:
        """
        获取当前 ARP 表

        Returns:
            ARP 表条目列表
        """
        with self._lock:
            return list(self._arp_table.values())

    def detect_spoofing(self) -> list:
        """
        检测 ARP 欺骗事件

        Returns:
            检测到的欺骗事件列表
        """
        with self._lock:
            return list(self._spoofing_events)

    def get_stats(self) -> dict:
        """
        获取防护统计信息

        Returns:
            统计信息字典
        """
        with self._lock:
            stats = dict(self._stats)
            stats["arp_table_size"] = len(self._arp_table)
            stats["spoofing_events_count"] = len(self._spoofing_events)
            stats["trusted_macs_count"] = len(self._trusted_macs)
            stats["is_running"] = self._running
            stats["interface"] = self._interface
            return stats

    def set_gateway(self, ip: str, mac: str) -> dict:
        """
        设置网关信息（用于网关欺骗检测）

        Args:
            ip: 网关 IP 地址
            mac: 网关 MAC 地址

        Returns:
            操作结果
        """
        with self._lock:
            self._gateway_ip = ip
            self._gateway_mac = mac.upper()
            self._save_config()
            logger.info("已设置网关: {} ({})".format(ip, self._gateway_mac))
            return {"status": "ok", "gateway_ip": ip, "gateway_mac": self._gateway_mac}

    def add_trusted_mac(self, mac: str, label: str = "") -> dict:
        """
        添加受信任的 MAC 地址

        Args:
            mac: MAC 地址
            label: 标签描述

        Returns:
            操作结果
        """
        with self._lock:
            mac_upper = mac.upper()
            self._trusted_macs[mac_upper] = label
            self._save_config()
            logger.info("添加受信任 MAC: {} ({})".format(mac_upper, label))
            return {"status": "ok", "message": "已添加受信任 MAC"}

    def remove_trusted_mac(self, mac: str) -> dict:
        """
        移除受信任的 MAC 地址

        Args:
            mac: MAC 地址

        Returns:
            操作结果
        """
        with self._lock:
            mac_upper = mac.upper()
            if mac_upper in self._trusted_macs:
                del self._trusted_macs[mac_upper]
                self._save_config()
                logger.info("移除受信任 MAC: {}".format(mac_upper))
                return {"status": "ok", "message": "已移除"}
            return {"status": "error", "message": "MAC 不在受信任列表中"}

    def get_trusted_macs(self) -> dict:
        """
        获取受信任的 MAC 地址列表

        Returns:
            受信任 MAC 字典
        """
        with self._lock:
            return dict(self._trusted_macs)

    def clear_spoofing_events(self) -> dict:
        """
        清除欺骗事件记录

        Returns:
            操作结果
        """
        with self._lock:
            count = len(self._spoofing_events)
            self._spoofing_events.clear()
            logger.info("已清除 {} 条 ARP 欺骗事件记录".format(count))
            return {"status": "ok", "cleared": count}

    # ----------------------------------------------------------
    # 内部方法
    # ----------------------------------------------------------

    def _protection_loop(self):
        """ARP 防护主循环"""
        logger.info("ARP 防护线程已启动")
        while self._running:
            try:
                self._refresh_arp_table()
                self._analyze_arp_changes()
                self._check_gateway_integrity()
            except Exception as e:
                logger.error("ARP 防护循环异常: {}".format(e))
            time.sleep(ARP_TABLE_CHECK_INTERVAL)

    def _refresh_arp_table(self):
        """从系统刷新 ARP 表"""
        try:
            result = subprocess.run(
                ["arp", "-a", "-n"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            new_table = {}

            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue

                # 解析 arp -a 输出
                # 格式: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
                match = re.search(
                    r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9A-Fa-f:]{17})',
                    line
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2).upper()

                    # 提取接口名
                    iface_match = re.search(r'on\s+(\S+)', line)
                    iface = iface_match.group(1) if iface_match else ""

                    entry = {
                        "ip": ip,
                        "mac": mac,
                        "interface": iface,
                        "updated_at": datetime.now().isoformat(),
                    }
                    new_table[ip] = entry

            with self._lock:
                old_table = self._arp_table
                self._arp_table = new_table

                # 检测 MAC 变更
                for ip, new_entry in new_table.items():
                    if ip in old_table:
                        old_mac = old_table[ip].get("mac", "")
                        new_mac = new_entry["mac"]
                        if old_mac != new_mac and old_mac:
                            self._handle_mac_change(ip, old_mac, new_mac)

                self._stats["total_arp_packets"] += len(new_table)

        except FileNotFoundError:
            logger.warning("arp 命令不可用")
        except subprocess.TimeoutExpired:
            logger.warning("刷新 ARP 表超时")
        except Exception as e:
            logger.debug("刷新 ARP 表失败: {}".format(e))

    def _handle_mac_change(self, ip: str, old_mac: str, new_mac: str):
        """
        处理 MAC 地址变更事件

        Args:
            ip: IP 地址
            old_mac: 旧 MAC 地址
            new_mac: 新 MAC 地址
        """
        now = datetime.now()

        # 跳过受信任 MAC 之间的切换
        if old_mac in self._trusted_macs or new_mac in self._trusted_macs:
            logger.debug("受信任 MAC 变更，跳过: {} {} -> {}".format(ip, old_mac, new_mac))
            return

        with self._lock:
            self._stats["total_mac_changes"] += 1

            # 记录 MAC 变更历史
            if ip not in self._mac_history:
                self._mac_history[ip] = []

            self._mac_history[ip].append({
                "old_mac": old_mac,
                "new_mac": new_mac,
                "timestamp": now.isoformat(),
            })

            # 清理过期记录
            cutoff = now.timestamp() - MAC_CHANGE_WINDOW
            self._mac_history[ip] = [
                h for h in self._mac_history[ip]
                if datetime.fromisoformat(h["timestamp"]).timestamp() > cutoff
            ]

            # 检查是否超过阈值
            change_count = len(self._mac_history[ip])
            if change_count >= MAX_MAC_CHANGES_PER_IP:
                self._record_spoofing_event(
                    ip=ip,
                    old_mac=old_mac,
                    new_mac=new_mac,
                    reason="IP {} 的 MAC 地址在 {} 秒内变更 {} 次，疑似 ARP 欺骗".format(
                        ip, MAC_CHANGE_WINDOW, change_count),
                    severity="high",
                )

            # 检查网关 MAC 是否被篡改
            if self._gateway_ip and ip == self._gateway_ip:
                if new_mac != self._gateway_mac:
                    self._record_spoofing_event(
                        ip=ip,
                        old_mac=old_mac,
                        new_mac=new_mac,
                        reason="网关 {} 的 MAC 地址被篡改！期望: {}，实际: {}".format(
                            ip, self._gateway_mac, new_mac),
                        severity="critical",
                    )
                    self._stats["gateway_spoof_attempts"] += 1

    def _analyze_arp_changes(self):
        """分析 ARP 表变更，检测异常模式"""
        with self._lock:
            # 检测同一 MAC 对应多个 IP（可能为 ARP 欺骗）
            mac_to_ips: Dict[str, List[str]] = {}
            for ip, entry in self._arp_table.items():
                mac = entry.get("mac", "")
                if mac and mac != "FF:FF:FF:FF:FF:FF":
                    if mac not in mac_to_ips:
                        mac_to_ips[mac] = []
                    mac_to_ips[mac].append(ip)

            for mac, ips in mac_to_ips.items():
                if len(ips) > 3 and mac not in self._trusted_macs:
                    self._record_spoofing_event(
                        ip="multiple",
                        old_mac="",
                        new_mac=mac,
                        reason="MAC {} 同时对应 {} 个 IP: {}，疑似 ARP 欺骗".format(
                            mac, len(ips), ", ".join(ips[:5])),
                        severity="medium",
                    )

    def _check_gateway_integrity(self):
        """检查网关完整性"""
        if not self._gateway_ip or not self._gateway_mac:
            return

        with self._lock:
            gateway_entry = self._arp_table.get(self._gateway_ip)
            if not gateway_entry:
                logger.warning("网关 {} 不在 ARP 表中".format(self._gateway_ip))
                return

            current_mac = gateway_entry.get("mac", "")
            if current_mac != self._gateway_mac:
                self._record_spoofing_event(
                    ip=self._gateway_ip,
                    old_mac=self._gateway_mac,
                    new_mac=current_mac,
                    reason="网关 MAC 地址异常！期望: {}，实际: {}".format(
                        self._gateway_mac, current_mac),
                    severity="critical",
                )
                self._stats["gateway_spoof_attempts"] += 1

                # 尝试发送正确 ARP 条目修复
                self._send_gratuitous_arp(
                    self._gateway_ip, self._gateway_mac
                )

    def _send_gratuitous_arp(self, ip: str, mac: str):
        """
        发送免费 ARP 包以修复 ARP 表

        Args:
            ip: IP 地址
            mac: 正确的 MAC 地址
        """
        try:
            # 使用 arping 发送免费 ARP
            cmd = ["arping", "-U", "-c", "3", "-I", self._interface, ip]
            subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            logger.info("已发送免费 ARP 修复: {} -> {}".format(ip, mac))
        except FileNotFoundError:
            logger.warning("arping 未安装")
        except subprocess.TimeoutExpired:
            logger.warning("发送免费 ARP 超时")
        except Exception as e:
            logger.debug("发送免费 ARP 失败: {}".format(e))

    def _record_spoofing_event(self, ip: str, old_mac: str,
                               new_mac: str, reason: str,
                               severity: str = "high"):
        """
        记录 ARP 欺骗事件

        Args:
            ip: 涉及的 IP 地址
            old_mac: 原始 MAC
            new_mac: 新 MAC
            reason: 事件原因
            severity: 严重级别
        """
        event = {
            "type": "arp_spoofing",
            "ip": ip,
            "old_mac": old_mac,
            "new_mac": new_mac,
            "reason": reason,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "interface": self._interface,
        }
        self._spoofing_events.append(event)
        self._stats["total_spoofing_detected"] += 1

        # 限制事件数量
        max_events = 5000
        if len(self._spoofing_events) > max_events:
            self._spoofing_events = self._spoofing_events[-max_events:]

        logger.warning("ARP 欺骗检测: {}".format(reason))

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

    def _load_config(self):
        """从文件加载配置"""
        try:
            data_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data"
            )
            os.makedirs(data_dir, exist_ok=True)
            path = os.path.join(data_dir, "arp_protection.json")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._gateway_ip = data.get("gateway_ip", "")
                self._gateway_mac = data.get("gateway_mac", "")
                for mac, label in data.get("trusted_macs", {}).items():
                    self._trusted_macs[mac.upper()] = label
                logger.info("ARP 防护配置已加载")
        except Exception as e:
            logger.debug("加载 ARP 防护配置失败: {}".format(e))

    def _save_config(self):
        """保存配置到文件"""
        try:
            data_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data"
            )
            os.makedirs(data_dir, exist_ok=True)
            path = os.path.join(data_dir, "arp_protection.json")
            data = {
                "gateway_ip": self._gateway_ip,
                "gateway_mac": self._gateway_mac,
                "trusted_macs": self._trusted_macs,
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error("保存 ARP 防护配置失败: {}".format(e))

    def static_arp_entry(self, ip: str, mac: str) -> dict:
        """
        添加静态 ARP 条目（防御措施）

        Args:
            ip: IP 地址
            mac: MAC 地址

        Returns:
            操作结果
        """
        try:
            cmd = ["arp", "-s", ip, mac]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.info("已添加静态 ARP 条目: {} -> {}".format(ip, mac))
                return {"status": "ok", "message": "静态 ARP 条目已添加"}
            else:
                return {
                    "status": "error",
                    "message": "添加静态 ARP 条目失败: {}".format(result.stderr),
                }
        except FileNotFoundError:
            return {"status": "error", "message": "arp 命令不可用"}
        except Exception as e:
            return {"status": "error", "message": str(e)}


# ============================================================
# 单例
# ============================================================

_instance: Optional[ARPProtection] = None


def get_arp_protection() -> ARPProtection:
    """获取 ARP 防护器单例"""
    global _instance
    if _instance is None:
        _instance = ARPProtection()
    return _instance
