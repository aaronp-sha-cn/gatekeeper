"""
GateKeeper - 透明网桥管理模块
实现Layer 2透明桥接模式，系统对网络透明，安全功能作用于桥接流量
"""

import re
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from config.logging_config import get_logger

logger = get_logger("bridge")


class BridgeMode(Enum):
    """桥接模式"""
    TRANSPARENT = "transparent"  # 纯透明桥接
    ROUTING = "routing"          # 路由模式（默认）


@dataclass
class BridgeConfig:
    """网桥配置"""
    enabled: bool = False
    bridge_name: str = "br0"
    wan_interface: str = "eth0"   # 上联接口（连接外网）
    lan_interface: str = "eth1"   # 下联接口（连接内网）
    mode: BridgeMode = BridgeMode.TRANSPARENT
    
    # 透明模式特性
    intercept_http: bool = True   # 拦截HTTP流量供IDS分析
    intercept_https: bool = False # 拦截HTTPS（需要证书）
    bypass_local: bool = True     # 绕过本机流量


class BridgeManager:
    """透明网桥管理器"""
    
    def __init__(self):
        self._config = BridgeConfig()
        self._running = False
        self._lock = threading.Lock()
        
        # 流量重定向规则标记
        self._iptables_mark = "0x1"
        self._bridge_chain = "GK_BRIDGE"
        
        logger.info("网桥管理器初始化完成")
    
    @property
    def config(self) -> BridgeConfig:
        return self._config
    
    @property
    def is_running(self) -> bool:
        return self._running
    
    # ============================================================
    # 网桥创建/销毁
    # ============================================================
    
    def create_bridge(self, wan_iface: str, lan_iface: str, 
                      bridge_name: str = "br0") -> bool:
        """
        创建透明网桥
        
        Args:
            wan_iface: 上联接口（连接外网/上级网络）
            lan_iface: 下联接口（连接内网设备）
            bridge_name: 网桥名称
        """
        # 验证网桥名称格式
        bridge_name_pattern = r'^[a-zA-Z0-9_\-]+$'
        if not bridge_name or not re.match(bridge_name_pattern, bridge_name):
            logger.error(f"无效的网桥名称: {bridge_name}")
            return False

        # 验证接口名称格式
        iface_pattern = r'^[a-zA-Z0-9_\-]+$'
        if not wan_iface or not re.match(iface_pattern, wan_iface):
            logger.error(f"无效的上联接口名称: {wan_iface}")
            return False
        if not lan_iface or not re.match(iface_pattern, lan_iface):
            logger.error(f"无效的下联接口名称: {lan_iface}")
            return False

        try:
            self._config.wan_interface = wan_iface
            self._config.lan_interface = lan_iface
            self._config.bridge_name = bridge_name
            
            # 1. 创建网桥
            self._run_cmd(["ip", "link", "add", bridge_name, "type", "bridge"])
            
            # 2. 配置网桥（禁用STP，减少延迟）
            self._run_cmd(["ip", "link", "set", bridge_name, "up"])
            self._run_cmd(["sysctl", "-w", f"net.bridge.bridge-nf-call-iptables=1"])
            
            # 3. 将物理接口加入网桥
            # 先关闭接口，加入网桥，再启动
            for iface in [wan_iface, lan_iface]:
                self._run_cmd(["ip", "link", "set", iface, "down"])
                self._run_cmd(["ip", "link", "set", iface, "master", bridge_name])
                self._run_cmd(["ip", "link", "set", iface, "up"])
            
            # 4. 启动网桥
            self._run_cmd(["ip", "link", "set", bridge_name, "up"])
            
            # 5. 配置流量重定向（将桥接流量重定向到IDS）
            self._setup_traffic_redirection(bridge_name)
            
            self._config.enabled = True
            self._running = True
            
            logger.info(f"透明网桥已创建: {bridge_name} ({wan_iface} + {lan_iface})")
            return True
            
        except Exception as e:
            logger.error(f"创建网桥失败: {e}")
            return False
    
    def destroy_bridge(self) -> bool:
        """销毁网桥，恢复原始配置"""
        try:
            bridge = self._config.bridge_name
            wan = self._config.wan_interface
            lan = self._config.lan_interface
            
            # 1. 清除流量重定向规则
            self._clear_traffic_redirection()
            
            # 2. 将接口从网桥移除
            for iface in [wan, lan]:
                try:
                    self._run_cmd(["ip", "link", "set", iface, "down"])
                    self._run_cmd(["ip", "link", "set", iface, "nomaster"])
                    self._run_cmd(["ip", "link", "set", iface, "up"])
                except Exception as e:
                    logger.warning(f"移除接口 {iface} 失败: {e}")
                    pass

            # 3. 删除网桥
            try:
                self._run_cmd(["ip", "link", "set", bridge, "down"])
                self._run_cmd(["ip", "link", "delete", bridge, "type", "bridge"])
            except Exception as e:
                logger.warning(f"删除网桥 {bridge} 失败: {e}")
                pass
            
            self._config.enabled = False
            self._running = False
            
            logger.info("透明网桥已销毁")
            return True
            
        except Exception as e:
            logger.error(f"销毁网桥失败: {e}")
            return False
    
    # ============================================================
    # 流量重定向（透明模式核心）
    # ============================================================
    
    def _setup_traffic_redirection(self, bridge_name: str):
        """
        设置流量重定向规则
        将桥接流量复制/重定向到本地进行安全检测
        """
        # 创建自定义链
        self._run_cmd(["iptables", "-t", "mangle", "-N", self._bridge_chain], check=False)
        
        # 清除旧规则
        self._run_cmd(["iptables", "-t", "mangle", "-F", self._bridge_chain], check=False)
        
        # 1. 标记HTTP流量 (端口80)
        self._run_cmd([
            "iptables", "-t", "mangle", "-A", self._bridge_chain,
            "-p", "tcp", "--dport", "80",
            "-j", "MARK", "--set-mark", self._iptables_mark
        ])
        
        # 2. 标记HTTPS流量 (端口443)
        self._run_cmd([
            "iptables", "-t", "mangle", "-A", self._bridge_chain,
            "-p", "tcp", "--dport", "443",
            "-j", "MARK", "--set-mark", self._iptables_mark
        ])
        
        # 3. 标记所有TCP流量（用于IDS深度检测）
        self._run_cmd([
            "iptables", "-t", "mangle", "-A", self._bridge_chain,
            "-p", "tcp",
            "-j", "MARK", "--set-mark", self._iptables_mark
        ])
        
        # 4. 将规则应用到桥接接口的PREROUTING链
        self._run_cmd([
            "iptables", "-t", "mangle", "-I", "PREROUTING", "1",
            "-i", bridge_name,
            "-j", self._bridge_chain
        ])
        
        # 5. 配置TPROXY（透明代理）用于高级检测
        self._setup_tproxy(bridge_name)
        
        logger.info("流量重定向规则已配置")
    
    def _setup_tproxy(self, bridge_name: str):
        """配置TPROXY透明代理"""
        try:
            # 创建TPROXY路由表
            self._run_cmd(["ip", "rule", "add", "fwmark", self._iptables_mark, "table", "100"], check=False)
            self._run_cmd(["ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100"], check=False)
            
            # TPROXY规则（将标记流量重定向到本地）
            self._run_cmd([
                "iptables", "-t", "mangle", "-A", self._bridge_chain,
                "-m", "mark", "--mark", self._iptables_mark,
                "-j", "TPROXY", "--on-port", "8080", "--tproxy-mark", self._iptables_mark
            ])
            
        except Exception as e:
            logger.warning(f"TPROXY配置警告: {e}")
    
    def _clear_traffic_redirection(self):
        """清除流量重定向规则"""
        try:
            # 清除PREROUTING链中的规则
            self._run_cmd([
                "iptables", "-t", "mangle", "-D", "PREROUTING",
                "-j", self._bridge_chain
            ], check=False)
            
            # 清除并删除自定义链
            self._run_cmd(["iptables", "-t", "mangle", "-F", self._bridge_chain], check=False)
            self._run_cmd(["iptables", "-t", "mangle", "-X", self._bridge_chain], check=False)
            
            # 清除TPROXY路由
            self._run_cmd(["ip", "rule", "del", "fwmark", self._iptables_mark, "table", "100"], check=False)
            
            logger.info("流量重定向规则已清除")
        except Exception as e:
            logger.warning(f"清除重定向规则警告: {e}")
    
    # ============================================================
    # ebtables二层过滤
    # ============================================================
    
    def add_mac_filter(self, mac_address: str, action: str = "DROP") -> bool:
        """
        添加MAC地址过滤（二层）
        
        Args:
            mac_address: MAC地址
            action: DROP/ACCEPT/REJECT
        """
        # 验证MAC地址格式
        mac_pattern = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
        if not re.match(mac_pattern, mac_address):
            logger.error(f"无效的MAC地址格式: {mac_address}")
            return False

        # 验证action白名单
        valid_actions = ("DROP", "ACCEPT", "REJECT")
        if action not in valid_actions:
            logger.error(f"无效的过滤动作: {action}，仅允许: {valid_actions}")
            return False

        try:
            self._run_cmd([
                "ebtables", "-A", "FORWARD",
                "-s", mac_address,
                "-j", action
            ])
            logger.info(f"MAC过滤已添加: {mac_address} -> {action}")
            return True
        except Exception as e:
            logger.error(f"添加MAC过滤失败: {e}")
            return False
    
    def remove_mac_filter(self, mac_address: str) -> bool:
        """移除MAC地址过滤"""
        try:
            self._run_cmd([
                "ebtables", "-D", "FORWARD",
                "-s", mac_address,
                "-j", "DROP"
            ])
            return True
        except Exception as e:
            logger.error(f"移除MAC过滤失败: {e}")
            return False
    
    # ============================================================
    # ARP防护
    # ============================================================
    
    def enable_arp_protection(self) -> bool:
        """启用ARP欺骗防护"""
        try:
            # 启用arp_filter
            self._run_cmd(["sysctl", "-w", "net.ipv4.conf.all.arp_filter=1"])
            
            # ebtables ARP规则
            self._run_cmd([
                "ebtables", "-A", "FORWARD",
                "-p", "ARP", "--arp-op", "Request",
                "-j", "ACCEPT"
            ])
            
            logger.info("ARP防护已启用")
            return True
        except Exception as e:
            logger.error(f"启用ARP防护失败: {e}")
            return False
    
    # ============================================================
    # 状态查询
    # ============================================================
    
    def get_status(self) -> Dict:
        """获取网桥状态"""
        status = {
            "enabled": self._config.enabled,
            "running": self._running,
            "bridge_name": self._config.bridge_name,
            "wan_interface": self._config.wan_interface,
            "lan_interface": self._config.lan_interface,
            "mode": self._config.mode.value,
            "interfaces": []
        }
        
        # 获取网桥接口状态
        if self._config.enabled:
            try:
                result = subprocess.run(
                    ["ip", "link", "show", "master", self._config.bridge_name],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            iface = parts[1].strip()
                            if iface:
                                status["interfaces"].append(iface)
            except Exception as e:
                logger.warning(f"获取网桥接口状态失败: {e}")
                pass

        # 获取网桥统计
        try:
            result = subprocess.run(
                ["cat", f"/sys/class/net/{self._config.bridge_name}/statistics/rx_packets"],
                capture_output=True, text=True, timeout=10
            )
            status["rx_packets"] = int(result.stdout.strip()) if result.returncode == 0 else 0

            result = subprocess.run(
                ["cat", f"/sys/class/net/{self._config.bridge_name}/statistics/tx_packets"],
                capture_output=True, text=True, timeout=10
            )
            status["tx_packets"] = int(result.stdout.strip()) if result.returncode == 0 else 0
        except Exception as e:
            logger.warning(f"获取网桥统计失败: {e}")
            status["rx_packets"] = 0
            status["tx_packets"] = 0
        
        return status
    
    def get_connected_devices(self) -> List[Dict]:
        """获取连接到网桥的设备"""
        devices = []
        
        try:
            # 从ARP表获取
            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.split('\n'):
                if 'lladdr' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        devices.append({
                            "ip": parts[0],
                            "mac": parts[2] if parts[1] == 'lladdr' else parts[4],
                            "interface": parts[-1] if parts[-1] != 'REACHABLE' else parts[-2],
                            "state": parts[-1] if parts[-1] in ['REACHABLE', 'STALE', 'FAILED'] else 'UNKNOWN'
                        })
        except Exception as e:
            logger.error(f"获取连接设备失败: {e}")
        
        return devices
    
    # ============================================================
    # 工具方法
    # ============================================================
    
    def _run_cmd(self, cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """执行系统命令"""
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if check and result.returncode != 0:
            raise RuntimeError(f"命令失败: {' '.join(cmd)} - {result.stderr}")
        return result


# 全局网桥管理器实例
_bridge_manager: Optional[BridgeManager] = None
_bridge_manager_lock = threading.Lock()


def get_bridge_manager() -> BridgeManager:
    """获取网桥管理器实例（单例）"""
    global _bridge_manager
    if _bridge_manager is None:
        with _bridge_manager_lock:
            if _bridge_manager is None:
                _bridge_manager = BridgeManager()
    return _bridge_manager
