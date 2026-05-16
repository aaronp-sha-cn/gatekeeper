"""
GateKeeper - 网关管理模块
实现NAT转发、DHCP服务器、DNS转发等网关功能
支持多IP地址段和VLAN绑定
支持将系统部署为网络出口防火墙
"""

import subprocess
import threading
import socket
import struct
import time
import os
import re
import ipaddress
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

from config.logging_config import get_logger
from core.database import db_manager
from core.models import DHCPSubnet, DHCPLease

logger = get_logger("gateway")


class NATType(str, Enum):
    """NAT类型枚举"""
    MASQUERADE = "masquerade"  # 动态NAT（拨号上网）
    SNAT = "snat"              # 静态源NAT
    DNAT = "dnat"              # 目的NAT（端口转发）


class WANMode(str, Enum):
    """WAN连接方式枚举"""
    DHCP = "dhcp"              # DHCP自动获取
    PPPOE = "pppoe"            # PPPoE拨号
    STATIC = "static"          # 静态IP


@dataclass
class WANConfig:
    """WAN连接配置"""
    mode: WANMode = WANMode.DHCP
    interface: str = "eth0"           # 物理接口
    pppoe_interface: str = "ppp0"     # PPPoE虚拟接口
    # 静态IP参数
    static_ip: str = ""
    static_netmask: str = "255.255.255.0"
    static_gateway: str = ""
    static_dns: List[str] = field(default_factory=list)
    # PPPoE参数
    pppoe_username: str = ""
    pppoe_password: str = ""
    pppoe_mtu: int = 1492
    pppoe_auto_reconnect: bool = True
    # 连接状态
    is_connected: bool = False
    current_ip: str = ""
    gateway_ip: str = ""
    dns_servers: List[str] = field(default_factory=list)
    connect_time: Optional[datetime] = None
    error_message: str = ""


@dataclass
class NATRule:
    """NAT规则"""
    name: str
    nat_type: NATType
    out_interface: Optional[str] = None      # 出接口（MASQUERADE）
    source_network: Optional[str] = None     # 源网络（SNAT）
    to_source: Optional[str] = None          # SNAT目标IP
    protocol: Optional[str] = None            # 协议（DNAT）
    dest_port: Optional[int] = None           # 目标端口（DNAT）
    to_destination: Optional[str] = None     # DNAT目标地址
    is_enabled: bool = True


@dataclass
class DHCPLease:
    """DHCP租约"""
    mac_address: str
    ip_address: str
    hostname: str
    lease_start: datetime
    lease_duration: int  # 秒


@dataclass
class GatewayConfig:
    """网关配置"""
    enabled: bool = False
    wan_interface: str = "eth0"
    lan_interface: str = "eth1"
    lan_network: str = "192.168.1.0/24"
    lan_gateway: str = "192.168.1.1"
    dhcp_enabled: bool = True
    dhcp_start: str = "192.168.1.100"
    dhcp_end: str = "192.168.1.200"
    dhcp_lease_time: int = 86400  # 24小时
    dns_enabled: bool = True
    dns_upstream: List[str] = field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])


class GatewayManager:
    """网关管理器"""

    def __init__(self):
        self._config = GatewayConfig()
        self._wan_config = WANConfig()
        self._nat_rules: Dict[str, NATRule] = {}
        self._dhcp_leases: Dict[str, DHCPLease] = {}
        self._running = False
        self._dhcp_thread: Optional[threading.Thread] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._pppoe_monitor_thread: Optional[threading.Thread] = None
        self._pppoe_monitor_stop = threading.Event()
        self._lock = threading.Lock()

        # DHCP服务器状态
        self._dhcp_socket: Optional[socket.socket] = None

        logger.info("网关管理器初始化完成")

    @property
    def config(self) -> GatewayConfig:
        return self._config

    @property
    def is_running(self) -> bool:
        return self._running

    # ============================================================
    # 网关启用/禁用
    # ============================================================

    def enable_gateway(self, wan_interface: str, lan_interface: str,
                       lan_network: str = "192.168.1.0/24") -> bool:
        """
        启用网关模式
        配置IP转发和NAT
        """
        try:
            self._config.wan_interface = wan_interface
            self._config.lan_interface = lan_interface
            self._config.lan_network = lan_network

            # 1. 启用IP转发
            self._enable_ip_forward()

            # 2. 配置LAN接口IP
            gateway_ip = lan_network.rsplit('.', 1)[0] + '.1'
            self._config.lan_gateway = gateway_ip
            self._configure_lan_interface(lan_interface, gateway_ip)

            # 3. 配置NAT（MASQUERADE）
            self._setup_nat(wan_interface, lan_network)

            # 4. 启动DHCP服务器（如果启用）
            if self._config.dhcp_enabled:
                self._start_dhcp_server()

            # 5. 启动DNS转发（如果启用）
            if self._config.dns_enabled:
                self._start_dns_forwarder()

            self._config.enabled = True
            self._running = True

            logger.info(f"网关模式已启用: WAN={wan_interface}, LAN={lan_interface}, 网络={lan_network}")
            return True

        except Exception as e:
            logger.error(f"启用网关失败: {e}")
            return False

    def disable_gateway(self) -> bool:
        """禁用网关模式"""
        try:
            # 停止DHCP
            self._stop_dhcp_server()

            # 停止DNS
            self._stop_dns_forwarder()

            # 清除NAT规则
            self._clear_nat()

            # 禁用IP转发
            self._disable_ip_forward()

            self._config.enabled = False
            self._running = False

            logger.info("网关模式已禁用")
            return True

        except Exception as e:
            logger.error(f"禁用网关失败: {e}")
            return False

    # ============================================================
    # WAN上联接口管理（DHCP / PPPoE / 静态IP）
    # ============================================================

    @property
    def wan_config(self) -> WANConfig:
        return self._wan_config

    def configure_wan(self, mode: str, interface: str = "eth0",
                      static_ip: str = "", static_netmask: str = "255.255.255.0",
                      static_gateway: str = "", static_dns: List[str] = None,
                      pppoe_username: str = "", pppoe_password: str = "",
                      pppoe_mtu: int = 1492) -> Dict:
        """
        配置WAN上联接口连接方式
        
        Args:
            mode: 连接方式 (dhcp / pppoe / static)
            interface: 物理接口名
            static_ip: 静态IP地址
            static_netmask: 子网掩码
            static_gateway: 网关地址
            static_dns: DNS服务器列表
            pppoe_username: PPPoE用户名
            pppoe_password: PPPoE密码
            pppoe_mtu: PPPoE MTU
            
        Returns:
            {"success": bool, "message": str}
        """
        try:
            wan_mode = WANMode(mode.lower())
        except ValueError:
            return {"success": False, "message": "不支持的连接方式: {}，可选: dhcp, pppoe, static".format(mode)}

        self._wan_config.mode = wan_mode
        self._wan_config.interface = interface
        self._wan_config.static_ip = static_ip
        self._wan_config.static_netmask = static_netmask
        self._wan_config.static_gateway = static_gateway
        self._wan_config.static_dns = static_dns or []
        self._wan_config.pppoe_username = pppoe_username
        self._wan_config.pppoe_password = pppoe_password
        self._wan_config.pppoe_mtu = pppoe_mtu

        logger.info(f"WAN配置已更新: mode={wan_mode.value}, interface={interface}")
        return {"success": True, "message": "WAN配置已保存"}

    def connect_wan(self) -> Dict:
        """
        根据配置连接WAN接口
        
        Returns:
            {"success": bool, "message": str, "ip": str}
        """
        # 先断开现有连接
        self.disconnect_wan()

        mode = self._wan_config.mode

        if mode == WANMode.DHCP:
            return self._connect_wan_dhcp()
        elif mode == WANMode.PPPOE:
            return self._connect_wan_pppoe()
        elif mode == WANMode.STATIC:
            return self._connect_wan_static()
        else:
            return {"success": False, "message": "未知的连接方式"}

    def disconnect_wan(self) -> Dict:
        """断开WAN连接"""
        try:
            # 停止PPPoE监控
            self._pppoe_monitor_stop.set()
            if self._pppoe_monitor_thread and self._pppoe_monitor_thread.is_alive():
                self._pppoe_monitor_thread.join(timeout=5)

            # 停止PPPoE连接
            subprocess.run(["poff", "gatekeeper-pppoe"], capture_output=True, timeout=10)

            # 释放DHCP
            subprocess.run(["dhclient", "-r", self._wan_config.interface],
                          capture_output=True, timeout=10)

            # 删除静态IP
            subprocess.run(["ip", "addr", "flush", "dev", self._wan_config.interface],
                          capture_output=True)

            # 删除默认路由
            subprocess.run(["ip", "route", "del", "default"],
                          capture_output=True)

            self._wan_config.is_connected = False
            self._wan_config.current_ip = ""
            self._wan_config.gateway_ip = ""

            logger.info("WAN连接已断开")
            return {"success": True, "message": "WAN已断开"}

        except Exception as e:
            logger.error(f"断开WAN失败: {e}")
            return {"success": False, "message": f"断开失败: {e}"}

    def _connect_wan_dhcp(self) -> Dict:
        """通过DHCP获取WAN IP"""
        try:
            iface = self._wan_config.interface

            # 确保接口UP
            subprocess.run(["ip", "link", "set", iface, "up"], check=True, capture_output=True)
            time.sleep(2)

            # 释放旧租约
            subprocess.run(["dhclient", "-r", iface], capture_output=True, timeout=10)
            time.sleep(1)

            # 获取新租约
            result = subprocess.run(
                ["dhclient", "-v", "-1", iface],
                capture_output=True, text=True, timeout=30
            )

            # 等待获取IP
            time.sleep(3)

            # 读取获取到的IP
            ip_info = self._get_interface_ip(iface)

            if ip_info:
                self._wan_config.is_connected = True
                self._wan_config.current_ip = ip_info["ip"]
                self._wan_config.connect_time = datetime.now()

                # 获取网关
                gw = self._get_default_gateway()
                self._wan_config.gateway_ip = gw

                # 获取DNS
                self._wan_config.dns_servers = self._get_system_dns()

                logger.info(f"WAN DHCP连接成功: IP={ip_info['ip']}, GW={gw}")
                return {"success": True, "message": "DHCP连接成功", "ip": ip_info["ip"]}
            else:
                self._wan_config.error_message = "DHCP获取IP超时"
                logger.error("WAN DHCP获取IP失败")
                return {"success": False, "message": "DHCP获取IP失败，请检查网络连接"}

        except subprocess.TimeoutExpired:
            return {"success": False, "message": "DHCP获取IP超时"}
        except Exception as e:
            logger.error(f"WAN DHCP连接失败: {e}")
            return {"success": False, "message": f"DHCP连接失败: {e}"}

    def _connect_wan_pppoe(self) -> Dict:
        """通过PPPoE拨号连接WAN"""
        try:
            iface = self._wan_config.interface
            username = self._wan_config.pppoe_username
            password = self._wan_config.pppoe_password
            mtu = self._wan_config.pppoe_mtu

            if not username or not password:
                return {"success": False, "message": "PPPoE用户名和密码不能为空"}

            # 检查pppd是否安装
            result = subprocess.run(["which", "pppd"], capture_output=True)
            if result.returncode != 0:
                return {"success": False, "message": "pppd未安装，请执行: apt install pppoeconf ppp"}

            # 确保物理接口UP
            subprocess.run(["ip", "link", "set", iface, "up"], check=True, capture_output=True)
            time.sleep(2)

            # 生成PPPoE配置文件
            pppoe_conf = self._generate_pppoe_config(iface, username, password, mtu)
            chap_secrets = "{} * {} *".format(username, password)

            # 写入配置文件
            peers_dir = "/etc/ppp/peers"
            os.makedirs(peers_dir, exist_ok=True)

            with open(f"{peers_dir}/gatekeeper-pppoe", "w") as f:
                f.write(pppoe_conf)

            # 写入认证文件
            with open("/etc/ppp/chap-secrets", "w") as f:
                f.write(chap_secrets + "\n")
            with open("/etc/ppp/pap-secrets", "w") as f:
                f.write(chap_secrets + "\n")

            # 设置权限
            os.chmod("/etc/ppp/chap-secrets", 0o600)
            os.chmod("/etc/ppp/pap-secrets", 0o600)

            # 启动PPPoE连接
            result = subprocess.run(
                ["pon", "gatekeeper-pppoe"],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                self._wan_config.error_message = "PPPoE拨号启动失败"
                return {"success": False, "message": f"PPPoE拨号启动失败: {result.stderr}"}

            # 等待连接建立（最多30秒）
            ppp_iface = self._wan_config.pppoe_interface
            for i in range(30):
                time.sleep(1)
                ip_info = self._get_interface_ip(ppp_iface)
                if ip_info:
                    self._wan_config.is_connected = True
                    self._wan_config.current_ip = ip_info["ip"]
                    self._wan_config.connect_time = datetime.now()
                    self._wan_config.gateway_ip = self._get_default_gateway()
                    self._wan_config.dns_servers = self._get_system_dns()

                    # 启动PPPoE监控线程
                    self._start_pppoe_monitor()

                    logger.info(f"WAN PPPoE连接成功: IP={ip_info['ip']}")
                    return {"success": True, "message": "PPPoE拨号成功", "ip": ip_info["ip"]}

            self._wan_config.error_message = "PPPoE拨号超时"
            return {"success": False, "message": "PPPoE拨号超时，请检查用户名密码和网络连接"}

        except Exception as e:
            logger.error(f"WAN PPPoE连接失败: {e}")
            return {"success": False, "message": f"PPPoE连接失败: {e}"}

    def _connect_wan_static(self) -> Dict:
        """配置静态IP连接WAN"""
        try:
            iface = self._wan_config.interface
            ip = self._wan_config.static_ip
            netmask = self._wan_config.static_netmask
            gateway = self._wan_config.static_gateway

            if not ip or not gateway:
                return {"success": False, "message": "静态IP和网关不能为空"}

            # 计算CIDR前缀长度
            cidr = self._netmask_to_cidr(netmask)

            # 清除旧IP
            subprocess.run(["ip", "addr", "flush", "dev", iface], capture_output=True)

            # 配置IP地址
            subprocess.run([
                "ip", "addr", "add", f"{ip}/{cidr}", "dev", iface
            ], check=True, capture_output=True)

            # 启用接口
            subprocess.run(["ip", "link", "set", iface, "up"], check=True, capture_output=True)

            # 删除旧默认路由
            subprocess.run(["ip", "route", "del", "default"], capture_output=True)

            # 添加默认路由
            subprocess.run([
                "ip", "route", "add", "default", "via", gateway
            ], check=True, capture_output=True)

            # 配置DNS
            if self._wan_config.static_dns:
                self._set_system_dns(self._wan_config.static_dns)

            self._wan_config.is_connected = True
            self._wan_config.current_ip = ip
            self._wan_config.gateway_ip = gateway
            self._wan_config.dns_servers = self._wan_config.static_dns
            self._wan_config.connect_time = datetime.now()

            logger.info(f"WAN静态IP配置成功: IP={ip}/{cidr}, GW={gateway}")
            return {"success": True, "message": "静态IP配置成功", "ip": ip}

        except subprocess.CalledProcessError as e:
            self._wan_config.error_message = "静态IP配置失败"
            return {"success": False, "message": f"静态IP配置失败: {e}"}
        except Exception as e:
            logger.error(f"WAN静态IP配置失败: {e}")
            return {"success": False, "message": f"配置失败: {e}"}

    def _generate_pppoe_config(self, interface: str, username: str,
                                password: str, mtu: int) -> str:
        """生成PPPoE配置文件内容"""
        return f"""# GateKeeper PPPoE Configuration
# 自动生成 - 请勿手动修改

# 接口
plugin rp-pppoe.so {interface}

# 认证
name "{username}"
hide-password

# 网络参数
mtu {mtu}
mru {mtu}
noipdefault
defaultroute
replacedefaultroute

# DNS
usepeerdns

# 连接参数
persist
maxfail 5
holdoff 20
lcp-echo-interval 20
lcp-echo-failure 3

# 其他
noauth
nodefaultroute
nobsdcomp
nodeflate
"""

    def _start_pppoe_monitor(self):
        """启动PPPoE连接监控线程"""
        self._pppoe_monitor_stop.clear()
        self._pppoe_monitor_thread = threading.Thread(
            target=self._pppoe_monitor_loop,
            daemon=True
        )
        self._pppoe_monitor_thread.start()
        logger.info("PPPoE监控线程已启动")

    def _pppoe_monitor_loop(self):
        """PPPoE连接监控循环"""
        ppp_iface = self._wan_config.pppoe_interface
        while not self._pppoe_monitor_stop.is_set():
            try:
                ip_info = self._get_interface_ip(ppp_iface)
                if ip_info:
                    if not self._wan_config.is_connected:
                        self._wan_config.is_connected = True
                        self._wan_config.current_ip = ip_info["ip"]
                        self._wan_config.connect_time = datetime.now()
                        self._wan_config.gateway_ip = self._get_default_gateway()
                        logger.info(f"PPPoE连接恢复: IP={ip_info['ip']}")
                else:
                    if self._wan_config.is_connected:
                        self._wan_config.is_connected = False
                        self._wan_config.current_ip = ""
                        self._wan_config.error_message = "PPPoE连接断开"
                        logger.warning("PPPoE连接已断开")

                        # 自动重连
                        if self._wan_config.pppoe_auto_reconnect:
                            logger.info("尝试PPPoE自动重连...")
                            subprocess.run(["poff", "gatekeeper-pppoe"], capture_output=True)
                            time.sleep(5)
                            subprocess.run(["pon", "gatekeeper-pppoe"], capture_output=True)

            except Exception as e:
                logger.debug(f"PPPoE监控异常: {e}")

            self._pppoe_monitor_stop.wait(10)

    def get_wan_status(self) -> Dict:
        """获取WAN连接状态"""
        wc = self._wan_config

        # 实时检查连接状态
        if wc.mode == WANMode.PPPOE:
            ip_info = self._get_interface_ip(wc.pppoe_interface)
            wc.is_connected = bool(ip_info)
            if ip_info:
                wc.current_ip = ip_info["ip"]
        elif wc.mode == WANMode.DHCP:
            ip_info = self._get_interface_ip(wc.interface)
            wc.is_connected = bool(ip_info)
            if ip_info:
                wc.current_ip = ip_info["ip"]
        elif wc.mode == WANMode.STATIC:
            ip_info = self._get_interface_ip(wc.interface)
            wc.is_connected = bool(ip_info)

        return {
            "mode": wc.mode.value,
            "interface": wc.interface,
            "pppoe_interface": wc.pppoe_interface,
            "is_connected": wc.is_connected,
            "current_ip": wc.current_ip,
            "gateway_ip": self._get_default_gateway(),
            "dns_servers": self._get_system_dns(),
            "connect_time": wc.connect_time.isoformat() if wc.connect_time else None,
            "error_message": wc.error_message,
            "pppoe_username": wc.pppoe_username,
            "pppoe_mtu": wc.pppoe_mtu,
            "pppoe_auto_reconnect": wc.pppoe_auto_reconnect,
            "static_ip": wc.static_ip,
            "static_netmask": wc.static_netmask,
            "static_gateway": wc.static_gateway,
        }

    def _get_interface_ip(self, interface: str) -> Optional[Dict]:
        """获取接口IP信息"""
        try:
            result = subprocess.run(
                ["ip", "-j", "addr", "show", interface],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout:
                import json
                data = json.loads(result.stdout)
                if data and isinstance(data, list):
                    iface_data = data[0]
                    addr_info = iface_data.get("addr_info", [])
                    if addr_info:
                        return {
                            "ip": addr_info[0].get("local", ""),
                            "prefix": addr_info[0].get("prefixlen", ""),
                        }
        except (subprocess.TimeoutExpired, Exception):
            pass
        return None

    def _get_default_gateway(self) -> str:
        """获取默认网关"""
        try:
            result = subprocess.run(
                ["ip", "-j", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout:
                import json
                data = json.loads(result.stdout)
                if data and isinstance(data, list):
                    return data[0].get("gateway", "")
        except Exception:
            pass
        return ""

    def _get_system_dns(self) -> List[str]:
        """获取系统DNS配置"""
        dns_list = []
        try:
            if os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                dns_list.append(parts[1])
        except Exception:
            pass
        return dns_list

    def _set_system_dns(self, dns_servers: List[str]):
        """设置系统DNS"""
        try:
            content = "# GateKeeper DNS Configuration\n"
            for dns in dns_servers:
                content += f"nameserver {dns}\n"
            with open("/etc/resolv.conf", "w") as f:
                f.write(content)
        except Exception as e:
            logger.error(f"设置DNS失败: {e}")

    def _netmask_to_cidr(self, netmask: str) -> int:
        """子网掩码转CIDR前缀长度"""
        try:
            return sum(bin(int(x)).count('1') for x in netmask.split('.'))
        except Exception:
            return 24

    # ============================================================
    # IP转发
    # ============================================================

    def _enable_ip_forward(self):
        """启用IP转发"""
        # 临时启用
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True, capture_output=True
        )

        # 永久启用
        with open("/etc/sysctl.conf", "a") as f:
            if "net.ipv4.ip_forward" not in open("/etc/sysctl.conf").read():
                f.write("\n# GateKeeper Gateway\nnet.ipv4.ip_forward=1\n")

        logger.info("IP转发已启用")

    def _disable_ip_forward(self):
        """禁用IP转发"""
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=0"],
            check=True, capture_output=True
        )
        logger.info("IP转发已禁用")

    # ============================================================
    # NAT配置（高级）
    # ============================================================

    def _setup_nat(self, wan_interface: str, lan_network: str):
        """配置NAT（MASQUERADE）"""
        # 清除旧的GK NAT规则
        self._clear_nat()

        # 创建自定义链 GK_NAT
        subprocess.run(
            ["iptables", "-t", "nat", "-N", "GK_NAT"],
            capture_output=True
        )
        subprocess.run(
            ["iptables", "-t", "nat", "-N", "GK_DNAT"],
            capture_output=True
        )

        # 添加MASQUERADE规则到自定义链
        subprocess.run([
            "iptables", "-t", "nat", "-A", "GK_NAT",
            "-s", lan_network,
            "-o", wan_interface,
            "-j", "MASQUERADE",
            "-m", "comment", "--comment", "GK_GW_NAT"
        ], check=True, capture_output=True)

        # 将自定义链挂载到POSTROUTING
        subprocess.run([
            "iptables", "-t", "nat", "-I", "POSTROUTING", "1",
            "-j", "GK_NAT"
        ], capture_output=True)

        # 将DNAT链挂载到PREROUTING
        subprocess.run([
            "iptables", "-t", "nat", "-I", "PREROUTING", "1",
            "-j", "GK_DNAT"
        ], capture_output=True)

        # 允许转发流量（使用自定义链）
        subprocess.run(
            ["iptables", "-N", "GK_FWD"],
            capture_output=True
        )
        subprocess.run([
            "iptables", "-I", "FORWARD", "1",
            "-j", "GK_FWD"
        ], capture_output=True)

        subprocess.run([
            "iptables", "-A", "GK_FWD",
            "-s", lan_network,
            "-j", "ACCEPT",
            "-m", "comment", "--comment", "GK_GW_FWD_OUT"
        ], check=True, capture_output=True)

        subprocess.run([
            "iptables", "-A", "GK_FWD",
            "-d", lan_network,
            "-j", "ACCEPT",
            "-m", "comment", "--comment", "GK_GW_FWD_IN"
        ], check=True, capture_output=True)

        # 默认允许已建立连接和相关连接
        subprocess.run([
            "iptables", "-A", "GK_FWD",
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
            "-m", "comment", "--comment", "GK_FWD_CT"
        ], check=True, capture_output=True)

        logger.info(f"NAT已配置(高级): {lan_network} -> {wan_interface}")

    def _clear_nat(self):
        """清除NAT规则（仅清除GK标记的规则，不影响其他配置）"""
        # 清除自定义链引用
        for chain, table in [("GK_NAT", "nat"), ("GK_DNAT", "nat")]:
            subprocess.run(
                ["iptables", "-t", table, "-D", "POSTROUTING", "-j", chain],
                capture_output=True
            )
            subprocess.run(
                ["iptables", "-t", table, "-D", "PREROUTING", "-j", chain],
                capture_output=True
            )
            # 清空并删除自定义链
            subprocess.run(
                ["iptables", "-t", table, "-F", chain],
                capture_output=True
            )
            subprocess.run(
                ["iptables", "-t", table, "-X", chain],
                capture_output=True
            )

        # 清除FORWARD中的GK链
        subprocess.run(
            ["iptables", "-D", "FORWARD", "-j", "GK_FWD"],
            capture_output=True
        )
        subprocess.run(
            ["iptables", "-F", "GK_FWD"],
            capture_output=True
        )
        subprocess.run(
            ["iptables", "-X", "GK_FWD"],
            capture_output=True
        )

        # 清除旧版GK规则（兼容）
        result = subprocess.run(
            ["iptables", "-L", "FORWARD", "-n", "--line-numbers"],
            capture_output=True, text=True
        )
        for line in reversed(result.stdout.split('\n')):
            if "GK_GW" in line:
                parts = line.split()
                if parts:
                    try:
                        num = parts[0]
                        subprocess.run(
                            ["iptables", "-D", "FORWARD", num],
                            capture_output=True
                        )
                    except (ValueError, IndexError):
                        pass

        logger.info("NAT规则已清除")

    # ============================================================
    # NAT高级配置
    # ============================================================

    def get_nat_rules(self) -> List[Dict]:
        """获取所有NAT规则"""
        rules = []
        try:
            # POSTROUTING规则
            result = subprocess.run(
                ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "--line-numbers"],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if "GK" in line or "MASQUERADE" in line or "SNAT" in line:
                    rules.append({"chain": "POSTROUTING", "table": "nat", "raw": line.strip()})

            # PREROUTING规则
            result = subprocess.run(
                ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers"],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if "GK" in line or "DNAT" in line:
                    rules.append({"chain": "PREROUTING", "table": "nat", "raw": line.strip()})

            # FORWARD规则
            result = subprocess.run(
                ["iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers"],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if "GK" in line:
                    rules.append({"chain": "FORWARD", "table": "filter", "raw": line.strip()})

        except Exception as e:
            logger.error(f"获取NAT规则失败: {e}")

        return rules

    def get_nat_config(self) -> Dict:
        """获取当前NAT高级配置"""
        try:
            # 连接跟踪设置
            ct_settings = {}
            sysctl_keys = [
                "net.netfilter.nf_conntrack_max",
                "net.netfilter.nf_conntrack_tcp_timeout_established",
                "net.netfilter.nf_conntrack_tcp_timeout_time_wait",
                "net.netfilter.nf_conntrack_udp_timeout",
                "net.ipv4.netfilter.ip_conntrack_max",
            ]
            for key in sysctl_keys:
                try:
                    result = subprocess.run(
                        ["sysctl", "-n", key],
                        capture_output=True, text=True, timeout=3
                    )
                    if result.returncode == 0:
                        short_key = key.split('.')[-1]
                        ct_settings[short_key] = result.stdout.strip()
                except Exception:
                    pass

            # 当前连接跟踪数
            try:
                with open("/proc/sys/net/netfilter/nf_conntrack_count") as f:
                    ct_count = int(f.read().strip())
                with open("/proc/sys/net/netfilter/nf_conntrack_max") as f:
                    ct_max = int(f.read().strip())
            except (FileNotFoundError, ValueError):
                ct_count = 0
                ct_max = 0

            # SYN代理设置
            syn_proxy = False
            try:
                result = subprocess.run(
                    ["iptables", "-L", "GK_FWD", "-n"],
                    capture_output=True, text=True
                )
                if "SYNPROXY" in result.stdout:
                    syn_proxy = True
            except Exception:
                pass

            return {
                "enabled": self._config.enabled,
                "wan_interface": self._config.wan_interface,
                "lan_interface": self._config.lan_interface,
                "lan_network": self._config.lan_network,
                "conntrack_count": ct_count,
                "conntrack_max": ct_max,
                "conntrack_usage": round(ct_count / ct_max * 100, 1) if ct_max > 0 else 0,
                "conntrack_settings": ct_settings,
                "syn_proxy": syn_proxy,
                "rules_count": len(self.get_nat_rules()),
            }

        except Exception as e:
            logger.error(f"获取NAT配置失败: {e}")
            return {"error": str(e)}

    def set_nat_advanced(self, conntrack_max: int = None,
                         tcp_established_timeout: int = None,
                         tcp_time_wait_timeout: int = None,
                         udp_timeout: int = None,
                         enable_syn_proxy: bool = None,
                         enable_log_dropped: bool = None) -> Dict:
        """
        设置NAT高级参数
        
        Args:
            conntrack_max: 最大连接跟踪数
            tcp_established_timeout: TCP已建立连接超时(秒)
            tcp_time_wait_timeout: TCP TIME_WAIT超时(秒)
            udp_timeout: UDP超时(秒)
            enable_syn_proxy: 启用SYN代理防SYN Flood
            enable_log_dropped: 记录被丢弃的转发包
        """
        changes = []

        try:
            if conntrack_max is not None:
                self._set_sysctl("net.netfilter.nf_conntrack_max", conntrack_max)
                changes.append(f"连接跟踪上限: {conntrack_max}")

            if tcp_established_timeout is not None:
                self._set_sysctl("net.netfilter.nf_conntrack_tcp_timeout_established", tcp_established_timeout)
                changes.append(f"TCP建立超时: {tcp_established_timeout}s")

            if tcp_time_wait_timeout is not None:
                self._set_sysctl("net.netfilter.nf_conntrack_tcp_timeout_time_wait", tcp_time_wait_timeout)
                changes.append(f"TCP TIME_WAIT超时: {tcp_time_wait_timeout}s")

            if udp_timeout is not None:
                self._set_sysctl("net.netfilter.nf_conntrack_udp_timeout", udp_timeout)
                changes.append(f"UDP超时: {udp_timeout}s")

            if enable_syn_proxy is not None:
                if enable_syn_proxy:
                    self._enable_syn_proxy()
                    changes.append("SYN代理: 已启用")
                else:
                    self._disable_syn_proxy()
                    changes.append("SYN代理: 已禁用")

            if enable_log_dropped is not None:
                if enable_log_dropped:
                    self._enable_forward_log()
                    changes.append("转发日志: 已启用")
                else:
                    self._disable_forward_log()
                    changes.append("转发日志: 已禁用")

            logger.info(f"NAT高级配置已更新: {', '.join(changes)}")
            return {"success": True, "message": "配置已更新", "changes": changes}

        except Exception as e:
            logger.error(f"NAT高级配置失败: {e}")
            return {"success": False, "message": f"配置失败: {e}"}

    def _set_sysctl(self, key: str, value):
        """设置sysctl参数（临时+永久）"""
        subprocess.run(
            ["sysctl", "-w", f"{key}={value}"],
            check=True, capture_output=True
        )
        # 写入配置文件
        try:
            conf_file = "/etc/sysctl.d/99-gatekeeper.conf"
            os.makedirs("/etc/sysctl.d", exist_ok=True)
            with open(conf_file, "a") as f:
                f.write(f"{key}={value}\n")
        except Exception:
            pass

    def _enable_syn_proxy(self):
        """启用SYN代理（防SYN Flood攻击）"""
        if not self._config.enabled:
            return
        wan = self._config.wan_interface
        # 在FORWARD链中添加SYN代理规则
        subprocess.run([
            "iptables", "-I", "GK_FWD", "1",
            "-i", wan, "-p", "tcp", "--syn",
            "-m", "conntrack", "--ctstate", "NEW",
            "-j", "SYNPROXY", "--sack-perm", "--timestamp", "--wscale", "6",
            "-m", "comment", "--comment", "GK_SYNPROXY"
        ], capture_output=True)

        # 设置SYN接收队列
        self._set_sysctl("net.ipv4.tcp_syncookies", 1)
        self._set_sysctl("net.ipv4.tcp_max_syn_backlog", 8192)

    def _disable_syn_proxy(self):
        """禁用SYN代理"""
        subprocess.run(
            ["iptables", "-D", "GK_FWD", "-m", "comment", "--comment", "GK_SYNPROXY", "-j", "SYNPROXY"],
            capture_output=True
        )

    def _enable_forward_log(self):
        """启用转发日志"""
        subprocess.run([
            "iptables", "-A", "GK_FWD",
            "-j", "LOG", "--log-prefix", "GK_FWD_DROP: ",
            "--log-level", "4",
            "-m", "comment", "--comment", "GK_FWD_LOG"
        ], capture_output=True)

    def _disable_forward_log(self):
        """禁用转发日志"""
        subprocess.run(
            ["iptables", "-D", "GK_FWD", "-m", "comment", "--comment", "GK_FWD_LOG", "-j", "LOG"],
            capture_output=True
        )

    def add_custom_nat_rule(self, chain: str, rule_spec: str, comment: str = "") -> Dict:
        """
        添加自定义NAT规则
        
        Args:
            chain: POSTROUTING / PREROUTING / FORWARD
            rule_spec: iptables规则参数（不含链名和-j）
            comment: 规则注释
        """
        try:
            chain = chain.upper()
            valid_chains = {"POSTROUTING", "PREROUTING", "FORWARD"}
            if chain not in valid_chains:
                return {"success": False, "message": f"无效链名，可选: {', '.join(valid_chains)}"}

            table = "nat" if chain in ("POSTROUTING", "PREROUTING") else "filter"
            target_chain = f"GK_{chain[:3]}" if chain in ("POSTROUTING", "PREROUTING") else "GK_FWD"

            args = ["iptables", "-t", table, "-A", target_chain]
            args.extend(rule_spec.split())
            if comment:
                args.extend(["-m", "comment", "--comment", f"GK_CUSTOM:{comment}"])

            result = subprocess.run(args, capture_output=True, text=True)
            if result.returncode == 0:
                return {"success": True, "message": "规则已添加"}
            else:
                return {"success": False, "message": f"添加失败: {result.stderr}"}

        except Exception as e:
            return {"success": False, "message": f"添加失败: {e}"}

    def flush_conntrack(self) -> Dict:
        """刷新连接跟踪表"""
        try:
            result = subprocess.run(
                ["conntrack", "-F"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return {"success": True, "message": "连接跟踪表已刷新"}
            else:
                return {"success": False, "message": f"刷新失败(可能未安装conntrack工具): {result.stderr}"}
        except FileNotFoundError:
            # 回退方法：直接写入 /proc/net/nf_conntrack_flush
            try:
                with open("/proc/net/nf_conntrack_flush", "w") as f:
                    f.write("f\n")
                return {"success": True, "message": "连接跟踪表已刷新(回退方法)"}
            except (IOError, PermissionError) as e:
                return {"success": False, "message": "刷新失败(回退方法): {}".format(e)}
        except Exception as e:
            return {"success": False, "message": f"刷新失败: {e}"}

    def add_port_forward(self, name: str, protocol: str, external_port: int,
                         internal_ip: str, internal_port: int) -> bool:
        """
        添加端口转发（DNAT）
        """
        try:
            # DNAT规则
            subprocess.run([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-i", self._config.wan_interface,
                "-p", protocol,
                "--dport", str(external_port),
                "-j", "DNAT",
                "--to-destination", f"{internal_ip}:{internal_port}",
                "-m", "comment", "--comment", f"GK_DNAT_{name}"
            ], check=True, capture_output=True)

            # 允许转发的规则
            subprocess.run([
                "iptables", "-A", "FORWARD",
                "-p", protocol,
                "-d", internal_ip,
                "--dport", str(internal_port),
                "-j", "ACCEPT",
                "-m", "comment", "--comment", f"GK_DNAT_{name}"
            ], check=True, capture_output=True)

            rule = NATRule(
                name=name,
                nat_type=NATType.DNAT,
                protocol=protocol,
                dest_port=external_port,
                to_destination=f"{internal_ip}:{internal_port}"
            )
            self._nat_rules[name] = rule

            logger.info(f"端口转发已添加: {external_port}/{protocol} -> {internal_ip}:{internal_port}")
            return True

        except Exception as e:
            logger.error(f"添加端口转发失败: {e}")
            return False

    def remove_port_forward(self, name: str) -> bool:
        """删除端口转发"""
        if name not in self._nat_rules:
            return False

        try:
            rule = self._nat_rules[name]

            # 删除DNAT规则
            subprocess.run([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-m", "comment", "--comment", f"GK_DNAT_{name}"
            ], capture_output=True)

            # 删除FORWARD规则
            subprocess.run([
                "iptables", "-D", "FORWARD",
                "-m", "comment", "--comment", f"GK_DNAT_{name}"
            ], capture_output=True)

            del self._nat_rules[name]
            logger.info(f"端口转发已删除: {name}")
            return True

        except Exception as e:
            logger.error(f"删除端口转发失败: {e}")
            return False

    # ============================================================
    # LAN接口配置
    # ============================================================

    def _configure_lan_interface(self, interface: str, ip_address: str):
        """配置LAN接口IP地址"""
        subprocess.run([
            "ip", "addr", "add", f"{ip_address}/24", "dev", interface
        ], capture_output=True)

        subprocess.run([
            "ip", "link", "set", interface, "up"
        ], capture_output=True)

        logger.info(f"LAN接口已配置: {interface} -> {ip_address}/24")

    # ============================================================
    # DHCP服务器
    # ============================================================

    def configure_dhcp(self, enabled: bool = True, start_ip: str = "192.168.1.100",
                       end_ip: str = "192.168.1.200", lease_time: int = 86400,
                       dns_servers: List[str] = None):
        """配置DHCP服务器"""
        self._config.dhcp_enabled = enabled
        self._config.dhcp_start = start_ip
        self._config.dhcp_end = end_ip
        self._config.dhcp_lease_time = lease_time
        if dns_servers:
            self._config.dns_upstream = dns_servers

        logger.info(f"DHCP配置已更新: {start_ip}-{end_ip}, 租约{lease_time}秒")

    def _start_dhcp_server(self):
        """启动DHCP服务器（简化版）"""
        # 使用dnsmasq作为DHCP服务器
        config_content = f"""# GateKeeper DHCP Configuration
interface={self._config.lan_interface}
bind-interfaces
dhcp-range={self._config.dhcp_start},{self._config.dhcp_end},{self._config.dhcp_lease_time}
dhcp-option=3,{self._config.lan_gateway}
dhcp-option=6,{','.join(self._config.dns_upstream)}
log-dhcp
"""

        config_path = "/etc/dnsmasq.d/gatekeeper-dhcp.conf"
        os.makedirs("/etc/dnsmasq.d", exist_ok=True)

        with open(config_path, "w") as f:
            f.write(config_content)

        # 重启dnsmasq
        subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)
        subprocess.run(["systemctl", "enable", "dnsmasq"], capture_output=True)

        logger.info("DHCP服务器已启动")

    def _stop_dhcp_server(self):
        """停止DHCP服务器"""
        subprocess.run(["systemctl", "stop", "dnsmasq"], capture_output=True)
        if os.path.exists("/etc/dnsmasq.d/gatekeeper-dhcp.conf"):
            os.remove("/etc/dnsmasq.d/gatekeeper-dhcp.conf")
        logger.info("DHCP服务器已停止")

    def get_dhcp_leases(self) -> List[Dict]:
        """获取DHCP租约列表"""
        leases = []
        lease_file = "/var/lib/misc/dnsmasq.leases"

        if os.path.exists(lease_file):
            with open(lease_file, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        leases.append({
                            "timestamp": int(parts[0]),
                            "mac_address": parts[1],
                            "ip_address": parts[2],
                            "hostname": parts[3] if parts[3] != "*" else "",
                            "client_id": parts[4] if len(parts) > 4 else ""
                        })

        return leases

    # ============================================================
    # 多网段DHCP管理（支持VLAN）
    # ============================================================

    def add_dhcp_subnet(self, name: str, network: str, gateway: str,
                        start_ip: str, end_ip: str, interface: str,
                        vlan_id: Optional[int] = None,
                        lease_time: int = 86400,
                        dns_servers: Optional[List[str]] = None,
                        description: str = "") -> Dict:
        """
        添加DHCP子网配置
        支持多IP地址段和VLAN绑定
        
        Args:
            name: 子网名称（如"办公网"、"访客网"）
            network: 网络地址（如 192.168.1.0/24）
            gateway: 网关地址
            start_ip: DHCP起始IP
            end_ip: DHCP结束IP
            interface: 绑定的网络接口
            vlan_id: VLAN ID (1-4094)，None表示无VLAN
            lease_time: 租约时间（秒）
            dns_servers: DNS服务器列表
            description: 描述
            
        Returns:
            {"success": bool, "message": str, "subnet_id": int}
        """
        try:
            # 验证网络参数
            network_obj = ipaddress.ip_network(network, strict=False)
            
            # 验证IP范围
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            
            if start not in network_obj or end not in network_obj:
                return {"success": False, "message": "IP地址范围不在指定网络内"}
            
            if start > end:
                return {"success": False, "message": "起始IP不能大于结束IP"}
            
            # 验证VLAN ID
            if vlan_id is not None and (vlan_id < 1 or vlan_id > 4094):
                return {"success": False, "message": "VLAN ID必须在1-4094范围内"}
            
            # 检查网络是否已存在
            with db_manager.get_session() as session:
                existing = session.query(DHCPSubnet).filter(
                    DHCPSubnet.network == network
                ).first()
                if existing:
                    return {"success": False, "message": f"网络 {network} 已存在"}
            
            # 创建VLAN接口（如果需要）
            vlan_interface = None
            if vlan_id:
                vlan_interface = f"{interface}.{vlan_id}"
                self._create_vlan_interface(interface, vlan_id)
            
            # 保存到数据库
            with db_manager.get_session() as session:
                subnet = DHCPSubnet(
                    name=name,
                    network=network,
                    gateway=gateway,
                    start_ip=start_ip,
                    end_ip=end_ip,
                    lease_time=lease_time,
                    dns_servers=",".join(dns_servers) if dns_servers else None,
                    interface=interface,
                    vlan_id=vlan_id,
                    vlan_interface=vlan_interface,
                    description=description,
                    is_enabled=True
                )
                session.add(subnet)
                session.commit()
                subnet_id = subnet.id
            
            # 更新dnsmasq配置
            self._update_dnsmasq_config()
            
            logger.info(f"DHCP子网已添加: {name} ({network}), VLAN={vlan_id}")
            return {"success": True, "message": "DHCP子网添加成功", "subnet_id": subnet_id}
            
        except ValueError as e:
            return {"success": False, "message": f"参数错误: {e}"}
        except Exception as e:
            logger.error(f"添加DHCP子网失败: {e}")
            return {"success": False, "message": f"添加失败: {e}"}

    def update_dhcp_subnet(self, subnet_id: int, **kwargs) -> Dict:
        """
        更新DHCP子网配置
        
        Args:
            subnet_id: 子网ID
            **kwargs: 要更新的字段
            
        Returns:
            {"success": bool, "message": str}
        """
        try:
            with db_manager.get_session() as session:
                subnet = session.query(DHCPSubnet).filter(
                    DHCPSubnet.id == subnet_id
                ).first()
                
                if not subnet:
                    return {"success": False, "message": "子网不存在"}
                
                # 更新允许的字段
                allowed_fields = [
                    "name", "gateway", "start_ip", "end_ip",
                    "lease_time", "dns_servers", "is_enabled",
                    "priority", "description"
                ]
                
                for field in allowed_fields:
                    if field in kwargs:
                        if field == "dns_servers" and isinstance(kwargs[field], list):
                            setattr(subnet, field, ",".join(kwargs[field]))
                        else:
                            setattr(subnet, field, kwargs[field])
                
                session.commit()
            
            # 更新dnsmasq配置
            self._update_dnsmasq_config()
            
            logger.info(f"DHCP子网已更新: ID={subnet_id}")
            return {"success": True, "message": "更新成功"}
            
        except Exception as e:
            logger.error(f"更新DHCP子网失败: {e}")
            return {"success": False, "message": f"更新失败: {e}"}

    def delete_dhcp_subnet(self, subnet_id: int) -> Dict:
        """删除DHCP子网配置"""
        try:
            with db_manager.get_session() as session:
                subnet = session.query(DHCPSubnet).filter(
                    DHCPSubnet.id == subnet_id
                ).first()
                
                if not subnet:
                    return {"success": False, "message": "子网不存在"}
                
                vlan_interface = subnet.vlan_interface
                vlan_id = subnet.vlan_id
                
                # 删除相关租约
                session.query(DHCPLease).filter(
                    DHCPLease.subnet_id == subnet_id
                ).delete()
                
                # 删除子网
                session.delete(subnet)
                session.commit()
            
            # 删除VLAN接口（如果没有其他子网使用）
            if vlan_interface and vlan_id:
                self._remove_vlan_interface(vlan_interface)
            
            # 更新dnsmasq配置
            self._update_dnsmasq_config()
            
            logger.info(f"DHCP子网已删除: ID={subnet_id}")
            return {"success": True, "message": "删除成功"}
            
        except Exception as e:
            logger.error(f"删除DHCP子网失败: {e}")
            return {"success": False, "message": f"删除失败: {e}"}

    def get_dhcp_subnets(self) -> List[Dict]:
        """获取所有DHCP子网配置"""
        try:
            with db_manager.get_session() as session:
                subnets = session.query(DHCPSubnet).order_by(
                    DHCPSubnet.priority, DHCPSubnet.id
                ).all()
                
                result = []
                for s in subnets:
                    # 获取该子网的活跃租约数
                    active_leases = session.query(DHCPLease).filter(
                        DHCPLease.subnet_id == s.id,
                        DHCPLease.is_active == True,
                        DHCPLease.lease_end > datetime.now()
                    ).count()
                    
                    result.append({
                        "id": s.id,
                        "name": s.name,
                        "network": s.network,
                        "gateway": s.gateway,
                        "start_ip": s.start_ip,
                        "end_ip": s.end_ip,
                        "lease_time": s.lease_time,
                        "dns_servers": s.dns_servers.split(",") if s.dns_servers else [],
                        "interface": s.interface,
                        "vlan_id": s.vlan_id,
                        "vlan_interface": s.vlan_interface,
                        "is_enabled": s.is_enabled,
                        "priority": s.priority,
                        "description": s.description,
                        "active_leases": active_leases,
                        "created_at": s.created_at.isoformat() if s.created_at else None
                    })
                
                return result
                
        except Exception as e:
            logger.error(f"获取DHCP子网列表失败: {e}")
            return []

    def get_dhcp_subnet(self, subnet_id: int) -> Optional[Dict]:
        """获取单个DHCP子网配置"""
        try:
            with db_manager.get_session() as session:
                subnet = session.query(DHCPSubnet).filter(
                    DHCPSubnet.id == subnet_id
                ).first()
                
                if not subnet:
                    return None
                
                return {
                    "id": subnet.id,
                    "name": subnet.name,
                    "network": subnet.network,
                    "gateway": subnet.gateway,
                    "start_ip": subnet.start_ip,
                    "end_ip": subnet.end_ip,
                    "lease_time": subnet.lease_time,
                    "dns_servers": subnet.dns_servers.split(",") if subnet.dns_servers else [],
                    "interface": subnet.interface,
                    "vlan_id": subnet.vlan_id,
                    "vlan_interface": subnet.vlan_interface,
                    "is_enabled": subnet.is_enabled,
                    "priority": subnet.priority,
                    "description": subnet.description,
                    "created_at": subnet.created_at.isoformat() if subnet.created_at else None
                }
                
        except Exception as e:
            logger.error(f"获取DHCP子网失败: {e}")
            return None

    def _create_vlan_interface(self, interface: str, vlan_id: int):
        """创建VLAN接口"""
        vlan_interface = f"{interface}.{vlan_id}"
        
        try:
            # 检查接口是否已存在
            result = subprocess.run(
                ["ip", "link", "show", vlan_interface],
                capture_output=True
            )
            
            if result.returncode != 0:
                # 创建VLAN接口
                subprocess.run([
                    "ip", "link", "add", "link", interface,
                    "name", vlan_interface,
                    "type", "vlan", "id", str(vlan_id)
                ], check=True, capture_output=True)
                
                # 启用接口
                subprocess.run([
                    "ip", "link", "set", vlan_interface, "up"
                ], check=True, capture_output=True)
                
                logger.info(f"VLAN接口已创建: {vlan_interface}")
            else:
                logger.debug(f"VLAN接口已存在: {vlan_interface}")
                
        except subprocess.CalledProcessError as e:
            logger.error(f"创建VLAN接口失败: {e}")

    def _remove_vlan_interface(self, vlan_interface: str):
        """删除VLAN接口"""
        try:
            subprocess.run([
                "ip", "link", "delete", vlan_interface
            ], capture_output=True)
            
            logger.info(f"VLAN接口已删除: {vlan_interface}")
            
        except Exception as e:
            logger.error(f"删除VLAN接口失败: {e}")

    def _update_dnsmasq_config(self):
        """更新dnsmasq配置文件（支持多网段）"""
        try:
            # 获取所有启用的子网
            with db_manager.get_session() as session:
                subnets = session.query(DHCPSubnet).filter(
                    DHCPSubnet.is_enabled == True
                ).order_by(DHCPSubnet.priority).all()
            
            if not subnets:
                # 没有子网配置，停止DHCP
                self._stop_dhcp_server()
                return
            
            # 构建配置内容
            config_content = "# GateKeeper DHCP Configuration\n"
            config_content += "# 自动生成 - 请勿手动修改\n\n"
            
            # 全局设置
            config_content += "log-dhcp\n"
            config_content += "dhcp-lease-max=4294967295\n\n"
            
            for subnet in subnets:
                # 确定使用的接口
                if subnet.vlan_interface:
                    iface = subnet.vlan_interface
                else:
                    iface = subnet.interface
                
                config_content += f"# 子网: {subnet.name}\n"
                config_content += f"interface={iface}\n"
                
                # DHCP范围
                lease_time_str = self._format_lease_time(subnet.lease_time)
                config_content += f"dhcp-range={iface},{subnet.start_ip},{subnet.end_ip},{lease_time_str}\n"
                
                # 网关选项
                config_content += f"dhcp-option={iface},3,{subnet.gateway}\n"
                
                # DNS选项
                if subnet.dns_servers:
                    dns_list = subnet.dns_servers.replace(",", ",")
                    config_content += f"dhcp-option={iface},6,{dns_list}\n"
                
                config_content += "\n"
            
            # 写入配置文件
            config_path = "/etc/dnsmasq.d/gatekeeper-dhcp.conf"
            os.makedirs("/etc/dnsmasq.d", exist_ok=True)
            
            with open(config_path, "w") as f:
                f.write(config_content)
            
            # 重启dnsmasq
            subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)
            
            logger.info(f"dnsmasq配置已更新，共 {len(subnets)} 个子网")
            
        except Exception as e:
            logger.error(f"更新dnsmasq配置失败: {e}")

    def _format_lease_time(self, seconds: int) -> str:
        """格式化租约时间"""
        if seconds >= 86400:
            return f"{seconds // 3600}h"
        elif seconds >= 3600:
            return f"{seconds // 3600}h"
        elif seconds >= 60:
            return f"{seconds // 60}m"
        else:
            return f"{seconds}s"

    def get_vlan_interfaces(self) -> List[Dict]:
        """获取所有VLAN接口"""
        vlans = []
        try:
            result = subprocess.run(
                ["ip", "-br", "link", "show", "type", "vlan"],
                capture_output=True, text=True
            )
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                    
                parts = line.split()
                if len(parts) >= 2:
                    vlan_info = {
                        "name": parts[0],
                        "status": parts[1],
                    }
                    
                    # 解析VLAN ID
                    if '.' in parts[0]:
                        parent, vid = parts[0].rsplit('.', 1)
                        vlan_info["parent"] = parent
                        vlan_info["vlan_id"] = int(vid) if vid.isdigit() else None
                    
                    vlans.append(vlan_info)
                    
        except Exception as e:
            logger.error(f"获取VLAN接口失败: {e}")
            
        return vlans

    def get_dhcp_statistics(self) -> Dict:
        """获取DHCP统计信息"""
        try:
            with db_manager.get_session() as session:
                # 总子网数
                total_subnets = session.query(DHCPSubnet).count()
                
                # 启用的子网数
                enabled_subnets = session.query(DHCPSubnet).filter(
                    DHCPSubnet.is_enabled == True
                ).count()
                
                # VLAN子网数
                vlan_subnets = session.query(DHCPSubnet).filter(
                    DHCPSubnet.vlan_id != None
                ).count()
                
                # 总租约数
                total_leases = session.query(DHCPLease).count()
                
                # 活跃租约数
                active_leases = session.query(DHCPLease).filter(
                    DHCPLease.is_active == True,
                    DHCPLease.lease_end > datetime.now()
                ).count()
                
                # 各子网统计
                subnet_stats = []
                subnets = session.query(DHCPSubnet).all()
                for subnet in subnets:
                    active = session.query(DHCPLease).filter(
                        DHCPLease.subnet_id == subnet.id,
                        DHCPLease.is_active == True,
                        DHCPLease.lease_end > datetime.now()
                    ).count()
                    
                    # 计算IP池使用率
                    try:
                        start = int(ipaddress.ip_address(subnet.start_ip))
                        end = int(ipaddress.ip_address(subnet.end_ip))
                        pool_size = end - start + 1
                        usage = (active / pool_size * 100) if pool_size > 0 else 0
                    except:
                        usage = 0
                    
                    subnet_stats.append({
                        "id": subnet.id,
                        "name": subnet.name,
                        "network": subnet.network,
                        "vlan_id": subnet.vlan_id,
                        "active_leases": active,
                        "pool_usage": round(usage, 1)
                    })
                
                return {
                    "total_subnets": total_subnets,
                    "enabled_subnets": enabled_subnets,
                    "vlan_subnets": vlan_subnets,
                    "total_leases": total_leases,
                    "active_leases": active_leases,
                    "subnet_stats": subnet_stats
                }
                
        except Exception as e:
            logger.error(f"获取DHCP统计失败: {e}")
            return {
                "total_subnets": 0,
                "enabled_subnets": 0,
                "vlan_subnets": 0,
                "total_leases": 0,
                "active_leases": 0,
                "subnet_stats": []
            }

    # ============================================================
    # DNS转发
    # ============================================================

    def configure_dns(self, enabled: bool = True, upstream: List[str] = None):
        """配置DNS转发"""
        self._config.dns_enabled = enabled
        if upstream:
            self._config.dns_upstream = upstream
        logger.info(f"DNS配置已更新: 上游服务器 {upstream}")

    def _start_dns_forwarder(self):
        """启动DNS转发（使用dnsmasq）"""
        config_content = f"""# GateKeeper DNS Configuration
port=53
bind-interfaces
interface={self._config.lan_interface}
no-resolv
"""

        for dns in self._config.dns_upstream:
            config_content += f"server={dns}\n"

        config_path = "/etc/dnsmasq.d/gatekeeper-dns.conf"
        os.makedirs("/etc/dnsmasq.d", exist_ok=True)

        with open(config_path, "w") as f:
            f.write(config_content)

        subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)
        logger.info("DNS转发已启动")

    def _stop_dns_forwarder(self):
        """停止DNS转发"""
        if os.path.exists("/etc/dnsmasq.d/gatekeeper-dns.conf"):
            os.remove("/etc/dnsmasq.d/gatekeeper-dns.conf")
        logger.info("DNS转发已停止")

    # ============================================================
    # 状态和信息
    # ============================================================

    def get_status(self) -> Dict:
        """获取网关状态"""
        status = {
            "enabled": self._config.enabled,
            "running": self._running,
            "wan_interface": self._config.wan_interface,
            "lan_interface": self._config.lan_interface,
            "lan_network": self._config.lan_network,
            "lan_gateway": self._config.lan_gateway,
            "dhcp": {
                "enabled": self._config.dhcp_enabled,
                "range": f"{self._config.dhcp_start} - {self._config.dhcp_end}",
                "lease_time": self._config.dhcp_lease_time,
                "active_leases": len(self.get_dhcp_leases())
            },
            "dns": {
                "enabled": self._config.dns_enabled,
                "upstream": self._config.dns_upstream
            },
            "nat_rules": len(self._nat_rules),
            "port_forwards": [
                {
                    "name": name,
                    "type": rule.nat_type.value,
                    "external_port": rule.dest_port,
                    "protocol": rule.protocol,
                    "destination": rule.to_destination
                }
                for name, rule in self._nat_rules.items()
                if rule.nat_type == NATType.DNAT
            ]
        }

        # 检查IP转发状态
        try:
            result = subprocess.run(
                ["sysctl", "-n", "net.ipv4.ip_forward"],
                capture_output=True, text=True
            )
            status["ip_forward"] = result.stdout.strip() == "1"
        except:
            status["ip_forward"] = False

        return status

    def get_interfaces(self) -> List[Dict]:
        """获取网络接口列表"""
        interfaces = []
        try:
            result = subprocess.run(
                ["ip", "-br", "addr", "show"],
                capture_output=True, text=True
            )

            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 2:
                    iface = {
                        "name": parts[0],
                        "status": parts[1],
                        "ip": parts[2] if len(parts) > 2 else ""
                    }
                    interfaces.append(iface)

        except Exception as e:
            logger.error(f"获取接口列表失败: {e}")

        return interfaces


# 全局网关管理器实例
_gateway_manager: Optional[GatewayManager] = None
_gateway_manager_lock = threading.Lock()


def get_gateway_manager() -> GatewayManager:
    """获取网关管理器实例（单例）"""
    global _gateway_manager
    if _gateway_manager is None:
        with _gateway_manager_lock:
            if _gateway_manager is None:
                _gateway_manager = GatewayManager()
    return _gateway_manager
