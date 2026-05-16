"""
GateKeeper - 网络配置管理
管理系统网络接口、路由和DNS配置
"""

import subprocess
import re
import threading
from typing import Dict, List, Optional, Any
from pathlib import Path

from config.settings import settings
from config.logging_config import get_logger

logger = get_logger("network_config")


class NetworkConfigManager:
    """
    网络配置管理器
    管理网络接口、IP地址、路由和DNS配置
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._interfaces_cache: Optional[Dict] = None
        self._cache_time: float = 0
        self._cache_ttl = 30  # 缓存有效期（秒）

        logger.info("网络配置管理器初始化完成")

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """
        获取所有网络接口信息

        Returns:
            接口信息列表
        """
        import time
        now = time.time()

        # 检查缓存
        if self._interfaces_cache and (now - self._cache_time) < self._cache_ttl:
            return list(self._interfaces_cache.values())

        interfaces = []

        try:
            # 使用 /proc/net/dev 获取接口列表
            result = subprocess.run(
                ["cat", "/proc/net/dev"],
                capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[2:]  # 跳过前两行标题
                for line in lines:
                    parts = line.split()
                    if not parts:
                        continue
                    iface_name = parts[0].rstrip(":")
                    if iface_name == "lo":
                        continue

                    rx_bytes = int(parts[1])
                    tx_bytes = int(parts[9])
                    rx_packets = int(parts[2])
                    tx_packets = int(parts[10])

                    # 获取IP地址
                    ip_info = self._get_interface_ip(iface_name)

                    interfaces.append({
                        "name": iface_name,
                        "ip_address": ip_info.get("ip", ""),
                        "netmask": ip_info.get("netmask", ""),
                        "mac_address": ip_info.get("mac", ""),
                        "is_up": ip_info.get("is_up", False),
                        "rx_bytes": rx_bytes,
                        "tx_bytes": tx_bytes,
                        "rx_packets": rx_packets,
                        "tx_packets": tx_packets,
                    })

        except Exception as e:
            logger.error("获取网络接口失败: {}".format(e))

        # 更新缓存
        self._interfaces_cache = {i["name"]: i for i in interfaces}
        self._cache_time = now

        return interfaces

    def _get_interface_ip(self, iface_name: str) -> Dict[str, str]:
        """获取指定接口的IP信息"""
        info = {"ip": "", "netmask": "", "mac": "", "is_up": False}

        try:
            # 获取IP地址
            result = subprocess.run(
                ["ip", "-4", "addr", "show", iface_name],
                capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                output = result.stdout
                if "UP" in output.split("\n")[0]:
                    info["is_up"] = True

                # 提取IP地址
                ip_match = re.search(
                    r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)",
                    output
                )
                if ip_match:
                    ip_cidr = ip_match.group(1)
                    ip_parts = ip_cidr.split("/")
                    info["ip"] = ip_parts[0]
                    prefix = int(ip_parts[1])
                    info["netmask"] = self._prefix_to_netmask(prefix)

                # 提取MAC地址
                mac_match = re.search(
                    r"link/ether\s+([0-9a-fA-F:]{17})",
                    output
                )
                if mac_match:
                    info["mac"] = mac_match.group(1)

        except Exception as e:
            logger.debug("获取接口 {} IP信息失败: {}".format(iface_name, e))

        return info

    def _prefix_to_netmask(self, prefix: int) -> str:
        """将CIDR前缀转换为子网掩码"""
        if prefix == 0:
            return "0.0.0.0"
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return "{}.{}.{}.{}".format((mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF)

    def get_interface_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """根据名称获取接口信息"""
        interfaces = self.get_interfaces()
        for iface in interfaces:
            if iface["name"] == name:
                return iface
        return None

    def set_interface_up(self, iface_name: str) -> Dict[str, Any]:
        """启用网络接口"""
        try:
            result = subprocess.run(
                ["ip", "link", "set", iface_name, "up"],
                capture_output=True, text=True, timeout=10,
                check=True,
            )
            self._invalidate_cache()
            logger.info("启用网络接口: {}".format(iface_name))
            return {"status": "ok", "interface": iface_name}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def set_interface_down(self, iface_name: str) -> Dict[str, Any]:
        """禁用网络接口"""
        try:
            result = subprocess.run(
                ["ip", "link", "set", iface_name, "down"],
                capture_output=True, text=True, timeout=10,
                check=True,
            )
            self._invalidate_cache()
            logger.info("禁用网络接口: {}".format(iface_name))
            return {"status": "ok", "interface": iface_name}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def set_interface_promisc(self, iface_name: str, enable: bool = True) -> Dict[str, Any]:
        """设置接口混杂模式"""
        mode = "promisc" if enable else "-promisc"
        try:
            result = subprocess.run(
                ["ip", "link", "set", iface_name, mode],
                capture_output=True, text=True, timeout=10,
                check=True,
            )
            self._invalidate_cache()
            logger.info("设置接口 {} 混杂模式: {}".format(iface_name, '开启' if enable else '关闭'))
            return {"status": "ok", "interface": iface_name, "promisc": enable}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_routing_table(self) -> List[Dict[str, str]]:
        """获取路由表"""
        routes = []
        try:
            result = subprocess.run(
                ["ip", "route"],
                capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if not line.strip():
                        continue
                    parts = line.split()
                    route = {
                        "destination": parts[0] if parts else "",
                        "gateway": "",
                        "interface": "",
                        "metric": "",
                    }
                    for i, part in enumerate(parts):
                        if part == "via" and i + 1 < len(parts):
                            route["gateway"] = parts[i + 1]
                        elif part == "dev" and i + 1 < len(parts):
                            route["interface"] = parts[i + 1]
                        elif part == "metric" and i + 1 < len(parts):
                            route["metric"] = parts[i + 1]
                    routes.append(route)

        except Exception as e:
            logger.error("获取路由表失败: {}".format(e))

        return routes

    def get_dns_config(self) -> Dict[str, Any]:
        """获取DNS配置"""
        dns_info = {"nameservers": [], "search": [], "domain": ""}

        # 读取 /etc/resolv.conf
        resolv_conf = Path("/etc/resolv.conf")
        if resolv_conf.exists():
            try:
                content = resolv_conf.read_text()
                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith("nameserver"):
                        dns_info["nameservers"].append(line.split()[1])
                    elif line.startswith("search"):
                        dns_info["search"] = line.split()[1:]
                    elif line.startswith("domain"):
                        dns_info["domain"] = line.split()[1] if len(line.split()) > 1 else ""
            except Exception as e:
                logger.error("读取DNS配置失败: {}".format(e))

        return dns_info

    def get_network_stats(self) -> Dict[str, Any]:
        """获取网络统计信息"""
        interfaces = self.get_interfaces()

        total_rx = sum(i["rx_bytes"] for i in interfaces)
        total_tx = sum(i["tx_bytes"] for i in interfaces)
        total_rx_packets = sum(i["rx_packets"] for i in interfaces)
        total_tx_packets = sum(i["tx_packets"] for i in interfaces)

        return {
            "interfaces": interfaces,
            "total_rx_bytes": total_rx,
            "total_tx_bytes": total_tx,
            "total_rx_packets": total_rx_packets,
            "total_tx_packets": total_tx_packets,
            "interface_count": len(interfaces),
        }

    def _invalidate_cache(self):
        """使接口缓存失效"""
        self._interfaces_cache = None
        self._cache_time = 0

    def configure_interface(self, name: str, ip_address: str = "", netmask: str = "",
                            gateway: str = "", dns: List[str] = None, mtu: int = 1500,
                            description: str = "", enabled: bool = True) -> Dict[str, Any]:
        """
        配置网络接口

        Args:
            name: 接口名称
            ip_address: IP地址
            netmask: 子网掩码或CIDR前缀
            gateway: 默认网关
            dns: DNS服务器列表
            mtu: MTU值
            description: 接口描述
            enabled: 是否启用

        Returns:
            配置结果
        """
        try:
            with self._lock:
                # 启用/禁用接口
                if enabled:
                    self.set_interface_up(name)
                else:
                    self.set_interface_down(name)

                # 配置IP地址（如果提供）
                if ip_address:
                    # 清除现有IP
                    subprocess.run(
                        ["ip", "addr", "flush", "dev", name],
                        capture_output=True, timeout=10, check=False
                    )
                    # 添加新IP
                    if "/" in netmask:
                        cidr = netmask
                    else:
                        # 转换子网掩码为CIDR
                        prefix = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                        cidr = "{}/{}".format(ip_address, prefix)
                    
                    subprocess.run(
                        ["ip", "addr", "add", cidr, "dev", name],
                        capture_output=True, timeout=10, check=True
                    )

                # 配置MTU
                if mtu:
                    subprocess.run(
                        ["ip", "link", "set", "dev", name, "mtu", str(mtu)],
                        capture_output=True, timeout=10, check=True
                    )

                # 配置网关（如果提供）
                if gateway:
                    # 删除现有默认路由
                    subprocess.run(
                        ["ip", "route", "del", "default"],
                        capture_output=True, timeout=10, check=False
                    )
                    # 添加新默认路由
                    subprocess.run(
                        ["ip", "route", "add", "default", "via", gateway],
                        capture_output=True, timeout=10, check=True
                    )

                # 配置DNS（如果提供）
                if dns:
                    self._update_dns_config(dns)

                self._invalidate_cache()
                logger.info("配置网络接口 {} 成功".format(name))
                return {"status": "ok", "interface": name}

        except Exception as e:
            logger.error("配置网络接口 {} 失败: {}".format(name, e))
            return {"status": "error", "message": str(e)}

    def add_route(self, target: str, netmask: str, gateway: str) -> Dict[str, Any]:
        """
        添加静态路由

        Args:
            target: 目标网络
            netmask: 子网掩码
            gateway: 网关地址

        Returns:
            添加结果
        """
        try:
            with self._lock:
                # 构建CIDR表示
                if "/" in netmask:
                    cidr = "{}/{}".format(target, netmask.replace("/", ""))
                else:
                    prefix = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                    cidr = "{}/{}".format(target, prefix)

                subprocess.run(
                    ["ip", "route", "add", cidr, "via", gateway],
                    capture_output=True, timeout=10, check=True
                )

                logger.info("添加静态路由: {} via {}".format(cidr, gateway))
                return {"status": "ok", "route": "{} via {}".format(cidr, gateway)}

        except Exception as e:
            logger.error("添加静态路由失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def update_dns(self, dns_servers: List[str]) -> Dict[str, Any]:
        """
        更新DNS配置

        Args:
            dns_servers: DNS服务器列表

        Returns:
            更新结果
        """
        try:
            return self._update_dns_config(dns_servers)
        except Exception as e:
            logger.error("更新DNS配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def _update_dns_config(self, dns_servers: List[str]) -> Dict[str, Any]:
        """内部方法：更新DNS配置文件"""
        try:
            resolv_conf = Path("/etc/resolv.conf")
            
            # 读取现有内容（保留search和domain）
            search_lines = []
            if resolv_conf.exists():
                content = resolv_conf.read_text()
                for line in content.split("\n"):
                    if line.strip().startswith("search") or line.strip().startswith("domain"):
                        search_lines.append(line.strip())

            # 写入新配置
            with open("/etc/resolv.conf", "w") as f:
                f.write("# Generated by GateKeeper\n")
                for line in search_lines:
                    f.write(line + "\n")
                for dns in dns_servers:
                    f.write("nameserver {}\n".format(dns))

            logger.info("更新DNS配置: {}".format(dns_servers))
            return {"status": "ok", "nameservers": dns_servers}

        except Exception as e:
            logger.error("更新DNS配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}
