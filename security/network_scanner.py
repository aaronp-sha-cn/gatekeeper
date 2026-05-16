"""
GateKeeper - 网络扫描器模块
提供网络资产发现、主机扫描与服务识别功能
"""

import re
import socket
import subprocess
import threading
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Any

from config.logging_config import get_logger

logger = get_logger("network_scanner")

# 常见服务端口映射
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

# 扫描超时设置
PING_TIMEOUT = 3
PORT_SCAN_TIMEOUT = 2
ARP_SCAN_TIMEOUT = 30


class NetworkScanner:
    """网络扫描器 - 网络资产发现与服务识别"""

    def __init__(self):
        """初始化网络扫描器"""
        self._discovered_hosts: Dict[str, dict] = {}
        self._scan_history: List[dict] = []
        self._lock = threading.Lock()
        self._stats = {
            "total_scans": 0,
            "total_hosts_discovered": 0,
            "total_ports_found": 0,
            "last_scan_time": None,
            "scan_errors": 0,
        }
        logger.info("网络扫描器初始化完成")

    def scan_network(self, subnet: str) -> list:
        """
        扫描指定子网，发现活跃主机

        Args:
            subnet: 子网CIDR格式，如 "192.168.1.0/24"

        Returns:
            发现的主机列表，每个元素为包含主机信息的字典
        """
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as e:
            logger.error("无效的子网格式 '{}': {}".format(subnet, e))
            return []

        logger.info("开始扫描子网: {} (共 {} 个地址)".format(subnet, network.num_addresses))

        scan_result = {
            "subnet": subnet,
            "start_time": datetime.now().isoformat(),
            "hosts": [],
        }

        hosts = []
        total = network.num_addresses

        # 使用 ping 扫描发现活跃主机
        for idx, ip in enumerate(network.hosts()):
            ip_str = str(ip)
            if idx % 50 == 0 and idx > 0:
                logger.debug("扫描进度: {}/{}".format(idx, total))

            if self._ping_host(ip_str):
                host_info = self.scan_host(ip_str)
                hosts.append(host_info)

        scan_result["end_time"] = datetime.now().isoformat()
        scan_result["host_count"] = len(hosts)

        with self._lock:
            for host in hosts:
                ip_addr = host.get("ip", "")
                if ip_addr:
                    self._discovered_hosts[ip_addr] = host
            self._scan_history.append(scan_result)
            self._stats["total_scans"] += 1
            self._stats["total_hosts_discovered"] = len(self._discovered_hosts)
            self._stats["last_scan_time"] = datetime.now().isoformat()

        logger.info("子网扫描完成: {}，发现 {} 台活跃主机".format(subnet, len(hosts)))
        return hosts

    def scan_host(self, ip: str) -> dict:
        """
        扫描单个主机，探测开放端口与服务

        Args:
            ip: 目标主机IP地址

        Returns:
            主机信息字典，包含IP、MAC、开放端口等信息
        """
        host_info = {
            "ip": ip,
            "hostname": "",
            "mac": "",
            "vendor": "",
            "open_ports": [],
            "os_guess": "",
            "status": "unknown",
            "last_seen": datetime.now().isoformat(),
        }

        # 尝试反向DNS解析
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            host_info["hostname"] = hostname
        except (socket.herror, socket.gaierror, OSError):
            pass

        # 尝试获取MAC地址（通过ARP表）
        mac = self._get_mac_from_arp(ip)
        if mac:
            host_info["mac"] = mac
            host_info["vendor"] = self._guess_vendor(mac)

        # 端口扫描
        open_ports = self._port_scan(ip)
        host_info["open_ports"] = open_ports

        # 判断主机状态
        if open_ports:
            host_info["status"] = "alive"
        elif self._ping_host(ip):
            host_info["status"] = "alive"
        else:
            host_info["status"] = "offline"

        with self._lock:
            self._stats["total_ports_found"] += len(open_ports)

        return host_info

    def get_discovered_hosts(self) -> list:
        """
        获取所有已发现的主机列表

        Returns:
            已发现主机的信息列表
        """
        with self._lock:
            return list(self._discovered_hosts.values())

    def get_stats(self) -> dict:
        """
        获取扫描器统计信息

        Returns:
            统计信息字典
        """
        with self._lock:
            stats = dict(self._stats)
            stats["current_discovered_hosts"] = len(self._discovered_hosts)
            stats["scan_history_count"] = len(self._scan_history)
            return stats

    # ----------------------------------------------------------
    # 内部方法
    # ----------------------------------------------------------

    def _ping_host(self, ip: str, timeout: int = PING_TIMEOUT) -> bool:
        """
        使用系统 ping 命令检测主机是否在线

        Args:
            ip: 目标IP地址
            timeout: 超时时间（秒）

        Returns:
            主机是否可达
        """
        try:
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 2
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:
            logger.warning("ping 命令不可用")
            return False
        except Exception as e:
            logger.debug("ping {} 失败: {}".format(ip, e))
            return False

    def _get_mac_from_arp(self, ip: str) -> str:
        """
        从系统ARP表获取指定IP的MAC地址

        Args:
            ip: 目标IP地址

        Returns:
            MAC地址字符串，未找到返回空字符串
        """
        try:
            # 先尝试发送ping以刷新ARP缓存
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, text=True, timeout=3
            )
        except Exception:
            pass

        try:
            # 读取ARP表
            result = subprocess.run(
                ["arp", "-n", ip],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout
            # 解析ARP表输出
            for line in output.splitlines():
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', part):
                            return part.upper()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # 备选方案：读取 /proc/net/arp
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            return mac.upper()
        except Exception:
            pass

        return ""

    def _port_scan(self, ip: str, ports: List[int] = None,
                   timeout: int = PORT_SCAN_TIMEOUT) -> List[dict]:
        """
        扫描目标主机的指定端口

        Args:
            ip: 目标IP地址
            ports: 要扫描的端口列表，None表示扫描常见端口
            timeout: 连接超时时间（秒）

        Returns:
            开放端口信息列表
        """
        if ports is None:
            ports = sorted(COMMON_PORTS.keys())

        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service_name = COMMON_PORTS.get(port, "unknown")
                    banner = self._grab_banner(sock, port)
                    open_ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "service": service_name,
                        "banner": banner,
                    })
                sock.close()
            except (socket.error, socket.timeout, OSError):
                pass

        return open_ports

    def _grab_banner(self, sock: socket.socket, port: int,
                     length: int = 256) -> str:
        """
        尝试获取服务横幅信息

        Args:
            sock: 已连接的socket
            port: 端口号
            length: 读取长度

        Returns:
            横幅字符串
        """
        try:
            # 对于HTTP类服务，发送请求
            if port in (80, 8080, 8443):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            elif port in (443,):
                return "tls"  # TLS端口不抓取明文横幅
            elif port in (25, 110, 143, 587, 993, 995):
                pass  # 等待服务器主动发送横幅
            elif port == 21:
                pass  # FTP服务器会主动发送横幅

            sock.settimeout(2)
            data = sock.recv(length)
            return data.decode("utf-8", errors="replace").strip()[:length]
        except Exception:
            return ""

    def _guess_vendor(self, mac: str) -> str:
        """
        根据MAC地址前缀猜测设备厂商

        Args:
            mac: MAC地址

        Returns:
            厂商名称
        """
        # 常见厂商MAC前缀
        vendors = {
            "00:1A:2B": "Cisco",
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:15:5D": "Microsoft Hyper-V",
            "08:00:27": "VirtualBox",
            "00:1C:42": "Parallels",
            "F8:FF:0A": "Apple",
            "3C:22:FB": "Apple",
            "A4:83:E7": "Apple",
            "DC:A6:32": "Raspberry Pi",
            "B8:27:EB": "Raspberry Pi",
            "E4:5F:01": "Raspberry Pi",
            "00:1B:44": "Dell",
            "00:1E:4F": "Dell",
            "F0:DE:F1": "Intel",
            "8C:EC:4B": "Intel",
            "70:B5:E8": "Intel",
            "A4:4C:C8": "Samsung",
            "DC:2B:2A": "Samsung",
            "AC:87:A3": "Huawei",
            "48:DB:50": "Huawei",
            "00:9A:CD": "Xiaomi",
            "78:11:DC": "Xiaomi",
            "B0:F1:EC": "TP-Link",
            "C0:25:E9": "TP-Link",
            "D8:32:14": "Netgear",
            "60:38:E0": "Netgear",
            "A0:63:91": "Espressif (IoT)",
            "24:0A:C4": "Espressif (IoT)",
            "30:AE:A4": "Shenzhen (IoT)",
        }

        prefix = mac[:8].upper()
        return vendors.get(prefix, "Unknown")

    def arp_scan(self, subnet: str) -> list:
        """
        使用arp-scan进行快速主机发现

        Args:
            subnet: 子网CIDR格式

        Returns:
            发现的主机列表
        """
        hosts = []
        try:
            cmd = ["arp-scan", "--localnet", "--retry=1", "--timeout=500"]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=ARP_SCAN_TIMEOUT
            )
            output = result.stdout

            for line in output.splitlines():
                # 解析 arp-scan 输出格式: IP MAC [vendor]
                match = re.match(
                    r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})\s+(.*)',
                    line.strip()
                )
                if match:
                    ip_addr = match.group(1)
                    mac_addr = match.group(2).upper()
                    vendor = match.group(3).strip()

                    host_info = {
                        "ip": ip_addr,
                        "mac": mac_addr,
                        "vendor": vendor,
                        "status": "alive",
                        "last_seen": datetime.now().isoformat(),
                    }

                    # 尝试反向DNS
                    try:
                        host_info["hostname"] = socket.gethostbyaddr(ip_addr)[0]
                    except Exception:
                        pass

                    hosts.append(host_info)

                    with self._lock:
                        self._discovered_hosts[ip_addr] = host_info

            logger.info("arp-scan 发现 {} 台主机".format(len(hosts)))

        except FileNotFoundError:
            logger.warning("arp-scan 未安装，请执行: apt-get install arp-scan")
        except subprocess.TimeoutExpired:
            logger.warning("arp-scan 超时")
        except Exception as e:
            logger.error("arp-scan 执行失败: {}".format(e))

        return hosts

    def get_scan_history(self, limit: int = 20) -> list:
        """
        获取扫描历史记录

        Args:
            limit: 返回的最大记录数

        Returns:
            扫描历史列表
        """
        with self._lock:
            return list(self._scan_history[-limit:])

    def clear_discovered(self) -> dict:
        """
        清除已发现的主机记录

        Returns:
            操作结果
        """
        with self._lock:
            count = len(self._discovered_hosts)
            self._discovered_hosts.clear()
            logger.info("已清除 {} 条主机发现记录".format(count))
            return {"status": "ok", "cleared": count}


# ============================================================
# 单例
# ============================================================

_instance: Optional[NetworkScanner] = None


def get_network_scanner() -> NetworkScanner:
    """获取网络扫描器单例"""
    global _instance
    if _instance is None:
        _instance = NetworkScanner()
    return _instance
