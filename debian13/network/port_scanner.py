"""
GateKeeper - 端口扫描模块
网络端口扫描与服务识别
"""

import socket
import threading
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from config.settings import settings
from config.logging_config import get_logger

logger = get_logger("port_scanner")


# 常见端口及服务映射
WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
    69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD",
    520: "RIP", 523: "IBM-DB2", 530: "RPC", 543: "Klogin",
    544: "Kshell", 548: "AFP", 554: "RTSP", 587: "Submission",
    631: "IPP", 636: "LDAPS", 873: "Rsync", 902: "VMware",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel-SSL", 2181: "ZooKeeper", 2222: "SSH-Alt",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4369: "EPMD",
    5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6443: "Kubernetes-API", 7001: "WebLogic",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "ES-Transport",
    11211: "Memcached", 15672: "RabbitMQ-Management", 27017: "MongoDB",
    27018: "MongoDB-Shard", 28017: "MongoDB-Web",
}


class PortScanner:
    """
    端口扫描器
    支持TCP Connect扫描和TCP SYN扫描
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._timeout = 2  # 默认超时（秒）
        self._max_threads = 100  # 最大并发线程数
        self._scan_results: Dict[str, Dict] = {}

        logger.info("端口扫描器初始化完成")

    def scan_host(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        timeout: float = 2.0,
    ) -> Dict[str, Any]:
        """
        扫描单个主机的端口

        Args:
            host: 目标主机（IP或域名）
            ports: 要扫描的端口列表，None表示扫描常见端口
            timeout: 连接超时（秒）

        Returns:
            扫描结果
        """
        if ports is None:
            ports = list(WELL_KNOWN_PORTS.keys())

        # 解析主机名
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return {"status": "error", "message": "无法解析主机名: {}".format(host)}

        open_ports = []
        closed_ports = []
        filtered_ports = []

        with ThreadPoolExecutor(max_workers=self._max_threads) as executor:
            futures = {
                executor.submit(self._check_port, ip, port, timeout): port
                for port in ports
            }

            for future in as_completed(futures):
                port = futures[future]
                try:
                    status, banner = future.result()
                    service = WELL_KNOWN_PORTS.get(port, "unknown")

                    port_info = {
                        "port": port,
                        "service": service,
                        "status": status,
                        "banner": banner.decode("utf-8", errors="replace").strip() if banner else "",
                    }

                    if status == "open":
                        open_ports.append(port_info)
                    elif status == "closed":
                        closed_ports.append(port_info)
                    else:
                        filtered_ports.append(port_info)

                except Exception as e:
                    filtered_ports.append({
                        "port": port,
                        "service": WELL_KNOWN_PORTS.get(port, "unknown"),
                        "status": "filtered",
                        "error": str(e),
                    })

        result = {
            "status": "ok",
            "host": host,
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "open_ports": sorted(open_ports, key=lambda x: x["port"]),
            "closed_ports_count": len(closed_ports),
            "filtered_ports_count": len(filtered_ports),
            "total_scanned": len(ports),
            "open_count": len(open_ports),
        }

        # 缓存结果
        self._scan_results[host] = result

        logger.info(
            "端口扫描完成: {} ({}), 开放端口: {}/{}".format(
                host, ip, len(open_ports), len(ports)
            )
        )

        return result

    def scan_network(
        self,
        network: str,
        ports: Optional[List[int]] = None,
        timeout: float = 2.0,
    ) -> Dict[str, Any]:
        """
        扫描网络范围

        Args:
            network: 网络范围（CIDR格式，如 192.168.1.0/24）
            ports: 要扫描的端口列表
            timeout: 连接超时

        Returns:
            扫描结果
        """
        import ipaddress

        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            return {"status": "error", "message": "无效的网络地址: {}".format(e)}

        hosts = [str(ip) for ip in net.hosts()]
        results = []

        for host in hosts:
            result = self.scan_host(host, ports, timeout)
            if result.get("status") == "ok" and result.get("open_count", 0) > 0:
                results.append(result)

        return {
            "status": "ok",
            "network": network,
            "total_hosts": len(hosts),
            "hosts_with_open_ports": len(results),
            "results": results,
            "timestamp": datetime.now().isoformat(),
        }

    def _check_port(
        self, host: str, port: int, timeout: float
    ) -> Tuple[str, bytes]:
        """
        检查单个端口状态

        Args:
            host: 目标IP
            port: 端口号
            timeout: 超时时间

        Returns:
            (状态, banner)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                banner = b""
                try:
                    # 尝试获取banner
                    probe = self._get_probe(port)
                    if probe:
                        sock.send(probe)
                    banner = sock.recv(1024)
                except Exception:
                    pass
                finally:
                    sock.close()
                return ("open", banner)
            else:
                sock.close()
                return ("closed", b"")

        except socket.timeout:
            return ("filtered", b"")
        except Exception:
            return ("filtered", b"")

    def _get_probe(self, port: int) -> bytes:
        """获取端口探测数据"""
        probes = {
            80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            443: b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00",
            21: b"",
            22: b"",
            25: b"EHLO gatekeeper\r\n",
            110: b"",
            143: b"",
        }
        return probes.get(port, b"")

    def get_last_result(self, host: str) -> Optional[Dict]:
        """获取上次扫描结果"""
        return self._scan_results.get(host)

    def quick_scan(self, host: str) -> Dict[str, Any]:
        """快速扫描（仅扫描常见端口）"""
        quick_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
        return self.scan_host(host, quick_ports, timeout=1.0)
