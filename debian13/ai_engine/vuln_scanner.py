"""
GateKeeper - 漏洞扫描引擎
自动化网络漏洞扫描与评估，支持端口扫描和服务识别
"""

import threading
import socket
import time
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

from config.settings import settings
from config.logging_config import get_logger
from core.database import db_manager
from core.models import (
    Vulnerability, ScanResult, ScanStatus, VulnSeverity
)

logger = get_logger("vuln_scanner")


# 常见服务端口映射
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCBind",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

# 常见漏洞签名
VULN_SIGNATURES = [
    {
        "name": "Open SSH Weak Key Exchange",
        "port": 22,
        "service": "SSH",
        "pattern": b"SSH-2.0-OpenSSH_",
        "severity": VulnSeverity.MEDIUM,
        "description": "SSH服务器使用弱密钥交换算法",
        "solution": "升级SSH服务器并配置强密钥交换算法",
    },
    {
        "name": "FTP Anonymous Login",
        "port": 21,
        "service": "FTP",
        "pattern": b"220",
        "severity": VulnSeverity.HIGH,
        "description": "FTP服务器可能允许匿名登录",
        "solution": "禁用匿名登录，使用加密的SFTP替代FTP",
    },
    {
        "name": "HTTP Server Version Disclosure",
        "port": 80,
        "service": "HTTP",
        "pattern": b"Server:",
        "severity": VulnSeverity.LOW,
        "description": "HTTP服务器泄露版本信息",
        "solution": "配置Web服务器隐藏版本信息",
    },
    {
        "name": "Redis Unauthenticated Access",
        "port": 6379,
        "service": "Redis",
        "pattern": b"redis_version",
        "severity": VulnSeverity.CRITICAL,
        "description": "Redis服务器未设置认证，可能被未授权访问",
        "solution": "为Redis设置密码认证，并限制访问IP",
    },
    {
        "name": "MongoDB Unauthenticated Access",
        "port": 27017,
        "service": "MongoDB",
        "pattern": b"MongoDB",
        "severity": VulnSeverity.CRITICAL,
        "description": "MongoDB服务器未设置认证",
        "solution": "启用MongoDB认证，配置访问控制",
    },
    {
        "name": "Elasticsearch Open Access",
        "port": 9200,
        "service": "Elasticsearch",
        "pattern": b"elasticsearch",
        "severity": VulnSeverity.HIGH,
        "description": "Elasticsearch可能未设置访问控制",
        "solution": "启用Elasticsearch安全认证，配置防火墙规则",
    },
]


class VulnerabilityScanner:
    """
    漏洞扫描引擎
    支持端口扫描、服务识别和漏洞检测
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._scan_threads: Dict[int, threading.Thread] = {}
        self._scan_status: Dict[int, Dict] = {}

        # 扫描配置
        self._timeout = 3  # 连接超时（秒）
        self._max_concurrency = settings.ai_model.vuln_scan_concurrency
        self._scan_ports = list(COMMON_PORTS.keys())

        logger.info("漏洞扫描引擎初始化完成")

    def start_scan(
        self,
        target: str,
        scan_type: str = "vuln_scan",
        ports: Optional[List[int]] = None,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        启动漏洞扫描任务

        Args:
            target: 扫描目标（IP/CIDR/主机名）
            scan_type: 扫描类型 (port_scan / vuln_scan / service_scan)
            ports: 自定义端口列表
            user_id: 发起扫描的用户ID

        Returns:
            扫描任务信息
        """
        # 创建扫描记录
        scan = ScanResult(
            scan_type=scan_type,
            target=target,
            status=ScanStatus.PENDING,
            scan_options={
                "ports": ports or self._scan_ports,
                "timeout": self._timeout,
                "concurrency": self._max_concurrency,
            },
            created_by=user_id,
        )
        scan = db_manager.add(scan)

        # 启动扫描线程
        thread = threading.Thread(
            target=self._execute_scan,
            args=(scan.id, target, scan_type, ports),
            name="vuln-scan-{}".format(scan.id),
            daemon=True,
        )
        self._scan_threads[scan.id] = thread
        self._scan_status[scan.id] = {
            "progress": 0,
            "status": "running",
        }
        thread.start()

        logger.info("启动扫描任务: id={}, target={}, type={}".format(scan.id, target, scan_type))
        return {"status": "started", "scan_id": scan.id, "target": target}

    def _execute_scan(
        self,
        scan_id: int,
        target: str,
        scan_type: str,
        ports: Optional[List[int]],
    ):
        """执行扫描任务（在独立线程中运行）"""
        # 更新状态为运行中
        self._update_scan_status(scan_id, ScanStatus.RUNNING)

        try:
            # 解析目标
            hosts = self._resolve_targets(target)

            # 更新扫描记录
            with db_manager.get_session() as session:
                scan = session.query(ScanResult).filter_by(id=scan_id).first()
                if scan:
                    scan.total_hosts = len(hosts)
                    scan.started_at = datetime.now()

            scan_ports = ports or self._scan_ports
            total_vulns = 0
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0

            for i, host in enumerate(hosts):
                # 更新进度
                progress = int((i / len(hosts)) * 100)
                self._scan_status[scan_id] = {
                    "progress": progress,
                    "status": "running",
                    "current_host": host,
                }

                # 端口扫描
                open_ports = self._port_scan(host, scan_ports)

                # 服务识别
                services = self._service_detection(host, open_ports)

                # 漏洞检测
                if scan_type in ("vuln_scan", "service_scan"):
                    vulns = self._vuln_detection(host, services)
                    total_vulns += len(vulns)

                    for vuln in vulns:
                        vuln.scan_id = scan_id
                        db_manager.add(vuln)

                        if vuln.severity == VulnSeverity.CRITICAL:
                            critical_count += 1
                        elif vuln.severity == VulnSeverity.HIGH:
                            high_count += 1
                        elif vuln.severity == VulnSeverity.MEDIUM:
                            medium_count += 1
                        else:
                            low_count += 1

                # 更新扫描记录
                with db_manager.get_session() as session:
                    scan = session.query(ScanResult).filter_by(id=scan_id).first()
                    if scan:
                        scan.scanned_hosts = i + 1
                        scan.total_vulns = total_vulns
                        scan.critical_vulns = critical_count
                        scan.high_vulns = high_count
                        scan.medium_vulns = medium_count
                        scan.low_vulns = low_count

            # 扫描完成
            self._update_scan_status(scan_id, ScanStatus.COMPLETED)
            self._scan_status[scan_id] = {"progress": 100, "status": "completed"}

            logger.info(
                "扫描完成: id={}, target={}, vulns={}".format(
                    scan_id, target, total_vulns
                )
            )

        except Exception as e:
            logger.error("扫描任务失败: id={}, error={}".format(scan_id, e))
            self._update_scan_status(scan_id, ScanStatus.FAILED, error=str(e))
            self._scan_status[scan_id] = {"progress": 0, "status": "failed"}

    def _resolve_targets(self, target: str) -> List[str]:
        """
        解析扫描目标
        支持单个IP、CIDR范围、主机名

        Args:
            target: 目标字符串

        Returns:
            IP地址列表
        """
        hosts = []

        # CIDR范围
        if "/" in target:
            import ipaddress
            try:
                network = ipaddress.ip_network(target, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
            except ValueError:
                logger.error("无效的CIDR地址: {}".format(target))
        else:
            # 主机名解析
            try:
                ip = socket.gethostbyname(target)
                hosts = [ip]
            except socket.gaierror:
                # 可能是IP地址
                import ipaddress
                try:
                    ipaddress.ip_address(target)
                    hosts = [target]
                except ValueError:
                    logger.error("无法解析目标: {}".format(target))

        return hosts

    def _port_scan(self, host: str, ports: List[int]) -> List[Tuple[int, str]]:
        """
        扫描目标主机的开放端口

        Args:
            host: 目标IP
            ports: 要扫描的端口列表

        Returns:
            (端口, 状态) 列表
        """
        open_ports = []

        with ThreadPoolExecutor(max_workers=self._max_concurrency) as executor:
            futures = {
                executor.submit(self._check_port, host, port): port
                for port in ports
            }

            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        service = COMMON_PORTS.get(port, "unknown")
                        open_ports.append((port, service))
                        logger.debug("发现开放端口: {}:{} ({})".format(host, port, service))
                except Exception:
                    pass

        return open_ports

    def _check_port(self, host: str, port: int) -> Tuple[bool, bytes]:
        """
        检查单个端口是否开放

        Args:
            host: 目标IP
            port: 端口号

        Returns:
            (是否开放, banner数据)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                # 尝试获取banner
                banner = b""
                try:
                    sock.send(b"\r\n")
                    banner = sock.recv(1024)
                except Exception:
                    pass
                sock.close()
                return True, banner
            sock.close()
            return False, b""
        except Exception:
            return False, b""

    def _service_detection(
        self, host: str, open_ports: List[Tuple[int, str]]
    ) -> Dict[int, Dict]:
        """
        服务识别
        通过banner抓取识别运行在端口上的服务

        Args:
            host: 目标IP
            open_ports: 开放端口列表

        Returns:
            端口到服务信息的映射
        """
        services = {}
        for port, known_service in open_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self._timeout)
                sock.connect((host, port))

                # 发送探测数据
                probe_data = self._get_probe_data(port)
                if probe_data:
                    sock.send(probe_data)

                banner = sock.recv(1024)
                sock.close()

                services[port] = {
                    "port": port,
                    "known_service": known_service,
                    "banner": banner.decode("utf-8", errors="replace").strip(),
                    "detected_service": self._identify_service(banner, known_service),
                }
            except Exception as e:
                services[port] = {
                    "port": port,
                    "known_service": known_service,
                    "banner": "",
                    "error": str(e),
                }

        return services

    def _get_probe_data(self, port: int) -> bytes:
        """获取服务探测数据"""
        probes = {
            80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            443: b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00",
            25: b"EHLO gatekeeper\r\n",
            110: b"",
            143: b"",
            21: b"",
            22: b"",
        }
        return probes.get(port, b"")

    def _identify_service(self, banner: bytes, known_service: str) -> str:
        """通过banner识别服务"""
        banner_str = banner.decode("utf-8", errors="replace").lower()

        service_signatures = {
            "apache": "Apache HTTPD",
            "nginx": "Nginx",
            "openssh": "OpenSSH",
            "dropbear": "Dropbear SSH",
            "mysql": "MySQL",
            "postgresql": "PostgreSQL",
            "redis": "Redis",
            "ftp": "FTP Server",
            "smtp": "SMTP Server",
            "elasticsearch": "Elasticsearch",
            "mongodb": "MongoDB",
        }

        for sig, service_name in service_signatures.items():
            if sig in banner_str:
                return service_name

        return known_service

    def _vuln_detection(
        self, host: str, services: Dict[int, Dict]
    ) -> List[Vulnerability]:
        """
        漏洞检测
        基于服务信息和已知漏洞签名检测漏洞

        Args:
            host: 目标IP
            services: 服务信息字典

        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []

        for port, service_info in services.items():
            banner = service_info.get("banner", "")

            for signature in VULN_SIGNATURES:
                # 端口匹配
                if signature["port"] != port:
                    continue

                # 模式匹配
                if signature["pattern"] and signature["pattern"] not in banner.encode():
                    continue

                # 创建漏洞记录
                vuln = Vulnerability(
                    host=host,
                    port=port,
                    service=service_info.get("detected_service", ""),
                    name=signature["name"],
                    description=signature["description"],
                    severity=signature["severity"],
                    solution=signature["solution"],
                    is_confirmed=True,
                )
                vulnerabilities.append(vuln)
                logger.warning(
                    "发现漏洞: {}:{} - {} [{}]".format(
                        host, port, signature['name'],
                        signature['severity'].value
                    )
                )

        return vulnerabilities

    def _update_scan_status(
        self,
        scan_id: int,
        status: ScanStatus,
        error: Optional[str] = None,
    ):
        """更新扫描状态"""
        try:
            with db_manager.get_session() as session:
                scan = session.query(ScanResult).filter_by(id=scan_id).first()
                if scan:
                    scan.status = status
                    if status == ScanStatus.COMPLETED:
                        scan.completed_at = datetime.now()
                    elif status == ScanStatus.FAILED:
                        scan.completed_at = datetime.now()
                        scan.error_message = error
        except Exception as e:
            logger.error("更新扫描状态失败: {}".format(e))

    def get_scan_progress(self, scan_id: int) -> Optional[Dict]:
        """获取扫描进度"""
        return self._scan_status.get(scan_id)

    def cancel_scan(self, scan_id: int) -> bool:
        """取消扫描任务"""
        if scan_id in self._scan_status:
            self._scan_status[scan_id] = {"progress": 0, "status": "cancelled"}
            self._update_scan_status(scan_id, ScanStatus.CANCELLED)
            logger.info("取消扫描任务: id={}".format(scan_id))
            return True
        return False

    def get_scan_results(self, scan_id: int) -> Optional[Dict]:
        """获取扫描结果"""
        try:
            with db_manager.get_session() as session:
                scan = session.query(ScanResult).filter_by(id=scan_id).first()
                if not scan:
                    return None

                vulns = (
                    session.query(Vulnerability)
                    .filter_by(scan_id=scan_id)
                    .all()
                )

                return {
                    "scan": {
                        "id": scan.id,
                        "type": scan.scan_type,
                        "target": scan.target,
                        "status": scan.status.value,
                        "started_at": str(scan.started_at) if scan.started_at else None,
                        "completed_at": str(scan.completed_at) if scan.completed_at else None,
                        "total_hosts": scan.total_hosts,
                        "scanned_hosts": scan.scanned_hosts,
                        "total_vulns": scan.total_vulns,
                        "critical_vulns": scan.critical_vulns,
                        "high_vulns": scan.high_vulns,
                        "medium_vulns": scan.medium_vulns,
                        "low_vulns": scan.low_vulns,
                    },
                    "vulnerabilities": [
                        {
                            "id": v.id,
                            "host": v.host,
                            "port": v.port,
                            "service": v.service,
                            "name": v.name,
                            "severity": v.severity.value,
                            "description": v.description,
                            "solution": v.solution,
                            "cve_id": v.cve_id,
                            "cvss_score": v.cvss_score,
                        }
                        for v in vulns
                    ],
                }
        except Exception as e:
            logger.error("获取扫描结果失败: {}".format(e))
            return None
