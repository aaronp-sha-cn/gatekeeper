"""
GateKeeper - 漏洞扫描引擎
网络漏洞扫描、服务版本识别、弱口令检测、已知漏洞匹配
"""

import socket
import ssl
import threading
import re
import ipaddress
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from config.logging_config import get_logger
from core.database import db_manager
from core.models import (
    Vulnerability, ScanResult, ScanStatus, VulnSeverity
)

logger = get_logger("vuln_scanner")


# ============================================================
# 内置漏洞数据库（CVE模拟数据）
# ============================================================

VULN_DATABASE = [
    {
        "service": "ssh",
        "version_pattern": "OpenSSH_7.",
        "cve": "CVE-2023-38408",
        "cvss": 7.8,
        "severity": "high",
        "desc": "OpenSSH远程代码执行漏洞",
        "solution": "升级到OpenSSH 9.3+",
    },
    {
        "service": "ssh",
        "version_pattern": "OpenSSH_8.",
        "cve": "CVE-2023-51385",
        "cvss": 6.5,
        "severity": "medium",
        "desc": "OpenSSH双释放漏洞",
        "solution": "升级到OpenSSH 9.6+",
    },
    {
        "service": "http",
        "version_pattern": "Apache/2.4.49",
        "cve": "CVE-2021-41773",
        "cvss": 7.5,
        "severity": "high",
        "desc": "Apache路径穿越与文件泄露漏洞",
        "solution": "升级到Apache 2.4.50+",
    },
    {
        "service": "http",
        "version_pattern": "Apache/2.4.50",
        "cve": "CVE-2021-42013",
        "cvss": 9.8,
        "severity": "critical",
        "desc": "Apache路径穿越漏洞（绕过补丁）",
        "solution": "升级到Apache 2.4.51+",
    },
    {
        "service": "http",
        "version_pattern": "nginx/1.16.",
        "cve": "CVE-2019-9511",
        "cvss": 7.5,
        "severity": "high",
        "desc": "nginx HTTP/2拒绝服务漏洞",
        "solution": "升级到nginx 1.17.3+",
    },
    {
        "service": "http",
        "version_pattern": "nginx/1.18.",
        "cve": "CVE-2021-23017",
        "cvss": 7.7,
        "severity": "high",
        "desc": "nginx DNS解析器越界写入漏洞",
        "solution": "升级到nginx 1.21.0+",
    },
    {
        "service": "mysql",
        "version_pattern": "5.5.",
        "cve": "CVE-2017-3308",
        "cvss": 9.8,
        "severity": "critical",
        "desc": "MySQL Server远程代码执行漏洞",
        "solution": "升级到MySQL 8.0+",
    },
    {
        "service": "mysql",
        "version_pattern": "5.6.",
        "cve": "CVE-2019-2737",
        "cvss": 9.8,
        "severity": "critical",
        "desc": "MySQL Server权限提升漏洞",
        "solution": "升级到MySQL 8.0+",
    },
    {
        "service": "mysql",
        "version_pattern": "5.7.",
        "cve": "CVE-2021-2153",
        "cvss": 4.3,
        "severity": "medium",
        "desc": "MySQL Server提权漏洞",
        "solution": "升级到MySQL 8.0.29+",
    },
    {
        "service": "ftp",
        "version_pattern": "vsftpd 2.3.4",
        "cve": "CVE-2011-2523",
        "cvss": 7.5,
        "severity": "high",
        "desc": "vsftpd 2.3.4反向Shell后门漏洞",
        "solution": "升级vsftpd到最新版本",
    },
    {
        "service": "smb",
        "version_pattern": "Samba 3.",
        "cve": "CVE-2017-7494",
        "cvss": 8.8,
        "severity": "high",
        "desc": "Samba远程代码执行漏洞（SambaCry）",
        "solution": "升级到Samba 4.6+",
    },
    {
        "service": "smb",
        "version_pattern": "SMBv1",
        "cve": "CVE-2017-0144",
        "cvss": 8.1,
        "severity": "high",
        "desc": "SMB远程代码执行漏洞（永恒之蓝）",
        "solution": "禁用SMBv1，安装MS17-010补丁",
    },
    {
        "service": "rdp",
        "version_pattern": "RDP",
        "cve": "CVE-2019-0708",
        "cvss": 9.8,
        "severity": "critical",
        "desc": "Windows RDP远程桌面服务漏洞（BlueKeep）",
        "solution": "安装安全补丁，禁用RDP或限制访问",
    },
    {
        "service": "smtp",
        "version_pattern": "Postfix",
        "cve": "CVE-2020-26048",
        "cvss": 5.3,
        "severity": "medium",
        "desc": "Postfix SMTP命令注入漏洞",
        "solution": "升级Postfix到3.5.7+",
    },
    {
        "service": "redis",
        "version_pattern": "redis",
        "cve": "CVE-2021-32687",
        "cvss": 6.8,
        "severity": "medium",
        "desc": "Redis Lua脚本沙箱逃逸漏洞",
        "solution": "升级Redis到6.2.6+",
    },
]


# ============================================================
# 危险端口定义
# ============================================================

DANGEROUS_PORTS = {
    23: {"service": "Telnet", "severity": "high", "desc": "Telnet明文传输，易被嗅探", "solution": "使用SSH替代Telnet"},
    445: {"service": "SMB", "severity": "high", "desc": "SMB端口，易受永恒之蓝等攻击", "solution": "限制SMB访问，安装最新补丁"},
    3389: {"service": "RDP", "severity": "high", "desc": "远程桌面端口，易受暴力破解", "solution": "限制RDP访问源IP，使用VPN"},
    5900: {"service": "VNC", "severity": "high", "desc": "VNC远程控制，默认无加密", "solution": "使用SSH隧道或限制访问源"},
    21: {"service": "FTP", "severity": "medium", "desc": "FTP明文传输", "solution": "使用SFTP/SCP替代"},
    25: {"service": "SMTP", "severity": "medium", "desc": "SMTP开放可能被利用发送垃圾邮件", "solution": "配置SMTP认证"},
    161: {"service": "SNMP", "severity": "medium", "desc": "SNMP默认community为public", "solution": "修改默认community字符串"},
    512: {"service": "rexec", "severity": "high", "desc": "rexec远程执行，无加密", "solution": "禁用rexec服务"},
    513: {"service": "rlogin", "severity": "high", "desc": "rlogin远程登录，无加密", "solution": "使用SSH替代rlogin"},
    514: {"service": "Syslog", "severity": "low", "desc": "Syslog端口，可能泄露日志信息", "solution": "限制访问源IP"},
    2049: {"service": "NFS", "severity": "medium", "desc": "NFS网络文件系统，可能未授权访问", "solution": "配置NFS导出规则"},
    3306: {"service": "MySQL", "severity": "medium", "desc": "MySQL数据库端口暴露", "solution": "限制访问源IP"},
    5432: {"service": "PostgreSQL", "severity": "medium", "desc": "PostgreSQL数据库端口暴露", "solution": "限制访问源IP"},
    6379: {"service": "Redis", "severity": "high", "desc": "Redis默认无认证", "solution": "启用Redis认证，绑定本地"},
    11211: {"service": "Memcached", "severity": "medium", "desc": "Memcached默认无认证", "solution": "启用SASL认证，限制访问"},
    27017: {"service": "MongoDB", "severity": "high", "desc": "MongoDB默认无认证", "solution": "启用认证，限制访问源IP"},
}


# ============================================================
# 常见弱口令字典
# ============================================================

COMMON_CREDENTIALS = {
    "ssh": [
        ("root", "root"), ("root", "toor"), ("root", "123456"),
        ("root", "password"), ("admin", "admin"), ("admin", "123456"),
        ("admin", "password"), ("test", "test"), ("user", "user"),
        ("ubuntu", "ubuntu"), ("centos", "centos"),
    ],
    "ftp": [
        ("anonymous", ""), ("anonymous", "anonymous"),
        ("ftp", "ftp"), ("admin", "admin"), ("root", "root"),
    ],
    "mysql": [
        ("root", "root"), ("root", ""), ("root", "123456"),
        ("root", "password"), ("root", "mysql"), ("admin", "admin"),
    ],
    "redis": [
        ("default", ""), ("default", "redis"),
    ],
    "mongodb": [
        ("admin", ""), ("root", "root"), ("admin", "admin"),
    ],
    "smtp": [
        ("admin", "admin"), ("postmaster", ""), ("test", "test"),
    ],
}


# ============================================================
# 扫描结果数据类
# ============================================================

@dataclass
class VulnScanResult:
    """单个漏洞扫描结果"""
    host: str = ""
    port: int = 0
    service: str = ""
    vulnerability: str = ""
    severity: str = "info"  # info/low/medium/high/critical
    cve_id: str = ""
    cvss_score: float = 0.0
    description: str = ""
    solution: str = ""
    evidence: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


# ============================================================
# 漏洞扫描器
# ============================================================

class VulnScanner:
    """漏洞扫描器 - 支持服务识别、弱口令检测、CVE匹配、SSL检查等"""

    def __init__(self):
        self._lock = threading.Lock()
        self._scanning = False
        self._stop_flag = threading.Event()
        self._scan_thread: Optional[threading.Thread] = None
        self._current_scan_id: Optional[int] = None
        self._progress: Dict[str, Any] = {
            "status": "idle",
            "target": "",
            "scan_type": "",
            "current_host": "",
            "scanned_hosts": 0,
            "total_hosts": 0,
            "found_vulns": 0,
            "start_time": None,
        }
        self._timeout = 3
        self._max_threads = 50
        self._quick_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
            1433, 1521, 2049, 3306, 3389, 5432, 5672, 5900, 6379,
            8080, 8443, 9200, 11211, 27017,
        ]
        self._full_ports = list(range(1, 1025))
        self._results_cache: Dict[str, List[VulnScanResult]] = {}

        logger.info("漏洞扫描器初始化完成")

    def scan_host(self, target: str, ports: Optional[List[int]] = None,
                  scan_type: str = "quick") -> List[VulnScanResult]:
        """
        扫描单个主机的漏洞

        Args:
            target: 目标主机IP或域名
            ports: 自定义端口列表
            scan_type: quick/full/custom

        Returns:
            漏洞扫描结果列表
        """
        results: List[VulnScanResult] = []

        # 解析主机名
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            logger.error("无法解析主机名: {}".format(target))
            return results

        # 确定扫描端口
        if scan_type == "quick":
            scan_ports = self._quick_ports
        elif scan_type == "full":
            scan_ports = self._full_ports
        elif scan_type == "custom" and ports:
            scan_ports = ports
        else:
            scan_ports = self._quick_ports

        # 第一步：端口扫描 + 服务版本识别
        open_ports = self._scan_ports(ip, scan_ports)
        logger.info("主机 {} 开放端口: {}".format(ip, [p["port"] for p in open_ports]))

        # 第二步：对每个开放端口进行深度检测
        for port_info in open_ports:
            if self._stop_flag.is_set():
                break

            port = port_info["port"]
            service = port_info["service"]
            banner = port_info["banner"]

            # 2.1 已知漏洞检测
            vulns = self._check_known_vulns(ip, port, service, banner)
            results.extend(vulns)

            # 2.2 危险端口检测
            vuln = self._check_dangerous_port(ip, port, service)
            if vuln:
                results.append(vuln)

            # 2.3 弱口令检测
            vulns = self._check_weak_credentials(ip, port, service)
            results.extend(vulns)

            # 2.4 SSL/TLS证书检查
            if port in (443, 465, 993, 995, 8443):
                vulns = self._check_ssl_tls(ip, port)
                results.extend(vulns)

            # 2.5 HTTP安全头检测
            if port in (80, 8080, 8443, 443):
                vulns = self._check_http_headers(ip, port)
                results.extend(vulns)

            # 2.6 SSH配置检测
            if service in ("SSH", "ssh") or port == 22:
                vulns = self._check_ssh_config(ip, port, banner)
                results.extend(vulns)

        # 缓存结果
        self._results_cache[target] = results
        logger.info("主机 {} 扫描完成，发现 {} 个漏洞".format(ip, len(results)))
        return results

    def scan_network(self, cidr: str, ports: Optional[List[int]] = None,
                     scan_type: str = "quick") -> Dict[str, Any]:
        """
        扫描网络范围的漏洞

        Args:
            cidr: CIDR格式的网络地址
            ports: 自定义端口列表
            scan_type: quick/full/custom

        Returns:
            扫描结果汇总
        """
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            logger.error("无效的网络地址: {}".format(e))
            return {"status": "error", "message": "无效的网络地址: {}".format(e)}

        hosts = [str(ip) for ip in net.hosts()]
        all_results: List[VulnScanResult] = []
        host_results: Dict[str, List[Dict]] = {}

        for host in hosts:
            if self._stop_flag.is_set():
                break

            self._progress["current_host"] = host
            self._progress["scanned_hosts"] += 1

            host_vulns = self.scan_host(host, ports, scan_type)
            all_results.extend(host_vulns)
            host_results[host] = [v.to_dict() for v in host_vulns]

        return {
            "status": "ok",
            "network": cidr,
            "total_hosts": len(hosts),
            "scanned_hosts": self._progress["scanned_hosts"],
            "total_vulns": len(all_results),
            "host_results": host_results,
            "timestamp": datetime.now().isoformat(),
        }

    def start_scan(self, target: str, scan_type: str = "quick",
                   ports: Optional[List[int]] = None,
                   username: str = "system") -> Dict[str, Any]:
        """
        启动扫描任务（异步，在后台线程中执行）

        Args:
            target: 扫描目标（IP/CIDR/域名）
            scan_type: quick/full/custom
            ports: 自定义端口
            username: 操作用户

        Returns:
            扫描任务信息
        """
        if self._scanning:
            return {"status": "error", "message": "已有扫描任务正在运行"}

        # 创建扫描记录
        scan_record = ScanResult(
            scan_type="vuln_scan",
            target=target,
            status=ScanStatus.PENDING,
            scan_options={
                "scan_type": scan_type,
                "ports": ports,
            },
            created_by=None,
        )
        db_manager.add(scan_record)
        self._current_scan_id = scan_record.id

        # 重置状态
        self._stop_flag.clear()
        self._scanning = True
        self._progress = {
            "status": "running",
            "target": target,
            "scan_type": scan_type,
            "current_host": "",
            "scanned_hosts": 0,
            "total_hosts": 1,
            "found_vulns": 0,
            "start_time": datetime.now().isoformat(),
            "scan_id": scan_record.id,
        }

        # 更新状态为运行中
        with db_manager.get_session() as session:
            record = session.query(ScanResult).filter_by(id=scan_record.id).first()
            if record:
                record.status = ScanStatus.RUNNING
                record.started_at = datetime.now()

        # 启动后台扫描线程
        self._scan_thread = threading.Thread(
            target=self._run_scan_task,
            args=(target, scan_type, ports, scan_record.id),
            daemon=True,
        )
        self._scan_thread.start()

        logger.info("漏洞扫描任务已启动: target={}, type={}, scan_id={}".format(
            target, scan_type, scan_record.id))
        return {"status": "ok", "scan_id": scan_record.id, "message": "扫描任务已启动"}

    def _run_scan_task(self, target: str, scan_type: str,
                       ports: Optional[List[int]], scan_id: int):
        """后台扫描线程执行函数"""
        all_results: List[VulnScanResult] = []

        try:
            # 判断是单主机还是网络扫描
            is_network = "/" in target
            if is_network:
                try:
                    net = ipaddress.ip_network(target, strict=False)
                    hosts = [str(ip) for ip in net.hosts()]
                    self._progress["total_hosts"] = len(hosts)
                except ValueError:
                    hosts = [target]
                    self._progress["total_hosts"] = 1
            else:
                hosts = [target]
                self._progress["total_hosts"] = 1

            for host in hosts:
                if self._stop_flag.is_set():
                    break

                self._progress["current_host"] = host
                self._progress["scanned_hosts"] += 1

                host_vulns = self.scan_host(host, ports, scan_type)
                all_results.extend(host_vulns)
                self._progress["found_vulns"] = len(all_results)

            # 保存漏洞到数据库
            self._save_results(scan_id, all_results, hosts)

            # 更新扫描记录
            with db_manager.get_session() as session:
                record = session.query(ScanResult).filter_by(id=scan_id).first()
                if record:
                    record.status = ScanStatus.COMPLETED
                    record.completed_at = datetime.now()
                    record.total_hosts = len(hosts)
                    record.scanned_hosts = self._progress["scanned_hosts"]
                    record.total_vulns = len(all_results)
                    record.critical_vulns = sum(
                        1 for v in all_results if v.severity == "critical"
                    )
                    record.high_vulns = sum(
                        1 for v in all_results if v.severity == "high"
                    )
                    record.medium_vulns = sum(
                        1 for v in all_results if v.severity == "medium"
                    )
                    record.low_vulns = sum(
                        1 for v in all_results if v.severity == "low"
                    )

            self._progress["status"] = "completed"
            logger.info("扫描任务完成: scan_id={}, 漏洞数={}".format(scan_id, len(all_results)))

        except Exception as e:
            logger.error("扫描任务异常: {}".format(e))
            with db_manager.get_session() as session:
                record = session.query(ScanResult).filter_by(id=scan_id).first()
                if record:
                    record.status = ScanStatus.FAILED
                    record.error_message = str(e)
                    record.completed_at = datetime.now()
            self._progress["status"] = "failed"
            self._progress["error"] = str(e)

        finally:
            self._scanning = False

    def _save_results(self, scan_id: int, results: List[VulnScanResult],
                      hosts: List[str]):
        """保存扫描结果到数据库"""
        try:
            vuln_objects = []
            for r in results:
                vuln = Vulnerability(
                    scan_id=scan_id,
                    host=r.host,
                    port=r.port,
                    service=r.service,
                    name=r.vulnerability,
                    description=r.description,
                    severity=VulnSeverity(r.severity),
                    cve_id=r.cve_id,
                    cvss_score=r.cvss_score,
                    solution=r.solution,
                    is_confirmed=r.cvss_score > 0,
                )
                vuln_objects.append(vuln)

            if vuln_objects:
                with db_manager.get_session() as session:
                    session.add_all(vuln_objects)

            logger.info("已保存 {} 条漏洞记录到数据库".format(len(vuln_objects)))
        except Exception as e:
            logger.error("保存漏洞结果失败: {}".format(e))

    def stop_scan(self) -> Dict[str, Any]:
        """停止当前扫描"""
        if not self._scanning:
            return {"status": "error", "message": "没有正在运行的扫描任务"}

        self._stop_flag.set()
        self._progress["status"] = "cancelled"

        # 更新数据库记录
        if self._current_scan_id:
            with db_manager.get_session() as session:
                record = session.query(ScanResult).filter_by(
                    id=self._current_scan_id
                ).first()
                if record and record.status == ScanStatus.RUNNING:
                    record.status = ScanStatus.CANCELLED
                    record.completed_at = datetime.now()

        logger.info("扫描任务已停止: scan_id={}".format(self._current_scan_id))
        return {"status": "ok", "message": "扫描任务已停止"}

    def get_scan_status(self) -> Dict[str, Any]:
        """获取当前扫描状态"""
        return dict(self._progress)

    def get_scan_history(self, limit: int = 20) -> List[Dict]:
        """获取扫描历史"""
        try:
            with db_manager.get_session() as session:
                records = session.query(ScanResult).filter(
                    ScanResult.scan_type == "vuln_scan"
                ).order_by(ScanResult.created_at.desc()).limit(limit).all()

                return [{
                    "id": r.id,
                    "target": r.target,
                    "status": r.status.value,
                    "scan_type": r.scan_options.get("scan_type", "") if r.scan_options else "",
                    "total_hosts": r.total_hosts,
                    "scanned_hosts": r.scanned_hosts,
                    "total_vulns": r.total_vulns,
                    "critical_vulns": r.critical_vulns,
                    "high_vulns": r.high_vulns,
                    "medium_vulns": r.medium_vulns,
                    "low_vulns": r.low_vulns,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                } for r in records]
        except Exception as e:
            logger.error("获取扫描历史失败: {}".format(e))
            return []

    def get_latest_results(self, target: str, severity: Optional[str] = None,
                           page: int = 1, per_page: int = 50) -> Dict[str, Any]:
        """
        获取目标的最新扫描结果

        Args:
            target: 目标主机
            severity: 严重程度过滤
            page: 页码
            per_page: 每页数量

        Returns:
            分页结果
        """
        try:
            with db_manager.get_session() as session:
                # 查找该目标的最新扫描记录
                latest_scan = session.query(ScanResult).filter(
                    ScanResult.scan_type == "vuln_scan",
                    ScanResult.target == target,
                    ScanResult.status == ScanStatus.COMPLETED,
                ).order_by(ScanResult.created_at.desc()).first()

                if not latest_scan:
                    return {"total": 0, "page": page, "per_page": per_page, "results": []}

                query = session.query(Vulnerability).filter(
                    Vulnerability.scan_id == latest_scan.id
                )

                if severity:
                    query = query.filter(Vulnerability.severity == VulnSeverity(severity))

                total = query.count()
                vulns = query.order_by(
                    Vulnerability.severity.desc(),
                    Vulnerability.cvss_score.desc(),
                ).offset((page - 1) * per_page).limit(per_page).all()

                return {
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "scan_id": latest_scan.id,
                    "results": [{
                        "id": v.id,
                        "host": v.host,
                        "port": v.port,
                        "service": v.service,
                        "name": v.name,
                        "severity": v.severity.value,
                        "cve_id": v.cve_id,
                        "cvss_score": v.cvss_score,
                        "description": v.description,
                        "solution": v.solution,
                        "is_confirmed": v.is_confirmed,
                        "is_fixed": v.is_fixed,
                        "created_at": v.created_at.isoformat() if v.created_at else None,
                    } for v in vulns],
                }
        except Exception as e:
            logger.error("获取扫描结果失败: {}".format(e))
            return {"total": 0, "page": page, "per_page": per_page, "results": []}

    def get_all_results(self, severity: Optional[str] = None,
                        page: int = 1, per_page: int = 50) -> Dict[str, Any]:
        """获取所有漏洞结果（分页，支持过滤）"""
        try:
            with db_manager.get_session() as session:
                query = session.query(Vulnerability)

                if severity:
                    query = query.filter(Vulnerability.severity == VulnSeverity(severity))

                total = query.count()
                vulns = query.order_by(
                    Vulnerability.created_at.desc(),
                ).offset((page - 1) * per_page).limit(per_page).all()

                return {
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "results": [{
                        "id": v.id,
                        "host": v.host,
                        "port": v.port,
                        "service": v.service,
                        "name": v.name,
                        "severity": v.severity.value,
                        "cve_id": v.cve_id,
                        "cvss_score": v.cvss_score,
                        "description": v.description,
                        "solution": v.solution,
                        "is_confirmed": v.is_confirmed,
                        "is_fixed": v.is_fixed,
                        "created_at": v.created_at.isoformat() if v.created_at else None,
                    } for v in vulns],
                }
        except Exception as e:
            logger.error("获取漏洞结果失败: {}".format(e))
            return {"total": 0, "page": page, "per_page": per_page, "results": []}

    def get_stats(self) -> Dict[str, Any]:
        """获取漏洞扫描统计信息"""
        try:
            with db_manager.get_session() as session:
                # 总扫描次数
                total_scans = session.query(ScanResult).filter(
                    ScanResult.scan_type == "vuln_scan"
                ).count()

                # 总漏洞数
                total_vulns = session.query(Vulnerability).count()

                # 未修复漏洞数
                unfixed_vulns = session.query(Vulnerability).filter(
                    Vulnerability.is_fixed == False
                ).count()

                # 按严重程度统计
                severity_stats = {}
                for sev in VulnSeverity:
                    count = session.query(Vulnerability).filter(
                        Vulnerability.severity == sev
                    ).count()
                    severity_stats[sev.value] = count

                # 最近扫描
                recent_scans = session.query(ScanResult).filter(
                    ScanResult.scan_type == "vuln_scan"
                ).order_by(ScanResult.created_at.desc()).limit(5).all()

                # 高危漏洞数
                critical_count = severity_stats.get("critical", 0)
                high_count = severity_stats.get("high", 0)

                return {
                    "total_scans": total_scans,
                    "total_vulns": total_vulns,
                    "unfixed_vulns": unfixed_vulns,
                    "critical_vulns": critical_count,
                    "high_vulns": high_count,
                    "severity_distribution": severity_stats,
                    "recent_scans": [{
                        "id": r.id,
                        "target": r.target,
                        "status": r.status.value,
                        "total_vulns": r.total_vulns,
                        "created_at": r.created_at.isoformat() if r.created_at else None,
                    } for r in recent_scans],
                }
        except Exception as e:
            logger.error("获取统计信息失败: {}".format(e))
            return {
                "total_scans": 0, "total_vulns": 0, "unfixed_vulns": 0,
                "critical_vulns": 0, "high_vulns": 0,
                "severity_distribution": {},
                "recent_scans": [],
            }

    # ============================================================
    # 内部检测方法
    # ============================================================

    def _scan_ports(self, host: str, ports: List[int]) -> List[Dict]:
        """扫描端口并获取banner"""
        open_ports = []

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self._timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    banner = b""
                    try:
                        probe = self._get_probe(port)
                        if probe:
                            sock.send(probe)
                        banner = sock.recv(1024)
                    except Exception:
                        pass
                    finally:
                        sock.close()
                    return {
                        "port": port,
                        "service": self._identify_service(port, banner),
                        "banner": banner.decode("utf-8", errors="replace").strip(),
                        "raw_banner": banner,
                    }
                else:
                    sock.close()
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self._max_threads) as executor:
            futures = {executor.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                if self._stop_flag.is_set():
                    break
                result = future.result()
                if result:
                    open_ports.append(result)

        return sorted(open_ports, key=lambda x: x["port"])

    def _get_probe(self, port: int) -> bytes:
        """获取端口探测数据"""
        probes = {
            80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            443: b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00",
            8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            25: b"EHLO gatekeeper\r\n",
            110: b"",
            143: b"",
        }
        return probes.get(port, b"")

    def _identify_service(self, port: int, banner: bytes) -> str:
        """根据端口和banner识别服务"""
        banner_str = banner.decode("utf-8", errors="replace").strip().lower()

        # 常见服务banner特征
        service_signatures = [
            ("ssh", ["ssh-", "openssh", "dropbear"]),
            ("http", ["http/", "apache", "nginx", "server:", "iis"]),
            ("ftp", ["ftp", "vsftpd", "proftpd", "pure-ftpd", "filezilla"]),
            ("smtp", ["smtp", "postfix", "sendmail", "exim"]),
            ("mysql", ["mysql", "mariadb"]),
            ("redis", ["redis"]),
            ("mongodb", ["mongodb"]),
            ("pop3", ["pop3", "+ok"]),
            ("imap", ["imap", "* ok"]),
            ("smb", ["smb"]),
        ]

        for service_name, signatures in service_signatures:
            for sig in signatures:
                if sig in banner_str:
                    return service_name

        # 根据端口推断
        port_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 5672: "amqp",
            5900: "vnc", 6379: "redis", 8080: "http",
            8443: "https", 9200: "elasticsearch", 11211: "memcached",
            27017: "mongodb",
        }

        return port_services.get(port, "unknown")

    def _check_known_vulns(self, host: str, port: int,
                           service: str, banner: str) -> List[VulnScanResult]:
        """基于CVE数据库检测已知漏洞"""
        results = []

        for vuln in VULN_DATABASE:
            if vuln["service"] != service:
                continue

            if vuln["version_pattern"] in banner:
                results.append(VulnScanResult(
                    host=host,
                    port=port,
                    service=service,
                    vulnerability=vuln["desc"],
                    severity=vuln["severity"],
                    cve_id=vuln["cve"],
                    cvss_score=vuln["cvss"],
                    description=vuln["desc"],
                    solution=vuln["solution"],
                    evidence="Banner: {}".format(banner[:200]),
                ))

        return results

    def _check_dangerous_port(self, host: str, port: int,
                              service: str) -> Optional[VulnScanResult]:
        """检查是否为危险端口"""
        if port not in DANGEROUS_PORTS:
            return None

        info = DANGEROUS_PORTS[port]
        return VulnScanResult(
            host=host,
            port=port,
            service=service,
            vulnerability="危险端口开放: {}".format(info["service"]),
            severity=info["severity"],
            description=info["desc"],
            solution=info["solution"],
            evidence="端口 {} ({}) 处于开放状态".format(port, info["service"]),
        )

    def _check_weak_credentials(self, host: str, port: int,
                                service: str) -> List[VulnScanResult]:
        """弱口令检测（模拟检测，不实际尝试登录）"""
        results = []

        if service not in COMMON_CREDENTIALS:
            return results

        # 检测是否存在弱口令风险（基于服务类型和banner特征）
        creds = COMMON_CREDENTIALS.get(service, [])

        if creds:
            results.append(VulnScanResult(
                host=host,
                port=port,
                service=service,
                vulnerability="弱口令风险",
                severity="high",
                description="服务 {} (端口 {}) 存在弱口令风险，共检测到 {} 组常见弱口令组合".format(
                    service, port, len(creds)
                ),
                solution="修改默认密码，使用强密码策略，启用多因素认证",
                evidence="服务类型: {}, 常见弱口令组合数: {}".format(service, len(creds)),
            ))

        return results

    def _check_ssl_tls(self, host: str, port: int) -> List[VulnScanResult]:
        """SSL/TLS证书检查"""
        results = []

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # 检查TLS版本
                    if version and "TLSv1" in version and "1.3" not in version:
                        results.append(VulnScanResult(
                            host=host,
                            port=port,
                            service="ssl/tls",
                            vulnerability="弱TLS版本",
                            severity="medium",
                            description="服务器使用 {} 协议，建议升级到TLS 1.2+".format(version),
                            solution="升级到TLS 1.2或更高版本，禁用TLS 1.0/1.1",
                            evidence="TLS版本: {}".format(version),
                        ))

                    # 检查加密套件
                    if cipher:
                        cipher_name = cipher[0]
                        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
                        for weak in weak_ciphers:
                            if weak in cipher_name.upper():
                                results.append(VulnScanResult(
                                    host=host,
                                    port=port,
                                    service="ssl/tls",
                                    vulnerability="弱加密套件",
                                    severity="medium",
                                    description="检测到弱加密套件: {}".format(cipher_name),
                                    solution="禁用弱加密套件，使用AES-GCM或ChaCha20",
                                    evidence="加密套件: {}".format(cipher_name),
                                ))
                                break

                    # 检查证书
                    if cert:
                        import ssl as ssl_module
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend

                        try:
                            parsed_cert = x509.load_der_x509_certificate(
                                cert, default_backend()
                            )
                            # 检查证书过期
                            now = datetime.now()
                            if parsed_cert.not_valid_after_utc:
                                expiry = parsed_cert.not_valid_after_utc.replace(tzinfo=None)
                            else:
                                expiry = parsed_cert.not_valid_after

                            days_to_expire = (expiry - now).days
                            if days_to_expire < 0:
                                results.append(VulnScanResult(
                                    host=host,
                                    port=port,
                                    service="ssl/tls",
                                    vulnerability="SSL证书已过期",
                                    severity="high",
                                    description="SSL证书已于 {} 过期".format(
                                        expiry.strftime("%Y-%m-%d")
                                    ),
                                    solution="立即更新SSL证书",
                                    evidence="过期日期: {}".format(expiry.strftime("%Y-%m-%d")),
                                ))
                            elif days_to_expire < 30:
                                results.append(VulnScanResult(
                                    host=host,
                                    port=port,
                                    service="ssl/tls",
                                    vulnerability="SSL证书即将过期",
                                    severity="medium",
                                    description="SSL证书将在 {} 天后过期 ({})".format(
                                        days_to_expire, expiry.strftime("%Y-%m-%d")
                                    ),
                                    solution="尽快续签SSL证书",
                                    evidence="过期日期: {}".format(expiry.strftime("%Y-%m-%d")),
                                ))

                            # 检查自签名证书
                            try:
                                issuer = parsed_cert.issuer.rfc4514_string()
                                subject = parsed_cert.subject.rfc4514_string()
                                if issuer == subject:
                                    results.append(VulnScanResult(
                                        host=host,
                                        port=port,
                                        service="ssl/tls",
                                        vulnerability="自签名SSL证书",
                                        severity="low",
                                        description="服务器使用自签名SSL证书",
                                        solution="使用受信任的CA签发证书",
                                        evidence="颁发者: {}".format(issuer),
                                    ))
                            except Exception:
                                pass

                        except ImportError:
                            # cryptography库不可用时，跳过证书解析
                            pass
                        except Exception as e:
                            logger.debug("证书解析失败: {}".format(e))

        except ssl.SSLError as e:
            results.append(VulnScanResult(
                host=host,
                port=port,
                service="ssl/tls",
                vulnerability="SSL/TLS连接异常",
                severity="medium",
                description="SSL/TLS握手失败: {}".format(str(e)[:200]),
                solution="检查SSL证书配置",
                evidence=str(e)[:200],
            ))
        except Exception as e:
            logger.debug("SSL检查失败 {}:{}".format(host, port))

        return results

    def _check_http_headers(self, host: str, port: int) -> List[VulnScanResult]:
        """HTTP安全头检测"""
        results = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((host, port))

            request = "HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n".format(host)
            sock.send(request.encode())

            response = sock.recv(4096).decode("utf-8", errors="replace")
            sock.close()

            # 检查安全头
            security_headers = {
                "X-Frame-Options": {
                    "missing_severity": "medium",
                    "desc": "缺少X-Frame-Options头，可能导致点击劫持攻击",
                    "solution": "添加 X-Frame-Options: DENY 或 SAMEORIGIN",
                },
                "X-Content-Type-Options": {
                    "missing_severity": "low",
                    "desc": "缺少X-Content-Type-Options头，可能导致MIME类型嗅探",
                    "solution": "添加 X-Content-Type-Options: nosniff",
                },
                "X-XSS-Protection": {
                    "missing_severity": "medium",
                    "desc": "缺少X-XSS-Protection头，浏览器XSS过滤可能被禁用",
                    "solution": "添加 X-XSS-Protection: 1; mode=block",
                },
                "Strict-Transport-Security": {
                    "missing_severity": "medium",
                    "desc": "缺少Strict-Transport-Security (HSTS)头",
                    "solution": "添加 Strict-Transport-Security: max-age=31536000; includeSubDomains",
                },
                "Content-Security-Policy": {
                    "missing_severity": "medium",
                    "desc": "缺少Content-Security-Policy (CSP)头",
                    "solution": "配置合适的Content-Security-Policy策略",
                },
            }

            for header_name, info in security_headers.items():
                if header_name.lower() not in response.lower():
                    results.append(VulnScanResult(
                        host=host,
                        port=port,
                        service="http",
                        vulnerability="缺少安全头: {}".format(header_name),
                        severity=info["missing_severity"],
                        description=info["desc"],
                        solution=info["solution"],
                        evidence="HTTP响应中未找到 {} 头".format(header_name),
                    ))

            # 检查Server版本信息泄露
            server_match = re.search(r"Server:\s*(.+?)[\r\n]", response, re.IGNORECASE)
            if server_match:
                server_info = server_match.group(1).strip()
                results.append(VulnScanResult(
                    host=host,
                    port=port,
                    service="http",
                    vulnerability="服务器版本信息泄露",
                    severity="low",
                    description="HTTP响应头中暴露了服务器版本信息: {}".format(server_info),
                    solution="配置服务器隐藏版本信息",
                    evidence="Server: {}".format(server_info),
                ))

        except Exception as e:
            logger.debug("HTTP头检测失败 {}:{}".format(host, port))

        return results

    def _check_ssh_config(self, host: str, port: int,
                          banner: str) -> List[VulnScanResult]:
        """SSH配置检测"""
        results = []

        # 检查SSH版本
        if banner:
            # 检查旧版SSH
            if "OpenSSH_5" in banner or "OpenSSH_6" in banner or "OpenSSH_7" in banner:
                results.append(VulnScanResult(
                    host=host,
                    port=port,
                    service="ssh",
                    vulnerability="SSH版本过旧",
                    severity="medium",
                    description="检测到旧版SSH: {}".format(banner.split("\n")[0][:100]),
                    solution="升级到OpenSSH 8.0+版本",
                    evidence="Banner: {}".format(banner.split("\n")[0][:200]),
                ))

            # 检查弱加密算法（基于banner信息推断）
            weak_algo_patterns = [
                ("SSH-1", "critical", "SSH协议版本1已被弃用，存在严重安全漏洞"),
            ]
            for pattern, severity, desc in weak_algo_patterns:
                if pattern in banner:
                    results.append(VulnScanResult(
                        host=host,
                        port=port,
                        service="ssh",
                        vulnerability="SSH弱协议/算法",
                        severity=severity,
                        description=desc,
                        solution="升级SSH到最新版本，禁用SSH协议版本1和弱加密算法",
                        evidence="Banner: {}".format(banner.split("\n")[0][:200]),
                    ))

        # 通用SSH安全建议
        results.append(VulnScanResult(
            host=host,
            port=port,
            service="ssh",
            vulnerability="SSH安全配置建议",
            severity="info",
            description="建议检查SSH配置: 禁用root远程登录、禁用空密码、使用密钥认证",
            solution="在sshd_config中设置: PermitRootLogin no, PasswordAuthentication no, PubkeyAuthentication yes",
            evidence="SSH端口 {} 开放".format(port),
        ))

        return results


# ============================================================
# 单例管理
# ============================================================

_vuln_scanner: Optional[VulnScanner] = None
_scanner_lock = threading.Lock()


def get_vuln_scanner() -> VulnScanner:
    """获取漏洞扫描器单例"""
    global _vuln_scanner
    with _scanner_lock:
        if _vuln_scanner is None:
            _vuln_scanner = VulnScanner()
        return _vuln_scanner
