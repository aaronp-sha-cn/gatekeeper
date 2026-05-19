"""
GateKeeper - 资产发现引擎
网络资产自动发现、识别与风险管理
"""

import uuid
import socket
import threading
import time
import csv
import io
import json
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any

from config.logging_config import get_logger

logger = get_logger("asset_discovery")

# ============================================================
# MAC厂商数据库（简洁版：15个厂商，每个3-5个前缀，共约60条）
# ============================================================
MAC_VENDOR_DB = {
    # Apple
    "00:03:93": "Apple", "00:0A:27": "Apple", "00:0D:93": "Apple",
    "00:1E:52": "Apple", "3C:22:FB": "Apple",
    # Huawei
    "00:18:82": "Huawei", "00:1E:73": "Huawei", "08:3A:88": "Huawei",
    "20:7D:74": "Huawei", "48:DB:50": "Huawei",
    # Xiaomi
    "00:9E:C8": "Xiaomi", "10:82:87": "Xiaomi", "28:CF:E9": "Xiaomi",
    "34:CE:C8": "Xiaomi", "78:11:DC": "Xiaomi",
    # TP-Link
    "00:27:19": "TP-Link", "04:D4:C4": "TP-Link", "10:BF:48": "TP-Link",
    "14:CF:92": "TP-Link", "50:C7:BF": "TP-Link",
    # Samsung
    "00:1A:96": "Samsung", "00:25:66": "Samsung", "00:40:A3": "Samsung",
    "14:7D:C5": "Samsung", "A0:CB:FD": "Samsung",
    # Cisco
    "00:0C:29": "Cisco", "00:1B:54": "Cisco", "00:22:55": "Cisco",
    "00:50:56": "Cisco", "F0:AB:30": "Cisco",
    # Intel
    "00:07:E9": "Intel", "00:1B:DC": "Intel", "00:1F:3B": "Intel",
    "3C:97:0E": "Intel", "70:B5:E8": "Intel",
    # Dell
    "00:14:22": "Dell", "00:1C:23": "Dell", "00:1E:4F": "Dell",
    "18:A9:9B": "Dell", "F8:BC:12": "Dell",
    # HPE
    "00:1A:4B": "HPE", "00:1C:C4": "HPE", "00:25:B3": "HPE",
    "2C:41:38": "HPE", "3C:D9:2B": "HPE",
    # ZTE
    "00:23:63": "ZTE", "00:8E:F2": "ZTE", "10:BD:18": "ZTE",
    "14:5E:9F": "ZTE", "CC:96:A0": "ZTE",
    # Lenovo
    "00:09:2D": "Lenovo", "00:24:54": "Lenovo", "00:50:FC": "Lenovo",
    "40:8D:5C": "Lenovo", "88:AE:1D": "Lenovo",
    # OPPO
    "00:7E:75": "OPPO", "3C:06:30": "OPPO", "5C:7D:5E": "OPPO",
    "7C:11:BE": "OPPO", "A8:8E:24": "OPPO",
    # vivo
    "00:7C:48": "vivo", "20:82:87": "vivo", "4C:11:BF": "vivo",
    "70:FD:96": "vivo", "A4:77:33": "vivo",
    # Espressif (ESP32/ESP8266 IoT)
    "00:1A:2B": "Espressif", "18:FE:34": "Espressif",
    "24:0A:C4": "Espressif", "30:AE:A4": "Espressif",
    "BC:DD:C2": "Espressif",
    # Brother (打印机)
    "00:05:74": "Brother", "00:1B:A9": "Brother", "00:80:77": "Brother",
    "30:05:5C": "Brother", "F8:0F:41": "Brother",
}

# 常见服务端口映射
SERVICE_PORT_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS-SSN", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9090: "Prometheus", 27017: "MongoDB",
}

# 高风险端口
HIGH_RISK_PORTS = {23, 135, 445, 3389, 1433, 3306, 5432, 6379, 27017, 5555}


@dataclass
class NetworkAsset:
    """网络资产"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ip_address: str = ""
    mac_address: str = ""
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    vendor: str = ""
    device_type: str = "unknown"  # server/workstation/printer/iot/mobile/router/switch/ap/unknown
    open_ports: List[int] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    is_online: bool = False
    risk_level: str = "low"  # low/medium/high/critical
    vulnerabilities_count: int = 0
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class AssetScanTask:
    """扫描任务"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    scan_type: str = "quick"  # quick/full/custom
    status: str = "pending"  # pending/running/completed/failed/stopped
    progress: int = 0
    started_at: str = ""
    completed_at: str = ""
    discovered_count: int = 0
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AssetDiscoveryManager:
    """资产发现管理器"""

    def __init__(self):
        self._assets: Dict[str, NetworkAsset] = {}
        self._scan_tasks: List[AssetScanTask] = []
        self._current_task: Optional[AssetScanTask] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def start_scan(self, target: str, scan_type: str = "quick",
                   ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        启动扫描任务

        Args:
            target: 扫描目标（IP/CIDR/域名）
            scan_type: 扫描类型 (quick/full/custom)
            ports: 自定义端口列表

        Returns:
            任务信息
        """
        if self._current_task and self._current_task.status == "running":
            return {"status": "error", "message": "已有扫描任务正在运行"}

        task = AssetScanTask(
            target=target,
            scan_type=scan_type,
            status="running",
            started_at=datetime.now().isoformat(),
        )
        self._current_task = task
        self._scan_tasks.insert(0, task)
        self._stop_event.clear()

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(task, scan_type, ports),
            daemon=True,
        )
        self._scan_thread.start()

        logger.info("资产扫描任务已启动: target={}, type={}".format(target, scan_type))
        return {"status": "ok", "task": task.to_dict()}

    def stop_scan(self) -> Dict[str, Any]:
        """停止当前扫描"""
        if not self._current_task or self._current_task.status != "running":
            return {"status": "error", "message": "没有正在运行的扫描任务"}

        self._stop_event.set()
        self._current_task.status = "stopped"
        self._current_task.completed_at = datetime.now().isoformat()
        logger.info("资产扫描任务已停止")
        return {"status": "ok", "message": "扫描已停止"}

    def get_scan_status(self) -> Dict[str, Any]:
        """获取当前扫描状态"""
        if self._current_task:
            return {"status": "ok", "task": self._current_task.to_dict()}
        return {"status": "ok", "task": None}

    def get_assets(self, device_type: Optional[str] = None,
                   vendor: Optional[str] = None,
                   risk_level: Optional[str] = None,
                   online_only: bool = False,
                   page: int = 1, page_size: int = 50) -> Dict[str, Any]:
        """
        查询资产列表

        Args:
            device_type: 按设备类型筛选
            vendor: 按厂商筛选
            risk_level: 按风险级别筛选
            online_only: 仅在线资产
            page: 页码
            page_size: 每页数量

        Returns:
            资产列表与分页信息
        """
        with self._lock:
            assets = list(self._assets.values())

        # 筛选
        if device_type:
            assets = [a for a in assets if a.device_type == device_type]
        if vendor:
            assets = [a for a in assets if vendor.lower() in a.vendor.lower()]
        if risk_level:
            assets = [a for a in assets if a.risk_level == risk_level]
        if online_only:
            assets = [a for a in assets if a.is_online]

        total = len(assets)
        start = (page - 1) * page_size
        end = start + page_size
        page_items = assets[start:end]

        return {
            "status": "ok",
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size if total > 0 else 0,
            "assets": [a.to_dict() for a in page_items],
        }

    def get_asset(self, asset_id: str) -> Dict[str, Any]:
        """获取资产详情"""
        with self._lock:
            asset = self._assets.get(asset_id)
        if not asset:
            return {"status": "error", "message": "资产不存在"}
        return {"status": "ok", "asset": asset.to_dict()}

    def delete_asset(self, asset_id: str) -> Dict[str, Any]:
        """删除资产"""
        with self._lock:
            if asset_id not in self._assets:
                return {"status": "error", "message": "资产不存在"}
            del self._assets[asset_id]
        logger.info("资产已删除: {}".format(asset_id))
        return {"status": "ok", "message": "资产已删除"}

    def update_asset(self, asset_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """更新资产信息"""
        with self._lock:
            asset = self._assets.get(asset_id)
            if not asset:
                return {"status": "error", "message": "资产不存在"}

            for key, value in updates.items():
                if hasattr(asset, key):
                    setattr(asset, key, value)

            # 重新评估风险
            asset.risk_level = self._assess_risk(asset)

        logger.info("资产已更新: {}".format(asset_id))
        return {"status": "ok", "asset": asset.to_dict()}

    def get_stats(self) -> Dict[str, Any]:
        """获取资产统计信息"""
        with self._lock:
            assets = list(self._assets.values())

        total = len(assets)
        online = sum(1 for a in assets if a.is_online)
        offline = total - online

        # 按设备类型统计
        type_counts = {}
        for a in assets:
            t = a.device_type or "unknown"
            type_counts[t] = type_counts.get(t, 0) + 1

        # 按风险级别统计
        risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for a in assets:
            r = a.risk_level or "low"
            if r in risk_counts:
                risk_counts[r] += 1

        # 按厂商统计
        vendor_counts = {}
        for a in assets:
            v = a.vendor or "Unknown"
            vendor_counts[v] = vendor_counts.get(v, 0) + 1

        # 按OS统计
        os_counts = {}
        for a in assets:
            o = a.os_name or "Unknown"
            os_counts[o] = os_counts.get(o, 0) + 1

        return {
            "status": "ok",
            "total": total,
            "online": online,
            "offline": offline,
            "high_risk": risk_counts["high"] + risk_counts["critical"],
            "device_types": type_counts,
            "risk_levels": risk_counts,
            "vendors": vendor_counts,
            "os_distribution": os_counts,
        }

    def get_scan_history(self) -> Dict[str, Any]:
        """获取扫描历史"""
        return {
            "status": "ok",
            "total": len(self._scan_tasks),
            "tasks": [t.to_dict() for t in self._scan_tasks[:20]],
        }

    def export_assets(self, fmt: str = "csv") -> Dict[str, Any]:
        """
        导出资产数据

        Args:
            fmt: 导出格式 (csv/json)

        Returns:
            导出结果
        """
        with self._lock:
            assets = list(self._assets.values())

        if fmt == "json":
            data = json.dumps([a.to_dict() for a in assets], ensure_ascii=False, indent=2)
            return {"status": "ok", "format": "json", "data": data}

        elif fmt == "csv":
            output = io.StringIO()
            if assets:
                writer = csv.DictWriter(output, fieldnames=[
                    "ip_address", "mac_address", "hostname", "os_name",
                    "os_version", "vendor", "device_type", "open_ports",
                    "is_online", "risk_level", "vulnerabilities_count",
                    "first_seen", "last_seen",
                ])
                writer.writeheader()
                for a in assets:
                    writer.writerow({
                        "ip_address": a.ip_address,
                        "mac_address": a.mac_address,
                        "hostname": a.hostname,
                        "os_name": a.os_name,
                        "os_version": a.os_version,
                        "vendor": a.vendor,
                        "device_type": a.device_type,
                        "open_ports": ";".join(str(p) for p in a.open_ports),
                        "is_online": a.is_online,
                        "risk_level": a.risk_level,
                        "vulnerabilities_count": a.vulnerabilities_count,
                        "first_seen": a.first_seen,
                        "last_seen": a.last_seen,
                    })
            data = output.getvalue()
            return {"status": "ok", "format": "csv", "data": data}

        return {"status": "error", "message": "不支持的格式: {}".format(fmt)}

    # ============================================================
    # 内部方法
    # ============================================================

    def _run_scan(self, task: AssetScanTask, scan_type: str,
                  ports: Optional[List[int]] = None):
        """执行扫描（在后台线程中运行）"""
        try:
            target = task.target
            now = datetime.now().isoformat()

            # 解析目标IP列表
            ip_list = self._resolve_targets(target)
            if not ip_list:
                task.status = "failed"
                task.error_message = "无法解析目标: {}".format(target)
                task.completed_at = datetime.now().isoformat()
                return

            total_ips = len(ip_list)

            # 根据扫描类型确定端口
            if scan_type == "quick":
                scan_ports = [21, 22, 23, 80, 443, 3389, 8080]
            elif scan_type == "full":
                scan_ports = list(range(1, 1025))
            elif scan_type == "custom" and ports:
                scan_ports = ports
            else:
                scan_ports = [21, 22, 23, 80, 443, 3389, 8080]

            for idx, ip in enumerate(ip_list):
                if self._stop_event.is_set():
                    break

                task.progress = int((idx / total_ips) * 100)
                task.discovered_count = idx

                try:
                    asset = self._probe_host(ip, scan_ports, now)
                    if asset:
                        with self._lock:
                            # 如果IP已存在，更新资产
                            existing = None
                            for a in self._assets.values():
                                if a.ip_address == ip:
                                    existing = a
                                    break
                            if existing:
                                existing.last_seen = now
                                existing.is_online = True
                                if asset.open_ports:
                                    existing.open_ports = asset.open_ports
                                if asset.services:
                                    existing.services = asset.services
                                if asset.hostname:
                                    existing.hostname = asset.hostname
                                if asset.mac_address:
                                    existing.mac_address = asset.mac_address
                                    existing.vendor = self._identify_vendor(asset.mac_address)
                                existing.risk_level = self._assess_risk(existing)
                            else:
                                with self._lock:
                                    self._assets[asset.id] = asset
                except Exception as e:
                    logger.debug("扫描主机失败 {}: {}".format(ip, e))

            task.progress = 100
            task.discovered_count = len(self._assets)
            task.status = "completed"
            task.completed_at = datetime.now().isoformat()
            logger.info("扫描完成: 发现 {} 个资产".format(len(self._assets)))

        except Exception as e:
            logger.error("扫描任务异常: {}".format(e))
            task.status = "failed"
            task.error_message = str(e)
            task.completed_at = datetime.now().isoformat()

    def _resolve_targets(self, target: str) -> List[str]:
        """解析扫描目标为IP列表"""
        ip_list = []

        # CIDR格式
        if "/" in target:
            try:
                import ipaddress
                network = ipaddress.ip_network(target, strict=False)
                # 限制扫描数量，防止大范围扫描
                hosts = list(network.hosts())
                if len(hosts) > 1024:
                    hosts = hosts[:1024]
                ip_list = [str(h) for h in hosts]
            except ValueError:
                pass
        elif target.replace(".", "").isdigit():
            ip_list = [target]
        else:
            # 尝试域名解析
            try:
                resolved = socket.gethostbyname(target)
                ip_list = [resolved]
            except socket.gaierror:
                pass

        return ip_list

    def _probe_host(self, ip: str, ports: List[int],
                    now: str) -> Optional[NetworkAsset]:
        """探测单个主机"""
        open_ports = []
        services = []
        mac_address = ""
        hostname = ""
        ttl = 0

        # 端口扫描（TCP connect）
        for port in ports:
            if self._stop_event.is_set():
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    svc_name = SERVICE_PORT_MAP.get(port, "unknown")
                    services.append({
                        "port": port,
                        "name": svc_name,
                        "protocol": "tcp",
                    })
                sock.close()
            except (socket.error, OSError):
                pass

        if not open_ports:
            return None

        # TTL探测（用于OS识别）
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((ip, open_ports[0]))
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            sock.close()
        except (socket.error, OSError):
            pass

        # 尝试反向DNS解析
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass

        # OS识别
        os_name, os_version = self._identify_os("", ttl)

        # 设备类型识别
        device_type = self._identify_device_type(open_ports, services, os_name)

        # 创建资产
        asset = NetworkAsset(
            ip_address=ip,
            mac_address=mac_address,
            hostname=hostname,
            os_name=os_name,
            os_version=os_version,
            vendor=self._identify_vendor(mac_address),
            device_type=device_type,
            open_ports=open_ports,
            services=services,
            first_seen=now,
            last_seen=now,
            is_online=True,
        )

        # 评估风险
        asset.risk_level = self._assess_risk(asset)

        return asset

    def _identify_os(self, banner: str, ttl: int) -> tuple:
        """
        通过TTL识别操作系统

        Args:
            banner: 服务banner（备用）
            ttl: TTL值

        Returns:
            (os_name, os_version)
        """
        if ttl <= 0:
            # 尝试从banner识别
            banner_lower = banner.lower() if banner else ""
            if "linux" in banner_lower:
                return ("Linux", "")
            elif "windows" in banner_lower:
                return ("Windows", "")
            return ("Unknown", "")

        if ttl <= 64:
            return ("Linux", "")
        elif ttl <= 128:
            return ("Windows", "")
        elif ttl <= 255:
            return ("Network Device", "")
        else:
            return ("Unknown", "")

    def _identify_vendor(self, mac_address: str) -> str:
        """
        通过MAC前缀识别厂商

        Args:
            mac_address: MAC地址

        Returns:
            厂商名称
        """
        if not mac_address:
            return ""
        # 标准化MAC地址格式
        mac_clean = mac_address.upper().replace("-", ":")
        prefix = mac_clean[:8]  # 前3字节
        return MAC_VENDOR_DB.get(prefix, "")

    def _identify_device_type(self, ports: List[int],
                              services: List[Dict],
                              os_name: str) -> str:
        """
        识别设备类型

        Args:
            ports: 开放端口列表
            services: 服务列表
            os_name: 操作系统名称

        Returns:
            设备类型字符串
        """
        port_set = set(ports)
        svc_names = {s.get("name", "") for s in services}

        # 路由器/交换机特征
        if os_name == "Network Device":
            return "router"

        # 打印机特征
        printer_ports = {80, 443, 515, 631, 9100}
        if port_set & printer_ports:
            if 515 in port_set or 631 in port_set or 9100 in port_set:
                return "printer"

        # IoT设备特征（少量端口，可能有Web管理界面）
        iot_ports = {80, 443, 1883, 5353, 8080, 8443}
        if port_set <= iot_ports and len(port_set) <= 3:
            return "iot"

        # 移动设备特征
        mobile_svcs = {"USBMux", "AirPlay", "AirTunes"}
        if svc_names & mobile_svcs:
            return "mobile"

        # 服务器特征
        server_ports = {22, 80, 443, 3306, 5432, 1433, 8080, 8443, 27017, 6379}
        if len(port_set & server_ports) >= 3:
            return "server"

        # 工作站特征
        workstation_ports = {135, 139, 445, 3389}
        if port_set & workstation_ports:
            return "workstation"

        # 默认判断
        if 22 in port_set and 80 in port_set:
            return "server"
        elif 3389 in port_set:
            return "workstation"
        elif 80 in port_set or 443 in port_set:
            return "server"

        return "unknown"

    def _assess_risk(self, asset: NetworkAsset) -> str:
        """
        评估资产风险级别

        Args:
            asset: 网络资产

        Returns:
            风险级别 (low/medium/high/critical)
        """
        risk_score = 0
        port_set = set(asset.open_ports)

        # 高风险端口开放
        high_risk_open = port_set & HIGH_RISK_PORTS
        risk_score += len(high_risk_open) * 20

        # 开放端口数量
        risk_score += min(len(asset.open_ports), 20)

        # 漏洞数量
        risk_score += asset.vulnerabilities_count * 10

        # Telnet开放（明文传输）
        if 23 in port_set:
            risk_score += 15

        # SMB开放（历史上漏洞多）
        if 445 in port_set:
            risk_score += 10

        # RDP开放
        if 3389 in port_set:
            risk_score += 10

        # 数据库端口开放
        db_ports = {1433, 3306, 5432, 6379, 27017}
        if port_set & db_ports:
            risk_score += 15

        # 判定风险级别
        if risk_score >= 50:
            return "critical"
        elif risk_score >= 30:
            return "high"
        elif risk_score >= 15:
            return "medium"
        return "low"


# ============================================================
# 单例
# ============================================================
_manager_instance: Optional[AssetDiscoveryManager] = None
_manager_lock = threading.Lock()


def get_asset_discovery() -> AssetDiscoveryManager:
    """获取资产发现管理器单例"""
    global _manager_instance
    if _manager_instance is None:
        with _manager_lock:
            if _manager_instance is None:
                _manager_instance = AssetDiscoveryManager()
    return _manager_instance
