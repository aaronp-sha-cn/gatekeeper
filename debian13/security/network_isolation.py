"""
GateKeeper - 网络隔离模块
提供网络区域隔离、隔离规则管理和流量控制功能
"""

import json
import uuid
import threading
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any

from config.logging_config import get_logger
from core.database import db_manager

logger = get_logger("network_isolation")


# ============================================================
# 数据模型（内存 + JSON 持久化）
# ============================================================

class IsolationZone:
    """隔离区域"""

    SECURITY_LEVELS = ["public", "trusted", "restricted", "guest", "dmz"]

    def __init__(self, name: str, description: str = "", vlan_id: int = None,
                 subnet_cidr: str = "", interfaces: List[str] = None,
                 security_level: str = "trusted",
                 allowed_zones: List[str] = None,
                 blocked_services: List[str] = None,
                 enabled: bool = True, zone_id: str = None):
        self.id = zone_id or str(uuid.uuid4())[:8]
        self.name = name
        self.description = description
        self.vlan_id = vlan_id
        self.subnet_cidr = subnet_cidr
        self.interfaces = interfaces or []
        self.security_level = security_level
        self.allowed_zones = allowed_zones or []
        self.blocked_services = blocked_services or []
        self.enabled = enabled
        self.created_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "vlan_id": self.vlan_id,
            "subnet_cidr": self.subnet_cidr,
            "interfaces": self.interfaces,
            "security_level": self.security_level,
            "allowed_zones": self.allowed_zones,
            "blocked_services": self.blocked_services,
            "enabled": self.enabled,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IsolationZone":
        zone = cls(
            name=data["name"],
            description=data.get("description", ""),
            vlan_id=data.get("vlan_id"),
            subnet_cidr=data.get("subnet_cidr", ""),
            interfaces=data.get("interfaces", []),
            security_level=data.get("security_level", "trusted"),
            allowed_zones=data.get("allowed_zones", []),
            blocked_services=data.get("blocked_services", []),
            enabled=data.get("enabled", True),
            zone_id=data.get("id"),
        )
        zone.created_at = data.get("created_at", datetime.now().isoformat())
        return zone


class IsolationRule:
    """隔离规则"""

    def __init__(self, name: str, source_zone: str, dest_zone: str,
                 allowed_protocols: List[str] = None,
                 allowed_ports: List[int] = None,
                 direction: str = "bidirectional",
                 schedule: str = "24x7",
                 enabled: bool = True, rule_id: str = None):
        self.id = rule_id or str(uuid.uuid4())[:8]
        self.name = name
        self.source_zone = source_zone
        self.dest_zone = dest_zone
        self.allowed_protocols = allowed_protocols or ["any"]
        self.allowed_ports = allowed_ports or []
        self.direction = direction
        self.schedule = schedule
        self.enabled = enabled
        self.hit_count = 0
        self.created_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "source_zone": self.source_zone,
            "dest_zone": self.dest_zone,
            "allowed_protocols": self.allowed_protocols,
            "allowed_ports": self.allowed_ports,
            "direction": self.direction,
            "schedule": self.schedule,
            "enabled": self.enabled,
            "hit_count": self.hit_count,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IsolationRule":
        rule = cls(
            name=data["name"],
            source_zone=data["source_zone"],
            dest_zone=data["dest_zone"],
            allowed_protocols=data.get("allowed_protocols", ["any"]),
            allowed_ports=data.get("allowed_ports", []),
            direction=data.get("direction", "bidirectional"),
            schedule=data.get("schedule", "24x7"),
            enabled=data.get("enabled", True),
            rule_id=data.get("id"),
        )
        rule.hit_count = data.get("hit_count", 0)
        rule.created_at = data.get("created_at", datetime.now().isoformat())
        return rule


# ============================================================
# 预设模板
# ============================================================

PRESETS = {
    "home": {
        "name": "家庭网络",
        "description": "适用于家庭环境的网络隔离方案",
        "zones": [
            {
                "name": "内网",
                "description": "家庭内网，信任区域",
                "vlan_id": 1,
                "subnet_cidr": "192.168.1.0/24",
                "interfaces": ["eth0"],
                "security_level": "trusted",
                "allowed_zones": ["guest", "iot"],
                "blocked_services": [],
                "enabled": True,
            },
            {
                "name": "访客网络",
                "description": "访客专用网络，与内网隔离",
                "vlan_id": 10,
                "subnet_cidr": "192.168.10.0/24",
                "interfaces": ["eth0.10"],
                "security_level": "guest",
                "allowed_zones": [],
                "blocked_services": ["ssh", "rdp", "smb", "ftp"],
                "enabled": True,
            },
            {
                "name": "IoT设备",
                "description": "物联网设备区域，严格限制",
                "vlan_id": 20,
                "subnet_cidr": "192.168.20.0/24",
                "interfaces": ["eth0.20"],
                "security_level": "restricted",
                "allowed_zones": [],
                "blocked_services": ["ssh", "rdp", "smb", "ftp", "telnet"],
                "enabled": True,
            },
        ],
        "rules": [
            {
                "name": "内网-访客隔离",
                "source_zone": "内网",
                "dest_zone": "访客网络",
                "allowed_protocols": ["icmp"],
                "allowed_ports": [],
                "direction": "one_way",
                "schedule": "24x7",
                "enabled": True,
            },
            {
                "name": "内网-IoT隔离",
                "source_zone": "内网",
                "dest_zone": "IoT设备",
                "allowed_protocols": ["tcp", "udp"],
                "allowed_ports": [80, 443, 53],
                "direction": "one_way",
                "schedule": "24x7",
                "enabled": True,
            },
        ],
    },
    "office": {
        "name": "办公网络",
        "description": "适用于企业办公环境的网络隔离方案",
        "zones": [
            {
                "name": "办公网",
                "description": "员工办公网络",
                "vlan_id": 100,
                "subnet_cidr": "10.0.1.0/24",
                "interfaces": ["eth0"],
                "security_level": "trusted",
                "allowed_zones": ["dmz", "server"],
                "blocked_services": [],
                "enabled": True,
            },
            {
                "name": "访客网络",
                "description": "访客网络，完全隔离",
                "vlan_id": 200,
                "subnet_cidr": "10.0.2.0/24",
                "interfaces": ["eth0.200"],
                "security_level": "guest",
                "allowed_zones": [],
                "blocked_services": ["ssh", "rdp", "smb", "ftp", "telnet"],
                "enabled": True,
            },
            {
                "name": "DMZ",
                "description": "非军事区，放置对外服务",
                "vlan_id": 300,
                "subnet_cidr": "10.0.3.0/24",
                "interfaces": ["eth0.300"],
                "security_level": "dmz",
                "allowed_zones": ["server"],
                "blocked_services": ["ssh", "rdp", "smb"],
                "enabled": True,
            },
            {
                "name": "服务器区",
                "description": "内部服务器区域，高安全级别",
                "vlan_id": 400,
                "subnet_cidr": "10.0.4.0/24",
                "interfaces": ["eth0.400"],
                "security_level": "restricted",
                "allowed_zones": ["office"],
                "blocked_services": ["ftp", "telnet"],
                "enabled": True,
            },
        ],
        "rules": [
            {
                "name": "办公网-DMZ访问",
                "source_zone": "办公网",
                "dest_zone": "DMZ",
                "allowed_protocols": ["tcp"],
                "allowed_ports": [80, 443],
                "direction": "bidirectional",
                "schedule": "24x7",
                "enabled": True,
            },
            {
                "name": "办公网-服务器区访问",
                "source_zone": "办公网",
                "dest_zone": "服务器区",
                "allowed_protocols": ["tcp", "udp"],
                "allowed_ports": [22, 3389, 3306, 5432, 8080],
                "direction": "one_way",
                "schedule": "work_hours",
                "enabled": True,
            },
            {
                "name": "DMZ-服务器区访问",
                "source_zone": "DMZ",
                "dest_zone": "服务器区",
                "allowed_protocols": ["tcp"],
                "allowed_ports": [3306, 5432, 6379],
                "direction": "one_way",
                "schedule": "24x7",
                "enabled": True,
            },
            {
                "name": "访客网络完全隔离",
                "source_zone": "访客网络",
                "dest_zone": "办公网",
                "allowed_protocols": [],
                "allowed_ports": [],
                "direction": "bidirectional",
                "schedule": "24x7",
                "enabled": True,
            },
        ],
    },
    "school": {
        "name": "校园网络",
        "description": "适用于学校/教育机构的网络隔离方案",
        "zones": [
            {
                "name": "教学网",
                "description": "教师和教学设备网络",
                "vlan_id": 50,
                "subnet_cidr": "172.16.1.0/24",
                "interfaces": ["eth0"],
                "security_level": "trusted",
                "allowed_zones": ["student", "server_room"],
                "blocked_services": [],
                "enabled": True,
            },
            {
                "name": "学生网",
                "description": "学生终端网络",
                "vlan_id": 60,
                "subnet_cidr": "172.16.2.0/24",
                "interfaces": ["eth0.60"],
                "security_level": "guest",
                "allowed_zones": [],
                "blocked_services": ["ssh", "rdp", "smb", "ftp", "telnet"],
                "enabled": True,
            },
            {
                "name": "机房",
                "description": "计算机机房，限制访问",
                "vlan_id": 70,
                "subnet_cidr": "172.16.3.0/24",
                "interfaces": ["eth0.70"],
                "security_level": "restricted",
                "allowed_zones": [],
                "blocked_services": ["ssh", "rdp", "smb", "ftp"],
                "enabled": True,
            },
        ],
        "rules": [
            {
                "name": "教学网-学生网隔离",
                "source_zone": "教学网",
                "dest_zone": "学生网",
                "allowed_protocols": ["tcp", "udp"],
                "allowed_ports": [80, 443, 53],
                "direction": "one_way",
                "schedule": "work_hours",
                "enabled": True,
            },
            {
                "name": "机房网络限制",
                "source_zone": "机房",
                "dest_zone": "教学网",
                "allowed_protocols": ["tcp"],
                "allowed_ports": [80, 443],
                "direction": "one_way",
                "schedule": "work_hours",
                "enabled": True,
            },
        ],
    },
    "datacenter": {
        "name": "数据中心",
        "description": "适用于数据中心/IDC机房的网络安全隔离方案",
        "zones": [
            {
                "name": "生产环境",
                "description": "生产业务服务器区域",
                "vlan_id": 1000,
                "subnet_cidr": "10.10.1.0/24",
                "interfaces": ["eth0"],
                "security_level": "restricted",
                "allowed_zones": ["staging", "management"],
                "blocked_services": ["telnet", "ftp"],
                "enabled": True,
            },
            {
                "name": "预发布环境",
                "description": "预发布/测试服务器区域",
                "vlan_id": 1100,
                "subnet_cidr": "10.10.2.0/24",
                "interfaces": ["eth0.1100"],
                "security_level": "restricted",
                "allowed_zones": ["production", "management"],
                "blocked_services": ["telnet", "ftp"],
                "enabled": True,
            },
            {
                "name": "管理网络",
                "description": "运维管理跳板机区域",
                "vlan_id": 1200,
                "subnet_cidr": "10.10.3.0/24",
                "interfaces": ["eth0.1200"],
                "security_level": "trusted",
                "allowed_zones": ["production", "staging", "storage", "backup"],
                "blocked_services": [],
                "enabled": True,
            },
            {
                "name": "存储网络",
                "description": "SAN/NAS 存储区域",
                "vlan_id": 1300,
                "subnet_cidr": "10.10.4.0/24",
                "interfaces": ["eth0.1300"],
                "security_level": "restricted",
                "allowed_zones": ["production", "staging", "backup"],
                "blocked_services": ["ssh", "telnet", "ftp", "http"],
                "enabled": True,
            },
            {
                "name": "备份网络",
                "description": "数据备份专用网络",
                "vlan_id": 1400,
                "subnet_cidr": "10.10.5.0/24",
                "interfaces": ["eth0.1400"],
                "security_level": "restricted",
                "allowed_zones": ["storage"],
                "blocked_services": ["ssh", "telnet", "ftp", "http", "smb"],
                "enabled": True,
            },
        ],
        "rules": [
            {
                "name": "管理网-生产环境访问",
                "source_zone": "管理网络",
                "dest_zone": "生产环境",
                "allowed_protocols": ["tcp", "udp"],
                "allowed_ports": [22, 443, 6379, 3306, 5432, 8080],
                "direction": "one_way",
                "schedule": "24x7",
                "enabled": True,
            },
            {
                "name": "管理网-存储访问",
                "source_zone": "管理网络",
                "dest_zone": "存储网络",
                "allowed_protocols": ["tcp"],
                "allowed_ports": [22, 2049, 3260],
                "direction": "one_way",
                "schedule": "24x7",
                "enabled": True,
            },
            {
                "name": "生产-存储访问",
                "source_zone": "生产环境",
                "dest_zone": "存储网络",
                "allowed_protocols": ["tcp"],
                "allowed_ports": [2049, 3260, 3306, 5432],
                "direction": "one_way",
                "schedule": "24x7",
                "enabled": True,
            },
            {
                "name": "备份-存储访问",
                "source_zone": "备份网络",
                "dest_zone": "存储网络",
                "allowed_protocols": ["tcp"],
                "allowed_ports": [2049, 3260, 22],
                "direction": "one_way",
                "schedule": "off_hours",
                "enabled": True,
            },
        ],
    },
    "iot_factory": {
        "name": "工控网络",
        "description": "适用于工业制造/物联网场景的网络隔离方案",
        "zones": [
            {
                "name": "办公网络",
                "description": "工厂办公区域",
                "vlan_id": 10,
                "subnet_cidr": "192.168.10.0/24",
                "interfaces": ["eth0"],
                "security_level": "trusted",
                "allowed_zones": ["scada", "dmz"],
                "blocked_services": [],
                "enabled": True,
            },
            {
                "name": "SCADA网络",
                "description": "工业控制系统网络，最高安全级别",
                "vlan_id": 20,
                "subnet_cidr": "192.168.20.0/24",
                "interfaces": ["eth0.20"],
                "security_level": "restricted",
                "allowed_zones": ["plc"],
                "blocked_services": ["ssh", "rdp", "smb", "ftp", "telnet", "http"],
                "enabled": True,
            },
            {
                "name": "PLC网络",
                "description": "可编程逻辑控制器网络",
                "vlan_id": 30,
                "subnet_cidr": "192.168.30.0/24",
                "interfaces": ["eth0.30"],
                "security_level": "restricted",
                "allowed_zones": ["scada"],
                "blocked_services": ["ssh", "rdp", "smb", "ftp", "telnet", "http"],
                "enabled": True,
            },
            {
                "name": "DMZ",
                "description": "工厂对外服务区域",
                "vlan_id": 40,
                "subnet_cidr": "192.168.40.0/24",
                "interfaces": ["eth0.40"],
                "security_level": "dmz",
                "allowed_zones": ["office"],
                "blocked_services": ["ssh", "rdp", "smb"],
                "enabled": True,
            },
        ],
        "rules": [
            {
                "name": "办公-SCADA单向访问",
                "source_zone": "办公网络",
                "dest_zone": "SCADA网络",
                "allowed_protocols": ["tcp"],
                "allowed_ports": [443, 502],
                "direction": "one_way",
                "schedule": "work_hours",
                "enabled": True,
            },
            {
                "name": "SCADA-PLC通信",
                "source_zone": "SCADA网络",
                "dest_zone": "PLC网络",
                "allowed_protocols": ["tcp", "udp"],
                "allowed_ports": [502, 44818, 2222],
                "direction": "bidirectional",
                "schedule": "24x7",
                "enabled": True,
            },
            {
                "name": "DMZ-办公隔离",
                "source_zone": "DMZ",
                "dest_zone": "SCADA网络",
                "allowed_protocols": [],
                "allowed_ports": [],
                "direction": "bidirectional",
                "schedule": "24x7",
                "enabled": True,
            },
        ],
    },
    "hotel": {
        "name": "酒店网络",
        "description": "适用于酒店/宾馆的网络隔离方案",
        "zones": [
            {
                "name": "管理网络",
                "description": "酒店管理后台网络",
                "vlan_id": 100,
                "subnet_cidr": "10.0.100.0/24",
                "interfaces": ["eth0"],
                "security_level": "trusted",
                "allowed_zones": ["pms", "guest_wifi"],
                "blocked_services": [],
                "enabled": True,
            },
            {
                "name": "PMS系统",
                "description": "酒店管理系统（PMS）",
                "vlan_id": 200,
                "subnet_cidr": "10.0.200.0/24",
                "interfaces": ["eth0.200"],
                "security_level": "restricted",
                "allowed_zones": ["management"],
                "blocked_services": ["ssh", "rdp", "ftp", "telnet"],
                "enabled": True,
            },
            {
                "name": "客房WiFi",
                "description": "住客无线网络",
                "vlan_id": 300,
                "subnet_cidr": "10.0.3.0/22",
                "interfaces": ["eth0.300"],
                "security_level": "guest",
                "allowed_zones": [],
                "blocked_services": ["ssh", "rdp", "smb", "ftp", "telnet"],
                "enabled": True,
            },
            {
                "name": "会议网络",
                "description": "会议室/活动区域网络",
                "vlan_id": 400,
                "subnet_cidr": "10.0.4.0/24",
                "interfaces": ["eth0.400"],
                "security_level": "guest",
                "allowed_zones": [],
                "blocked_services": ["ssh", "rdp", "smb", "ftp", "telnet"],
                "enabled": True,
            },
        ],
        "rules": [
            {
                "name": "管理-PMS通信",
                "source_zone": "管理网络",
                "dest_zone": "PMS系统",
                "allowed_protocols": ["tcp"],
                "allowed_ports": [22, 443, 3306, 8080],
                "direction": "one_way",
                "schedule": "24x7",
                "enabled": True,
            },
            {
                "name": "客房网络完全隔离",
                "source_zone": "客房WiFi",
                "dest_zone": "管理网络",
                "allowed_protocols": [],
                "allowed_ports": [],
                "direction": "bidirectional",
                "schedule": "24x7",
                "enabled": True,
            },
            {
                "name": "客房-PMS隔离",
                "source_zone": "客房WiFi",
                "dest_zone": "PMS系统",
                "allowed_protocols": [],
                "allowed_ports": [],
                "direction": "bidirectional",
                "schedule": "24x7",
                "enabled": True,
            },
        ],
    },
}


# ============================================================
# 网络隔离管理器
# ============================================================

class NetworkIsolationManager:
    """网络隔离管理器"""

    def __init__(self):
        self._zones: Dict[str, IsolationZone] = {}
        self._rules: Dict[str, IsolationRule] = {}
        self._lock = threading.Lock()
        self._blocked_traffic_count = 0
        self._active_preset = None  # 当前激活的预设模板名称
        self._load_data()
        logger.info("网络隔离管理器初始化完成")

    # ----------------------------------------------------------
    # 持久化
    # ----------------------------------------------------------

    def _get_data_path(self) -> str:
        """获取数据存储路径"""
        import os
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, "network_isolation.json")

    def _load_data(self):
        """从文件加载数据"""
        try:
            import os
            path = self._get_data_path()
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for z in data.get("zones", []):
                    zone = IsolationZone.from_dict(z)
                    self._zones[zone.id] = zone
                for r in data.get("rules", []):
                    rule = IsolationRule.from_dict(r)
                    self._rules[rule.id] = rule
                self._blocked_traffic_count = data.get("blocked_traffic_count", 0)
                self._active_preset = data.get("active_preset")
                logger.info("已加载 {} 个隔离区域, {} 条隔离规则".format(
                    len(self._zones), len(self._rules)))
        except Exception as e:
            logger.error("加载网络隔离数据失败: {}".format(e))

    def _save_data(self):
        """保存数据到文件"""
        try:
            data = {
                "zones": [z.to_dict() for z in self._zones.values()],
                "rules": [r.to_dict() for r in self._rules.values()],
                "blocked_traffic_count": self._blocked_traffic_count,
                "active_preset": self._active_preset,
            }
            with open(self._get_data_path(), "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error("保存网络隔离数据失败: {}".format(e))

    # ----------------------------------------------------------
    # 区域管理
    # ----------------------------------------------------------

    def create_zone(self, zone_data: dict) -> dict:
        """
        创建隔离区域

        Args:
            zone_data: 区域配置字典

        Returns:
            {"status": "ok", "zone": dict} 或 {"status": "error", "message": str}
        """
        with self._lock:
            name = zone_data.get("name", "").strip()
            if not name:
                return {"status": "error", "message": "区域名称不能为空"}

            # 检查名称是否重复
            for z in self._zones.values():
                if z.name == name:
                    return {"status": "error", "message": "区域名称已存在: {}".format(name)}

            security_level = zone_data.get("security_level", "trusted")
            if security_level not in IsolationZone.SECURITY_LEVELS:
                return {"status": "error", "message": "无效的安全级别: {}".format(security_level)}

            zone = IsolationZone(
                name=name,
                description=zone_data.get("description", ""),
                vlan_id=zone_data.get("vlan_id"),
                subnet_cidr=zone_data.get("subnet_cidr", ""),
                interfaces=zone_data.get("interfaces", []),
                security_level=security_level,
                allowed_zones=zone_data.get("allowed_zones", []),
                blocked_services=zone_data.get("blocked_services", []),
                enabled=zone_data.get("enabled", True),
            )
            self._zones[zone.id] = zone
            self._save_data()
            logger.info("创建隔离区域: {} ({})".format(zone.name, zone.id))
            return {"status": "ok", "zone": zone.to_dict()}

    def delete_zone(self, zone_id: str) -> dict:
        """
        删除隔离区域

        Args:
            zone_id: 区域ID

        Returns:
            {"status": "ok"} 或 {"status": "error", "message": str}
        """
        with self._lock:
            if zone_id not in self._zones:
                return {"status": "error", "message": "区域不存在: {}".format(zone_id)}

            zone_name = self._zones[zone_id].name
            del self._zones[zone_id]

            # 同时删除关联规则
            rules_to_remove = [
                rid for rid, rule in self._rules.items()
                if rule.source_zone == zone_name or rule.dest_zone == zone_name
            ]
            for rid in rules_to_remove:
                del self._rules[rid]

            self._save_data()
            logger.info("删除隔离区域: {} (关联规则 {} 条)".format(zone_name, len(rules_to_remove)))
            return {"status": "ok", "removed_rules": len(rules_to_remove)}

    def update_zone(self, zone_id: str, updates: dict) -> dict:
        """
        更新隔离区域

        Args:
            zone_id: 区域ID
            updates: 更新内容字典

        Returns:
            {"status": "ok", "zone": dict} 或 {"status": "error", "message": str}
        """
        with self._lock:
            if zone_id not in self._zones:
                return {"status": "error", "message": "区域不存在: {}".format(zone_id)}

            zone = self._zones[zone_id]

            # 如果修改了名称，需要同步更新规则引用
            new_name = updates.get("name")
            if new_name and new_name != zone.name:
                # 检查名称是否重复
                for z in self._zones.values():
                    if z.id != zone_id and z.name == new_name:
                        return {"status": "error", "message": "区域名称已存在: {}".format(new_name)}
                old_name = zone.name
                zone.name = new_name
                # 更新规则中的区域名称引用
                for rule in self._rules.values():
                    if rule.source_zone == old_name:
                        rule.source_zone = new_name
                    if rule.dest_zone == old_name:
                        rule.dest_zone = new_name

            if "description" in updates:
                zone.description = updates["description"]
            if "vlan_id" in updates:
                zone.vlan_id = updates["vlan_id"]
            if "subnet_cidr" in updates:
                zone.subnet_cidr = updates["subnet_cidr"]
            if "interfaces" in updates:
                zone.interfaces = updates["interfaces"]
            if "security_level" in updates:
                if updates["security_level"] not in IsolationZone.SECURITY_LEVELS:
                    return {"status": "error", "message": "无效的安全级别"}
                zone.security_level = updates["security_level"]
            if "allowed_zones" in updates:
                zone.allowed_zones = updates["allowed_zones"]
            if "blocked_services" in updates:
                zone.blocked_services = updates["blocked_services"]
            if "enabled" in updates:
                zone.enabled = updates["enabled"]

            self._save_data()
            logger.info("更新隔离区域: {}".format(zone.name))
            return {"status": "ok", "zone": zone.to_dict()}

    def get_zones(self) -> List[dict]:
        """获取所有隔离区域"""
        return [z.to_dict() for z in self._zones.values()]

    def get_zone(self, zone_id: str) -> Optional[dict]:
        """获取单个隔离区域"""
        zone = self._zones.get(zone_id)
        return zone.to_dict() if zone else None

    # ----------------------------------------------------------
    # 规则管理
    # ----------------------------------------------------------

    def add_rule(self, rule_data: dict) -> dict:
        """
        添加隔离规则

        Args:
            rule_data: 规则配置字典

        Returns:
            {"status": "ok", "rule": dict} 或 {"status": "error", "message": str}
        """
        with self._lock:
            name = rule_data.get("name", "").strip()
            if not name:
                return {"status": "error", "message": "规则名称不能为空"}

            source_zone = rule_data.get("source_zone", "")
            dest_zone = rule_data.get("dest_zone", "")
            if not source_zone or not dest_zone:
                return {"status": "error", "message": "源区域和目标区域不能为空"}

            # 验证区域是否存在
            zone_names = {z.name for z in self._zones.values()}
            if source_zone not in zone_names:
                return {"status": "error", "message": "源区域不存在: {}".format(source_zone)}
            if dest_zone not in zone_names:
                return {"status": "error", "message": "目标区域不存在: {}".format(dest_zone)}

            direction = rule_data.get("direction", "bidirectional")
            if direction not in ("one_way", "bidirectional"):
                return {"status": "error", "message": "无效的方向: {}".format(direction)}

            schedule = rule_data.get("schedule", "24x7")
            if schedule not in ("24x7", "work_hours", "custom"):
                return {"status": "error", "message": "无效的调度: {}".format(schedule)}

            rule = IsolationRule(
                name=name,
                source_zone=source_zone,
                dest_zone=dest_zone,
                allowed_protocols=rule_data.get("allowed_protocols", ["any"]),
                allowed_ports=rule_data.get("allowed_ports", []),
                direction=direction,
                schedule=schedule,
                enabled=rule_data.get("enabled", True),
            )
            self._rules[rule.id] = rule
            self._save_data()
            logger.info("添加隔离规则: {} ({} -> {})".format(rule.name, source_zone, dest_zone))
            return {"status": "ok", "rule": rule.to_dict()}

    def remove_rule(self, rule_id: str) -> dict:
        """
        删除隔离规则

        Args:
            rule_id: 规则ID

        Returns:
            {"status": "ok"} 或 {"status": "error", "message": str}
        """
        with self._lock:
            if rule_id not in self._rules:
                return {"status": "error", "message": "规则不存在: {}".format(rule_id)}

            rule_name = self._rules[rule_id].name
            del self._rules[rule_id]
            self._save_data()
            logger.info("删除隔离规则: {}".format(rule_name))
            return {"status": "ok"}

    def toggle_rule(self, rule_id: str, enabled: bool) -> dict:
        """
        启用/禁用隔离规则

        Args:
            rule_id: 规则ID
            enabled: 是否启用

        Returns:
            {"status": "ok", "rule": dict} 或 {"status": "error", "message": str}
        """
        with self._lock:
            if rule_id not in self._rules:
                return {"status": "error", "message": "规则不存在: {}".format(rule_id)}

            self._rules[rule_id].enabled = enabled
            self._save_data()
            logger.info("{}隔离规则: {}".format("启用" if enabled else "禁用",
                                                self._rules[rule_id].name))
            return {"status": "ok", "rule": self._rules[rule_id].to_dict()}

    def get_rules(self) -> List[dict]:
        """获取所有隔离规则"""
        return [r.to_dict() for r in self._rules.values()]

    # ----------------------------------------------------------
    # 流量检查
    # ----------------------------------------------------------

    def check_traffic(self, src_zone: str, dst_zone: str,
                      protocol: str = "tcp", port: int = 0) -> dict:
        """
        检查流量是否允许通过

        Args:
            src_zone: 源区域名称
            dst_zone: 目标区域名称
            protocol: 协议 (tcp/udp/icmp/any)
            port: 目标端口

        Returns:
            {"allowed": bool, "reason": str, "matched_rule": str|None}
        """
        with self._lock:
            # 查找源和目标区域
            src = None
            dst = None
            for z in self._zones.values():
                if z.name == src_zone:
                    src = z
                if z.name == dst_zone:
                    dst = z

            if not src:
                return {"allowed": False, "reason": "源区域不存在: {}".format(src_zone),
                        "matched_rule": None}
            if not dst:
                return {"allowed": False, "reason": "目标区域不存在: {}".format(dst_zone),
                        "matched_rule": None}

            if not src.enabled:
                return {"allowed": False, "reason": "源区域已禁用", "matched_rule": None}
            if not dst.enabled:
                return {"allowed": False, "reason": "目标区域已禁用", "matched_rule": None}

            # 同区域流量默认允许
            if src_zone == dst_zone:
                return {"allowed": True, "reason": "同区域流量，默认允许", "matched_rule": None}

            # 检查是否有匹配的规则
            matched_rule = None
            for rule in self._rules.values():
                if not rule.enabled:
                    continue

                # 检查规则的方向匹配
                direction_match = False
                if rule.source_zone == src_zone and rule.dest_zone == dst_zone:
                    direction_match = True
                elif rule.direction == "bidirectional":
                    if rule.source_zone == dst_zone and rule.dest_zone == src_zone:
                        direction_match = True

                if not direction_match:
                    continue

                # 检查协议
                proto_match = "any" in rule.allowed_protocols or protocol in rule.allowed_protocols
                if not proto_match:
                    continue

                # 检查端口
                port_match = True
                if rule.allowed_ports and port > 0:
                    port_match = port in rule.allowed_ports
                if not port_match:
                    continue

                # 检查调度
                schedule_match = self._check_schedule(rule.schedule)
                if not schedule_match:
                    continue

                matched_rule = rule
                break

            if matched_rule:
                # 有匹配规则且允许端口/协议
                if matched_rule.allowed_protocols and matched_rule.allowed_protocols != [""]:
                    matched_rule.hit_count += 1
                    self._save_data()
                    return {
                        "allowed": True,
                        "reason": "匹配规则: {}".format(matched_rule.name),
                        "matched_rule": matched_rule.to_dict(),
                    }
                else:
                    # 空协议列表表示拒绝
                    self._blocked_traffic_count += 1
                    matched_rule.hit_count += 1
                    self._save_data()
                    return {
                        "allowed": False,
                        "reason": "规则明确拒绝: {}".format(matched_rule.name),
                        "matched_rule": matched_rule.to_dict(),
                    }

            # 没有匹配规则，检查区域的allowed_zones
            if dst_zone in src.allowed_zones:
                return {"allowed": True, "reason": "目标区域在源区域的允许列表中",
                        "matched_rule": None}

            # 默认拒绝
            self._blocked_traffic_count += 1
            self._save_data()
            return {"allowed": False, "reason": "默认拒绝：无匹配规则且目标不在允许列表中",
                    "matched_rule": None}

    def _check_schedule(self, schedule: str) -> bool:
        """检查当前时间是否在调度范围内"""
        if schedule == "24x7":
            return True
        elif schedule == "work_hours":
            now = datetime.now()
            # 工作时间: 周一到周五 8:00-18:00
            if now.weekday() >= 5:
                return False
            return 8 <= now.hour < 18
        elif schedule == "custom":
            return True  # 自定义调度暂默认允许
        return True

    # ----------------------------------------------------------
    # 应用隔离规则
    # ----------------------------------------------------------

    def apply_isolation(self) -> dict:
        """
        应用隔离规则到系统

        Returns:
            {"status": "ok", "iptables_rules": list, "message": str}
        """
        try:
            rules = self._apply_iptables_rules()
            logger.info("已应用网络隔离规则，共生成 {} 条iptables规则".format(len(rules)))
            return {
                "status": "ok",
                "iptables_rules": rules,
                "message": "已成功应用 {} 条iptables规则".format(len(rules)),
            }
        except Exception as e:
            logger.error("应用隔离规则失败: {}".format(e))
            return {"status": "error", "message": "应用隔离规则失败: {}".format(str(e))}

    def _apply_iptables_rules(self) -> List[str]:
        """
        生成iptables规则

        Returns:
            iptables规则字符串列表
        """
        iptables_rules = []

        # 创建自定义链
        iptables_rules.append("iptables -N GK_ISOLATION 2>/dev/null || true")
        iptables_rules.append("iptables -F GK_ISOLATION")

        # 为每个启用的区域创建子链
        for zone in self._zones.values():
            if not zone.enabled:
                continue
            chain_name = "GK_ZONE_{}".format(zone.name.upper().replace(" ", "_"))
            iptables_rules.append("iptables -N {} 2>/dev/null || true".format(chain_name))
            iptables_rules.append("iptables -F {}".format(chain_name))

        # 根据规则生成iptables条目
        for rule in self._rules.values():
            if not rule.enabled:
                continue

            src_zone = next((z for z in self._zones.values() if z.name == rule.source_zone), None)
            dst_zone = next((z for z in self._zones.values() if z.name == rule.dest_zone), None)

            if not src_zone or not dst_zone:
                continue

            if not src_zone.enabled or not dst_zone.enabled:
                continue

            # 获取子网
            src_subnet = src_zone.subnet_cidr or "0.0.0.0/0"
            dst_subnet = dst_zone.subnet_cidr or "0.0.0.0/0"

            for proto in rule.allowed_protocols:
                if proto == "any":
                    proto = "all"

                # 正向规则
                if rule.allowed_ports:
                    for port in rule.allowed_ports:
                        rule_str = (
                            "iptables -A GK_ISOLATION -s {} -d {} "
                            "-p {} --dport {} -j ACCEPT"
                        ).format(src_subnet, dst_subnet, proto, port)
                        iptables_rules.append(rule_str)
                else:
                    if rule.allowed_protocols == [""]:
                        # 拒绝规则
                        rule_str = (
                            "iptables -A GK_ISOLATION -s {} -d {} -j DROP"
                        ).format(src_subnet, dst_subnet)
                        iptables_rules.append(rule_str)
                    else:
                        rule_str = (
                            "iptables -A GK_ISOLATION -s {} -d {} -p {} -j ACCEPT"
                        ).format(src_subnet, dst_subnet, proto)
                        iptables_rules.append(rule_str)

                # 双向规则
                if rule.direction == "bidirectional":
                    if rule.allowed_ports:
                        for port in rule.allowed_ports:
                            rule_str = (
                                "iptables -A GK_ISOLATION -s {} -d {} "
                                "-p {} --dport {} -j ACCEPT"
                            ).format(dst_subnet, src_subnet, proto, port)
                            iptables_rules.append(rule_str)
                    elif rule.allowed_protocols != [""]:
                        rule_str = (
                            "iptables -A GK_ISOLATION -s {} -d {} -p {} -j ACCEPT"
                        ).format(dst_subnet, src_subnet, proto)
                        iptables_rules.append(rule_str)

        # 默认拒绝所有区域间流量
        for zone in self._zones.values():
            if not zone.enabled or not zone.subnet_cidr:
                continue
            for other_zone in self._zones.values():
                if other_zone.id == zone.id or not other_zone.enabled:
                    continue
                if not other_zone.subnet_cidr:
                    continue
                # 检查是否已有允许规则（简化处理：在末尾添加默认拒绝）
                rule_str = (
                    "iptables -A GK_ISOLATION -s {} -d {} -j DROP"
                ).format(zone.subnet_cidr, other_zone.subnet_cidr)
                iptables_rules.append(rule_str)

        # 将自定义链加入FORWARD链
        iptables_rules.append("iptables -D FORWARD -j GK_ISOLATION 2>/dev/null || true")
        iptables_rules.append("iptables -A FORWARD -j GK_ISOLATION")

        return iptables_rules

    # ----------------------------------------------------------
    # 状态与拓扑
    # ----------------------------------------------------------

    def get_status(self) -> dict:
        """获取隔离状态概览"""
        zones = list(self._zones.values())
        rules = list(self._rules.values())

        enabled_zones = [z for z in zones if z.enabled]
        enabled_rules = [r for r in rules if r.enabled]

        total_hit_count = sum(r.hit_count for r in rules)

        return {
            "total_zones": len(zones),
            "enabled_zones": len(enabled_zones),
            "total_rules": len(rules),
            "enabled_rules": len(enabled_rules),
            "blocked_traffic_count": self._blocked_traffic_count,
            "total_hit_count": total_hit_count,
            "zones": [z.to_dict() for z in zones],
            "rules": [r.to_dict() for r in rules],
        }

    def get_topology(self) -> dict:
        """
        获取区域拓扑（区域间连接关系）

        Returns:
            {
                "nodes": [{"id", "name", "security_level", "enabled"}],
                "edges": [{"source", "target", "rule_name", "allowed"}]
            }
        """
        nodes = []
        for zone in self._zones.values():
            nodes.append({
                "id": zone.id,
                "name": zone.name,
                "security_level": zone.security_level,
                "enabled": zone.enabled,
                "vlan_id": zone.vlan_id,
                "subnet_cidr": zone.subnet_cidr,
            })

        edges = []
        seen = set()
        for rule in self._rules.values():
            # 正向
            edge_key = (rule.source_zone, rule.dest_zone)
            if edge_key not in seen:
                seen.add(edge_key)
                is_allow = bool(rule.allowed_protocols) and rule.allowed_protocols != [""]
                edges.append({
                    "source": rule.source_zone,
                    "target": rule.dest_zone,
                    "rule_name": rule.name,
                    "allowed": is_allow,
                    "enabled": rule.enabled,
                    "protocols": rule.allowed_protocols,
                    "direction": rule.direction,
                })

            # 双向
            if rule.direction == "bidirectional":
                reverse_key = (rule.dest_zone, rule.source_zone)
                if reverse_key not in seen:
                    seen.add(reverse_key)
                    is_allow = bool(rule.allowed_protocols) and rule.allowed_protocols != [""]
                    edges.append({
                        "source": rule.dest_zone,
                        "target": rule.source_zone,
                        "rule_name": rule.name,
                        "allowed": is_allow,
                        "enabled": rule.enabled,
                        "protocols": rule.allowed_protocols,
                        "direction": rule.direction,
                    })

        return {"nodes": nodes, "edges": edges}

    # ----------------------------------------------------------
    # 预设模板
    # ----------------------------------------------------------

    def apply_preset(self, preset_name: str) -> dict:
        """
        应用预设模板

        Args:
            preset_name: 预设名称 (home/office/school)

        Returns:
            {"status": "ok", "message": str} 或 {"status": "error", "message": str}
        """
        if preset_name not in PRESETS:
            available = ", ".join(PRESETS.keys())
            return {"status": "error", "message": "未知预设: {}，可用预设: {}".format(
                preset_name, available)}

        preset = PRESETS[preset_name]

        with self._lock:
            # 清除现有数据
            self._zones.clear()
            self._rules.clear()

            # 创建预设区域
            for z_data in preset["zones"]:
                zone = IsolationZone(
                    name=z_data["name"],
                    description=z_data.get("description", ""),
                    vlan_id=z_data.get("vlan_id"),
                    subnet_cidr=z_data.get("subnet_cidr", ""),
                    interfaces=z_data.get("interfaces", []),
                    security_level=z_data.get("security_level", "trusted"),
                    allowed_zones=z_data.get("allowed_zones", []),
                    blocked_services=z_data.get("blocked_services", []),
                    enabled=z_data.get("enabled", True),
                )
                self._zones[zone.id] = zone

            # 创建预设规则
            for r_data in preset["rules"]:
                rule = IsolationRule(
                    name=r_data["name"],
                    source_zone=r_data["source_zone"],
                    dest_zone=r_data["dest_zone"],
                    allowed_protocols=r_data.get("allowed_protocols", ["any"]),
                    allowed_ports=r_data.get("allowed_ports", []),
                    direction=r_data.get("direction", "bidirectional"),
                    schedule=r_data.get("schedule", "24x7"),
                    enabled=r_data.get("enabled", True),
                )
                self._rules[rule.id] = rule

            self._blocked_traffic_count = 0
            self._active_preset = preset_name
            self._save_data()

            logger.info("应用预设模板: {} ({} 个区域, {} 条规则)".format(
                preset_name, len(self._zones), len(self._rules)))

            return {
                "status": "ok",
                "message": "已应用预设 '{}'：{} 个区域, {} 条规则".format(
                    preset["name"], len(self._zones), len(self._rules)),
                "zones": [z.to_dict() for z in self._zones.values()],
                "rules": [r.to_dict() for r in self._rules.values()],
            }

    def get_presets(self) -> dict:
        """获取所有可用预设，包含当前激活状态"""
        return {
            "presets": {
                name: {
                    "name": preset["name"],
                    "description": preset["description"],
                    "zone_count": len(preset["zones"]),
                    "rule_count": len(preset["rules"]),
                    "active": (name == self._active_preset),
                }
                for name, preset in PRESETS.items()
            },
            "active_preset": self._active_preset,
        }


# ============================================================
# 单例
# ============================================================

_isolation_manager: Optional[NetworkIsolationManager] = None
_isolation_manager_lock = threading.Lock()


def get_isolation_manager() -> NetworkIsolationManager:
    """获取网络隔离管理器单例"""
    global _isolation_manager
    if _isolation_manager is None:
        with _isolation_manager_lock:
            if _isolation_manager is None:
                _isolation_manager = NetworkIsolationManager()
    return _isolation_manager
