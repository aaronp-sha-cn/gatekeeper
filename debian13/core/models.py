"""
GateKeeper - 数据模型
基于SQLAlchemy ORM的完整数据模型定义
"""

import datetime
import enum
from typing import Optional

from sqlalchemy import (
    Column, Integer, String, Boolean, Float, DateTime, Text,
    ForeignKey, Index, Enum, JSON, BigInteger, LargeBinary
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from config.database import Base


# ============================================================
# 枚举类型定义
# ============================================================

class AlertLevel(str, enum.Enum):
    """告警级别枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    """告警状态枚举"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    IGNORED = "ignored"


class VulnSeverity(str, enum.Enum):
    """漏洞严重程度枚举"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(str, enum.Enum):
    """扫描状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FirewallAction(str, enum.Enum):
    """防火墙动作枚举"""
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"
    LOG = "log"


class ProtocolType(str, enum.Enum):
    """协议类型枚举"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class ThreatLevel(str, enum.Enum):
    """威胁级别枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UserRole(str, enum.Enum):
    """用户角色枚举 - 使用大写以兼容数据库存储"""
    SUPER_ADMIN = "SUPER_ADMIN"  # 超级管理员 - 可管理所有模块和用户
    ADMIN = "ADMIN"              # 管理员 - 可管理用户和配置
    OPERATOR = "OPERATOR"        # 操作员 - 可操作安全模块
    VIEWER = "VIEWER"            # 查看者 - 仅查看


class AttackType(str, enum.Enum):
    """攻击类型枚举"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    EXPLOIT = "exploit"
    MALICIOUS_TOOL = "malicious_tool"
    DOS = "dos"
    OTHER = "other"


class AttackSeverity(str, enum.Enum):
    """攻击严重程度枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================
# 用户模型
# ============================================================

class User(Base):
    """用户表 - 管理系统用户"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    last_login = Column(DateTime, nullable=True)
    login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    must_change_password = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    # 关系
    alerts = relationship("Alert", back_populates="assigned_user", foreign_keys="[Alert.assigned_to]")
    firewall_rules = relationship("FirewallRule", back_populates="created_by_user")

    # Flask-Login 接口
    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return "<User(id={}, username='{}', role='{}')>".format(self.id, self.username, self.role)


# ============================================================
# 网络接口模型
# ============================================================

class NetworkInterface(Base):
    """网络接口表 - 记录监控的网络接口信息"""
    __tablename__ = "network_interfaces"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), nullable=False, unique=True)
    ip_address = Column(String(45), nullable=True)
    netmask = Column(String(45), nullable=True)
    mac_address = Column(String(17), nullable=True)
    interface_type = Column(String(32), default="ethernet", nullable=False)
    is_monitoring = Column(Boolean, default=False, nullable=False)
    is_up = Column(Boolean, default=False, nullable=False)
    speed_mbps = Column(Integer, nullable=True)
    mtu = Column(Integer, default=1500, nullable=False)
    rx_packets = Column(BigInteger, default=0, nullable=False)
    tx_packets = Column(BigInteger, default=0, nullable=False)
    rx_bytes = Column(BigInteger, default=0, nullable=False)
    tx_bytes = Column(BigInteger, default=0, nullable=False)
    rx_errors = Column(BigInteger, default=0, nullable=False)
    tx_errors = Column(BigInteger, default=0, nullable=False)
    last_seen = Column(DateTime, server_default=func.now(), nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    # 关系
    traffic_logs = relationship("TrafficLog", back_populates="interface")

    def __repr__(self):
        return "<NetworkInterface(id={}, name='{}', ip='{}')>".format(self.id, self.name, self.ip_address)


# ============================================================
# 防火墙规则模型
# ============================================================

class FirewallRule(Base):
    """防火墙规则表 - 管理防火墙规则"""
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    chain = Column(String(32), default="INPUT", nullable=False)
    protocol = Column(Enum(ProtocolType), default=ProtocolType.ANY, nullable=False)
    source_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    dest_ip = Column(String(45), nullable=True)
    dest_port = Column(Integer, nullable=True)
    action = Column(Enum(FirewallAction), default=FirewallAction.DROP, nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, default=100, nullable=False)
    hit_count = Column(BigInteger, default=0, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    # 关系
    created_by_user = relationship("User", back_populates="firewall_rules")

    def __repr__(self):
        return "<FirewallRule(id={}, name='{}', action='{}')>".format(self.id, self.name, self.action)


# ============================================================
# 流量日志模型
# ============================================================

class TrafficLog(Base):
    """流量日志表 - 记录网络流量数据"""
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False, index=True)
    interface_id = Column(Integer, ForeignKey("network_interfaces.id"), nullable=True)
    source_ip = Column(String(45), nullable=False, index=True)
    dest_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=False)
    packet_length = Column(Integer, nullable=False)
    flags = Column(String(32), nullable=True)
    ttl = Column(Integer, nullable=True)
    is_anomaly = Column(Boolean, default=False, nullable=False, index=True)
    anomaly_score = Column(Float, nullable=True)
    threat_label = Column(String(64), nullable=True)
    raw_packet = Column(LargeBinary, nullable=True)

    # 关系
    interface = relationship("NetworkInterface", back_populates="traffic_logs")

    # 索引
    __table_args__ = (
        Index("idx_traffic_src_dst", "source_ip", "dest_ip"),
        Index("idx_traffic_timestamp_proto", "timestamp", "protocol"),
    )

    def __repr__(self):
        return (
            "<TrafficLog(id={}, src='{}', dst='{}', proto='{}')>".format(
                self.id, self.source_ip, self.dest_ip, self.protocol
            )
        )


# ============================================================
# 告警模型
# ============================================================

class Alert(Base):
    """告警表 - 管理安全告警"""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    level = Column(Enum(AlertLevel), default=AlertLevel.MEDIUM, nullable=False, index=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW, nullable=False, index=True)
    source = Column(String(64), nullable=False)  # 告警来源: ids, vuln_scanner, firewall, ai_engine
    source_ip = Column(String(45), nullable=True)
    dest_ip = Column(String(45), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    severity_score = Column(Float, nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolution_note = Column(Text, nullable=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    # 关系
    assigned_user = relationship("User", back_populates="alerts", foreign_keys=[assigned_to])

    def __repr__(self):
        return "<Alert(id={}, title='{}', level='{}', status='{}')>".format(self.id, self.title, self.level, self.status)


# ============================================================
# 漏洞模型
# ============================================================

class Vulnerability(Base):
    """漏洞表 - 记录发现的漏洞"""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scan_results.id"), nullable=True)
    host = Column(String(45), nullable=False, index=True)
    port = Column(Integer, nullable=True)
    service = Column(String(128), nullable=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(VulnSeverity), default=VulnSeverity.MEDIUM, nullable=False, index=True)
    cve_id = Column(String(32), nullable=True)
    cvss_score = Column(Float, nullable=True)
    solution = Column(Text, nullable=True)
    references = Column(JSON, nullable=True)
    is_confirmed = Column(Boolean, default=False, nullable=False)
    is_fixed = Column(Boolean, default=False, nullable=False)
    fixed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self):
        return "<Vulnerability(id={}, name='{}', severity='{}', host='{}')>".format(self.id, self.name, self.severity, self.host)


# ============================================================
# IDS规则模型
# ============================================================

class IDSRule(Base):
    """IDS规则表 - 管理入侵检测规则"""
    __tablename__ = "ids_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(String(64), unique=True, nullable=False)  # 规则唯一标识
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(64), nullable=True)
    protocol = Column(String(16), nullable=True)
    source_ip = Column(String(45), nullable=True)
    source_port = Column(String(64), nullable=True)
    dest_ip = Column(String(45), nullable=True)
    dest_port = Column(String(64), nullable=True)
    pattern = Column(Text, nullable=True)  # 匹配模式/正则表达式
    pattern_type = Column(String(32), default="regex", nullable=False)  # regex / pcre / content
    is_enabled = Column(Boolean, default=True, nullable=False)
    confidence = Column(Float, default=0.8, nullable=False)  # 规则置信度
    hit_count = Column(BigInteger, default=0, nullable=False)
    last_hit = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self):
        return "<IDSRule(id={}, rule_id='{}', name='{}')>".format(self.id, self.rule_id, self.name)


# ============================================================
# 扫描结果模型
# ============================================================

class ScanResult(Base):
    """扫描结果表 - 记录漏洞扫描任务"""
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_type = Column(String(64), nullable=False)  # vuln_scan / port_scan / service_scan
    target = Column(String(256), nullable=False)  # 扫描目标: IP/CIDR/域名
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    total_hosts = Column(Integer, default=0, nullable=False)
    scanned_hosts = Column(Integer, default=0, nullable=False)
    total_vulns = Column(Integer, default=0, nullable=False)
    critical_vulns = Column(Integer, default=0, nullable=False)
    high_vulns = Column(Integer, default=0, nullable=False)
    medium_vulns = Column(Integer, default=0, nullable=False)
    low_vulns = Column(Integer, default=0, nullable=False)
    scan_options = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    # 关系
    vulnerabilities = relationship("Vulnerability", backref="scan_result")

    def __repr__(self):
        return "<ScanResult(id={}, type='{}', target='{}', status='{}')>".format(self.id, self.scan_type, self.target, self.status)


# ============================================================
# 系统配置模型
# ============================================================

class SystemConfig(Base):
    """系统配置表 - 存储动态配置"""
    __tablename__ = "system_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    category = Column(String(64), nullable=False, index=True)
    key = Column(String(128), nullable=False)
    value = Column(Text, nullable=False)
    value_type = Column(String(32), default="string", nullable=False)  # string / int / float / bool / json
    description = Column(Text, nullable=True)
    is_readonly = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (
        Index("idx_config_category_key", "category", "key", unique=True),
    )

    def get_typed_value(self):
        """根据value_type返回正确类型的值"""
        if self.value_type == "int":
            return int(self.value)
        elif self.value_type == "float":
            return float(self.value)
        elif self.value_type == "bool":
            return self.value.lower() in ("true", "1", "yes")
        elif self.value_type == "json":
            import json
            return json.loads(self.value)
        return self.value

    def __repr__(self):
        return "<SystemConfig(id={}, category='{}', key='{}')>".format(self.id, self.category, self.key)


# ============================================================
# DHCP子网模型 - 支持多IP地址段和VLAN
# ============================================================

class DHCPSubnet(Base):
    """DHCP子网配置表 - 支持多IP地址段和VLAN绑定"""
    __tablename__ = "dhcp_subnets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), nullable=False)  # 子网名称，如"办公网"、"访客网"
    network = Column(String(18), nullable=False)  # 网络地址，如 192.168.1.0/24
    gateway = Column(String(45), nullable=False)  # 网关地址
    start_ip = Column(String(45), nullable=False)  # DHCP起始IP
    end_ip = Column(String(45), nullable=False)  # DHCP结束IP
    lease_time = Column(Integer, default=86400, nullable=False)  # 租约时间（秒）
    dns_servers = Column(String(255), nullable=True)  # DNS服务器，逗号分隔
    interface = Column(String(32), nullable=False)  # 绑定的网络接口
    vlan_id = Column(Integer, nullable=True)  # VLAN ID (1-4094)，None表示无VLAN
    vlan_interface = Column(String(32), nullable=True)  # VLAN接口名，如 eth1.100
    is_enabled = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, default=100, nullable=False)  # 优先级，数字越小优先级越高
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    # 索引
    __table_args__ = (
        Index("idx_dhcp_subnet_vlan", "vlan_id"),
        Index("idx_dhcp_subnet_interface", "interface"),
    )

    def __repr__(self):
        return "<DHCPSubnet(id={}, name='{}', network='{}', vlan={})>".format(
            self.id, self.name, self.network, self.vlan_id
        )


class DHCPLease(Base):
    """DHCP租约记录表"""
    __tablename__ = "dhcp_leases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    subnet_id = Column(Integer, ForeignKey("dhcp_subnets.id"), nullable=False)
    mac_address = Column(String(17), nullable=False, index=True)  # MAC地址
    ip_address = Column(String(45), nullable=False, index=True)  # 分配的IP地址
    hostname = Column(String(64), nullable=True)  # 客户端主机名
    lease_start = Column(DateTime, server_default=func.now(), nullable=False)
    lease_end = Column(DateTime, nullable=False)  # 租约到期时间
    is_active = Column(Boolean, default=True, nullable=False)
    client_id = Column(String(64), nullable=True)  # 客户端标识

    # 关系
    subnet = relationship("DHCPSubnet", backref="leases")

    def __repr__(self):
        return "<DHCPLease(id={}, mac='{}', ip='{}')>".format(self.id, self.mac_address, self.ip_address)


# ============================================================
# 威胁情报模型
# ============================================================

class ThreatIntel(Base):
    """威胁情报表 - 存储威胁情报数据"""
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String(32), nullable=False)  # ip / domain / url / hash / email
    indicator_value = Column(String(512), nullable=False, index=True)
    threat_type = Column(String(64), nullable=True)  # malware / phishing / c2 / botnet / spam
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.MEDIUM, nullable=False, index=True)
    confidence = Column(Float, default=0.5, nullable=False)
    source = Column(String(128), nullable=False)  # 情报来源
    description = Column(Text, nullable=True)
    affected_systems = Column(JSON, nullable=True)
    ioc_data = Column(JSON, nullable=True)  # 入侵指标数据
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self):
        return (
            "<ThreatIntel(id={}, type='{}', value='{}', level='{}')>".format(
                self.id, self.indicator_type, self.indicator_value, self.threat_level
            )
        )


# ============================================================
# 攻击日志模型 (IDS)
# ============================================================

class AttackLog(Base):
    """攻击日志表 - 记录IDS检测到的攻击"""
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False, index=True)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False)
    dst_port = Column(Integer, nullable=True)
    attack_type = Column(Enum(AttackType), nullable=False, index=True)
    severity = Column(Enum(AttackSeverity), nullable=False, index=True)
    signature = Column(String(256), nullable=False)  # 匹配的攻击签名名称
    description = Column(Text, nullable=True)
    payload_preview = Column(Text, nullable=True)  # 攻击载荷预览
    protocol = Column(String(16), nullable=True)
    is_blocked = Column(Boolean, default=False, nullable=False)  # 是否已被阻断
    block_reason = Column(String(256), nullable=True)  # 阻断原因
    
    # 索引
    __table_args__ = (
        Index("idx_attack_src_time", "src_ip", "timestamp"),
        Index("idx_attack_type_severity", "attack_type", "severity"),
    )

    def __repr__(self):
        return "<AttackLog(id={}, src='{}', type='{}', severity='{}')>".format(
            self.id, self.src_ip, self.attack_type.value, self.severity.value
        )


# ============================================================
# 操作日志模型
# ============================================================

class AuditLog(Base):
    """操作审计日志表 - 记录Web和CLI的所有操作"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False, index=True)
    source = Column(String(16), nullable=False, index=True)  # web / cli / api / system
    username = Column(String(64), nullable=True, index=True)  # 操作用户
    action = Column(String(64), nullable=False, index=True)  # 操作类型
    module = Column(String(64), nullable=True, index=True)  # 功能模块
    detail = Column(Text, nullable=True)  # 操作详情
    client_ip = Column(String(45), nullable=True, index=True)  # 客户端IP
    user_agent = Column(String(256), nullable=True)  # 浏览器UA
    result = Column(String(16), nullable=False, default="success")  # success / failure
    error_message = Column(Text, nullable=True)  # 失败原因
    request_data = Column(Text, nullable=True)  # 请求数据(JSON)

    # 索引
    __table_args__ = (
        Index("idx_audit_source_time", "source", "timestamp"),
        Index("idx_audit_user_action", "username", "action"),
    )

    def __repr__(self):
        return "<AuditLog(id={}, src='{}', user='{}', action='{}')>".format(
            self.id, self.source, self.username, self.action
        )
