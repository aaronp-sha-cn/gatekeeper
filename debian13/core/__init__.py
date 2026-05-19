"""
GateKeeper - 核心模块
提供应用主控、数据库管理、数据模型和任务调度等核心功能
"""

from core.database import DatabaseManager
from core.models import (
    User, NetworkInterface, FirewallRule, TrafficLog,
    Alert, Vulnerability, IDSRule, ScanResult,
    SystemConfig, ThreatIntel, AttackLog,
    AlertLevel, AlertStatus, AttackType, AttackSeverity,
    DHCPSubnet, DHCPLease, AuditLog
)
from core.scheduler import TaskScheduler
from core.audit import AuditLogger, get_audit_logger

__version__ = "1.0.4"


def __getattr__(name):
    """延迟导入 GateKeeper 主类，避免循环依赖"""
    if name == "GateKeeper":
        from core.app import GateKeeper
        return GateKeeper
    raise AttributeError("module 'core' has no attribute '{}'".format(name))


__all__ = [
    "GateKeeper",
    "DatabaseManager",
    "User",
    "NetworkInterface",
    "FirewallRule",
    "TrafficLog",
    "Alert",
    "Vulnerability",
    "IDSRule",
    "ScanResult",
    "SystemConfig",
    "ThreatIntel",
    "AttackLog",
    "AlertLevel",
    "AlertStatus",
    "AttackType",
    "AttackSeverity",
    "DHCPSubnet",
    "DHCPLease",
    "AuditLog",
    "AuditLogger",
    "get_audit_logger",
    "TaskScheduler",
    "__version__",
]
