"""
GateKeeper - 日志配置
提供统一的日志管理，支持文件输出、控制台输出和安全审计日志
"""

import os
import sys
import json
import logging
import traceback
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from datetime import datetime

from config.settings import settings


# ============================================================
# 日志格式定义
# ============================================================

# JSON 日志格式开关 (通过环境变量 GK_LOG_FORMAT=json 启用)
LOG_FORMAT_JSON = os.environ.get("GK_LOG_FORMAT", "").lower() == "json"

# 标准日志格式
STANDARD_FORMAT = settings.log.format_string

# 简洁日志格式（控制台用）
SIMPLE_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"

# 安全审计日志格式
AUDIT_FORMAT = (
    "%(asctime)s | AUDIT | %(levelname)-8s | "
    "%(user)s | %(action)s | %(resource)s | %(result)s | %(message)s"
)

# 日期格式
DATE_FORMAT = settings.log.date_format


# ============================================================
# JSON 日志格式化器
# ============================================================

class JsonFormatter(logging.Formatter):
    """
    JSON 格式日志格式化器
    将日志记录输出为结构化的 JSON 格式，便于日志采集系统解析
    """

    def __init__(self, format_str=None, datefmt=None):
        super().__init__(datefmt=datefmt)
        self._format_str = format_str

    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(datetime.timezone.utc).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info),
            }

        # Include extra fields if present
        for attr in ("user", "action", "resource", "result"):
            if hasattr(record, attr):
                log_entry[attr] = getattr(record, attr)

        return json.dumps(log_entry, ensure_ascii=False, default=str)


# ============================================================
# 日志过滤器
# ============================================================

class SecurityAuditFilter(logging.Filter):
    """安全审计日志过滤器 - 只允许安全相关日志通过"""

    def filter(self, record):
        # 检查日志记录是否包含安全相关标记
        security_keywords = [
            "login", "logout", "auth", "permission", "firewall",
            "block", "allow", "alert", "threat", "intrusion",
            "vulnerability", "scan", "attack", "malicious"
        ]
        record_msg = record.getMessage().lower()
        return any(kw in record_msg for kw in security_keywords)


class SensitiveDataFilter(logging.Filter):
    """敏感数据过滤器 - 过滤日志中的敏感信息"""

    SENSITIVE_PATTERNS = [
        ("password", "***REDACTED***"),
        ("secret", "***REDACTED***"),
        ("token", "***REDACTED***"),
        ("api_key", "***REDACTED***"),
    ]

    def filter(self, record):
        msg = record.getMessage()
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            if pattern in msg.lower():
                record.msg = str(record.msg).replace(
                    pattern, replacement
                )
                if record.args:
                    record.args = tuple(
                        str(arg).replace(pattern, replacement)
                        for arg in record.args
                    )
        return True


# ============================================================
# 日志颜色配置（控制台用）
# ============================================================

class ColorFormatter(logging.Formatter):
    """带颜色的日志格式化器"""

    COLORS = {
        "DEBUG": "\033[36m",      # 青色
        "INFO": "\033[32m",       # 绿色
        "WARNING": "\033[33m",    # 黄色
        "ERROR": "\033[31m",      # 红色
        "CRITICAL": "\033[35m",   # 紫色
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = "{}{}{}".format(color, record.levelname, self.RESET)
        return super().format(record)


# ============================================================
# 日志管理器
# ============================================================

class LogManager:
    """
    统一日志管理器
    管理所有模块的日志配置
    """

    _instance = None
    _loggers = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._setup_root_logger()
        self._setup_audit_logger()

    def _setup_root_logger(self):
        """配置根日志记录器"""
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, settings.log.level.upper(), logging.INFO))

        # 清除已有处理器
        root_logger.handlers.clear()

        # 根据配置选择格式化器
        if LOG_FORMAT_JSON:
            console_fmt = JsonFormatter()
            file_fmt = JsonFormatter()
        else:
            console_fmt = ColorFormatter(SIMPLE_FORMAT, datefmt=DATE_FORMAT)
            file_fmt = logging.Formatter(STANDARD_FORMAT, datefmt=DATE_FORMAT)

        # 控制台处理器
        if settings.log.console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.DEBUG)
            console_handler.setFormatter(console_fmt)
            console_handler.addFilter(SensitiveDataFilter())
            root_logger.addHandler(console_handler)

        # 文件处理器
        if settings.log.file_output:
            log_file = Path(settings.log.file_path)
            log_file.parent.mkdir(parents=True, exist_ok=True)

            file_handler = RotatingFileHandler(
                filename=str(log_file),
                maxBytes=settings.log.max_file_size * 1024 * 1024,
                backupCount=settings.log.backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(file_fmt)
            file_handler.addFilter(SensitiveDataFilter())
            root_logger.addHandler(file_handler)

    def _setup_audit_logger(self):
        """配置安全审计日志记录器"""
        if not settings.log.security_audit:
            return

        audit_logger = logging.getLogger("gatekeeper.audit")
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False

        audit_file = Path(settings.log.security_log_path)
        audit_file.parent.mkdir(parents=True, exist_ok=True)

        # 按天轮转的审计日志
        audit_handler = TimedRotatingFileHandler(
            filename=str(audit_file),
            when="midnight",
            interval=1,
            backupCount=90,  # 保留90天
            encoding="utf-8",
        )
        audit_handler.setLevel(logging.INFO)
        audit_handler.setFormatter(logging.Formatter(AUDIT_FORMAT, datefmt=DATE_FORMAT))
        audit_handler.addFilter(SecurityAuditFilter())
        audit_logger.addHandler(audit_handler)

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        获取指定名称的日志记录器

        Args:
            name: 日志记录器名称，通常使用模块名

        Returns:
            配置好的Logger实例
        """
        if cls._instance is None:
            cls()
        logger = logging.getLogger("gatekeeper.{}".format(name))
        return logger


# ============================================================
# 便捷函数
# ============================================================

def get_logger(name: str) -> logging.Logger:
    """获取日志记录器的便捷函数"""
    return LogManager.get_logger(name)


def log_security_event(
    user: str,
    action: str,
    resource: str,
    result: str,
    message: str = "",
    level: str = "INFO"
):
    """
    记录安全审计事件

    Args:
        user: 操作用户
        action: 执行的操作（如 login, firewall_add, scan_start）
        resource: 操作的资源（如 IP地址, 规则ID）
        result: 操作结果（success, failure, denied）
        message: 附加消息
        level: 日志级别
    """
    audit_logger = logging.getLogger("gatekeeper.audit")
    log_level = getattr(logging, level.upper(), logging.INFO)

    audit_logger.log(
        log_level,
        message,
        extra={
            "user": user,
            "action": action,
            "resource": resource,
            "result": result,
        }
    )


# 初始化日志系统
log_manager = LogManager()
