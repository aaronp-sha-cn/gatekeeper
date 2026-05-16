"""
GateKeeper - 主配置文件
包含系统所有模块的配置参数，支持环境变量覆盖
"""

import os
import json
from pathlib import Path
from typing import Optional, List, Dict, Any


# ============================================================
# 基础路径配置
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
MODEL_DIR = BASE_DIR / "models"
UPLOAD_DIR = BASE_DIR / "uploads"
BACKUP_DIR = BASE_DIR / "backups"

# 确保必要目录存在
for _dir in [DATA_DIR, LOG_DIR, MODEL_DIR, UPLOAD_DIR, BACKUP_DIR]:
    _dir.mkdir(parents=True, exist_ok=True)


def _env(key, default="", cast=str):
    """从环境变量读取配置值，支持类型转换"""
    val = os.environ.get("GK_{}".format(key), default)
    if cast == bool:
        return val.lower() in ("true", "1", "yes", "on")
    if cast == int:
        return int(val) if val else default
    if cast == float:
        return float(val) if val else default
    if cast == list:
        return json.loads(val) if val else []
    return val


# ============================================================
# 数据库配置
# ============================================================

class DatabaseConfig(object):
    """数据库连接配置"""

    def __init__(self):
        # 数据库类型: sqlite / postgresql
        self.driver = _env("DB_DRIVER", "sqlite")

        # SQLite 配置
        self.sqlite_path = _env("DB_SQLITE_PATH", str(DATA_DIR / "gatekeeper.db"))

        # PostgreSQL 配置
        self.pg_host = _env("DB_PG_HOST", "localhost")
        self.pg_port = _env("DB_PG_PORT", 5432, int)
        self.pg_user = _env("DB_PG_USER", "gatekeeper")
        # 注意：生产环境必须通过环境变量设置强密码，默认空密码会阻止连接
        self.pg_password = _env("DB_PG_PASSWORD", "")
        self.pg_database = _env("DB_PG_DATABASE", "gatekeeper")

        # 连接池配置
        self.pool_size = _env("DB_POOL_SIZE", 10, int)
        self.max_overflow = _env("DB_MAX_OVERFLOW", 20, int)
        self.pool_timeout = _env("DB_POOL_TIMEOUT", 30, int)
        self.pool_recycle = _env("DB_POOL_RECYCLE", 3600, int)
        self.echo = _env("DB_ECHO", "false", bool)

    @property
    def url(self):
        """获取数据库连接URL"""
        if self.driver == "postgresql":
            return (
                "postgresql+psycopg2://{user}:{password}"
                "@{host}:{port}/{database}".format(
                    user=self.pg_user,
                    password=self.pg_password,
                    host=self.pg_host,
                    port=self.pg_port,
                    database=self.pg_database,
                )
            )
        return "sqlite:///{}".format(self.sqlite_path)

    def to_dict(self):
        """将配置导出为字典（敏感字段脱敏，用于API展示）"""
        return self._to_raw_dict(sanitize=True)

    def _to_raw_dict(self, sanitize=False):
        """将配置导出为字典，sanitize=True时脱敏敏感字段"""
        d = {
            "driver": self.driver,
            "sqlite_path": self.sqlite_path,
            "pg_host": self.pg_host,
            "pg_port": self.pg_port,
            "pg_user": self.pg_user,
            "pg_password": "***" if sanitize else self.pg_password,
            "pg_database": self.pg_database,
            "pool_size": self.pool_size,
            "max_overflow": self.max_overflow,
            "pool_timeout": self.pool_timeout,
            "pool_recycle": self.pool_recycle,
            "echo": self.echo,
        }
        return d


# ============================================================
# 网络配置
# ============================================================

class NetworkConfig(object):
    """网络监控配置"""

    def __init__(self):
        # 监听接口
        self.listen_interface = _env("NET_INTERFACE", "eth0")

        # 抓包模式: live / pcap_file
        self.capture_mode = _env("NET_CAPTURE_MODE", "live")

        # PCAP文件路径（离线分析模式）
        self.pcap_file = _env("NET_PCAP_FILE", "")

        # BPF过滤规则
        self.bpf_filter = _env("NET_BPF_FILTER", "")

        # 抓包缓冲区大小（MB）
        self.capture_buffer_size = _env("NET_BUFFER_SIZE", 256, int)

        # 最大包大小（字节）
        self.max_packet_size = _env("NET_MAX_PACKET_SIZE", 65535, int)

        # 是否启用混杂模式
        self.promiscuous = _env("NET_PROMISCUOUS", "true", bool)

        # 监控的端口列表
        self.monitored_ports = _env("NET_MONITORED_PORTS", "[]", list)

        # 排除的IP地址
        self.excluded_ips = _env("NET_EXCLUDED_IPS", "[]", list)

        # 流量采样率 (0.0 - 1.0)
        self.sampling_rate = _env("NET_SAMPLING_RATE", "1.0", float)

        # 超时设置（秒）
        self.capture_timeout = _env("NET_CAPTURE_TIMEOUT", 300, int)

        # IPv6 支持
        self.ipv6_enabled = _env("NET_IPV6_ENABLED", "false", bool)
        self.ipv6_listen_interface = _env("NET_IPV6_INTERFACE", "")

    def to_dict(self):
        """将配置导出为字典"""
        return {
            "listen_interface": self.listen_interface,
            "capture_mode": self.capture_mode,
            "pcap_file": self.pcap_file,
            "bpf_filter": self.bpf_filter,
            "capture_buffer_size": self.capture_buffer_size,
            "max_packet_size": self.max_packet_size,
            "promiscuous": self.promiscuous,
            "monitored_ports": self.monitored_ports,
            "excluded_ips": self.excluded_ips,
            "sampling_rate": self.sampling_rate,
            "capture_timeout": self.capture_timeout,
            "ipv6_enabled": self.ipv6_enabled,
            "ipv6_listen_interface": self.ipv6_listen_interface,
        }


# ============================================================
# AI模型配置
# ============================================================

class AIModelConfig(object):
    """AI模型相关配置"""

    def __init__(self):
        # 模型存储路径
        self.model_path = _env("AI_MODEL_PATH", str(MODEL_DIR))

        # 异常检测阈值
        self.anomaly_threshold = _env("AI_ANOMALY_THRESHOLD", "0.85", float)

        # 流量分析窗口大小（秒）
        self.analysis_window = _env("AI_ANALYSIS_WINDOW", 60, int)

        # 特征提取维度
        self.feature_dimensions = _env("AI_FEATURE_DIMENSIONS", 32, int)

        # 模型训练批量大小
        self.batch_size = _env("AI_BATCH_SIZE", 256, int)

        # 模型训练轮次
        self.training_epochs = _env("AI_TRAINING_EPOCHS", 100, int)

        # 学习率
        self.learning_rate = _env("AI_LEARNING_RATE", "0.001", float)

        # 是否启用在线学习
        self.online_learning = _env("AI_ONLINE_LEARNING", "true", bool)

        # 在线学习更新间隔（秒）
        self.online_update_interval = _env("AI_ONLINE_UPDATE_INTERVAL", 3600, int)

        # 威胁评分权重
        self.threat_score_weights = {
            "traffic_volume": 0.2,
            "protocol_anomaly": 0.25,
            "behavior_anomaly": 0.3,
            "threat_intel_match": 0.25,
        }

        # IDS规则置信度阈值
        self.ids_confidence_threshold = _env("AI_IDS_CONFIDENCE", "0.7", float)

        # 漏洞扫描并发数
        self.vuln_scan_concurrency = _env("AI_VULN_CONCURRENCY", 10, int)

    def to_dict(self):
        """将配置导出为字典"""
        return {
            "model_path": self.model_path,
            "anomaly_threshold": self.anomaly_threshold,
            "analysis_window": self.analysis_window,
            "feature_dimensions": self.feature_dimensions,
            "batch_size": self.batch_size,
            "training_epochs": self.training_epochs,
            "learning_rate": self.learning_rate,
            "online_learning": self.online_learning,
            "online_update_interval": self.online_update_interval,
            "threat_score_weights": self.threat_score_weights,
            "ids_confidence_threshold": self.ids_confidence_threshold,
            "vuln_scan_concurrency": self.vuln_scan_concurrency,
        }


# ============================================================
# 告警配置
# ============================================================

class AlertConfig(object):
    """告警系统配置"""

    def __init__(self):
        # 告警级别: low / medium / high / critical
        self.default_alert_level = _env("ALERT_DEFAULT_LEVEL", "medium")

        # 是否启用邮件告警
        self.email_enabled = _env("ALERT_EMAIL_ENABLED", "false", bool)

        # SMTP配置
        self.smtp_host = _env("ALERT_SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = _env("ALERT_SMTP_PORT", 587, int)
        self.smtp_user = _env("ALERT_SMTP_USER", "")
        self.smtp_password = _env("ALERT_SMTP_PASSWORD", "")
        self.smtp_use_tls = _env("ALERT_SMTP_TLS", "true", bool)

        # 邮件收件人列表
        self.email_recipients = _env("ALERT_EMAIL_RECIPIENTS", "[]", list)

        # 邮件发件人
        self.email_sender = _env("ALERT_EMAIL_SENDER", "gatekeeper@localhost")

        # 邮件主题前缀
        self.email_subject_prefix = _env("ALERT_EMAIL_PREFIX", "[GateKeeper]")

        # 是否启用Webhook告警
        self.webhook_enabled = _env("ALERT_WEBHOOK_ENABLED", "false", bool)

        # Webhook URL列表
        self.webhook_urls = _env("ALERT_WEBHOOK_URLS", "[]", list)

        # Webhook超时（秒）
        self.webhook_timeout = _env("ALERT_WEBHOOK_TIMEOUT", 10, int)

        # 告警冷却时间（秒），同一告警不重复发送
        self.alert_cooldown = _env("ALERT_COOLDOWN", 300, int)

        # 告警聚合窗口（秒）
        self.alert_aggregation_window = _env("ALERT_AGGREGATION", 60, int)

        # 最大告警频率（每分钟）
        self.max_alerts_per_minute = _env("ALERT_MAX_PER_MINUTE", 10, int)

    def to_dict(self):
        """将配置导出为字典（敏感字段脱敏）"""
        return self._to_raw_dict(sanitize=True)

    def _to_raw_dict(self, sanitize=False):
        """将配置导出为字典，sanitize=True时脱敏敏感字段"""
        return {
            "default_alert_level": self.default_alert_level,
            "email_enabled": self.email_enabled,
            "smtp_host": self.smtp_host,
            "smtp_port": self.smtp_port,
            "smtp_user": self.smtp_user,
            "smtp_password": "***" if sanitize else self.smtp_password,
            "smtp_use_tls": self.smtp_use_tls,
            "email_recipients": self.email_recipients,
            "email_sender": self.email_sender,
            "email_subject_prefix": self.email_subject_prefix,
            "webhook_enabled": self.webhook_enabled,
            "webhook_urls": self.webhook_urls,
            "webhook_timeout": self.webhook_timeout,
            "alert_cooldown": self.alert_cooldown,
            "alert_aggregation_window": self.alert_aggregation_window,
            "max_alerts_per_minute": self.max_alerts_per_minute,
        }


# ============================================================
# Web配置
# ============================================================

class WebConfig(object):
    """Web管理面板配置"""

    def __init__(self):
        # 监听地址
        self.host = _env("WEB_HOST", "0.0.0.0")

        # 监听端口
        self.port = _env("WEB_PORT", 8443, int)

        # 调试模式
        self.debug = _env("WEB_DEBUG", "false", bool)

        # 密钥（用于会话加密）
        # 安全修复：默认值为空字符串，生产环境必须通过 GK_WEB_SECRET_KEY 环境变量设置
        self.secret_key = _env("WEB_SECRET_KEY", "")

        # 验证 SECRET_KEY 是否已配置
        if not self.secret_key:
            import warnings
            warnings.warn(
                "SECRET_KEY 未设置！请通过环境变量 GK_WEB_SECRET_KEY 配置一个安全的密钥。"
                "未设置 SECRET_KEY 会导致每次重启后所有会话失效。",
                stacklevel=2,
            )

        # 是否启用HTTPS
        self.ssl_enabled = _env("WEB_SSL_ENABLED", "true", bool)

        # SSL证书路径
        self.ssl_cert = _env("WEB_SSL_CERT", str(DATA_DIR / "certs" / "server.crt"))

        # SSL密钥路径
        self.ssl_key = _env("WEB_SSL_KEY", str(DATA_DIR / "certs" / "server.key"))

        # 会话超时（分钟）
        self.session_timeout = _env("WEB_SESSION_TIMEOUT", 60, int)

        # 最大登录尝试次数
        self.max_login_attempts = _env("WEB_MAX_LOGIN_ATTEMPTS", 5, int)

        # 登录锁定时间（分钟）
        self.login_lockout_time = _env("WEB_LOGIN_LOCKOUT", 30, int)

        # API速率限制（每分钟请求数）
        self.rate_limit = _env("WEB_RATE_LIMIT", 100, int)

    def to_dict(self):
        """将配置导出为字典（敏感字段脱敏）"""
        return self._to_raw_dict(sanitize=True)

    def _to_raw_dict(self, sanitize=False):
        """将配置导出为字典，sanitize=True时脱敏敏感字段"""
        return {
            "host": self.host,
            "port": self.port,
            "debug": self.debug,
            "secret_key": "***" if sanitize else self.secret_key,
            "ssl_enabled": self.ssl_enabled,
            "ssl_cert": self.ssl_cert,
            "ssl_key": "***" if sanitize else self.ssl_key,
            "session_timeout": self.session_timeout,
            "max_login_attempts": self.max_login_attempts,
            "login_lockout_time": self.login_lockout_time,
            "rate_limit": self.rate_limit,
        }


# ============================================================
# 日志配置
# ============================================================

class LogConfig(object):
    """日志系统配置"""

    def __init__(self):
        # 日志级别: DEBUG / INFO / WARNING / ERROR / CRITICAL
        self.level = _env("LOG_LEVEL", "INFO")

        # 日志文件路径
        self.file_path = _env("LOG_FILE", str(LOG_DIR / "gatekeeper.log"))

        # 最大日志文件大小（MB）
        self.max_file_size = _env("LOG_MAX_SIZE", 100, int)

        # 保留的日志文件数量
        self.backup_count = _env("LOG_BACKUP_COUNT", 10, int)

        # 日志格式
        self.format_string = (
            "%(asctime)s | %(levelname)-8s | %(name)-20s | "
            "%(funcName)-15s | %(lineno)-4d | %(message)s"
        )

        # 日期格式
        self.date_format = "%Y-%m-%d %H:%M:%S"

        # 是否输出到控制台
        self.console_output = _env("LOG_CONSOLE", "true", bool)

        # 是否输出到文件
        self.file_output = _env("LOG_FILE_OUTPUT", "true", bool)

        # 是否启用安全审计日志
        self.security_audit = _env("LOG_SECURITY_AUDIT", "true", bool)

        # 安全审计日志路径
        self.security_log_path = _env(
            "LOG_SECURITY_PATH",
            str(LOG_DIR / "security_audit.log")
        )

    def to_dict(self):
        """将配置导出为字典"""
        return {
            "level": self.level,
            "file_path": self.file_path,
            "max_file_size": self.max_file_size,
            "backup_count": self.backup_count,
            "format_string": self.format_string,
            "date_format": self.date_format,
            "console_output": self.console_output,
            "file_output": self.file_output,
            "security_audit": self.security_audit,
            "security_log_path": self.security_log_path,
        }


# ============================================================
# 调度器配置
# ============================================================

class SchedulerConfig(object):
    """任务调度器配置"""

    def __init__(self):
        # 调度器类型: background / gevent
        self.executor = _env("SCHED_EXECUTOR", "background")

        # 最大工作线程数
        self.max_workers = _env("SCHED_MAX_WORKERS", 10, int)

        # 流量分析任务间隔（秒）
        self.traffic_analysis_interval = _env("SCHED_TRAFFIC_INTERVAL", 30, int)

        # 异常检测任务间隔（秒）
        self.anomaly_detection_interval = _env("SCHED_ANOMALY_INTERVAL", 60, int)

        # 漏洞扫描任务间隔（秒）
        self.vuln_scan_interval = _env("SCHED_VULN_INTERVAL", 3600, int)

        # 威胁情报更新间隔（秒）
        self.threat_intel_interval = _env("SCHED_THREAT_INTERVAL", 1800, int)

        # 模型在线学习间隔（秒）
        self.model_update_interval = _env("SCHED_MODEL_INTERVAL", 3600, int)

        # 报表生成间隔（秒）
        self.report_interval = _env("SCHED_REPORT_INTERVAL", 86400, int)

        # 数据清理间隔（秒）
        self.cleanup_interval = _env("SCHED_CLEANUP_INTERVAL", 86400, int)

        # 数据保留天数
        self.data_retention_days = _env("SCHED_DATA_RETENTION", 30, int)

    def to_dict(self):
        """将配置导出为字典"""
        return {
            "executor": self.executor,
            "max_workers": self.max_workers,
            "traffic_analysis_interval": self.traffic_analysis_interval,
            "anomaly_detection_interval": self.anomaly_detection_interval,
            "vuln_scan_interval": self.vuln_scan_interval,
            "threat_intel_interval": self.threat_intel_interval,
            "model_update_interval": self.model_update_interval,
            "report_interval": self.report_interval,
            "cleanup_interval": self.cleanup_interval,
            "data_retention_days": self.data_retention_days,
        }


# ============================================================
# 主配置类
# ============================================================

class Settings(object):
    """
    GateKeeper 全局配置管理类
    整合所有子模块配置，提供统一访问接口
    """

    def __init__(self):
        self.database = DatabaseConfig()
        self.network = NetworkConfig()
        self.ai_model = AIModelConfig()
        self.alert = AlertConfig()
        self.web = WebConfig()
        self.log = LogConfig()
        self.scheduler = SchedulerConfig()

        # 系统信息
        self.version = "1.1.0"
        self.app_name = "GateKeeper"
        self.instance_name = _env("INSTANCE_NAME", "default")

    def to_dict(self):
        """将所有配置导出为字典"""
        result = {
            "version": self.version,
            "app_name": self.app_name,
            "instance_name": self.instance_name,
        }
        for attr_name in ["database", "network", "ai_model", "alert", "web", "log", "scheduler"]:
            obj = getattr(self, attr_name)
            if hasattr(obj, "to_dict"):
                result[attr_name] = obj.to_dict()
            else:
                result[attr_name] = vars(obj)
        return result

    def update_from_dict(self, config_dict):
        """从字典更新配置"""
        for section_name, section_data in config_dict.items():
            if hasattr(self, section_name):
                section = getattr(self, section_name)
                if isinstance(section_data, dict):
                    for key, value in section_data.items():
                        if hasattr(section, key):
                            setattr(section, key, value)

    def save_to_file(self, filepath):
        """将当前配置保存到JSON文件（保留真实密码值）"""
        raw = {}
        for section_name in ["database", "network", "ai_model", "alert", "web", "log", "scheduler"]:
            section = getattr(self, section_name, None)
            if section and hasattr(section, "_to_raw_dict"):
                raw[section_name] = section._to_raw_dict(sanitize=False)
            elif section and hasattr(section, "to_dict"):
                raw[section_name] = section.to_dict()
        raw["version"] = self.version
        raw["app_name"] = self.app_name
        raw["instance_name"] = self.instance_name
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2, ensure_ascii=False)

    @classmethod
    def load_from_file(cls, filepath):
        """从JSON文件加载配置"""
        settings = cls()
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                config_dict = json.load(f)
            settings.update_from_dict(config_dict)
        return settings


# 全局配置单例
settings = Settings()
