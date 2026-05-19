"""
GateKeeper - Alembic 环境配置
数据库迁移运行时环境，自动导入所有模型元数据
"""

import sys
import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# 将项目根目录加入 sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 导入 Base 和所有模型，确保 metadata 包含所有表定义
from config.database import Base
import config.database  # noqa: F401 - 触发 init_db 中的模型导入

# 导入所有模型模块，确保所有 ORM 模型注册到 Base.metadata
from core.models import (  # noqa: F401
    User, NetworkInterface, FirewallRule, TrafficLog,
    Alert, Vulnerability, IDSRule, ScanResult,
    SystemConfig, ThreatIntel,
    DHCPSubnet, DHCPLease, AttackLog, AuditLog,
)
from security.vpn_service import VPNConfig, VPNClient  # noqa: F401
from security.dns_filter import DNSFilterRuleModel, DNSQueryLogModel  # noqa: F401
from security.gateway_antivirus import GatewayVirusLog  # noqa: F401

# Alembic Config 对象
config = context.config

# 设置日志
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# 元数据目标，用于 'autogenerate' 支持
target_metadata = Base.metadata

# 从环境变量覆盖 sqlalchemy.url（可选）
db_url = os.environ.get("GK_DB_ALEMBIC_URL")
if db_url:
    config.set_main_option("sqlalchemy.url", db_url)


def run_migrations_offline() -> None:
    """以 'offline' 模式运行迁移。

    仅需要 URL，不需要 Engine。调用 context.execute() 将给定的
    DDL 脚本输出到脚本。
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """以 'online' 模式运行迁移。

    创建 Engine 并关联 connection 到 context。
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
