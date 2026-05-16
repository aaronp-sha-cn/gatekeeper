"""
GateKeeper - 数据库配置
SQLAlchemy引擎与会话工厂配置
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import QueuePool, StaticPool

from config.settings import settings


# ============================================================
# 声明式基类
# ============================================================

Base = declarative_base()


# ============================================================
# 数据库引擎配置
# ============================================================

def get_engine():
    """
    创建并返回SQLAlchemy引擎
    根据配置自动选择SQLite或PostgreSQL
    """
    db_url = settings.database.url
    pool_size = settings.database.pool_size
    max_overflow = settings.database.max_overflow
    pool_timeout = settings.database.pool_timeout
    pool_recycle = settings.database.pool_recycle
    echo = settings.database.echo

    engine_kwargs = {
        "echo": echo,
        "pool_recycle": pool_recycle,
        "pool_pre_ping": True,  # 连接前检测是否有效
    }

    if settings.database.driver == "sqlite":
        # SQLite使用StaticPool以支持多线程
        engine_kwargs["poolclass"] = StaticPool
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        # PostgreSQL使用QueuePool
        engine_kwargs["poolclass"] = QueuePool
        engine_kwargs["pool_size"] = pool_size
        engine_kwargs["max_overflow"] = max_overflow
        engine_kwargs["pool_timeout"] = pool_timeout

    engine = create_engine(db_url, **engine_kwargs)
    return engine


# 创建全局引擎实例
engine = get_engine()


# ============================================================
# 会话工厂
# ============================================================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db():
    """
    获取数据库会话（依赖注入用）
    用法:
        db = get_db()
        try:
            # 数据库操作
            db.commit()
        finally:
            db.close()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# 上下文管理器用于get_db_session
from contextlib import contextmanager

@contextmanager
def get_db_session():
    """
    获取数据库会话（上下文管理器）
    用法:
        with get_db_session() as session:
            # 数据库操作
            session.commit()
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_scoped_session():
    """
    获取线程安全的scoped_session
    适用于多线程环境
    """
    session_factory = scoped_session(SessionLocal)
    return session_factory


# ============================================================
# 数据库初始化
# ============================================================

def _migrate_enum_values(bind_engine):
    """
    自动迁移：将旧的小写枚举值更新为大写（兼容历史数据）。
    例如：'super_admin' -> 'SUPER_ADMIN', 'admin' -> 'ADMIN'
    仅在检测到旧值存在时执行，避免不必要的写入。
    """
    try:
        import sqlalchemy as sa
        from sqlalchemy import text, inspect

        # 定义需要迁移的枚举值映射
        enum_mappings = {
            "users": {"role": {
                "super_admin": "SUPER_ADMIN",
                "admin": "ADMIN",
                "operator": "OPERATOR",
                "viewer": "VIEWER",
            }},
        }

        with bind_engine.connect() as conn:
            inspector = inspect(bind_engine)
            table_names = inspector.get_table_names()

            for table_name, column_mappings in enum_mappings.items():
                if table_name not in table_names:
                    continue

                columns = [col["name"] for col in inspector.get_columns(table_name)]

                for column_name, value_map in column_mappings.items():
                    if column_name not in columns:
                        continue

                    for old_value, new_value in value_map.items():
                        try:
                            # 检查旧值是否存在
                            if bind_engine.dialect.name == "sqlite":
                                check = conn.execute(
                                    text("SELECT COUNT(*) FROM {} WHERE {} = :val".format(
                                        table_name, column_name
                                    )),
                                    {"val": old_value}
                                ).scalar()
                            else:
                                check = conn.execute(
                                    text("SELECT COUNT(*) FROM {} WHERE {} = :val".format(
                                        table_name, column_name
                                    )),
                                    {"val": old_value}
                                ).scalar()

                            if check and check > 0:
                                conn.execute(
                                    text("UPDATE {} SET {} = :new WHERE {} = :old".format(
                                        table_name, column_name, column_name
                                    )),
                                    {"new": new_value, "old": old_value}
                                )
                                import logging
                                logging.getLogger("gatekeeper").info(
                                    "枚举迁移: {}.{} '{}' -> '{}' ({} 条记录)".format(
                                        table_name, column_name, old_value, new_value, check
                                    )
                                )
                        except Exception as e:
                            import logging
                            logging.getLogger("gatekeeper").warning(
                                "枚举迁移跳过 {}.{} '{}': {}".format(
                                    table_name, column_name, old_value, e
                                )
                            )

            conn.commit()

    except Exception as e:
        import logging
        logging.getLogger("gatekeeper").warning("枚举值迁移检查失败: {}".format(e))


def _migrate_missing_columns(bind_engine, base):
    """
    自动迁移：检查并添加 ORM 模型中定义但数据库表中缺失的列。
    仅支持 SQLite（通过 ALTER TABLE ADD COLUMN）。
    对于生产环境的 PostgreSQL 等数据库，建议使用 Alembic 迁移。
    """
    import logging
    _log = logging.getLogger("database.migration")

    if settings.database.driver != "sqlite":
        _log.debug("跳过自动列迁移（仅支持 SQLite，当前驱动: %s）", settings.database.driver)
        return

    from sqlalchemy import inspect, text

    db_inspector = inspect(bind_engine)
    existing_tables = db_inspector.get_table_names()

    for table_name, table_obj in base.metadata.tables.items():
        if table_name not in existing_tables:
            continue  # 表不存在，create_all 已处理

        # 获取数据库中该表已有的列名
        db_columns = {col["name"] for col in db_inspector.get_columns(table_name)}

        # 获取 ORM 模型中定义的列
        for column in table_obj.columns:
            col_name = column.name
            if col_name in db_columns:
                continue  # 列已存在，跳过

            # 构建列的 SQL 类型
            col_type = column.type.compile(dialect=bind_engine.dialect)

            # 构建 DEFAULT 值
            default_clause = ""
            if column.server_default is not None:
                sd = column.server_default
                if hasattr(sd, 'arg') and sd.arg is not None:
                    arg = sd.arg
                    if hasattr(arg, 'compile'):
                        compiled = arg.compile(dialect=bind_engine.dialect)
                        # 确保编译结果是纯字符串值，而非SQLAlchemy内部对象
                        compiled_str = str(compiled).strip("'\"")
                        # 检查是否包含SQLAlchemy内部类名
                        if 'ScalarElementColumnDefault' in compiled_str or 'ColumnDefault' in compiled_str:
                            # 提取实际值
                            actual_arg = getattr(arg, 'arg', arg) if hasattr(arg, 'arg') else arg
                            if isinstance(actual_arg, bool):
                                default_clause = " DEFAULT 1" if actual_arg else " DEFAULT 0"
                            elif isinstance(actual_arg, (int, float)):
                                default_clause = " DEFAULT {}".format(actual_arg)
                            elif isinstance(actual_arg, str):
                                default_clause = " DEFAULT '{}'".format(actual_arg)
                            else:
                                default_clause = ""
                        else:
                            default_clause = " DEFAULT {}".format(compiled_str)
                    elif isinstance(arg, bool):
                        default_clause = " DEFAULT 1" if arg else " DEFAULT 0"
                    elif isinstance(arg, str):
                        default_clause = " DEFAULT '{}'".format(arg)
                    elif isinstance(arg, (int, float)):
                        default_clause = " DEFAULT {}".format(arg)
                    else:
                        default_clause = " DEFAULT {}".format(arg)
            elif column.default is not None and not callable(column.default):
                if isinstance(column.default, bool):
                    default_clause = " DEFAULT 1" if column.default else " DEFAULT 0"
                elif isinstance(column.default, str):
                    default_clause = " DEFAULT '{}'".format(column.default)
                elif isinstance(column.default, (int, float)):
                    default_clause = " DEFAULT {}".format(column.default)
                else:
                    # 处理 SQLAlchemy ColumnDefault 对象，提取实际值
                    default_val = column.default.arg
                    if isinstance(default_val, bool):
                        default_clause = " DEFAULT 1" if default_val else " DEFAULT 0"
                    elif isinstance(default_val, str):
                        default_clause = " DEFAULT '{}'".format(default_val)
                    elif isinstance(default_val, (int, float)):
                        default_clause = " DEFAULT {}".format(default_val)
                    else:
                        default_clause = " DEFAULT '{}'".format(str(default_val))

            # SQLite ALTER TABLE ADD COLUMN 要求 NOT NULL 列必须有 DEFAULT 值
            nullable = "" if column.nullable else " NOT NULL"
            if column.nullable is False and not default_clause:
                # 根据列类型推断合理的默认值
                type_name = str(column.type).upper()
                if "BOOL" in type_name:
                    default_clause = " DEFAULT 0"
                elif "INT" in type_name:
                    default_clause = " DEFAULT 0"
                elif "FLOAT" in type_name or "NUMERIC" in type_name or "REAL" in type_name:
                    default_clause = " DEFAULT 0.0"
                elif "TEXT" in type_name or "VARCHAR" in type_name or "CHAR" in type_name:
                    default_clause = " DEFAULT ''"
                else:
                    default_clause = " DEFAULT ''"

            alter_sql = "ALTER TABLE {} ADD COLUMN {} {}{}{}".format(
                table_name, col_name, col_type, default_clause, nullable
            )

            try:
                with bind_engine.begin() as conn:
                    conn.execute(text(alter_sql))
                _log.info("自动迁移: 表 %s 添加列 %s (%s%s)", table_name, col_name, col_type, default_clause)
            except Exception as e:
                _log.warning("自动迁移失败: 表 %s 添加列 %s 失败: %s", table_name, col_name, e)


def init_db():
    """
    初始化数据库
    创建所有已注册的表，并自动迁移缺失的列
    """
    # 导入所有模型以确保它们被注册到Base.metadata
    from core.models import (
        User, NetworkInterface, FirewallRule, TrafficLog,
        Alert, Vulnerability, IDSRule, ScanResult,
        SystemConfig, ThreatIntel,
        DHCPSubnet, DHCPLease, AttackLog, AuditLog
    )
    from security.vpn_service import VPNConfig, VPNClient
    from security.dns_filter import DNSFilterRuleModel, DNSQueryLogModel
    from security.gateway_antivirus import GatewayVirusLog

    Base.metadata.create_all(bind=engine)

    # 自动迁移：为已有表添加缺失的列（SQLite 兼容）
    _migrate_missing_columns(engine, Base)

    # 自动迁移：将旧的小写枚举值更新为大写（兼容历史数据）
    _migrate_enum_values(engine)


def drop_db():
    """
    删除所有数据库表（危险操作，仅用于开发/测试）
    """
    Base.metadata.drop_all(bind=engine)


def check_connection():
    """
    检查数据库连接是否正常
    返回: (bool, str) - (是否成功, 消息)
    """
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            if settings.database.driver == "sqlite":
                result = conn.execute(text("SELECT 1"))
            else:
                result = conn.execute(text("SELECT version()"))
            row = result.fetchone()
            return True, "数据库连接正常: {}".format(row[0])
    except Exception as e:
        return False, "数据库连接失败: {}".format(str(e))
