# -*- coding: utf-8 -*-
"""
GateKeeper - 测试配置和公共 fixtures
提供 Flask 测试应用、内存数据库、测试用户等公共测试组件
"""

import os
import sys
import tempfile
import pytest
from unittest.mock import MagicMock, patch

# 确保项目根目录在 sys.path 中
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ============================================================
# 测试环境变量 — 必须在导入项目模块之前设置
# ============================================================
os.environ.setdefault("GK_DB_DRIVER", "sqlite")
os.environ.setdefault("GK_WEB_SSL_ENABLED", "false")
os.environ.setdefault("GK_WEB_SECRET_KEY", "test-secret-key-for-pytest")
os.environ.setdefault("GK_WEB_DEBUG", "false")
os.environ.setdefault("GK_LOG_LEVEL", "WARNING")
os.environ.setdefault("GK_LOG_CONSOLE", "false")
os.environ.setdefault("GK_LOG_FILE_OUTPUT", "false")
os.environ.setdefault("GK_WEB_HOST", "127.0.0.1")
os.environ.setdefault("GK_WEB_PORT", "0")
os.environ.setdefault("GK_NET_INTERFACE", "lo")


# ============================================================
# 数据库 fixtures
# ============================================================

@pytest.fixture(scope="session")
def db_engine():
    """
    创建测试用内存 SQLite 引擎（session 级别，所有测试共享）
    使用内存数据库避免污染开发/生产数据库
    """
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    return engine


@pytest.fixture(scope="session")
def db_tables(db_engine):
    """
    创建所有数据库表（session 级别）
    导入所有模型以确保它们注册到 Base.metadata
    """
    from config.database import Base

    # 导入所有模型以确保表被创建
    from core.models import (
        User, NetworkInterface, FirewallRule, TrafficLog,
        Alert, Vulnerability, IDSRule, ScanResult,
        SystemConfig, ThreatIntel, DHCPSubnet, DHCPLease,
        AttackLog, AuditLog,
    )
    from security.dns_filter import DNSFilterRuleModel, DNSQueryLogModel
    from security.gateway_antivirus import GatewayVirusLog

    Base.metadata.create_all(bind=db_engine)
    yield db_engine
    # 清理：关闭引擎
    db_engine.dispose()


@pytest.fixture(scope="function")
def db_session(db_tables):
    """
    创建函数级别的数据库会话
    每个测试函数结束后清理所有表数据，确保测试之间数据完全隔离
    """
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import text

    Session = sessionmaker(bind=db_tables)
    session = Session()

    yield session

    # 清理所有表数据（按外键依赖顺序）
    try:
        session.execute(text("DELETE FROM audit_logs"))
        session.execute(text("DELETE FROM attack_logs"))
        session.execute(text("DELETE FROM dns_query_logs"))
        session.execute(text("DELETE FROM gateway_virus_logs"))
        session.execute(text("DELETE FROM dhcp_leases"))
        session.execute(text("DELETE FROM dhcp_subnets"))
        session.execute(text("DELETE FROM vulnerabilities"))
        session.execute(text("DELETE FROM scan_results"))
        session.execute(text("DELETE FROM ids_rules"))
        session.execute(text("DELETE FROM traffic_logs"))
        session.execute(text("DELETE FROM alerts"))
        session.execute(text("DELETE FROM firewall_rules"))
        session.execute(text("DELETE FROM network_interfaces"))
        session.execute(text("DELETE FROM threat_intel"))
        session.execute(text("DELETE FROM system_configs"))
        session.execute(text("DELETE FROM dns_filter_rules"))
        session.execute(text("DELETE FROM users"))
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


@pytest.fixture(scope="function")
def db_manager_mock(db_session):
    """
    创建 mock 的 DatabaseManager，使用测试数据库会话
    替换全局 db_manager 以便项目代码使用测试数据库
    """
    from contextlib import contextmanager
    from unittest.mock import MagicMock

    mock_manager = MagicMock()

    @contextmanager
    def mock_get_session():
        yield db_session
        db_session.commit()

    mock_manager.get_session = mock_get_session
    mock_manager._engine = db_session.get_bind()

    return mock_manager


# ============================================================
# Flask 测试应用 fixtures
# ============================================================

@pytest.fixture(scope="function")
def app(db_manager_mock):
    """
    创建 Flask 测试应用
    使用内存数据库，不启动实际服务器
    """
    from flask import Flask
    from flask_login import LoginManager

    # 在导入 web.app 之前，先 patch db_manager
    with patch("core.database.db_manager", db_manager_mock), \
         patch("web.app.db_manager", db_manager_mock), \
         patch("core.app.db_manager", db_manager_mock):

        from web.app import create_web_app

        application = create_web_app()
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        application.config["SECRET_KEY"] = "test-secret-key"
        application.config["LOGIN_DISABLED"] = False

        yield application


@pytest.fixture(scope="function")
def client(app):
    """
    创建 Flask 测试客户端
    用于模拟 HTTP 请求
    """
    return app.test_client()


@pytest.fixture(scope="function")
def runner(app):
    """
    创建 Flask CLI 测试运行器
    """
    return app.test_cli_runner()


# ============================================================
# 测试用户 fixtures
# ============================================================

@pytest.fixture(scope="function")
def test_users(db_session):
    """
    创建测试用户：super_admin, admin, operator, viewer
    返回包含所有测试用户的字典
    """
    from core.models import User, UserRole
    from utils.crypto import hash_password

    users = {}

    # 超级管理员
    sp_admin = User(
        username="test_super_admin",
        email="sp_admin@test.local",
        password_hash=hash_password("Sp@Test2026!"),
        role=UserRole.SUPER_ADMIN,
        is_active=True,
    )
    db_session.add(sp_admin)
    users["super_admin"] = sp_admin

    # 管理员
    admin = User(
        username="test_admin",
        email="admin@test.local",
        password_hash=hash_password("Ad@Test2026!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add(admin)
    users["admin"] = admin

    # 操作员
    operator = User(
        username="test_operator",
        email="operator@test.local",
        password_hash=hash_password("Op@Test2026!"),
        role=UserRole.OPERATOR,
        is_active=True,
    )
    db_session.add(operator)
    users["operator"] = operator

    # 查看者
    viewer = User(
        username="test_viewer",
        email="viewer@test.local",
        password_hash=hash_password("Vi@Test2026!"),
        role=UserRole.VIEWER,
        is_active=True,
    )
    db_session.add(viewer)
    users["viewer"] = viewer

    db_session.flush()

    return users


@pytest.fixture(scope="function")
def super_admin_user(test_users):
    """返回超级管理员用户"""
    return test_users["super_admin"]


@pytest.fixture(scope="function")
def admin_user(test_users):
    """返回管理员用户"""
    return test_users["admin"]


@pytest.fixture(scope="function")
def operator_user(test_users):
    """返回操作员用户"""
    return test_users["operator"]


@pytest.fixture(scope="function")
def viewer_user(test_users):
    """返回查看者用户"""
    return test_users["viewer"]


# ============================================================
# 认证辅助 fixtures
# ============================================================

@pytest.fixture(scope="function")
def authenticated_client(client, test_users):
    """
    创建已认证的测试客户端（以管理员身份登录）
    """
    from flask_login import login_user

    # 使用 admin 用户登录
    admin = test_users["admin"]

    with client.application.test_request_context():
        from flask import session as flask_session
        login_user(admin)

    return client


# ============================================================
# 临时文件 fixtures
# ============================================================

@pytest.fixture(scope="function")
def tmp_file():
    """
    创建临时文件，测试结束后自动清理
    返回 (file_path, file_obj) 元组
    """
    fd, path = tempfile.mkstemp(prefix="gatekeeper_test_", suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        f.write("test content for GateKeeper\n")
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture(scope="function")
def tmp_dir():
    """
    创建临时目录，测试结束后自动清理
    """
    dirpath = tempfile.mkdtemp(prefix="gatekeeper_test_dir_")
    yield dirpath
    import shutil
    if os.path.exists(dirpath):
        shutil.rmtree(dirpath)


# ============================================================
# 安全引擎 fixtures
# ============================================================

@pytest.fixture(scope="function")
def ids_engine(db_manager_mock):
    """
    创建 IDS 引擎实例（mock 数据库依赖）
    """
    with patch("security.ids_engine.db_manager", db_manager_mock):
        from security.ids_engine import IDSEngine
        engine = IDSEngine(auto_block=False)
        return engine


@pytest.fixture(scope="function")
def waf_engine():
    """
    创建 WAF 引擎实例（纯内存，无需数据库）
    """
    from security.waf_engine import WAFEngine
    engine = WAFEngine()
    return engine


@pytest.fixture(scope="function")
def dns_filter_engine(db_manager_mock, db_session):
    """
    创建 DNS 过滤引擎实例（mock 数据库依赖）
    预加载内置规则到测试数据库，并跳过引擎内部的重复加载
    使用 patcher 确保在整个测试期间 mock 生效
    """
    from security.dns_filter import (
        DNSFilterEngine, DNSFilterRuleModel,
        BUILTIN_MALWARE_DOMAINS, BUILTIN_PHISHING_DOMAINS,
        BUILTIN_MINING_DOMAINS, BUILTIN_C2_DOMAINS,
    )

    # 预加载内置规则到测试数据库
    builtin_rules = []
    for domain in BUILTIN_MALWARE_DOMAINS:
        builtin_rules.append(DNSFilterRuleModel(
            name="内置恶意软件域名 - {}".format(domain),
            domain=domain, rule_type="category", category="malware",
            action="block", enabled=True,
        ))
    for domain in BUILTIN_PHISHING_DOMAINS:
        builtin_rules.append(DNSFilterRuleModel(
            name="内置钓鱼域名 - {}".format(domain),
            domain=domain, rule_type="category", category="phishing",
            action="block", enabled=True,
        ))
    for domain in BUILTIN_MINING_DOMAINS:
        builtin_rules.append(DNSFilterRuleModel(
            name="内置挖矿域名 - {}".format(domain),
            domain=domain, rule_type="category", category="mining",
            action="block", enabled=True,
        ))
    for domain in BUILTIN_C2_DOMAINS:
        builtin_rules.append(DNSFilterRuleModel(
            name="内置C2通信域名 - {}".format(domain),
            domain=domain, rule_type="category", category="c2",
            action="block", enabled=True,
        ))
    db_session.add_all(builtin_rules)
    db_session.flush()

    # 使用 start/stop 方式确保 patch 在整个测试期间有效
    patcher = patch("security.dns_filter.db_manager", db_manager_mock)
    patcher.start()
    engine = DNSFilterEngine()
    engine._initialized = True

    yield engine

    patcher.stop()


@pytest.fixture(scope="function")
def gateway_antivirus_engine(db_manager_mock):
    """
    创建网关防病毒引擎实例（mock 外部依赖）
    """
    with patch("security.gateway_antivirus.db_manager", db_manager_mock), \
         patch("security.gateway_antivirus.subprocess.run") as mock_run:
        # mock clamscan 不可用
        mock_run.return_value = MagicMock(returncode=1)
        from security.gateway_antivirus import GatewayAntivirusEngine
        engine = GatewayAntivirusEngine()
        return engine
