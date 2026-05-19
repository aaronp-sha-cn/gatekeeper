# -*- coding: utf-8 -*-
"""
GateKeeper - Web 路由测试
测试健康检查、认证、仪表盘、IDS、设置等关键 Web 路由
"""

import pytest
from unittest.mock import patch, MagicMock


# ============================================================
# 健康检查端点测试
# ============================================================

class TestHealthEndpoints:
    """健康检查相关端点测试"""

    def test_health_returns_200_with_status_ok(self, client):
        """GET /health 返回 200，状态为 ok"""
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "timestamp" in data

    def test_ready_returns_200_with_checks(self, client):
        """GET /ready 返回 200，包含 checks 信息"""
        resp = client.get("/ready")
        # 可能返回 200 或 503（取决于数据库连接状态），但应包含 checks
        data = resp.get_json()
        assert "checks" in data
        assert "status" in data
        assert "timestamp" in data
        # checks 中应包含 database、memory、disk 等检查项
        assert "database" in data["checks"]
        assert "memory" in data["checks"]
        assert "disk" in data["checks"]

    def test_metrics_returns_text_plain(self, client):
        """GET /metrics 返回 text/plain 内容类型"""
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert resp.content_type == "text/plain"
        # 内容应包含 Prometheus 格式的指标
        body = resp.data.decode("utf-8")
        assert "gatekeeper_up" in body
        assert "gatekeeper_uptime_seconds" in body
        assert "process_memory_bytes" in body


# ============================================================
# 认证路由测试
# ============================================================

class TestAuthRoutes:
    """认证相关路由测试"""

    def test_login_page_returns_200(self, client):
        """GET /auth/login 返回 200（渲染登录页面）"""
        resp = client.get("/auth/login")
        assert resp.status_code == 200

    def test_login_invalid_credentials_returns_401(self, client, test_users):
        """POST /auth/login 使用无效凭据返回 401"""
        resp = client.post(
            "/auth/login",
            json={"username": "nonexistent_user", "password": "wrong_password"},
            content_type="application/json",
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["status"] == "error"

    def test_login_valid_credentials_returns_success(self, client, test_users):
        """POST /auth/login 使用有效凭据返回成功"""
        admin = test_users["admin"]
        resp = client.post(
            "/auth/login",
            json={"username": admin.username, "password": "Ad@Test2026!"},
            content_type="application/json",
        )
        # 可能返回 200 (ok) 或 2fa_required，但不应返回错误
        assert resp.status_code in (200, 201)
        data = resp.get_json()
        assert data["status"] in ("ok", "2fa_required")

    def test_login_empty_fields_returns_400(self, client):
        """POST /auth/login 空用户名密码返回 400"""
        resp = client.post(
            "/auth/login",
            json={"username": "", "password": ""},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_logout_authenticated_returns_ok(self, authenticated_client):
        """POST /auth/logout 已认证用户返回 ok"""
        resp = authenticated_client.post("/auth/logout")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_logout_unauthenticated_returns_401(self, client):
        """POST /auth/logout 未认证用户返回 302 或 401"""
        resp = client.post("/auth/logout")
        # Flask-Login 对未认证的 @login_required 返回 302 重定向
        assert resp.status_code in (302, 401)

    def test_api_me_not_authenticated_returns_redirect(self, client):
        """GET /auth/api/me 未认证时返回重定向"""
        resp = client.get("/auth/api/me")
        # Flask-Login 默认重定向到登录页
        assert resp.status_code in (302, 401)

    def test_api_me_authenticated_returns_user_info(self, authenticated_client, test_users):
        """GET /auth/api/me 已认证时返回用户信息"""
        resp = authenticated_client.get("/auth/api/me")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "data" in data
        assert "username" in data["data"]
        assert "role" in data["data"]


# ============================================================
# 仪表盘路由测试
# ============================================================

class TestDashboardRoutes:
    """仪表盘相关路由测试"""

    def test_index_not_authenticated_redirects(self, client):
        """GET / 未认证时重定向到登录页"""
        resp = client.get("/")
        # Flask-Login 重定向到登录页
        assert resp.status_code in (302, 401)
        if resp.status_code == 302:
            assert "/login" in resp.headers.get("Location", "")

    def test_index_authenticated_returns_200(self, authenticated_client):
        """GET / 已认证时返回 200"""
        resp = authenticated_client.get("/")
        assert resp.status_code == 200

    def test_api_system_monitor_authenticated(self, authenticated_client):
        """GET /api/system-monitor 已认证时返回系统监控数据"""
        resp = authenticated_client.get("/api/system-monitor")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "data" in data
        assert "cpu" in data["data"]
        assert "memory" in data["data"]
        assert "disk" in data["data"]

    def test_api_stats_authenticated(self, authenticated_client):
        """GET /api/stats 已认证时返回统计数据"""
        resp = authenticated_client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "data" in data


# ============================================================
# IDS 路由测试
# ============================================================

class TestIDSRoutes:
    """IDS 管理路由测试"""

    def test_ids_index_authenticated_returns_200(self, authenticated_client):
        """GET /ids/ 已认证时返回 200"""
        resp = authenticated_client.get("/ids/")
        assert resp.status_code == 200

    def test_ids_index_not_authenticated_redirects(self, client):
        """GET /ids/ 未认证时重定向"""
        resp = client.get("/ids/")
        assert resp.status_code in (302, 401)

    def test_ids_api_stats_authenticated(self, authenticated_client):
        """GET /ids/api/stats 已认证时返回统计信息"""
        resp = authenticated_client.get("/ids/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "data" in data

    def test_ids_api_attacks_authenticated(self, authenticated_client):
        """GET /ids/api/attacks 已认证时返回攻击日志"""
        resp = authenticated_client.get("/ids/api/attacks")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "data" in data
        assert "logs" in data["data"]
        assert "total" in data["data"]

    def test_ids_api_blocked_ips_authenticated(self, authenticated_client):
        """GET /ids/api/blocked-ips 已认证时返回阻断 IP 列表"""
        resp = authenticated_client.get("/ids/api/blocked-ips")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "data" in data


# ============================================================
# 设置路由测试
# ============================================================

class TestSettingsRoutes:
    """设置相关路由测试"""

    def test_settings_index_authenticated_returns_200(self, authenticated_client):
        """GET /settings/ 已认证时返回 200"""
        resp = authenticated_client.get("/settings/")
        assert resp.status_code == 200

    def test_settings_index_not_authenticated_redirects(self, client):
        """GET /settings/ 未认证时重定向"""
        resp = client.get("/settings/")
        assert resp.status_code in (302, 401)

    def test_settings_api_config_authenticated(self, authenticated_client):
        """GET /settings/api/config 已认证时返回配置"""
        resp = authenticated_client.get("/settings/api/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_settings_api_system_info_authenticated(self, authenticated_client):
        """GET /settings/api/system/info 已认证时返回系统信息"""
        resp = authenticated_client.get("/settings/api/system/info")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "data" in data

    def test_settings_api_modules_authenticated(self, authenticated_client):
        """GET /settings/api/modules 已认证时返回模块列表"""
        resp = authenticated_client.get("/settings/api/modules")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "data" in data
        assert isinstance(data["data"], list)
