# -*- coding: utf-8 -*-
"""
GateKeeper - 告警系统测试
测试 AlertManager、EmailAlerter、WebhookAlerter 等告警组件
"""

import pytest
import time
import threading
from unittest.mock import patch, MagicMock, PropertyMock
from collections import deque


# ============================================================
# AlertManager 初始化测试
# ============================================================

class TestAlertManagerInit:
    """AlertManager 初始化测试"""

    @patch("alerting.alert_manager.settings")
    @patch("alerting.alert_manager.EmailAlerter")
    @patch("alerting.alert_manager.WebhookAlerter")
    def test_initialization(self, mock_webhook_cls, mock_email_cls, mock_settings):
        """测试 AlertManager 正确初始化"""
        mock_settings.alert.alert_cooldown = 300
        mock_settings.alert.alert_aggregation_window = 60
        mock_settings.alert.max_alerts_per_minute = 100
        mock_settings.alert.email_enabled = False
        mock_settings.alert.webhook_enabled = False

        from alerting.alert_manager import AlertManager
        manager = AlertManager()

        assert manager._cooldown_seconds == 300
        assert manager._aggregation_window == 60
        assert manager._max_per_minute == 100
        assert manager._stats["total_sent"] == 0
        assert manager._stats["suppressed"] == 0
        assert len(manager._callbacks) == 0
        assert not manager._aggregation_running

    @patch("alerting.alert_manager.settings")
    @patch("alerting.alert_manager.EmailAlerter")
    @patch("alerting.alert_manager.WebhookAlerter")
    def test_initialization_creates_alerter_instances(self, mock_webhook_cls, mock_email_cls, mock_settings):
        """测试初始化时创建邮件和 Webhook 告警器实例"""
        mock_settings.alert.alert_cooldown = 300
        mock_settings.alert.alert_aggregation_window = 60
        mock_settings.alert.max_alerts_per_minute = 100
        mock_settings.alert.email_enabled = True
        mock_settings.alert.webhook_enabled = True

        from alerting.alert_manager import AlertManager
        manager = AlertManager()

        mock_email_cls.assert_called_once()
        mock_webhook_cls.assert_called_once()


# ============================================================
# 告警创建测试（不同级别）
# ============================================================

class TestAlertCreation:
    """告警创建测试"""

    @pytest.fixture(autouse=True)
    def _setup_manager(self):
        """创建 mock 的 AlertManager"""
        with patch("alerting.alert_manager.settings") as mock_settings, \
             patch("alerting.alert_manager.EmailAlerter"), \
             patch("alerting.alert_manager.WebhookAlerter"), \
             patch("alerting.alert_manager.db_manager"):
            mock_settings.alert.alert_cooldown = 300
            mock_settings.alert.alert_aggregation_window = 60
            mock_settings.alert.max_alerts_per_minute = 100
            mock_settings.alert.email_enabled = False
            mock_settings.alert.webhook_enabled = False

            from alerting.alert_manager import AlertManager
            self.manager = AlertManager()

    @patch("alerting.alert_manager.db_manager")
    def test_create_low_level_alert(self, mock_db):
        """测试创建低级别告警"""
        mock_alert = MagicMock()
        mock_alert.id = 1
        mock_alert.title = "Test Low Alert"
        mock_alert.level = MagicMock()
        mock_alert.level.value = "low"
        mock_db.add.return_value = mock_alert

        with patch.object(self.manager, "_dispatch_alert"):
            result = self.manager.create_alert(
                title="Test Low Alert",
                level="low",
                source="test",
                description="Low level test alert",
            )
        assert result["status"] == "ok"
        assert result["alert_id"] == 1

    @patch("alerting.alert_manager.db_manager")
    def test_create_medium_level_alert(self, mock_db):
        """测试创建中级别告警"""
        mock_alert = MagicMock()
        mock_alert.id = 2
        mock_alert.title = "Test Medium Alert"
        mock_alert.level = MagicMock()
        mock_alert.level.value = "medium"
        mock_db.add.return_value = mock_alert

        with patch.object(self.manager, "_dispatch_alert"):
            result = self.manager.create_alert(
                title="Test Medium Alert",
                level="medium",
                source="test",
            )
        assert result["status"] == "ok"

    @patch("alerting.alert_manager.db_manager")
    def test_create_high_level_alert(self, mock_db):
        """测试创建高级别告警"""
        mock_alert = MagicMock()
        mock_alert.id = 3
        mock_alert.title = "Test High Alert"
        mock_alert.level = MagicMock()
        mock_alert.level.value = "high"
        mock_db.add.return_value = mock_alert

        with patch.object(self.manager, "_dispatch_alert"):
            result = self.manager.create_alert(
                title="Test High Alert",
                level="high",
                source="ids",
                source_ip="192.168.1.100",
            )
        assert result["status"] == "ok"

    @patch("alerting.alert_manager.db_manager")
    def test_create_critical_level_alert(self, mock_db):
        """测试创建严重级别告警"""
        mock_alert = MagicMock()
        mock_alert.id = 4
        mock_alert.title = "Test Critical Alert"
        mock_alert.level = MagicMock()
        mock_alert.level.value = "critical"
        mock_db.add.return_value = mock_alert

        with patch.object(self.manager, "_dispatch_alert"):
            result = self.manager.create_alert(
                title="Test Critical Alert",
                level="critical",
                source="firewall",
                source_ip="10.0.0.1",
                dest_ip="192.168.1.1",
                port=22,
                protocol="tcp",
            )
        assert result["status"] == "ok"

    @patch("alerting.alert_manager.db_manager")
    def test_create_alert_with_metadata(self, mock_db):
        """测试创建带元数据的告警"""
        mock_alert = MagicMock()
        mock_alert.id = 5
        mock_alert.title = "Alert with Metadata"
        mock_alert.level = MagicMock()
        mock_alert.level.value = "medium"
        mock_db.add.return_value = mock_alert

        with patch.object(self.manager, "_dispatch_alert"):
            result = self.manager.create_alert(
                title="Alert with Metadata",
                level="medium",
                source="waf",
                metadata={"rule_id": "waf-001", "payload": "SELECT * FROM users"},
            )
        assert result["status"] == "ok"


# ============================================================
# 告警冷却机制测试
# ============================================================

class TestAlertCooldown:
    """告警冷却机制测试"""

    @pytest.fixture(autouse=True)
    def _setup_manager(self):
        """创建冷却时间很短的 AlertManager"""
        with patch("alerting.alert_manager.settings") as mock_settings, \
             patch("alerting.alert_manager.EmailAlerter"), \
             patch("alerting.alert_manager.WebhookAlerter"), \
             patch("alerting.alert_manager.db_manager"):
            mock_settings.alert.alert_cooldown = 10  # 10秒冷却
            mock_settings.alert.alert_aggregation_window = 60
            mock_settings.alert.max_alerts_per_minute = 100
            mock_settings.alert.email_enabled = False
            mock_settings.alert.webhook_enabled = False

            from alerting.alert_manager import AlertManager
            self.manager = AlertManager()

    @patch("alerting.alert_manager.db_manager")
    def test_same_alert_suppressed_within_cooldown(self, mock_db):
        """相同告警在冷却期内被抑制"""
        mock_alert = MagicMock()
        mock_alert.id = 1
        mock_alert.level = MagicMock()
        mock_alert.level.value = "high"
        mock_db.add.return_value = mock_alert

        with patch.object(self.manager, "_dispatch_alert"):
            # 第一次告警应成功
            result1 = self.manager.create_alert(
                title="Port Scan Detected",
                level="high",
                source="ids",
                source_ip="10.0.0.1",
            )
            assert result1["status"] == "ok"

            # 相同告警在冷却期内应被抑制
            result2 = self.manager.create_alert(
                title="Port Scan Detected",
                level="high",
                source="ids",
                source_ip="10.0.0.1",
            )
            assert result2["status"] == "suppressed"
            assert result2["reason"] == "cooldown"

    @patch("alerting.alert_manager.db_manager")
    def test_different_alerts_not_suppressed(self, mock_db):
        """不同告警不受冷却影响"""
        mock_alert = MagicMock()
        mock_alert.id = 1
        mock_alert.level = MagicMock()
        mock_alert.level.value = "medium"
        mock_db.add.return_value = mock_alert

        with patch.object(self.manager, "_dispatch_alert"):
            result1 = self.manager.create_alert(
                title="Alert A",
                level="medium",
                source="ids",
                source_ip="10.0.0.1",
            )
            assert result1["status"] == "ok"

            # 不同标题的告警不应被抑制
            result2 = self.manager.create_alert(
                title="Alert B",
                level="medium",
                source="ids",
                source_ip="10.0.0.1",
            )
            assert result2["status"] == "ok"

    @patch("alerting.alert_manager.db_manager")
    def test_cooldown_stats_tracked(self, mock_db):
        """冷却抑制次数被正确统计"""
        mock_alert = MagicMock()
        mock_alert.id = 1
        mock_alert.level = MagicMock()
        mock_alert.level.value = "low"
        mock_db.add.return_value = mock_alert

        with patch.object(self.manager, "_dispatch_alert"):
            self.manager.create_alert(
                title="Repeated Alert",
                level="low",
                source="test",
            )
            # 触发 3 次冷却抑制
            self.manager.create_alert(
                title="Repeated Alert",
                level="low",
                source="test",
            )
            self.manager.create_alert(
                title="Repeated Alert",
                level="low",
                source="test",
            )
            self.manager.create_alert(
                title="Repeated Alert",
                level="low",
                source="test",
            )

        assert self.manager._stats["suppressed"] == 3


# ============================================================
# 告警频率限制测试
# ============================================================

class TestAlertRateLimiting:
    """告警频率限制测试"""

    @pytest.fixture(autouse=True)
    def _setup_manager(self):
        """创建频率限制很低的 AlertManager"""
        with patch("alerting.alert_manager.settings") as mock_settings, \
             patch("alerting.alert_manager.EmailAlerter"), \
             patch("alerting.alert_manager.WebhookAlerter"), \
             patch("alerting.alert_manager.db_manager"):
            mock_settings.alert.alert_cooldown = 0  # 关闭冷却
            mock_settings.alert.alert_aggregation_window = 60
            mock_settings.alert.max_alerts_per_minute = 3  # 每分钟最多3条
            mock_settings.alert.email_enabled = False
            mock_settings.alert.webhook_enabled = False

            from alerting.alert_manager import AlertManager
            self.manager = AlertManager()

    @patch("alerting.alert_manager.db_manager")
    def test_rate_limit_allows_within_limit(self, mock_db):
        """频率限制允许限制内的告警"""
        mock_alert = MagicMock()
        mock_alert.id = 1
        mock_alert.level = MagicMock()
        mock_alert.level.value = "low"
        mock_db.add.return_value = mock_alert

        with patch.object(self.manager, "_dispatch_alert"):
            # 3 条告警应全部通过
            for i in range(3):
                result = self.manager.create_alert(
                    title="Alert {}".format(i),
                    level="low",
                    source="test",
                )
                assert result["status"] == "ok"

    @patch("alerting.alert_manager.db_manager")
    def test_rate_limit_blocks_excess(self, mock_db):
        """频率限制阻止超出的告警"""
        mock_alert = MagicMock()
        mock_alert.id = 1
        mock_alert.level = MagicMock()
        mock_alert.level.value = "low"
        mock_db.add.return_value = mock_alert

        with patch.object(self.manager, "_dispatch_alert"):
            # 发送 5 条告警，最多 3 条通过
            results = []
            for i in range(5):
                result = self.manager.create_alert(
                    title="Rate Alert {}".format(i),
                    level="low",
                    source="test",
                )
                results.append(result)

            ok_count = sum(1 for r in results if r["status"] == "ok")
            suppressed_count = sum(1 for r in results if r["status"] == "suppressed" and r["reason"] == "rate_limit")

            assert ok_count == 3
            assert suppressed_count == 2


# ============================================================
# 邮件告警测试
# ============================================================

class TestEmailAlerter:
    """邮件告警器测试"""

    @patch("alerting.email_alert.settings")
    def test_email_alerter_configuration(self, mock_settings):
        """测试邮件告警器配置"""
        mock_settings.alert.email_enabled = True
        mock_settings.alert.smtp_host = "smtp.example.com"
        mock_settings.alert.smtp_port = 587
        mock_settings.alert.smtp_user = "alert@example.com"
        mock_settings.alert.smtp_password = "secret"
        mock_settings.alert.smtp_use_tls = True
        mock_settings.alert.email_sender = "gatekeeper@example.com"
        mock_settings.alert.email_recipients = ["admin@example.com"]
        mock_settings.alert.email_subject_prefix = "[GateKeeper]"

        from alerting.email_alert import EmailAlerter
        alerter = EmailAlerter()

        assert alerter._enabled is True
        assert alerter._smtp_host == "smtp.example.com"
        assert alerter._smtp_port == 587
        assert alerter._smtp_user == "alert@example.com"
        assert alerter._smtp_tls is True
        assert alerter._sender == "gatekeeper@example.com"
        assert len(alerter._recipients) == 1

    @patch("alerting.email_alert.settings")
    def test_email_alerter_disabled(self, mock_settings):
        """测试禁用状态的邮件告警器"""
        mock_settings.alert.email_enabled = False
        mock_settings.alert.smtp_host = "smtp.example.com"
        mock_settings.alert.smtp_port = 25
        mock_settings.alert.smtp_user = ""
        mock_settings.alert.smtp_password = ""
        mock_settings.alert.smtp_use_tls = False
        mock_settings.alert.email_sender = "gatekeeper@example.com"
        mock_settings.alert.email_recipients = []
        mock_settings.alert.email_subject_prefix = "[GateKeeper]"

        from alerting.email_alert import EmailAlerter
        alerter = EmailAlerter()

        assert alerter._enabled is False

    @patch("alerting.email_alert.settings")
    def test_send_alert_when_disabled(self, mock_settings):
        """测试禁用时发送告警返回 False"""
        mock_settings.alert.email_enabled = False
        mock_settings.alert.smtp_host = ""
        mock_settings.alert.smtp_port = 25
        mock_settings.alert.smtp_user = ""
        mock_settings.alert.smtp_password = ""
        mock_settings.alert.smtp_use_tls = False
        mock_settings.alert.email_sender = ""
        mock_settings.alert.email_recipients = []
        mock_settings.alert.email_subject_prefix = "[GK]"

        from alerting.email_alert import EmailAlerter
        alerter = EmailAlerter()

        result = alerter.send_alert(
            title="Test Alert",
            level="critical",
            source="test",
        )
        assert result is False

    @patch("alerting.email_alert.smtplib.SMTP")
    @patch("alerting.email_alert.settings")
    def test_send_alert_with_mock_smtp(self, mock_settings, mock_smtp_cls):
        """测试使用 mock SMTP 发送告警"""
        mock_settings.alert.email_enabled = True
        mock_settings.alert.smtp_host = "smtp.test.com"
        mock_settings.alert.smtp_port = 587
        mock_settings.alert.smtp_user = "user@test.com"
        mock_settings.alert.smtp_password = "pass"
        mock_settings.alert.smtp_use_tls = True
        mock_settings.alert.email_sender = "gk@test.com"
        mock_settings.alert.email_recipients = ["admin@test.com"]
        mock_settings.alert.email_subject_prefix = "[GK]"

        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        from alerting.email_alert import EmailAlerter
        alerter = EmailAlerter()

        # send_alert 在后台线程中发送，直接调用 _send_email
        alerter._send_email(
            subject="[GK] [CRITICAL] Test Alert",
            content="<h1>Test</h1>",
            is_html=True,
        )

        mock_smtp_cls.assert_called_once_with("smtp.test.com", 587, timeout=30)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user@test.com", "pass")
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch("alerting.email_alert.settings")
    def test_test_connection_success(self, mock_settings):
        """测试 SMTP 连接测试成功"""
        mock_settings.alert.email_enabled = True
        mock_settings.alert.smtp_host = "smtp.test.com"
        mock_settings.alert.smtp_port = 25
        mock_settings.alert.smtp_user = ""
        mock_settings.alert.smtp_password = ""
        mock_settings.alert.smtp_use_tls = False
        mock_settings.alert.email_sender = "gk@test.com"
        mock_settings.alert.email_recipients = ["admin@test.com"]
        mock_settings.alert.email_subject_prefix = "[GK]"

        with patch("alerting.email_alert.smtplib.SMTP") as mock_smtp_cls:
            mock_server = MagicMock()
            mock_smtp_cls.return_value = mock_server

            from alerting.email_alert import EmailAlerter
            alerter = EmailAlerter()
            result = alerter.test_connection()

            assert result["status"] == "ok"


# ============================================================
# Webhook 告警测试
# ============================================================

class TestWebhookAlerter:
    """Webhook 告警器测试"""

    @patch("alerting.webhook_alert.settings")
    def test_webhook_alerter_configuration(self, mock_settings):
        """测试 Webhook 告警器配置"""
        mock_settings.alert.webhook_enabled = True
        mock_settings.alert.webhook_urls = ["https://hooks.example.com/alert"]
        mock_settings.alert.webhook_timeout = 10

        from alerting.webhook_alert import WebhookAlerter
        alerter = WebhookAlerter()

        assert alerter._enabled is True
        assert len(alerter._urls) == 1
        assert alerter._timeout == 10

    @patch("alerting.webhook_alert.settings")
    def test_webhook_alerter_disabled(self, mock_settings):
        """测试禁用状态的 Webhook 告警器"""
        mock_settings.alert.webhook_enabled = False
        mock_settings.alert.webhook_urls = []
        mock_settings.alert.webhook_timeout = 10

        from alerting.webhook_alert import WebhookAlerter
        alerter = WebhookAlerter()

        assert alerter._enabled is False

    @patch("alerting.webhook_alert.settings")
    def test_send_alert_when_disabled(self, mock_settings):
        """测试禁用时发送告警返回 disabled 状态"""
        mock_settings.alert.webhook_enabled = False
        mock_settings.alert.webhook_urls = []
        mock_settings.alert.webhook_timeout = 10

        from alerting.webhook_alert import WebhookAlerter
        alerter = WebhookAlerter()

        result = alerter.send_alert(
            title="Test Alert",
            level="high",
            source="test",
        )
        assert result["status"] == "disabled"

    @patch("alerting.webhook_alert.settings")
    def test_send_alert_no_urls(self, mock_settings):
        """测试无 URL 时发送告警返回错误"""
        mock_settings.alert.webhook_enabled = True
        mock_settings.alert.webhook_urls = []
        mock_settings.alert.webhook_timeout = 10

        from alerting.webhook_alert import WebhookAlerter
        alerter = WebhookAlerter()

        result = alerter.send_alert(
            title="Test Alert",
            level="high",
            source="test",
        )
        assert result["status"] == "error"

    @patch("alerting.webhook_alert.urllib.request.urlopen")
    @patch("alerting.webhook_alert.settings")
    def test_send_custom_webhook_success(self, mock_settings, mock_urlopen):
        """测试发送自定义 Webhook 成功"""
        mock_settings.alert.webhook_enabled = True
        mock_settings.alert.webhook_urls = ["https://hooks.example.com/notify"]
        mock_settings.alert.webhook_timeout = 10

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        from alerting.webhook_alert import WebhookAlerter
        alerter = WebhookAlerter()

        result = alerter.send_custom(
            url="https://hooks.example.com/notify",
            payload={"text": "Test message"},
        )
        assert result["status"] == "ok"
        assert result["status_code"] == 200

    @patch("alerting.webhook_alert.settings")
    def test_level_to_color_mapping(self, mock_settings):
        """测试告警级别到颜色的映射"""
        mock_settings.alert.webhook_enabled = False
        mock_settings.alert.webhook_urls = []
        mock_settings.alert.webhook_timeout = 10

        from alerting.webhook_alert import WebhookAlerter
        alerter = WebhookAlerter()

        assert alerter._level_to_color("critical") == "#dc2626"
        assert alerter._level_to_color("high") == "#f59e0b"
        assert alerter._level_to_color("medium") == "#0ea5e9"
        assert alerter._level_to_color("low") == "#64748b"
        assert alerter._level_to_color("unknown") == "#64748b"


# ============================================================
# 告警聚合缓冲区测试
# ============================================================

class TestAlertAggregation:
    """告警聚合缓冲区处理测试"""

    @pytest.fixture(autouse=True)
    def _setup_manager(self):
        """创建 AlertManager"""
        with patch("alerting.alert_manager.settings") as mock_settings, \
             patch("alerting.alert_manager.EmailAlerter"), \
             patch("alerting.alert_manager.WebhookAlerter"), \
             patch("alerting.alert_manager.db_manager"):
            mock_settings.alert.alert_cooldown = 0
            mock_settings.alert.alert_aggregation_window = 60
            mock_settings.alert.max_alerts_per_minute = 1000
            mock_settings.alert.email_enabled = False
            mock_settings.alert.webhook_enabled = False

            from alerting.alert_manager import AlertManager
            self.manager = AlertManager()

    def test_empty_buffer_processing(self):
        """空缓冲区处理不报错"""
        self.manager._process_aggregation_buffer()
        assert len(self.manager._aggregation_buffer) == 0

    def test_single_item_buffer_no_aggregation(self):
        """单条告警不触发聚合"""
        mock_alert = MagicMock()
        self.manager._aggregation_buffer.append(mock_alert)
        self.manager._process_aggregation_buffer()
        # 单条告警不增加聚合计数
        assert self.manager._stats["aggregated"] == 0

    def test_multiple_items_buffer_triggers_aggregation(self):
        """多条告警触发聚合"""
        for i in range(5):
            self.manager._aggregation_buffer.append(MagicMock())

        self.manager._process_aggregation_buffer()
        # 5条告警聚合，减去1条直接分发，聚合了4条
        assert self.manager._stats["aggregated"] == 4
        assert len(self.manager._aggregation_buffer) == 0

    def test_aggregation_buffer_maxlen(self):
        """聚合缓冲区有最大长度限制"""
        assert self.manager._aggregation_buffer.maxlen == 1000


# ============================================================
# 告警统计测试
# ============================================================

class TestAlertStatistics:
    """告警统计测试"""

    @pytest.fixture(autouse=True)
    def _setup_manager(self):
        """创建 AlertManager"""
        with patch("alerting.alert_manager.settings") as mock_settings, \
             patch("alerting.alert_manager.EmailAlerter"), \
             patch("alerting.alert_manager.WebhookAlerter"), \
             patch("alerting.alert_manager.db_manager"):
            mock_settings.alert.alert_cooldown = 0
            mock_settings.alert.alert_aggregation_window = 60
            mock_settings.alert.max_alerts_per_minute = 1000
            mock_settings.alert.email_enabled = True
            mock_settings.alert.webhook_enabled = True

            from alerting.alert_manager import AlertManager
            self.manager = AlertManager()

    @patch("alerting.alert_manager.db_manager")
    def test_get_statistics(self, mock_db):
        """测试获取告警统计"""
        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_db.get_session.return_value = mock_session

        mock_session.query.return_value.count.return_value = 42
        mock_session.query.return_value.filter_by.return_value.count.return_value = 5
        mock_session.query.return_value.group_by.return_value.all.return_value = []

        with patch("alerting.alert_manager.settings") as mock_settings:
            mock_settings.alert.email_enabled = True
            mock_settings.alert.webhook_enabled = True

            stats = self.manager.get_statistics()

        assert "total_sent" in stats
        assert "email_sent" in stats
        assert "webhook_sent" in stats
        assert "suppressed" in stats
        assert "aggregated" in stats
        assert "total_alerts" in stats
        assert "new_alerts" in stats
        assert "channels" in stats

    def test_stats_initial_values(self):
        """测试统计初始值"""
        assert self.manager._stats["total_sent"] == 0
        assert self.manager._stats["email_sent"] == 0
        assert self.manager._stats["webhook_sent"] == 0
        assert self.manager._stats["suppressed"] == 0
        assert self.manager._stats["aggregated"] == 0

    def test_register_callback(self):
        """测试注册告警回调"""
        callback = MagicMock()
        self.manager.register_callback(callback)
        assert len(self.manager._callbacks) == 1
        assert self.manager._callbacks[0] is callback


# ============================================================
# 告警分发测试
# ============================================================

class TestAlertDispatch:
    """告警分发测试"""

    @pytest.fixture(autouse=True)
    def _setup_manager(self):
        """创建 AlertManager"""
        with patch("alerting.alert_manager.settings") as mock_settings, \
             patch("alerting.alert_manager.EmailAlerter") as mock_email_cls, \
             patch("alerting.alert_manager.WebhookAlerter") as mock_webhook_cls, \
             patch("alerting.alert_manager.db_manager"):
            mock_settings.alert.alert_cooldown = 0
            mock_settings.alert.alert_aggregation_window = 60
            mock_settings.alert.max_alerts_per_minute = 1000
            mock_settings.alert.email_enabled = True
            mock_settings.alert.webhook_enabled = True

            from alerting.alert_manager import AlertManager, AlertLevel
            self.AlertLevel = AlertLevel
            self.manager = AlertManager()
            self.mock_email = mock_email_cls.return_value
            self.mock_webhook = mock_webhook_cls.return_value

    def test_dispatch_high_alert_sends_email(self):
        """高级别告警发送邮件"""
        mock_alert = MagicMock()
        mock_alert.title = "High Alert"
        mock_alert.level = self.AlertLevel.HIGH
        mock_alert.source = "ids"
        mock_alert.description = "Test"
        mock_alert.source_ip = "10.0.0.1"
        mock_alert.dest_ip = ""
        mock_alert.metadata_json = None

        self.manager._dispatch_alert(mock_alert)
        self.mock_email.send_alert.assert_called_once()
        self.mock_webhook.send_alert.assert_called_once()

    def test_dispatch_critical_alert_sends_email(self):
        """严重级别告警发送邮件"""
        mock_alert = MagicMock()
        mock_alert.title = "Critical Alert"
        mock_alert.level = self.AlertLevel.CRITICAL
        mock_alert.source = "firewall"
        mock_alert.description = "Critical event"
        mock_alert.source_ip = "1.2.3.4"
        mock_alert.dest_ip = ""
        mock_alert.metadata_json = None

        self.manager._dispatch_alert(mock_alert)
        self.mock_email.send_alert.assert_called_once()
        self.mock_webhook.send_alert.assert_called_once()

    def test_dispatch_low_alert_no_email(self):
        """低级别告警不发送邮件"""
        mock_alert = MagicMock()
        mock_alert.title = "Low Alert"
        mock_alert.level = self.AlertLevel.LOW
        mock_alert.source = "system"
        mock_alert.description = "Info"
        mock_alert.source_ip = ""
        mock_alert.dest_ip = ""
        mock_alert.metadata_json = None

        self.manager._dispatch_alert(mock_alert)
        self.mock_email.send_alert.assert_not_called()
        # Webhook 应该总是发送
        self.mock_webhook.send_alert.assert_called_once()
