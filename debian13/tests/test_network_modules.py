# -*- coding: utf-8 -*-
"""
GateKeeper - 网络模块测试
测试 FirewallManager、DHCPService、DNSFilterEngine 等网络组件
"""

import pytest
import os
import tempfile
from unittest.mock import patch, MagicMock, call


# ============================================================
# FirewallManager 测试
# ============================================================

class TestFirewallManager:
    """防火墙管理器测试"""

    @pytest.fixture(autouse=True)
    def _setup(self):
        """创建 FirewallManager（mock subprocess）"""
        with patch("network.firewall.subprocess.run") as mock_run, \
             patch("network.firewall.db_manager"):
            # mock _detect_backend: which nft 返回非0, which iptables 返回0
            mock_run.side_effect = [
                MagicMock(returncode=1),  # which nft
                MagicMock(returncode=0),  # which iptables
            ]
            from network.firewall import FirewallManager
            self.manager = FirewallManager()
            self.mock_run = mock_run

    def test_initialization(self):
        """测试防火墙管理器初始化"""
        assert self.manager._backend == "iptables"

    def test_add_rule_valid_params(self):
        """测试添加有效防火墙规则"""
        self.mock_run.side_effect = [
            MagicMock(returncode=1),  # which nft (already called in init)
            MagicMock(returncode=0),  # which iptables
            MagicMock(returncode=0),  # iptables -A
        ]

        result = self.manager.add_rule(
            name="Block SSH",
            action="DROP",
            chain="INPUT",
            protocol="tcp",
            dest_port=22,
            source_ip="10.0.0.0/8",
        )
        assert result["status"] == "ok"
        assert result["name"] == "Block SSH"

    def test_add_rule_invalid_chain(self):
        """测试添加无效链的规则"""
        result = self.manager.add_rule(
            name="Test Rule",
            action="DROP",
            chain="INVALID_CHAIN",
        )
        assert result["status"] == "error"
        assert "chain" in result["message"].lower()

    def test_add_rule_invalid_action(self):
        """测试添加无效动作的规则"""
        result = self.manager.add_rule(
            name="Test Rule",
            action="INVALID",
            chain="INPUT",
        )
        assert result["status"] == "error"
        assert "action" in result["message"].lower()

    def test_add_rule_invalid_protocol(self):
        """测试添加无效协议的规则"""
        result = self.manager.add_rule(
            name="Test Rule",
            action="DROP",
            chain="INPUT",
            protocol="invalid_proto",
        )
        assert result["status"] == "error"
        assert "protocol" in result["message"].lower()

    def test_add_rule_invalid_name(self):
        """测试添加无效名称的规则"""
        result = self.manager.add_rule(
            name="",
            action="DROP",
            chain="INPUT",
        )
        assert result["status"] == "error"
        assert "名称" in result["message"]

    def test_add_rule_invalid_source_ip(self):
        """测试添加无效源IP的规则"""
        result = self.manager.add_rule(
            name="Test Rule",
            action="DROP",
            chain="INPUT",
            source_ip="not-an-ip",
        )
        assert result["status"] == "error"
        assert "IP" in result["message"]

    def test_add_rule_invalid_dest_ip(self):
        """测试添加无效目标IP的规则"""
        result = self.manager.add_rule(
            name="Test Rule",
            action="DROP",
            chain="INPUT",
            dest_ip="999.999.999.999",
        )
        assert result["status"] == "error"
        assert "IP" in result["message"]

    def test_add_rule_port_out_of_range(self):
        """测试添加端口超出范围的规则"""
        result = self.manager.add_rule(
            name="Test Rule",
            action="DROP",
            chain="INPUT",
            dest_port=99999,
        )
        assert result["status"] == "error"
        assert "端口" in result["message"]

    def test_add_rule_port_zero(self):
        """测试添加端口为0的规则"""
        result = self.manager.add_rule(
            name="Test Rule",
            action="DROP",
            chain="INPUT",
            source_port=0,
        )
        assert result["status"] == "error"
        assert "端口" in result["message"]

    def test_add_rule_valid_cidr(self):
        """测试添加带 CIDR 的有效 IP"""
        self.mock_run.side_effect = [
            MagicMock(returncode=1),
            MagicMock(returncode=0),
            MagicMock(returncode=0),
        ]

        result = self.manager.add_rule(
            name="Block Subnet",
            action="DROP",
            chain="INPUT",
            source_ip="192.168.0.0/16",
        )
        assert result["status"] == "ok"

    def test_add_rule_log_action(self):
        """测试添加 LOG 动作的规则"""
        self.mock_run.side_effect = [
            MagicMock(returncode=1),
            MagicMock(returncode=0),
            MagicMock(returncode=0),
        ]

        result = self.manager.add_rule(
            name="Log Rule",
            action="LOG",
            chain="INPUT",
        )
        assert result["status"] == "ok"

    def test_remove_rule_not_found(self):
        """测试移除不存在的规则"""
        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.first.return_value = None

        with patch("network.firewall.db_manager") as mock_db:
            mock_db.get_session.return_value = mock_session
            result = self.manager.remove_rule(9999)

        assert result["status"] == "not_found"

    def test_list_rules_empty(self):
        """测试列出空规则列表"""
        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.order_by.return_value.all.return_value = []

        with patch("network.firewall.db_manager") as mock_db:
            mock_db.get_session.return_value = mock_session
            rules = self.manager.list_rules()

        assert rules == []

    def test_get_iptables_rules(self):
        """测试获取 iptables 规则列表"""
        self.mock_run.side_effect = [
            MagicMock(returncode=1),
            MagicMock(returncode=0),
            MagicMock(stdout="Chain INPUT (policy DROP)\ntarget  prot opt source  destination\n", returncode=0),
        ]

        result = self.manager.get_iptables_rules()
        assert "Chain INPUT" in result

    def test_get_status(self):
        """测试获取防火墙状态"""
        self.mock_run.side_effect = [
            MagicMock(returncode=1),
            MagicMock(returncode=0),
            MagicMock(stdout="Chain INPUT (policy DROP)\nChain FORWARD (policy DROP)\nChain OUTPUT (policy ACCEPT)\n", returncode=0),
        ]

        status = self.manager.get_status()
        assert status["backend"] == "iptables"
        assert status["status"] == "active"
        assert "rules_count" in status


# ============================================================
# DHCPService 测试
# ============================================================

class TestDHCPService:
    """DHCP 服务测试"""

    @pytest.fixture(autouse=True)
    def _reset_singleton(self):
        """重置 DHCPService 单例"""
        from network.dhcp import DHCPService
        # 重置单例
        DHCPService._instance = None
        yield
        # 清理
        DHCPService._instance = None

    def test_initialization(self):
        """测试 DHCP 服务初始化"""
        from network.dhcp import DHCPService
        service = DHCPService()
        assert service._enabled is False
        assert service._interface is None
        assert service._range_start is None
        assert service._range_end is None
        assert service._dns_servers == ["8.8.8.8", "8.8.4.4"]
        assert service._lease_time == 86400

    def test_singleton_pattern(self):
        """测试单例模式"""
        from network.dhcp import DHCPService
        s1 = DHCPService()
        s2 = DHCPService()
        assert s1 is s2

    def test_configure(self):
        """测试 DHCP 配置"""
        from network.dhcp import DHCPService
        service = DHCPService()
        service.configure(
            interface="eth0",
            range_start="192.168.1.100",
            range_end="192.168.1.200",
            gateway="192.168.1.1",
            dns_servers=["8.8.8.8", "1.1.1.1"],
            lease_time=43200,
        )
        assert service._interface == "eth0"
        assert service._range_start == "192.168.1.100"
        assert service._range_end == "192.168.1.200"
        assert service._gateway == "192.168.1.1"
        assert service._dns_servers == ["8.8.8.8", "1.1.1.1"]
        assert service._lease_time == 43200

    def test_configure_default_dns(self):
        """测试配置使用默认 DNS"""
        from network.dhcp import DHCPService
        service = DHCPService()
        service.configure(
            interface="eth1",
            range_start="10.0.0.50",
            range_end="10.0.0.150",
        )
        assert service._dns_servers == ["8.8.8.8", "8.8.4.4"]

    def test_start_success(self):
        """测试启动 DHCP 服务成功"""
        from network.dhcp import DHCPService
        service = DHCPService()
        service.configure(
            interface="eth0",
            range_start="192.168.1.100",
            range_end="192.168.1.200",
        )

        with patch.object(service, "_generate_config", return_value=True), \
             patch("network.dhcp.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = service.start()

        assert result is True
        assert service._enabled is True

    def test_start_config_failure(self):
        """测试启动 DHCP 服务配置失败"""
        from network.dhcp import DHCPService
        service = DHCPService()
        service.configure(
            interface="eth0",
            range_start="192.168.1.100",
            range_end="192.168.1.200",
        )

        with patch.object(service, "_generate_config", return_value=False):
            result = service.start()

        assert result is False
        assert service._enabled is False

    def test_stop_success(self):
        """测试停止 DHCP 服务成功"""
        from network.dhcp import DHCPService
        service = DHCPService()
        service._enabled = True

        with patch("network.dhcp.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = service.stop()

        assert result is True
        assert service._enabled is False

    def test_stop_not_running(self):
        """测试停止未运行的 DHCP 服务"""
        from network.dhcp import DHCPService
        service = DHCPService()
        service._enabled = False

        with patch("network.dhcp.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = service.stop()

        assert result is True

    def test_get_leases_no_file(self):
        """测试读取租约文件不存在"""
        from network.dhcp import DHCPService
        service = DHCPService()

        with patch("network.dhcp.os.path.exists", return_value=False):
            leases = service.get_leases()

        assert leases == []

    def test_get_leases_with_file(self):
        """测试读取租约文件"""
        from network.dhcp import DHCPService
        service = DHCPService()

        lease_content = """1704067200 aa:bb:cc:dd:ee:ff 192.168.1.100 laptop *
1704067300 11:22:33:44:55:66 192.168.1.101 phone *
# comment line
"""
        with patch("network.dhcp.os.path.exists", return_value=True), \
             patch("builtins.open", MagicMock(return_value=MagicMock(
                 __enter__=MagicMock(return_value=MagicMock(
                     __iter__=MagicMock(return_value=iter(lease_content.splitlines()))
                 )),
                 __exit__=MagicMock(return_value=False),
             ))):
            leases = service.get_leases()

        assert len(leases) == 2
        assert leases[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert leases[0]["ip"] == "192.168.1.100"
        assert leases[0]["hostname"] == "laptop"
        assert leases[1]["mac"] == "11:22:33:44:55:66"
        assert leases[1]["ip"] == "192.168.1.101"

    def test_get_status(self):
        """测试获取 DHCP 状态"""
        from network.dhcp import DHCPService
        service = DHCPService()
        service.configure(
            interface="eth0",
            range_start="192.168.1.100",
            range_end="192.168.1.200",
            gateway="192.168.1.1",
        )

        with patch("network.dhcp.subprocess.run") as mock_run, \
             patch.object(service, "get_leases", return_value=[]):
            mock_run.return_value = MagicMock(returncode=0)
            status = service.get_status()

        assert status["enabled"] is False
        assert status["interface"] == "eth0"
        assert "192.168.1.100" in status["range"]
        assert status["gateway"] == "192.168.1.1"
        assert status["active_leases"] == 0

    def test_restart(self):
        """测试重启 DHCP 服务"""
        from network.dhcp import DHCPService
        service = DHCPService()
        service.configure(
            interface="eth0",
            range_start="192.168.1.100",
            range_end="192.168.1.200",
        )

        with patch.object(service, "stop", return_value=True) as mock_stop, \
             patch.object(service, "start", return_value=True) as mock_start:
            result = service.restart()

        mock_stop.assert_called_once()
        mock_start.assert_called_once()
        assert result is True


# ============================================================
# DNSFilterEngine 测试
# ============================================================

class TestDNSFilterEngine:
    """DNS 过滤引擎测试"""

    @pytest.fixture
    def engine(self, db_manager_mock, db_session):
        """创建 DNSFilterEngine 实例"""
        with patch("security.dns_filter.db_manager", db_manager_mock):
            from security.dns_filter import DNSFilterEngine
            eng = DNSFilterEngine()
            eng._initialized = True
            return eng

    def test_check_domain_blocked(self, engine):
        """测试检查恶意域名被拦截"""
        result = engine.check_domain("malware-site.org")
        assert result["action"] == "block"

    def test_check_domain_phishing(self, engine):
        """测试检查钓鱼域名被拦截"""
        result = engine.check_domain("secure-account-verify.com")
        assert result["action"] == "block"

    def test_check_domain_allowed(self, engine):
        """测试检查正常域名被放行"""
        result = engine.check_domain("google.com")
        assert result["action"] == "allowed"

    def test_check_domain_wildcard(self, engine):
        """测试检查通配符域名匹配"""
        result = engine.check_domain("subdomain.malware-site.org")
        assert result["action"] == "block"

    def test_get_rules(self, engine):
        """测试获取规则列表"""
        rules = engine.get_rules()
        assert isinstance(rules, list)

    def test_add_and_remove_custom_rule(self, engine, db_session):
        """测试添加和删除自定义规则"""
        # 添加规则
        result = engine.add_rule(
            name="Test Block Rule",
            domain="test-bad-domain.com",
            rule_type="blacklist",
            action="block",
        )
        assert result["status"] == "ok"

        # 验证规则生效
        check = engine.check_domain("test-bad-domain.com")
        assert check["action"] == "block"

        # 删除规则
        rules = engine.get_rules()
        custom_rules = [r for r in rules if r["domain"] == "test-bad-domain.com"]
        if custom_rules:
            remove_result = engine.remove_rule(custom_rules[0]["id"])
            assert remove_result["status"] == "ok"

    def test_check_domain_with_category(self, engine):
        """测试检查域名返回分类信息"""
        result = engine.check_domain("malware-site.org")
        assert result["action"] == "block"
        assert "category" in result or "matched_rule" in result
