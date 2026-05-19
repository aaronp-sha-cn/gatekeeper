"""
GateKeeper - CLI测试
"""

import pytest
from unittest.mock import patch, MagicMock


# ============================================================
# CommandHandler 测试
# ============================================================

class TestCommandHandler:
    """命令处理器测试"""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from cli.commands import CommandHandler
        self.handler = CommandHandler()

    def test_help_command(self):
        """测试帮助命令"""
        result = self.handler.execute("help")
        assert result["type"] == "output"

    def test_exit_command(self):
        """测试退出命令"""
        result = self.handler.execute("exit")
        assert result["type"] == "exit"
        result = self.handler.execute("quit")
        assert result["type"] == "exit"

    def test_version_command(self):
        """测试版本命令"""
        result = self.handler.execute("version")
        assert result["type"] == "output"

    def test_unknown_command(self):
        """测试未知命令"""
        result = self.handler.execute("nonexistent_command")
        assert result["type"] == "error"

    def test_empty_input(self):
        """测试空输入"""
        result = self.handler.execute("")
        assert result["type"] == "output"

    def test_get_commands(self):
        """测试获取命令列表"""
        commands = self.handler.get_commands()
        assert "help" in commands
        assert "exit" in commands
        assert "status" in commands
        assert "scan" in commands

    def test_status_command(self):
        """测试状态命令"""
        result = self.handler.execute("status")
        assert result["type"] == "output"


# ============================================================
# GateKeeperCompleter 测试
# ============================================================

class TestGateKeeperCompleter:
    """自动补全测试"""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from cli.completer import GateKeeperCompleter
        self.completer = GateKeeperCompleter()

    def test_commands_list(self):
        """测试命令列表不为空"""
        assert len(self.completer.COMMANDS) > 0
        assert "help" in self.completer.COMMANDS
        assert "scan" in self.completer.COMMANDS

    def test_subcommands(self):
        """测试子命令映射"""
        assert "capture" in self.completer.SUBCOMMANDS
        assert "start" in self.completer.SUBCOMMANDS["capture"]
        assert "firewall" in self.completer.SUBCOMMANDS
        assert "list" in self.completer.SUBCOMMANDS["firewall"]
