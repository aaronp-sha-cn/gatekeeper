"""
GateKeeper - CLI自动补全
基于prompt-toolkit的命令自动补全功能
"""

from typing import List, Iterable, Optional
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document


class GateKeeperCompleter(Completer):
    """
    GateKeeper CLI 自动补全器
    提供命令、子命令和参数的自动补全
    """

    # 主命令列表
    COMMANDS = [
        "help", "exit", "quit", "status", "version",
        "network", "net", "interfaces", "ifconfig",
        "capture", "scan", "portscan",
        "firewall", "fw", "alerts", "intel", "threat",
        "ai", "db",
    ]

    # 子命令映射
    SUBCOMMANDS = {
        "network": ["status"],
        "net": ["status"],
        "capture": ["start", "stop", "stats"],
        "firewall": ["list", "add", "remove", "status"],
        "fw": ["list", "add", "remove", "status"],
        "alerts": ["stats"],
        "intel": ["check", "search", "stats"],
        "threat": ["check", "search", "stats"],
        "ai": ["status", "detect"],
        "db": ["status", "stats"],
    }

    # 参数提示
    ARGUMENTS = {
        "capture start": ["eth0", "wlan0", "ens33", "enp0s3"],
        "scan": ["192.168.1.0/24", "192.168.1.1", "10.0.0.0/16"],
        "portscan": ["192.168.1.1", "localhost", "10.0.0.1"],
        "firewall add": ["DROP", "ACCEPT", "REJECT"],
        "intel check": ["8.8.8.8", "1.1.1.1", "192.168.1.1"],
        "threat check": ["8.8.8.8", "1.1.1.1", "192.168.1.1"],
    }

    def get_completions(
        self, document: Document, complete_event
    ) -> Iterable[Completion]:
        """
        获取补全建议

        Args:
            document: 当前文档
            complete_event: 补全事件

        Yields:
            补全建议
        """
        text = document.text_before_cursor.strip()

        if not text:
            for cmd in self.COMMANDS:
                yield Completion(cmd, start_position=0)
            return

        parts = text.split()
        current = parts[-1] if parts else ""

        # 补全主命令
        if len(parts) == 1:
            for cmd in self.COMMANDS:
                if cmd.startswith(current.lower()):
                    yield Completion(
                        cmd,
                        start_position=-len(current),
                        display=cmd,
                    )
            return

        # 补全子命令
        command = parts[0].lower()
        if len(parts) == 2:
            subcmds = self.SUBCOMMANDS.get(command, [])
            for sub in subcmds:
                if sub.startswith(current.lower()):
                    yield Completion(
                        sub,
                        start_position=-len(current),
                        display=sub,
                    )
            return

        # 补全参数
        prefix = " ".join(parts[:-1])
        args = self.ARGUMENTS.get(prefix, [])
        for arg in args:
            if arg.startswith(current):
                yield Completion(
                    arg,
                    start_position=-len(current),
                    display=arg,
                )
