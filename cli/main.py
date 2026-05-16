"""
GateKeeper - CLI入口
基于prompt-toolkit的交互式命令行管理工具
"""

import sys
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style

from cli.commands import CommandHandler
from cli.completer import GateKeeperCompleter
from config.settings import settings
from config.logging_config import get_logger

logger = get_logger("cli")


# CLI样式定义
STYLE = Style.from_dict({
    "prompt": "ansicyan bold",
    "command": "ansigreen",
    "error": "ansired bold",
    "info": "ansiblue",
    "warning": "ansiyellow",
    "success": "ansigreen",
})


class GateKeeperCLI:
    """
    GateKeeper 交互式命令行工具
    """

    def __init__(self):
        self._running = True
        self._command_handler = CommandHandler()
        self._completer = GateKeeperCompleter()

        # 创建PromptSession
        self._session = PromptSession(
            history=FileHistory(".gatekeeper_cli_history"),
            auto_suggest=AutoSuggestFromHistory(),
            completer=self._completer,
            style=STYLE,
            enable_system_prompt=True,
        )

    def run(self):
        """启动CLI"""
        self._print_banner()

        while self._running:
            try:
                user_input = self._session.prompt(
                    [("class:prompt", "gatekeeper> ")],
                )

                if not user_input.strip():
                    continue

                # 处理命令
                result = self._command_handler.execute(user_input)

                if result.get("type") == "exit":
                    self._running = False
                elif result.get("type") == "error":
                    print("[ERROR] {}".format(result.get('message', '未知错误')))
                elif result.get("type") == "output":
                    self._format_output(result.get("data", {}))

            except KeyboardInterrupt:
                print("\n输入 Ctrl+D 或输入 'exit' 退出")
                continue
            except EOFError:
                print("\n再见!")
                break
            except Exception as e:
                print("[ERROR] 命令执行失败: {}".format(e))

    def _print_banner(self):
        """打印欢迎横幅"""
        banner = """
    ╔══════════════════════════════════════════════╗
    ║         GateKeeper v{}              ║
    ║      AI安全网络防御系统 - 命令行工具      ║
    ╚══════════════════════════════════════════════╝

    输入 'help' 查看可用命令
    输入 'exit' 退出系统
""".format(settings.version)
        print(banner)

    def _format_output(self, data: dict):
        """格式化输出数据"""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, list):
                    print("\n{}:".format(key))
                    for item in value:
                        if isinstance(item, dict):
                            for k, v in item.items():
                                print("  {}: {}".format(k, v))
                        else:
                            print("  - {}".format(item))
                else:
                    print("{}: {}".format(key, value))
        elif isinstance(data, str):
            print(data)
        else:
            print(data)


def main():
    """CLI入口函数 - 启动 Junos 风格交互式命令行"""
    from cli.junos_cli import main as junos_main
    junos_main()


if __name__ == "__main__":
    main()
