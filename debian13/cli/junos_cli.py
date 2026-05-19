# -*- coding: utf-8 -*-
"""
GateKeeper - Junos 风格命令行界面
基于 cmd.Cmd 实现，支持操作模式 (>) 和配置模式 (#)，候选配置独立于运行配置。
commit 将候选配置应用到系统，rollback 回退到之前的提交状态。
"""

import cmd
import os
import sys
import json
import copy
import glob
import subprocess
import time
import hashlib
import getpass
from datetime import datetime
from pathlib import Path

# ============================================================
# ANSI 颜色常量
# ============================================================

class C:
    """ANSI 转义码颜色常量"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"


def color(text, c):
    """为文本添加 ANSI 颜色"""
    return "{}{}{}".format(c, text, C.RESET)


def bold(text):
    """加粗文本"""
    return color(text, C.BOLD)


# ============================================================
# 日志配置
# ============================================================

try:
    from config.logging_config import get_logger
    logger = get_logger("junos_cli")
except Exception:
    import logging
    logger = logging.getLogger("junos_cli")
    if not logger.handlers:
        _h = logging.StreamHandler(sys.stdout)
        _h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(_h)
        logger.setLevel(logging.DEBUG)


# ============================================================
# 配置文件路径
# ============================================================

CONFIG_DIR = "/etc/gatekeeper"
RUNNING_CONFIG_FILE = os.path.join(CONFIG_DIR, "junos_config.json")
CANDIDATE_CONFIG_FILE = os.path.join(CONFIG_DIR, "junos_candidate.json")
ROLLBACK_DIR = os.path.join(CONFIG_DIR, "junos_rollback")
HISTORY_FILE = os.path.join(os.path.expanduser("~"), ".gatekeeper_junos_history")


# ============================================================
# 工具函数
# ============================================================

def run_cmd(cmd_list, check=False, capture=True, timeout=30):
    """
    执行系统命令并返回结果

    Args:
        cmd_list: 命令列表
        check: 是否检查返回码
        capture: 是否捕获输出
        timeout: 超时秒数

    Returns:
        subprocess.CompletedProcess 或模拟结果对象
    """
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=capture,
            text=True,
            check=check,
            timeout=timeout
        )
        return result
    except subprocess.CalledProcessError as e:
        return e
    except subprocess.TimeoutExpired:
        class _TimeoutResult:
            returncode = 124
            stdout = ""
            stderr = "命令执行超时"
        return _TimeoutResult()
    except FileNotFoundError:
        class _NotFoundResult:
            returncode = 127
            stdout = ""
            stderr = "命令未找到: {}".format(cmd_list[0] if cmd_list else "")
        return _NotFoundResult()
    except Exception as e:
        class _ErrResult:
            def __init__(self, err):
                self.returncode = 1
                self.stderr = str(err)
                self.stdout = ""
        return _ErrResult(e)


def ensure_config_dir():
    """确保配置目录存在"""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(ROLLBACK_DIR, exist_ok=True)


def load_config(filepath):
    """
    从 JSON 文件加载配置

    Args:
        filepath: 配置文件路径

    Returns:
        配置字典
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return _default_config()


def save_config(filepath, config):
    """
    保存配置到 JSON 文件

    Args:
        filepath: 配置文件路径
        config: 配置字典
    """
    ensure_config_dir()
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def _default_config():
    """返回默认空配置"""
    return {
        "version": "1.0.4",
        "system": {
            "services": {},
            "name-server": [],
            "root-authentication": {"hashed-password": ""}
        },
        "interfaces": {},
        "routing-options": {
            "static": {}
        },
        "protocols": {
            "ospf": {},
            "bgp": {}
        },
        "security": {
            "zones": {},
            "policies": {},
            "address-book": {"global": {}},
            "nat": {"source": {}},
            "ipsec": {},
            "ike": {}
        }
    }


def deep_set(d, keys, value):
    """
    在嵌套字典中设置值，自动创建中间层级

    Args:
        d: 目标字典
        keys: 键路径列表
        value: 要设置的值
    """
    for key in keys[:-1]:
        if key not in d or not isinstance(d[key], dict):
            d[key] = {}
        d = d[key]
    d[keys[-1]] = value


def deep_get(d, keys, default=None):
    """
    从嵌套字典中获取值

    Args:
        d: 源字典
        keys: 键路径列表
        default: 默认值

    Returns:
        找到的值或默认值
    """
    for key in keys:
        if not isinstance(d, dict) or key not in d:
            return default
        d = d[key]
    return d


def deep_delete(d, keys):
    """
    从嵌套字典中删除值

    Args:
        d: 源字典
        keys: 键路径列表

    Returns:
        是否成功删除
    """
    for key in keys[:-1]:
        if not isinstance(d, dict) or key not in d:
            return False
        d = d[key]
    if isinstance(d, dict) and keys[-1] in d:
        del d[keys[-1]]
        return True
    return False


def config_to_set_commands(config, prefix="set"):
    """
    将配置字典转换为 set 命令列表

    Args:
        config: 配置字典
        prefix: 命令前缀

    Returns:
        set 命令字符串列表
    """
    commands = []
    if isinstance(config, dict):
        for key, value in config.items():
            full_key = "{} {}".format(prefix, key) if prefix else key
            if isinstance(value, dict) and value:
                commands.extend(config_to_set_commands(value, full_key))
            elif isinstance(value, list):
                for item in value:
                    commands.append("{} {}".format(full_key, item))
            elif value != "" and value is not None:
                commands.append("{} {}".format(full_key, value))
            else:
                commands.append(full_key)
    return commands


def dict_diff(running, candidate, path=""):
    """
    比较两个配置字典，返回差异

    Args:
        running: 运行配置
        candidate: 候选配置
        path: 当前路径

    Returns:
        差异字符串列表
    """
    diffs = []
    all_keys = set(list(running.keys()) + list(candidate.keys()))

    for key in sorted(all_keys):
        current_path = "{} {}".format(path, key) if path else key
        r_val = running.get(key)
        c_val = candidate.get(key)

        if key not in running:
            diffs.append(color("+ {}".format(current_path), C.GREEN))
            if isinstance(c_val, dict):
                diffs.extend(dict_diff({}, c_val, current_path))
            elif isinstance(c_val, list):
                for item in c_val:
                    diffs.append(color("+ {} {}".format(current_path, item), C.GREEN))
            elif c_val != "" and c_val is not None:
                diffs.append(color("+ {} {}".format(current_path, c_val), C.GREEN))
        elif key not in candidate:
            diffs.append(color("- {}".format(current_path), C.RED))
            if isinstance(r_val, dict):
                diffs.extend(dict_diff(r_val, {}, current_path))
            elif isinstance(r_val, list):
                for item in r_val:
                    diffs.append(color("- {} {}".format(current_path, item), C.RED))
            elif r_val != "" and r_val is not None:
                diffs.append(color("- {} {}".format(current_path, r_val), C.RED))
        elif isinstance(r_val, dict) and isinstance(c_val, dict):
            diffs.extend(dict_diff(r_val, c_val, current_path))
        elif r_val != c_val:
            if isinstance(c_val, list):
                diffs.append(color("- {} {}".format(current_path, r_val), C.RED))
                for item in c_val:
                    diffs.append(color("+ {} {}".format(current_path, item), C.GREEN))
            else:
                diffs.append(color("- {} {}".format(current_path, r_val), C.RED))
                diffs.append(color("+ {} {}".format(current_path, c_val), C.GREEN))

    return diffs


# ============================================================
# 操作模式 CLI
# ============================================================

class OperationalMode(cmd.Cmd):
    """
    Junos 操作模式 CLI
    提示符: GateKeeper>
    支持所有操作模式命令，Tab 补全，命令历史。
    """

    intro = color(
        "\nGateKeeper Junos CLI - 操作模式\n"
        "输入 '?' 获取帮助，'configure' 进入配置模式\n",
        C.CYAN
    )
    prompt = color("GateKeeper> ", C.GREEN)

    def __init__(self, running_config=None):
        """
        初始化操作模式

        Args:
            running_config: 运行配置字典，为 None 时从文件加载
        """
        super().__init__()
        if running_config is not None:
            self.running_config = running_config
        else:
            self.running_config = load_config(RUNNING_CONFIG_FILE)
        self._setup_history()

    def _setup_history(self):
        """配置 readline 命令历史"""
        try:
            readline.read_history_file(HISTORY_FILE)
        except (FileNotFoundError, PermissionError):
            pass
        readline.set_history_length(1000)

    def _save_history(self):
        """保存命令历史"""
        try:
            readline.write_history_file(HISTORY_FILE)
        except (PermissionError, OSError):
            pass

    def precmd(self, line):
        """命令预处理：去除前后空白，记录历史"""
        stripped = line.strip()
        if stripped and stripped != "?":
            logger.debug("操作模式命令: %s", stripped)
        return stripped

    def postcmd(self, stop, line):
        """命令后处理"""
        return stop

    def postloop(self):
        """退出循环后保存历史"""
        self._save_history()

    def default(self, line):
        """处理未知命令"""
        if line == "?":
            self.do_help("")
            return
        print(color("错误: 未知命令 '{}'. 输入 '?' 获取帮助。".format(line), C.RED))

    def emptyline(self):
        """空行不做任何操作"""
        pass

    # ---- 显示命令 ----

    def do_show(self, line):
        """
        显示系统信息
        用法: show <version|interfaces|route|configuration|security|system>
        """
        args = line.strip().split()
        if not args:
            print(color("用法: show <version|interfaces|route|configuration|security|system>", C.YELLOW))
            return

        subcmd = args[0]

        if subcmd == "version":
            self._show_version()
        elif subcmd == "interfaces":
            terse = len(args) > 1 and "terse" in args[1:]
            self._show_interfaces(terse)
        elif subcmd == "route" or subcmd == "routes":
            self._show_routes()
        elif subcmd == "configuration":
            section = args[1] if len(args) > 1 else None
            self._show_configuration(section)
        elif subcmd == "security":
            self._show_security(args[1:])
        elif subcmd == "system":
            self._show_system(args[1:])
        else:
            print(color("错误: 未知的 show 子命令 '{}'".format(subcmd), C.RED))

    def complete_show(self, text, line, begidx, endidx):
        """show 命令补全"""
        subcmds = [
            "version", "interfaces", "route", "configuration",
            "security", "system"
        ]
        if not text:
            return subcmds
        return [s for s in subcmds if s.startswith(text)]

    def _show_version(self):
        """显示系统版本信息"""
        print(color("\nGateKeeper 防火墙系统", C.BOLD))
        print(color("─" * 50, C.CYAN))

        # 主机名
        hostname = os.uname().nodename or "gatekeeper"
        print("  主机名:              {}".format(hostname))

        # GateKeeper 版本
        try:
            from config.settings import Settings
            gk_version = Settings().version
        except Exception:
            gk_version = "未知"
        print("  GateKeeper 版本:     {}".format(gk_version))

        # Debian 版本
        try:
            with open("/etc/debian_version", "r") as f:
                debian_ver = f.read().strip()
            print("  基础系统:            Debian {}".format(debian_ver))
        except Exception:
            print("  基础系统:            未知")

        # 内核信息
        uname = os.uname()
        print("  内核:                {} {}".format(uname.sysname, uname.release))
        print("  架构:                {}".format(uname.machine))

        # 运行时间
        try:
            with open("/proc/uptime", "r") as f:
                uptime_seconds = float(f.read().split()[0])
            uptime_str = self._format_uptime(uptime_seconds)
            print("  运行时间:            {}".format(uptime_str))
        except Exception:
            print("  运行时间:            未知")

        # 最后启动时间
        print("  最后启动:            {}".format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        # 配置版本
        cfg_ver = self.running_config.get("version", "未知")
        print("  配置版本:            {}".format(cfg_ver))
        print()

    def _show_interfaces(self, terse=False):
        """显示网络接口信息"""
        print(color("\n接口状态:", C.BOLD))
        print(color("─" * 70, C.CYAN))

        # 解析 ip -br addr
        result = run_cmd(["ip", "-br", "addr"])
        if result.returncode != 0:
            print(color("  无法获取接口信息: {}".format(result.stderr), C.RED))
            return

        lines = result.stdout.strip().split("\n")
        if terse:
            print("  {:<16} {:<10} {:<20} {:<10}".format(
                "接口", "状态", "地址", "MTU"
            ))
            print("  " + "-" * 60)
        else:
            print("  {:<16} {:<10} {:<24} {:<10} {:<10}".format(
                "接口", "状态", "地址", "MTU", "MAC"
            ))
            print("  " + "-" * 76)

        for iface_line in lines:
            parts = iface_line.split()
            if not parts:
                continue
            iface_name = parts[0]
            iface_state = parts[1] if len(parts) > 1 else "UNKNOWN"

            # 获取地址
            addr = ""
            if len(parts) > 2:
                addr = parts[2]

            # 获取 MTU
            mtu = self._get_iface_mtu(iface_name)

            # 获取 MAC
            mac = self._get_iface_mac(iface_name)

            # 获取操作状态
            operstate = self._get_iface_operstate(iface_name)
            status = color(operstate.upper(), C.GREEN) if operstate == "up" else color(operstate.upper(), C.RED)

            if terse:
                print("  {:<16} {:<10} {:<20} {:<10}".format(
                    iface_name, status, addr, mtu
                ))
            else:
                print("  {:<16} {:<10} {:<24} {:<10} {:<10}".format(
                    iface_name, status, addr, mtu, mac
                ))

        print()

    def _show_routes(self):
        """显示路由表"""
        print(color("\n路由表:", C.BOLD))
        print(color("─" * 70, C.CYAN))

        result = run_cmd(["ip", "route", "show"])
        if result.returncode != 0:
            print(color("  无法获取路由表: {}".format(result.stderr), C.RED))
            return

        lines = result.stdout.strip().split("\n")
        print("  {:<20} {:<15} {:<10} {:<15}".format(
            "目标网络", "网关", "类型", "接口"
        ))
        print("  " + "-" * 65)

        for route_line in lines:
            if not route_line.strip():
                continue
            parts = route_line.split()
            if not parts:
                continue

            dest = parts[0]
            gateway = ""
            iface = ""
            rtype = ""

            for i, part in enumerate(parts):
                if part == "via" and i + 1 < len(parts):
                    gateway = parts[i + 1]
                elif part == "dev" and i + 1 < len(parts):
                    iface = parts[i + 1]
                elif part == "proto" and i + 1 < len(parts):
                    rtype = parts[i + 1]

            if not gateway:
                gateway = "直连"
                rtype = "kernel"

            print("  {:<20} {:<15} {:<10} {:<15}".format(
                dest, gateway, rtype, iface
            ))

        print()

    def _show_configuration(self, section=None):
        """显示运行配置"""
        print(color("\n运行配置:", C.BOLD))
        print(color("─" * 50, C.CYAN))

        if section is None:
            print(color(json.dumps(self.running_config, indent=2, ensure_ascii=False), C.CYAN))
        elif section == "security":
            sec = self.running_config.get("security", {})
            print(color(json.dumps(sec, indent=2, ensure_ascii=False), C.CYAN))
        elif section == "interfaces":
            intf = self.running_config.get("interfaces", {})
            print(color(json.dumps(intf, indent=2, ensure_ascii=False), C.CYAN))
        elif section == "routing-options":
            rt = self.running_config.get("routing-options", {})
            print(color(json.dumps(rt, indent=2, ensure_ascii=False), C.CYAN))
        elif section == "protocols":
            proto = self.running_config.get("protocols", {})
            print(color(json.dumps(proto, indent=2, ensure_ascii=False), C.CYAN))
        elif section == "services":
            svc = self.running_config.get("system", {}).get("services", {})
            print(color(json.dumps(svc, indent=2, ensure_ascii=False), C.CYAN))
        else:
            print(color("  未知配置段落: {}".format(section), C.YELLOW))

        print()

    def complete_show_configuration(self, text, line, begidx, endidx):
        """show configuration 补全"""
        sections = ["security", "interfaces", "routing-options", "protocols", "services"]
        if not text:
            return sections
        return [s for s in sections if s.startswith(text)]

    def _show_security(self, args):
        """显示安全配置"""
        if not args:
            print(color("  用法: show security <zones|policies|nat|ipsec|flow>", C.YELLOW))
            return

        subcmd = args[0]
        security = self.running_config.get("security", {})

        if subcmd == "zones":
            self._show_security_zones(security)
        elif subcmd == "policies":
            self._show_security_policies(security)
        elif subcmd == "nat":
            self._show_security_nat(security)
        elif subcmd == "ipsec":
            self._show_security_ipsec(security)
        elif subcmd == "flow":
            self._show_security_flow(args[1:])
        else:
            print(color("  未知安全子命令: {}".format(subcmd), C.RED))

    def complete_show_security(self, text, line, begidx, endidx):
        """show security 补全"""
        subcmds = ["zones", "policies", "nat", "ipsec", "flow"]
        if not text:
            return subcmds
        return [s for s in subcmds if s.startswith(text)]

    def _show_security_zones(self, security):
        """显示安全区域"""
        zones = security.get("zones", {})
        if not zones:
            print(color("  未配置安全区域", C.YELLOW))
            return

        print(color("\n安全区域:", C.BOLD))
        print(color("─" * 50, C.CYAN))
        for zname, zconf in zones.items():
            print("  区域: {}".format(color(zname, C.BOLD)))
            interfaces = zconf.get("interfaces", [])
            if interfaces:
                print("    接口: {}".format(", ".join(interfaces)))
            addr_book = zconf.get("address-book", {})
            if addr_book:
                print("    地址簿:")
                for aname, aip in addr_book.items():
                    print("      {} -> {}".format(aname, aip))
        print()

    def _show_security_policies(self, security):
        """显示安全策略"""
        policies = security.get("policies", {})
        if not policies:
            print(color("  未配置安全策略", C.YELLOW))
            return

        print(color("\n安全策略:", C.BOLD))
        print(color("─" * 70, C.CYAN))
        for from_zone, to_zones in policies.items():
            for to_zone, pols in to_zones.items():
                for pname, pconf in pols.items():
                    match = pconf.get("match", {})
                    then = pconf.get("then", "deny")
                    print("  {} -> {} | 策略: {}".format(
                        color(from_zone, C.BOLD), color(to_zone, C.BOLD),
                        color(pname, C.CYAN)
                    ))
                    print("    源地址: {}".format(match.get("source-address", "any")))
                    print("    目标地址: {}".format(match.get("destination-address", "any")))
                    print("    应用: {}".format(match.get("application", "any")))
                    action_color = C.GREEN if then == "permit" else C.RED
                    print("    动作: {}".format(color(then, action_color)))
        print()

    def _show_security_nat(self, security):
        """显示源 NAT 规则"""
        nat = security.get("nat", {}).get("source", {})
        if not nat:
            print(color("  未配置 NAT 规则", C.YELLOW))
            return

        print(color("\n源 NAT 规则:", C.BOLD))
        print(color("─" * 60, C.CYAN))
        for rs_name, rs_conf in nat.items():
            print("  规则集: {}".format(color(rs_name, C.BOLD)))
            print("    从区域: {}".format(rs_conf.get("from", {}).get("zone", "any")))
            print("    到区域: {}".format(rs_conf.get("to", {}).get("zone", "any")))
            rules = rs_conf.get("rule", {})
            for rnum, rconf in rules.items():
                print("    规则 {}: 匹配 {}".format(
                    rnum, rconf.get("match", {}).get("source-address", "any")
                ))
                then = rconf.get("then", {}).get("source-nat", "off")
                print("      动作: source-nat {}".format(then))
        print()

    def _show_security_ipsec(self, security):
        """显示 IPSec VPN 状态"""
        ipsec = security.get("ipsec", {})
        if not ipsec:
            print(color("  未配置 IPSec VPN", C.YELLOW))
            return

        print(color("\nIPSec VPN:", C.BOLD))
        print(color("─" * 50, C.CYAN))
        for vpn_name, vpn_conf in ipsec.items():
            print("  VPN: {}".format(color(vpn_name, C.BOLD)))
            print("    绑定接口: {}".format(vpn_conf.get("bind-interface", "未设置")))
            print("    IKE 网关: {}".format(vpn_conf.get("ike", {}).get("gateway", "未设置")))
        print()

    def _show_security_flow(self, args):
        """显示活动会话摘要"""
        if not args or "session" not in args:
            print(color("  用法: show security flow session summary", C.YELLOW))
            return

        print(color("\n活动会话摘要:", C.BOLD))
        print(color("─" * 40, C.CYAN))

        result = run_cmd(["conntrack", "-C"])
        if result.returncode == 0:
            try:
                count = int(result.stdout.strip())
                print("  活动会话数: {}".format(color(str(count), C.GREEN)))
            except ValueError:
                print("  活动会话数: 未知")
        else:
            # 尝试 /proc/net/nf_conntrack
            try:
                with open("/proc/net/nf_conntrack", "r") as f:
                    lines = f.readlines()
                print("  活动会话数: {}".format(color(str(len(lines)), C.GREEN)))
            except Exception:
                print("  无法获取会话信息 (需要 root 权限)")
        print()

    def _show_system(self, args):
        """显示系统信息"""
        if not args:
            print(color("  用法: show system <uptime>", C.YELLOW))
            return

        subcmd = args[0]
        if subcmd == "uptime":
            self._show_system_uptime()
        else:
            print(color("  未知系统子命令: {}".format(subcmd), C.RED))

    def complete_show_system(self, text, line, begidx, endidx):
        """show system 补全"""
        return ["uptime"]

    def _show_system_uptime(self):
        """显示系统运行时间"""
        print(color("\n系统运行时间:", C.BOLD))
        print(color("─" * 40, C.CYAN))

        try:
            with open("/proc/uptime", "r") as f:
                uptime_seconds = float(f.read().split()[0])
            print("  当前时间: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            print("  运行时间: {}".format(self._format_uptime(uptime_seconds)))

            # 负载
            try:
                with open("/proc/loadavg", "r") as f:
                    loadavg = f.read().strip()
                print("  系统负载: {}".format(loadavg))
            except Exception:
                pass
        except Exception as e:
            print(color("  无法获取运行时间: {}".format(e), C.RED))
        print()

    # ---- 网络工具命令 ----

    def do_ping(self, line):
        """
        Ping 目标主机
        用法: ping <host> [count <n>]
        """
        args = line.strip().split()
        if not args:
            print(color("用法: ping <host> [count <n>]", C.YELLOW))
            return

        host = args[0]
        count = "4"
        if "count" in args:
            idx = args.index("count")
            if idx + 1 < len(args):
                count = args[idx + 1]

        print(color("\nPING {} ({} 数据包):".format(host, count), C.BOLD))
        print(color("─" * 40, C.CYAN))

        result = run_cmd(["ping", "-c", count, "-W", "2", host], check=False)
        print(result.stdout)
        if result.returncode != 0 and result.stderr:
            print(color(result.stderr, C.RED))

    def complete_ping(self, text, line, begidx, endidx):
        """ping 命令补全"""
        return ["count"]

    def do_traceroute(self, line):
        """
        追踪到目标主机的路由
        用法: traceroute <host>
        """
        args = line.strip().split()
        if not args:
            print(color("用法: traceroute <host>", C.YELLOW))
            return

        host = args[0]
        print(color("\nTraceroute {}:".format(host), C.BOLD))
        print(color("─" * 40, C.CYAN))

        result = run_cmd(["traceroute", "-w", "2", "-m", "30", host], check=False, timeout=60)
        print(result.stdout)
        if result.returncode != 0 and result.stderr:
            print(color(result.stderr, C.RED))

    # ---- 模式切换 ----

    def do_configure(self, line):
        """
        进入配置模式
        用法: configure [private]
        """
        args = line.strip().split()
        private = "private" in args

        print(color("\n进入配置模式...", C.CYAN))
        if private:
            print(color("  (私有配置会话)", C.YELLOW))

        config_mode = ConfigurationMode(self.running_config, private=private)
        config_mode.cmdloop()

        # 配置模式退出后，更新运行配置
        self.running_config = config_mode.running_config

    def complete_configure(self, text, line, begidx, endidx):
        """configure 命令补全"""
        return ["private"]

    # ---- 退出 ----

    def do_exit(self, line):
        """退出 CLI"""
        print(color("\n再见!", C.CYAN))
        return True

    def do_quit(self, line):
        """退出 CLI"""
        return self.do_exit(line)

    # ---- 帮助 ----

    def do_help(self, line):
        """显示帮助信息"""
        print(color("\nGateKeeper Junos CLI - 操作模式", C.BOLD))
        print(color("─" * 50, C.CYAN))
        print(color("  显示命令:", C.BOLD))
        print("    show version                        系统版本信息")
        print("    show interfaces [terse]             网络接口状态")
        print("    show route                          路由表")
        print("    show configuration [section]        运行配置")
        print("    show security zones                 安全区域")
        print("    show security policies              安全策略")
        print("    show security nat source            源 NAT 规则")
        print("    show security ipsec sa              IPSec VPN 状态")
        print("    show security flow session summary  活动会话")
        print("    show system uptime                  系统运行时间")
        print()
        print(color("  网络工具:", C.BOLD))
        print("    ping <host> [count <n>]             Ping 主机")
        print("    traceroute <host>                   路由追踪")
        print()
        print(color("  模式切换:", C.BOLD))
        print("    configure [private]                 进入配置模式")
        print()
        print(color("  其他:", C.BOLD))
        print("    exit / quit                         退出 CLI")
        print("    ? / help                            显示帮助")
        print()

    # ---- 辅助方法 ----

    @staticmethod
    def _format_uptime(seconds):
        """
        格式化运行时间

        Args:
            seconds: 秒数

        Returns:
            格式化的时间字符串
        """
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)

        parts = []
        if days > 0:
            parts.append("{} 天".format(days))
        if hours > 0:
            parts.append("{} 小时".format(hours))
        if minutes > 0:
            parts.append("{} 分钟".format(minutes))
        parts.append("{} 秒".format(secs))
        return " ".join(parts)

    @staticmethod
    def _get_iface_mtu(iface):
        """获取接口 MTU"""
        try:
            with open("/sys/class/net/{}/mtu".format(iface), "r") as f:
                return f.read().strip()
        except Exception:
            return "1500"

    @staticmethod
    def _get_iface_mac(iface):
        """获取接口 MAC 地址"""
        try:
            with open("/sys/class/net/{}/address".format(iface), "r") as f:
                return f.read().strip()
        except Exception:
            return "N/A"

    @staticmethod
    def _get_iface_operstate(iface):
        """获取接口操作状态"""
        try:
            with open("/sys/class/net/{}/operstate".format(iface), "r") as f:
                return f.read().strip().lower()
        except Exception:
            return "unknown"


# ============================================================
# 配置模式 CLI
# ============================================================

class ConfigurationMode(cmd.Cmd):
    """
    Junos 配置模式 CLI
    提示符: [edit] GateKeeper#
    支持候选配置管理，set/delete/commit/rollback 等命令。
    """

    intro = color("\n进入配置模式 - 输入 'commit' 应用更改，'exit' 退出\n", C.CYAN)

    def __init__(self, running_config, private=False):
        """
        初始化配置模式

        Args:
            running_config: 运行配置字典
            private: 是否为私有配置会话
        """
        super().__init__()
        self.running_config = running_config
        self.candidate_config = copy.deepcopy(running_config)
        self.private = private
        self.edit_path = []  # 当前编辑路径
        self._update_prompt()
        self._setup_history()

    def _setup_history(self):
        """配置 readline 命令历史"""
        try:
            readline.read_history_file(HISTORY_FILE)
        except (FileNotFoundError, PermissionError):
            pass

    def _save_history(self):
        """保存命令历史"""
        try:
            readline.write_history_file(HISTORY_FILE)
        except (PermissionError, OSError):
            pass

    def _update_prompt(self):
        """更新提示符"""
        if self.edit_path:
            edit_str = " ".join(self.edit_path)
            self.prompt = color("[edit {}] ".format(edit_str), C.CYAN) + color("GateKeeper# ", C.GREEN)
        else:
            self.prompt = color("[edit] ", C.CYAN) + color("GateKeeper# ", C.GREEN)

    def precmd(self, line):
        """命令预处理"""
        stripped = line.strip()
        if stripped and stripped != "?":
            logger.debug("配置模式命令: %s", stripped)
        return stripped

    def postloop(self):
        """退出循环后保存历史"""
        self._save_history()

    def default(self, line):
        """处理未知命令"""
        if line == "?":
            self.do_help("")
            return
        print(color("错误: 未知命令 '{}'. 输入 '?' 获取帮助。".format(line), C.RED))

    def emptyline(self):
        """空行不做任何操作"""
        pass

    # ---- set 命令 ----

    def do_set(self, line):
        """
        设置配置参数
        用法: set <配置路径>
        示例:
          set security zones security-zone trust interfaces eth0
          set interfaces eth0 unit 0 family inet address 192.168.1.1/24
          set routing-options static route 0.0.0.0/0 next-hop 10.0.0.1
        """
        tokens = line.strip().split()
        if not tokens:
            print(color("用法: set <配置路径>", C.YELLOW))
            return

        self._apply_set(tokens)

    def _apply_set(self, tokens):
        """
        将 set 命令的 token 列表应用到候选配置

        Args:
            tokens: set 命令后的 token 列表
        """
        if len(tokens) < 2:
            print(color("错误: 配置路径过短", C.RED))
            return

        category = tokens[0]

        try:
            if category == "security":
                self._set_security(tokens[1:])
            elif category == "interfaces":
                self._set_interface(tokens[1:])
            elif category == "routing-options":
                self._set_routing(tokens[1:])
            elif category == "protocols":
                self._set_protocols(tokens[1:])
            elif category == "system":
                self._set_system(tokens[1:])
            else:
                print(color("错误: 未知的配置类别 '{}'".format(category), C.RED))
        except (IndexError, KeyError) as e:
            print(color("错误: 参数不足或格式错误 - {}".format(e), C.RED))

    def _set_security(self, tokens):
        """处理 set security 子命令"""
        if not tokens:
            print(color("用法: set security <zones|policies|address-book|nat|ipsec|ike>", C.YELLOW))
            return

        sub = tokens[0]

        if sub == "zones" and len(tokens) >= 4:
            # set security zones security-zone <name> ...
            if tokens[1] == "security-zone":
                zone_name = tokens[2]
                zones = self.candidate_config.setdefault("security", {}).setdefault("zones", {})
                zone = zones.setdefault(zone_name, {})

                if len(tokens) >= 5:
                    action = tokens[3]
                    if action == "address-book" and len(tokens) >= 7 and tokens[4] == "address":
                        addr_name = tokens[5]
                        addr_ip = tokens[6]
                        ab = zone.setdefault("address-book", {})
                        ab[addr_name] = addr_ip
                        print(color("  [设置] 区域 {} 地址簿 {} = {}".format(zone_name, addr_name, addr_ip), C.GREEN))
                    elif action == "interfaces":
                        iface = tokens[4]
                        ifaces = zone.setdefault("interfaces", [])
                        if iface not in ifaces:
                            ifaces.append(iface)
                        print(color("  [设置] 区域 {} 接口 {}".format(zone_name, iface), C.GREEN))
                    else:
                        print(color("  [设置] 区域 {} {} {}".format(zone_name, action, " ".join(tokens[4:])), C.GREEN))
                else:
                    print(color("  [设置] 区域 {} 已存在".format(zone_name), C.GREEN))

        elif sub == "policies" and len(tokens) >= 10:
            # set security policies from-zone <z1> to-zone <z2> policy <name> ...
            if tokens[1] == "from-zone" and tokens[3] == "to-zone" and tokens[5] == "policy":
                from_zone = tokens[2]
                to_zone = tokens[4]
                pol_name = tokens[6]

                policies = self.candidate_config.setdefault("security", {}).setdefault("policies", {})
                fz = policies.setdefault(from_zone, {})
                tz = fz.setdefault(to_zone, {})
                pol = tz.setdefault(pol_name, {})

                if tokens[7] == "match" and len(tokens) >= 14:
                    match = pol.setdefault("match", {})
                    i = 8
                    while i < len(tokens):
                        if tokens[i] == "source-address" and i + 1 < len(tokens):
                            match["source-address"] = tokens[i + 1]
                            i += 2
                        elif tokens[i] == "destination-address" and i + 1 < len(tokens):
                            match["destination-address"] = tokens[i + 1]
                            i += 2
                        elif tokens[i] == "application" and i + 1 < len(tokens):
                            match["application"] = tokens[i + 1]
                            i += 2
                        else:
                            i += 1
                    print(color("  [设置] 策略 {} -> {} {} 匹配规则已更新".format(from_zone, to_zone, pol_name), C.GREEN))

                elif tokens[7] == "then" and len(tokens) >= 9:
                    action = tokens[8]
                    if action in ("permit", "deny", "reject"):
                        pol["then"] = action
                        print(color("  [设置] 策略 {} -> {} {} 动作 = {}".format(from_zone, to_zone, pol_name, action), C.GREEN))
                    else:
                        print(color("错误: 未知策略动作 '{}' (允许: permit/deny/reject)".format(action), C.RED))
                else:
                    print(color("  [设置] 策略 {} -> {} {} 已创建".format(from_zone, to_zone, pol_name), C.GREEN))

        elif sub == "address-book" and len(tokens) >= 5:
            # set security address-book global address <name> <ip/prefix>
            if tokens[1] == "global" and tokens[2] == "address":
                addr_name = tokens[3]
                addr_ip = tokens[4]
                ab = self.candidate_config.setdefault("security", {}).setdefault("address-book", {}).setdefault("global", {})
                ab[addr_name] = addr_ip
                print(color("  [设置] 全局地址簿 {} = {}".format(addr_name, addr_ip), C.GREEN))

        elif sub == "nat" and len(tokens) >= 5:
            self._set_security_nat(tokens[1:])

        elif sub == "ipsec" and len(tokens) >= 4:
            self._set_security_ipsec(tokens[1:])

        elif sub == "ike" and len(tokens) >= 4:
            self._set_security_ike(tokens[1:])

        else:
            print(color("错误: 安全配置格式不正确", C.RED))

    def _set_security_nat(self, tokens):
        """处理 set security nat source 子命令"""
        # set security nat source rule-set <name> from zone <zone> to zone <zone>
        # set security nat source rule-set <name> rule <n> match source-address <addr>
        # set security nat source rule-set <name> rule <n> then source-nat interface|off
        if len(tokens) < 4 or tokens[0] != "source" or tokens[1] != "rule-set":
            print(color("用法: set security nat source rule-set <name> ...", C.YELLOW))
            return

        rs_name = tokens[2]
        nat = self.candidate_config.setdefault("security", {}).setdefault("nat", {}).setdefault("source", {})
        rs = nat.setdefault(rs_name, {})

        if len(tokens) >= 4 and tokens[3] == "from" and len(tokens) >= 7:
            if tokens[4] == "zone" and tokens[5] == "to" and tokens[6] == "zone":
                rs.setdefault("from", {})["zone"] = tokens[5] if len(tokens) > 7 else "any"
                rs.setdefault("to", {})["zone"] = tokens[7] if len(tokens) > 7 else "any"
                print(color("  [设置] NAT 规则集 {} 区域 {} -> {}".format(rs_name, tokens[5], tokens[7]), C.GREEN))

        elif len(tokens) >= 6 and tokens[3] == "rule":
            rule_num = tokens[4]
            rules = rs.setdefault("rule", {})
            rule = rules.setdefault(rule_num, {})

            if len(tokens) >= 7 and tokens[5] == "match":
                if tokens[6] == "source-address" and len(tokens) >= 8:
                    rule.setdefault("match", {})["source-address"] = tokens[7]
                    print(color("  [设置] NAT 规则 {} 匹配源地址 {}".format(rule_num, tokens[7]), C.GREEN))
            elif len(tokens) >= 7 and tokens[5] == "then":
                if tokens[6] == "source-nat" and len(tokens) >= 8:
                    rule.setdefault("then", {})["source-nat"] = tokens[7]
                    print(color("  [设置] NAT 规则 {} 动作 source-nat {}".format(rule_num, tokens[7]), C.GREEN))

    def _set_security_ipsec(self, tokens):
        """处理 set security ipsec 子命令"""
        # set security ipsec vpn <name> bind-interface st0.<n>
        # set security ipsec vpn <name> ike gateway <gw-name>
        if tokens[0] == "vpn" and len(tokens) >= 3:
            vpn_name = tokens[1]
            ipsec = self.candidate_config.setdefault("security", {}).setdefault("ipsec", {})
            vpn = ipsec.setdefault(vpn_name, {})

            if len(tokens) >= 5 and tokens[2] == "bind-interface":
                vpn["bind-interface"] = tokens[3]
                print(color("  [设置] IPSec VPN {} 绑定接口 {}".format(vpn_name, tokens[3]), C.GREEN))
            elif len(tokens) >= 5 and tokens[2] == "ike" and tokens[3] == "gateway":
                vpn.setdefault("ike", {})["gateway"] = tokens[4]
                print(color("  [设置] IPSec VPN {} IKE 网关 {}".format(vpn_name, tokens[4]), C.GREEN))

    def _set_security_ike(self, tokens):
        """处理 set security ike 子命令"""
        # set security ike gateway <name> address <ip>
        # set security ike proposal <name> authentication-method pre-shared-keys
        if len(tokens) < 2:
            print(color("用法: set security ike <gateway|proposal> ...", C.YELLOW))
            return

        ike = self.candidate_config.setdefault("security", {}).setdefault("ike", {})

        if tokens[0] == "gateway" and len(tokens) >= 4:
            gw_name = tokens[1]
            gw = ike.setdefault("gateway", {}).setdefault(gw_name, {})
            if tokens[2] == "address":
                gw["address"] = tokens[3]
                print(color("  [设置] IKE 网关 {} 地址 {}".format(gw_name, tokens[3]), C.GREEN))

        elif tokens[0] == "proposal" and len(tokens) >= 4:
            prop_name = tokens[1]
            prop = ike.setdefault("proposal", {}).setdefault(prop_name, {})
            if tokens[2] == "authentication-method":
                prop["authentication-method"] = tokens[3]
                print(color("  [设置] IKE 提议 {} 认证方法 {}".format(prop_name, tokens[3]), C.GREEN))

    def _set_interface(self, tokens):
        """处理 set interfaces 子命令"""
        # set interfaces <name> unit 0 family inet address <ip/prefix>
        # set interfaces <name> unit 0 family inet dhcp
        if len(tokens) < 2:
            print(color("用法: set interfaces <name> unit 0 family inet address <ip/prefix>", C.YELLOW))
            return

        iface_name = tokens[0]
        interfaces = self.candidate_config.setdefault("interfaces", {})
        iface = interfaces.setdefault(iface_name, {})

        if len(tokens) >= 3 and tokens[1] == "unit":
            unit = tokens[2]
            unit_conf = iface.setdefault("unit", {}).setdefault(unit, {})

            if len(tokens) >= 5 and tokens[3] == "family" and tokens[4] == "inet":
                inet = unit_conf.setdefault("family", {}).setdefault("inet", {})
                if len(tokens) >= 7 and tokens[5] == "address":
                    inet["address"] = tokens[6]
                    print(color("  [设置] 接口 {} 单元 {} 地址 {}".format(iface_name, unit, tokens[6]), C.GREEN))
                elif len(tokens) >= 6 and tokens[5] == "dhcp":
                    inet["dhcp"] = True
                    print(color("  [设置] 接口 {} 单元 {} DHCP 已启用".format(iface_name, unit), C.GREEN))

    def _set_routing(self, tokens):
        """处理 set routing-options 子命令"""
        # set routing-options static route <dest/prefix> next-hop <gw>
        if len(tokens) < 2 or tokens[0] != "static":
            print(color("用法: set routing-options static route <dest/prefix> next-hop <gw>", C.YELLOW))
            return

        static = self.candidate_config.setdefault("routing-options", {}).setdefault("static", {})

        if len(tokens) >= 3 and tokens[1] == "route":
            dest = tokens[2]
            if len(tokens) >= 5 and tokens[3] == "next-hop":
                gw = tokens[4]
                static[dest] = {"next-hop": gw}
                print(color("  [设置] 静态路由 {} 下一跳 {}".format(dest, gw), C.GREEN))

    def _set_protocols(self, tokens):
        """处理 set protocols 子命令"""
        if len(tokens) < 2:
            print(color("用法: set protocols <ospf|bgp> ...", C.YELLOW))
            return

        proto = tokens[0]
        protocols = self.candidate_config.setdefault("protocols", {})

        if proto == "ospf" and len(tokens) >= 4:
            # set protocols ospf area <area> interface <iface>
            if tokens[1] == "area":
                area = tokens[2]
                ospf = protocols.setdefault("ospf", {})
                area_conf = ospf.setdefault(area, {})
                if tokens[3] == "interface" and len(tokens) >= 5:
                    iface = tokens[4]
                    ifaces = area_conf.setdefault("interfaces", [])
                    if iface not in ifaces:
                        ifaces.append(iface)
                    print(color("  [设置] OSPF 区域 {} 接口 {}".format(area, iface), C.GREEN))

        elif proto == "bgp" and len(tokens) >= 4:
            # set protocols bgp group <name> type external peer-as <asn>
            # set protocols bgp group <name> neighbor <ip>
            if tokens[1] == "group":
                group_name = tokens[2]
                bgp = protocols.setdefault("bgp", {})
                group = bgp.setdefault(group_name, {})

                if len(tokens) >= 5 and tokens[3] == "type":
                    group["type"] = tokens[4]
                    print(color("  [设置] BGP 组 {} 类型 {}".format(group_name, tokens[4]), C.GREEN))
                elif len(tokens) >= 5 and tokens[3] == "peer-as":
                    group["peer-as"] = tokens[4]
                    print(color("  [设置] BGP 组 {} 对端 AS {}".format(group_name, tokens[4]), C.GREEN))
                elif len(tokens) >= 5 and tokens[3] == "neighbor":
                    neighbors = group.setdefault("neighbors", [])
                    if tokens[4] not in neighbors:
                        neighbors.append(tokens[4])
                    print(color("  [设置] BGP 组 {} 邻居 {}".format(group_name, tokens[4]), C.GREEN))

    def _set_system(self, tokens):
        """处理 set system 子命令"""
        if len(tokens) < 2:
            print(color("用法: set system <services|name-server|root-authentication>", C.YELLOW))
            return

        sub = tokens[0]
        system = self.candidate_config.setdefault("system", {})

        if sub == "services":
            if len(tokens) >= 2:
                svc_name = tokens[1]
                services = system.setdefault("services", {})
                services[svc_name] = True
                print(color("  [设置] 系统服务 {} 已启用".format(svc_name), C.GREEN))

        elif sub == "name-server" and len(tokens) >= 2:
            ns = tokens[1]
            name_servers = system.setdefault("name-server", [])
            if ns not in name_servers:
                name_servers.append(ns)
            print(color("  [设置] DNS 服务器 {}".format(ns), C.GREEN))

        elif sub == "root-authentication":
            if len(tokens) >= 2 and tokens[1] == "plain-text-password":
                print(color("  请输入新密码:", C.YELLOW))
                try:
                    pwd = getpass.getpass("  密码: ")
                    pwd2 = getpass.getpass("  确认密码: ")
                    if pwd != pwd2:
                        print(color("  错误: 两次密码不匹配", C.RED))
                        return
                    hashed = hashlib.sha256(pwd.encode()).hexdigest()
                    system["root-authentication"] = {"hashed-password": hashed}
                    print(color("  [设置] root 密码已更新", C.GREEN))
                except (EOFError, KeyboardInterrupt):
                    print(color("\n  密码设置已取消", C.YELLOW))

    # ---- delete 命令 ----

    def do_delete(self, line):
        """
        删除配置参数
        用法: delete <配置路径>
        示例:
          delete security zones security-zone trust
          delete interfaces eth0
        """
        tokens = line.strip().split()
        if not tokens:
            print(color("用法: delete <配置路径>", C.YELLOW))
            return

        self._apply_delete(tokens)

    def _apply_delete(self, tokens):
        """
        将 delete 命令的 token 列表应用到候选配置

        Args:
            tokens: delete 命令后的 token 列表
        """
        if len(tokens) < 2:
            print(color("错误: 删除路径过短", C.RED))
            return

        category = tokens[0]

        try:
            if category == "security":
                self._delete_security(tokens[1:])
            elif category == "interfaces":
                self._delete_interface(tokens[1:])
            elif category == "routing-options":
                self._delete_routing(tokens[1:])
            elif category == "protocols":
                self._delete_protocols(tokens[1:])
            elif category == "system":
                self._delete_system(tokens[1:])
            else:
                print(color("错误: 未知的配置类别 '{}'".format(category), C.RED))
        except (IndexError, KeyError) as e:
            print(color("错误: 参数不足或格式错误 - {}".format(e), C.RED))

    def _delete_security(self, tokens):
        """处理 delete security 子命令"""
        if not tokens:
            return

        sub = tokens[0]
        security = self.candidate_config.get("security", {})

        if sub == "zones" and len(tokens) >= 4 and tokens[1] == "security-zone":
            zone_name = tokens[2]
            zones = security.get("zones", {})
            if zone_name in zones:
                if len(tokens) >= 5:
                    action = tokens[3]
                    if action == "address-book" and len(tokens) >= 6 and tokens[4] == "address":
                        addr_name = tokens[5]
                        ab = zones[zone_name].get("address-book", {})
                        if addr_name in ab:
                            del ab[addr_name]
                            print(color("  [删除] 区域 {} 地址簿 {}".format(zone_name, addr_name), C.YELLOW))
                    elif action == "interfaces":
                        iface = tokens[4]
                        ifaces = zones[zone_name].get("interfaces", [])
                        if iface in ifaces:
                            ifaces.remove(iface)
                            print(color("  [删除] 区域 {} 接口 {}".format(zone_name, iface), C.YELLOW))
                else:
                    del zones[zone_name]
                    print(color("  [删除] 区域 {}".format(zone_name), C.YELLOW))
            else:
                print(color("  警告: 区域 {} 不存在".format(zone_name), C.YELLOW))

        elif sub == "policies" and len(tokens) >= 7:
            if tokens[1] == "from-zone" and tokens[3] == "to-zone" and tokens[5] == "policy":
                from_zone = tokens[2]
                to_zone = tokens[4]
                pol_name = tokens[6]
                policies = security.get("policies", {})
                if from_zone in policies and to_zone in policies[from_zone]:
                    if pol_name in policies[from_zone][to_zone]:
                        del policies[from_zone][to_zone][pol_name]
                        print(color("  [删除] 策略 {} -> {} {}".format(from_zone, to_zone, pol_name), C.YELLOW))

        elif sub == "address-book" and len(tokens) >= 5:
            if tokens[1] == "global" and tokens[2] == "address":
                addr_name = tokens[3]
                ab = security.get("address-book", {}).get("global", {})
                if addr_name in ab:
                    del ab[addr_name]
                    print(color("  [删除] 全局地址簿 {}".format(addr_name), C.YELLOW))

        elif sub == "nat" and len(tokens) >= 4:
            if tokens[1] == "source" and tokens[2] == "rule-set":
                rs_name = tokens[3]
                nat = security.get("nat", {}).get("source", {})
                if rs_name in nat:
                    del nat[rs_name]
                    print(color("  [删除] NAT 规则集 {}".format(rs_name), C.YELLOW))

        elif sub == "ipsec" and len(tokens) >= 3:
            if tokens[1] == "vpn":
                vpn_name = tokens[2]
                ipsec = security.get("ipsec", {})
                if vpn_name in ipsec:
                    del ipsec[vpn_name]
                    print(color("  [删除] IPSec VPN {}".format(vpn_name), C.YELLOW))

        elif sub == "ike" and len(tokens) >= 3:
            if tokens[1] == "gateway":
                gw_name = tokens[2]
                ike = security.get("ike", {}).get("gateway", {})
                if gw_name in ike:
                    del ike[gw_name]
                    print(color("  [删除] IKE 网关 {}".format(gw_name), C.YELLOW))

    def _delete_interface(self, tokens):
        """处理 delete interfaces 子命令"""
        if not tokens:
            return
        iface_name = tokens[0]
        interfaces = self.candidate_config.get("interfaces", {})
        if iface_name in interfaces:
            del interfaces[iface_name]
            print(color("  [删除] 接口 {}".format(iface_name), C.YELLOW))

    def _delete_routing(self, tokens):
        """处理 delete routing-options 子命令"""
        if len(tokens) >= 3 and tokens[0] == "static" and tokens[1] == "route":
            dest = tokens[2]
            static = self.candidate_config.get("routing-options", {}).get("static", {})
            if dest in static:
                del static[dest]
                print(color("  [删除] 静态路由 {}".format(dest), C.YELLOW))

    def _delete_protocols(self, tokens):
        """处理 delete protocols 子命令"""
        if len(tokens) >= 2:
            proto = tokens[0]
            protocols = self.candidate_config.get("protocols", {})
            if proto == "ospf" and len(tokens) >= 3:
                area = tokens[1]
                ospf = protocols.get("ospf", {})
                if area in ospf:
                    if len(tokens) >= 5 and tokens[2] == "interface":
                        iface = tokens[3]
                        ifaces = ospf[area].get("interfaces", [])
                        if iface in ifaces:
                            ifaces.remove(iface)
                            print(color("  [删除] OSPF 区域 {} 接口 {}".format(area, iface), C.YELLOW))
                    else:
                        del ospf[area]
                        print(color("  [删除] OSPF 区域 {}".format(area), C.YELLOW))
            elif proto == "bgp" and len(tokens) >= 3:
                group_name = tokens[1]
                bgp = protocols.get("bgp", {})
                if group_name in bgp:
                    del bgp[group_name]
                    print(color("  [删除] BGP 组 {}".format(group_name), C.YELLOW))

    def _delete_system(self, tokens):
        """处理 delete system 子命令"""
        if not tokens:
            return
        sub = tokens[0]
        system = self.candidate_config.get("system", {})

        if sub == "services" and len(tokens) >= 2:
            svc_name = tokens[1]
            services = system.get("services", {})
            if svc_name in services:
                del services[svc_name]
                print(color("  [删除] 系统服务 {}".format(svc_name), C.YELLOW))

        elif sub == "name-server" and len(tokens) >= 2:
            ns = tokens[1]
            name_servers = system.get("name-server", [])
            if ns in name_servers:
                name_servers.remove(ns)
                print(color("  [删除] DNS 服务器 {}".format(ns), C.YELLOW))

    # ---- show 命令 (配置模式) ----

    def do_show(self, line):
        """
        显示配置信息
        用法: show | compare
              show | display set
        """
        args = line.strip()

        if "| compare" in args:
            self._show_compare()
        elif "| display set" in args:
            self._show_display_set()
        elif not args or args == "configuration":
            print(color("\n候选配置:", C.BOLD))
            print(color("─" * 50, C.CYAN))
            print(color(json.dumps(self.candidate_config, indent=2, ensure_ascii=False), C.CYAN))
            print()
        else:
            print(color("  用法: show | compare  或  show | display set", C.YELLOW))

    def complete_show(self, text, line, begidx, endidx):
        """show 命令补全"""
        options = ["| compare", "| display set", "configuration"]
        if not text:
            return options
        return [o for o in options if o.startswith(text)]

    def _show_compare(self):
        """显示候选配置与运行配置的差异"""
        diffs = dict_diff(self.running_config, self.candidate_config)
        if not diffs:
            print(color("\n  [候选配置与运行配置相同]", C.GREEN))
            return

        print(color("\n配置差异:", C.BOLD))
        print(color("─" * 50, C.CYAN))
        for d in diffs:
            print("  {}".format(d))
        print()

    def _show_display_set(self):
        """以 set 命令格式显示候选配置"""
        commands = config_to_set_commands(self.candidate_config)
        if not commands:
            print(color("\n  [候选配置为空]", C.YELLOW))
            return

        print(color("\n候选配置 (set 命令格式):", C.BOLD))
        print(color("─" * 50, C.CYAN))
        for cmd in commands:
            print("  {}".format(color(cmd, C.CYAN)))
        print()

    # ---- commit 命令 ----

    def do_commit(self, line):
        """
        提交候选配置到运行配置
        用法: commit [check]
        """
        args = line.strip().split()
        check_only = "check" in args

        if check_only:
            self._commit_check()
        else:
            self._commit_apply()

    def complete_commit(self, text, line, begidx, endidx):
        """commit 命令补全"""
        return ["check"]

    def _commit_check(self):
        """验证候选配置但不应用"""
        print(color("\n配置验证:", C.BOLD))
        print(color("─" * 40, C.CYAN))

        errors = self._validate_config()
        if errors:
            for err in errors:
                print(color("  错误: {}".format(err), C.RED))
            print(color("\n  配置验证失败!", C.RED))
        else:
            print(color("  配置验证通过", C.GREEN))
        print()

    def _validate_config(self):
        """
        验证候选配置

        Returns:
            错误消息列表
        """
        errors = []

        # 验证接口地址格式
        interfaces = self.candidate_config.get("interfaces", {})
        for iname, iconf in interfaces.items():
            for unit, uconf in iconf.get("unit", {}).items():
                addr = uconf.get("family", {}).get("inet", {}).get("address", "")
                if addr and "/" not in addr:
                    errors.append("接口 {} 单元 {} 地址缺少前缀长度: {}".format(iname, unit, addr))

        # 验证静态路由
        static = self.candidate_config.get("routing-options", {}).get("static", {})
        for dest, route_conf in static.items():
            if "/" not in dest:
                errors.append("静态路由目标缺少前缀长度: {}".format(dest))
            if "next-hop" not in route_conf:
                errors.append("静态路由 {} 缺少下一跳".format(dest))

        # 验证策略
        policies = self.candidate_config.get("security", {}).get("policies", {})
        for fz, tz_dict in policies.items():
            for tz, pols in tz_dict.items():
                for pname, pconf in pols.items():
                    if "then" not in pconf:
                        errors.append("策略 {} -> {} {} 缺少动作 (then permit/deny/reject)".format(fz, tz, pname))

        return errors

    def _commit_apply(self):
        """将候选配置应用到运行配置并执行系统命令"""
        print(color("\n提交配置:", C.BOLD))
        print(color("─" * 40, C.CYAN))

        # 验证
        errors = self._validate_config()
        if errors:
            for err in errors:
                print(color("  错误: {}".format(err), C.RED))
            print(color("\n  提交失败: 配置验证未通过!", C.RED))
            return

        # 保存回滚点
        self._save_rollback()

        # 执行系统命令
        print(color("  正在应用配置...", C.CYAN))
        apply_errors = self._apply_to_system()

        if apply_errors:
            for err in apply_errors:
                print(color("  警告: {}".format(err), C.YELLOW))
            print(color("\n  配置已保存，但部分系统命令执行失败", C.YELLOW))
        else:
            print(color("  配置已成功应用", C.GREEN))

        # 更新运行配置
        self.running_config = copy.deepcopy(self.candidate_config)
        save_config(RUNNING_CONFIG_FILE, self.running_config)
        save_config(CANDIDATE_CONFIG_FILE, self.candidate_config)

        print(color("  提交完成", C.GREEN))
        print()

    def _save_rollback(self):
        """保存当前运行配置作为回滚点"""
        ensure_config_dir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rollback_file = os.path.join(ROLLBACK_DIR, "rollback_{}.json".format(timestamp))
        save_config(rollback_file, self.running_config)
        logger.info("回滚点已保存: %s", rollback_file)

    def _apply_to_system(self):
        """
        将候选配置转换为系统命令并执行

        Returns:
            错误消息列表
        """
        errors = []

        # 应用接口配置
        errors.extend(self._apply_interfaces())

        # 应用防火墙规则 (区域 -> iptables)
        errors.extend(self._apply_zones())

        # 应用安全策略
        errors.extend(self._apply_policies())

        # 应用 NAT 规则
        errors.extend(self._apply_nat())

        # 应用静态路由
        errors.extend(self._apply_static_routes())

        # 应用 OSPF
        errors.extend(self._apply_ospf())

        # 应用 BGP
        errors.extend(self._apply_bgp())

        # 应用系统服务
        errors.extend(self._apply_system_services())

        return errors

    def _apply_interfaces(self):
        """应用接口配置到系统"""
        errors = []
        interfaces = self.candidate_config.get("interfaces", {})

        for iname, iconf in interfaces.items():
            for unit, uconf in iconf.get("unit", {}).items():
                inet = uconf.get("family", {}).get("inet", {})
                addr = inet.get("address", "")
                is_dhcp = inet.get("dhcp", False)

                # 启用接口
                result = run_cmd(["ip", "link", "set", iname, "up"])
                if result.returncode != 0:
                    errors.append("无法启用接口 {}: {}".format(iname, result.stderr))
                    continue

                if addr:
                    # 添加 IP 地址
                    result = run_cmd(["ip", "addr", "add", addr, "dev", iname])
                    if result.returncode != 0:
                        errors.append("无法添加地址 {} 到 {}: {}".format(addr, iname, result.stderr))

                if is_dhcp:
                    # 启动 DHCP 客户端
                    result = run_cmd(["dhclient", "-1", iname], check=False)
                    if result.returncode != 0:
                        errors.append("DHCP 客户端启动失败 {}: {}".format(iname, result.stderr))

        return errors

    def _apply_zones(self):
        """应用安全区域到 iptables"""
        errors = []
        zones = self.candidate_config.get("security", {}).get("zones", {})

        for zname, zconf in zones.items():
            chain_name = "GK_ZONE_{}".format(zname.upper())

            # 创建区域链
            result = run_cmd([
                "iptables", "-N", chain_name
            ], check=False)
            # 忽略已存在的错误
            if result.returncode != 0 and "already exists" not in (result.stderr or ""):
                errors.append("无法创建 iptables 链 {}: {}".format(chain_name, result.stderr))

            # 将区域接口的流量导入区域链
            for iface in zconf.get("interfaces", []):
                run_cmd([
                    "iptables", "-A", "INPUT", "-i", iface, "-j", chain_name
                ], check=False)
                run_cmd([
                    "iptables", "-A", "FORWARD", "-i", iface, "-j", chain_name
                ], check=False)

        return errors

    def _apply_policies(self):
        """应用安全策略到 iptables"""
        errors = []
        policies = self.candidate_config.get("security", {}).get("policies", {})

        for from_zone, to_zones in policies.items():
            for to_zone, pols in to_zones.items():
                for pname, pconf in pols.items():
                    match = pconf.get("match", {})
                    then = pconf.get("then", "deny")

                    src_addr = match.get("source-address", "0.0.0.0/0")
                    dst_addr = match.get("destination-address", "0.0.0.0/0")

                    chain_name = "GK_ZONE_{}".format(from_zone.upper())
                    action = "ACCEPT" if then == "permit" else "DROP"

                    result = run_cmd([
                        "iptables", "-A", chain_name,
                        "-s", src_addr, "-d", dst_addr,
                        "-j", action
                    ], check=False)
                    if result.returncode != 0:
                        errors.append("无法应用策略 {} -> {} {}: {}".format(
                            from_zone, to_zone, pname, result.stderr))

        return errors

    def _apply_nat(self):
        """应用 NAT 规则到 iptables"""
        errors = []
        nat = self.candidate_config.get("security", {}).get("nat", {}).get("source", {})

        for rs_name, rs_conf in nat.items():
            rules = rs_conf.get("rule", {})
            for rnum, rconf in rules.items():
                src_addr = rconf.get("match", {}).get("source-address", "0.0.0.0/0")
                nat_action = rconf.get("then", {}).get("source-nat", "off")

                if nat_action == "interface":
                    # MASQUERADE
                    result = run_cmd([
                        "iptables", "-t", "nat", "-A", "POSTROUTING",
                        "-s", src_addr, "-j", "MASQUERADE"
                    ], check=False)
                    if result.returncode != 0:
                        errors.append("无法应用 NAT 规则 {}: {}".format(rnum, result.stderr))
                elif nat_action == "off":
                    # 不做 NAT，跳过
                    pass

        return errors

    def _apply_static_routes(self):
        """应用静态路由到系统"""
        errors = []
        static = self.candidate_config.get("routing-options", {}).get("static", {})

        for dest, route_conf in static.items():
            gw = route_conf.get("next-hop", "")
            if not gw:
                continue

            result = run_cmd(["ip", "route", "add", dest, "via", gw], check=False)
            if result.returncode != 0:
                # 路由可能已存在，尝试替换
                result2 = run_cmd(["ip", "route", "replace", dest, "via", gw], check=False)
                if result2.returncode != 0:
                    errors.append("无法添加路由 {} via {}: {}".format(dest, gw, result2.stderr))

        return errors

    def _apply_ospf(self):
        """应用 OSPF 配置到 FRRouting"""
        errors = []
        ospf = self.candidate_config.get("protocols", {}).get("ospf", {})

        if not ospf:
            return errors

        # 构建 vtysh 命令
        vtysh_cmds = ["router ospf\n"]
        for area, area_conf in ospf.items():
            vtysh_cmds.append(" network {} area {}\n".format(
                "0.0.0.0/0", area
            ))
            for iface in area_conf.get("interfaces", []):
                vtysh_cmds.append(" interface {}\n".format(iface))
        vtysh_cmds.append("!\n")

        vtysh_input = "".join(vtysh_cmds)
        result = run_cmd(["vtysh"], check=False, capture=True)
        if result.returncode != 0:
            errors.append("无法连接 FRRouting vtysh: {}".format(result.stderr))

        return errors

    def _apply_bgp(self):
        """应用 BGP 配置到 FRRouting"""
        errors = []
        bgp = self.candidate_config.get("protocols", {}).get("bgp", {})

        if not bgp:
            return errors

        for group_name, gconf in bgp.items():
            peer_as = gconf.get("peer-as", "")
            gtype = gconf.get("type", "external")
            neighbors = gconf.get("neighbors", [])

            if not peer_as:
                errors.append("BGP 组 {} 缺少 peer-as".format(group_name))
                continue

            for neighbor in neighbors:
                result = run_cmd([
                    "vtysh", "-c",
                    "router bgp {} {}".format(peer_as, gtype),
                    "-c", "neighbor {} remote-as {}".format(neighbor, peer_as)
                ], check=False)
                if result.returncode != 0:
                    errors.append("BGP 邻居 {} 配置失败: {}".format(neighbor, result.stderr))

        return errors

    def _apply_system_services(self):
        """应用系统服务配置"""
        errors = []
        services = self.candidate_config.get("system", {}).get("services", {})

        if services.get("ssh"):
            result = run_cmd(["systemctl", "enable", "--now", "ssh"], check=False)
            if result.returncode != 0:
                errors.append("无法启用 SSH 服务: {}".format(result.stderr))

        if services.get("dhcp-local-server"):
            result = run_cmd(["systemctl", "enable", "--now", "isc-dhcp-server"], check=False)
            if result.returncode != 0:
                errors.append("无法启用 DHCP 服务: {}".format(result.stderr))

        return errors

    # ---- rollback 命令 ----

    def do_rollback(self, line):
        """
        回退候选配置到之前的提交状态
        用法: rollback [n]  (默认 1)
        """
        args = line.strip().split()
        n = 1
        if args:
            try:
                n = int(args[0])
            except ValueError:
                print(color("错误: 回退编号必须是整数", C.RED))
                return

        # 获取回滚文件列表
        rollback_files = sorted(
            glob.glob(os.path.join(ROLLBACK_DIR, "rollback_*.json")),
            reverse=True
        )

        if not rollback_files:
            print(color("  没有可用的回滚点", C.YELLOW))
            return

        if n < 1 or n > len(rollback_files):
            print(color("  回退编号超出范围 (1-{})".format(len(rollback_files)), C.YELLOW))
            return

        rollback_file = rollback_files[n - 1]
        rollback_config = load_config(rollback_file)

        self.candidate_config = copy.deepcopy(rollback_config)
        print(color("  候选配置已回退到: {}".format(os.path.basename(rollback_file)), C.GREEN))

    def complete_rollback(self, text, line, begidx, endidx):
        """rollback 命令补全"""
        rollback_files = sorted(
            glob.glob(os.path.join(ROLLBACK_DIR, "rollback_*.json")),
            reverse=True
        )
        return [str(i + 1) for i in range(min(len(rollback_files), 10))]

    # ---- run 命令 ----

    def do_run(self, line):
        """
        在配置模式中执行操作模式命令
        用法: run <operational-command>
        """
        if not line.strip():
            print(color("用法: run <操作模式命令>", C.YELLOW))
            return

        # 创建临时操作模式实例执行命令
        ops = OperationalMode(self.running_config)
        ops.onecmd(line.strip())

    def complete_run(self, text, line, begidx, endidx):
        """run 命令补全 - 委托给操作模式补全"""
        ops = OperationalMode(self.running_config)
        run_line = line.replace("run", "", 1).strip()
        if run_line.startswith("show"):
            return ops.complete_show(text.replace("show ", "", 1), run_line, begidx, endidx)
        return []

    # ---- 导航命令 ----

    def do_top(self, line):
        """回到配置层级顶部"""
        self.edit_path = []
        self._update_prompt()
        print(color("  [导航] 回到顶层", C.CYAN))

    def do_up(self, line):
        """回到上一级配置层级"""
        if self.edit_path:
            self.edit_path.pop()
            self._update_prompt()
            print(color("  [导航] 上一级", C.CYAN))
        else:
            print(color("  已在顶层", C.YELLOW))

    # ---- 退出 ----

    def do_exit(self, line):
        """退出配置模式"""
        if self._has_uncommitted_changes():
            print(color("\n  警告: 存在未提交的更改!", C.YELLOW))
            print(color("  输入 'commit' 提交更改，或再次输入 'exit' 放弃更改退出", C.YELLOW))
            # 标记有未提交更改
            if not hasattr(self, '_exit_confirmed'):
                self._exit_confirmed = True
                return False
            else:
                # 第二次确认退出
                self._exit_confirmed = False
                print(color("\n  未提交的更改已放弃", C.YELLOW))
        return True

    def do_quit(self, line):
        """退出配置模式"""
        return self.do_exit(line)

    def _has_uncommitted_changes(self):
        """
        检查是否有未提交的更改

        Returns:
            是否有更改
        """
        return self.running_config != self.candidate_config

    # ---- 帮助 ----

    def do_help(self, line):
        """显示帮助信息"""
        print(color("\nGateKeeper Junos CLI - 配置模式", C.BOLD))
        print(color("─" * 55, C.CYAN))
        print(color("  配置命令:", C.BOLD))
        print("    set <配置路径>                       设置配置参数")
        print("    delete <配置路径>                    删除配置参数")
        print()
        print(color("  显示命令:", C.BOLD))
        print("    show | compare                      比较候选与运行配置")
        print("    show | display set                  以 set 命令格式显示候选配置")
        print("    show                                显示候选配置")
        print()
        print(color("  提交与回退:", C.BOLD))
        print("    commit                              应用候选配置到系统")
        print("    commit check                        验证候选配置")
        print("    rollback [n]                        回退到之前的提交 (默认 1)")
        print()
        print(color("  导航:", C.BOLD))
        print("    top                                 回到配置层级顶部")
        print("    up                                  回到上一级")
        print()
        print(color("  其他:", C.BOLD))
        print("    run <操作命令>                       执行操作模式命令")
        print("    exit / quit                         退出配置模式")
        print("    ? / help                            显示帮助")
        print()
        print(color("  set 命令示例:", C.BOLD))
        print("    set security zones security-zone trust interfaces eth0")
        print("    set security policies from-zone trust to-zone untrust policy P1 \\")
        print("        match source-address any destination-address any application any \\")
        print("        then permit")
        print("    set interfaces eth0 unit 0 family inet address 192.168.1.1/24")
        print("    set routing-options static route 0.0.0.0/0 next-hop 10.0.0.1")
        print("    set system services ssh")
        print()


# ============================================================
# 主入口
# ============================================================

def main():
    """主入口函数 - 启动 Junos CLI"""
    try:
        from config.settings import Settings
        gk_version = Settings().version
    except Exception:
        gk_version = "1.0.4"
    print(color("╔══════════════════════════════════════════════╗", C.CYAN))
    print(color("║     GateKeeper Junos CLI v{}        ║".format(gk_version), C.CYAN))
    print(color("║     网络安全设备管理界面                    ║", C.CYAN))
    print(color("╚══════════════════════════════════════════════╝", C.CYAN))

    # 确保配置目录存在
    ensure_config_dir()

    # 加载或初始化运行配置
    if os.path.exists(RUNNING_CONFIG_FILE):
        running_config = load_config(RUNNING_CONFIG_FILE)
        logger.info("已加载运行配置: %s", RUNNING_CONFIG_FILE)
    else:
        running_config = _default_config()
        save_config(RUNNING_CONFIG_FILE, running_config)
        logger.info("已创建默认运行配置: %s", RUNNING_CONFIG_FILE)

    # 加载候选配置
    if os.path.exists(CANDIDATE_CONFIG_FILE):
        candidate = load_config(CANDIDATE_CONFIG_FILE)
        if candidate != running_config:
            logger.warning("检测到未提交的候选配置")

    # 启动操作模式
    try:
        cli = OperationalMode(running_config)
        cli.cmdloop()
    except KeyboardInterrupt:
        print(color("\n\n收到中断信号，正在退出...", C.YELLOW))
    finally:
        print(color("\nGateKeeper Junos CLI 已退出", C.CYAN))


if __name__ == "__main__":
    main()
