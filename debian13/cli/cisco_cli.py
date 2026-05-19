"""
GateKeeper - 交互式命令行界面
基于 cmd.Cmd 实现，支持 Tab 补全、命令缩写、历史记录和彩色输出。
执行实际系统命令，而非模拟配置。
"""
import cmd, os, sys, readline, platform, socket, subprocess, time, json
from datetime import datetime

class C:
    """ANSI 颜色常量"""
    RESET = "\033[0m"; BOLD = "\033[1m"; RED = "\033[31m"
    GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"
    MAGENTA = "\033[35m"; CYAN = "\033[36m"

def color(text, c):
    return "{}{}{}".format(c, text, C.RESET)

def bold(text):
    return color(text, C.BOLD)

# 命令缩写映射
ABBREVS = {
    "sh": "show", "sho": "show", "conf": "configure", "con": "configure",
    "int": "interface", "ex": "exit", "exi": "exit", "h": "help",
    "hel": "help", "pin": "ping", "tra": "traceroute", "deb": "debug",
    "wr": "write", "rel": "reload", "host": "hostname", "hostn": "hostname",
    "ena": "enable", "acc": "access-list", "lin": "line",
    "ser": "service", "des": "description", "desc": "description",
    "spe": "speed", "dup": "duplex", "per": "permit", "den": "deny",
    "rem": "remark", "run": "running-config", "sta": "startup-config",
    "clk": "clock", "usr": "users", "ter": "terminal", "mem": "memory",
    "br": "brief", "bro": "brief", "ro": "route", "rou": "route",
    "ver": "version", "nam": "name-server", "name": "name-server",
    "star": "startup-config", "runn": "running-config",
    "pass": "password", "pas": "password",
    "t": "terminal",
}

def expand_cmd(text):
    t = text.strip().lower()
    if t in ABBREVS:
        return ABBREVS[t]
    for abbr, full in ABBREVS.items():
        if t.startswith(abbr) and len(t) >= min(len(abbr), 3):
            return full
    return t

_EXPAND2 = {"configure", "show", "ip", "no", "line", "write", "debug"}

# 配置文件路径
CONFIG_FILE = "/etc/gatekeeper/cisco_config.json"

def run_cmd(cmd_list, check=True, capture=True):
    """执行系统命令并返回结果"""
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=capture,
            text=True,
            check=check,
            timeout=30
        )
        return result
    except subprocess.CalledProcessError as e:
        return e
    except Exception as e:
        class FakeResult:
            def __init__(self, err):
                self.returncode = 1
                self.stderr = str(err)
                self.stdout = ""
        return FakeResult(e)

class CiscoCLI(cmd.Cmd):
    """GateKeeper交互式命令行界面 - 执行实际系统配置"""
    intro = ""
    MODE_HELP = {
        "user": "\n  用户模式 (Router>):\n"
            "  show version/interfaces/ip route/ip interface brief/running-config/clock/users\n"
            "  ping <host>  traceroute <host>  enable  exit  ?\n",
        "priv": "\n  特权模式 (Router#):\n"
            "  configure terminal  write memory  reload  disable  start shell\n"
            "  show running-config/startup-config/version/interfaces/ip route/ip interface brief/clock/users\n"
            "  ping <host>  traceroute <host>  debug/undebug <flag>  exit  ?\n",
        "config": "\n  全局配置 (Router(config)#):\n"
            "  hostname <name>  enable password <pwd>  interface <name>\n"
            "  ip route <dest> <mask> <gw>  ip name-server <ip>\n"
            "  access-list <num> standard  line console/vty  service <name>\n"
            "  no shutdown/ip route/access-list/hostname  end  exit  ?\n",
        "config_if": "\n  接口配置 (Router(config-if)#):\n"
            "  ip address <ip> <mask>/dhcp  no shutdown  shutdown\n"
            "  description <text>  speed <10/100/1000/auto>  duplex <half/full/auto>  mtu <68-9000>\n"
            "  end  exit  ?\n",
        "config_acl": "\n  ACL配置 (Router(config-std-nacl)#):\n"
            "  permit <source>  deny <source>  remark <text>  end  exit  ?\n",
    }

    def __init__(self, net_mgr=None, fw_mgr=None):
        super().__init__()
        self.hostname = self._get_system_hostname()
        self.enable_password = ""
        self.mode = "user"
        self.cur_if = ""
        self.cur_acl = ""
        self.net_mgr = net_mgr
        self.fw_mgr = fw_mgr
        self._hist = os.path.expanduser("~/.gatekeeper_cisco_cli_history")
        try:
            if os.path.exists(self._hist):
                readline.read_history_file(self._hist)
            readline.set_history_length(500)
        except Exception:
            pass
        print(color("\n  ================================================", C.CYAN))
        try:
            from config.settings import Settings
            gk_version = Settings().version
        except Exception:
            gk_version = "1.0.4"
        print(color("    GateKeeper v{}".format(gk_version), C.CYAN))
        print(color("    AI 安全网络防御系统", C.CYAN))
        print(color("  ================================================", C.CYAN))
        print("  输入 {} 查看可用命令, {} 进入特权模式\n".format(bold("?"), bold("enable")))

    def _get_system_hostname(self):
        """获取系统主机名"""
        try:
            result = run_cmd(["hostname"], check=False)
            return result.stdout.strip() if result.returncode == 0 else "Router"
        except:
            return "Router"

    @property
    def prompt(self):
        m = {"user": (">", C.CYAN), "priv": ("#", C.GREEN),
             "config": ("(config)#", C.YELLOW),
             "config_if": ("(config-if)#", C.MAGENTA),
             "config_acl": ("(config-std-nacl)#", C.MAGENTA)}
        suffix, clr = m.get(self.mode, (">", C.CYAN))
        return color("{}{}".format(self.hostname, suffix), clr) + " "

    def precmd(self, line):
        line = line.strip()
        if not line:
            return ""
        if line == "?":
            return "help"
        ll = line.lower()
        if ll.startswith("enable password"):
            return "_enable_password " + line[len("enable password"):].strip()
        if ll.startswith("access-list"):
            return "access_list " + line[len("access-list"):].strip()
        if ll.startswith("no "):
            rest = line[3:].strip()
            if rest.lower().startswith("access-list"):
                return "no _access_list " + rest[len("access-list"):].strip()
        if ll.startswith("ip address") and self.mode == "config_if":
            return "ip_address " + line[len("ip address"):].strip()
        parts = line.split()
        if parts:
            parts[0] = expand_cmd(parts[0])
            if parts[0] in _EXPAND2 and len(parts) > 1:
                parts[1] = expand_cmd(parts[1])
            for i in range(2, len(parts)):
                parts[i] = expand_cmd(parts[i])
        return " ".join(parts)

    def default(self, line):
        print(color('% 未识别的命令: "{}"  输入 "?" 查看帮助'.format(line), C.RED))

    def emptyline(self):
        pass

    def do_help(self, arg):
        print(color(self.MODE_HELP.get(self.mode, ""), C.BOLD))

    # ---- 模式切换 ----
    def do_enable(self, arg):
        if self.enable_password:
            if input("密码: ") != self.enable_password:
                print(color("% 密码错误", C.RED)); return
        self.mode = "priv"
        print(color("已进入特权模式", C.GREEN))

    def do_disable(self, arg):
        if self.mode in ("config", "config_if", "config_acl"):
            self.mode = "priv"; self.cur_if = ""; self.cur_acl = ""
        elif self.mode == "priv":
            self.mode = "user"
        print(color("已返回用户模式", C.GREEN))

    def do_exit(self, arg):
        if self.mode in ("config", "config_if", "config_acl"):
            self.mode = "priv" if self.mode == "config" else "config"
            self.cur_if = ""; self.cur_acl = ""
            return False
        elif self.mode == "priv":
            self.mode = "user"; return False
        self._save_hist()
        print(color("\n再见!", C.CYAN)); return True

    def do_end(self, arg):
        self.mode = "priv"; self.cur_if = ""; self.cur_acl = ""
        print(color("已返回特权模式", C.GREEN)); return False

    def _save_hist(self):
        try:
            readline.write_history_file(self._hist)
        except Exception:
            pass

    # ---- show 命令 ----
    def do_show(self, arg):
        parts = arg.strip().split()
        if not parts:
            print(color("% show 需要参数", C.RED)); return
        sub = parts[0].lower()
        rest = " ".join(parts[1:])
        show_map = {
            "version": self._show_ver, "interfaces": self._show_int,
            "ip": self._show_ip, "running-config": self._show_run,
            "startup-config": self._show_start, "clock": self._show_clk,
            "users": self._show_users, "audit": self._show_audit,
            "ddos": self._show_ddos,
            "waf": self._show_waf,
            "vulnerability": self._show_vuln,
            "honeypot": self._show_honeypot,
            "two-factor": self._show_two_factor,
        }
        fn = show_map.get(sub)
        if fn:
            fn(rest)
        else:
            print(color("% 未知 show 子命令: {}".format(sub), C.RED))

    def _show_ver(self, _):
        print(color("\nGateKeeper 防火墙系统", C.BOLD))
        print(color("─" * 50, C.CYAN))

        # 主机名
        print("  主机名:              {}".format(self.hostname))

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
        print("  内核:                {} {}".format(platform.system(), platform.release()))
        print("  架构:                {}".format(platform.machine()))
        print("  Python:              {}".format(platform.python_version()))

        # 运行时间
        try:
            with open("/proc/uptime", "r") as f:
                uptime = float(f.read().split()[0])
                days = int(uptime / 86400)
                hours = int((uptime % 86400) / 3600)
                mins = int((uptime % 3600) / 60)
                print("  运行时间:            {}天 {}小时 {}分钟".format(days, hours, mins))
        except Exception:
            print("  运行时间:            未知")

        # 管理器状态
        if self.net_mgr:
            print("  网络管理:            已集成")
        if self.fw_mgr:
            print("  防火墙:              已集成")

        print()

    def _show_int(self, _):
        print(color("\n接口状态:", C.BOLD))
        print("  {:<12} {:<18} {:<8} {:<6} {}".format("名称", "IP地址", "状态", "MTU", "描述"))
        print("  " + "-" * 70)
        try:
            result = run_cmd(["ip", "-json", "addr", "show"], check=False)
            if result.returncode == 0:
                import json
                interfaces = json.loads(result.stdout)
                for iface in interfaces:
                    name = iface.get("ifname", "unknown")
                    state = iface.get("operstate", "unknown").lower()
                    status = color("up", C.GREEN) if state == "up" else color("down", C.RED)
                    mtu = iface.get("mtu", "-")
                    # 获取IP地址
                    ip_addr = "未分配"
                    addr_info = iface.get("addr_info", [])
                    for addr in addr_info:
                        if addr.get("family") == "inet":
                            ip_addr = "{}/{}".format(addr.get("local", ""), addr.get("prefixlen", ""))
                            break
                    # 获取描述
                    desc = ""
                    try:
                        with open("/sys/class/net/{}/ifalias".format(name), "r") as f:
                            desc = f.read().strip()
                    except:
                        pass
                    print("  {:<12} {:<18} {:<8} {:<6} {}".format(name, ip_addr, status, mtu, desc))
        except Exception as e:
            print("  获取接口失败: {}".format(e))
        print()

    def _show_ip(self, rest):
        parts = rest.strip().split()
        if not parts:
            print(color("% show ip 需要子命令 (route / interface brief)", C.RED)); return
        if parts[0].lower() == "route":
            self._show_ip_route()
        elif parts[0].lower() == "interface":
            self._show_ip_brief()

    def _show_ip_route(self):
        print(color("\n路由表:", C.BOLD))
        print("  {:<20} {:<18} {:<12} {}".format("目标网络", "网关", "接口", "协议"))
        print("  " + "-" * 60)
        try:
            result = run_cmd(["ip", "route", "show"], check=False)
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.strip():
                        parts = line.split()
                        dest = parts[0] if parts else "default"
                        gateway = "-"
                        iface = "-"
                        proto = "-"
                        for i, p in enumerate(parts):
                            if p == "via" and i + 1 < len(parts):
                                gateway = parts[i + 1]
                            elif p == "dev" and i + 1 < len(parts):
                                iface = parts[i + 1]
                            elif p == "proto" and i + 1 < len(parts):
                                proto = parts[i + 1]
                        print("  {:<20} {:<18} {:<12} {}".format(dest, gateway, iface, proto))
        except Exception as e:
            print("  获取路由失败: {}".format(e))
        print()

    def _show_ip_brief(self):
        print(color("\n接口              IP地址            状态    协议", C.BOLD))
        print("  " + "-" * 55)
        try:
            result = run_cmd(["ip", "-json", "addr", "show"], check=False)
            if result.returncode == 0:
                import json
                interfaces = json.loads(result.stdout)
                for iface in interfaces:
                    name = iface.get("ifname", "unknown")
                    state = iface.get("operstate", "unknown").lower()
                    status = color("up", C.GREEN) if state == "up" else color("down", C.RED)
                    ip_addr = "未分配"
                    addr_info = iface.get("addr_info", [])
                    for addr in addr_info:
                        if addr.get("family") == "inet":
                            ip_addr = "{}/{}".format(addr.get("local", ""), addr.get("prefixlen", ""))
                            break
                    print("  {:<17} {:<18} {:<7} {}".format(name, ip_addr, status, status))
        except Exception as e:
            print("  获取接口失败: {}".format(e))
        print()

    def _show_run(self, _):
        print(color("\n! 当前运行配置", C.YELLOW))
        print("! 主机名: {}".format(self.hostname))
        print("! 系统时间: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        print("!")
        # 显示接口配置
        try:
            result = run_cmd(["ip", "-json", "addr", "show"], check=False)
            if result.returncode == 0:
                import json
                interfaces = json.loads(result.stdout)
                for iface in interfaces:
                    name = iface.get("ifname", "unknown")
                    print("interface {}".format(name))
                    state = iface.get("operstate", "unknown").lower()
                    if state != "up":
                        print(" shutdown")
                    addr_info = iface.get("addr_info", [])
                    for addr in addr_info:
                        if addr.get("family") == "inet":
                            ip = addr.get("local", "")
                            prefix = addr.get("prefixlen", "")
                            # 转换prefix为掩码
                            mask = self._prefix_to_mask(prefix)
                            print(" ip address {} {}".format(ip, mask))
                    mtu = iface.get("mtu")
                    if mtu:
                        print(" mtu {}".format(mtu))
                    print("!")
        except Exception as e:
            print("! 获取接口配置失败: {}".format(e))
        # 显示路由配置
        try:
            result = run_cmd(["ip", "route", "show"], check=False)
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.strip() and "proto static" in line:
                        parts = line.split()
                        dest = parts[0] if parts else "0.0.0.0/0"
                        gateway = ""
                        for i, p in enumerate(parts):
                            if p == "via" and i + 1 < len(parts):
                                gateway = parts[i + 1]
                                break
                        if gateway:
                            print("ip route {} {}".format(dest, gateway))
        except:
            pass
        # 显示DNS配置
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            print("ip name-server {}".format(parts[1]))
        except:
            pass
        print("end")

    def _prefix_to_mask(self, prefix):
        """将前缀长度转换为子网掩码"""
        try:
            p = int(prefix)
            mask = (0xffffffff >> (32 - p)) << (32 - p)
            return "{}.{}.{}.{}".format(
                (mask >> 24) & 0xff,
                (mask >> 16) & 0xff,
                (mask >> 8) & 0xff,
                mask & 0xff
            )
        except:
            return "255.255.255.0"

    def _show_start(self, _):
        print(color("\n! 启动配置 (从 {} 读取)".format(CONFIG_FILE), C.YELLOW))
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    print(f.read())
            else:
                print("! 配置文件不存在，显示当前运行配置")
                self._show_run(_)
        except Exception as e:
            print("! 读取配置失败: {}".format(e))

    def _show_clk(self, _):
        result = run_cmd(["date", "+%Y年%m月%d日 %H:%M:%S %A"], check=False)
        if result.returncode == 0:
            print("  {}".format(result.stdout.strip()))
        else:
            print("  {}".format(datetime.now().strftime("%Y年%m月%d日 %H:%M:%S %A")))

    def _show_users(self, _):
        print(color("\n  线路    用户        主机", C.BOLD))
        print("  " + "-" * 45)
        try:
            result = run_cmd(["who"], check=False)
            if result.returncode == 0:
                for i, line in enumerate(result.stdout.strip().split("\n")):
                    parts = line.split()
                    if len(parts) >= 3:
                        user = parts[0]
                        tty = parts[1]
                        host = parts[2] if len(parts) > 2 else "-"
                        print("  {:<8} {:<10} {}".format(tty, user, host))
        except:
            print("  con 0   admin       console")
        print()

    def _show_audit(self, rest):
        """显示操作审计日志"""
        parts = rest.strip().split()
        count = 20  # 默认显示条数
        source = ""
        username = ""

        if parts:
            for i, p in enumerate(parts):
                if p == "-n" and i + 1 < len(parts):
                    try:
                        count = int(parts[i + 1])
                    except ValueError:
                        pass
                elif p == "-s" and i + 1 < len(parts):
                    source = parts[i + 1]
                elif p == "-u" and i + 1 < len(parts):
                    username = parts[i + 1]

        try:
            from core.audit import get_audit_logger
            al = get_audit_logger()
            data = al.query(
                source=source or None,
                username=username or None,
                page=1,
                page_size=count
            )

            if not data["records"]:
                print(color("  暂无审计日志", C.YELLOW))
                return

            print(color("\n  操作审计日志 (最近{}条)".format(count), C.BOLD))
            print("  " + "-" * 100)
            print("  {:<20} {:<6} {:<10} {:<16} {:<10} {:<30}".format(
                "时间", "来源", "用户", "操作", "模块", "详情"))
            print("  " + "-" * 100)

            for r in data["records"]:
                ts = r["timestamp"][:19] if r["timestamp"] else "-"
                src = color(r["source"].upper(), C.CYAN)
                res = "" if r["result"] == "success" else color(" [失败]", C.RED)
                detail = r["detail"] or ""
                if len(detail) > 28:
                    detail = detail[:28] + ".."
                print("  {:<20} {:<6} {:<10} {:<16} {:<10} {}{}".format(
                    ts, src, r["username"], r["action"],
                    r["module"] or "-", detail, res
                ))

            print("  " + "-" * 100)
            print(color("  共 {} 条记录".format(data["total"]), C.CYAN))
            print()

        except Exception as e:
            print(color("  获取审计日志失败: {}".format(e), C.RED))

    def _show_honeypot(self, rest):
        """显示蜜罐系统状态"""
        parts = rest.strip().split()
        if not parts:
            print(color("% 用法: show honeypot <services|captures|stats>", C.RED))
            return
        action = parts[0].lower()
        try:
            from security.honeypot import get_honeypot_manager
            mgr = get_honeypot_manager()

            if action == "services":
                services = mgr.list_services()
                if not services:
                    print(color("  暂无蜜罐服务", C.YELLOW))
                    return
                print(color("\n  蜜罐服务列表:", C.BOLD))
                print("  " + "-" * 85)
                print("  {:<16} {:<10} {:<8} {:<6} {:<10} {:<10} {:<10}".format(
                    "名称", "类型", "端口", "协议", "状态", "连接数", "最后攻击"))
                print("  " + "-" * 85)
                for s in services:
                    status = color("运行中", C.GREEN) if s["enabled"] else color("已停止", C.RED)
                    last = (s["stats"].get("last_attack") or "-")[:19]
                    print("  {:<16} {:<10} {:<8} {:<6} {:<10} {:<10} {}".format(
                        s["name"], s["service_type"].upper(), s["listen_port"],
                        s["protocol"].upper(), status,
                        s["stats"].get("attacked_count", 0), last))
                print("  " + "-" * 85)
                print(color("  共 {} 个服务".format(len(services)), C.CYAN))
                print()

            elif action == "captures":
                count = 20
                if len(parts) > 1:
                    try:
                        count = int(parts[1])
                    except ValueError:
                        pass
                captures = mgr.get_captures(limit=count)
                if not captures:
                    print(color("  暂无捕获记录", C.YELLOW))
                    return
                print(color("\n  蜜罐捕获记录 (最近{}条)".format(count), C.BOLD))
                print("  " + "-" * 110)
                print("  {:<20} {:<14} {:<16} {:<6} {:<10} {:<10} {}".format(
                    "时间", "服务", "客户端IP", "端口", "协议", "威胁级别", "标签"))
                print("  " + "-" * 110)
                for c in captures:
                    ts = c["timestamp"][:19] if c["timestamp"] else "-"
                    level = c["threat_level"]
                    if level == "critical":
                        level_str = color(level.upper(), C.RED)
                    elif level == "high":
                        level_str = color(level.upper(), C.YELLOW)
                    elif level == "medium":
                        level_str = color(level.upper(), C.YELLOW)
                    else:
                        level_str = color(level.upper(), C.GREEN)
                    print("  {:<20} {:<14} {:<16} {:<6} {:<10} {:<10} {}".format(
                        ts, c["service_name"], c["client_ip"],
                        c["client_port"], c["protocol"].upper(),
                        level_str, c.get("tags", "-")))
                print("  " + "-" * 110)
                print()

            elif action == "stats":
                stats = mgr.get_stats()
                print(color("\n  蜜罐系统统计:", C.BOLD))
                print("  " + "-" * 40)
                print("  总服务数:      {}".format(stats["total_services"]))
                print("  运行中服务:    {}".format(stats["running_services"]))
                print("  总捕获数:      {}".format(stats["total_captures"]))
                print("  总攻击数:      {}".format(stats["total_attacks"]))
                print("  今日捕获:      {}".format(stats["today_captures"]))
                print("  " + "-" * 40)
                td = stats.get("threat_distribution", {})
                print("  威胁级别分布:")
                print("    Low:      {}".format(td.get("low", 0)))
                print("    Medium:   {}".format(td.get("medium", 0)))
                print("    High:     {}".format(td.get("high", 0)))
                print("    Critical: {}".format(td.get("critical", 0)))
                top = stats.get("top_attackers", [])
                if top:
                    print("  " + "-" * 40)
                    print("  Top攻击源IP:")
                    for ip, cnt in top[:5]:
                        print("    {:<20} {} 次".format(ip, cnt))
                print("  " + "-" * 40)
                print()
            else:
                print(color("% 未知参数: {} (可用: services/captures/stats)".format(action), C.RED))
        except Exception as e:
            print(color("  获取蜜罐信息失败: {}".format(e), C.RED))

    def _show_waf(self, rest):
        """显示WAF状态"""
        parts = rest.strip().split()
        if not parts:
            print(color("% 用法: show waf <status|rules|stats>", C.RED))
            return
        action = parts[0].lower()
        try:
            from security.waf_engine import get_waf_engine
            waf = get_waf_engine()
            if action == "status":
                stats = waf.get_stats()
                print(color("\nWAF状态:", C.CYAN))
                print("-" * 40)
                print("  总规则数:    {}".format(stats.get("total_rules", 0)))
                print("  已启用:      {}".format(stats.get("enabled_rules", 0)))
                print("  总检查数:    {}".format(stats.get("total_inspected", 0)))
                print("  拦截次数:    {}".format(stats.get("total_blocked", 0)))
                print("  拦截率:      {}%".format(stats.get("block_rate", 0)))
                print("-" * 40)
            elif action == "rules":
                rules = waf.get_rules()
                print(color("\nWAF规则列表:", C.CYAN))
                print("-" * 80)
                for r in rules:
                    enabled = color("启用", C.GREEN) if r["enabled"] else color("禁用", C.RED)
                    print("  {:<6} {:<20} {:<10} {:<30}".format(r["id"], r["name"], enabled, r.get("description", "")))
                print("-" * 80)
            elif action == "stats":
                stats = waf.get_stats()
                print(color("\nWAF统计:", C.CYAN))
                print("-" * 40)
                print("  总规则数:    {}".format(stats.get("total_rules", 0)))
                print("  已启用:      {}".format(stats.get("enabled_rules", 0)))
                print("  总检查数:    {}".format(stats.get("total_inspected", 0)))
                print("  拦截次数:    {}".format(stats.get("total_blocked", 0)))
                print("  记录次数:    {}".format(stats.get("total_logged", 0)))
                print("  拦截率:      {}%".format(stats.get("block_rate", 0)))
                print("  按类型分布:")
                for k, v in stats.get("by_type", {}).items():
                    print("    {:<20} {}".format(k, v))
                print("  按严重程度分布:")
                for k, v in stats.get("by_severity", {}).items():
                    print("    {:<20} {}".format(k, v))
                print("-" * 40)
            else:
                print(color("% 未知子命令: {}".format(action), C.RED))
        except Exception as e:
            print(color("% 获取WAF信息失败: {}".format(e), C.RED))

    def _show_vuln(self, rest):
        """显示漏洞扫描统计"""
        parts = rest.strip().split()
        action = parts[0].lower() if parts else "stats"

        try:
            from security.vuln_scanner import get_vuln_scanner
            scanner = get_vuln_scanner()

            if action == "stats":
                stats = scanner.get_stats()
                print(color("\n漏洞扫描统计:", C.CYAN))
                print("  " + "-" * 50)
                print("  总扫描次数:      {}".format(stats["total_scans"]))
                print("  发现漏洞总数:    {}".format(stats["total_vulns"]))
                print("  未修复漏洞:      {}".format(stats["unfixed_vulns"]))
                print("  严重漏洞:        {}".format(stats["critical_vulns"]))
                print("  高危漏洞:        {}".format(stats["high_vulns"]))
                print("  " + "-" * 50)
                print(color("  严重度分布:", C.BOLD))
                sev = stats.get("severity_distribution", {})
                sev_names = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
                sev_colors = {"critical": C.RED, "high": C.YELLOW, "medium": C.YELLOW, "low": C.GREEN, "info": C.BLUE}
                for k in ("critical", "high", "medium", "low", "info"):
                    name = sev_names.get(k, k)
                    cnt = sev.get(k, 0)
                    c = sev_colors.get(k, C.RESET)
                    print("    {:<8} {:>6}".format(name, color(str(cnt), c)))
                print("  " + "-" * 50)
                if stats.get("recent_scans"):
                    print(color("  最近扫描:", C.BOLD))
                    for s in stats["recent_scans"]:
                        ts = s["created_at"][:19] if s["created_at"] else "-"
                        status_c = C.GREEN if s["status"] == "completed" else C.RED
                        print("    {} | {:<20} | 漏洞: {} | {}".format(
                            ts, s["target"], s["total_vulns"],
                            color(s["status"], status_c)
                        ))
                print()

            elif action == "history":
                history = scanner.get_scan_history(limit=20)
                if not history:
                    print(color("  暂无扫描历史", C.YELLOW))
                    return
                print(color("\n扫描历史记录:", C.CYAN))
                print("  " + "-" * 90)
                print("  {:<6} {:<20} {:<10} {:<8} {:<8} {:<8} {:<8} {:<20}".format(
                    "ID", "目标", "状态", "总漏洞", "严重", "高危", "中危", "时间"))
                print("  " + "-" * 90)
                for h in history:
                    ts = h["created_at"][:19] if h["created_at"] else "-"
                    status_c = C.GREEN if h["status"] == "completed" else C.RED
                    print("  {:<6} {:<20} {:<10} {:<8} {:<8} {:<8} {:<8} {}".format(
                        h["id"], h["target"][:20], color(h["status"], status_c),
                        h["total_vulns"], h["critical_vulns"], h["high_vulns"],
                        h["medium_vulns"], ts
                    ))
                print("  " + "-" * 90)
                print(color("  共 {} 条记录".format(len(history)), C.CYAN))
                print()

            elif action == "results":
                target = parts[1] if len(parts) > 1 else ""
                severity = parts[2] if len(parts) > 2 else ""
                if not target:
                    print(color("% 用法: show vulnerability results <目标> [严重度]", C.RED))
                    return
                data = scanner.get_latest_results(target=target, severity=severity or None, page=1, per_page=20)
                if not data["results"]:
                    print(color("  未找到目标 {} 的扫描结果".format(target), C.YELLOW))
                    return
                print(color("\n漏洞结果 (目标: {}):".format(target), C.CYAN))
                print("  " + "-" * 100)
                print("  {:<16} {:<6} {:<10} {:<30} {:<16} {:<6} {:<8}".format(
                    "主机", "端口", "服务", "漏洞", "CVE", "CVSS", "严重度"))
                print("  " + "-" * 100)
                for v in data["results"]:
                    sev_c = {"critical": C.RED, "high": C.YELLOW, "medium": C.YELLOW, "low": C.GREEN, "info": C.BLUE}
                    c = sev_c.get(v["severity"], C.RESET)
                    print("  {:<16} {:<6} {:<10} {:<30} {:<16} {:<6} {}".format(
                        v["host"][:16], str(v["port"] or "-"), (v["service"] or "-")[:10],
                        (v["name"] or "-")[:30], (v["cve_id"] or "-")[:16],
                        str(v["cvss_score"] or "-"), color(v["severity"], c)
                    ))
                print("  " + "-" * 100)
                print(color("  共 {} 条结果".format(data["total"]), C.CYAN))
                print()

            else:
                print(color("% 用法: show vulnerability [stats|history|results]", C.RED))

        except Exception as e:
            print(color("  获取漏洞信息失败: {}".format(e), C.RED))

    # ---- 双因素认证(2FA) ----
    def _show_two_factor(self, rest):
        """显示2FA状态信息"""
        try:
            from security.two_factor import get_two_factor_auth
            tfa = get_two_factor_auth()

            print(color("\n双因素认证(2FA)状态:", C.BOLD))
            print("  " + "-" * 50)

            # 检查所有用户的2FA状态
            from core.database import db_manager
            from core.models import User
            from sqlalchemy import text

            with db_manager.get_session() as session:
                users = session.query(User).filter_by(is_active=True).all()

            if not users:
                print("  暂无活跃用户")
                print("  " + "-" * 50)
                return

            enabled_count = 0
            for u in users:
                config = tfa.get_user_2fa(u.id)
                if config and config.enabled:
                    enabled_count += 1
                    status = color("已启用", C.GREEN)
                    last_used = config.last_used.strftime("%Y-%m-%d %H:%M") if config.last_used else "从未使用"
                    backup_count = len(config.backup_codes)
                    print("  用户: {:<16} 状态: {:<10} 备用码: {:>3} 个  上次使用: {}".format(
                        u.username, status, backup_count, last_used))
                else:
                    status = color("未启用", C.RED)
                    print("  用户: {:<16} 状态: {:<10}".format(u.username, status))

            print("  " + "-" * 50)
            print("  总用户数: {}  已启用2FA: {}".format(len(users), color(str(enabled_count), C.GREEN)))
            print()

        except Exception as e:
            print(color("  获取2FA信息失败: {}".format(e), C.RED))

    def do_two_factor(self, arg):
        """双因素认证管理命令"""
        parts = arg.strip().split()
        if not parts:
            print(color("% 用法: two-factor <enable|disable|status>", C.RED))
            print("  enable   - 为指定用户启用2FA")
            print("  disable  - 为指定用户禁用2FA")
            print("  status   - 查看当前用户2FA状态")
            return

        action = parts[0].lower()

        if action == "enable":
            self._two_factor_enable(parts[1:])
        elif action == "disable":
            self._two_factor_disable(parts[1:])
        elif action == "status":
            self._two_factor_status(parts[1:])
        else:
            print(color("% 未知操作: {} (可用: enable/disable/status)".format(action), C.RED))

    def _two_factor_enable(self, args):
        """为用户启用2FA"""
        username = args[0] if args else ""
        if not username:
            username = input("请输入用户名: ").strip()
        if not username:
            print(color("% 用户名不能为空", C.RED))
            return

        try:
            from security.two_factor import get_two_factor_auth
            from core.database import db_manager
            from core.models import User

            tfa = get_two_factor_auth()

            with db_manager.get_session() as session:
                user = session.query(User).filter_by(username=username).first()
                if not user:
                    print(color("% 用户不存在: {}".format(username), C.RED))
                    return

                if not user.is_active:
                    print(color("% 用户已被禁用: {}".format(username), C.RED))
                    return

                # 检查是否已启用
                if tfa.is_2fa_enabled(user.id):
                    print(color("% 用户 {} 已启用2FA".format(username), C.YELLOW))
                    return

                # 生成密钥和备用码
                secret = tfa.generate_secret()
                uri = tfa.get_totp_uri(user.username, secret)
                backup_codes = tfa.generate_backup_codes(10)

                print(color("\n  双因素认证设置 - 用户: {}".format(username), C.BOLD))
                print("  " + "=" * 50)
                print("  密钥(Secret): {}".format(color(secret, C.CYAN)))
                print("  URI: {}".format(uri))
                print("  " + "=" * 50)
                print("\n  请使用身份验证器应用扫描上方URI或手动输入密钥")
                print("  然后输入应用中显示的6位验证码以确认启用:")

                code = input("  验证码: ").strip()
                if not code or len(code) != 6:
                    print(color("% 验证码格式错误", C.RED))
                    return

                if not tfa.verify_code(secret, code):
                    print(color("% 验证码错误，请确认时间同步后重试", C.RED))
                    return

                # 启用2FA
                success = tfa.enable_2fa(user.id, secret, backup_codes)
                if success:
                    print(color("\n  双因素认证已成功启用!", C.GREEN))
                    print("  " + "-" * 50)
                    print("  备用恢复码 (请妥善保存，每张码仅可使用一次):")
                    for i, c in enumerate(backup_codes, 1):
                        print("    {:>2}. {}".format(i, color(c, C.CYAN)))
                    print("  " + "-" * 50)

                    try:
                        from core.audit import log_cli_action
                        log_cli_action(
                            action="2fa_enable", module="cli",
                            detail="CLI为用户{}启用双因素认证".format(username)
                        )
                    except Exception:
                        pass
                else:
                    print(color("% 启用失败", C.RED))

        except Exception as e:
            print(color("  启用2FA失败: {}".format(e), C.RED))

    def _two_factor_disable(self, args):
        """为用户禁用2FA"""
        username = args[0] if args else ""
        if not username:
            username = input("请输入用户名: ").strip()
        if not username:
            print(color("% 用户名不能为空", C.RED))
            return

        try:
            from security.two_factor import get_two_factor_auth
            from core.database import db_manager
            from core.models import User

            tfa = get_two_factor_auth()

            with db_manager.get_session() as session:
                user = session.query(User).filter_by(username=username).first()
                if not user:
                    print(color("% 用户不存在: {}".format(username), C.RED))
                    return

                if not tfa.is_2fa_enabled(user.id):
                    print(color("% 用户 {} 未启用2FA".format(username), C.YELLOW))
                    return

                confirm = input("确定要禁用用户 {} 的双因素认证吗? (yes/no): ".format(username)).strip().lower()
                if confirm != "yes":
                    print("  操作已取消")
                    return

                success = tfa.disable_2fa(user.id)
                if success:
                    print(color("  用户 {} 的双因素认证已禁用".format(username), C.GREEN))
                    try:
                        from core.audit import log_cli_action
                        log_cli_action(
                            action="2fa_disable", module="cli",
                            detail="CLI为用户{}禁用双因素认证".format(username)
                        )
                    except Exception:
                        pass
                else:
                    print(color("% 禁用失败", C.RED))

        except Exception as e:
            print(color("  禁用2FA失败: {}".format(e), C.RED))

    def _two_factor_status(self, args):
        """查看用户2FA状态"""
        username = args[0] if args else ""
        try:
            from security.two_factor import get_two_factor_auth
            from core.database import db_manager
            from core.models import User

            tfa = get_two_factor_auth()

            if username:
                with db_manager.get_session() as session:
                    user = session.query(User).filter_by(username=username).first()
                    if not user:
                        print(color("% 用户不存在: {}".format(username), C.RED))
                        return

                config = tfa.get_user_2fa(user.id)
                print(color("\n用户 {} 的2FA状态:".format(username), C.BOLD))
                print("  " + "-" * 40)
                if config and config.enabled:
                    print("  状态:       {}".format(color("已启用", C.GREEN)))
                    print("  启用时间:   {}".format(
                        config.created_at.strftime("%Y-%m-%d %H:%M") if config.created_at else "-"))
                    print("  最后使用:   {}".format(
                        config.last_used.strftime("%Y-%m-%d %H:%M") if config.last_used else "从未使用"))
                    print("  备用码剩余: {} 个".format(len(config.backup_codes)))
                else:
                    print("  状态:       {}".format(color("未启用", C.RED)))
                print("  " + "-" * 40)
                print()
            else:
                # 显示所有用户状态
                self._show_two_factor("")

        except Exception as e:
            print(color("  获取2FA状态失败: {}".format(e), C.RED))

    def complete_two_factor(self, text, line, begidx, endidx):
        """two-factor命令补全"""
        if len(line.split()) <= 2:
            return [c for c in ["enable", "disable", "status"] if c.startswith(text)]
        return []

    # ---- scan vulnerability ----
    def do_scan(self, arg):
        """执行扫描命令"""
        parts = arg.strip().split()
        if not parts:
            print(color("% 用法: scan vulnerability <目标> [quick|full|custom] [端口]", C.RED))
            return

        sub = parts[0].lower()
        if sub != "vulnerability":
            print(color("% 未知扫描类型: {}".format(sub), C.RED))
            print("  可用类型: vulnerability")
            return

        target = parts[1] if len(parts) > 1 else ""
        if not target:
            print(color("% 请指定扫描目标", C.RED))
            return

        scan_type = parts[2] if len(parts) > 2 else "quick"
        if scan_type not in ("quick", "full", "custom"):
            print(color("% 无效扫描类型: {}".format(scan_type), C.RED))
            return

        ports = None
        if scan_type == "custom" and len(parts) > 3:
            try:
                ports = []
                for p in parts[3].split(","):
                    p = p.strip()
                    if "-" in p:
                        start, end = p.split("-", 1)
                        ports.extend(range(int(start), int(end) + 1))
                    else:
                        ports.append(int(p))
            except ValueError:
                print(color("% 无效的端口格式", C.RED))
                return

        print(color("\n  启动漏洞扫描...", C.BOLD))
        print("  目标: {}  类型: {}".format(color(target, C.CYAN), scan_type))
        print("  " + "-" * 50)

        try:
            from security.vuln_scanner import get_vuln_scanner
            scanner = get_vuln_scanner()
            result = scanner.start_scan(target=target, scan_type=scan_type, ports=ports)

            if result["status"] == "ok":
                print(color("  扫描任务已启动 (ID: {})".format(result["scan_id"]), C.GREEN))
                print("  使用 'show vulnerability stats' 查看扫描进度和结果")
            else:
                print(color("  启动失败: {}".format(result.get("message", "未知错误")), C.RED))
        except Exception as e:
            print(color("  扫描失败: {}".format(e), C.RED))
        print()

    # ---- ping / traceroute ----
    def do_ping(self, arg):
        if not arg.strip():
            print(color("% 用法: ping <主机名或IP>", C.RED)); return
        target = arg.strip().split()[0]
        print("  正在 ping {} ...".format(color(target, C.BOLD)))
        print("  " + "-" * 50)
        try:
            result = run_cmd(["ping", "-c", "4", "-W", "2", target], check=False)
            print(result.stdout if result.stdout else result.stderr)
        except Exception as e:
            print("  ping 失败: {}".format(e))
        print()

    def do_traceroute(self, arg):
        if not arg.strip():
            print(color("% 用法: traceroute <主机名或IP>", C.RED)); return
        target = arg.strip().split()[0]
        print("  追踪路由到 {}，最大跳数 30:".format(color(target, C.BOLD)))
        print("  " + "-" * 50)
        try:
            result = run_cmd(["traceroute", "-n", "-w", "2", "-m", "15", target],
                           check=False, timeout=60)
            print(result.stdout if result.stdout else "  追踪完成。")
        except FileNotFoundError:
            print("  (系统未安装 traceroute)")
        except Exception as e:
            print("  追踪失败: {}".format(e))
        print()

    # ---- 特权命令 ----
    def do_configure(self, arg):
        parts = arg.strip().split()
        if parts and parts[0].lower() == "terminal":
            self.mode = "config"; print(color("已进入全局配置模式", C.GREEN))
        else:
            print(color("% 用法: configure terminal", C.RED))

    def do_write(self, arg):
        parts = arg.strip().split()
        if parts and parts[0].lower() in ("memory", "mem"):
            print(color("正在保存配置...", C.YELLOW))
            try:
                # 确保目录存在
                os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
                config = {
                    "hostname": self.hostname,
                    "enable_password": self.enable_password,
                    "saved_at": datetime.now().isoformat()
                }
                with open(CONFIG_FILE, "w") as f:
                    json.dump(config, f, indent=2)
                print(color("[OK] 配置已保存到 {}".format(CONFIG_FILE), C.GREEN))
            except Exception as e:
                print(color("% 保存失败: {}".format(e), C.RED))
        else:
            print(color("% 用法: write memory", C.RED))

    def do_reload(self, arg):
        if input(color("确认重启系统? [确认/取消]: ", C.RED)).strip().lower() in ("y", "yes", "确认"):
            print(color("正在重启系统...", C.YELLOW))
            try:
                result = run_cmd(["reboot"], check=False)
                if result.returncode != 0:
                    # 尝试使用sudo
                    result = run_cmd(["sudo", "reboot"], check=False)
                if result.returncode != 0:
                    print(color("% 重启失败: {}".format(result.stderr), C.RED))
            except Exception as e:
                print(color("% 重启失败: {}".format(e), C.RED))
        else:
            print("已取消。")

    def do_start(self, arg):
        """start shell - 切换到原始 GateKeeper CLI 模式"""
        if arg.strip().lower() != "shell":
            print(color('% 未识别的命令: "start {}"  输入 "?" 查看帮助'.format(arg.strip()), C.RED))
            return
        if self.mode != "priv":
            print(color("% start shell 仅在特权模式下可用", C.RED))
            return
        print(color("\n正在切换到 GateKeeper Shell 模式...", C.YELLOW))
        print(color("输入 'exit' 返回 Cisco IOS CLI\n", C.YELLOW))
        try:
            from cli.main import GateKeeperCLI
            shell = GateKeeperCLI()
            shell.run()
        except Exception as e:
            print(color("Shell 启动失败: {}".format(e), C.RED))
        print(color("\n已返回 Cisco IOS CLI", C.GREEN))

    def do_debug(self, arg):
        if not arg.strip():
            print(color("% 用法: debug <标志>", C.RED)); return
        print(color("调试 {} 已开启".format(arg.strip()), C.YELLOW))

    def do_undebug(self, arg):
        if not arg.strip():
            print(color("% 用法: undebug <标志>", C.RED)); return
        print(color("调试 {} 已关闭".format(arg.strip()), C.YELLOW))

    # ---- 全局配置 ----
    def do_hostname(self, arg):
        if not arg.strip():
            print(color("% 用法: hostname <名称>", C.RED)); return
        new_hostname = arg.strip()
        try:
            # 临时设置主机名
            result = run_cmd(["hostname", new_hostname], check=False)
            if result.returncode == 0:
                # 永久设置主机名
                try:
                    with open("/etc/hostname", "w") as f:
                        f.write(new_hostname + "\n")
                except:
                    pass
                # 更新hosts文件
                try:
                    ip = "127.0.1.1"
                    hosts_line = "{} {}\n".format(ip, new_hostname)
                    with open("/etc/hosts", "r") as f:
                        lines = f.readlines()
                    # 检查是否已存在
                    found = False
                    for i, line in enumerate(lines):
                        if line.startswith(ip + " "):
                            lines[i] = hosts_line
                            found = True
                            break
                    if not found:
                        lines.append(hosts_line)
                    with open("/etc/hosts", "w") as f:
                        f.writelines(lines)
                except:
                    pass
                self.hostname = new_hostname
                print(color("主机名已更改为: {}".format(new_hostname), C.GREEN))
            else:
                # 尝试使用sudo
                result = run_cmd(["sudo", "hostname", new_hostname], check=False)
                if result.returncode == 0:
                    self.hostname = new_hostname
                    print(color("主机名已更改为: {}".format(new_hostname), C.GREEN))
                else:
                    print(color("% 设置主机名失败: {}".format(result.stderr), C.RED))
        except Exception as e:
            print(color("% 设置主机名失败: {}".format(e), C.RED))

    def do__enable_password(self, arg):
        if not arg.strip():
            print(color("% 用法: enable password <密码>", C.RED)); return
        self.enable_password = arg.strip()
        print(color("特权密码已设置", C.GREEN))

    def do_interface(self, arg):
        if not arg.strip():
            print(color("% 用法: interface <接口名>", C.RED)); return
        iname = arg.strip()
        # 验证接口是否存在
        try:
            result = run_cmd(["ip", "link", "show", iname], check=False)
            if result.returncode != 0:
                print(color("% 警告: 接口 {} 不存在".format(iname), C.YELLOW))
        except:
            pass
        self.cur_if = iname; self.mode = "config_if"
        print(color("已进入接口 {} 配置模式".format(iname), C.GREEN))

    def do_ip(self, arg):
        parts = arg.strip().split()
        if not parts:
            print(color("% ip 命令需要参数", C.RED)); return
        sub = parts[0].lower(); rest = " ".join(parts[1:])
        if sub == "route":
            self._config_ip_route(rest)
        elif sub in ("name-server", "name"):
            self._config_dns(rest)
        elif sub == "address" and self.mode == "config_if":
            self._set_ip_addr(rest)
        elif sub == "nat":
            self._config_nat(rest)
        else:
            print(color("% 未知的 ip 子命令: {}".format(sub), C.RED))

    def _config_nat(self, rest):
        """配置NAT"""
        parts = rest.strip().split()
        if not parts:
            print(color("% 用法: ip nat <inside|outside|source>", C.RED))
            print("  ip nat inside  - 设置接口为NAT内部")
            print("  ip nat outside - 设置接口为NAT外部")
            print("  ip nat source  - 配置源NAT")
            return

        action = parts[0].lower()

        if action == "source":
            # ip nat source list 1 interface eth0 overload
            if len(parts) >= 5 and parts[1] == "list":
                acl_num = parts[2]
                out_iface = parts[4] if len(parts) > 4 else "eth0"
                try:
                    # 启用IP转发
                    run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
                    # 添加MASQUERADE规则
                    result = run_cmd([
                        "iptables", "-t", "nat", "-A", "POSTROUTING",
                        "-o", out_iface, "-j", "MASQUERADE"
                    ], check=False)
                    if result.returncode == 0:
                        print(color("NAT已启用: 出接口 {}".format(out_iface), C.GREEN))
                    else:
                        print(color("% 启用NAT失败: {}".format(result.stderr), C.RED))
                except Exception as e:
                    print(color("% 配置NAT失败: {}".format(e), C.RED))
            else:
                print(color("% 用法: ip nat source list <ACL> interface <接口> overload", C.RED))
        else:
            print(color("% NAT配置: {} 接口标记".format(action), C.YELLOW))

    def _config_ip_route(self, rest):
        rp = rest.strip().split()
        if len(rp) < 3:
            print(color("% 用法: ip route <目标> <掩码> <下一跳>", C.RED)); return
        dest, mask, gateway = rp[0], rp[1], rp[2]
        try:
            # 转换掩码为CIDR
            cidr = self._mask_to_cidr(mask)
            dest_cidr = "{}/{}".format(dest, cidr) if "/" not in dest else dest
            result = run_cmd(["ip", "route", "add", dest_cidr, "via", gateway], check=False)
            if result.returncode == 0:
                print(color("静态路由已添加: {} via {}".format(dest_cidr, gateway), C.GREEN))
            else:
                # 尝试使用sudo
                result = run_cmd(["sudo", "ip", "route", "add", dest_cidr, "via", gateway], check=False)
                if result.returncode == 0:
                    print(color("静态路由已添加: {} via {}".format(dest_cidr, gateway), C.GREEN))
                else:
                    print(color("% 添加路由失败: {}".format(result.stderr), C.RED))
        except Exception as e:
            print(color("% 添加路由失败: {}".format(e), C.RED))

    def _mask_to_cidr(self, mask):
        """将子网掩码转换为CIDR前缀"""
        try:
            parts = mask.split(".")
            binary = sum(bin(int(x)).count("1") for x in parts)
            return binary
        except:
            return 24

    def _config_dns(self, rest):
        for ns in rest.strip().split():
            try:
                with open("/etc/resolv.conf", "a") as f:
                    f.write("nameserver {}\n".format(ns))
                print(color("DNS服务器已添加: {}".format(ns), C.GREEN))
            except Exception as e:
                print(color("% 添加DNS失败: {}".format(e), C.RED))

    def do_ip_address(self, arg):
        self._set_ip_addr(arg)

    def _set_ip_addr(self, arg):
        if not self.cur_if:
            print(color("% 未选择接口", C.RED)); return
        parts = arg.strip().split()
        if not parts:
            print(color("% 用法: ip address <IP> <掩码> 或 ip address dhcp", C.RED)); return
        if parts[0].lower() == "dhcp":
            # 配置DHCP - 使用dhclient或dhcpcd
            try:
                # 先释放现有IP
                run_cmd(["ip", "addr", "flush", "dev", self.cur_if], check=False)
                # 启动DHCP客户端
                result = run_cmd(["dhclient", self.cur_if], check=False, timeout=10)
                if result.returncode == 0:
                    print(color("接口 {} 已设置为 DHCP".format(self.cur_if), C.GREEN))
                else:
                    # 尝试dhcpcd
                    result = run_cmd(["dhcpcd", self.cur_if], check=False, timeout=10)
                    if result.returncode == 0:
                        print(color("接口 {} 已设置为 DHCP".format(self.cur_if), C.GREEN))
                    else:
                        print(color("% DHCP配置失败，请手动安装dhclient或dhcpcd", C.RED))
            except Exception as e:
                print(color("% DHCP配置失败: {}".format(e), C.RED))
        elif len(parts) >= 2:
            ip, mask = parts[0], parts[1]
            try:
                # 转换掩码为CIDR
                cidr = self._mask_to_cidr(mask)
                # 先清除现有IP
                run_cmd(["ip", "addr", "flush", "dev", self.cur_if], check=False)
                # 添加新IP
                result = run_cmd(["ip", "addr", "add", "{}/{}".format(ip, cidr), "dev", self.cur_if], check=False)
                if result.returncode == 0:
                    print(color("接口 {} IP已设置为 {}/{}".format(self.cur_if, ip, mask), C.GREEN))
                else:
                    result = run_cmd(["sudo", "ip", "addr", "add", "{}/{}".format(ip, cidr), "dev", self.cur_if], check=False)
                    if result.returncode == 0:
                        print(color("接口 {} IP已设置为 {}/{}".format(self.cur_if, ip, mask), C.GREEN))
                    else:
                        print(color("% 设置IP失败: {}".format(result.stderr), C.RED))
            except Exception as e:
                print(color("% 设置IP失败: {}".format(e), C.RED))

    def do_access_list(self, arg):
        self._enter_acl(arg)

    def do__access_list(self, arg):
        self._enter_acl(arg)

    def _enter_acl(self, arg):
        parts = arg.strip().split()
        if len(parts) < 2:
            print(color("% 用法: access-list <编号> standard", C.RED)); return
        if parts[1].lower() == "standard":
            self.cur_acl = parts[0]; self.mode = "config_acl"
            print(color("已进入标准ACL {} 配置模式".format(parts[0]), C.GREEN))
            print(color("  注意: ACL规则将通过iptables实现", C.YELLOW))
        else:
            print(color("% 目前仅支持标准ACL (standard)", C.RED))

    def do__no_access_list(self, arg):
        parts = arg.strip().split()
        if parts:
            acl_num = parts[0]
            try:
                # 删除对应的iptables规则
                result = run_cmd(["iptables", "-D", "INPUT", "-m", "comment", "--comment", "ACL_{}".format(acl_num)], check=False)
                print(color("ACL {} 已删除".format(acl_num), C.GREEN))
            except Exception as e:
                print(color("% 删除ACL失败: {}".format(e), C.RED))

    def do_line(self, arg):
        parts = arg.strip().split()
        if not parts:
            print(color("% 用法: line [console | vty <起始> <结束>]", C.RED)); return
        if parts[0].lower() == "console":
            print(color("控制台线路配置", C.YELLOW))
            print("  exec-timeout 0 0\n  logging synchronous")
        elif parts[0].lower() == "vty":
            rng = " {}-{}".format(parts[1], parts[2]) if len(parts) >= 3 else ""
            print(color("VTY线路{} 配置".format(rng), C.YELLOW))
            print("  transport input ssh telnet\n  login local")
        else:
            print(color("% 未知的线路类型: {}".format(parts[0]), C.RED))

    def do_service(self, arg):
        if not arg.strip():
            print(color("% 用法: service <服务名>", C.RED))
            print(color("  service dhcp ...       - DHCP服务器管理", C.CYAN))
            print(color("  service gateway ...    - 网关管理", C.CYAN))
            print(color("  service wan ...        - WAN上联接口管理", C.CYAN))
            print(color("  service speedtest ...  - 网络测速", C.CYAN))
            print(color("  service nat ...        - NAT高级配置", C.CYAN))
            return
        parts = arg.strip().split()
        service = parts[0].lower()
        rest = " ".join(parts[1:]) if len(parts) > 1 else ""

        if service == "dhcp":
            self._service_dhcp(rest)
        elif service == "gateway":
            self._service_gateway(rest)
        elif service == "wan":
            self._service_wan(rest)
        elif service == "speedtest":
            self._service_speedtest(rest)
        elif service == "nat":
            self._service_nat(rest)
        else:
            try:
                result = run_cmd(["systemctl", "enable", service], check=False)
                result2 = run_cmd(["systemctl", "start", service], check=False)
                if result.returncode == 0 or result2.returncode == 0:
                    print(color("服务 {} 已启用并启动".format(service), C.GREEN))
                else:
                    print(color("% 启动服务失败，尝试使用service命令", C.YELLOW))
                    result = run_cmd(["service", service, "start"], check=False)
                    if result.returncode == 0:
                        print(color("服务 {} 已启动".format(service), C.GREEN))
                    else:
                        print(color("% 启动服务失败".format(service), C.RED))
            except Exception as e:
                print(color("% 启动服务失败: {}".format(e), C.RED))

    def _service_dhcp(self, rest):
        """配置DHCP服务 - 支持多网段和VLAN"""
        parts = rest.strip().split()
        if not parts:
            print(color("% 用法: service dhcp <start|stop|config|subnet|list|vlan>", C.RED))
            print(color("  start          - 启动DHCP服务", C.CYAN))
            print(color("  stop           - 停止DHCP服务", C.CYAN))
            print(color("  list           - 列出所有DHCP子网", C.CYAN))
            print(color("  subnet add     - 添加DHCP子网", C.CYAN))
            print(color("  subnet del     - 删除DHCP子网", C.CYAN))
            print(color("  vlan           - 查看VLAN接口", C.CYAN))
            return

        action = parts[0].lower()

        if action == "start":
            try:
                result = run_cmd(["systemctl", "start", "dnsmasq"], check=False)
                run_cmd(["systemctl", "enable", "dnsmasq"], check=False)
                if result.returncode == 0:
                    print(color("DHCP服务已启动", C.GREEN))
                else:
                    print(color("% 启动DHCP失败: {}".format(result.stderr), C.RED))
            except Exception as e:
                print(color("% 启动DHCP失败: {}".format(e), C.RED))

        elif action == "stop":
            run_cmd(["systemctl", "stop", "dnsmasq"], check=False)
            print(color("DHCP服务已停止", C.YELLOW))

        elif action == "list":
            self._list_dhcp_subnets()

        elif action == "subnet":
            if len(parts) < 2:
                print(color("% 用法: service dhcp subnet <add|del|show>", C.RED))
                return
            sub_action = parts[1].lower()
            if sub_action == "add":
                self._add_dhcp_subnet(parts[2:] if len(parts) > 2 else [])
            elif sub_action == "del":
                self._del_dhcp_subnet(parts[2:] if len(parts) > 2 else [])
            elif sub_action == "show":
                self._show_dhcp_subnet(parts[2:] if len(parts) > 2 else [])
            else:
                print(color("% 用法: service dhcp subnet <add|del|show>", C.RED))

        elif action == "vlan":
            self._list_vlan_interfaces()

        elif action == "config":
            if len(parts) >= 4:
                start_ip = parts[1]
                end_ip = parts[2]
                lease_time = parts[3]
                print(color("DHCP配置: {} - {}, 租约{}秒".format(start_ip, end_ip, lease_time), C.GREEN))
            else:
                print(color("% 用法: service dhcp config <起始IP> <结束IP> <租约时间>", C.RED))

        else:
            print(color("% 未知操作: {}".format(action), C.RED))

    def _list_dhcp_subnets(self):
        """列出所有DHCP子网"""
        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()
            subnets = manager.get_dhcp_subnets()

            if not subnets:
                print(color("暂无DHCP子网配置", C.YELLOW))
                return

            print(color("\nDHCP子网列表:", C.CYAN))
            print("-" * 100)
            print("{:<4} {:<12} {:<20} {:<25} {:<12} {:<8} {:<8}".format(
                "ID", "名称", "网络", "IP范围", "接口", "VLAN", "状态"
            ))
            print("-" * 100)

            for s in subnets:
                vlan_str = str(s["vlan_id"]) if s["vlan_id"] else "-"
                status = color("启用", C.GREEN) if s["is_enabled"] else color("禁用", C.RED)
                ip_range = "{} - {}".format(s["start_ip"], s["end_ip"])
                iface = s["vlan_interface"] if s["vlan_interface"] else s["interface"]
                print("{:<4} {:<12} {:<20} {:<25} {:<12} {:<8} {}".format(
                    s["id"], s["name"], s["network"], ip_range, iface, vlan_str, status
                ))

            print("-" * 100)
            print(color("共 {} 个子网".format(len(subnets)), C.CYAN))

        except Exception as e:
            print(color("% 获取子网列表失败: {}".format(e), C.RED))

    def _add_dhcp_subnet(self, args):
        """添加DHCP子网"""
        # service dhcp subnet add <名称> <网络> <网关> <起始IP> <结束IP> <接口> [VLAN ID]
        if len(args) < 6:
            print(color("% 用法: service dhcp subnet add <名称> <网络> <网关> <起始IP> <结束IP> <接口> [VLAN ID]", C.RED))
            print(color("  示例: service dhcp subnet add 办公网 192.168.1.0/24 192.168.1.1 192.168.1.100 192.168.1.200 eth1", C.CYAN))
            print(color("  VLAN: service dhcp subnet add 访客网 192.168.2.0/24 192.168.2.1 192.168.2.100 192.168.2.200 eth1 100", C.CYAN))
            return

        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()

            name = args[0]
            network = args[1]
            gateway = args[2]
            start_ip = args[3]
            end_ip = args[4]
            interface = args[5]
            vlan_id = int(args[6]) if len(args) > 6 else None

            result = manager.add_dhcp_subnet(
                name=name,
                network=network,
                gateway=gateway,
                start_ip=start_ip,
                end_ip=end_ip,
                interface=interface,
                vlan_id=vlan_id
            )

            if result["success"]:
                print(color("DHCP子网 '{}' 添加成功".format(name), C.GREEN))
                if vlan_id:
                    print(color("VLAN {} 接口 {} 已创建".format(vlan_id, "{}.{}".format(interface, vlan_id)), C.CYAN))
            else:
                print(color("% 添加失败: {}".format(result["message"]), C.RED))

        except Exception as e:
            print(color("% 添加子网失败: {}".format(e), C.RED))

    def _del_dhcp_subnet(self, args):
        """删除DHCP子网"""
        if len(args) < 1:
            print(color("% 用法: service dhcp subnet del <子网ID>", C.RED))
            return

        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()

            subnet_id = int(args[0])
            result = manager.delete_dhcp_subnet(subnet_id)

            if result["success"]:
                print(color("DHCP子网已删除", C.GREEN))
            else:
                print(color("% 删除失败: {}".format(result["message"]), C.RED))

        except Exception as e:
            print(color("% 删除子网失败: {}".format(e), C.RED))

    def _show_dhcp_subnet(self, args):
        """显示DHCP子网详情"""
        if len(args) < 1:
            print(color("% 用法: service dhcp subnet show <子网ID>", C.RED))
            return

        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()

            subnet_id = int(args[0])
            subnet = manager.get_dhcp_subnet(subnet_id)

            if not subnet:
                print(color("% 子网不存在", C.RED))
                return

            print(color("\nDHCP子网详情:", C.CYAN))
            print("-" * 40)
            print("  ID:          {}".format(subnet["id"]))
            print("  名称:        {}".format(subnet["name"]))
            print("  网络:        {}".format(subnet["network"]))
            print("  网关:        {}".format(subnet["gateway"]))
            print("  IP范围:      {} - {}".format(subnet["start_ip"], subnet["end_ip"]))
            print("  租约时间:    {} 秒".format(subnet["lease_time"]))
            print("  DNS服务器:   {}".format(", ".join(subnet["dns_servers"]) if subnet["dns_servers"] else "默认"))
            print("  接口:        {}".format(subnet["interface"]))
            if subnet["vlan_id"]:
                print("  VLAN ID:     {}".format(subnet["vlan_id"]))
                print("  VLAN接口:    {}".format(subnet["vlan_interface"]))
            print("  状态:        {}".format(color("启用", C.GREEN) if subnet["is_enabled"] else color("禁用", C.RED)))
            print("  优先级:      {}".format(subnet["priority"]))
            print("  描述:        {}".format(subnet["description"] or "无"))
            print("-" * 40)

        except Exception as e:
            print(color("% 获取子网详情失败: {}".format(e), C.RED))

    def _list_vlan_interfaces(self):
        """列出VLAN接口"""
        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()
            vlans = manager.get_vlan_interfaces()

            if not vlans:
                print(color("暂无VLAN接口", C.YELLOW))
                return

            print(color("\nVLAN接口列表:", C.CYAN))
            print("-" * 60)
            print("{:<20} {:<10} {:<15} {:<10}".format("接口名", "VLAN ID", "父接口", "状态"))
            print("-" * 60)

            for v in vlans:
                print("{:<20} {:<10} {:<15} {:<10}".format(
                    v["name"],
                    v.get("vlan_id", "-"),
                    v.get("parent", "-"),
                    v["status"]
                ))

            print("-" * 60)

        except Exception as e:
            print(color("% 获取VLAN列表失败: {}".format(e), C.RED))

    def _service_speedtest(self, rest):
        """网络测速"""
        parts = rest.strip().split()
        if not parts:
            print(color("% 用法: service speedtest <start|result|servers>", C.RED))
            print(color("  start [目标IP]  - 开始测速", C.CYAN))
            print(color("  result          - 查看上次结果", C.CYAN))
            print(color("  servers         - 查看可用服务器", C.CYAN))
            return

        action = parts[0].lower()

        if action == "start":
            target = parts[1] if len(parts) > 1 else ""
            print(color("正在启动网络测速...", C.CYAN))
            try:
                from network.speedtest import get_speedtest
                tester = get_speedtest()

                def on_progress(phase, progress, msg):
                    bar_len = 30
                    filled = int(bar_len * progress / 100)
                    bar = '█' * filled + '░' * (bar_len - filled)
                    print(f"\r  [{bar}] {progress:5.1f}% {msg}", end='', flush=True)

                tester.set_progress_callback(on_progress)
                result = tester.run_speedtest(target_host=target)
                print()  # 换行

                print(color("\n测速结果:", C.CYAN))
                print("-" * 45)
                print(f"  测速目标:    {result.target_host or '自动选择'}")
                print(f"  延迟:        {color(str(result.latency_ms) + ' ms', C.GREEN)}")
                print(f"  抖动:        {color(str(result.jitter_ms) + ' ms', C.GREEN)}")
                print(f"  丢包率:      {color(str(result.packet_loss) + '%', C.GREEN if result.packet_loss < 1 else C.RED)}")
                print(f"  下载速度:    {color(str(result.download_speed_mbps) + ' Mbps', C.GREEN)}")
                print(f"  上传速度:    {color(str(result.upload_speed_mbps) + ' Mbps', C.GREEN)}")
                print(f"  测试耗时:    {result.test_duration}s")
                if result.error:
                    print(f"  备注:        {color(result.error, C.YELLOW)}")
                print("-" * 45)

            except Exception as e:
                print(color(f"\n测速失败: {e}", C.RED))

        elif action == "result":
            try:
                from network.speedtest import get_speedtest
                r = get_speedtest().result
                print(color("\n上次测速结果:", C.CYAN))
                print(f"  时间: {r.timestamp}")
                print(f"  下载: {r.download_speed_mbps} Mbps | 上传: {r.upload_speed_mbps} Mbps")
                print(f"  延迟: {r.latency_ms} ms | 抖动: {r.jitter_ms} ms")
            except Exception as e:
                print(color(f"获取结果失败: {e}", C.RED))

        elif action == "servers":
            try:
                from network.speedtest import get_speedtest
                servers = get_speedtest().get_speedtest_servers()
                print(color("\n可用测速服务器:", C.CYAN))
                print("-" * 50)
                for s in servers:
                    status = color(f"{s['latency']}ms", C.GREEN) if s['available'] else color("不可达", C.RED)
                    print(f"  {s['name']:<20} {s['host']:<20} {status}")
                print("-" * 50)
            except Exception as e:
                print(color(f"获取服务器列表失败: {e}", C.RED))

        else:
            print(color("% 未知操作: {}".format(action), C.RED))

    def _service_nat(self, rest):
        """NAT高级配置"""
        parts = rest.strip().split()
        if not parts:
            print(color("% 用法: service nat <config|rules|flush|set>", C.RED))
            print(color("  config          - 查看当前NAT配置", C.CYAN))
            print(color("  rules           - 查看NAT规则列表", C.CYAN))
            print(color("  flush           - 刷新连接跟踪表", C.CYAN))
            print(color("  set ctmax <N>   - 设置连接跟踪上限", C.CYAN))
            print(color("  set tcp_est <N> - TCP建立超时(秒)", C.CYAN))
            print(color("  set tcp_tw <N>  - TCP TIME_WAIT超时(秒)", C.CYAN))
            print(color("  set udp <N>     - UDP超时(秒)", C.CYAN))
            print(color("  set synproxy on/off - SYN代理", C.CYAN))
            print(color("  set log on/off  - 转发日志", C.CYAN))
            return

        action = parts[0].lower()

        if action == "config":
            self._show_nat_config()
        elif action == "rules":
            self._show_nat_rules()
        elif action == "flush":
            self._flush_conntrack()
        elif action == "set":
            self._set_nat_param(parts[1:] if len(parts) > 1 else [])
        else:
            print(color("% 未知操作: {}".format(action), C.RED))

    def _show_nat_config(self):
        """显示NAT配置"""
        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()
            config = manager.get_nat_config()

            if "error" in config:
                print(color("获取NAT配置失败: {}".format(config["error"]), C.RED))
                return

            print(color("\nNAT高级配置:", C.CYAN))
            print("-" * 50)
            print(f"  状态:        {'已启用' if config.get('enabled') else '未启用'}")
            print(f"  WAN接口:     {config.get('wan_interface', '-')}")
            print(f"  LAN接口:     {config.get('lan_interface', '-')}")
            print(f"  LAN网络:     {config.get('lan_network', '-')}")
            print(f"  连接跟踪:    {config.get('conntrack_count', 0)} / {config.get('conntrack_max', 0)} ({config.get('conntrack_usage', 0)}%)")
            print(f"  SYN代理:     {'已启用' if config.get('syn_proxy') else '未启用'}")
            print(f"  NAT规则数:   {config.get('rules_count', 0)}")

            ct = config.get("conntrack_settings", {})
            if ct:
                print(color("\n  连接跟踪参数:", C.CYAN))
                for k, v in ct.items():
                    print(f"    {k}: {v}")

            print("-" * 50)

        except Exception as e:
            print(color("获取NAT配置失败: {}".format(e), C.RED))

    def _show_nat_rules(self):
        """显示NAT规则"""
        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()
            rules = manager.get_nat_rules()

            if not rules:
                print(color("暂无NAT规则", C.YELLOW))
                return

            print(color("\nNAT规则列表:", C.CYAN))
            print("-" * 80)
            for r in rules:
                print(f"  [{r['table']}/{r['chain']}] {r['raw']}")
            print("-" * 80)
            print(color("共 {} 条规则".format(len(rules)), C.CYAN))

        except Exception as e:
            print(color("获取NAT规则失败: {}".format(e), C.RED))

    def _flush_conntrack(self):
        """刷新连接跟踪表"""
        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()
            result = manager.flush_conntrack()
            if result["success"]:
                print(color("连接跟踪表已刷新", C.GREEN))
            else:
                print(color("刷新失败: {}".format(result["message"]), C.RED))
        except Exception as e:
            print(color("刷新失败: {}".format(e), C.RED))

    def _set_nat_param(self, args):
        """设置NAT参数"""
        if len(args) < 2:
            print(color("% 用法: service nat set <参数名> <值>", C.RED))
            return

        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()

            param = args[0].lower()
            value = args[1]

            kwargs = {}
            if param == "ctmax":
                kwargs["conntrack_max"] = int(value)
            elif param == "tcp_est":
                kwargs["tcp_established_timeout"] = int(value)
            elif param == "tcp_tw":
                kwargs["tcp_time_wait_timeout"] = int(value)
            elif param == "udp":
                kwargs["udp_timeout"] = int(value)
            elif param == "synproxy":
                kwargs["enable_syn_proxy"] = value.lower() in ("on", "1", "true", "yes")
            elif param == "log":
                kwargs["enable_log_dropped"] = value.lower() in ("on", "1", "true", "yes")
            else:
                print(color("% 未知参数: {}".format(param), C.RED))
                return

            result = manager.set_nat_advanced(**kwargs)
            if result["success"]:
                print(color("配置已更新: {}".format(", ".join(result.get("changes", []))), C.GREEN))
            else:
                print(color("配置失败: {}".format(result["message"]), C.RED))

        except Exception as e:
            print(color("设置失败: {}".format(e), C.RED))

    def _service_wan(self, rest):
        """WAN上联接口管理 - DHCP/PPPoE/静态IP"""
        parts = rest.strip().split()
        if not parts:
            print(color("% 用法: service wan <connect|disconnect|status|config>", C.RED))
            print(color("  status              - 查看WAN连接状态", C.CYAN))
            print(color("  connect             - 连接WAN", C.CYAN))
            print(color("  disconnect          - 断开WAN", C.CYAN))
            print(color("  config dhcp         - 设置DHCP模式", C.CYAN))
            print(color("  config pppoe <用户> <密码> [MTU]  - 设置PPPoE拨号", C.CYAN))
            print(color("  config static <IP> <掩码> <网关> [DNS]  - 设置静态IP", C.CYAN))
            return

        action = parts[0].lower()

        if action == "status":
            self._show_wan_status()
        elif action == "connect":
            self._connect_wan()
        elif action == "disconnect":
            self._disconnect_wan()
        elif action == "config":
            self._config_wan(parts[1:] if len(parts) > 1 else [])
        else:
            print(color("% 未知操作: {}".format(action), C.RED))

    def _show_wan_status(self):
        """显示WAN连接状态"""
        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()
            status = manager.get_wan_status()

            mode_map = {"dhcp": "DHCP自动获取", "pppoe": "PPPoE拨号", "static": "静态IP"}
            conn = color("已连接", C.GREEN) if status["is_connected"] else color("未连接", C.RED)

            print(color("\nWAN上联接口状态:", C.CYAN))
            print("-" * 50)
            print("  连接方式:    {}".format(mode_map.get(status["mode"], status["mode"])))
            print("  物理接口:    {}".format(status["interface"]))
            print("  连接状态:    {}".format(conn))
            print("  WAN IP:      {}".format(status["current_ip"] or "-"))
            print("  网关:        {}".format(status["gateway_ip"] or "-"))
            print("  DNS:         {}".format(", ".join(status["dns_servers"]) if status["dns_servers"] else "-"))
            if status["connect_time"]:
                print("  连接时间:    {}".format(status["connect_time"]))
            if status["error_message"]:
                print("  错误信息:    {}".format(color(status["error_message"], C.RED)))
            if status["mode"] == "pppoe":
                print("  PPPoE用户:   {}".format(status["pppoe_username"]))
                print("  PPPoE MTU:   {}".format(status["pppoe_mtu"]))
                print("  自动重连:    {}".format("是" if status["pppoe_auto_reconnect"] else "否"))
            print("-" * 50)

        except Exception as e:
            print(color("% 获取WAN状态失败: {}".format(e), C.RED))

    def _connect_wan(self):
        """连接WAN"""
        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()
            print(color("正在连接WAN...", C.CYAN))
            result = manager.connect_wan()

            if result["success"]:
                print(color("WAN连接成功: IP={}".format(result.get("ip", "")), C.GREEN))
            else:
                print(color("WAN连接失败: {}".format(result["message"]), C.RED))

        except Exception as e:
            print(color("% 连接WAN失败: {}".format(e), C.RED))

    def _disconnect_wan(self):
        """断开WAN"""
        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()
            result = manager.disconnect_wan()
            print(color("WAN已断开", C.YELLOW))
        except Exception as e:
            print(color("% 断开WAN失败: {}".format(e), C.RED))

    def _config_wan(self, args):
        """配置WAN连接方式"""
        if not args:
            print(color("% 用法:", C.RED))
            print(color("  service wan config dhcp", C.CYAN))
            print(color("  service wan config pppoe <用户名> <密码> [MTU]", C.CYAN))
            print(color("  service wan config static <IP> <掩码> <网关> [DNS1,DNS2]", C.CYAN))
            return

        try:
            from network.gateway import get_gateway_manager
            manager = get_gateway_manager()

            mode = args[0].lower()

            if mode == "dhcp":
                result = manager.configure_wan(mode="dhcp")
                if result["success"]:
                    print(color("WAN已设置为DHCP模式", C.GREEN))
                    print(color("执行 service wan connect 连接", C.CYAN))
                else:
                    print(color("% {}", result["message"]), C.RED)

            elif mode == "pppoe":
                if len(args) < 3:
                    print(color("% 用法: service wan config pppoe <用户名> <密码> [MTU]", C.RED))
                    return
                username = args[1]
                password = args[2]
                mtu = int(args[3]) if len(args) > 3 else 1492

                result = manager.configure_wan(
                    mode="pppoe",
                    pppoe_username=username,
                    pppoe_password=password,
                    pppoe_mtu=mtu
                )
                if result["success"]:
                    print(color("WAN已设置为PPPoE模式: 用户={}".format(username), C.GREEN))
                    print(color("执行 service wan connect 拨号", C.CYAN))
                else:
                    print(color("% {}", result["message"]), C.RED)

            elif mode == "static":
                if len(args) < 4:
                    print(color("% 用法: service wan config static <IP> <掩码> <网关> [DNS]", C.RED))
                    return
                ip = args[1]
                netmask = args[2]
                gateway = args[3]
                dns = args[4].split(",") if len(args) > 4 else []

                result = manager.configure_wan(
                    mode="static",
                    static_ip=ip,
                    static_netmask=netmask,
                    static_gateway=gateway,
                    static_dns=dns
                )
                if result["success"]:
                    print(color("WAN已设置为静态IP: {} / {}".format(ip, netmask), C.GREEN))
                    print(color("执行 service wan connect 应用配置", C.CYAN))
                else:
                    print(color("% {}", result["message"]), C.RED)

            else:
                print(color("% 不支持的连接方式: {}，可选: dhcp, pppoe, static".format(mode), C.RED))

        except Exception as e:
            print(color("% 配置WAN失败: {}".format(e), C.RED))

    def _service_gateway(self, rest):
        """配置网关服务"""
        parts = rest.strip().split()
        if not parts:
            print(color("% 用法: service gateway <enable|disable> <WAN接口> <LAN接口>", C.RED))
            return

        action = parts[0].lower()

        if action == "enable":
            if len(parts) >= 3:
                wan_iface = parts[1]
                lan_iface = parts[2]
                try:
                    # 启用IP转发
                    run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
                    # 配置NAT
                    result = run_cmd([
                        "iptables", "-t", "nat", "-A", "POSTROUTING",
                        "-o", wan_iface, "-j", "MASQUERADE"
                    ], check=False)
                    if result.returncode == 0:
                        print(color("网关已启用: WAN={}, LAN={}".format(wan_iface, lan_iface), C.GREEN))
                        print(color("内网设备可通过此系统访问互联网", C.CYAN))
                    else:
                        print(color("% 启用网关失败: {}".format(result.stderr), C.RED))
                except Exception as e:
                    print(color("% 启用网关失败: {}".format(e), C.RED))
            else:
                print(color("% 用法: service gateway enable <WAN接口> <LAN接口>", C.RED))

        elif action == "disable":
            try:
                run_cmd(["iptables", "-t", "nat", "-F", "POSTROUTING"], check=False)
                run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=False)
                print(color("网关已禁用", C.YELLOW))
            except Exception as e:
                print(color("% 禁用网关失败: {}".format(e), C.RED))

    def do_no(self, arg):
        parts = arg.strip().split()
        if not parts:
            return
        sub = parts[0].lower()
        if sub == "shutdown" and self.mode == "config_if" and self.cur_if:
            self._do_no_shutdown()
        elif sub == "ip" and len(parts) > 1:
            if parts[1].lower() == "route" and len(parts) >= 5:
                self._do_no_ip_route(parts)
            elif parts[1].lower() == "address" and self.mode == "config_if":
                self._do_no_ip_address()
        elif sub == "access-list" and len(parts) > 1:
            self._do_no_access_list(parts[1])
        elif sub == "hostname":
            self._do_no_hostname()
        else:
            print(color("% 未知的 no 子命令: {}".format(sub), C.RED))

    def _do_no_shutdown(self):
        try:
            result = run_cmd(["ip", "link", "set", self.cur_if, "up"], check=False)
            if result.returncode == 0:
                print(color("接口 {} 已启用".format(self.cur_if), C.GREEN))
            else:
                result = run_cmd(["sudo", "ip", "link", "set", self.cur_if, "up"], check=False)
                if result.returncode == 0:
                    print(color("接口 {} 已启用".format(self.cur_if), C.GREEN))
                else:
                    print(color("% 启用接口失败: {}".format(result.stderr), C.RED))
        except Exception as e:
            print(color("% 启用接口失败: {}".format(e), C.RED))

    def _do_no_ip_route(self, parts):
        d, m, g = parts[2], parts[3], parts[4]
        try:
            cidr = self._mask_to_cidr(m)
            dest_cidr = "{}/{}".format(d, cidr) if "/" not in d else d
            result = run_cmd(["ip", "route", "del", dest_cidr, "via", g], check=False)
            if result.returncode == 0:
                print(color("静态路由已删除: {} via {}".format(dest_cidr, g), C.GREEN))
            else:
                result = run_cmd(["sudo", "ip", "route", "del", dest_cidr, "via", g], check=False)
                if result.returncode == 0:
                    print(color("静态路由已删除: {} via {}".format(dest_cidr, g), C.GREEN))
                else:
                    print(color("% 删除路由失败: {}".format(result.stderr), C.RED))
        except Exception as e:
            print(color("% 删除路由失败: {}".format(e), C.RED))

    def _do_no_ip_address(self):
        try:
            result = run_cmd(["ip", "addr", "flush", "dev", self.cur_if], check=False)
            if result.returncode == 0:
                print(color("接口 {} IP地址已清除".format(self.cur_if), C.GREEN))
            else:
                result = run_cmd(["sudo", "ip", "addr", "flush", "dev", self.cur_if], check=False)
                if result.returncode == 0:
                    print(color("接口 {} IP地址已清除".format(self.cur_if), C.GREEN))
                else:
                    print(color("% 清除IP失败: {}".format(result.stderr), C.RED))
        except Exception as e:
            print(color("% 清除IP失败: {}".format(e), C.RED))

    def _do_no_access_list(self, acl_num):
        try:
            # 删除所有带ACL标记的规则
            result = run_cmd(["iptables", "-L", "INPUT", "--line-numbers", "-n"], check=False)
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in reversed(lines):
                    if "ACL_{}".format(acl_num) in line:
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            run_cmd(["iptables", "-D", "INPUT", parts[0]], check=False)
            print(color("ACL {} 已删除".format(acl_num), C.GREEN))
        except Exception as e:
            print(color("% 删除ACL失败: {}".format(e), C.RED))

    def _do_no_hostname(self):
        try:
            result = run_cmd(["hostname", "Router"], check=False)
            self.hostname = "Router"
            print(color("主机名已恢复为: Router", C.GREEN))
        except Exception as e:
            print(color("% 恢复主机名失败: {}".format(e), C.RED))

    # ---- 接口配置 ----
    def do_shutdown(self, arg):
        if self.mode == "config_if" and self.cur_if:
            try:
                result = run_cmd(["ip", "link", "set", self.cur_if, "down"], check=False)
                if result.returncode == 0:
                    print(color("接口 {} 已关闭".format(self.cur_if), C.YELLOW))
                else:
                    result = run_cmd(["sudo", "ip", "link", "set", self.cur_if, "down"], check=False)
                    if result.returncode == 0:
                        print(color("接口 {} 已关闭".format(self.cur_if), C.YELLOW))
                    else:
                        print(color("% 关闭接口失败: {}".format(result.stderr), C.RED))
            except Exception as e:
                print(color("% 关闭接口失败: {}".format(e), C.RED))
        else:
            print(color("% shutdown 需要在接口配置模式下使用", C.RED))

    def do_description(self, arg):
        if self.mode != "config_if":
            print(color("% description 需要在接口配置模式下使用", C.RED)); return
        if not arg.strip():
            print(color("% 用法: description <描述文本>", C.RED)); return
        desc = arg.strip()
        try:
            # 使用ethtool设置描述或通过sysfs
            with open("/sys/class/net/{}/ifalias".format(self.cur_if), "w") as f:
                f.write(desc)
            print(color("描述已设置: {}".format(desc), C.GREEN))
        except Exception as e:
            print(color("% 设置描述失败: {}".format(e), C.RED))

    def do_speed(self, arg):
        if self.mode != "config_if":
            print(color("% speed 需要在接口配置模式下使用", C.RED)); return
        if not arg.strip():
            print(color("% 用法: speed <10|100|1000|auto>", C.RED)); return
        speed = arg.strip()
        try:
            if speed == "auto":
                result = run_cmd(["ethtool", "-s", self.cur_if, "autoneg", "on"], check=False)
            else:
                result = run_cmd(["ethtool", "-s", self.cur_if, "speed", speed, "autoneg", "off"], check=False)
            if result.returncode == 0:
                print(color("速率已设置为 {}".format(speed), C.GREEN))
            else:
                print(color("% 设置速率失败: {}".format(result.stderr), C.YELLOW))
                print(color("  可能需要安装ethtool或使用sudo", C.YELLOW))
        except Exception as e:
            print(color("% 设置速率失败: {}".format(e), C.RED))

    def do_duplex(self, arg):
        if self.mode != "config_if":
            print(color("% duplex 需要在接口配置模式下使用", C.RED)); return
        if not arg.strip():
            print(color("% 用法: duplex <half|full|auto>", C.RED)); return
        duplex = arg.strip()
        try:
            if duplex == "auto":
                result = run_cmd(["ethtool", "-s", self.cur_if, "autoneg", "on"], check=False)
            else:
                result = run_cmd(["ethtool", "-s", self.cur_if, "duplex", duplex], check=False)
            if result.returncode == 0:
                print(color("双工模式已设置为 {}".format(duplex), C.GREEN))
            else:
                print(color("% 设置双工模式失败: {}".format(result.stderr), C.YELLOW))
                print(color("  可能需要安装ethtool或使用sudo", C.YELLOW))
        except Exception as e:
            print(color("% 设置双工模式失败: {}".format(e), C.RED))

    def do_mtu(self, arg):
        if self.mode != "config_if":
            print(color("% mtu 需要在接口配置模式下使用", C.RED)); return
        if not arg.strip():
            print(color("% 用法: mtu <值>", C.RED)); return
        try:
            val = int(arg.strip())
            if not 68 <= val <= 9000:
                print(color("% MTU 值应在 68-9000 之间", C.RED)); return
            result = run_cmd(["ip", "link", "set", self.cur_if, "mtu", str(val)], check=False)
            if result.returncode == 0:
                print(color("MTU 已设置为 {}".format(val), C.GREEN))
            else:
                result = run_cmd(["sudo", "ip", "link", "set", self.cur_if, "mtu", str(val)], check=False)
                if result.returncode == 0:
                    print(color("MTU 已设置为 {}".format(val), C.GREEN))
                else:
                    print(color("% 设置MTU失败: {}".format(result.stderr), C.RED))
        except ValueError:
            print(color("% MTU 必须是数字", C.RED))
        except Exception as e:
            print(color("% 设置MTU失败: {}".format(e), C.RED))

    # ---- ACL 配置 ----
    def do_permit(self, arg):
        if self.mode != "config_acl":
            print(color("% permit 需要在ACL配置模式下使用", C.RED)); return
        if not arg.strip():
            print(color("% 用法: permit <源地址>", C.RED)); return
        source = arg.strip()
        try:
            # 使用iptables实现ACL
            if source == "any":
                result = run_cmd(["iptables", "-A", "INPUT", "-m", "comment", "--comment", "ACL_{}".format(self.cur_acl), "-j", "ACCEPT"], check=False)
            else:
                result = run_cmd(["iptables", "-A", "INPUT", "-s", source, "-m", "comment", "--comment", "ACL_{}".format(self.cur_acl), "-j", "ACCEPT"], check=False)
            if result.returncode == 0:
                print(color("规则已添加: permit {}".format(source), C.GREEN))
            else:
                result = run_cmd(["sudo", "iptables", "-A", "INPUT", "-s", source, "-m", "comment", "--comment", "ACL_{}".format(self.cur_acl), "-j", "ACCEPT"], check=False)
                if result.returncode == 0:
                    print(color("规则已添加: permit {}".format(source), C.GREEN))
                else:
                    print(color("% 添加规则失败: {}".format(result.stderr), C.RED))
        except Exception as e:
            print(color("% 添加规则失败: {}".format(e), C.RED))

    def do_deny(self, arg):
        if self.mode != "config_acl":
            print(color("% deny 需要在ACL配置模式下使用", C.RED)); return
        if not arg.strip():
            print(color("% 用法: deny <源地址>", C.RED)); return
        source = arg.strip()
        try:
            if source == "any":
                result = run_cmd(["iptables", "-A", "INPUT", "-m", "comment", "--comment", "ACL_{}".format(self.cur_acl), "-j", "DROP"], check=False)
            else:
                result = run_cmd(["iptables", "-A", "INPUT", "-s", source, "-m", "comment", "--comment", "ACL_{}".format(self.cur_acl), "-j", "DROP"], check=False)
            if result.returncode == 0:
                print(color("规则已添加: deny {}".format(source), C.GREEN))
            else:
                result = run_cmd(["sudo", "iptables", "-A", "INPUT", "-s", source, "-m", "comment", "--comment", "ACL_{}".format(self.cur_acl), "-j", "DROP"], check=False)
                if result.returncode == 0:
                    print(color("规则已添加: deny {}".format(source), C.GREEN))
                else:
                    print(color("% 添加规则失败: {}".format(result.stderr), C.RED))
        except Exception as e:
            print(color("% 添加规则失败: {}".format(e), C.RED))

    def do_remark(self, arg):
        if self.mode != "config_acl":
            print(color("% remark 需要在ACL配置模式下使用", C.RED)); return
        if not arg.strip():
            print(color("% 用法: remark <文本>", C.RED)); return
        print(color("备注已添加: {}".format(arg.strip()), C.GREEN))

    def do_waf_rule(self, arg):
        """WAF规则管理"""
        if self.mode not in ("priv", "config"):
            print(color("% waf-rule 仅在特权或配置模式下可用", C.RED))
            return
        parts = arg.strip().split()
        if not parts:
            print(color("% 用法: waf-rule <add|del|enable|disable|list>", C.RED))
            return
        action = parts[0].lower()
        try:
            from security.waf_engine import get_waf_engine
            waf = get_waf_engine()
            if action == "add":
                if len(parts) < 3:
                    print(color("% 用法: waf-rule add <名称> <规则类型> [参数]", C.RED))
                    return
                name = parts[1]
                rule_type = parts[2]
                pattern = parts[3] if len(parts) > 3 else ""
                if not pattern:
                    print(color("% 请提供匹配模式(pattern)", C.RED))
                    return
                rule = waf.add_rule(name=name, rule_type=rule_type, pattern=pattern)
                print(color("规则已添加: {} (ID: {})".format(name, rule.id), C.GREEN))
            elif action == "del":
                if len(parts) < 2:
                    print(color("% 用法: waf-rule del <规则ID>", C.RED))
                    return
                success = waf.remove_rule(int(parts[1]))
                if success:
                    print(color("规则已删除", C.GREEN))
                else:
                    print(color("% 删除失败: 规则不存在", C.RED))
            elif action == "enable":
                if len(parts) < 2:
                    print(color("% 用法: waf-rule enable <规则ID>", C.RED))
                    return
                success = waf.toggle_rule(int(parts[1]), True)
                if success:
                    print(color("规则已启用", C.GREEN))
                else:
                    print(color("% 启用失败: 规则不存在", C.RED))
            elif action == "disable":
                if len(parts) < 2:
                    print(color("% 用法: waf-rule disable <规则ID>", C.RED))
                    return
                success = waf.toggle_rule(int(parts[1]), False)
                if success:
                    print(color("规则已禁用", C.YELLOW))
                else:
                    print(color("% 禁用失败: 规则不存在", C.RED))
            elif action == "list":
                rules = waf.get_rules()
                print(color("\nWAF规则列表:", C.CYAN))
                print("-" * 80)
                for r in rules:
                    enabled = color("启用", C.GREEN) if r["enabled"] else color("禁用", C.RED)
                    print("  {:<6} {:<20} {:<10} {:<30}".format(r["id"], r["name"], enabled, r.get("description", "")))
                print("-" * 80)
            else:
                print(color("% 未知操作: {}".format(action), C.RED))
        except Exception as e:
            print(color("% WAF操作失败: {}".format(e), C.RED))

    # ---- Tab 补全 ----
    def complete_show(self, text, line, begidx, endidx):
        return [c for c in ["version", "interfaces", "ip route", "ip interface brief",
                "running-config", "startup-config", "clock", "users", "audit", "ddos", "waf",
                "honeypot services", "honeypot captures", "honeypot stats",
                "two-factor"] if c.startswith(text)]

    def complete_ip(self, text, line, begidx, endidx):
        if len(line.split()) <= 2:
            return [c for c in ["route", "name-server", "address"] if c.startswith(text)]
        return []

    def complete_interface(self, text, line, begidx, endidx):
        try:
            result = run_cmd(["ls", "/sys/class/net/"], check=False)
            if result.returncode == 0:
                return [i for i in result.stdout.strip().split("\n") if i.startswith(text)]
        except:
            pass
        return ["eth0", "eth1", "ens33", "ens34", "lo"]

    def complete_configure(self, text, line, begidx, endidx):
        return [c for c in ["terminal"] if c.startswith(text)]

    def complete_write(self, text, line, begidx, endidx):
        return [c for c in ["memory"] if c.startswith(text)]

    def complete_no(self, text, line, begidx, endidx):
        return [c for c in ["shutdown", "ip route", "ip address", "access-list", "hostname"]
                if c.startswith(text)]

    def complete_line(self, text, line, begidx, endidx):
        return [c for c in ["console", "vty"] if c.startswith(text)]

    def complete_access_list(self, text, line, begidx, endidx):
        return [c for c in ["standard"] if c.startswith(text)]

    def complete_speed(self, text, line, begidx, endidx):
        return [c for c in ["10", "100", "1000", "auto"] if c.startswith(text)]

    def complete_duplex(self, text, line, begidx, endidx):
        return [c for c in ["half", "full", "auto"] if c.startswith(text)]

    def complete_debug(self, text, line, begidx, endidx):
        return [c for c in ["all", "packet", "acl", "ip", "arp"] if c.startswith(text)]

    complete_undebug = complete_debug

    def complete_service(self, text, line, begidx, endidx):
        return [c for c in ["password-encryption", "dhcp", "timestamps", "ssh", "http"] if c.startswith(text)]

    # ---- 启动 ----
    def run(self):
        try:
            self.cmdloop()
        except KeyboardInterrupt:
            print("\n")
        finally:
            self._save_hist()


def main(net_mgr=None, fw_mgr=None):
    try:
        CiscoCLI(net_mgr=net_mgr, fw_mgr=fw_mgr).run()
    except Exception as e:
        print(color("CLI 启动失败: {}".format(e), C.RED))
        sys.exit(1)


if __name__ == "__main__":
    _net_mgr = _fw_mgr = None
    try:
        from network.network_config import NetworkConfigManager
        _net_mgr = NetworkConfigManager()
    except Exception:
        pass
    try:
        from network.firewall import FirewallManager
        _fw_mgr = FirewallManager()
    except Exception:
        pass
    main(net_mgr=_net_mgr, fw_mgr=_fw_mgr)
