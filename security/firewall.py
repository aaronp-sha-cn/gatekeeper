"""GateKeeper 安全防火墙策略管理模块"""
import logging
import threading
import subprocess
import re

logger = logging.getLogger(__name__)

class SecurityFirewall:
    """安全防火墙策略管理（单例模式）"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._rules = []
        self._default_policy = "DROP"
        self._enabled = True
        self._iptables_comment_prefix = "GK"
        logger.info("安全防火墙策略管理器初始化完成")

    def _build_iptables_args(self, rule):
        """构建iptables命令参数"""
        args = ["iptables", "-A", rule["chain"]]

        if rule.get("protocol") and rule["protocol"] not in ("any", "all"):
            args.extend(["-p", rule["protocol"]])

        if rule.get("src"):
            args.extend(["-s", rule["src"]])

        if rule.get("dst"):
            args.extend(["-d", rule["dst"]])

        if rule.get("sport"):
            args.extend(["--sport", str(rule["sport"])])

        if rule.get("dport"):
            args.extend(["--dport", str(rule["dport"])])

        if rule.get("comment"):
            args.extend(["-m", "comment", "--comment",
                         "{}: {}".format(self._iptables_comment_prefix, rule["comment"])])

        args.extend(["-j", rule["action"]])
        return args

    def _apply_to_iptables(self, rule):
        """将单条规则应用到iptables"""
        if not self._enabled:
            logger.debug("防火墙未启用，跳过iptables应用")
            return

        try:
            args = self._build_iptables_args(rule)
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.error("iptables规则应用失败: {} - {}".format(
                    " ".join(args), result.stderr.strip()))
            else:
                logger.info("iptables规则已应用: chain={} action={} protocol={} dport={}".format(
                    rule.get("chain"), rule.get("action"), rule.get("protocol"), rule.get("dport")))
        except subprocess.TimeoutExpired:
            logger.error("iptables命令超时: {}".format(" ".join(self._build_iptables_args(rule))))
        except FileNotFoundError:
            logger.error("iptables命令未找到，请确保系统已安装iptables")
        except Exception as e:
            logger.error("应用iptables规则异常: {}".format(e))

    def _remove_from_iptables(self, rule):
        """从iptables移除单条规则"""
        if not self._enabled:
            return

        try:
            args = self._build_iptables_args(rule)
            # 将 -A 替换为 -D 来删除规则
            args[2] = "-D"
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.debug("iptables规则移除失败（可能已不存在）: {}".format(result.stderr.strip()))
            else:
                logger.info("iptables规则已移除: chain={} action={} protocol={} dport={}".format(
                    rule.get("chain"), rule.get("action"), rule.get("protocol"), rule.get("dport")))
        except subprocess.TimeoutExpired:
            logger.error("iptables删除命令超时")
        except FileNotFoundError:
            logger.error("iptables命令未找到")
        except Exception as e:
            logger.error("移除iptables规则异常: {}".format(e))

    def add_rule(self, chain="INPUT", action="ACCEPT", protocol="tcp", src=None, dst=None, sport=None, dport=None, comment=None):
        """添加防火墙规则"""
        # 参数验证
        valid_chains = ["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"]
        valid_actions = ["ACCEPT", "DROP", "REJECT", "LOG", "RETURN"]
        valid_protocols = ["tcp", "udp", "icmp", "any", "all"]

        chain = chain.upper()
        action = action.upper()

        if chain not in valid_chains:
            raise ValueError(f"无效的链: {chain}，允许值: {valid_chains}")
        if action not in valid_actions:
            raise ValueError(f"无效的动作: {action}，允许值: {valid_actions}")
        if protocol not in valid_protocols:
            raise ValueError(f"无效的协议: {protocol}，允许值: {valid_protocols}")

        if src and not self._validate_ip(src):
            raise ValueError(f"无效的源IP: {src}")
        if dst and not self._validate_ip(dst):
            raise ValueError(f"无效的目标IP: {dst}")
        if dport and not self._validate_port(dport):
            raise ValueError(f"无效的目标端口: {dport}")
        if sport and not self._validate_port(sport):
            raise ValueError(f"无效的源端口: {sport}")

        rule = {
            "chain": chain, "action": action, "protocol": protocol,
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "comment": comment, "enabled": True, "id": len(self._rules) + 1
        }
        self._rules.append(rule)
        logger.info(f"防火墙规则已添加: {chain} {action} {protocol} {dport}")
        # 同步到iptables
        self._apply_to_iptables(rule)
        return rule

    def remove_rule(self, rule_id):
        """移除规则"""
        removed = [r for r in self._rules if r.get("id") == rule_id]
        self._rules = [r for r in self._rules if r.get("id") != rule_id]
        logger.info(f"防火墙规则已移除: ID={rule_id}")
        # 从iptables移除
        for rule in removed:
            self._remove_from_iptables(rule)

    def get_rules(self, chain=None):
        """获取规则列表"""
        if chain:
            return [r for r in self._rules if r.get("chain") == chain]
        return list(self._rules)

    def sync_rules(self):
        """同步所有内存规则到iptables"""
        if not self._enabled:
            logger.warning("防火墙未启用，跳过同步")
            return {"status": "skipped", "message": "防火墙未启用"}

        try:
            # 先清除所有GateKeeper标记的iptables规则
            self._clear_gk_iptables_rules()

            # 重新应用所有内存中的规则
            applied = 0
            failed = 0
            for rule in self._rules:
                if rule.get("enabled", True):
                    try:
                        self._apply_to_iptables(rule)
                        applied += 1
                    except Exception as e:
                        logger.error("同步规则失败: {}".format(e))
                        failed += 1

            logger.info("防火墙规则同步完成: 应用={}, 失败={}".format(applied, failed))
            return {"status": "ok", "applied": applied, "failed": failed}

        except Exception as e:
            logger.error("同步防火墙规则失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def _clear_gk_iptables_rules(self):
        """清除所有GateKeeper标记的iptables规则 - 使用内存规则列表安全重建"""
        chains = ["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"]
        for chain in chains:
            try:
                # 列出规则并找到GateKeeper标记的规则
                result = subprocess.run(
                    ["iptables", "-S", chain],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    continue

                # 从后往前删除，避免索引偏移
                lines_to_delete = []
                for line in result.stdout.strip().split("\n"):
                    if self._iptables_comment_prefix in line:
                        lines_to_delete.append(line)

                for line in reversed(lines_to_delete):
                    try:
                        # 使用 shlex.split 安全解析规则行
                        import shlex
                        parts = shlex.split(line)
                        if len(parts) < 3 or parts[0] != "-A":
                            continue
                        # 验证链名是否合法
                        if parts[1] not in chains:
                            continue
                        # 构建删除命令: -A -> -D
                        delete_cmd = ["iptables"] + ["-D"] + parts[1:]
                        # 验证命令参数中不包含shell危险字符
                        safe = True
                        for part in delete_cmd[1:]:
                            if any(c in part for c in [';', '&', '|', '$', '`', '(', ')', '<', '>', '\n', '\r']):
                                safe = False
                                break
                        if not safe:
                            logger.warning("跳过疑似注入的iptables规则: {}".format(line))
                            continue
                        subprocess.run(delete_cmd, capture_output=True, text=True, timeout=10)
                    except Exception:
                        pass

            except Exception as e:
                logger.debug("清除链 {} 的GK规则失败: {}".format(chain, e))

    def load_from_iptables(self):
        """从当前iptables规则加载到内存"""
        loaded_rules = []
        chains = ["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"]

        try:
            for chain in chains:
                result = subprocess.run(
                    ["iptables", "-S", chain],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    continue

                for line in result.stdout.strip().split("\n"):
                    if not line.startswith("-A"):
                        continue

                    parts = line.split()
                    rule = {
                        "chain": chain,
                        "action": "ACCEPT",
                        "protocol": "any",
                        "src": None,
                        "dst": None,
                        "sport": None,
                        "dport": None,
                        "comment": None,
                        "enabled": True,
                    }

                    i = 2  # 跳过 -A <chain>
                    while i < len(parts):
                        part = parts[i]
                        if part == "-p" and i + 1 < len(parts):
                            rule["protocol"] = parts[i + 1]
                            i += 2
                        elif part == "-s" and i + 1 < len(parts):
                            rule["src"] = parts[i + 1]
                            i += 2
                        elif part == "-d" and i + 1 < len(parts):
                            rule["dst"] = parts[i + 1]
                            i += 2
                        elif part == "--sport" and i + 1 < len(parts):
                            rule["sport"] = parts[i + 1]
                            i += 2
                        elif part == "--dport" and i + 1 < len(parts):
                            rule["dport"] = parts[i + 1]
                            i += 2
                        elif part == "--comment" and i + 1 < len(parts):
                            rule["comment"] = parts[i + 1]
                            i += 2
                        elif part == "-j" and i + 1 < len(parts):
                            rule["action"] = parts[i + 1]
                            i += 2
                        else:
                            i += 1

                    rule["id"] = len(loaded_rules) + 1
                    loaded_rules.append(rule)

            logger.info("从iptables加载了 {} 条规则".format(len(loaded_rules)))
            return loaded_rules

        except subprocess.TimeoutExpired:
            logger.error("读取iptables规则超时")
            return loaded_rules
        except FileNotFoundError:
            logger.error("iptables命令未找到")
            return loaded_rules
        except Exception as e:
            logger.error("加载iptables规则失败: {}".format(e))
            return loaded_rules

    def _validate_ip(self, ip):
        """验证IP地址格式"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
        if ip and '*' in ip:
            return True
        return bool(re.match(pattern, str(ip)))

    def _validate_port(self, port):
        """验证端口号"""
        if isinstance(port, str) and '-' in port:
            parts = port.split('-')
            return all(p.isdigit() and 1 <= int(p) <= 65535 for p in parts)
        if str(port).isdigit():
            return 1 <= int(port) <= 65535
        return False

    def get_stats(self):
        """获取防火墙统计"""
        return {
            "total_rules": len(self._rules),
            "enabled_rules": len([r for r in self._rules if r.get("enabled")]),
            "default_policy": self._default_policy,
            "enabled": self._enabled
        }
