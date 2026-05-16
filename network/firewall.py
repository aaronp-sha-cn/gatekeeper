"""
GateKeeper - 防火墙管理模块
基于iptables/nftables的防火墙规则管理
"""

import subprocess
import re
import threading
import ipaddress
from typing import Dict, List, Optional, Any
from datetime import datetime

from config.settings import settings
from config.logging_config import get_logger, log_security_event
from core.database import db_manager
from core.models import FirewallRule, FirewallAction, ProtocolType

logger = get_logger("firewall")


def is_valid_ipv6(address: str) -> bool:
    """
    验证是否为有效的IPv6地址

    Args:
        address: 待验证的IP地址字符串

    Returns:
        是否为有效的IPv6地址
    """
    try:
        addr = ipaddress.IPv6Address(address)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv4(address: str) -> bool:
    """
    验证是否为有效的IPv4地址（含CIDR）

    Args:
        address: 待验证的IP地址字符串

    Returns:
        是否为有效的IPv4地址
    """
    try:
        if '/' in address:
            ipaddress.IPv4Network(address, strict=False)
        else:
            ipaddress.IPv4Address(address)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


class FirewallManager:
    """
    防火墙管理器
    管理iptables防火墙规则的增删改查
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._backend = self._detect_backend()
        self._ip6tables_available = self._detect_ip6tables()
        self._default_rules_initialized = False

        logger.info("防火墙管理器初始化完成，后端: {}, IPv6(ip6tables): {}".format(
            self._backend, "可用" if self._ip6tables_available else "不可用"
        ))

        # 异步初始化默认规则，不阻塞 API 请求
        threading.Thread(target=self._init_default_rules, daemon=True).start()

    def _init_default_rules(self):
        """
        初始化默认安全规则

        在首次初始化时添加一组基础防火墙规则，包括：
        - 允许 loopback 接口
        - 允许已建立/关联连接
        - 允许 SSH、DNS、Web 管理界面、ICMP、DHCP
        - 丢弃无效包
        - 记录被丢弃的包
        - 设置 INPUT/FORWARD 链默认策略为 DROP
        """
        logger.info("开始初始化默认防火墙规则...")

        # 检查 INPUT 链是否已有规则，如果有则跳过初始化（避免重复添加）
        try:
            check_result = subprocess.run(
                ["iptables", "-L", "INPUT", "-n"],
                capture_output=True, text=True, timeout=5
            )
            if check_result.returncode == 0:
                # 如果 INPUT 链中存在非默认策略的规则行，则认为已经初始化过
                lines = check_result.stdout.strip().split("\n")
                # 跳过 "Chain INPUT" 和 "target prot ..." 表头行
                rule_lines = [
                    line for line in lines
                    if line.strip() and not line.startswith("Chain") and not line.startswith("target")
                ]
                if rule_lines:
                    logger.info("INPUT 链已存在规则，跳过默认规则初始化")
                    return
        except Exception as e:
            logger.warning("检查 INPUT 链规则失败: {}，将继续初始化默认规则".format(e))

        # 定义默认规则列表：(描述, iptables 参数列表)
        default_rules = [
            ("允许 loopback 接口", ["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"]),
            (
                "允许已建立/关联连接 (INPUT)",
                ["-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ),
            (
                "允许 FORWARD 已建立连接",
                ["-A", "FORWARD", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ),
            ("允许 SSH (tcp/22)", ["-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"]),
            ("允许 DNS (udp/53)", ["-A", "INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"]),
            ("允许 DNS (tcp/53)", ["-A", "INPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"]),
            (
                "允许 Web 管理界面 (tcp/8443)",
                ["-A", "INPUT", "-p", "tcp", "--dport", "8443", "-j", "ACCEPT"],
            ),
            (
                "允许 ICMP (ping)",
                ["-A", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "ACCEPT"],
            ),
            ("允许 DHCP (udp/67:68)", ["-A", "INPUT", "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"]),
            (
                "丢弃无效包",
                ["-A", "INPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"],
            ),
            (
                "记录被丢弃的 INPUT 包",
                ["-A", "INPUT", "-j", "LOG", "--log-prefix", "GK:INPUT-DROP: "],
            ),
            (
                "记录被丢弃的 FORWARD 包",
                ["-A", "FORWARD", "-j", "LOG", "--log-prefix", "GK:FORWARD-DROP: "],
            ),
        ]

        success_count = 0
        fail_count = 0

        for description, rule_args in default_rules:
            try:
                # 使用 iptables -C 检查规则是否已存在，避免重复添加
                # -C 参数与 -A 参数格式一致，只是将 -A 替换为 -C
                check_args = ["iptables", "-C"] + rule_args[1:]  # 去掉 -A，换成 -C
                check_result = subprocess.run(
                    check_args, capture_output=True, text=True, timeout=5
                )
                if check_result.returncode == 0:
                    logger.debug("规则已存在，跳过: {}".format(description))
                    continue

                # 规则不存在，执行添加
                add_result = subprocess.run(
                    ["iptables"] + rule_args,
                    capture_output=True, text=True, timeout=5
                )
                if add_result.returncode == 0:
                    logger.info("默认规则添加成功: {}".format(description))
                    success_count += 1
                else:
                    logger.warning(
                        "默认规则添加失败: {}，错误: {}".format(
                            description, add_result.stderr.strip()
                        )
                    )
                    fail_count += 1
            except subprocess.TimeoutExpired:
                logger.warning("默认规则添加超时: {}".format(description))
                fail_count += 1
            except Exception as e:
                logger.warning("默认规则添加异常: {}，错误: {}".format(description, e))
                fail_count += 1

        # 设置链默认策略（单独处理，因为 -P 不支持 -C 检查）
        default_policies = [
            ("INPUT 链默认策略 DROP", ["-P", "INPUT", "DROP"]),
            ("FORWARD 链默认策略 DROP", ["-P", "FORWARD", "DROP"]),
        ]

        for description, policy_args in default_policies:
            try:
                policy_result = subprocess.run(
                    ["iptables"] + policy_args,
                    capture_output=True, text=True, timeout=5
                )
                if policy_result.returncode == 0:
                    logger.info("默认策略设置成功: {}".format(description))
                    success_count += 1
                else:
                    logger.warning(
                        "默认策略设置失败: {}，错误: {}".format(
                            description, policy_result.stderr.strip()
                        )
                    )
                    fail_count += 1
            except subprocess.TimeoutExpired:
                logger.warning("默认策略设置超时: {}".format(description))
                fail_count += 1
            except Exception as e:
                logger.warning("默认策略设置异常: {}，错误: {}".format(description, e))
                fail_count += 1

        logger.info(
            "默认防火墙规则初始化完成，成功: {}，失败: {}".format(success_count, fail_count)
        )

    def _detect_backend(self) -> str:
        """检测防火墙后端"""
        try:
            result = subprocess.run(
                ["which", "nft"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return "nftables"

            result = subprocess.run(
                ["which", "iptables"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return "iptables"
        except Exception:
            pass
        return "iptables"  # 默认使用iptables

    def _detect_ip6tables(self) -> bool:
        """检测系统是否支持 ip6tables"""
        if not settings.network.ipv6_enabled:
            return False
        try:
            result = subprocess.run(
                ["which", "ip6tables"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.info("检测到 ip6tables 可用")
                return True
        except Exception:
            pass
        logger.info("ip6tables 不可用，IPv6 防火墙规则将被跳过")
        return False

    def _get_iptables_cmd(self, ip: Optional[str] = None) -> str:
        """
        根据IP地址类型选择 iptables 或 ip6tables 命令

        Args:
            ip: IP地址，用于判断是否为IPv6

        Returns:
            命令名称 ("iptables" 或 "ip6tables")
        """
        if ip and is_valid_ipv6(ip):
            if self._ip6tables_available:
                return "ip6tables"
            else:
                logger.warning("IPv6地址 {} 需要 ip6tables，但 ip6tables 不可用".format(ip))
                return "iptables"
        return "iptables"

    def _run_command(self, args: List[str], check: bool = False) -> subprocess.CompletedProcess:
        """执行系统命令"""
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=30,
                check=check,
            )
            return result
        except subprocess.TimeoutExpired:
            logger.error("命令执行超时: {}".format(' '.join(args)))
            raise
        except subprocess.CalledProcessError as e:
            logger.error("命令执行失败: {}".format(e.stderr))
            raise

    def add_rule(
        self,
        name: str,
        action: str = "DROP",
        chain: str = "INPUT",
        protocol: str = "any",
        source_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        dest_ip: Optional[str] = None,
        dest_port: Optional[int] = None,
        description: str = "",
        priority: int = 100,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        添加防火墙规则

        Args:
            name: 规则名称
            action: 动作 (ACCEPT/DROP/REJECT/LOG)
            chain: 链 (INPUT/OUTPUT/FORWARD)
            protocol: 协议 (tcp/udp/icmp/any)
            source_ip: 源IP
            source_port: 源端口
            dest_ip: 目标IP
            dest_port: 目标端口
            description: 规则描述
            priority: 优先级
            user_id: 创建用户ID

        Returns:
            添加结果
        """
        import re
        
        # 安全修复：参数白名单验证
        # 1. chain 白名单
        VALID_CHAINS = {"INPUT", "OUTPUT", "FORWARD"}
        if chain.upper() not in VALID_CHAINS:
            return {"status": "error", "message": "无效的 chain: {}，仅支持 INPUT/OUTPUT/FORWARD".format(chain)}
        
        # 2. action 白名单
        VALID_ACTIONS = {"ACCEPT", "DROP", "REJECT", "LOG"}
        if action.upper() not in VALID_ACTIONS:
            return {"status": "error", "message": "无效的 action: {}，仅支持 ACCEPT/DROP/REJECT/LOG".format(action)}
        
        # 3. protocol 白名单
        VALID_PROTOCOLS = {"tcp", "udp", "icmp", "any"}
        if protocol.lower() not in VALID_PROTOCOLS:
            return {"status": "error", "message": "无效的 protocol: {}，仅支持 tcp/udp/icmp/any".format(protocol)}
        
        # 4. 规则名称验证（防止注入）
        if not name or not re.match(r'^[a-zA-Z0-9_\- ]{1,64}$', name):
            return {"status": "error", "message": "规则名称无效：仅允许字母、数字、下划线、连字符、空格，长度1-64"}
        
        # 5. IP 地址格式验证
        IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
        if source_ip and not IP_PATTERN.match(source_ip) and not is_valid_ipv6(source_ip):
            return {"status": "error", "message": "无效的源 IP 地址格式: {}".format(source_ip)}
        if dest_ip and not IP_PATTERN.match(dest_ip) and not is_valid_ipv6(dest_ip):
            return {"status": "error", "message": "无效的目标 IP 地址格式: {}".format(dest_ip)}

        # 6. 端口范围验证
        if source_port is not None and (source_port < 1 or source_port > 65535):
            return {"status": "error", "message": "源端口超出有效范围 (1-65535)"}
        if dest_port is not None and (dest_port < 1 or dest_port > 65535):
            return {"status": "error", "message": "目标端口超出有效范围 (1-65535)"}

        # 确定使用 iptables 还是 ip6tables（根据源IP或目标IP判断）
        ip_for_cmd = source_ip or dest_ip
        iptables_cmd = self._get_iptables_cmd(ip_for_cmd)

        # 构建iptables命令
        iptables_args = [iptables_cmd, "-A", chain]

        if protocol and protocol.lower() != "any":
            iptables_args.extend(["-p", protocol.lower()])

        if source_ip:
            iptables_args.extend(["-s", source_ip])

        if source_port:
            iptables_args.extend(["--sport", str(source_port)])

        if dest_ip:
            iptables_args.extend(["-d", dest_ip])

        if dest_port:
            iptables_args.extend(["--dport", str(dest_port)])

        # 动作处理 - 注意LOG动作需要特殊处理
        if action.upper() == "LOG":
            iptables_args.extend(["-j", "LOG", "--log-prefix", "GK: "])
        else:
            iptables_args.extend(["-j", action.upper()])

        # 添加注释
        iptables_args.extend(["-m", "comment", "--comment", "GK:{}".format(name)])

        # 执行命令
        try:
            with self._lock:
                self._run_command(iptables_args, check=True)
                logger.info("防火墙规则已添加: {}".format(name))
        except Exception as e:
            logger.error("添加防火墙规则失败: {}, 错误: {}".format(name, e))
            return {"status": "error", "message": str(e)}

        # 保存到数据库
        try:
            rule = FirewallRule(
                name=name,
                description=description,
                chain=chain,
                protocol=ProtocolType(protocol.lower()) if protocol.lower() in ("tcp", "udp", "icmp") else ProtocolType.ANY,
                source_ip=source_ip,
                source_port=source_port,
                dest_ip=dest_ip,
                dest_port=dest_port,
                action=FirewallAction(action.upper()),
                is_enabled=True,
                priority=priority,
                created_by=user_id,
            )
            db_manager.add(rule)

            log_security_event(
                user="system" if not user_id else str(user_id),
                action="firewall_add",
                resource=name,
                result="success",
                message="添加防火墙规则: {}, action={}".format(name, action)
            )

        except Exception as e:
            logger.warning("保存规则到数据库失败: {}".format(e))

        return {"status": "ok", "name": name, "action": action}

    def remove_rule(self, rule_id: int) -> Dict[str, Any]:
        """
        移除防火墙规则

        Args:
            rule_id: 规则ID

        Returns:
            移除结果
        """
        try:
            with db_manager.get_session() as session:
                rule = session.query(FirewallRule).filter_by(id=rule_id).first()
                if not rule:
                    return {"status": "not_found", "rule_id": rule_id}

                # 从iptables移除
                ip_for_cmd = rule.source_ip or rule.dest_ip
                iptables_cmd = self._get_iptables_cmd(ip_for_cmd)
                iptables_args = [iptables_cmd, "-D", rule.chain]

                if rule.protocol and rule.protocol != ProtocolType.ANY:
                    iptables_args.extend(["-p", rule.protocol.value])

                if rule.source_ip:
                    iptables_args.extend(["-s", rule.source_ip])

                if rule.source_port:
                    iptables_args.extend(["--sport", str(rule.source_port)])

                if rule.dest_port:
                    iptables_args.extend(["--dport", str(rule.dest_port)])

                action_map = {
                    FirewallAction.ACCEPT: "ACCEPT",
                    FirewallAction.DROP: "DROP",
                    FirewallAction.REJECT: "REJECT",
                    FirewallAction.LOG: "LOG",
                }
                iptables_args.extend(["-j", action_map.get(rule.action, "DROP")])

                # LOG动作需要包含 --log-prefix 参数才能正确匹配并删除
                if rule.action == FirewallAction.LOG:
                    iptables_args.extend(["--log-prefix", "GK: "])

                try:
                    with self._lock:
                        self._run_command(iptables_args)
                except Exception as e:
                    logger.warning("从iptables移除规则失败: {}".format(e))

                # 从数据库移除
                session.delete(rule)

                log_security_event(
                    user="system",
                    action="firewall_remove",
                    resource=rule.name,
                    result="success",
                    message="移除防火墙规则: {}".format(rule.name)
                )

                logger.info("防火墙规则已移除: {}".format(rule.name))
                return {"status": "ok", "rule_id": rule_id, "name": rule.name}

        except Exception as e:
            logger.error("移除防火墙规则失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def remove_rule_by_source(self, source_ip: str) -> Dict[str, Any]:
        """根据源IP移除防火墙规则"""
        try:
            with db_manager.get_session() as session:
                rules = (
                    session.query(FirewallRule)
                    .filter_by(source_ip=source_ip)
                    .all()
                )
                removed = 0
                for rule in rules:
                    session.delete(rule)
                    removed += 1
                return {"status": "ok", "removed": removed}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def list_rules(self) -> List[Dict[str, Any]]:
        """
        列出所有防火墙规则

        Returns:
            规则列表
        """
        try:
            with db_manager.get_session() as session:
                rules = session.query(FirewallRule).order_by(FirewallRule.priority).all()
                return [
                    {
                        "id": r.id,
                        "name": r.name,
                        "description": r.description,
                        "chain": r.chain,
                        "protocol": r.protocol.value,
                        "source_ip": r.source_ip,
                        "source_port": r.source_port,
                        "dest_ip": r.dest_ip,
                        "dest_port": r.dest_port,
                        "action": r.action.value,
                        "is_enabled": r.is_enabled,
                        "priority": r.priority,
                        "hit_count": r.hit_count,
                        "created_at": str(r.created_at),
                    }
                    for r in rules
                ]
        except Exception as e:
            logger.error("列出防火墙规则失败: {}".format(e))
            return []

    def get_iptables_rules(self) -> str:
        """获取当前iptables规则列表"""
        try:
            result = self._run_command(["iptables", "-L", "-n", "-v", "--line-numbers"])
            return result.stdout
        except Exception as e:
            return "获取iptables规则失败: {}".format(e)

    def enable_rule(self, rule_id: int) -> Dict[str, Any]:
        """启用防火墙规则"""
        try:
            with db_manager.get_session() as session:
                rule = session.query(FirewallRule).filter_by(id=rule_id).first()
                if rule:
                    rule.is_enabled = True
                    return {"status": "ok", "rule_id": rule_id}
                return {"status": "not_found", "rule_id": rule_id}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def disable_rule(self, rule_id: int) -> Dict[str, Any]:
        """禁用防火墙规则"""
        try:
            with db_manager.get_session() as session:
                rule = session.query(FirewallRule).filter_by(id=rule_id).first()
                if rule:
                    rule.is_enabled = False
                    return {"status": "ok", "rule_id": rule_id}
                return {"status": "not_found", "rule_id": rule_id}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_status(self) -> Dict[str, Any]:
        """获取防火墙状态"""
        try:
            result = self._run_command(["iptables", "-L", "-n"])
            rules_count = len([l for l in result.stdout.split("\n") if l.strip() and not l.startswith("Chain") and not l.startswith("target")])

            return {
                "backend": self._backend,
                "status": "active",
                "rules_count": rules_count,
            }
        except Exception as e:
            return {
                "backend": self._backend,
                "status": "error",
                "message": str(e),
            }

    def save_rules(self) -> Dict[str, Any]:
        """保存当前iptables规则（持久化）"""
        try:
            # 尝试使用iptables-persistent
            result = self._run_command(
                ["iptables-save"],
            )
            if result.returncode == 0:
                logger.info("防火墙规则已保存")
                return {"status": "ok", "message": "规则已保存"}
            return {"status": "error", "message": "保存失败"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
