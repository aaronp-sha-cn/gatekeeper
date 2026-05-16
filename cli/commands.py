"""
GateKeeper - 命令定义
CLI命令处理器，解析和执行用户输入的命令
"""

import json
from typing import Dict, Any, List, Optional

from config.settings import settings
from config.logging_config import get_logger
from core.database import db_manager
from core.models import Alert, FirewallRule, TrafficLog, ScanResult, ThreatIntel
from ai_engine.vuln_scanner import VulnerabilityScanner
from ai_engine.threat_intelligence import ThreatIntelligenceManager
from ai_engine.anomaly_detector import AnomalyDetector
from network.port_scanner import PortScanner
from network.firewall import FirewallManager
from network.network_config import NetworkConfigManager
from network.packet_capture import PacketCapture

logger = get_logger("cli_commands")


class CommandHandler:
    """
    CLI命令处理器
    解析用户输入并执行对应的操作
    """

    def __init__(self):
        self._scanner = VulnerabilityScanner()
        self._intel_mgr = ThreatIntelligenceManager()
        self._detector = AnomalyDetector()
        self._port_scanner = PortScanner()
        self._firewall = FirewallManager()
        self._net_config = NetworkConfigManager()
        self._capture = PacketCapture()

        # 命令注册表
        self._commands = {
            "help": self._cmd_help,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "status": self._cmd_status,
            "version": self._cmd_version,
            # 网络命令
            "network": self._cmd_network,
            "net": self._cmd_network,
            "interfaces": self._cmd_interfaces,
            "ifconfig": self._cmd_interfaces,
            # 捕获命令
            "capture": self._cmd_capture,
            # 扫描命令
            "scan": self._cmd_scan,
            "portscan": self._cmd_portscan,
            # 防火墙命令
            "firewall": self._cmd_firewall,
            "fw": self._cmd_firewall,
            # 告警命令
            "alerts": self._cmd_alerts,
            # 威胁情报命令
            "intel": self._cmd_intel,
            "threat": self._cmd_intel,
            # AI命令
            "ai": self._cmd_ai,
            # 数据库命令
            "db": self._cmd_db,
            # VPN命令
            "vpn": self._cmd_vpn,
            # QoS命令
            "qos": self._cmd_qos,
            # DNS过滤命令
            "dns": self._cmd_dns,
            "dnsfilter": self._cmd_dns,
            # 网络隔离命令
            "isolation": self._cmd_isolation,
            "iso": self._cmd_isolation,
            # 合规检查命令
            "compliance": self._cmd_compliance,
            "comply": self._cmd_compliance,
            # 资产发现命令
            "assets": self._cmd_assets,
            "asset": self._cmd_assets,
            "discover": self._cmd_assets,
        }

    def execute(self, user_input: str) -> Dict[str, Any]:
        """
        执行用户命令

        Args:
            user_input: 用户输入的命令字符串

        Returns:
            执行结果
        """
        parts = user_input.strip().split()
        if not parts:
            return {"type": "output", "data": ""}

        command = parts[0].lower()
        args = parts[1:]

        handler = self._commands.get(command)
        if handler:
            try:
                return handler(args)
            except Exception as e:
                logger.error("命令执行失败: {}, 错误: {}".format(command, e))
                return {"type": "error", "message": str(e)}
        else:
            return {
                "type": "error",
                "message": "未知命令: {}，输入 'help' 查看帮助".format(command),
            }

    def _cmd_help(self, args: List[str]) -> Dict[str, Any]:
        """显示帮助信息"""
        help_text = """
可用命令:

  系统命令:
    help              显示帮助信息
    exit / quit       退出CLI
    status            显示系统状态
    version           显示版本信息

  网络命令:
    network status    显示网络状态
    interfaces        列出网络接口
    ifconfig          列出网络接口（别名）

  数据包捕获:
    capture start [interface]   开始捕获数据包
    capture stop                停止捕获
    capture stats               显示捕获统计

  扫描命令:
    scan <target> [ports]       漏洞扫描
    portscan <target>           端口扫描

  防火墙命令:
    firewall list               列出防火墙规则
    firewall add <args>         添加规则
    firewall remove <id>        移除规则
    firewall status             防火墙状态

  告警命令:
    alerts [count]              显示最近告警
    alerts stats                告警统计

  威胁情报:
    intel check <ip>            检查IP威胁
    intel search <query>        搜索情报
    intel stats                 情报统计

  AI引擎:
    ai status                  AI引擎状态
    ai detect                  执行异常检测

  数据库:
    db status                  数据库状态
    db stats                   数据库统计

  VPN管理:
    vpn list                   列出VPN配置
    vpn create <name> <type> <ip> <port> <range>  创建VPN配置
    vpn delete <id>            删除VPN配置
    vpn start <id>             启动VPN服务
    vpn stop <id>              停止VPN服务
    vpn clients <config_id>    查看客户端列表
    vpn add-client <config_id> <username> [public_key]  添加客户端
    vpn remove-client <client_id>  移除客户端
    vpn status                 VPN服务状态
    vpn stats                  VPN统计信息

  QoS流量整形:
    qos list                   列出QoS规则
    qos add <name> <interface> <direction> <match_type> <match_value> [priority] [bw_limit] [action]  添加规则
    qos remove <id>            删除规则
    qos enable <id>            启用规则
    qos disable <id>           禁用规则
    qos apply                  应用所有规则到系统
    qos clear                  清除tc规则
    qos stats [interface]      显示流量统计
    qos bandwidth <interface>  显示接口带宽使用
    qos preset <name> [interface]  应用预设策略 (office/gaming/balanced/strict)
    qos status                 显示tc规则状态

  DNS过滤:
    dns list                   列出DNS过滤规则
    dns add <name> <domain> [type] [category] [action]  添加规则
    dns remove <id>            删除规则
    dns enable <id>            启用规则
    dns disable <id>           禁用规则
    dns test <domain> [type]   测试域名查询
    dns stats                  DNS过滤统计
    dns logs [limit]           查看DNS查询日志
    dns clear [days]           清理日志(默认30天)

  网络隔离:
    isolation zones                    列出所有隔离区域
    isolation create-zone <name> [level] [subnet] [vlan]  创建隔离区域
    isolation delete-zone <zone_id>    删除隔离区域
    isolation rules                    列出所有隔离规则
    isolation add-rule <name> <src> <dst> [proto] [ports] [direction]  添加隔离规则
    isolation remove-rule <rule_id>    删除隔离规则
    isolation toggle-rule <rule_id> <on|off>  启用/禁用规则
    isolation check <src> <dst> [proto] [port]  检查流量是否允许
    isolation apply                    应用隔离规则到iptables
    isolation topology                 查看区域拓扑
    isolation status                   查看隔离状态
    isolation preset <name>            应用预设模板 (home/office/school)
    isolation presets                  列出可用预设

  合规检查:
    compliance run [standard]         执行完整合规检查 (cis/djcp)
    compliance category <name>        执行分类检查
    compliance score                  查看当前合规分数
    compliance report [id]            查看报告详情
    compliance reports                列出历史报告
    compliance export <id> [format]   导出报告 (json/csv/html)

  资产发现:
    assets scan <target> [type]       扫描资产 (type: quick/full/custom)
    assets stop                       停止扫描
    assets status                     扫描状态
    assets list [filters]             列出资产
    assets get <asset_id>             资产详情
    assets delete <asset_id>          删除资产
    assets stats                      资产统计
    assets history                    扫描历史
    assets export [format]            导出资产 (csv/json)
"""
        return {"type": "output", "data": help_text.strip()}

    def _cmd_exit(self, args: List[str]) -> Dict[str, Any]:
        """退出CLI"""
        return {"type": "exit", "message": "再见!"}

    def _cmd_status(self, args: List[str]) -> Dict[str, Any]:
        """显示系统状态"""
        db_health = db_manager.check_health()
        fw_status = self._firewall.get_status()
        net_stats = self._net_config.get_network_stats()

        status = {
            "version": settings.version,
            "database": db_health,
            "firewall": fw_status,
            "network": {
                "interfaces": net_stats["interface_count"],
                "total_rx_bytes": net_stats["total_rx_bytes"],
                "total_tx_bytes": net_stats["total_tx_bytes"],
            },
            "capture_running": self._capture.is_running,
        }

        return {"type": "output", "data": status}

    def _cmd_version(self, args: List[str]) -> Dict[str, Any]:
        """显示版本信息"""
        return {"type": "output", "data": "GateKeeper v{}".format(settings.version)}

    def _cmd_network(self, args: List[str]) -> Dict[str, Any]:
        """网络命令"""
        if not args or args[0] == "status":
            stats = self._net_config.get_network_stats()
            return {"type": "output", "data": stats}
        return {"type": "error", "message": "用法: network [status]"}

    def _cmd_interfaces(self, args: List[str]) -> Dict[str, Any]:
        """列出网络接口"""
        interfaces = self._net_config.get_interfaces()
        return {"type": "output", "data": {"interfaces": interfaces}}

    def _cmd_capture(self, args: List[str]) -> Dict[str, Any]:
        """数据包捕获命令"""
        if not args:
            return {"type": "error", "message": "用法: capture [start|stop|stats]"}

        action = args[0].lower()

        if action == "start":
            interface = args[1] if len(args) > 1 else settings.network.listen_interface
            result = self._capture.start_capture(interface=interface)
            return {"type": "output", "data": result}

        elif action == "stop":
            result = self._capture.stop_capture()
            return {"type": "output", "data": result}

        elif action == "stats":
            stats = self._capture.get_stats()
            return {"type": "output", "data": stats}

        return {"type": "error", "message": "用法: capture [start|stop|stats]"}

    def _cmd_scan(self, args: List[str]) -> Dict[str, Any]:
        """漏洞扫描命令"""
        if not args:
            return {"type": "error", "message": "用法: scan <target> [ports]"}

        target = args[0]
        ports = None
        if len(args) > 1:
            try:
                ports = [int(p) for p in args[1].split(",")]
            except ValueError:
                return {"type": "error", "message": "端口格式错误，使用逗号分隔"}

        result = self._scanner.start_scan(target, ports=ports)
        return {"type": "output", "data": result}

    def _cmd_portscan(self, args: List[str]) -> Dict[str, Any]:
        """端口扫描命令"""
        if not args:
            return {"type": "error", "message": "用法: portscan <target>"}

        target = args[0]
        result = self._port_scanner.scan_host(target)
        return {"type": "output", "data": result}

    def _cmd_firewall(self, args: List[str]) -> Dict[str, Any]:
        """防火墙命令"""
        if not args:
            return {"type": "error", "message": "用法: firewall [list|add|remove|status]"}

        action = args[0].lower()

        if action == "list":
            rules = self._firewall.list_rules()
            return {"type": "output", "data": {"rules": rules, "count": len(rules)}}

        elif action == "status":
            status = self._firewall.get_status()
            return {"type": "output", "data": status}

        elif action == "add":
            if len(args) < 3:
                return {"type": "error", "message": "用法: firewall add <name> <source_ip> [action]"}
            name = args[1]
            source_ip = args[2]
            action_type = args[3] if len(args) > 3 else "DROP"
            result = self._firewall.add_rule(name=name, source_ip=source_ip, action=action_type)
            return {"type": "output", "data": result}

        elif action == "remove":
            if len(args) < 2:
                return {"type": "error", "message": "用法: firewall remove <rule_id>"}
            try:
                rule_id = int(args[1])
                result = self._firewall.remove_rule(rule_id)
                return {"type": "output", "data": result}
            except ValueError:
                return {"type": "error", "message": "规则ID必须是数字"}

        return {"type": "error", "message": "用法: firewall [list|add|remove|status]"}

    def _cmd_alerts(self, args: List[str]) -> Dict[str, Any]:
        """告警命令"""
        if not args or args[0] == "stats":
            try:
                with db_manager.get_session() as session:
                    total = session.query(Alert).count()
                    new = session.query(Alert).filter_by(status="new").count()
                    critical = session.query(Alert).filter_by(level="critical").count()
                    high = session.query(Alert).filter_by(level="high").count()

                return {"type": "output", "data": {
                    "total": total,
                    "new": new,
                    "critical": critical,
                    "high": high,
                }}
            except Exception as e:
                return {"type": "error", "message": str(e)}

        try:
            count = int(args[0])
        except ValueError:
            count = 20

        try:
            with db_manager.get_session() as session:
                alerts = (
                    session.query(Alert)
                    .order_by(Alert.created_at.desc())
                    .limit(count)
                    .all()
                )
                return {"type": "output", "data": {
                    "alerts": [
                        {
                            "id": a.id,
                            "title": a.title,
                            "level": a.level.value,
                            "status": a.status.value,
                            "source": a.source,
                            "created_at": str(a.created_at),
                        }
                        for a in alerts
                    ]
                }}
        except Exception as e:
            return {"type": "error", "message": str(e)}

    def _cmd_intel(self, args: List[str]) -> Dict[str, Any]:
        """威胁情报命令"""
        if not args:
            return {"type": "error", "message": "用法: intel [check|search|stats] <value>"}

        action = args[0].lower()

        if action == "check" and len(args) > 1:
            result = self._intel_mgr.check_ip(args[1])
            return {"type": "output", "data": result}

        elif action == "search" and len(args) > 1:
            results = self._intel_mgr.search(args[1])
            return {"type": "output", "data": {"results": results, "count": len(results)}}

        elif action == "stats":
            stats = self._intel_mgr.get_statistics()
            return {"type": "output", "data": stats}

        return {"type": "error", "message": "用法: intel [check|search|stats] <value>"}

    def _cmd_ai(self, args: List[str]) -> Dict[str, Any]:
        """AI引擎命令"""
        if not args or args[0] == "status":
            stats = self._detector.get_statistics()
            return {"type": "output", "data": stats}

        if args[0] == "detect":
            result = self._detector.run_detection()
            return {"type": "output", "data": result}

        return {"type": "error", "message": "用法: ai [status|detect]"}

    def _cmd_db(self, args: List[str]) -> Dict[str, Any]:
        """数据库命令"""
        if not args or args[0] == "status":
            health = db_manager.check_health()
            return {"type": "output", "data": health}

        if args[0] == "stats":
            sizes = db_manager.get_table_sizes()
            return {"type": "output", "data": {"table_sizes": sizes}}

        return {"type": "error", "message": "用法: db [status|stats]"}

    def _cmd_vpn(self, args: List[str]) -> Dict[str, Any]:
        """VPN管理命令"""
        from security.vpn_service import get_vpn_service

        vpn_svc = get_vpn_service()

        if not args:
            return {"type": "error", "message": "用法: vpn [list|create|delete|start|stop|clients|add-client|remove-client|status|stats]"}

        action = args[0].lower()

        if action == "list":
            configs = vpn_svc.get_configs()
            return {"type": "output", "data": {"configs": configs, "total": len(configs)}}

        elif action == "create":
            if len(args) < 6:
                return {"type": "error", "message": "用法: vpn create <name> <type> <server_ip> <port> <ip_range> [dns]"}
            name = args[1]
            vpn_type = args[2]
            server_ip = args[3]
            try:
                port = int(args[4])
            except ValueError:
                return {"type": "error", "message": "端口必须是数字"}
            ip_range = args[5]
            dns = args[6] if len(args) > 6 else ""
            result = vpn_svc.create_config(
                name=name, vpn_type=vpn_type, server_ip=server_ip,
                port=port, ip_range=ip_range, dns=dns,
            )
            return {"type": "output", "data": result}

        elif action == "delete":
            if len(args) < 2:
                return {"type": "error", "message": "用法: vpn delete <config_id>"}
            try:
                config_id = int(args[1])
            except ValueError:
                return {"type": "error", "message": "配置ID必须是数字"}
            result = vpn_svc.delete_config(config_id)
            return {"type": "output", "data": result}

        elif action == "start":
            if len(args) < 2:
                return {"type": "error", "message": "用法: vpn start <config_id>"}
            try:
                config_id = int(args[1])
            except ValueError:
                return {"type": "error", "message": "配置ID必须是数字"}
            result = vpn_svc.start_service(config_id)
            return {"type": "output", "data": result}

        elif action == "stop":
            if len(args) < 2:
                return {"type": "error", "message": "用法: vpn stop <config_id>"}
            try:
                config_id = int(args[1])
            except ValueError:
                return {"type": "error", "message": "配置ID必须是数字"}
            result = vpn_svc.stop_service(config_id)
            return {"type": "output", "data": result}

        elif action == "clients":
            if len(args) < 2:
                return {"type": "error", "message": "用法: vpn clients <config_id>"}
            try:
                config_id = int(args[1])
            except ValueError:
                return {"type": "error", "message": "配置ID必须是数字"}
            clients = vpn_svc.get_clients(config_id)
            return {"type": "output", "data": {"clients": clients, "total": len(clients)}}

        elif action == "add-client":
            if len(args) < 3:
                return {"type": "error", "message": "用法: vpn add-client <config_id> <username> [public_key]"}
            try:
                config_id = int(args[1])
            except ValueError:
                return {"type": "error", "message": "配置ID必须是数字"}
            username = args[2]
            public_key = args[3] if len(args) > 3 else ""
            result = vpn_svc.add_client(config_id, username, public_key)
            return {"type": "output", "data": result}

        elif action == "remove-client":
            if len(args) < 2:
                return {"type": "error", "message": "用法: vpn remove-client <client_id>"}
            try:
                client_id = int(args[1])
            except ValueError:
                return {"type": "error", "message": "客户端ID必须是数字"}
            result = vpn_svc.remove_client(client_id)
            return {"type": "output", "data": result}

        elif action == "status":
            status = vpn_svc.get_status()
            return {"type": "output", "data": status}

        elif action == "stats":
            stats = vpn_svc.get_stats()
            return {"type": "output", "data": stats}

        return {"type": "error", "message": "用法: vpn [list|create|delete|start|stop|clients|add-client|remove-client|status|stats]"}

    def get_commands(self) -> List[str]:
        """获取所有已注册的命令"""
        return list(self._commands.keys())

    def _cmd_qos(self, args: List[str]) -> Dict[str, Any]:
        """QoS流量整形命令"""
        from security.qos_manager import get_qos_manager, QoSRule

        if not args:
            return {"type": "error", "message": "用法: qos [list|add|remove|enable|disable|apply|clear|stats|bandwidth|preset|status]"}

        action = args[0].lower()
        manager = get_qos_manager()

        if action == "list":
            rules = manager.get_rules()
            return {"type": "output", "data": {"rules": rules, "count": len(rules)}}

        elif action == "add":
            if len(args) < 6:
                return {"type": "error", "message": "用法: qos add <name> <interface> <direction> <match_type> <match_value> [priority] [bw_limit] [action]"}
            name = args[1]
            interface = args[2]
            direction = args[3]
            match_type = args[4]
            match_value = args[5]
            priority = int(args[6]) if len(args) > 6 else 50
            bw_limit = float(args[7]) if len(args) > 7 else 0
            rule_action = args[8] if len(args) > 8 else "shape"

            rule = QoSRule(
                name=name,
                interface=interface,
                direction=direction,
                match_type=match_type,
                match_value=match_value,
                priority=priority,
                bandwidth_limit=bw_limit,
                action=rule_action,
            )
            created = manager.add_rule(rule)
            return {"type": "output", "data": created.to_dict()}

        elif action == "remove":
            if len(args) < 2:
                return {"type": "error", "message": "用法: qos remove <rule_id>"}
            try:
                rule_id = int(args[1])
                success = manager.remove_rule(rule_id)
                if success:
                    return {"type": "output", "data": {"message": "规则 {} 已删除".format(rule_id)}}
                return {"type": "error", "message": "规则不存在"}
            except ValueError:
                return {"type": "error", "message": "规则ID必须是数字"}

        elif action == "enable":
            if len(args) < 2:
                return {"type": "error", "message": "用法: qos enable <rule_id>"}
            try:
                rule_id = int(args[1])
                success = manager.toggle_rule(rule_id, True)
                if success:
                    return {"type": "output", "data": {"message": "规则 {} 已启用".format(rule_id)}}
                return {"type": "error", "message": "规则不存在"}
            except ValueError:
                return {"type": "error", "message": "规则ID必须是数字"}

        elif action == "disable":
            if len(args) < 2:
                return {"type": "error", "message": "用法: qos disable <rule_id>"}
            try:
                rule_id = int(args[1])
                success = manager.toggle_rule(rule_id, False)
                if success:
                    return {"type": "output", "data": {"message": "规则 {} 已禁用".format(rule_id)}}
                return {"type": "error", "message": "规则不存在"}
            except ValueError:
                return {"type": "error", "message": "规则ID必须是数字"}

        elif action == "apply":
            result = manager.apply_rules()
            return {"type": "output", "data": result}

        elif action == "clear":
            result = manager.remove_tc_rules()
            return {"type": "output", "data": result}

        elif action == "stats":
            interface = args[1] if len(args) > 1 else None
            stats = manager.get_stats(interface=interface)
            return {"type": "output", "data": {"stats": stats, "count": len(stats)}}

        elif action == "bandwidth":
            if len(args) < 2:
                return {"type": "error", "message": "用法: qos bandwidth <interface>"}
            bw = manager.get_bandwidth_usage(args[1])
            return {"type": "output", "data": bw}

        elif action == "preset":
            if len(args) < 2:
                return {"type": "error", "message": "用法: qos preset <name> [interface]"}
            preset_name = args[1]
            interface = args[2] if len(args) > 2 else "eth0"
            result = manager.apply_preset(preset_name, interface=interface)
            return {"type": "output", "data": result}

        elif action == "status":
            interface = args[1] if len(args) > 1 else None
            status = manager.get_tc_status(interface=interface)
            return {"type": "output", "data": status}

        return {"type": "error", "message": "用法: qos [list|add|remove|enable|disable|apply|clear|stats|bandwidth|preset|status]"}

    def _cmd_isolation(self, args: List[str]) -> Dict[str, Any]:
        """网络隔离命令"""
        from security.network_isolation import get_isolation_manager

        manager = get_isolation_manager()

        if not args:
            return {"type": "error", "message": "用法: isolation [zones|create-zone|delete-zone|rules|add-rule|remove-rule|toggle-rule|check|apply|topology|status|preset|presets]"}

        action = args[0].lower()

        if action == "zones":
            zones = manager.get_zones()
            return {"type": "output", "data": {"zones": zones, "total": len(zones)}}

        elif action == "create-zone":
            if len(args) < 2:
                return {"type": "error", "message": "用法: isolation create-zone <name> [level] [subnet] [vlan]"}
            name = args[1]
            level = args[2] if len(args) > 2 else "trusted"
            subnet = args[3] if len(args) > 3 else ""
            vlan = int(args[4]) if len(args) > 4 else None
            result = manager.create_zone({
                "name": name,
                "security_level": level,
                "subnet_cidr": subnet,
                "vlan_id": vlan,
            })
            return {"type": "output", "data": result}

        elif action == "delete-zone":
            if len(args) < 2:
                return {"type": "error", "message": "用法: isolation delete-zone <zone_id>"}
            result = manager.delete_zone(args[1])
            return {"type": "output", "data": result}

        elif action == "rules":
            rules = manager.get_rules()
            return {"type": "output", "data": {"rules": rules, "total": len(rules)}}

        elif action == "add-rule":
            if len(args) < 4:
                return {"type": "error", "message": "用法: isolation add-rule <name> <src_zone> <dst_zone> [proto] [ports] [direction]"}
            name = args[1]
            src = args[2]
            dst = args[3]
            proto = args[4].split(",") if len(args) > 4 else ["any"]
            ports = [int(p) for p in args[5].split(",")] if len(args) > 5 else []
            direction = args[6] if len(args) > 6 else "bidirectional"
            result = manager.add_rule({
                "name": name,
                "source_zone": src,
                "dest_zone": dst,
                "allowed_protocols": proto,
                "allowed_ports": ports,
                "direction": direction,
            })
            return {"type": "output", "data": result}

        elif action == "remove-rule":
            if len(args) < 2:
                return {"type": "error", "message": "用法: isolation remove-rule <rule_id>"}
            result = manager.remove_rule(args[1])
            return {"type": "output", "data": result}

        elif action == "toggle-rule":
            if len(args) < 3:
                return {"type": "error", "message": "用法: isolation toggle-rule <rule_id> <on|off>"}
            enabled = args[2].lower() in ("on", "true", "1", "enable")
            result = manager.toggle_rule(args[1], enabled)
            return {"type": "output", "data": result}

        elif action == "check":
            if len(args) < 3:
                return {"type": "error", "message": "用法: isolation check <src_zone> <dst_zone> [proto] [port]"}
            src = args[1]
            dst = args[2]
            proto = args[3] if len(args) > 3 else "tcp"
            port = int(args[4]) if len(args) > 4 else 0
            result = manager.check_traffic(src, dst, proto, port)
            return {"type": "output", "data": result}

        elif action == "apply":
            result = manager.apply_isolation()
            return {"type": "output", "data": result}

        elif action == "topology":
            topo = manager.get_topology()
            return {"type": "output", "data": topo}

        elif action == "status":
            status = manager.get_status()
            return {"type": "output", "data": status}

        elif action == "preset":
            if len(args) < 2:
                return {"type": "error", "message": "用法: isolation preset <name>"}
            result = manager.apply_preset(args[1])
            return {"type": "output", "data": result}

        elif action == "presets":
            presets = manager.get_presets()
            return {"type": "output", "data": presets}

        return {"type": "error", "message": "用法: isolation [zones|create-zone|delete-zone|rules|add-rule|remove-rule|toggle-rule|check|apply|topology|status|preset|presets]"}

    def _cmd_dns(self, args: List[str]) -> Dict[str, Any]:
        """DNS过滤命令"""
        from security.dns_filter import get_dns_filter

        if not args:
            return {"type": "error", "message": "用法: dns [list|add|remove|enable|disable|test|stats|logs|clear]"}

        action = args[0].lower()
        engine = get_dns_filter()

        if action == "list":
            rule_type = args[1] if len(args) > 1 else None
            category = args[2] if len(args) > 2 else None
            rules = engine.get_rules(rule_type=rule_type, category=category)
            return {"type": "output", "data": {"rules": rules, "total": len(rules)}}

        elif action == "add":
            if len(args) < 3:
                return {"type": "error", "message": "用法: dns add <name> <domain> [type] [category] [action]"}
            name = args[1]
            domain = args[2]
            rule_type = args[3] if len(args) > 3 else "blacklist"
            category = args[4] if len(args) > 4 else "custom"
            action_type = args[5] if len(args) > 5 else "block"
            rule = engine.add_rule(
                name=name, domain=domain, rule_type=rule_type,
                category=category, action=action_type,
            )
            return {"type": "output", "data": rule.to_dict()}

        elif action == "remove":
            if len(args) < 2:
                return {"type": "error", "message": "用法: dns remove <rule_id>"}
            try:
                rule_id = int(args[1])
            except ValueError:
                return {"type": "error", "message": "规则ID必须是数字"}
            success = engine.remove_rule(rule_id)
            if success:
                return {"type": "output", "data": {"message": "规则 {} 已删除".format(rule_id)}}
            return {"type": "error", "message": "规则不存在"}

        elif action == "enable":
            if len(args) < 2:
                return {"type": "error", "message": "用法: dns enable <rule_id>"}
            try:
                rule_id = int(args[1])
            except ValueError:
                return {"type": "error", "message": "规则ID必须是数字"}
            success = engine.toggle_rule(rule_id, True)
            if success:
                return {"type": "output", "data": {"message": "规则 {} 已启用".format(rule_id)}}
            return {"type": "error", "message": "规则不存在"}

        elif action == "disable":
            if len(args) < 2:
                return {"type": "error", "message": "用法: dns disable <rule_id>"}
            try:
                rule_id = int(args[1])
            except ValueError:
                return {"type": "error", "message": "规则ID必须是数字"}
            success = engine.toggle_rule(rule_id, False)
            if success:
                return {"type": "output", "data": {"message": "规则 {} 已禁用".format(rule_id)}}
            return {"type": "error", "message": "规则不存在"}

        elif action == "test":
            if len(args) < 2:
                return {"type": "error", "message": "用法: dns test <domain> [query_type]"}
            domain = args[1]
            query_type = args[2] if len(args) > 2 else "A"
            result = engine.inspect_query(domain=domain, query_type=query_type)
            return {"type": "output", "data": result}

        elif action == "stats":
            stats = engine.get_stats()
            return {"type": "output", "data": stats}

        elif action == "logs":
            limit = 50
            if len(args) > 1:
                try:
                    limit = int(args[1])
                except ValueError:
                    return {"type": "error", "message": "limit必须是数字"}
            logs = engine.get_logs(limit=limit)
            return {"type": "output", "data": logs}

        elif action == "clear":
            days = 30
            if len(args) > 1:
                try:
                    days = int(args[1])
                except ValueError:
                    return {"type": "error", "message": "天数必须是数字"}
            result = engine.clear_logs(days=days)
            return {"type": "output", "data": result}

        return {"type": "error", "message": "用法: dns [list|add|remove|enable|disable|test|stats|logs|clear]"}

    def _cmd_assets(self, args: List[str]) -> Dict[str, Any]:
        """资产发现命令"""
        from security.asset_discovery import get_asset_discovery

        if not args:
            return {"type": "error", "message": "用法: assets [scan|stop|status|list|get|delete|stats|history|export]"}

        action = args[0].lower()
        manager = get_asset_discovery()

        if action == "scan":
            if len(args) < 2:
                return {"type": "error", "message": "用法: assets scan <target> [type]"}
            target = args[1]
            scan_type = args[2] if len(args) > 2 else "quick"
            if scan_type not in ("quick", "full", "custom"):
                return {"type": "error", "message": "扫描类型: quick, full, custom"}
            result = manager.start_scan(target, scan_type=scan_type)
            return {"type": "output", "data": result}

        elif action == "stop":
            result = manager.stop_scan()
            return {"type": "output", "data": result}

        elif action == "status":
            result = manager.get_scan_status()
            return {"type": "output", "data": result}

        elif action == "list":
            result = manager.get_assets(page=1, page_size=50)
            return {"type": "output", "data": {
                "total": result["total"],
                "assets": result["assets"],
            }}

        elif action == "get":
            if len(args) < 2:
                return {"type": "error", "message": "用法: assets get <asset_id>"}
            result = manager.get_asset(args[1])
            return {"type": "output", "data": result}

        elif action == "delete":
            if len(args) < 2:
                return {"type": "error", "message": "用法: assets delete <asset_id>"}
            result = manager.delete_asset(args[1])
            return {"type": "output", "data": result}

        elif action == "stats":
            result = manager.get_stats()
            return {"type": "output", "data": result}

        elif action == "history":
            result = manager.get_scan_history()
            return {"type": "output", "data": result}

        elif action == "export":
            fmt = args[1] if len(args) > 1 else "csv"
            result = manager.export_assets(format=fmt)
            if result["status"] == "ok":
                return {"type": "output", "data": {
                    "message": "导出完成",
                    "format": fmt,
                    "content": result["data"][:500] + ("..." if len(result["data"]) > 500 else ""),
                }}
            return {"type": "output", "data": result}

        return {"type": "error", "message": "用法: assets [scan|stop|status|list|get|delete|stats|history|export]"}

    def _cmd_compliance(self, args: List[str]) -> Dict[str, Any]:
        """合规检查命令"""
        from security.compliance_checker import get_compliance_checker

        if not args:
            return {"type": "error", "message": "用法: compliance [run|category|score|report|reports|export]"}

        action = args[0].lower()
        checker = get_compliance_checker()

        if action == "run":
            standard = args[1] if len(args) > 1 else "cis"
            if standard not in ("cis", "djcp"):
                return {"type": "error", "message": "支持的标准: cis, djcp"}

            if checker.is_checking():
                return {"type": "error", "message": "合规检查正在进行中"}

            report = checker.run_full_check(standard)
            return {"type": "output", "data": report.to_dict()}

        elif action == "category":
            if len(args) < 2:
                return {"type": "error", "message": "用法: compliance category <名称>"}
            category = args[1]
            standard = args[2] if len(args) > 2 else "cis"
            checks = checker.run_category_check(category, standard)
            return {"type": "output", "data": {
                "category": category,
                "checks": [c.to_dict() for c in checks],
                "total": len(checks),
                "passed": sum(1 for c in checks if c.status == "pass"),
                "failed": sum(1 for c in checks if c.status == "fail"),
                "warnings": sum(1 for c in checks if c.status == "warning"),
            }}

        elif action == "score":
            score = checker.get_score()
            latest = checker.get_latest_report()
            return {"type": "output", "data": {
                "score": score,
                "latest_report": latest,
            }}

        elif action == "report":
            if len(args) < 2:
                # 返回最新报告
                report = checker.get_latest_report()
                if report:
                    return {"type": "output", "data": report}
                return {"type": "error", "message": "暂无报告"}
            report_id = args[1]
            reports = checker.get_reports()
            for r in reports:
                if r["id"] == report_id:
                    return {"type": "output", "data": r}
            return {"type": "error", "message": "报告不存在: {}".format(report_id)}

        elif action == "reports":
            reports = checker.get_reports()
            return {"type": "output", "data": {
                "total": len(reports),
                "reports": reports,
            }}

        elif action == "export":
            if len(args) < 2:
                return {"type": "error", "message": "用法: compliance export <report_id> [format]"}
            report_id = args[1]
            fmt = args[2] if len(args) > 2 else "json"
            content = checker.export_report(report_id, format=fmt)
            if content is None:
                return {"type": "error", "message": "报告不存在或导出失败"}
            return {"type": "output", "data": {
                "message": "导出完成",
                "format": fmt,
                "report_id": report_id,
                "content": content,
            }}

        return {"type": "error", "message": "用法: compliance [run|category|score|report|reports|export]"}

    def _cmd_siem(self, args: List[str]) -> Dict[str, Any]:
        """SIEM安全信息管理命令"""
        from security.siem_engine import get_siem_engine

        if not args:
            return {"type": "error", "message": "用法: siem [collect|correlate|stats|events|timeline|chain|rules|export]"}

        action = args[0].lower()
        engine = get_siem_engine()

        if action == "collect":
            events = engine.collect_events()
            return {"type": "output", "data": {
                "message": "事件收集完成",
                "event_count": len(events),
                "sources": list(set(e.source for e in events)),
            }}

        elif action == "correlate":
            engine.collect_events()
            alerts = engine.correlate_events()
            return {"type": "output", "data": {
                "message": "关联分析完成",
                "alert_count": len(alerts),
                "alerts": alerts,
            }}

        elif action == "stats":
            stats = engine.get_stats()
            return {"type": "output", "data": stats}

        elif action == "events":
            source = args[1] if len(args) > 1 else None
            severity = args[2] if len(args) > 2 else None
            page = int(args[3]) if len(args) > 3 else 1
            result = engine.get_events(source=source, severity=severity, page=page)
            return {"type": "output", "data": {
                "total": result["total"],
                "page": result["page"],
                "total_pages": result["total_pages"],
                "events": result["events"],
            }}

        elif action == "timeline":
            hours = int(args[1]) if len(args) > 1 else 24
            timeline = engine.get_timeline(hours=hours)
            return {"type": "output", "data": {
                "hours": hours,
                "timeline": timeline,
            }}

        elif action == "chain":
            if len(args) < 2:
                return {"type": "error", "message": "用法: siem chain <ip>"}
            ip = args[1]
            chain = engine.get_attack_chain(ip)
            return {"type": "output", "data": chain}

        elif action == "rules":
            rules = engine.get_correlation_rules()
            return {"type": "output", "data": {
                "total": len(rules),
                "rules": rules,
            }}

        elif action == "export":
            fmt = args[1] if len(args) > 1 else "json"
            content = engine.export_events(format=fmt)
            if fmt == "json":
                try:
                    parsed = json.loads(content)
                    return {"type": "output", "data": {
                        "message": "导出完成",
                        "format": fmt,
                        "event_count": len(parsed),
                        "events": parsed,
                    }}
                except Exception:
                    return {"type": "output", "data": {"message": "导出完成", "format": fmt, "content": content}}
            else:
                return {"type": "output", "data": {"message": "导出完成", "format": fmt, "content": content}}

        return {"type": "error", "message": "用法: siem [collect|correlate|stats|events|timeline|chain|rules|export]"}
