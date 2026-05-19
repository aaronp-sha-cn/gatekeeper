"""
GateKeeper - 网络配置命令
CLI中网络相关的扩展命令
"""

from typing import Dict, Any, List

from config.logging_config import get_logger
from network.network_config import NetworkConfigManager

logger = get_logger("cli_network_commands")


class NetworkCommands:
    """
    网络配置命令集合
    提供更详细的网络管理命令
    """

    def __init__(self):
        self._net_config = NetworkConfigManager()

    def cmd_show_interface(self, args: List[str]) -> Dict[str, Any]:
        """显示指定接口详情"""
        if not args:
            interfaces = self._net_config.get_interfaces()
            return {
                "type": "output",
                "data": {"interfaces": interfaces}
            }

        iface_name = args[0]
        iface = self._net_config.get_interface_by_name(iface_name)
        if iface:
            return {"type": "output", "data": iface}
        return {"type": "error", "message": "接口不存在: {}".format(iface_name)}

    def cmd_set_promisc(self, args: List[str]) -> Dict[str, Any]:
        """设置混杂模式"""
        if len(args) < 2:
            return {"type": "error", "message": "用法: promisc <interface> <on|off>"}

        iface_name = args[0]
        enable = args[1].lower() in ("on", "true", "1", "yes")
        result = self._net_config.set_interface_promisc(iface_name, enable)
        return {"type": "output", "data": result}

    def cmd_show_routes(self, args: List[str]) -> Dict[str, Any]:
        """显示路由表"""
        routes = self._net_config.get_routing_table()
        return {"type": "output", "data": {"routes": routes}}

    def cmd_show_dns(self, args: List[str]) -> Dict[str, Any]:
        """显示DNS配置"""
        dns = self._net_config.get_dns_config()
        return {"type": "output", "data": dns}

    def cmd_interface_up(self, args: List[str]) -> Dict[str, Any]:
        """启用接口"""
        if not args:
            return {"type": "error", "message": "用法: ifup <interface>"}
        result = self._net_config.set_interface_up(args[0])
        return {"type": "output", "data": result}

    def cmd_interface_down(self, args: List[str]) -> Dict[str, Any]:
        """禁用接口"""
        if not args:
            return {"type": "error", "message": "用法: ifdown <interface>"}
        result = self._net_config.set_interface_down(args[0])
        return {"type": "output", "data": result}
