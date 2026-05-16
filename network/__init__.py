"""
GateKeeper - 网络模块
提供数据包捕获、防火墙管理、端口扫描、网络配置、协议解析和动态路由功能
"""


def __getattr__(name):
    """延迟导入，避免循环依赖"""
    _imports = {
        "PacketCapture": ("network.packet_capture", "PacketCapture"),
        "FirewallManager": ("network.firewall", "FirewallManager"),
        "PortScanner": ("network.port_scanner", "PortScanner"),
        "NetworkConfigManager": ("network.network_config", "NetworkConfigManager"),
        "ProtocolParser": ("network.protocol_parser", "ProtocolParser"),
        "DynamicRoutingManager": ("network.dynamic_routing", "DynamicRoutingManager"),
        "get_dynamic_routing": ("network.dynamic_routing", "get_dynamic_routing"),
    }
    if name in _imports:
        import importlib
        mod_path, attr = _imports[name]
        mod = importlib.import_module(mod_path)
        return getattr(mod, attr)
    raise AttributeError("module 'network' has no attribute '{}'".format(name))


__all__ = [
    "PacketCapture",
    "FirewallManager",
    "PortScanner",
    "NetworkConfigManager",
    "ProtocolParser",
    "DynamicRoutingManager",
    "get_dynamic_routing",
]
