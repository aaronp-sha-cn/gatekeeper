"""
动态路由模块 - 集成FRRouting实现OSPF/BGP
通过vtysh命令行接口管理FRR守护进程
"""

import subprocess
import json
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional, Any
from enum import Enum
from config.logging_config import get_logger

logger = get_logger("dynamic_routing")


class RoutingProtocol(Enum):
    """路由协议类型"""
    OSPF = "ospf"
    OSPF6 = "ospf6"
    BGP = "bgp"
    RIP = "rip"
    RIPNG = "ripng"
    ISIS = "isis"


class OSPFAreaType(Enum):
    """OSPF区域类型"""
    NORMAL = "normal"
    STUB = "stub"
    NSSA = "nssa"


@dataclass
class OSPFConfig:
    """OSPF配置"""
    router_id: str  # 路由器ID，如1.1.1.1
    areas: List[dict]  # 区域配置 [{area_id: "0", networks: ["10.0.0.0/8"], type: "normal"}]
    redistribute: List[str]  # 重分发: ["connected", "static", "bgp"]
    passive_interfaces: List[str]  # 被动接口
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "router_id": self.router_id,
            "areas": self.areas,
            "redistribute": self.redistribute,
            "passive_interfaces": self.passive_interfaces,
            "enabled": self.enabled,
        }


@dataclass
class BGPNeighbor:
    """BGP邻居"""
    ip: str
    remote_as: int
    description: str = ""
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "remote_as": self.remote_as,
            "description": self.description,
            "enabled": self.enabled,
        }


@dataclass
class BGPConfig:
    """BGP配置"""
    local_as: int  # 本地AS号
    router_id: str
    neighbors: List[BGPNeighbor]
    networks: List[str]  # 宣告的网络
    redistribute: List[str]  # 重分发
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "local_as": self.local_as,
            "router_id": self.router_id,
            "neighbors": [n.to_dict() for n in self.neighbors],
            "networks": self.networks,
            "redistribute": self.redistribute,
            "enabled": self.enabled,
        }


@dataclass
class RouteEntry:
    """路由条目"""
    destination: str  # 目的网络
    gateway: str  # 下一跳
    interface: str
    protocol: str  # ospf/bgp/static/connected
    metric: int
    preference: int

    def to_dict(self) -> dict:
        return {
            "destination": self.destination,
            "gateway": self.gateway,
            "interface": self.interface,
            "protocol": self.protocol,
            "metric": self.metric,
            "preference": self.preference,
        }


class DynamicRoutingManager:
    """动态路由管理器"""

    def __init__(self):
        self._lock = threading.Lock()
        self._frr_enabled = False
        self._ospf_config: Optional[OSPFConfig] = None
        self._bgp_config: Optional[BGPConfig] = None
        self._check_frr_available()

    def _check_frr_available(self) -> bool:
        """检查FRR是否可用，未安装则自动安装"""
        import shutil
        try:
            result = subprocess.run(
                ["vtysh", "-c", "show version"],
                capture_output=True,
                timeout=5,
                text=True
            )
            self._frr_enabled = result.returncode == 0
            if self._frr_enabled:
                logger.info("FRRouting检测成功")
            return self._frr_enabled
        except FileNotFoundError:
            logger.info("FRRouting 未安装，正在自动安装...")
            try:
                subprocess.run(
                    ["apt-get", "install", "-y",
                     "-o", "DPkg::Options::=--force-confdef",
                     "-o", "DPkg::Options::=--force-confold",
                     "frr", "frr-pythontools"],
                    capture_output=True, timeout=120,
                )
                result = subprocess.run(
                    ["vtysh", "-c", "show version"],
                    capture_output=True, timeout=5, text=True,
                )
                if result.returncode == 0:
                    self._frr_enabled = True
                    logger.info("FRRouting 安装成功")
                    return True
            except Exception as e:
                logger.warning("自动安装 FRRouting 失败: %s", e)
            self._frr_enabled = False
            return False
        except Exception as e:
            self._frr_enabled = False
            logger.debug("FRRouting不可用: {}".format(e))
            return False

    def _run_vtysh(self, commands: List[str]) -> tuple:
        """
        执行vtysh命令

        Args:
            commands: 命令列表

        Returns:
            (return_code, stdout, stderr)
        """
        cmd = ["vtysh"]
        for c in commands:
            cmd.extend(["-c", c])
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30,
                text=True
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error("vtysh命令超时")
            return -1, "", "Command timeout"
        except Exception as e:
            logger.error("vtysh命令执行失败: {}".format(e))
            return -1, "", str(e)

    # ==================== OSPF管理 ====================

    def configure_ospf(self, config: OSPFConfig) -> bool:
        """
        配置OSPF

        Args:
            config: OSPF配置对象

        Returns:
            是否成功
        """
        with self._lock:
            commands = [
                "configure terminal",
                "router ospf",
                "ospf router-id {}".format(config.router_id),
            ]

            # 配置区域和网络
            for area in config.areas:
                for network in area.get("networks", []):
                    commands.append("network {} area {}".format(network, area["area_id"]))

            # 配置重分发
            for redist in config.redistribute:
                commands.append("redistribute {}".format(redist))

            # 配置被动接口
            for iface in config.passive_interfaces:
                commands.append("passive-interface {}".format(iface))

            commands.append("end")
            commands.append("write")

            ret, out, err = self._run_vtysh(commands)
            if ret == 0:
                self._ospf_config = config
                logger.info("OSPF配置成功: router-id={}".format(config.router_id))
                return True
            else:
                logger.error("OSPF配置失败: {}".format(err))
                return False

    def get_ospf_status(self) -> dict:
        """
        获取OSPF状态

        Returns:
            状态字典
        """
        ret, out, err = self._run_vtysh(["show ip ospf"])
        return {
            "enabled": self._ospf_config is not None and self._ospf_config.enabled,
            "running": "OSPF Routing Process" in out if ret == 0 else False,
            "output": out if ret == 0 else err,
            "config": self._ospf_config.to_dict() if self._ospf_config else None,
        }

    def get_ospf_neighbors(self) -> List[dict]:
        """
        获取OSPF邻居列表

        Returns:
            邻居列表
        """
        ret, out, err = self._run_vtysh(["show ip ospf neighbor"])
        neighbors = []
        if ret == 0:
            for line in out.split("\n"):
                if line.strip() and not line.startswith("Neighbor ID") and not line.startswith("---"):
                    parts = line.split()
                    if len(parts) >= 6:
                        neighbors.append({
                            "neighbor_id": parts[0],
                            "priority": parts[1],
                            "state": parts[2],
                            "dead_time": parts[3],
                            "address": parts[4],
                            "interface": parts[5],
                        })
        return neighbors

    def get_ospf_database(self) -> dict:
        """
        获取OSPF数据库

        Returns:
            数据库信息
        """
        ret, out, err = self._run_vtysh(["show ip ospf database"])
        return {"output": out if ret == 0 else err}

    def get_ospf_interfaces(self) -> List[dict]:
        """
        获取OSPF接口信息

        Returns:
            接口列表
        """
        ret, out, err = self._run_vtysh(["show ip ospf interface"])
        interfaces = []
        if ret == 0:
            current_iface = None
            for line in out.split("\n"):
                line = line.strip()
                if line and not line.startswith(" "):
                    # 新接口
                    if current_iface:
                        interfaces.append(current_iface)
                    current_iface = {
                        "name": line.split()[0] if line.split() else line,
                        "state": "",
                        "area": "",
                        "cost": "",
                    }
                elif current_iface and ":" in line:
                    # 属性行
                    key_val = line.split(":", 1)
                    if len(key_val) == 2:
                        key = key_val[0].strip().lower()
                        val = key_val[1].strip()
                        if "state" in key:
                            current_iface["state"] = val
                        elif "area" in key:
                            current_iface["area"] = val
                        elif "cost" in key:
                            current_iface["cost"] = val
            if current_iface:
                interfaces.append(current_iface)
        return interfaces

    def disable_ospf(self) -> bool:
        """
        禁用OSPF

        Returns:
            是否成功
        """
        with self._lock:
            ret, out, err = self._run_vtysh([
                "configure terminal",
                "no router ospf",
                "end",
                "write"
            ])
            if ret == 0:
                if self._ospf_config:
                    self._ospf_config.enabled = False
                logger.info("OSPF已禁用")
                return True
            return False

    # ==================== BGP管理 ====================

    def configure_bgp(self, config: BGPConfig) -> bool:
        """
        配置BGP

        Args:
            config: BGP配置对象

        Returns:
            是否成功
        """
        with self._lock:
            commands = [
                "configure terminal",
                "router bgp {}".format(config.local_as),
                "bgp router-id {}".format(config.router_id),
            ]

            # 配置邻居
            for neighbor in config.neighbors:
                if neighbor.enabled:
                    commands.append("neighbor {} remote-as {}".format(neighbor.ip, neighbor.remote_as))
                    if neighbor.description:
                        commands.append("neighbor {} description {}".format(neighbor.ip, neighbor.description))

            # 宣告网络
            for network in config.networks:
                commands.append("network {}".format(network))

            # 重分发
            for redist in config.redistribute:
                commands.append("redistribute {}".format(redist))

            commands.append("end")
            commands.append("write")

            ret, out, err = self._run_vtysh(commands)
            if ret == 0:
                self._bgp_config = config
                logger.info("BGP配置成功: AS={}".format(config.local_as))
                return True
            else:
                logger.error("BGP配置失败: {}".format(err))
                return False

    def get_bgp_status(self) -> dict:
        """
        获取BGP状态

        Returns:
            状态字典
        """
        ret, out, err = self._run_vtysh(["show ip bgp summary"])
        return {
            "enabled": self._bgp_config is not None and self._bgp_config.enabled,
            "running": "BGP router identifier" in out if ret == 0 else False,
            "output": out if ret == 0 else err,
            "config": self._bgp_config.to_dict() if self._bgp_config else None,
        }

    def get_bgp_neighbors(self) -> List[dict]:
        """
        获取BGP邻居状态

        Returns:
            邻居列表
        """
        ret, out, err = self._run_vtysh(["show ip bgp summary"])
        neighbors = []
        if ret == 0:
            for line in out.split("\n"):
                line = line.strip()
                if line and not line.startswith("BGP") and not line.startswith("Neighbor") and not line.startswith("---"):
                    parts = line.split()
                    if len(parts) >= 10:
                        state_pfx = parts[9]
                        is_up = state_pfx.isdigit()
                        neighbors.append({
                            "neighbor": parts[0],
                            "version": parts[1],
                            "as": parts[2],
                            "msg_rcvd": parts[3],
                            "msg_sent": parts[4],
                            "tbl_ver": parts[5],
                            "in_q": parts[6],
                            "out_q": parts[7],
                            "up_down": parts[8],
                            "state_pfxrcd": state_pfx,
                            "is_up": is_up,
                        })
        return neighbors

    def get_bgp_routes(self) -> List[dict]:
        """
        获取BGP路由表

        Returns:
            路由列表
        """
        ret, out, err = self._run_vtysh(["show ip bgp"])
        routes = []
        if ret == 0:
            for line in out.split("\n"):
                line = line.strip()
                if line and not line.startswith("BGP table version") and not line.startswith("Total number"):
                    routes.append({"line": line})
        return routes

    def get_bgp_advertised_routes(self, neighbor_ip: str = None) -> List[dict]:
        """
        获取BGP宣告的路由

        Args:
            neighbor_ip: 邻居IP，如果指定则显示向该邻居宣告的路由

        Returns:
            路由列表
        """
        if neighbor_ip:
            ret, out, err = self._run_vtysh([
                "show ip bgp neighbors {} advertised-routes".format(neighbor_ip)
            ])
        else:
            ret, out, err = self._run_vtysh(["show ip bgp"])

        routes = []
        if ret == 0:
            for line in out.split("\n"):
                if line.strip():
                    routes.append({"line": line.strip()})
        return routes

    def disable_bgp(self) -> bool:
        """
        禁用BGP

        Returns:
            是否成功
        """
        with self._lock:
            local_as = self._bgp_config.local_as if self._bgp_config else ""
            cmd = "no router bgp {}".format(local_as) if local_as else "no router bgp"
            ret, out, err = self._run_vtysh([
                "configure terminal",
                cmd,
                "end",
                "write"
            ])
            if ret == 0:
                if self._bgp_config:
                    self._bgp_config.enabled = False
                logger.info("BGP已禁用")
                return True
            return False

    # ==================== 路由表管理 ====================

    def get_routing_table(self, protocol: str = None) -> List[dict]:
        """
        获取路由表

        Args:
            protocol: 协议过滤 (ospf/bgp/static/connected)

        Returns:
            路由条目列表
        """
        if protocol:
            ret, out, err = self._run_vtysh(["show ip route {}".format(protocol)])
        else:
            ret, out, err = self._run_vtysh(["show ip route"])

        routes = []
        if ret == 0:
            for line in out.split("\n"):
                line = line.strip()
                # 解析路由条目
                # 格式: O   10.0.0.0/8 [110/2] via 192.168.1.1, eth0, 00:00:10
                if line and (line.startswith("O") or line.startswith("B") or
                             line.startswith("S") or line.startswith("C") or
                             line.startswith("R") or line.startswith("D")):
                    routes.append({"raw": line})
        return routes

    def get_route_summary(self) -> dict:
        """
        获取路由摘要

        Returns:
            摘要信息
        """
        ret, out, err = self._run_vtysh(["show ip route summary"])
        return {"output": out if ret == 0 else err}

    def get_rib(self) -> List[dict]:
        """
        获取RIB(路由信息库)

        Returns:
            RIB条目列表
        """
        return self.get_routing_table()

    # ==================== 服务管理 ====================

    def start_frr_services(self) -> bool:
        """
        启动FRR服务

        Returns:
            是否成功
        """
        try:
            result = subprocess.run(
                ["systemctl", "start", "frr"],
                capture_output=True,
                timeout=30,
                text=True
            )
            if result.returncode == 0:
                self._frr_enabled = True
                logger.info("FRR服务已启动")
                return True
            else:
                logger.error("启动FRR失败: {}".format(result.stderr))
                return False
        except Exception as e:
            logger.error("启动FRR失败: {}".format(e))
            return False

    def stop_frr_services(self) -> bool:
        """
        停止FRR服务

        Returns:
            是否成功
        """
        try:
            result = subprocess.run(
                ["systemctl", "stop", "frr"],
                capture_output=True,
                timeout=30,
                text=True
            )
            if result.returncode == 0:
                self._frr_enabled = False
                logger.info("FRR服务已停止")
                return True
            else:
                logger.error("停止FRR失败: {}".format(result.stderr))
                return False
        except Exception as e:
            logger.error("停止FRR失败: {}".format(e))
            return False

    def restart_frr_services(self) -> bool:
        """
        重启FRR服务

        Returns:
            是否成功
        """
        try:
            result = subprocess.run(
                ["systemctl", "restart", "frr"],
                capture_output=True,
                timeout=30,
                text=True
            )
            if result.returncode == 0:
                self._frr_enabled = True
                logger.info("FRR服务已重启")
                return True
            else:
                logger.error("重启FRR失败: {}".format(result.stderr))
                return False
        except Exception as e:
            logger.error("重启FRR失败: {}".format(e))
            return False

    def get_frr_status(self) -> dict:
        """
        获取FRR服务状态

        Returns:
            状态字典
        """
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "frr"],
                capture_output=True,
                timeout=5,
                text=True
            )
            is_active = result.returncode == 0

            # 获取各守护进程状态
            daemons_status = {}
            for daemon in ["zebra", "ospfd", "bgpd", "ospf6d", "ripd", "ripngd", "isisd"]:
                daemon_result = subprocess.run(
                    ["systemctl", "is-active", daemon],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                daemons_status[daemon] = daemon_result.returncode == 0

            return {
                "active": is_active,
                "daemons": daemons_status,
            }
        except Exception as e:
            logger.error("获取FRR状态失败: {}".format(e))
            return {"active": False, "daemons": {}}

    def get_status(self) -> dict:
        """
        获取整体状态

        Returns:
            状态字典
        """
        return {
            "frr_available": self._frr_enabled,
            "frr_status": self.get_frr_status(),
            "ospf": self.get_ospf_status(),
            "bgp": self.get_bgp_status(),
        }

    def get_version(self) -> str:
        """
        获取FRR版本

        Returns:
            版本字符串
        """
        ret, out, err = self._run_vtysh(["show version"])
        if ret == 0:
            # 提取版本信息
            for line in out.split("\n"):
                if "FRRouting" in line or "version" in line.lower():
                    return line.strip()
        return "Unknown"


# 单例
_dynamic_routing_manager: Optional[DynamicRoutingManager] = None


def get_dynamic_routing() -> DynamicRoutingManager:
    """获取动态路由管理器单例"""
    global _dynamic_routing_manager
    if _dynamic_routing_manager is None:
        _dynamic_routing_manager = DynamicRoutingManager()
    return _dynamic_routing_manager
