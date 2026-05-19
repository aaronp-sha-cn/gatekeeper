"""
双出口接入模块 - 多WAN接入、策略路由、负载均衡、故障切换
实现企业级双出口网络接入管理
"""

import os
import re
import subprocess
import threading
import time
import json
import uuid
import ipaddress
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from enum import Enum

from config.logging_config import get_logger

logger = get_logger("dual_wan")


def _validate_interface_name(name):
    """验证接口名称，仅允许字母、数字、下划线和连字符"""
    if not re.match(r'^[a-zA-Z0-9_\-]+$', name):
        raise ValueError("无效的接口名: {}".format(name))


def _validate_ip_address(addr):
    """验证IP地址格式"""
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        raise ValueError("无效的IP地址: {}".format(addr))


def _validate_protocol(proto):
    """验证协议类型"""
    if proto.upper() not in ('TCP', 'UDP', 'ICMP', 'ALL'):
        raise ValueError("无效的协议: {}".format(proto))


class WANStatus(Enum):
    """WAN接口状态枚举"""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class LoadBalanceMode(Enum):
    """负载均衡模式枚举"""
    FAILOVER = "failover"      # 主备模式
    ROUND_ROBIN = "round_robin"  # 轮询
    WEIGHTED = "weighted"       # 加权
    SOURCE_IP = "source_ip"     # 基于源IP哈希


@dataclass
class WANInterface:
    """WAN接口配置"""
    id: str
    name: str  # 接口名，如eth0、ppp0
    description: str = ""
    weight: int = 1  # 权重（加权负载均衡时使用）
    priority: int = 1  # 优先级（主备模式时使用，数字越小优先级越高）
    enabled: bool = True
    is_primary: bool = False
    gateway: str = ""
    ip_address: str = ""
    status: str = WANStatus.UNKNOWN.value
    last_check: str = ""
    latency_ms: float = 0.0
    packet_loss: float = 0.0
    bandwidth_mbps: float = 0.0
    check_targets: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    # 故障计数器
    consecutive_failures: int = 0
    consecutive_successes: int = 0


@dataclass
class PolicyRouteRule:
    """策略路由规则"""
    id: str
    name: str
    source_ip: str  # 源IP或网段
    wan_interface: str  # 使用的WAN接口ID
    dest_ip: str = ""  # 目标IP或网段（空表示任意）
    protocol: str = ""  # tcp/udp/icmp/空表示任意
    dest_port: int = 0  # 目标端口
    enabled: bool = True
    hit_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    description: str = ""


@dataclass
class DualWANConfig:
    """双出口配置"""
    enabled: bool = False
    load_balance_mode: str = LoadBalanceMode.FAILOVER.value
    health_check_interval: int = 10  # 秒
    health_check_timeout: int = 3  # 秒
    failover_threshold: int = 3  # 连续失败次数触发切换
    recovery_threshold: int = 2  # 连续成功次数恢复
    auto_failover: bool = True  # 是否自动故障切换


class DualWANManager:
    """双出口管理器"""

    def __init__(self):
        self._lock = threading.Lock()
        self._config = DualWANConfig()
        self._wan_interfaces: Dict[str, WANInterface] = {}
        self._policy_rules: Dict[str, PolicyRouteRule] = {}
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitor = threading.Event()
        self._routing_tables: Dict[str, int] = {}  # 路由表ID映射
        self._iptables_marks: Dict[str, int] = {}  # iptables标记映射
        self._data_file = "data/dual_wan.json"
        self._next_table_id = 100
        self._next_mark = 100
        self._failover_log: List[Dict] = []  # 故障切换日志
        
        self._load_data()
        logger.info("双出口管理器初始化完成")

    def _load_data(self):
        """加载持久化数据"""
        try:
            if os.path.exists(self._data_file):
                with open(self._data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                # 加载配置
                if "config" in data:
                    config_data = data["config"]
                    self._config = DualWANConfig(**config_data)
                
                # 加载WAN接口
                if "wan_interfaces" in data:
                    for wan_data in data["wan_interfaces"]:
                        wan = WANInterface(**wan_data)
                        self._wan_interfaces[wan.id] = wan
                
                # 加载策略路由规则
                if "policy_rules" in data:
                    for rule_data in data["policy_rules"]:
                        rule = PolicyRouteRule(**rule_data)
                        self._policy_rules[rule.id] = rule
                
                # 加载路由表映射
                if "routing_tables" in data:
                    self._routing_tables = data["routing_tables"]
                    if self._routing_tables:
                        self._next_table_id = max(self._routing_tables.values()) + 1
                
                # 加载iptables标记映射
                if "iptables_marks" in data:
                    self._iptables_marks = data["iptables_marks"]
                    if self._iptables_marks:
                        self._next_mark = max(self._iptables_marks.values()) + 1
                
                logger.info(f"已加载双出口配置: {len(self._wan_interfaces)}个WAN接口, {len(self._policy_rules)}条策略规则")
                
        except Exception as e:
            logger.warning(f"加载双出口数据失败: {e}")

    def _save_data(self):
        """保存持久化数据"""
        try:
            os.makedirs(os.path.dirname(self._data_file), exist_ok=True)
            
            data = {
                "config": asdict(self._config),
                "wan_interfaces": [asdict(w) for w in self._wan_interfaces.values()],
                "policy_rules": [asdict(r) for r in self._policy_rules.values()],
                "routing_tables": self._routing_tables,
                "iptables_marks": self._iptables_marks,
            }
            
            with open(self._data_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            logger.error(f"保存双出口数据失败: {e}")

    # ==================== WAN接口管理 ====================

    def add_wan_interface(self, name: str, gateway: str, ip_address: str,
                          description: str = "", weight: int = 1, priority: int = 1,
                          check_targets: List[str] = None) -> Dict[str, Any]:
        """
        添加WAN接口
        
        Args:
            name: 接口名称
            gateway: 网关地址
            ip_address: IP地址
            description: 描述
            weight: 权重
            priority: 优先级
            check_targets: 健康检查目标列表
            
        Returns:
            {"success": bool, "message": str, "wan_id": str}
        """
        with self._lock:
            # 验证输入参数
            _validate_interface_name(name)
            _validate_ip_address(gateway)
            _validate_ip_address(ip_address)

            # 检查接口名是否已存在
            for wan in self._wan_interfaces.values():
                if wan.name == name:
                    return {"success": False, "message": f"接口 {name} 已存在"}
            
            wan_id = str(uuid.uuid4())[:8]
            wan = WANInterface(
                id=wan_id,
                name=name,
                description=description,
                weight=weight,
                priority=priority,
                gateway=gateway,
                ip_address=ip_address,
                check_targets=check_targets or ["8.8.8.8", "1.1.1.1"],
            )
            
            self._wan_interfaces[wan_id] = wan
            
            # 设置路由表
            self._setup_routing_table(wan)
            
            self._save_data()
            logger.info(f"添加WAN接口: {name} (ID: {wan_id})")
            
            return {"success": True, "message": "WAN接口添加成功", "wan_id": wan_id}

    def remove_wan_interface(self, wan_id: str) -> Dict[str, Any]:
        """移除WAN接口"""
        with self._lock:
            if wan_id not in self._wan_interfaces:
                return {"success": False, "message": "WAN接口不存在"}
            
            wan = self._wan_interfaces[wan_id]
            
            # 清理路由表
            self._cleanup_routing_table(wan)
            
            # 清理相关策略路由规则
            rules_to_remove = [rid for rid, r in self._policy_rules.items() 
                              if r.wan_interface == wan_id]
            for rid in rules_to_remove:
                self._remove_policy_rule_iptables(self._policy_rules[rid])
                del self._policy_rules[rid]
            
            del self._wan_interfaces[wan_id]
            self._save_data()
            
            logger.info(f"移除WAN接口: {wan.name}")
            return {"success": True, "message": "WAN接口已移除"}

    def get_wan_interfaces(self) -> List[Dict]:
        """获取所有WAN接口"""
        return [asdict(w) for w in self._wan_interfaces.values()]

    def get_wan_interface(self, wan_id: str) -> Optional[Dict]:
        """获取单个WAN接口"""
        wan = self._wan_interfaces.get(wan_id)
        return asdict(wan) if wan else None

    def update_wan_interface(self, wan_id: str, **updates) -> Dict[str, Any]:
        """更新WAN接口配置"""
        with self._lock:
            if wan_id not in self._wan_interfaces:
                return {"success": False, "message": "WAN接口不存在"}
            
            wan = self._wan_interfaces[wan_id]
            
            # 更新允许的字段
            allowed_fields = ["name", "description", "weight", "priority", "enabled",
                            "gateway", "ip_address", "check_targets"]
            
            for key, value in updates.items():
                if key in allowed_fields and hasattr(wan, key):
                    setattr(wan, key, value)
            
            # 如果网关或接口名变化，重新设置路由表
            if "gateway" in updates or "name" in updates:
                self._cleanup_routing_table(wan)
                self._setup_routing_table(wan)
            
            self._save_data()
            return {"success": True, "message": "WAN接口配置已更新"}

    # ==================== 路由表管理 ====================

    def _setup_routing_table(self, wan: WANInterface) -> bool:
        """为WAN接口设置独立路由表"""
        try:
            table_id = self._next_table_id
            self._next_table_id += 1
            self._routing_tables[wan.id] = table_id
            
            # 添加路由表到/etc/iproute2/rt_tables（如果不存在）
            rt_tables_file = "/etc/iproute2/rt_tables"
            table_name = f"wan_{wan.id}"
            
            try:
                with open(rt_tables_file, "a") as f:
                    f.write(f"{table_id} {table_name}\n")
            except PermissionError:
                logger.warning(f"无法写入 {rt_tables_file}，需要root权限")
            
            # 执行路由命令
            commands = [
                # 添加默认路由到指定表
                ["ip", "route", "add", "default", "via", wan.gateway, "dev", wan.name, "table", str(table_id)],
                # 添加源地址路由规则
                ["ip", "rule", "add", "from", wan.ip_address, "table", str(table_id)],
            ]
            
            for cmd in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
                    if result.returncode != 0:
                        logger.warning(f"路由命令执行失败: {' '.join(cmd)}\n{result.stderr}")
                except subprocess.TimeoutExpired:
                    logger.warning(f"路由命令超时: {' '.join(cmd)}")
                except FileNotFoundError:
                    logger.warning("ip命令不存在，跳过路由设置")
            
            logger.info(f"WAN接口 {wan.name} 路由表设置完成: table {table_id}")
            return True
            
        except Exception as e:
            logger.error(f"设置路由表失败: {e}")
            return False

    def _cleanup_routing_table(self, wan: WANInterface):
        """清理WAN接口的路由表"""
        table_id = self._routing_tables.get(wan.id)
        if not table_id:
            return
        
        try:
            commands = [
                ["ip", "route", "flush", "table", str(table_id)],
                ["ip", "rule", "del", "from", wan.ip_address, "table", str(table_id)],
            ]
            
            for cmd in commands:
                try:
                    subprocess.run(cmd, capture_output=True, timeout=5)
                except Exception:
                    pass
            
            if wan.id in self._routing_tables:
                del self._routing_tables[wan.id]
                
            logger.info(f"WAN接口 {wan.name} 路由表已清理")
            
        except Exception as e:
            logger.warning(f"清理路由表失败: {e}")

    # ==================== 策略路由 ====================

    def add_policy_rule(self, name: str, source_ip: str, wan_interface: str,
                        dest_ip: str = "", protocol: str = "", dest_port: int = 0,
                        description: str = "") -> Dict[str, Any]:
        """添加策略路由规则"""
        with self._lock:
            # 验证输入参数
            if source_ip:
                _validate_ip_address(source_ip)
            if dest_ip:
                _validate_ip_address(dest_ip)
            if protocol:
                _validate_protocol(protocol)

            # 检查WAN接口是否存在
            if wan_interface not in self._wan_interfaces:
                return {"success": False, "message": "指定的WAN接口不存在"}
            
            rule_id = str(uuid.uuid4())[:8]
            rule = PolicyRouteRule(
                id=rule_id,
                name=name,
                source_ip=source_ip,
                dest_ip=dest_ip,
                protocol=protocol,
                dest_port=dest_port,
                wan_interface=wan_interface,
                description=description,
            )
            
            self._policy_rules[rule_id] = rule
            
            # 应用规则
            self._apply_policy_rule(rule)
            
            self._save_data()
            logger.info(f"添加策略路由规则: {name}")
            
            return {"success": True, "message": "策略路由规则添加成功", "rule_id": rule_id}

    def remove_policy_rule(self, rule_id: str) -> Dict[str, Any]:
        """移除策略路由规则"""
        with self._lock:
            if rule_id not in self._policy_rules:
                return {"success": False, "message": "策略路由规则不存在"}
            
            rule = self._policy_rules[rule_id]
            self._remove_policy_rule_iptables(rule)
            del self._policy_rules[rule_id]
            self._save_data()
            
            logger.info(f"移除策略路由规则: {rule.name}")
            return {"success": True, "message": "策略路由规则已移除"}

    def get_policy_rules(self) -> List[Dict]:
        """获取所有策略路由规则"""
        return [asdict(r) for r in self._policy_rules.values()]

    def toggle_policy_rule(self, rule_id: str, enabled: bool) -> Dict[str, Any]:
        """启用/禁用策略路由规则"""
        with self._lock:
            if rule_id not in self._policy_rules:
                return {"success": False, "message": "策略路由规则不存在"}
            
            rule = self._policy_rules[rule_id]
            rule.enabled = enabled
            
            if enabled:
                self._apply_policy_rule(rule)
            else:
                self._remove_policy_rule_iptables(rule)
            
            self._save_data()
            return {"success": True, "message": f"策略路由规则已{'启用' if enabled else '禁用'}"}

    def _apply_policy_rule(self, rule: PolicyRouteRule):
        """应用策略路由规则到iptables"""
        wan = self._wan_interfaces.get(rule.wan_interface)
        if not wan:
            return False
        
        table_id = self._routing_tables.get(rule.wan_interface, 100)
        
        # 分配iptables标记
        if rule.id not in self._iptables_marks:
            self._iptables_marks[rule.id] = self._next_mark
            self._next_mark += 1
        
        mark = self._iptables_marks[rule.id]
        
        # 构建iptables命令
        cmd_parts = ["iptables", "-t", "mangle", "-A", "PREROUTING"]
        
        if rule.source_ip:
            cmd_parts.extend(["-s", rule.source_ip])
        if rule.dest_ip:
            cmd_parts.extend(["-d", rule.dest_ip])
        if rule.protocol:
            cmd_parts.extend(["-p", rule.protocol])
        if rule.dest_port:
            cmd_parts.extend(["--dport", str(rule.dest_port)])
        
        cmd_parts.extend(["-j", "MARK", "--set-mark", str(mark)])
        
        try:
            # 添加iptables标记规则
            result = subprocess.run(cmd_parts, capture_output=True, timeout=5, text=True)
            if result.returncode != 0:
                logger.warning(f"iptables命令执行失败: {result.stderr}")
                return False
            
            # 添加ip rule规则
            rule_cmd = ["ip", "rule", "add", "fwmark", str(mark), "table", str(table_id)]
            result = subprocess.run(rule_cmd, capture_output=True, timeout=5, text=True)
            if result.returncode != 0:
                logger.warning(f"ip rule命令执行失败: {result.stderr}")
            
            logger.info(f"策略路由规则 {rule.name} 已应用 (mark={mark}, table={table_id})")
            return True
            
        except subprocess.TimeoutExpired:
            logger.error(f"应用策略路由超时: {rule.name}")
            return False
        except FileNotFoundError:
            logger.warning("iptables命令不存在，跳过规则应用")
            return False
        except Exception as e:
            logger.error(f"应用策略路由失败: {e}")
            return False

    def _remove_policy_rule_iptables(self, rule: PolicyRouteRule):
        """从iptables移除策略路由规则"""
        mark = self._iptables_marks.get(rule.id)
        if not mark:
            return
        
        table_id = self._routing_tables.get(rule.wan_interface)
        
        try:
            # 构建删除命令
            cmd_parts = ["iptables", "-t", "mangle", "-D", "PREROUTING"]
            
            if rule.source_ip:
                cmd_parts.extend(["-s", rule.source_ip])
            if rule.dest_ip:
                cmd_parts.extend(["-d", rule.dest_ip])
            if rule.protocol:
                cmd_parts.extend(["-p", rule.protocol])
            if rule.dest_port:
                cmd_parts.extend(["--dport", str(rule.dest_port)])
            
            cmd_parts.extend(["-j", "MARK", "--set-mark", str(mark)])
            
            subprocess.run(cmd_parts, capture_output=True, timeout=5)
            
            # 删除ip rule
            if table_id:
                subprocess.run(["ip", "rule", "del", "fwmark", str(mark), "table", str(table_id)],
                             capture_output=True, timeout=5)
            
            if rule.id in self._iptables_marks:
                del self._iptables_marks[rule.id]
            
            logger.info(f"策略路由规则 {rule.name} 已从iptables移除")
            
        except Exception as e:
            logger.warning(f"移除iptables规则失败: {e}")

    # ==================== 负载均衡 ====================

    def set_load_balance_mode(self, mode: str) -> Dict[str, Any]:
        """设置负载均衡模式"""
        with self._lock:
            valid_modes = [m.value for m in LoadBalanceMode]
            if mode not in valid_modes:
                return {"success": False, "message": f"无效的负载均衡模式，可选: {valid_modes}"}
            
            old_mode = self._config.load_balance_mode
            self._config.load_balance_mode = mode
            
            # 清除旧的负载均衡规则
            self._clear_load_balance_rules()
            
            # 应用新的负载均衡配置
            self._apply_load_balance()
            
            self._save_data()
            logger.info(f"负载均衡模式已更改: {old_mode} -> {mode}")
            
            return {"success": True, "message": f"负载均衡模式已设置为 {mode}"}

    def _clear_load_balance_rules(self):
        """清除负载均衡规则 - 仅清除GK-DUALWAN自定义链中的规则"""
        try:
            # 从POSTROUTING链中移除对GK-DUALWAN链的引用
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "GK-DUALWAN"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

        try:
            # 清空并删除GK-DUALWAN自定义链
            subprocess.run(
                ["iptables", "-t", "nat", "-F", "GK-DUALWAN"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

        try:
            subprocess.run(
                ["iptables", "-t", "nat", "-X", "GK-DUALWAN"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

    def _apply_load_balance(self):
        """应用负载均衡配置"""
        online_wans = [w for w in self._wan_interfaces.values() 
                      if w.status == WANStatus.ONLINE.value and w.enabled]
        
        if not online_wans:
            logger.warning("没有可用的在线WAN接口，无法应用负载均衡")
            return
        
        mode = self._config.load_balance_mode
        
        # 创建GK-DUALWAN自定义链并挂载到POSTROUTING
        try:
            subprocess.run(
                ["iptables", "-t", "nat", "-N", "GK-DUALWAN"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass  # 链可能已存在
        try:
            subprocess.run(
                ["iptables", "-t", "nat", "-F", "GK-DUALWAN"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass
        try:
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "GK-DUALWAN"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass
        
        if mode == LoadBalanceMode.FAILOVER.value:
            self._setup_failover(online_wans)
        elif mode == LoadBalanceMode.ROUND_ROBIN.value:
            self._setup_round_robin(online_wans)
        elif mode == LoadBalanceMode.WEIGHTED.value:
            self._setup_weighted(online_wans)
        elif mode == LoadBalanceMode.SOURCE_IP.value:
            self._setup_source_ip_hash(online_wans)

    def _setup_failover(self, online_wans: List[WANInterface]):
        """设置主备模式"""
        # 按优先级排序
        sorted_wans = sorted(online_wans, key=lambda w: w.priority)
        primary_wan = sorted_wans[0]
        
        # 设置默认路由指向主接口
        try:
            # 删除现有默认路由
            subprocess.run(["ip", "route", "del", "default"],
                          capture_output=True, timeout=5)
            
            # 添加新的默认路由
            subprocess.run(["ip", "route", "add", "default", "via", 
                          primary_wan.gateway, "dev", primary_wan.name],
                          capture_output=True, timeout=5)
            
            # 设置NAT
            subprocess.run(["iptables", "-t", "nat", "-A", "GK-DUALWAN",
                          "-o", primary_wan.name, "-j", "MASQUERADE"],
                          capture_output=True, timeout=5)
            
            logger.info(f"主备模式: 主接口设置为 {primary_wan.name}")
            
        except Exception as e:
            logger.error(f"设置主备模式失败: {e}")

    def _setup_round_robin(self, online_wans: List[WANInterface]):
        """设置轮询模式"""
        try:
            # 使用iptables statistic模块实现轮询
            for i, wan in enumerate(online_wans):
                # 计算概率
                probability = 1.0 / (len(online_wans) - i)
                
                cmd = ["iptables", "-t", "nat", "-A", "GK-DUALWAN",
                       "-o", wan.name, "-m", "statistic",
                       "--mode", "random", "--probability", str(probability),
                       "-j", "MASQUERADE"]
                
                subprocess.run(cmd, capture_output=True, timeout=5)
            
            logger.info(f"轮询模式: 已配置 {len(online_wans)} 个接口")
            
        except Exception as e:
            logger.error(f"设置轮询模式失败: {e}")

    def _setup_weighted(self, online_wans: List[WANInterface]):
        """设置加权模式"""
        try:
            total_weight = sum(w.weight for w in online_wans)
            remaining = total_weight
            
            for wan in online_wans:
                if remaining <= 0:
                    break
                
                probability = wan.weight / remaining
                remaining -= wan.weight
                
                cmd = ["iptables", "-t", "nat", "-A", "GK-DUALWAN",
                       "-o", wan.name, "-m", "statistic",
                       "--mode", "random", "--probability", str(probability),
                       "-j", "MASQUERADE"]
                
                subprocess.run(cmd, capture_output=True, timeout=5)
            
            logger.info(f"加权模式: 已配置 {len(online_wans)} 个接口")
            
        except Exception as e:
            logger.error(f"设置加权模式失败: {e}")

    def _setup_source_ip_hash(self, online_wans: List[WANInterface]):
        """设置源IP哈希模式"""
        try:
            # 使用iptables的HMARK或nth模式
            for i, wan in enumerate(online_wans):
                cmd = ["iptables", "-t", "nat", "-A", "GK-DUALWAN",
                       "-o", wan.name, "-m", "statistic",
                       "--mode", "nth", "--every", str(len(online_wans)),
                       "--packet", str(i),
                       "-j", "MASQUERADE"]
                
                subprocess.run(cmd, capture_output=True, timeout=5)
            
            logger.info(f"源IP哈希模式: 已配置 {len(online_wans)} 个接口")
            
        except Exception as e:
            logger.error(f"设置源IP哈希模式失败: {e}")

    # ==================== 健康检查 ====================

    def start_health_monitor(self) -> Dict[str, Any]:
        """启动健康检查线程"""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return {"success": False, "message": "健康检查已在运行中"}
        
        self._stop_monitor.clear()
        self._monitor_thread = threading.Thread(target=self._health_check_loop, daemon=True)
        self._monitor_thread.start()
        
        logger.info("健康检查线程已启动")
        return {"success": True, "message": "健康检查已启动"}

    def stop_health_monitor(self) -> Dict[str, Any]:
        """停止健康检查线程"""
        self._stop_monitor.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        
        logger.info("健康检查线程已停止")
        return {"success": True, "message": "健康检查已停止"}

    def _health_check_loop(self):
        """健康检查循环"""
        while not self._stop_monitor.is_set():
            for wan_id, wan in list(self._wan_interfaces.items()):
                if wan.enabled:
                    self._check_wan_health(wan)
            
            # 等待下一次检查
            self._stop_monitor.wait(self._config.health_check_interval)

    def _check_wan_health(self, wan: WANInterface):
        """检查单个WAN接口健康状态"""
        success_count = 0
        total_latency = 0.0
        
        for target in wan.check_targets:
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", str(self._config.health_check_timeout), target],
                    capture_output=True,
                    timeout=self._config.health_check_timeout + 2,
                    text=True
                )
                
                if result.returncode == 0:
                    success_count += 1
                    # 解析延迟
                    for line in result.stdout.split("\n"):
                        if "time=" in line:
                            try:
                                latency_str = line.split("time=")[1].split()[0]
                                total_latency += float(latency_str)
                            except (IndexError, ValueError):
                                pass
                                
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                logger.debug(f"健康检查异常: {target} - {e}")
        
        # 更新统计信息
        with self._lock:
            wan.last_check = datetime.now().isoformat()
            wan.packet_loss = (len(wan.check_targets) - success_count) / len(wan.check_targets) * 100
            wan.latency_ms = total_latency / success_count if success_count > 0 else 9999
            
            # 更新状态
            old_status = wan.status
            
            if success_count == len(wan.check_targets):
                wan.status = WANStatus.ONLINE.value
                wan.consecutive_failures = 0
                wan.consecutive_successes += 1
            elif success_count > 0:
                wan.status = WANStatus.DEGRADED.value
                wan.consecutive_failures += 1
                wan.consecutive_successes = 0
            else:
                wan.status = WANStatus.OFFLINE.value
                wan.consecutive_failures += 1
                wan.consecutive_successes = 0
            
            # 状态变化时触发故障切换
            if old_status != wan.status:
                logger.info(f"WAN接口 {wan.name} 状态变化: {old_status} -> {wan.status}")
                self._handle_status_change(wan, old_status)

    def _handle_status_change(self, wan: WANInterface, old_status: str):
        """处理WAN状态变化"""
        # 记录故障切换日志
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "wan_id": wan.id,
            "wan_name": wan.name,
            "old_status": old_status,
            "new_status": wan.status,
            "latency_ms": wan.latency_ms,
            "packet_loss": wan.packet_loss,
        }
        self._failover_log.append(log_entry)
        
        # 保留最近100条日志
        if len(self._failover_log) > 100:
            self._failover_log = self._failover_log[-100:]
        
        # 自动故障切换
        if self._config.auto_failover and self._config.load_balance_mode == LoadBalanceMode.FAILOVER.value:
            if wan.status == WANStatus.OFFLINE.value:
                self._do_failover()
            elif wan.status == WANStatus.ONLINE.value and wan.consecutive_successes >= self._config.recovery_threshold:
                # 恢复到主接口
                self._do_failover()

    def _do_failover(self):
        """执行故障切换"""
        # 找到可用的WAN接口
        online_wans = [w for w in self._wan_interfaces.values()
                      if w.status == WANStatus.ONLINE.value and w.enabled]
        
        if not online_wans:
            logger.warning("没有可用的WAN接口进行故障切换")
            return
        
        # 按优先级排序
        online_wans.sort(key=lambda w: w.priority)
        new_primary = online_wans[0]
        
        logger.info(f"故障切换到: {new_primary.name}")
        
        # 重新应用负载均衡
        self._clear_load_balance_rules()
        self._setup_failover(online_wans)

    # ==================== 配置管理 ====================

    def update_config(self, **kwargs) -> Dict[str, Any]:
        """更新双出口配置"""
        with self._lock:
            allowed_fields = ["enabled", "load_balance_mode", "health_check_interval",
                            "health_check_timeout", "failover_threshold", "recovery_threshold",
                            "auto_failover"]
            
            for key, value in kwargs.items():
                if key in allowed_fields and hasattr(self._config, key):
                    setattr(self._config, key, value)
            
            self._save_data()
            return {"success": True, "message": "配置已更新"}

    def get_config(self) -> Dict:
        """获取当前配置"""
        return asdict(self._config)

    # ==================== 统计信息 ====================

    def get_stats(self) -> dict:
        """获取统计信息"""
        online = sum(1 for w in self._wan_interfaces.values() if w.status == WANStatus.ONLINE.value)
        offline = sum(1 for w in self._wan_interfaces.values() if w.status == WANStatus.OFFLINE.value)
        degraded = sum(1 for w in self._wan_interfaces.values() if w.status == WANStatus.DEGRADED.value)
        
        return {
            "total_wans": len(self._wan_interfaces),
            "online": online,
            "offline": offline,
            "degraded": degraded,
            "policy_rules": len(self._policy_rules),
            "enabled_rules": sum(1 for r in self._policy_rules.values() if r.enabled),
            "load_balance_mode": self._config.load_balance_mode,
            "monitor_running": self._monitor_thread.is_alive() if self._monitor_thread else False,
            "auto_failover": self._config.auto_failover,
        }

    def get_status(self) -> dict:
        """获取整体状态"""
        return {
            "config": asdict(self._config),
            "wan_interfaces": [asdict(w) for w in self._wan_interfaces.values()],
            "policy_rules": [asdict(r) for r in self._policy_rules.values()],
            "stats": self.get_stats(),
            "failover_log": self._failover_log[-20:],  # 最近20条
        }

    def get_failover_log(self, limit: int = 50) -> List[Dict]:
        """获取故障切换日志"""
        return self._failover_log[-limit:]

    def manual_failover(self, target_wan_id: str) -> Dict[str, Any]:
        """手动故障切换到指定接口"""
        with self._lock:
            if target_wan_id not in self._wan_interfaces:
                return {"success": False, "message": "目标WAN接口不存在"}
            
            target_wan = self._wan_interfaces[target_wan_id]
            
            if target_wan.status != WANStatus.ONLINE.value:
                return {"success": False, "message": f"目标接口状态为 {target_wan.status}，无法切换"}
            
            if not target_wan.enabled:
                return {"success": False, "message": "目标接口未启用"}
            
            # 更新优先级使其成为主接口
            for wan in self._wan_interfaces.values():
                if wan.id == target_wan_id:
                    wan.priority = 1
                    wan.is_primary = True
                else:
                    wan.is_primary = False
            
            # 执行切换
            online_wans = [w for w in self._wan_interfaces.values()
                          if w.status == WANStatus.ONLINE.value and w.enabled]
            
            self._clear_load_balance_rules()
            self._setup_failover(online_wans)
            
            # 记录日志
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "wan_id": target_wan_id,
                "wan_name": target_wan.name,
                "old_status": "manual_failover",
                "new_status": "primary",
                "latency_ms": target_wan.latency_ms,
                "packet_loss": target_wan.packet_loss,
            }
            self._failover_log.append(log_entry)
            
            self._save_data()
            logger.info(f"手动故障切换到: {target_wan.name}")
            
            return {"success": True, "message": f"已切换到 {target_wan.name}"}


# 单例实例
_dual_wan_manager: Optional[DualWANManager] = None


def get_dual_wan() -> DualWANManager:
    """获取双出口管理器单例"""
    global _dual_wan_manager
    if _dual_wan_manager is None:
        _dual_wan_manager = DualWANManager()
    return _dual_wan_manager
