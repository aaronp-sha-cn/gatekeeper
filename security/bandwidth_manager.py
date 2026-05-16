"""
GateKeeper - 带宽管理模块
提供基于 tc/htb 的流量整形、带宽限制与使用量监控功能
"""

import re
import os
import json
import time
import threading
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any

from config.logging_config import get_logger

logger = get_logger("bandwidth_manager")

# 默认配置
DEFAULT_INTERFACE = "eth0"
DEFAULT_TOTAL_BANDWIDTH = "1000mbit"
TC_TIMEOUT = 10
DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data"
)
BANDWIDTH_DATA_FILE = os.path.join(DATA_DIR, "bandwidth_manager.json")

# 速率单位转换因子
RATE_UNITS = {
    "kbit": 1000,
    "mbit": 1000000,
    "gbit": 1000000000,
    "kbps": 1000,
    "mbps": 1000000,
    "gbps": 1000000000,
}


class BandwidthManager:
    """带宽管理器 - 流量整形与带宽限制"""

    def __init__(self):
        """初始化带宽管理器"""
        self._limits: Dict[str, dict] = {}
        self._interface = DEFAULT_INTERFACE
        self._total_bandwidth = DEFAULT_TOTAL_BANDWIDTH
        self._lock = threading.Lock()
        self._stats = {
            "total_limits_set": 0,
            "total_limits_removed": 0,
            "total_commands_executed": 0,
            "total_errors": 0,
            "last_update_time": None,
        }
        self._command_history: List[dict] = []
        self._load_data()
        logger.info("带宽管理器初始化完成（接口: {}, 已有 {} 条限制规则）".format(
            self._interface, len(self._limits)))

    def set_limit(self, ip: str, rate: str) -> dict:
        """
        设置指定 IP 的带宽限制

        Args:
            ip: 目标 IP 地址
            rate: 速率限制字符串，如 "10mbit", "500kbit", "1gbit"

        Returns:
            操作结果字典
        """
        if not self._validate_ip(ip):
            return {"status": "error", "message": "无效的 IP 地址: {}".format(ip)}

        rate_normalized = self._normalize_rate(rate)
        if not rate_normalized:
            return {"status": "error", "message": "无效的速率格式: {}".format(rate)}

        with self._lock:
            # 生成唯一的 class ID
            class_id = self._get_next_class_id(ip)

            self._limits[ip] = {
                "ip": ip,
                "rate": rate_normalized,
                "ceil": self._calc_ceil(rate_normalized),
                "class_id": class_id,
                "interface": self._interface,
                "enabled": True,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
            }

            # 应用 tc 规则
            result = self._apply_limit(ip, self._limits[ip])
            if result.get("status") == "ok":
                self._stats["total_limits_set"] += 1
                self._stats["last_update_time"] = datetime.now().isoformat()
                self._save_data()
                logger.info("设置带宽限制: {} -> {}".format(ip, rate_normalized))
                return {"status": "ok", "ip": ip, "rate": rate_normalized}
            else:
                # 回滚
                del self._limits[ip]
                self._stats["total_errors"] += 1
                return result

    def remove_limit(self, ip: str) -> dict:
        """
        移除指定 IP 的带宽限制

        Args:
            ip: 目标 IP 地址

        Returns:
            操作结果字典
        """
        with self._lock:
            if ip not in self._limits:
                return {"status": "error", "message": "IP {} 没有带宽限制".format(ip)}

            limit = self._limits[ip]
            class_id = limit.get("class_id", "")

            # 删除 tc 规则
            self._remove_tc_class(class_id)

            del self._limits[ip]
            self._stats["total_limits_removed"] += 1
            self._stats["last_update_time"] = datetime.now().isoformat()
            self._save_data()

            logger.info("移除带宽限制: {}".format(ip))
            return {"status": "ok", "removed_ip": ip}

    def get_limits(self) -> dict:
        """
        获取所有带宽限制规则

        Returns:
            带宽限制规则字典
        """
        with self._lock:
            return {
                "interface": self._interface,
                "total_bandwidth": self._total_bandwidth,
                "limits": list(self._limits.values()),
                "count": len(self._limits),
            }

    def get_usage(self) -> dict:
        """
        获取当前带宽使用情况

        Returns:
            各 IP 的带宽使用信息
        """
        usage = {}
        try:
            # 获取 tc class 统计
            result = subprocess.run(
                ["tc", "-s", "class", "show", "dev", self._interface],
                capture_output=True, text=True, timeout=TC_TIMEOUT
            )
            output = result.stdout

            with self._lock:
                for ip, limit in self._limits.items():
                    class_id = limit.get("class_id", "")
                    rate = limit.get("rate", "")

                    # 从 tc 输出中查找对应 class 的统计
                    class_stats = self._parse_tc_class_stats(output, class_id)

                    usage[ip] = {
                        "ip": ip,
                        "limit_rate": rate,
                        "bytes_sent": class_stats.get("bytes", 0),
                        "packets_sent": class_stats.get("packets", 0),
                        "dropped": class_stats.get("dropped", 0),
                        "overlimits": class_stats.get("overlimits", 0),
                        "rate_bps": class_stats.get("rate_bps", 0),
                        "utilization": self._calc_utilization(
                            class_stats.get("rate_bps", 0), rate
                        ),
                    }

        except FileNotFoundError:
            logger.warning("tc 命令不可用")
        except subprocess.TimeoutExpired:
            logger.warning("获取带宽使用超时")
        except Exception as e:
            logger.error("获取带宽使用失败: {}".format(e))

        return usage

    def get_stats(self) -> dict:
        """
        获取带宽管理器统计信息

        Returns:
            统计信息字典
        """
        with self._lock:
            stats = dict(self._stats)
            stats["active_limits"] = len(self._limits)
            stats["interface"] = self._interface
            stats["total_bandwidth"] = self._total_bandwidth
            return stats

    def set_interface(self, interface: str) -> dict:
        """
        设置管理的网络接口

        Args:
            interface: 网络接口名称

        Returns:
            操作结果
        """
        with self._lock:
            if not self._interface_exists(interface):
                return {"status": "error", "message": "网络接口不存在: {}".format(interface)}

            old_interface = self._interface
            self._interface = interface
            self._save_data()
            logger.info("切换管理接口: {} -> {}".format(old_interface, interface))
            return {"status": "ok", "interface": interface}

    def set_total_bandwidth(self, bandwidth: str) -> dict:
        """
        设置总带宽上限

        Args:
            bandwidth: 总带宽字符串，如 "1000mbit"

        Returns:
            操作结果
        """
        normalized = self._normalize_rate(bandwidth)
        if not normalized:
            return {"status": "error", "message": "无效的带宽格式: {}".format(bandwidth)}

        with self._lock:
            self._total_bandwidth = normalized
            self._save_data()
            logger.info("设置总带宽: {}".format(normalized))
            return {"status": "ok", "total_bandwidth": normalized}

    def apply_all_limits(self) -> dict:
        """
        重新应用所有带宽限制规则

        Returns:
            操作结果
        """
        with self._lock:
            # 先清除现有 tc 规则
            self._clear_tc_rules()

            # 重建根队列
            self._setup_root_qdisc()

            applied = 0
            errors = 0
            for ip, limit in self._limits.items():
                if limit.get("enabled", True):
                    result = self._apply_limit(ip, limit)
                    if result.get("status") == "ok":
                        applied += 1
                    else:
                        errors += 1

            logger.info("重新应用带宽限制: 成功 {} 条, 失败 {} 条".format(applied, errors))
            return {
                "status": "ok",
                "applied": applied,
                "errors": errors,
                "message": "已应用 {} 条带宽限制规则".format(applied),
            }

    def clear_all_limits(self) -> dict:
        """
        清除所有带宽限制

        Returns:
            操作结果
        """
        with self._lock:
            count = len(self._limits)
            self._limits.clear()
            self._clear_tc_rules()
            self._save_data()
            logger.info("已清除所有带宽限制（共 {} 条）".format(count))
            return {"status": "ok", "cleared": count}

    def get_command_history(self, limit: int = 50) -> list:
        """
        获取 tc 命令执行历史

        Args:
            limit: 最大返回数量

        Returns:
            命令历史列表
        """
        with self._lock:
            return list(self._command_history[-limit:])

    # ----------------------------------------------------------
    # 内部方法
    # ----------------------------------------------------------

    def _apply_limit(self, ip: str, limit: dict) -> dict:
        """
        应用单条带宽限制到 tc

        Args:
            ip: 目标 IP
            limit: 限制配置

        Returns:
            操作结果
        """
        iface = self._interface
        class_id = limit.get("class_id", "")
        rate = limit.get("rate", "1mbit")
        ceil = limit.get("ceil", rate)

        try:
            # 确保 HTB 根队列存在
            self._setup_root_qdisc()

            # 添加 HTB 分类
            cmd_add_class = (
                "tc class add dev {} parent 1:1 classid 1:{} htb rate {} ceil {}"
            ).format(iface, class_id, rate, ceil)
            self._exec_tc(cmd_add_class)

            # 添加过滤器匹配目标 IP
            cmd_add_filter = (
                "tc filter add dev {} protocol ip parent 1:0 prio 1 "
                "u32 match ip dst {} flowid 1:{}"
            ).format(iface, ip, class_id)
            self._exec_tc(cmd_add_filter)

            return {"status": "ok"}

        except Exception as e:
            logger.error("应用带宽限制失败 ({}): {}".format(ip, e))
            return {"status": "error", "message": str(e)}

    def _setup_root_qdisc(self):
        """设置 HTB 根队列"""
        try:
            # 创建 HTB 根队列
            cmd_root = "tc qdisc add dev {} root handle 1: htb default 999".format(
                self._interface)
            self._exec_tc(cmd_root)

            # 创建根分类
            cmd_root_class = (
                "tc class add dev {} parent 1: classid 1:1 htb rate {} ceil {}"
            ).format(self._interface, self._total_bandwidth,
                     self._total_bandwidth)
            self._exec_tc(cmd_root_class)

            # 创建默认分类（未匹配的流量）
            cmd_default = (
                "tc class add dev {} parent 1:1 classid 1:999 htb rate 1kbit ceil {}"
            ).format(self._interface, self._total_bandwidth)
            self._exec_tc(cmd_default)

        except Exception as e:
            logger.debug("设置根队列失败（可能已存在）: {}".format(e))

    def _clear_tc_rules(self):
        """清除接口上的所有 tc 规则"""
        try:
            self._exec_tc("tc qdisc del dev {} root 2>/dev/null".format(self._interface))
        except Exception:
            pass

    def _remove_tc_class(self, class_id: str):
        """
        删除指定的 tc 分类

        Args:
            class_id: 分类 ID
        """
        try:
            self._exec_tc(
                "tc class del dev {} parent 1:1 classid 1:{}".format(
                    self._interface, class_id)
            )
            # 同时删除关联的过滤器
            self._exec_tc(
                "tc filter del dev {} protocol ip parent 1:0 prio 1".format(
                    self._interface)
            )
        except Exception as e:
            logger.debug("删除 tc 分类失败: {}".format(e))

    def _exec_tc(self, cmd: str) -> str:
        """
        执行 tc 命令

        Args:
            cmd: 完整的 tc 命令字符串

        Returns:
            命令输出

        Raises:
            subprocess.CalledProcessError: 命令执行失败
        """
        self._stats["total_commands_executed"] += 1
        self._command_history.append({
            "command": cmd,
            "timestamp": datetime.now().isoformat(),
        })
        if len(self._command_history) > 200:
            self._command_history = self._command_history[-200:]

        # 安全修复：将命令字符串解析为列表，避免 shell=True 的命令注入风险
        # tc 命令格式: "tc qdisc/class/filter ... dev <interface> ..."
        cmd_parts = cmd.split()
        # 如果命令以 "tc" 开头，直接使用；否则添加 "tc" 前缀
        if cmd_parts and cmd_parts[0] != "tc":
            cmd_parts = ["tc"] + cmd_parts
        
        result = subprocess.run(
            cmd_parts, shell=False, capture_output=True, text=True, timeout=TC_TIMEOUT
        )
        if result.returncode != 0 and result.stderr:
            # 某些 tc 错误是预期的（如规则已存在）
            if "File exists" not in result.stderr:
                logger.debug("tc 命令返回非零: {}".format(result.stderr.strip()))
        return result.stdout + result.stderr

    def _get_next_class_id(self, ip: str) -> str:
        """
        为 IP 生成唯一的 tc class ID

        Args:
            ip: IP 地址

        Returns:
            class ID 字符串
        """
        # 使用 IP 最后一段作为基础 ID（10-250 范围）
        try:
            last_octet = int(ip.split(".")[-1])
            class_id = max(10, min(250, last_octet))
        except (ValueError, IndexError):
            class_id = 100

        # 检查冲突
        existing_ids = {
            limit.get("class_id", "") for limit in self._limits.values()
        }
        while str(class_id) in existing_ids:
            class_id += 1
            if class_id > 250:
                class_id = 10

        return str(class_id)

    def _parse_tc_class_stats(self, tc_output: str, class_id: str) -> dict:
        """
        解析 tc -s class show 输出中的统计信息

        Args:
            tc_output: tc 命令输出
            class_id: 目标 class ID

        Returns:
            统计信息字典
        """
        stats = {
            "bytes": 0,
            "packets": 0,
            "dropped": 0,
            "overlimits": 0,
            "rate_bps": 0,
        }

        # 查找对应 class 的块
        pattern = r'class htb 1:{}.*?(?=class htb|\Z)'.format(re.escape(class_id))
        match = re.search(pattern, tc_output, re.DOTALL)
        if not match:
            return stats

        block = match.group(0)

        # 提取字节数
        byte_match = re.search(r'Sent\s+(\d+)', block)
        if byte_match:
            stats["bytes"] = int(byte_match.group(1))

        # 提取包数
        pkt_match = re.search(r'Sent\s+\d+\s+bytes\s+(\d+)', block)
        if pkt_match:
            stats["packets"] = int(pkt_match.group(1))

        # 提取丢包数
        drop_match = re.search(r'dropped\s+(\d+)', block)
        if drop_match:
            stats["dropped"] = int(drop_match.group(1))

        # 提取超限次数
        over_match = re.search(r'overlimits\s+(\d+)', block)
        if over_match:
            stats["overlimits"] = int(over_match.group(1))

        # 提取速率
        rate_match = re.search(r'rate\s+(\d+)', block)
        if rate_match:
            stats["rate_bps"] = int(rate_match.group(1))

        return stats

    def _normalize_rate(self, rate: str) -> str:
        """
        标准化速率字符串

        Args:
            rate: 速率字符串，如 "10mbit", "500kbit"

        Returns:
            标准化后的速率字符串，无效格式返回空字符串
        """
        rate = rate.strip().lower()
        for unit in RATE_UNITS:
            if rate.endswith(unit):
                # 验证数值部分
                num_str = rate[:-len(unit)]
                try:
                    value = float(num_str)
                    if value > 0:
                        return "{}{}".format(int(value), unit)
                except ValueError:
                    pass
        return ""

    def _calc_ceil(self, rate: str) -> str:
        """
        计算突发上限（ceil），默认为 rate 的 1.2 倍

        Args:
            rate: 速率字符串

        Returns:
            ceil 速率字符串
        """
        for unit, factor in RATE_UNITS.items():
            if rate.endswith(unit):
                num_str = rate[:-len(unit)]
                try:
                    value = float(num_str)
                    ceil_value = int(value * 1.2)
                    return "{}{}".format(ceil_value, unit)
                except ValueError:
                    pass
        return rate

    def _calc_utilization(self, rate_bps: int, limit_rate: str) -> float:
        """
        计算带宽利用率百分比

        Args:
            rate_bps: 当前速率（bps）
            limit_rate: 限制速率字符串

        Returns:
            利用率百分比（0-100）
        """
        for unit, factor in RATE_UNITS.items():
            if limit_rate.endswith(unit):
                num_str = limit_rate[:-len(unit)]
                try:
                    limit_bps = float(num_str) * factor
                    if limit_bps > 0:
                        return round(min(100.0, (rate_bps / limit_bps) * 100), 2)
                except ValueError:
                    pass
        return 0.0

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """
        验证 IP 地址格式

        Args:
            ip: IP 地址字符串

        Returns:
            是否为有效的 IPv4 地址
        """
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        return True

    def _interface_exists(self, interface: str) -> bool:
        """
        检查网络接口是否存在

        Args:
            interface: 接口名称

        Returns:
            接口是否存在
        """
        try:
            with open("/proc/net/dev", "r") as f:
                for line in f.readlines()[2:]:
                    if interface in line:
                        return True
            return False
        except Exception:
            return False

    def _load_data(self):
        """从 JSON 文件加载数据"""
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            if os.path.exists(BANDWIDTH_DATA_FILE):
                with open(BANDWIDTH_DATA_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._interface = data.get("interface", DEFAULT_INTERFACE)
                self._total_bandwidth = data.get("total_bandwidth", DEFAULT_TOTAL_BANDWIDTH)
                for ip, limit in data.get("limits", {}).items():
                    self._limits[ip] = limit
                self._stats.update(data.get("stats", {}))
                logger.info("已加载带宽管理数据（{} 条限制规则）".format(len(self._limits)))
        except Exception as e:
            logger.error("加载带宽管理数据失败: {}".format(e))

    def _save_data(self):
        """保存数据到 JSON 文件"""
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            data = {
                "interface": self._interface,
                "total_bandwidth": self._total_bandwidth,
                "limits": self._limits,
                "stats": self._stats,
            }
            with open(BANDWIDTH_DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error("保存带宽管理数据失败: {}".format(e))


# ============================================================
# 单例
# ============================================================

_instance: Optional[BandwidthManager] = None
_instance_lock = threading.Lock()


def get_bandwidth_manager() -> BandwidthManager:
    """获取带宽管理器单例"""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = BandwidthManager()
    return _instance
