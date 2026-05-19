"""
GateKeeper - MAC 地址管理模块
提供 MAC 地址白名单/黑名单管理、设备访问控制与持久化存储功能
"""

import re
import os
import json
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any

from config.logging_config import get_logger

logger = get_logger("mac_manager")

# MAC 地址正则校验
MAC_PATTERN = re.compile(
    r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$'
)

# 数据文件路径
DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data"
)
MAC_DATA_FILE = os.path.join(DATA_DIR, "mac_manager.json")


class MACManager:
    """MAC 地址管理器 - 白名单/黑名单管理与设备访问控制"""

    def __init__(self):
        """初始化 MAC 地址管理器"""
        self._whitelist: Dict[str, dict] = {}
        self._blacklist: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stats = {
            "total_whitelist": 0,
            "total_blacklist": 0,
            "total_checks": 0,
            "total_allowed": 0,
            "total_blocked": 0,
            "last_check_time": None,
        }
        self._load_data()
        logger.info("MAC 地址管理器初始化完成（白名单: {}, 黑名单: {}）".format(
            len(self._whitelist), len(self._blacklist)))

    def add_whitelist(self, mac: str, label: str = "") -> dict:
        """
        添加 MAC 地址到白名单

        Args:
            mac: MAC 地址
            label: 设备标签/描述

        Returns:
            操作结果字典
        """
        mac_normalized = self._normalize_mac(mac)
        if not mac_normalized:
            return {"status": "error", "message": "无效的 MAC 地址格式: {}".format(mac)}

        with self._lock:
            # 如果在黑名单中，先移除
            if mac_normalized in self._blacklist:
                del self._blacklist[mac_normalized]
                logger.info("MAC {} 从黑名单移至白名单".format(mac_normalized))

            self._whitelist[mac_normalized] = {
                "mac": mac_normalized,
                "label": label,
                "added_at": datetime.now().isoformat(),
            }
            self._stats["total_whitelist"] = len(self._whitelist)
            self._save_data()

            logger.info("添加白名单 MAC: {} ({})".format(mac_normalized, label))
            return {"status": "ok", "mac": mac_normalized, "label": label}

    def add_blacklist(self, mac: str, reason: str = "") -> dict:
        """
        添加 MAC 地址到黑名单

        Args:
            mac: MAC 地址
            reason: 加入黑名单的原因

        Returns:
            操作结果字典
        """
        mac_normalized = self._normalize_mac(mac)
        if not mac_normalized:
            return {"status": "error", "message": "无效的 MAC 地址格式: {}".format(mac)}

        with self._lock:
            # 如果在白名单中，先移除
            if mac_normalized in self._whitelist:
                del self._whitelist[mac_normalized]
                logger.info("MAC {} 从白名单移至黑名单".format(mac_normalized))

            self._blacklist[mac_normalized] = {
                "mac": mac_normalized,
                "reason": reason,
                "added_at": datetime.now().isoformat(),
            }
            self._stats["total_blacklist"] = len(self._blacklist)
            self._save_data()

            logger.info("添加黑名单 MAC: {} (原因: {})".format(mac_normalized, reason))
            return {"status": "ok", "mac": mac_normalized, "reason": reason}

    def remove(self, mac: str) -> dict:
        """
        从白名单或黑名单中移除 MAC 地址

        Args:
            mac: MAC 地址

        Returns:
            操作结果字典
        """
        mac_normalized = self._normalize_mac(mac)
        if not mac_normalized:
            return {"status": "error", "message": "无效的 MAC 地址格式: {}".format(mac)}

        with self._lock:
            removed_from = None
            if mac_normalized in self._whitelist:
                del self._whitelist[mac_normalized]
                removed_from = "whitelist"
                self._stats["total_whitelist"] = len(self._whitelist)
            elif mac_normalized in self._blacklist:
                del self._blacklist[mac_normalized]
                removed_from = "blacklist"
                self._stats["total_blacklist"] = len(self._blacklist)

            if removed_from:
                self._save_data()
                logger.info("移除 MAC: {} (从 {})".format(mac_normalized, removed_from))
                return {"status": "ok", "mac": mac_normalized, "removed_from": removed_from}
            else:
                return {"status": "error", "message": "MAC 地址不在任何列表中: {}".format(mac_normalized)}

    def check_mac(self, mac: str) -> dict:
        """
        检查 MAC 地址的访问状态

        Args:
            mac: 要检查的 MAC 地址

        Returns:
            检查结果字典，包含 action (allow/deny) 和详细信息
        """
        mac_normalized = self._normalize_mac(mac)
        if not mac_normalized:
            return {
                "action": "deny",
                "reason": "无效的 MAC 地址格式",
                "mac": mac,
                "list": None,
            }

        with self._lock:
            self._stats["total_checks"] += 1
            self._stats["last_check_time"] = datetime.now().isoformat()

            # 黑名单优先
            if mac_normalized in self._blacklist:
                entry = self._blacklist[mac_normalized]
                self._stats["total_blocked"] += 1
                return {
                    "action": "deny",
                    "reason": "MAC 地址在黑名单中: {}".format(entry.get("reason", "")),
                    "mac": mac_normalized,
                    "list": "blacklist",
                    "detail": entry,
                }

            # 白名单模式：如果白名单不为空，则只允许白名单中的 MAC
            if self._whitelist:
                if mac_normalized in self._whitelist:
                    entry = self._whitelist[mac_normalized]
                    self._stats["total_allowed"] += 1
                    return {
                        "action": "allow",
                        "reason": "MAC 地址在白名单中: {}".format(entry.get("label", "")),
                        "mac": mac_normalized,
                        "list": "whitelist",
                        "detail": entry,
                    }
                else:
                    self._stats["total_blocked"] += 1
                    return {
                        "action": "deny",
                        "reason": "MAC 地址不在白名单中（白名单模式已启用）",
                        "mac": mac_normalized,
                        "list": None,
                        "detail": None,
                    }

            # 白名单为空，默认允许
            self._stats["total_allowed"] += 1
            return {
                "action": "allow",
                "reason": "默认允许（白名单模式未启用）",
                "mac": mac_normalized,
                "list": None,
                "detail": None,
            }

    def get_lists(self) -> dict:
        """
        获取白名单和黑名单

        Returns:
            包含 whitelist 和 blacklist 的字典
        """
        with self._lock:
            return {
                "whitelist": list(self._whitelist.values()),
                "blacklist": list(self._blacklist.values()),
                "whitelist_enabled": len(self._whitelist) > 0,
            }

    def get_stats(self) -> dict:
        """
        获取管理器统计信息

        Returns:
            统计信息字典
        """
        with self._lock:
            stats = dict(self._stats)
            stats["current_whitelist_count"] = len(self._whitelist)
            stats["current_blacklist_count"] = len(self._blacklist)
            return stats

    def get_whitelist(self) -> list:
        """
        获取白名单列表

        Returns:
            白名单条目列表
        """
        with self._lock:
            return list(self._whitelist.values())

    def get_blacklist(self) -> list:
        """
        获取黑名单列表

        Returns:
            黑名单条目列表
        """
        with self._lock:
            return list(self._blacklist.values())

    def is_in_whitelist(self, mac: str) -> bool:
        """
        检查 MAC 是否在白名单中

        Args:
            mac: MAC 地址

        Returns:
            是否在白名单中
        """
        mac_normalized = self._normalize_mac(mac)
        with self._lock:
            return mac_normalized in self._whitelist

    def is_in_blacklist(self, mac: str) -> bool:
        """
        检查 MAC 是否在黑名单中

        Args:
            mac: MAC 地址

        Returns:
            是否在黑名单中
        """
        mac_normalized = self._normalize_mac(mac)
        with self._lock:
            return mac_normalized in self._blacklist

    def import_list(self, data: dict) -> dict:
        """
        批量导入白名单/黑名单

        Args:
            data: 包含 whitelist 和 blacklist 键的字典

        Returns:
            导入结果
        """
        imported_whitelist = 0
        imported_blacklist = 0

        with self._lock:
            for item in data.get("whitelist", []):
                mac = item.get("mac", "")
                label = item.get("label", "")
                mac_normalized = self._normalize_mac(mac)
                if mac_normalized:
                    self._whitelist[mac_normalized] = {
                        "mac": mac_normalized,
                        "label": label,
                        "added_at": datetime.now().isoformat(),
                    }
                    imported_whitelist += 1

            for item in data.get("blacklist", []):
                mac = item.get("mac", "")
                reason = item.get("reason", "")
                mac_normalized = self._normalize_mac(mac)
                if mac_normalized:
                    self._blacklist[mac_normalized] = {
                        "mac": mac_normalized,
                        "reason": reason,
                        "added_at": datetime.now().isoformat(),
                    }
                    imported_blacklist += 1

            self._stats["total_whitelist"] = len(self._whitelist)
            self._stats["total_blacklist"] = len(self._blacklist)
            self._save_data()

        logger.info("批量导入完成: 白名单 {} 条, 黑名单 {} 条".format(
            imported_whitelist, imported_blacklist))
        return {
            "status": "ok",
            "imported_whitelist": imported_whitelist,
            "imported_blacklist": imported_blacklist,
        }

    def clear_all(self) -> dict:
        """
        清空所有白名单和黑名单

        Returns:
            操作结果
        """
        with self._lock:
            wl_count = len(self._whitelist)
            bl_count = len(self._blacklist)
            self._whitelist.clear()
            self._blacklist.clear()
            self._stats["total_whitelist"] = 0
            self._stats["total_blacklist"] = 0
            self._save_data()
            logger.info("已清空所有列表（白名单: {}, 黑名单: {}）".format(wl_count, bl_count))
            return {
                "status": "ok",
                "cleared_whitelist": wl_count,
                "cleared_blacklist": bl_count,
            }

    # ----------------------------------------------------------
    # 内部方法
    # ----------------------------------------------------------

    @staticmethod
    def _normalize_mac(mac: str) -> str:
        """
        标准化 MAC 地址格式（统一为大写，使用冒号分隔）

        Args:
            mac: 原始 MAC 地址字符串

        Returns:
            标准化后的 MAC 地址，无效格式返回空字符串
        """
        if not mac:
            return ""
        mac = mac.strip().upper()
        # 统一分隔符为冒号
        mac = mac.replace("-", ":")
        if MAC_PATTERN.match(mac):
            return mac
        return ""

    def _load_data(self):
        """从 JSON 文件加载数据"""
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            if os.path.exists(MAC_DATA_FILE):
                with open(MAC_DATA_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)

                for item in data.get("whitelist", []):
                    mac = item.get("mac", "")
                    if mac:
                        self._whitelist[mac.upper()] = item

                for item in data.get("blacklist", []):
                    mac = item.get("mac", "")
                    if mac:
                        self._blacklist[mac.upper()] = item

                self._stats.update(data.get("stats", {}))
                logger.info("已加载 MAC 管理数据（白名单: {}, 黑名单: {}）".format(
                    len(self._whitelist), len(self._blacklist)))
        except Exception as e:
            logger.error("加载 MAC 管理数据失败: {}".format(e))

    def _save_data(self):
        """保存数据到 JSON 文件"""
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            data = {
                "whitelist": list(self._whitelist.values()),
                "blacklist": list(self._blacklist.values()),
                "stats": self._stats,
            }
            with open(MAC_DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error("保存 MAC 管理数据失败: {}".format(e))


# ============================================================
# 单例
# ============================================================

_instance: Optional[MACManager] = None
_instance_lock = threading.Lock()


def get_mac_manager() -> MACManager:
    """获取 MAC 地址管理器单例"""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = MACManager()
    return _instance
