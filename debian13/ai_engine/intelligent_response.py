"""
GateKeeper - 智能响应引擎
基于威胁等级的自动化响应策略执行
"""

import logging
import threading
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

# 模块级单例
_instance = None
_instance_lock = threading.Lock()

# 威胁等级阈值
THREAT_THRESHOLDS = {
    "low": 0.3,
    "medium": 0.5,
    "high": 0.7,
    "critical": 0.9,
}

# 内置默认策略
DEFAULT_STRATEGIES = {
    "block_ip": {
        "id": "block_ip",
        "name": "IP封禁",
        "description": "封禁威胁源IP地址",
        "min_threat_level": "high",
        "min_score": 0.7,
        "action": "block",
        "target_type": "ip",
        "enabled": True,
        "cooldown": 300,
    },
    "isolate_host": {
        "id": "isolate_host",
        "name": "主机隔离",
        "description": "隔离被入侵的主机",
        "min_threat_level": "critical",
        "min_score": 0.9,
        "action": "isolate",
        "target_type": "host",
        "enabled": True,
        "cooldown": 600,
    },
    "alert_admin": {
        "id": "alert_admin",
        "name": "管理员告警",
        "description": "向管理员发送安全告警通知",
        "min_threat_level": "medium",
        "min_score": 0.5,
        "action": "alert",
        "target_type": "any",
        "enabled": True,
        "cooldown": 60,
    },
    "rate_limit": {
        "id": "rate_limit",
        "name": "速率限制",
        "description": "对可疑源实施速率限制",
        "min_threat_level": "medium",
        "min_score": 0.5,
        "action": "rate_limit",
        "target_type": "ip",
        "enabled": True,
        "cooldown": 120,
    },
}


class IntelligentResponseEngine:
    """
    智能响应引擎
    根据威胁等级和类型自动匹配并执行响应策略
    """

    def __init__(self):
        self._lock = threading.Lock()

        # 响应策略: {strategy_id: strategy_dict}
        self._strategies: Dict[str, Dict[str, Any]] = {}

        # 策略执行冷却: {strategy_id: {target_key: last_execute_time}}
        self._cooldowns: Dict[str, Dict[str, float]] = defaultdict(dict)

        # 响应历史
        self._response_history: deque = deque(maxlen=2000)

        # 统计
        self._stats = {
            "total_responses": 0,
            "total_actions_taken": 0,
            "total_skipped": 0,
            "by_strategy": defaultdict(int),
            "by_level": defaultdict(int),
            "last_response": None,
        }

        # 加载默认策略
        for sid, strategy in DEFAULT_STRATEGIES.items():
            self._strategies[sid] = dict(strategy)

        logger.info(
            "智能响应引擎初始化完成, 加载{}条默认策略".format(len(self._strategies))
        )

    def respond(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据威胁信息执行自动化响应

        Args:
            threat: 威胁信息字典，应包含:
                - score: 威胁分数 (0.0-1.0)
                - level: 威胁等级 (low/medium/high/critical)
                - source_ip: 威胁源IP（可选）
                - target: 攻击目标（可选）
                - threat_type: 威胁类型（可选）
                - description: 威胁描述（可选）

        Returns:
            响应结果，包含执行的策略列表和详情
        """
        with self._lock:
            self._stats["total_responses"] += 1
            self._stats["last_response"] = datetime.now().isoformat()

            threat_score = float(threat.get("score", 0.0))
            threat_level = str(threat.get("level", "low")).lower()
            source_ip = threat.get("source_ip", "")
            target = threat.get("target", "")

            # 确定威胁等级
            if threat_level not in THREAT_THRESHOLDS:
                threat_level = self._score_to_level(threat_score)

            self._stats["by_level"][threat_level] += 1

            # 匹配并执行策略
            actions_taken = []
            actions_skipped = []

            for strategy_id, strategy in self._strategies.items():
                if not strategy.get("enabled", True):
                    continue

                # 检查威胁等级是否满足
                min_level = strategy.get("min_threat_level", "medium")
                if not self._level_meets(threat_level, min_level):
                    actions_skipped.append({
                        "strategy_id": strategy_id,
                        "reason": "threat_level_below_threshold",
                        "required": min_level,
                        "actual": threat_level,
                    })
                    continue

                # 检查分数是否满足
                min_score = strategy.get("min_score", 0.5)
                if threat_score < min_score:
                    actions_skipped.append({
                        "strategy_id": strategy_id,
                        "reason": "score_below_threshold",
                        "required": min_score,
                        "actual": threat_score,
                    })
                    continue

                # 检查冷却时间
                cooldown = strategy.get("cooldown", 0)
                if cooldown > 0:
                    target_key = source_ip or target or "global"
                    last_exec = self._cooldowns[strategy_id].get(target_key, 0)
                    if time.time() - last_exec < cooldown:
                        actions_skipped.append({
                            "strategy_id": strategy_id,
                            "reason": "cooldown_active",
                            "remaining_seconds": round(cooldown - (time.time() - last_exec), 1),
                        })
                        continue

                # 执行策略
                action_result = self._execute_strategy(strategy, threat)

                actions_taken.append({
                    "strategy_id": strategy_id,
                    "strategy_name": strategy.get("name", strategy_id),
                    "action": strategy.get("action"),
                    "result": action_result,
                    "timestamp": datetime.now().isoformat(),
                })

                # 更新冷却
                if cooldown > 0:
                    target_key = source_ip or target or "global"
                    self._cooldowns[strategy_id][target_key] = time.time()

                # 更新统计
                self._stats["total_actions_taken"] += 1
                self._stats["by_strategy"][strategy_id] += 1

            # 记录响应历史
            response_record = {
                "threat": threat,
                "actions_taken": actions_taken,
                "actions_skipped": actions_skipped,
                "threat_level": threat_level,
                "threat_score": threat_score,
                "timestamp": datetime.now().isoformat(),
            }
            self._response_history.append(response_record)

            result = {
                "status": "ok",
                "threat_level": threat_level,
                "threat_score": threat_score,
                "actions_taken": actions_taken,
                "actions_skipped": actions_skipped,
                "total_actions": len(actions_taken),
                "total_skipped": len(actions_skipped),
                "timestamp": datetime.now().isoformat(),
            }

            if actions_taken:
                logger.warning(
                    "智能响应执行: level={}, score={}, 执行{}项策略".format(
                        threat_level, threat_score, len(actions_taken)
                    )
                )
            else:
                logger.debug(
                    "智能响应跳过: level={}, score={}, 无匹配策略".format(
                        threat_level, threat_score
                    )
                )

            return result

    def add_strategy(self, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """
        添加自定义响应策略

        Args:
            strategy: 策略字典，应包含:
                - id: 策略唯一标识
                - name: 策略名称
                - description: 策略描述
                - min_threat_level: 最低触发威胁等级
                - min_score: 最低触发分数
                - action: 执行动作
                - target_type: 目标类型
                - enabled: 是否启用
                - cooldown: 冷却时间（秒）

        Returns:
            添加结果
        """
        with self._lock:
            strategy_id = strategy.get("id")
            if not strategy_id:
                return {"status": "error", "message": "策略ID不能为空"}

            is_update = strategy_id in self._strategies
            self._strategies[strategy_id] = dict(strategy)

            action = "更新" if is_update else "添加"
            logger.info("{}响应策略: id={}, name={}".format(action, strategy_id, strategy.get("name")))

            return {"status": "ok", "action": "updated" if is_update else "created", "strategy_id": strategy_id}

    def remove_strategy(self, strategy_id: str) -> Dict[str, Any]:
        """
        移除响应策略

        Args:
            strategy_id: 策略ID

        Returns:
            移除结果
        """
        with self._lock:
            if strategy_id not in self._strategies:
                return {"status": "error", "message": "策略不存在: {}".format(strategy_id)}

            removed = self._strategies.pop(strategy_id)

            # 清理相关冷却记录
            if strategy_id in self._cooldowns:
                del self._cooldowns[strategy_id]

            logger.info("移除响应策略: id={}, name={}".format(strategy_id, removed.get("name")))

            return {"status": "ok", "removed": removed}

    def _execute_strategy(self, strategy: Dict[str, Any], threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行单个响应策略

        Args:
            strategy: 策略配置
            threat: 威胁信息

        Returns:
            执行结果
        """
        action = strategy.get("action", "unknown")
        strategy_id = strategy.get("id", "unknown")

        try:
            if action == "block":
                source_ip = threat.get("source_ip", "")
                result = {
                    "status": "executed",
                    "action": "block_ip",
                    "target": source_ip,
                    "message": "已封禁IP: {}".format(source_ip) if source_ip else "无源IP可封禁",
                }
            elif action == "isolate":
                target = threat.get("target", "")
                result = {
                    "status": "executed",
                    "action": "isolate_host",
                    "target": target,
                    "message": "已隔离主机: {}".format(target) if target else "无目标可隔离",
                }
            elif action == "alert":
                result = {
                    "status": "executed",
                    "action": "alert_admin",
                    "message": "已发送管理员告警: {}".format(threat.get("description", "未知威胁")),
                }
            elif action == "rate_limit":
                source_ip = threat.get("source_ip", "")
                result = {
                    "status": "executed",
                    "action": "rate_limit",
                    "target": source_ip,
                    "message": "已对IP实施速率限制: {}".format(source_ip) if source_ip else "无源IP可限制",
                }
            else:
                result = {
                    "status": "executed",
                    "action": action,
                    "message": "已执行自定义动作: {}".format(action),
                }
        except Exception as e:
            logger.error("执行策略失败: id={}, error={}".format(strategy_id, e))
            result = {
                "status": "error",
                "action": action,
                "message": "策略执行失败: {}".format(str(e)),
            }

        return result

    def _score_to_level(self, score: float) -> str:
        """
        将威胁分数转换为威胁等级

        Args:
            score: 威胁分数 (0.0-1.0)

        Returns:
            威胁等级字符串
        """
        if score >= 0.9:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.5:
            return "medium"
        else:
            return "low"

    @staticmethod
    def _level_meets(actual_level: str, required_level: str) -> bool:
        """
        判断实际威胁等级是否满足要求的最低等级

        Args:
            actual_level: 实际威胁等级
            required_level: 要求的最低威胁等级

        Returns:
            是否满足
        """
        level_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return level_order.get(actual_level, 0) >= level_order.get(required_level, 0)

    def get_stats(self) -> Dict[str, Any]:
        """
        获取智能响应引擎统计信息

        Returns:
            统计数据字典
        """
        with self._lock:
            strategies_summary = {}
            for sid, strategy in self._strategies.items():
                strategies_summary[sid] = {
                    "name": strategy.get("name", sid),
                    "enabled": strategy.get("enabled", True),
                    "action": strategy.get("action"),
                    "min_threat_level": strategy.get("min_threat_level"),
                    "execution_count": self._stats["by_strategy"].get(sid, 0),
                }

            return {
                "total_responses": self._stats["total_responses"],
                "total_actions_taken": self._stats["total_actions_taken"],
                "total_skipped": self._stats["total_skipped"],
                "by_level": dict(self._stats["by_level"]),
                "last_response": self._stats["last_response"],
                "strategies_count": len(self._strategies),
                "strategies": strategies_summary,
                "response_history_size": len(self._response_history),
                "recent_responses": list(self._response_history)[-10:],
            }


def get_intelligent_response_engine() -> IntelligentResponseEngine:
    """
    获取智能响应引擎单例

    Returns:
        IntelligentResponseEngine 实例
    """
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = IntelligentResponseEngine()
    return _instance
