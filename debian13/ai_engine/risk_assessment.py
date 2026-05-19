"""
GateKeeper - 风险评估引擎
综合多维度安全风险量化评估
"""

import logging
import threading
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

# 模块级单例
_instance = None
_instance_lock = threading.Lock()

# 风险等级定义
RISK_LEVELS = {
    "low": {"min": 0, "max": 30, "color": "#22c55e", "label": "低风险"},
    "medium": {"min": 30, "max": 60, "color": "#f59e0b", "label": "中风险"},
    "high": {"min": 60, "max": 80, "color": "#f97316", "label": "高风险"},
    "critical": {"min": 80, "max": 100, "color": "#ef4444", "label": "严重风险"},
}

# 风险因子权重
DEFAULT_FACTOR_WEIGHTS = {
    "threat_intel": 0.25,
    "anomaly_score": 0.20,
    "vulnerability": 0.20,
    "exposure": 0.15,
    "behavior": 0.10,
    "asset_value": 0.10,
}


class RiskAssessmentEngine:
    """
    风险评估引擎
    综合多维度安全因子进行风险量化评估，输出风险分数和等级
    """

    def __init__(self):
        self._lock = threading.Lock()

        # 风险因子权重（可动态调整）
        self._factor_weights: Dict[str, float] = dict(DEFAULT_FACTOR_WEIGHTS)

        # 风险历史记录: {target_id: deque of risk records}
        self._risk_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

        # 全局风险记录
        self._all_risk_records: deque = deque(maxlen=5000)

        # 统计
        self._stats = {
            "total_assessments": 0,
            "by_level": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "last_assessment": None,
        }

        logger.info("风险评估引擎初始化完成")

    def assess_risk(self, target_id: str, factors: Dict[str, float]) -> Dict[str, Any]:
        """
        对目标进行综合风险评估

        Args:
            target_id: 评估目标标识（如IP、主机名、应用名等）
            factors: 风险因子字典，键为因子名称，值为0-100的分数
                     支持的因子: threat_intel, anomaly_score, vulnerability,
                                exposure, behavior, asset_value

        Returns:
            风险评估结果，包含综合分数、风险等级、各因子详情
        """
        with self._lock:
            self._stats["total_assessments"] += 1
            self._stats["last_assessment"] = datetime.now().isoformat()

            # 计算加权风险分数
            weighted_score = 0.0
            total_weight = 0.0
            factor_details = {}

            for factor_name, factor_value in factors.items():
                # 确保因子值在 0-100 范围内
                normalized_value = max(0.0, min(100.0, float(factor_value)))

                weight = self._factor_weights.get(factor_name, 0.1)
                weighted_score += normalized_value * weight
                total_weight += weight

                factor_details[factor_name] = {
                    "value": round(normalized_value, 2),
                    "weight": weight,
                    "weighted_score": round(normalized_value * weight, 2),
                }

            # 归一化分数到 0-100
            if total_weight > 0:
                risk_score = weighted_score / total_weight
            else:
                risk_score = 0.0

            risk_score = max(0.0, min(100.0, risk_score))

            # 确定风险等级
            risk_level = self.get_risk_level(risk_score)

            # 构建结果
            result = {
                "target_id": target_id,
                "risk_score": round(risk_score, 2),
                "risk_level": risk_level,
                "factors": factor_details,
                "timestamp": datetime.now().isoformat(),
            }

            # 更新统计
            if risk_level in self._stats["by_level"]:
                self._stats["by_level"][risk_level] += 1

            # 保存历史记录
            self._risk_history[target_id].append(result)
            self._all_risk_records.append(result)

            logger.info(
                "风险评估完成: target={}, score={}, level={}".format(
                    target_id, risk_score, risk_level
                )
            )

            return result

    def get_risk_level(self, score: float) -> str:
        """
        根据风险分数获取风险等级

        Args:
            score: 风险分数 (0-100)

        Returns:
            风险等级字符串: low, medium, high, critical
        """
        score = max(0.0, min(100.0, float(score)))

        if score < 30:
            return "low"
        elif score < 60:
            return "medium"
        elif score < 80:
            return "high"
        else:
            return "critical"

    def get_risk_history(self, target_id: str) -> List[Dict[str, Any]]:
        """
        获取指定目标的风险评估历史

        Args:
            target_id: 目标标识

        Returns:
            历史评估记录列表，按时间倒序排列
        """
        with self._lock:
            history = self._risk_history.get(target_id, deque())
            return list(reversed(list(history)))

    def get_stats(self) -> Dict[str, Any]:
        """
        获取风险评估引擎统计信息

        Returns:
            统计数据字典
        """
        with self._lock:
            return {
                **self._stats,
                "tracked_targets": len(self._risk_history),
                "total_records": len(self._all_risk_records),
                "factor_weights": dict(self._factor_weights),
            }


def get_risk_assessment_engine() -> RiskAssessmentEngine:
    """
    获取风险评估引擎单例

    Returns:
        RiskAssessmentEngine 实例
    """
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = RiskAssessmentEngine()
    return _instance
