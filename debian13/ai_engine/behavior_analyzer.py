"""
GateKeeper - 行为分析引擎
用户/实体行为基线建模与异常行为识别
"""

import threading
import time
import math
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict, deque

from config.logging_config import get_logger

logger = get_logger("behavior_analyzer")

# 模块级单例
_instance = None
_instance_lock = threading.Lock()


class BehaviorAnalyzer:
    """
    行为分析器
    基于历史行为数据建立实体行为基线，识别偏离基线的异常行为
    """

    def __init__(self):
        self._lock = threading.Lock()

        # 实体行为基线: {entity_id: {feature_name: {"mean": float, "std": float, "count": int, "sum": float, "sum_sq": float}}}
        self._baselines: Dict[str, Dict[str, Dict[str, float]]] = defaultdict(
            lambda: defaultdict(lambda: {"mean": 0.0, "std": 0.0, "count": 0, "sum": 0.0, "sum_sq": 0.0})
        )

        # 行为历史记录（用于回溯分析）
        self._behavior_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))

        # 异常行为记录
        self._anomaly_records: deque = deque(maxlen=1000)

        # 统计
        self._stats = {
            "total_analyses": 0,
            "total_anomalies": 0,
            "total_entities": 0,
            "total_baseline_updates": 0,
        }

        logger.info("行为分析引擎初始化完成")

    def analyze_behavior(self, entity_id: str, features: Dict[str, float]) -> Dict[str, Any]:
        """
        分析实体行为是否异常

        Args:
            entity_id: 实体标识（如用户ID、IP地址等）
            features: 行为特征字典，如 {"login_count": 5, "request_rate": 120.5}

        Returns:
            分析结果，包含是否异常、异常分数、异常特征等
        """
        with self._lock:
            self._stats["total_analyses"] += 1

            baseline = self._baselines.get(entity_id, {})
            anomaly_features = []
            anomaly_score = 0.0
            total_weight = 0.0

            for feature_name, value in features.items():
                if not isinstance(value, (int, float)):
                    continue

                feature_baseline = baseline.get(feature_name)
                if feature_baseline and feature_baseline["count"] >= 5:
                    mean = feature_baseline["mean"]
                    std = feature_baseline["std"]

                    # 计算Z-Score
                    if std > 1e-9:
                        z_score = abs(value - mean) / std
                    else:
                        z_score = 0.0 if abs(value - mean) < 1e-9 else 10.0

                    # Z-Score > 3 视为异常
                    if z_score > 3.0:
                        anomaly_features.append({
                            "feature": feature_name,
                            "value": value,
                            "baseline_mean": mean,
                            "baseline_std": std,
                            "z_score": round(z_score, 4),
                        })
                        anomaly_score += min(z_score / 10.0, 1.0)

                    total_weight += 1.0

            # 归一化异常分数
            if total_weight > 0:
                anomaly_score = min(anomaly_score / max(total_weight, 1.0), 1.0)
            else:
                anomaly_score = 0.0

            is_anomaly = len(anomaly_features) > 0

            result = {
                "entity_id": entity_id,
                "is_anomaly": is_anomaly,
                "anomaly_score": round(anomaly_score, 4),
                "anomaly_features": anomaly_features,
                "features_analyzed": len(features),
                "has_baseline": len(baseline) > 0,
                "timestamp": datetime.now().isoformat(),
            }

            if is_anomaly:
                self._stats["total_anomalies"] += 1
                self._anomaly_records.append(result)
                logger.warning(
                    "检测到异常行为: entity={}, score={}, 异常特征={}".format(
                        entity_id, anomaly_score, [f["feature"] for f in anomaly_features]
                    )
                )

            # 记录行为历史
            self._behavior_history[entity_id].append({
                "features": features,
                "result": result,
                "timestamp": datetime.now().isoformat(),
            })

            return result

    def get_baseline(self, entity_id: str) -> Dict[str, Any]:
        """
        获取实体的行为基线

        Args:
            entity_id: 实体标识

        Returns:
            行为基线数据
        """
        with self._lock:
            baseline = self._baselines.get(entity_id, {})
            if not baseline:
                return {
                    "entity_id": entity_id,
                    "exists": False,
                    "features": {},
                }

            features = {}
            for feature_name, stats in baseline.items():
                features[feature_name] = {
                    "mean": round(stats["mean"], 4),
                    "std": round(stats["std"], 4),
                    "count": stats["count"],
                }

            return {
                "entity_id": entity_id,
                "exists": True,
                "features": features,
                "feature_count": len(features),
            }

    def update_baseline(self, entity_id: str, features: Dict[str, float]) -> None:
        """
        使用新的行为数据更新实体基线（增量更新均值和标准差）

        Args:
            entity_id: 实体标识
            features: 行为特征字典
        """
        with self._lock:
            self._stats["total_baseline_updates"] += 1

            if entity_id not in self._baselines:
                self._stats["total_entities"] += 1

            for feature_name, value in features.items():
                if not isinstance(value, (int, float)):
                    continue

                stats = self._baselines[entity_id][feature_name]
                stats["count"] += 1
                old_mean = stats["mean"]
                stats["sum"] += value
                stats["sum_sq"] += value * value

                # Welford 在线算法更新均值
                stats["mean"] = old_mean + (value - old_mean) / stats["count"]

                # 更新标准差（使用增量方差公式）
                if stats["count"] > 1:
                    variance = (stats["sum_sq"] / stats["count"]) - (stats["mean"] ** 2)
                    stats["std"] = math.sqrt(max(0.0, variance))

            logger.debug(
                "更新行为基线: entity={}, features={}".format(entity_id, len(features))
            )

    def get_stats(self) -> Dict[str, Any]:
        """
        获取行为分析器统计信息

        Returns:
            统计数据字典
        """
        with self._lock:
            return {
                **self._stats,
                "tracked_entities": len(self._baselines),
                "anomaly_records": len(self._anomaly_records),
                "recent_anomalies": list(self._anomaly_records)[-10:],
            }


def get_behavior_analyzer() -> BehaviorAnalyzer:
    """
    获取行为分析器单例

    Returns:
        BehaviorAnalyzer 实例
    """
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = BehaviorAnalyzer()
    return _instance
