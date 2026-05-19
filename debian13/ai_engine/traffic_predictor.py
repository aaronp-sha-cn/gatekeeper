"""
GateKeeper - 流量预测引擎
基于历史数据的流量趋势预测（简单移动平均 + 线性回归）
"""

import logging
import threading
import time
import math
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from collections import deque

logger = logging.getLogger(__name__)

# 模块级单例
_instance = None
_instance_lock = threading.Lock()


class TrafficPredictor:
    """
    流量预测器
    使用简单移动平均和线性回归对网络流量趋势进行预测
    """

    def __init__(self):
        self._lock = threading.Lock()

        # 历史数据存储: deque of (timestamp, value)
        self._samples: deque = deque(maxlen=8640)  # 最多存储30天的每小时数据

        # 预测配置
        self._sma_window = 24  # 简单移动平均窗口（小时）
        self._max_history_hours = 720  # 最大历史数据保留时间（30天）

        # 统计
        self._stats = {
            "total_samples": 0,
            "total_predictions": 0,
            "last_prediction": None,
            "last_sample_time": None,
        }

        logger.info("流量预测引擎初始化完成")

    def add_sample(self, timestamp: datetime, value: float) -> None:
        """
        添加流量采样数据

        Args:
            timestamp: 采样时间戳
            value: 流量值（如字节数、包数、连接数等）
        """
        with self._lock:
            if not isinstance(timestamp, datetime):
                timestamp = datetime.fromtimestamp(timestamp) if isinstance(timestamp, (int, float)) else datetime.now()

            self._samples.append((timestamp, float(value)))
            self._stats["total_samples"] += 1
            self._stats["last_sample_time"] = timestamp.isoformat()

            logger.debug(
                "添加流量采样: time={}, value={}".format(timestamp.isoformat(), value)
            )

    def predict(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        预测未来指定小时数的流量趋势

        Args:
            hours: 预测的小时数

        Returns:
            预测结果列表，每项包含时间戳和预测值
        """
        with self._lock:
            self._stats["total_predictions"] += 1

            if len(self._samples) < 3:
                logger.warning("历史数据不足，无法进行预测（需要至少3条数据）")
                return []

            samples = list(self._samples)
            self._stats["last_prediction"] = datetime.now().isoformat()

            # 计算简单移动平均
            sma_value = self._calculate_sma(samples)

            # 计算线性回归
            slope, intercept = self._calculate_linear_regression(samples)

            # 生成预测结果
            last_timestamp = samples[-1][0]
            predictions = []

            for i in range(1, hours + 1):
                future_time = last_timestamp + timedelta(hours=i)

                # 综合预测：SMA + 线性回归加权
                lr_value = intercept + slope * i
                sma_weight = 0.4
                lr_weight = 0.6

                predicted_value = sma_weight * sma_value + lr_weight * lr_value
                predicted_value = max(0.0, predicted_value)  # 流量不能为负

                predictions.append({
                    "timestamp": future_time.isoformat(),
                    "hour_offset": i,
                    "predicted_value": round(predicted_value, 2),
                    "sma_component": round(sma_value, 2),
                    "lr_component": round(lr_value, 2),
                })

            logger.info(
                "流量预测完成: 预测{}小时, SMA={:.2f}, 趋势斜率={:.4f}".format(
                    hours, sma_value, slope
                )
            )

            return predictions

    def _calculate_sma(self, samples: List[Tuple[datetime, float]]) -> float:
        """
        计算简单移动平均值

        Args:
            samples: 采样数据列表

        Returns:
            移动平均值
        """
        window = min(self._sma_window, len(samples))
        recent = samples[-window:]
        return sum(v for _, v in recent) / len(recent)

    def _calculate_linear_regression(self, samples: List[Tuple[datetime, float]]) -> Tuple[float, float]:
        """
        计算线性回归参数（斜率和截距）

        Args:
            samples: 采样数据列表

        Returns:
            (斜率, 截距) 元组
        """
        n = len(samples)
        if n < 2:
            return 0.0, self._calculate_sma(samples)

        # 将时间戳转换为相对小时数
        base_time = samples[0][0]
        x_values = []
        y_values = []

        for ts, val in samples:
            delta = ts - base_time
            x = delta.total_seconds() / 3600.0  # 转换为小时
            x_values.append(x)
            y_values.append(val)

        # 计算线性回归: y = slope * x + intercept
        sum_x = sum(x_values)
        sum_y = sum(y_values)
        sum_xy = sum(x * y for x, y in zip(x_values, y_values))
        sum_x_sq = sum(x * x for x in x_values)

        denominator = n * sum_x_sq - sum_x * sum_x
        if abs(denominator) < 1e-12:
            return 0.0, sum_y / n

        slope = (n * sum_xy - sum_x * sum_y) / denominator
        intercept = (sum_y - slope * sum_x) / n

        return slope, intercept

    def get_stats(self) -> Dict[str, Any]:
        """
        获取流量预测器统计信息

        Returns:
            统计数据字典
        """
        with self._lock:
            samples = list(self._samples)
            current_value = samples[-1][1] if samples else 0.0

            # 计算基本统计
            if samples:
                values = [v for _, v in samples]
                avg_value = sum(values) / len(values)
                max_value = max(values)
                min_value = min(values)
            else:
                avg_value = 0.0
                max_value = 0.0
                min_value = 0.0

            return {
                **self._stats,
                "current_samples": len(samples),
                "current_value": round(current_value, 2),
                "average_value": round(avg_value, 2),
                "max_value": round(max_value, 2),
                "min_value": round(min_value, 2),
                "sma_window": self._sma_window,
            }


def get_traffic_predictor() -> TrafficPredictor:
    """
    获取流量预测器单例

    Returns:
        TrafficPredictor 实例
    """
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = TrafficPredictor()
    return _instance
