"""
GateKeeper - 异常检测引擎
基于机器学习的网络异常行为检测，支持多种检测算法
"""

import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import deque

try:
    import numpy as np
except ImportError:
    np = None

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.neighbors import LocalOutlierFactor
except ImportError:
    IsolationForest = None
    StandardScaler = None
    LocalOutlierFactor = None

from config.settings import settings
from config.logging_config import get_logger
from core.models import TrafficLog, Alert, AlertLevel, AlertStatus
from core.database import db_manager

logger = get_logger("anomaly_detector")


class AnomalyDetector:
    """
    网络异常检测引擎
    使用多种机器学习算法检测网络流量中的异常行为
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._threshold = settings.ai_model.anomaly_threshold

        # 特征标准化器
        if StandardScaler is not None:
            self._scaler = StandardScaler()
        else:
            self._scaler = None

        # Isolation Forest 模型（适用于高维数据）
        if IsolationForest is not None:
            self._isolation_forest = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                max_samples="auto",
                random_state=42,
                n_jobs=-1,
            )
        else:
            self._isolation_forest = None

        # 训练数据缓冲区
        self._training_buffer: deque = deque(maxlen=50000)
        self._is_trained = False

        # 检测结果历史
        self._detection_history: deque = deque(maxlen=1000)

        # 异常计数统计
        self._anomaly_counts = {
            "total": 0,
            "last_hour": 0,
            "by_type": {},
        }

        # 异常事件回调列表
        self._callbacks: List = []

        logger.info("异常检测引擎初始化完成")

    def add_training_data(self, features: np.ndarray):
        """
        添加训练数据

        Args:
            features: 特征矩阵 (n_samples, n_features)
        """
        with self._lock:
            if isinstance(features, list):
                features = np.array(features)
            if features.ndim == 1:
                features = features.reshape(1, -1)

            for row in features:
                self._training_buffer.append(row.tolist())

            logger.debug(
                "添加训练数据: {} 条, 缓冲区大小: {}".format(
                    len(features), len(self._training_buffer)
                )
            )

    def train(self) -> Dict[str, Any]:
        """
        使用缓冲区中的数据训练模型

        Returns:
            训练结果
        """
        with self._lock:
            if len(self._training_buffer) < 100:
                return {
                    "status": "insufficient_data",
                    "message": "训练数据不足，需要至少100条，当前{}条".format(len(self._training_buffer)),
                }

            X = np.array(list(self._training_buffer))

            # 标准化
            self._scaler.fit(X)
            X_scaled = self._scaler.transform(X)

            # 训练 Isolation Forest
            self._isolation_forest.fit(X_scaled)
            self._is_trained = True

            # 计算训练集上的异常分数
            scores = self._isolation_forest.decision_function(X_scaled)
            threshold = np.percentile(scores, 10)  # 底部10%为异常

            result = {
                "status": "ok",
                "training_samples": len(X),
                "n_features": X.shape[1],
                "threshold": round(float(threshold), 4),
                "mean_score": round(float(np.mean(scores)), 4),
                "std_score": round(float(np.std(scores)), 4),
            }

            logger.info(
                "模型训练完成: {} 样本, 阈值={:.4f}".format(
                    len(X), threshold
                )
            )
            return result

    def detect(self, features: np.ndarray) -> Dict[str, Any]:
        """
        检测单个样本是否异常

        Args:
            features: 特征向量 (n_features,)

        Returns:
            检测结果
        """
        if isinstance(features, list):
            features = np.array(features)

        if features.ndim == 1:
            features = features.reshape(1, -1)

        if not self._is_trained:
            # 未训练时使用简单规则检测
            return self._rule_based_detect(features[0])

        with self._lock:
            try:
                X_scaled = self._scaler.transform(features)
                score = self._isolation_forest.decision_function(X_scaled)[0]
                prediction = self._isolation_forest.predict(X_scaled)[0]

                is_anomaly = prediction == -1
                anomaly_score = max(0.0, min(1.0, 1.0 - (score + 0.5)))

                result = {
                    "is_anomaly": is_anomaly,
                    "anomaly_score": round(float(anomaly_score), 4),
                    "raw_score": round(float(score), 4),
                    "threshold": self._threshold,
                    "method": "isolation_forest",
                    "timestamp": datetime.now().isoformat(),
                }

                if is_anomaly:
                    self._anomaly_counts["total"] += 1
                    self._anomaly_counts["last_hour"] += 1
                    anomaly_type = self._classify_anomaly(features[0])
                    self._anomaly_counts["by_type"][anomaly_type] = (
                        self._anomaly_counts["by_type"].get(anomaly_type, 0) + 1
                    )
                    result["anomaly_type"] = anomaly_type

                self._detection_history.append(result)

                return result

            except Exception as e:
                logger.error("异常检测失败: {}".format(e))
                return self._rule_based_detect(features[0])

    def detect_batch(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """
        批量检测

        Args:
            features: 特征矩阵 (n_samples, n_features)

        Returns:
            检测结果列表
        """
        if isinstance(features, list):
            features = np.array(features)

        results = []
        for i in range(len(features)):
            result = self.detect(features[i])
            results.append(result)

        return results

    def _rule_based_detect(self, features: np.ndarray) -> Dict[str, Any]:
        """
        基于规则的简单异常检测
        当机器学习模型未训练时使用

        Args:
            features: 特征向量

        Returns:
            检测结果
        """
        anomaly_indicators = []
        anomaly_score = 0.0

        # 规则1: 包大小异常（过大或过小）
        if len(features) > 0:
            pkt_size = features[0]
            if pkt_size > 10000 or pkt_size == 0:
                anomaly_indicators.append("abnormal_packet_size")
                anomaly_score += 0.3

        # 规则2: 端口扫描检测（多个不同目标端口）
        if len(features) > 1:
            dst_ports = features[1]
            if dst_ports > 50:  # 短时间内连接超过50个不同端口
                anomaly_indicators.append("possible_port_scan")
                anomaly_score += 0.4

        # 规则3: 协议异常
        if len(features) > 2:
            protocol_entropy = features[2]
            if protocol_entropy < 0.1:  # 协议过于单一
                anomaly_indicators.append("low_protocol_diversity")
                anomaly_score += 0.2

        is_anomaly = anomaly_score >= self._threshold

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(float(min(anomaly_score, 1.0)), 4),
            "raw_score": round(float(anomaly_score), 4),
            "threshold": self._threshold,
            "method": "rule_based",
            "indicators": anomaly_indicators,
            "timestamp": datetime.now().isoformat(),
        }

    def _classify_anomaly(self, features: np.ndarray) -> str:
        """
        对检测到的异常进行分类

        Args:
            features: 异常特征向量

        Returns:
            异常类型字符串
        """
        # 简单的基于特征值的分类
        if len(features) > 1 and features[1] > 30:
            return "port_scan"
        if len(features) > 0 and features[0] > 5000:
            return "large_packet"
        if len(features) > 3 and features[3] > 100:
            return "high_frequency"
        return "unknown_anomaly"

    def run_detection(self) -> Dict[str, Any]:
        """
        执行一轮异常检测
        从数据库读取最近的流量日志，提取特征并检测

        Returns:
            检测结果摘要
        """
        logger.info("开始执行异常检测...")

        # 从数据库获取最近的流量数据
        try:
            with db_manager.get_session() as session:
                recent_logs = (
                    session.query(TrafficLog)
                    .order_by(TrafficLog.timestamp.desc())
                    .limit(1000)
                    .all()
                )
        except Exception as e:
            logger.error("获取流量日志失败: {}".format(e))
            return {"status": "error", "message": str(e)}

        if not recent_logs:
            return {"status": "no_data", "message": "无流量数据"}

        # 提取特征
        features = self._extract_features_from_logs(recent_logs)

        if not features:
            return {"status": "no_features", "message": "无法提取特征"}

        X = np.array(features)

        # 如果未训练，先添加训练数据
        if not self._is_trained:
            self.add_training_data(X)
            if len(self._training_buffer) >= 100:
                self.train()

        # 执行检测
        results = self.detect_batch(X)

        # 统计结果
        anomaly_count = sum(1 for r in results if r["is_anomaly"])
        avg_score = np.mean([r["anomaly_score"] for r in results])

        # 处理异常告警
        if anomaly_count > 0:
            self._handle_anomalies(results, recent_logs)

        summary = {
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "samples_analyzed": len(recent_logs),
            "anomalies_detected": anomaly_count,
            "anomaly_rate": round(anomaly_count / len(results), 4),
            "average_score": round(float(avg_score), 4),
            "model_trained": self._is_trained,
            "training_buffer_size": len(self._training_buffer),
        }

        logger.info(
            "异常检测完成: 分析{}条, 发现{}个异常".format(
                len(recent_logs), anomaly_count
            )
        )

        return summary

    def _extract_features_from_logs(self, logs: List[TrafficLog]) -> List[List[float]]:
        """
        从流量日志中提取特征向量

        Args:
            logs: 流量日志列表

        Returns:
            特征向量列表
        """
        from collections import Counter

        features = []
        for log in logs:
            feature_vector = [
                float(log.packet_length or 0),      # 包大小
                float(log.source_port or 0),          # 源端口
                float(log.dest_port or 0),            # 目标端口
                float(log.ttl or 64),                 # TTL
                float(len(log.flags or "")),          # 标志位数量
                float(1 if log.protocol == "TCP" else 0),  # 是否TCP
                float(1 if log.protocol == "UDP" else 0),  # 是否UDP
                float(1 if log.protocol == "ICMP" else 0), # 是否ICMP
            ]
            features.append(feature_vector)

        return features

    def _handle_anomalies(self, results: List[Dict], logs: List[TrafficLog]):
        """
        处理检测到的异常，生成告警

        Args:
            results: 检测结果列表
            logs: 对应的流量日志
        """
        for i, result in enumerate(results):
            if result["is_anomaly"] and i < len(logs):
                log = logs[i]
                anomaly_type = result.get("anomaly_type", "unknown")

                # 确定告警级别
                if result["anomaly_score"] >= 0.9:
                    level = AlertLevel.CRITICAL
                elif result["anomaly_score"] >= 0.7:
                    level = AlertLevel.HIGH
                elif result["anomaly_score"] >= 0.5:
                    level = AlertLevel.MEDIUM
                else:
                    level = AlertLevel.LOW

                # 创建告警
                alert = Alert(
                    title="检测到网络异常: {}".format(anomaly_type),
                    description=(
                        "源IP: {}, 目标IP: {}, 协议: {}, 异常分数: {}".format(
                            log.source_ip, log.dest_ip, log.protocol,
                            result['anomaly_score']
                        )
                    ),
                    level=level,
                    status=AlertStatus.NEW,
                    source="anomaly_detector",
                    source_ip=log.source_ip,
                    dest_ip=log.dest_ip,
                    port=log.dest_port,
                    protocol=log.protocol,
                    severity_score=result["anomaly_score"],
                    metadata_json={
                        "detection_method": result.get("method", "unknown"),
                        "anomaly_type": anomaly_type,
                        "raw_score": result.get("raw_score", 0),
                    },
                )

                try:
                    db_manager.add(alert)
                    logger.warning(
                        "异常告警: {}, score={}, src={}".format(
                            anomaly_type, result['anomaly_score'],
                            log.source_ip
                        )
                    )
                except Exception as e:
                    logger.error("创建异常告警失败: {}".format(e))

                # 触发回调
                for callback in self._callbacks:
                    try:
                        callback(result, log)
                    except Exception as e:
                        logger.error("异常回调执行失败: {}".format(e))

    def register_callback(self, callback):
        """注册异常事件回调函数"""
        self._callbacks.append(callback)

    def get_statistics(self) -> Dict[str, Any]:
        """获取异常检测统计"""
        return {
            "model_trained": self._is_trained,
            "training_buffer_size": len(self._training_buffer),
            "total_anomalies": self._anomaly_counts["total"],
            "last_hour_anomalies": self._anomaly_counts["last_hour"],
            "anomaly_types": dict(self._anomaly_counts["by_type"]),
            "detection_history_size": len(self._detection_history),
            "threshold": self._threshold,
        }

    def set_threshold(self, threshold: float):
        """设置异常检测阈值"""
        self._threshold = max(0.0, min(1.0, threshold))
        logger.info("异常检测阈值已更新: {}".format(self._threshold))
