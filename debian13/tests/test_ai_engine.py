"""
GateKeeper - AI引擎测试
"""

import pytest
import numpy as np
from unittest.mock import patch, MagicMock


# ============================================================
# TrafficAnalyzer 测试
# ============================================================

class TestTrafficAnalyzer:
    """流量分析引擎测试"""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from ai_engine.traffic_analyzer import TrafficAnalyzer
        self.analyzer = TrafficAnalyzer()

    def test_process_packet(self):
        """测试数据包处理"""
        packet_data = {
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "length": 1280,
            "flags": "S",
            "ttl": 64,
        }
        result = self.analyzer.process_packet(packet_data)
        assert result is not None
        assert result["src_ip"] == "192.168.1.100"
        assert result["protocol"] == "TCP"

    def test_analyze_empty_window(self):
        """测试空流量窗口分析"""
        result = self.analyzer.analyze_traffic_window()
        assert result["status"] == "no_data"

    def test_calculate_entropy(self):
        """测试信息熵计算"""
        # 均匀分布
        data = [1, 2, 3, 4, 5, 6, 7, 8]
        entropy = self.analyzer._calculate_entropy(data)
        assert entropy > 0

        # 单一值
        data = [1, 1, 1, 1]
        entropy = self.analyzer._calculate_entropy(data)
        assert entropy == 0.0

    def test_get_stats(self):
        """测试获取统计信息"""
        stats = self.analyzer.get_stats()
        assert "total_packets" in stats
        assert "total_bytes" in stats
        assert "protocol_distribution" in stats


# ============================================================
# AnomalyDetector 测试
# ============================================================

class TestAnomalyDetector:
    """异常检测引擎测试"""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from ai_engine.anomaly_detector import AnomalyDetector
        self.detector = AnomalyDetector()

    def test_rule_based_detect_normal(self):
        """测试规则检测 - 正常流量"""
        features = np.array([500, 5, 2.0, 64])
        result = self.detector._rule_based_detect(features)
        assert result["is_anomaly"] is False
        assert result["method"] == "rule_based"

    def test_rule_based_detect_anomaly(self):
        """测试规则检测 - 异常流量"""
        features = np.array([15000, 100, 0.1, 64])
        result = self.detector._rule_based_detect(features)
        assert result["is_anomaly"] is True

    def test_add_training_data(self):
        """测试添加训练数据"""
        features = np.random.rand(10, 5)
        self.detector.add_training_data(features)
        assert len(self.detector._training_buffer) == 10

    def test_set_threshold(self):
        """测试设置阈值"""
        self.detector.set_threshold(0.9)
        assert self.detector._threshold == 0.9
        self.detector.set_threshold(1.5)
        assert self.detector._threshold == 1.0
        self.detector.set_threshold(-0.5)
        assert self.detector._threshold == 0.0

    def test_get_statistics(self):
        """测试获取统计"""
        stats = self.detector.get_statistics()
        assert "model_trained" in stats
        assert "total_anomalies" in stats


# ============================================================
# ModelManager 测试
# ============================================================

class TestModelManager:
    """模型管理器测试"""

    @pytest.fixture(autouse=True)
    def _setup(self):
        from ai_engine.model_manager import ModelManager
        self.manager = ModelManager()

    def test_get_model(self):
        """测试获取模型"""
        model = self.manager.get_model("isolation_forest")
        assert model is not None

    def test_train_isolation_forest(self):
        """训练Isolation Forest"""
        X = np.random.rand(200, 5)
        result = self.manager.train_isolation_forest(X)
        assert result["status"] == "ok"
        assert "metrics" in result

    def test_get_model_info(self):
        """测试获取模型信息"""
        info = self.manager.get_model_info()
        assert "model_dir" in info
        assert "loaded_models" in info
