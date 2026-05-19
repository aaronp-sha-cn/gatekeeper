"""
GateKeeper - 流量分析引擎
基于机器学习的实时网络流量分析，提取流量特征并评估安全风险
"""

import time
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta

try:
    import numpy as np
except ImportError:
    np = None

try:
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import KMeans
except ImportError:
    StandardScaler = None
    KMeans = None

from config.settings import settings
from config.logging_config import get_logger
from core.database import db_manager
from core.models import TrafficLog

logger = get_logger("traffic_analyzer")


class TrafficAnalyzer:
    """
    网络流量分析引擎
    实时分析网络流量特征，识别异常模式
    """

    def __init__(self):
        self._running = False
        self._lock = threading.Lock()

        # 流量统计窗口
        self._window_size = settings.ai_model.analysis_window
        self._traffic_window: deque = deque(maxlen=10000)

        # 连接统计
        self._connection_stats: Dict[str, Dict] = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "src_ports": set(),
            "dst_ports": set(),
            "protocols": defaultdict(int),
            "start_time": None,
            "last_time": None,
            "flags": defaultdict(int),
        })

        # 特征提取器
        if StandardScaler is not None:
            self._scaler = StandardScaler()
        else:
            self._scaler = None

        # 聚类模型（用于流量模式识别）
        if KMeans is not None:
            self._cluster_model = KMeans(
                n_clusters=5,
                random_state=42,
                n_init=10,
            )
        else:
            self._cluster_model = None

        # 统计数据
        self._stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "packets_per_second": 0.0,
            "bytes_per_second": 0.0,
            "unique_sources": 0,
            "unique_destinations": 0,
            "protocol_distribution": defaultdict(int),
            "top_talkers": deque(maxlen=20),
        }

        # 历史数据（用于趋势分析）
        self._history_window = 3600  # 1小时历史
        self._pps_history: deque = deque(maxlen=self._history_window)
        self._bps_history: deque = deque(maxlen=self._history_window)

        # 流量日志缓冲区（用于批量写入数据库）
        self._log_buffer: List[TrafficLog] = []
        self._log_buffer_lock = threading.Lock()
        self._log_buffer_size = 100  # 缓冲区大小阈值
        self._log_flush_interval = 5  # 强制刷新间隔（秒）
        self._last_flush_time = time.time()

        logger.info("流量分析引擎初始化完成")

    def process_packet(self, packet_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        处理单个数据包

        Args:
            packet_data: 包含 src_ip, dst_ip, src_port, dst_port,
                        protocol, length, flags, ttl 的字典

        Returns:
            分析结果字典或None
        """
        src_ip = packet_data.get("src_ip", "0.0.0.0")
        dst_ip = packet_data.get("dst_ip", "0.0.0.0")
        src_port = packet_data.get("src_port")
        dst_port = packet_data.get("dst_port")
        protocol = packet_data.get("protocol", "UNKNOWN")
        length = packet_data.get("length", 0)
        flags = packet_data.get("flags", "")
        ttl = packet_data.get("ttl", 64)

        with self._lock:
            # 更新统计
            self._stats["total_packets"] += 1
            self._stats["total_bytes"] += length
            self._stats["protocol_distribution"][protocol] += 1

            # 更新连接统计
            conn_key = "{}:{}:{}".format(src_ip, dst_ip, protocol)
            stats = self._connection_stats[conn_key]
            stats["packet_count"] += 1
            stats["byte_count"] += length
            stats["src_ports"].add(src_port)
            stats["dst_ports"].add(dst_port)
            stats["protocols"][protocol] += 1
            now = time.time()
            stats["last_time"] = now
            if stats["start_time"] is None:
                stats["start_time"] = now
            if flags:
                stats["flags"][flags] += 1

            # 添加到流量窗口
            self._traffic_window.append({
                "timestamp": now,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": length,
                "flags": flags,
                "ttl": ttl,
            })

        # 保存到数据库（异步，不阻塞）
        self._save_traffic_log(packet_data)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "length": length,
        }

    def analyze_traffic_window(self) -> Dict[str, Any]:
        """
        分析当前流量窗口
        提取特征并评估整体安全状况

        Returns:
            分析结果字典
        """
        with self._lock:
            if not self._traffic_window:
                return {"status": "no_data", "message": "流量窗口为空"}

            now = time.time()
            window_start = now - self._window_size

            # 筛选窗口内的流量
            window_packets = [
                p for p in self._traffic_window
                if p["timestamp"] >= window_start
            ]

            if not window_packets:
                return {"status": "no_data", "message": "窗口内无流量"}

            # 计算基础统计
            total_packets = len(window_packets)
            total_bytes = sum(p["length"] for p in window_packets)
            elapsed = now - window_packets[0]["timestamp"] if window_packets else 1
            pps = total_packets / max(elapsed, 0.001)
            bps = total_bytes / max(elapsed, 0.001)

            # 更新历史
            self._pps_history.append(pps)
            self._bps_history.append(bps)

            # 提取特征
            features = self._extract_features(window_packets)

            # 流量模式分析
            pattern_analysis = self._analyze_patterns(window_packets)

            # 更新统计
            unique_src = len(set(p["src_ip"] for p in window_packets))
            unique_dst = len(set(p["dst_ip"] for p in window_packets))
            self._stats["packets_per_second"] = pps
            self._stats["bytes_per_second"] = bps
            self._stats["unique_sources"] = unique_src
            self._stats["unique_destinations"] = unique_dst

            # 更新top talkers
            src_counts = defaultdict(int)
            for p in window_packets:
                src_counts[p["src_ip"]] += 1
            top_sources = sorted(
                src_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]
            self._stats["top_talkers"] = deque(top_sources, maxlen=20)

            # 清理过期连接统计
            self._cleanup_connection_stats(now)

            result = {
                "status": "ok",
                "timestamp": datetime.now().isoformat(),
                "window_seconds": self._window_size,
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "packets_per_second": round(pps, 2),
                "bytes_per_second": round(bps, 2),
                "unique_sources": unique_src,
                "unique_destinations": unique_dst,
                "protocol_distribution": dict(self._stats["protocol_distribution"]),
                "features": features,
                "pattern_analysis": pattern_analysis,
                "top_sources": top_sources[:5],
            }

            logger.debug(
                "流量分析完成: {} packets, {:.1f} pps, {} sources".format(
                    total_packets, pps, unique_src
                )
            )

            return result

    def _extract_features(self, packets: List[Dict]) -> Dict[str, float]:
        """
        从流量数据中提取特征向量

        Args:
            packets: 数据包列表

        Returns:
            特征字典
        """
        if not packets:
            return {}

        # 基础统计特征
        lengths = [p["length"] for p in packets]
        protocols = [p["protocol"] for p in packets]
        src_ports = [p["src_port"] for p in packets if p.get("src_port")]
        dst_ports = [p["dst_port"] for p in packets if p.get("dst_port")]

        features = {
            # 包大小统计
            "mean_packet_size": float(np.mean(lengths)),
            "std_packet_size": float(np.std(lengths)),
            "min_packet_size": float(np.min(lengths)),
            "max_packet_size": float(np.max(lengths)),
            # 端口多样性
            "unique_src_ports": len(set(src_ports)),
            "unique_dst_ports": len(set(dst_ports)),
            "src_port_entropy": self._calculate_entropy(src_ports),
            "dst_port_entropy": self._calculate_entropy(dst_ports),
            # 协议多样性
            "protocol_entropy": self._calculate_entropy(protocols),
            "unique_protocols": len(set(protocols)),
            # IP多样性
            "unique_src_ips": len(set(p["src_ip"] for p in packets)),
            "unique_dst_ips": len(set(p["dst_ip"] for p in packets)),
            # 时间特征
            "packets_per_second": len(packets) / max(
                packets[-1]["timestamp"] - packets[0]["timestamp"], 0.001
            ),
        }

        return features

    def _analyze_patterns(self, packets: List[Dict]) -> Dict[str, Any]:
        """
        分析流量模式
        使用聚类和统计方法识别异常模式

        Args:
            packets: 数据包列表

        Returns:
            模式分析结果
        """
        if len(packets) < 10:
            return {"status": "insufficient_data"}

        # 构建特征矩阵
        feature_matrix = []
        for p in packets:
            feature_matrix.append([
                p["length"],
                p.get("src_port", 0) or 0,
                p.get("dst_port", 0) or 0,
                p.get("ttl", 64),
                len(p.get("flags", "")),
            ])

        X = np.array(feature_matrix, dtype=np.float64)

        # 标准化
        try:
            X_scaled = self._scaler.fit_transform(X) if self._scaler else X
        except Exception:
            X_scaled = X

        # 聚类分析
        n_clusters = min(5, len(packets) // 2)
        if n_clusters >= 2:
            self._cluster_model = KMeans(
                n_clusters=n_clusters, random_state=42, n_init=10
            )
            try:
                labels = self._cluster_model.fit_predict(X_scaled) if self._cluster_model else None
                unique_labels, counts = np.unique(labels, return_counts=True)

                # 检测异常簇（占比很小的簇可能是异常）
                total = len(labels)
                anomaly_clusters = []
                for label, count in zip(unique_labels, counts):
                    ratio = count / total
                    if ratio < 0.05:  # 占比小于5%的簇
                        anomaly_clusters.append({
                            "cluster_id": int(label),
                            "count": int(count),
                            "ratio": round(ratio, 4),
                        })

                return {
                    "status": "ok",
                    "n_clusters": n_clusters,
                    "cluster_sizes": {
                        int(l): int(c) for l, c in zip(unique_labels, counts)
                    },
                    "anomaly_clusters": anomaly_clusters,
                    "has_anomaly": len(anomaly_clusters) > 0,
                }
            except Exception as e:
                logger.debug("聚类分析失败: {}".format(e))
                return {"status": "error", "message": str(e)}

        return {"status": "insufficient_data"}

    def _calculate_entropy(self, data: List) -> float:
        """
        计算信息熵
        用于衡量数据的随机性和多样性

        Args:
            data: 数据列表

        Returns:
            熵值
        """
        if not data:
            return 0.0

        from collections import Counter
        counts = Counter(data)
        total = len(data)
        entropy = 0.0

        for count in counts.values():
            if count > 0:
                probability = count / total
                entropy -= probability * np.log2(probability)

        return round(entropy, 4)

    def _cleanup_connection_stats(self, current_time: float):
        """清理过期的连接统计"""
        timeout = 300  # 5分钟超时
        expired_keys = [
            key for key, stats in self._connection_stats.items()
            if stats["last_time"] and (current_time - stats["last_time"]) > timeout
        ]
        for key in expired_keys:
            del self._connection_stats[key]

    def _save_traffic_log(self, packet_data: Dict[str, Any]):
        """保存流量日志到数据库（使用缓冲区批量写入）"""
        try:
            log_entry = TrafficLog(
                source_ip=packet_data.get("src_ip", "0.0.0.0"),
                dest_ip=packet_data.get("dst_ip", "0.0.0.0"),
                source_port=packet_data.get("src_port"),
                dest_port=packet_data.get("dst_port"),
                protocol=packet_data.get("protocol", "UNKNOWN"),
                packet_length=packet_data.get("length", 0),
                flags=packet_data.get("flags", ""),
                ttl=packet_data.get("ttl"),
            )

            with self._log_buffer_lock:
                self._log_buffer.append(log_entry)

                # 检查是否需要刷新缓冲区
                current_time = time.time()
                should_flush = (
                    len(self._log_buffer) >= self._log_buffer_size or
                    (current_time - self._last_flush_time) >= self._log_flush_interval
                )

                if should_flush:
                    self._flush_log_buffer()

        except Exception as e:
            logger.debug("保存流量日志失败: {}".format(e))

    def _flush_log_buffer(self):
        """将缓冲区中的日志批量写入数据库"""
        if not self._log_buffer:
            return

        try:
            # 复制并清空缓冲区
            logs_to_save = self._log_buffer[:]
            self._log_buffer = []
            self._last_flush_time = time.time()

            # 批量写入数据库
            db_manager.add_all(logs_to_save)
            logger.debug("批量写入 {} 条流量日志".format(len(logs_to_save)))
        except Exception as e:
            logger.error("批量写入流量日志失败: {}".format(e))

    def flush_logs(self):
        """强制刷新日志缓冲区（供外部调用）"""
        with self._log_buffer_lock:
            self._flush_log_buffer()

    def get_stats(self) -> Dict[str, Any]:
        """获取当前流量统计"""
        with self._lock:
            return {
                **self._stats,
                "protocol_distribution": dict(
                    self._stats["protocol_distribution"]
                ),
                "active_connections": len(self._connection_stats),
                "top_talkers": list(self._stats["top_talkers"]),
                "pps_trend": list(self._pps_history)[-60:],  # 最近1分钟
                "bps_trend": list(self._bps_history)[-60:],
            }

    def get_connection_detail(self, src_ip: str, dst_ip: str, protocol: str = "") -> Optional[Dict]:
        """获取指定连接的详细信息"""
        with self._lock:
            if protocol:
                key = "{}:{}:{}".format(src_ip, dst_ip, protocol)
            else:
                # 查找所有匹配的连接
                matches = {
                    k: v for k, v in self._connection_stats.items()
                    if k.startswith("{}:{}".format(src_ip, dst_ip))
                }
                if not matches:
                    return None
                key = list(matches.keys())[0]

            stats = self._connection_stats.get(key)
            if not stats:
                return None

            return {
                "connection_key": key,
                "packet_count": stats["packet_count"],
                "byte_count": stats["byte_count"],
                "src_ports": list(stats["src_ports"]),
                "dst_ports": list(stats["dst_ports"]),
                "protocols": dict(stats["protocols"]),
                "flags": dict(stats["flags"]),
                "duration": (
                    stats["last_time"] - stats["start_time"]
                    if stats["start_time"] and stats["last_time"]
                    else 0
                ),
            }
