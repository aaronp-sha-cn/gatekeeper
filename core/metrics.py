"""
GateKeeper - Prometheus Metrics Collector
Provides metrics collection and Prometheus text format output
"""

import threading
import time
from typing import Dict, Optional, List, Tuple
from collections import defaultdict, deque


class MetricsCollector:
    """
    Metrics collector singleton
    Collects counters, gauges, and histograms and formats them
    for Prometheus scraping.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self._data_lock = threading.Lock()

        # Counters: metric_name -> {label_tuple: value}
        self._counters: Dict[str, Dict[tuple, float]] = defaultdict(lambda: defaultdict(float))

        # Gauges: metric_name -> {label_tuple: value}
        self._gauges: Dict[str, Dict[tuple, float]] = defaultdict(lambda: defaultdict(float))

        # Histograms: metric_name -> {label_tuple: deque(maxlen=N)}
        self._histograms: Dict[str, Dict[tuple, deque]] = defaultdict(lambda: defaultdict(list))
        self._histogram_max_samples: int = 1000

        # Metric metadata: metric_name -> {"help": ..., "type": ...}
        self._metadata: Dict[str, Dict[str, str]] = {}

        # Track last access time for counters/gauges: metric_name -> timestamp
        self._last_access: Dict[str, float] = {}

        # Pre-defined metrics
        self._define_predefined_metrics()

    def _define_predefined_metrics(self):
        """Define pre-configured GateKeeper metrics"""
        self._metadata["gatekeeper_http_requests_total"] = {
            "help": "Total number of HTTP requests received",
            "type": "counter",
        }
        self._metadata["gatekeeper_active_sessions"] = {
            "help": "Number of currently active user sessions",
            "type": "gauge",
        }
        self._metadata["gatekeeper_packets_captured"] = {
            "help": "Total number of network packets captured",
            "type": "counter",
        }
        self._metadata["gatekeeper_alerts_total"] = {
            "help": "Total number of alerts generated",
            "type": "counter",
        }
        self._metadata["gatekeeper_blocked_requests"] = {
            "help": "Total number of blocked requests",
            "type": "counter",
        }

    def _labels_to_tuple(self, labels: Optional[Dict[str, str]]) -> tuple:
        """Convert labels dict to a sorted tuple for use as dict key"""
        if not labels:
            return ()
        return tuple(sorted(labels.items()))

    def _labels_to_string(self, labels: Optional[Dict[str, str]]) -> str:
        """Convert labels dict to Prometheus label string"""
        if not labels:
            return ""
        parts = []
        for k, v in sorted(labels.items()):
            # Escape special characters in label values
            escaped_v = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            parts.append('{}="{}"'.format(k, escaped_v))
        return "{" + ",".join(parts) + "}"

    def increment_counter(self, name: str, labels: Optional[Dict[str, str]] = None, value: float = 1.0):
        """
        Increment a counter metric.

        Args:
            name: Metric name
            labels: Optional label dict (e.g., {"method": "GET", "status": "200"})
            value: Amount to increment (default 1.0)
        """
        key = self._labels_to_tuple(labels)
        with self._data_lock:
            self._counters[name][key] += value
            self._last_access[name] = time.time()
            if name not in self._metadata:
                self._metadata[name] = {"help": "", "type": "counter"}

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """
        Set a gauge metric to a specific value.

        Args:
            name: Metric name
            value: Gauge value
            labels: Optional label dict
        """
        key = self._labels_to_tuple(labels)
        with self._data_lock:
            self._gauges[name][key] = value
            self._last_access[name] = time.time()
            if name not in self._metadata:
                self._metadata[name] = {"help": "", "type": "gauge"}

    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None, max_samples: int = None):
        """
        Observe a value for a histogram metric.

        Args:
            name: Metric name
            value: Observed value
            labels: Optional label dict
            max_samples: Maximum samples per label combination (default: self._histogram_max_samples)
        """
        if max_samples is None:
            max_samples = self._histogram_max_samples
        key = self._labels_to_tuple(labels)
        with self._data_lock:
            values_list = self._histograms[name][key]
            # Convert plain list to deque with maxlen on first overflow
            if not isinstance(values_list, deque):
                if len(values_list) >= max_samples:
                    # Trim oldest values
                    values_list = deque(values_list[-max_samples:], maxlen=max_samples)
                    self._histograms[name][key] = values_list
                else:
                    values_list.append(value)
            else:
                values_list.append(value)
            self._last_access[name] = time.time()
            if name not in self._metadata:
                self._metadata[name] = {"help": "", "type": "histogram"}

    def _format_histogram_bucket(self, name: str, label_str: str, values: List[float]) -> List[str]:
        """Format histogram values into Prometheus bucket format"""
        if not values:
            return []

        lines = []
        sorted_values = sorted(values)
        count = len(sorted_values)

        # Standard Prometheus histogram buckets
        buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("+inf")]

        for bucket in buckets:
            if bucket == float("+inf"):
                bucket_count = count
                bucket_label = '+Inf'
            else:
                bucket_count = sum(1 for v in sorted_values if v <= bucket)
                bucket_label = str(bucket)

            metric_name = "{}_bucket".format(name)
            if label_str:
                lines.append("{}{{{},le=\"{}\"}} {}".format(metric_name, label_str[1:-1], bucket_label, bucket_count))
            else:
                lines.append("{}{{le=\"{}\"}} {}".format(metric_name, bucket_label, bucket_count))

        # _sum and _count
        total = sum(sorted_values)
        sum_name = "{}_sum".format(name)
        count_name = "{}_count".format(name)
        if label_str:
            lines.append("{}{} {}".format(sum_name, label_str, total))
            lines.append("{}{} {}".format(count_name, label_str, count))
        else:
            lines.append("{} {}".format(sum_name, total))
            lines.append("{} {}".format(count_name, count))

        return lines

    def generate_prometheus_output(self) -> str:
        """
        Generate metrics in Prometheus text exposition format.

        Returns:
            String in Prometheus text format
        """
        lines = []

        with self._data_lock:
            # Output counters
            for name, label_dict in self._counters.items():
                meta = self._metadata.get(name, {"help": "", "type": "counter"})
                if meta.get("help"):
                    lines.append("# HELP {} {}".format(name, meta["help"]))
                lines.append("# TYPE {} counter".format(name))
                for label_tuple, value in label_dict.items():
                    labels = dict(label_tuple) if label_tuple else None
                    label_str = self._labels_to_string(labels)
                    if label_str:
                        lines.append("{}{} {}".format(name, label_str, value))
                    else:
                        lines.append("{} {}".format(name, value))
                lines.append("")

            # Output gauges
            for name, label_dict in self._gauges.items():
                meta = self._metadata.get(name, {"help": "", "type": "gauge"})
                if meta.get("help"):
                    lines.append("# HELP {} {}".format(name, meta["help"]))
                lines.append("# TYPE {} gauge".format(name))
                for label_tuple, value in label_dict.items():
                    labels = dict(label_tuple) if label_tuple else None
                    label_str = self._labels_to_string(labels)
                    if label_str:
                        lines.append("{}{} {}".format(name, label_str, value))
                    else:
                        lines.append("{} {}".format(name, value))
                lines.append("")

            # Output histograms
            for name, label_dict in self._histograms.items():
                meta = self._metadata.get(name, {"help": "", "type": "histogram"})
                if meta.get("help"):
                    lines.append("# HELP {} {}".format(name, meta["help"]))
                lines.append("# TYPE {} histogram".format(name))
                for label_tuple, values in label_dict.items():
                    labels = dict(label_tuple) if label_tuple else None
                    label_str = self._labels_to_string(labels)
                    hist_lines = self._format_histogram_bucket(name, label_str, values)
                    lines.extend(hist_lines)
                lines.append("")

        return "\n".join(lines).strip() + "\n"

    def reset(self):
        """Reset all collected metrics (useful for testing)"""
        with self._data_lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._last_access.clear()

    def cleanup_old_metrics(self, max_age_seconds: int = 3600):
        """
        Remove counters and gauges that have not been accessed in the last max_age_seconds.

        This prevents unbounded growth of metric label combinations for counters/gauges
        that are no longer being actively used.

        Args:
            max_age_seconds: Maximum age in seconds (default: 3600 = 1 hour)
        """
        cutoff = time.time() - max_age_seconds
        with self._data_lock:
            # Clean counters
            stale_counters = [
                name for name, ts in self._last_access.items()
                if name in self._counters and ts < cutoff
            ]
            for name in stale_counters:
                del self._counters[name]
                del self._last_access[name]

            # Clean gauges
            stale_gauges = [
                name for name, ts in self._last_access.items()
                if name in self._gauges and ts < cutoff
            ]
            for name in stale_gauges:
                del self._gauges[name]
                if name in self._last_access:
                    del self._last_access[name]

            if stale_counters or stale_gauges:
                logger = __import__("config.logging_config", fromlist=["get_logger"]).get_logger("metrics")
                logger.info("清理过期指标: {} counters, {} gauges".format(
                    len(stale_counters), len(stale_gauges)
                ))


# Global metrics collector instance
metrics_collector = MetricsCollector()
