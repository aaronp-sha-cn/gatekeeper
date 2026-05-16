"""
GateKeeper - 网络测速模块
提供下载速度、上传速度和延迟测试功能
使用内置方法测速，不依赖第三方speedtest服务
"""

import threading
import time
import socket
import struct
import os
import subprocess
from typing import Dict, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

from config.logging_config import get_logger

logger = get_logger("speedtest")


@dataclass
class SpeedTestResult:
    """测速结果"""
    # 下载
    download_speed_mbps: float = 0.0       # 下载速度 (Mbps)
    download_speed_bytes: float = 0.0      # 下载速度 (bytes/s)
    # 上传
    upload_speed_mbps: float = 0.0          # 上传速度 (Mbps)
    upload_speed_bytes: float = 0.0         # 上传速度 (bytes/s)
    # 延迟
    latency_ms: float = 0.0                 # 延迟 (ms)
    jitter_ms: float = 0.0                  # 抖动 (ms)
    packet_loss: float = 0.0                # 丢包率 (%)
    # 元信息
    target_host: str = ""
    test_duration: float = 0.0              # 测试总耗时 (s)
    timestamp: str = ""
    is_running: bool = False
    error: str = ""


class NetworkSpeedTest:
    """网络测速器"""

    def __init__(self):
        self._result = SpeedTestResult()
        self._running = False
        self._cancel = threading.Event()
        self._progress_callback: Optional[Callable] = None
        self._test_thread: Optional[threading.Thread] = None

        # 默认测速服务器
        self._default_targets = [
            {"host": "114.114.114.114", "port": 53, "name": "114DNS"},
            {"host": "223.5.5.5", "port": 53, "name": "阿里DNS"},
            {"host": "8.8.8.8", "port": 53, "name": "Google DNS"},
            {"host": "1.1.1.1", "port": 53, "name": "Cloudflare DNS"},
        ]

    @property
    def result(self) -> SpeedTestResult:
        return self._result

    @property
    def is_running(self) -> bool:
        return self._running

    def set_progress_callback(self, callback: Callable):
        """设置进度回调函数 callback(phase: str, progress: float, message: str)"""
        self._progress_callback = callback

    def _notify_progress(self, phase: str, progress: float, message: str):
        """通知进度更新"""
        if self._progress_callback:
            try:
                self._progress_callback(phase, progress, message)
            except Exception:
                pass

    def run_speed_test(self, target_host: str = "", test_upload: bool = True,
                       test_download: bool = True, test_latency: bool = True) -> SpeedTestResult:
        """
        执行完整测速（阻塞模式）
        
        Args:
            target_host: 测速目标主机（留空自动选择）
            test_upload: 是否测试上传
            test_download: 是否测试下载
            test_latency: 是否测试延迟
        """
        self._result = SpeedTestResult(is_running=True, timestamp=datetime.now().isoformat())
        self._cancel.clear()
        start_time = time.time()

        try:
            # 选择目标
            target = self._select_target(target_host)
            self._result.target_host = target["host"]
            self._notify_progress("init", 0, f"测速目标: {target['name']} ({target['host']})")

            total_phases = sum([test_latency, test_download, test_upload])
            phase_idx = 0

            # 1. 延迟测试
            if test_latency and not self._cancel.is_set():
                self._notify_progress("latency", 0, "正在测试延迟...")
                self._test_latency(target["host"], target["port"])
                phase_idx += 1
                self._notify_progress("latency", 100, 
                    f"延迟: {self._result.latency_ms:.1f}ms, 抖动: {self._result.jitter_ms:.1f}ms")

            # 2. 下载速度测试
            if test_download and not self._cancel.is_set():
                self._notify_progress("download", 0, "正在测试下载速度...")
                self._test_download_speed(target["host"])
                phase_idx += 1
                self._notify_progress("download", 100,
                    f"下载: {self._result.download_speed_mbps:.2f} Mbps")

            # 3. 上传速度测试
            if test_upload and not self._cancel.is_set():
                self._notify_progress("upload", 0, "正在测试上传速度...")
                self._test_upload_speed(target["host"])
                phase_idx += 1
                self._notify_progress("upload", 100,
                    f"上传: {self._result.upload_speed_mbps:.2f} Mbps")

        except Exception as e:
            self._result.error = str(e)
            logger.error(f"测速失败: {e}")

        self._result.test_duration = round(time.time() - start_time, 1)
        self._result.is_running = False
        self._notify_progress("done", 100, "测速完成")

        return self._result

    def run_speed_test_async(self, target_host: str = "", callback: Optional[Callable] = None,
                              test_upload: bool = True, test_download: bool = True,
                              test_latency: bool = True):
        """
        异步执行测速（非阻塞模式）
        
        Args:
            callback: 完成回调 callback(result: SpeedTestResult)
        """
        if self._running:
            return

        self._running = True
        self._test_thread = threading.Thread(
            target=self._async_test_wrapper,
            args=(target_host, callback, test_upload, test_download, test_latency),
            daemon=True
        )
        self._test_thread.start()

    def _async_test_wrapper(self, target_host, callback, test_upload, test_download, test_latency):
        """异步测速包装器"""
        try:
            result = self.run_speed_test(target_host, test_upload, test_download, test_latency)
            if callback:
                callback(result)
        except Exception as e:
            logger.error(f"异步测速异常: {e}")
        finally:
            self._running = False

    def cancel(self):
        """取消正在进行的测速"""
        self._cancel.set()
        self._result.is_running = False
        logger.info("测速已取消")

    def _select_target(self, target_host: str) -> Dict:
        """选择测速目标（选择延迟最低的）"""
        if target_host:
            return {"host": target_host, "port": 53, "name": target_host}

        best_target = self._default_targets[0]
        best_latency = 9999

        for target in self._default_targets:
            latency = self._ping(target["host"], count=2, timeout=2)
            if latency < best_latency:
                best_latency = latency
                best_target = target

        return best_target

    def _ping(self, host: str, count: int = 3, timeout: float = 3) -> float:
        """Ping测试，返回平均延迟(ms)"""
        try:
            result = subprocess.run(
                ["ping", "-c", str(count), "-W", str(timeout), host],
                capture_output=True, text=True, timeout=timeout * count + 5
            )
            output = result.stdout

            # 解析平均延迟
            for line in output.split('\n'):
                if 'rtt min/avg/max/mdev' in line or 'min/avg/max' in line:
                    parts = line.split('=')[-1].strip().split('/')
                    if len(parts) >= 2:
                        return float(parts[1])

            # 解析单次延迟
            import re
            times = re.findall(r'time=([\d.]+)', output)
            if times:
                return sum(float(t) for t in times) / len(times)

        except (subprocess.TimeoutExpired, Exception):
            pass
        return 9999

    def _test_latency(self, host: str, port: int = 53):
        """延迟和抖动测试"""
        latencies = []
        lost = 0
        total = 20

        for i in range(total):
            if self._cancel.is_set():
                break

            start = time.time()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((host, port))
                elapsed = (time.time() - start) * 1000
                latencies.append(elapsed)
                sock.close()
            except (socket.timeout, OSError):
                lost += 1

            self._notify_progress("latency", (i + 1) / total * 100,
                f"延迟测试 {i+1}/{total}...")
            time.sleep(0.1)

        if latencies:
            self._result.latency_ms = round(sum(latencies) / len(latencies), 1)
            # 计算抖动（相邻延迟差的平均）
            if len(latencies) > 1:
                diffs = [abs(latencies[i] - latencies[i-1]) for i in range(1, len(latencies))]
                self._result.jitter_ms = round(sum(diffs) / len(diffs), 1)

        self._result.packet_loss = round(lost / total * 100, 1) if total > 0 else 0

    def _test_download_speed(self, host: str):
        """下载速度测试（通过TCP接收数据）"""
        # 使用公共测速方法：向目标发送HTTP请求获取数据
        # 如果目标不支持，则使用ICMP估算
        try:
            speed = self._test_speed_http_download(host)
            if speed > 0:
                self._result.download_speed_bytes = speed
                self._result.download_speed_mbps = round(speed * 8 / 1024 / 1024, 2)
                return
        except Exception:
            pass

        # 回退：使用ping估算带宽
        self._estimate_bandwidth_from_latency(host)

    def _test_speed_http_download(self, host: str) -> float:
        """通过HTTP下载测速"""
        import urllib.request

        # 使用公共测速文件
        test_urls = [
            f"http://{host}",  # 回退到直接连接
        ]

        # 尝试公共测速服务器
        public_urls = [
            "http://speedtest.tele2.net/1MB.zip",
            "http://cachefly.cachefly.net/1mb.test",
        ]

        total_bytes = 0
        start_time = time.time()
        test_duration = 5  # 测试5秒

        for url in public_urls:
            if self._cancel.is_set():
                break

            try:
                req = urllib.request.Request(url, headers={
                    'User-Agent': 'GateKeeper/1.0 SpeedTest'
                })
                with urllib.request.urlopen(req, timeout=10) as response:
                    chunk_size = 65536
                    while True:
                        if self._cancel.is_set():
                            break
                        if time.time() - start_time >= test_duration:
                            break
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                        elapsed = time.time() - start_time
                        speed_bps = total_bytes / elapsed if elapsed > 0 else 0
                        progress = min(elapsed / test_duration * 100, 100)
                        self._notify_progress("download", progress,
                            f"下载中: {speed_bps * 8 / 1024 / 1024:.2f} Mbps")

                if total_bytes > 0:
                    break
            except Exception:
                continue

        if total_bytes > 0:
            elapsed = time.time() - start_time
            return total_bytes / elapsed if elapsed > 0 else 0

        return 0

    def _test_upload_speed(self, host: str):
        """上传速度测试（通过TCP发送数据）"""
        total_bytes = 0
        start_time = time.time()
        test_duration = 5  # 测试5秒
        chunk_size = 65536  # 64KB
        # 填充随机数据
        data = os.urandom(chunk_size)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, 80))
            sock.settimeout(10)

            while not self._cancel.is_set():
                if time.time() - start_time >= test_duration:
                    break
                try:
                    sock.send(data)
                    total_bytes += chunk_size
                    elapsed = time.time() - start_time
                    speed_bps = total_bytes / elapsed if elapsed > 0 else 0
                    progress = min(elapsed / test_duration * 100, 100)
                    self._notify_progress("upload", progress,
                        f"上传中: {speed_bps * 8 / 1024 / 1024:.2f} Mbps")
                except (socket.timeout, BrokenPipeError, OSError):
                    break

            sock.close()

        except (socket.timeout, ConnectionRefusedError, OSError):
            # 如果TCP连接失败，使用估算方法
            self._estimate_upload_from_download()
            return

        if total_bytes > 0:
            elapsed = time.time() - start_time
            self._result.upload_speed_bytes = total_bytes / elapsed if elapsed > 0 else 0
            self._result.upload_speed_mbps = round(self._result.upload_speed_bytes * 8 / 1024 / 1024, 2)

    def _estimate_bandwidth_from_latency(self, host: str):
        """根据延迟估算带宽（回退方法）"""
        # 使用iperf3如果可用
        try:
            result = subprocess.run(
                ["which", "iperf3"], capture_output=True, timeout=3
            )
            if result.returncode == 0:
                # iperf3可用，但需要服务端，这里仅做标记
                logger.info("检测到iperf3，建议使用 iperf3 -c <server> 进行精确测速")
        except Exception:
            pass

        # 基于延迟的粗略估算（仅供参考）
        latency = self._result.latency_ms
        if latency > 0:
            # 简单估算：假设带宽与延迟成反比
            # 这是非常粗略的估算
            estimated_mbps = max(1, min(1000, 500 / (latency / 10)))
            self._result.download_speed_mbps = round(estimated_mbps, 2)
            self._result.download_speed_bytes = estimated_mbps * 1024 * 1024 / 8
            self._result.error = "无法直接测速，结果为基于延迟的估算值"

    def _estimate_upload_from_download(self):
        """根据下载速度估算上传速度"""
        if self._result.download_speed_mbps > 0:
            # 通常上传速度为下载的30%-80%
            ratio = 0.5
            self._result.upload_speed_mbps = round(self._result.download_speed_mbps * ratio, 2)
            self._result.upload_speed_bytes = self._result.upload_speed_mbps * 1024 * 1024 / 8
            if not self._result.error:
                self._result.error = "上传速度为估算值"

    def get_interface_speed(self, interface: str = "eth0") -> Dict:
        """获取接口速率信息"""
        try:
            # 从ethtool获取链路速度
            result = subprocess.run(
                ["ethtool", interface],
                capture_output=True, text=True, timeout=5
            )
            speed = 0
            duplex = ""
            for line in result.stdout.split('\n'):
                if 'Speed:' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        speed_str = parts[1].strip().replace('Mb/s', '').strip()
                        speed = int(speed_str)
                if 'Duplex:' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        duplex = parts[1].strip()

            return {
                "interface": interface,
                "speed_mbps": speed,
                "duplex": duplex,
                "link_up": speed > 0
            }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {
                "interface": interface,
                "speed_mbps": 0,
                "duplex": "Unknown",
                "link_up": False
            }

    def get_speedtest_servers(self) -> list:
        """获取可用测速服务器列表"""
        servers = []
        for target in self._default_targets:
            latency = self._ping(target["host"], count=1, timeout=2)
            servers.append({
                "host": target["host"],
                "port": target["port"],
                "name": target["name"],
                "latency": round(latency, 1) if latency < 9999 else -1,
                "available": latency < 9999
            })
        return sorted(servers, key=lambda x: x["latency"] if x["latency"] >= 0 else 9999)


# 全局实例
_speedtest_instance: Optional[NetworkSpeedTest] = None


def get_speedtest() -> NetworkSpeedTest:
    """获取测速器单例"""
    global _speedtest_instance
    if _speedtest_instance is None:
        _speedtest_instance = NetworkSpeedTest()
    return _speedtest_instance
