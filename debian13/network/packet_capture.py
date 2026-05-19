"""
GateKeeper - 数据包捕获模块
基于scapy的网络数据包捕获与处理
"""

import threading
import time
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime

from config.settings import settings
from config.logging_config import get_logger

logger = get_logger("packet_capture")


class PacketCapture:
    """
    数据包捕获引擎
    使用scapy进行网络数据包的实时捕获和处理
    """

    def __init__(self):
        self._running = False
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # 回调函数列表
        self._callbacks: List[Callable] = []

        # 统计信息
        self._stats = {
            "captured_packets": 0,
            "processed_packets": 0,
            "dropped_packets": 0,
            "capture_start_time": None,
            "interface": None,
            "bpf_filter": "",
        }

        logger.info("数据包捕获模块初始化完成")

    def start_capture(
        self,
        interface: str = "",
        bpf_filter: str = "",
        callback: Optional[Callable] = None,
    ) -> Dict[str, Any]:
        """
        启动数据包捕获

        Args:
            interface: 网络接口名称
            bpf_filter: BPF过滤规则
            callback: 数据包处理回调函数

        Returns:
            启动结果
        """
        if self._running:
            return {"status": "error", "message": "捕获已在运行中"}

        interface = interface or settings.network.listen_interface
        bpf_filter = bpf_filter or settings.network.bpf_filter

        if callback:
            self._callbacks.append(callback)

        self._stop_event.clear()
        self._running = True
        self._stats["interface"] = interface
        self._stats["bpf_filter"] = bpf_filter
        self._stats["capture_start_time"] = datetime.now().isoformat()

        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, bpf_filter),
            name="packet-capture",
            daemon=True,
        )
        self._capture_thread.start()

        logger.info(
            "数据包捕获已启动: interface={}, filter='{}'".format(
                interface, bpf_filter
            )
        )

        return {
            "status": "ok",
            "interface": interface,
            "bpf_filter": bpf_filter,
        }

    def stop_capture(self) -> Dict[str, Any]:
        """
        停止数据包捕获

        Returns:
            停止结果
        """
        if not self._running:
            return {"status": "error", "message": "捕获未在运行"}

        self._stop_event.set()
        self._running = False

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5)

        logger.info("数据包捕获已停止")
        return {
            "status": "ok",
            "captured_packets": self._stats["captured_packets"],
            "processed_packets": self._stats["processed_packets"],
        }

    def _capture_loop(self, interface: str, bpf_filter: str):
        """数据包捕获主循环"""
        try:
            from scapy.all import (
                sniff, IP, TCP, UDP, ICMP,
                IPv6, ICMPv6,
                conf as scapy_conf
            )

            # 配置scapy
            scapy_conf.verb = 0  # 关闭scapy的详细输出

            def packet_handler(packet):
                """处理捕获的数据包"""
                if self._stop_event.is_set():
                    return

                self._stats["captured_packets"] += 1

                try:
                    # 解析数据包
                    packet_data = self._parse_packet(packet)
                    if packet_data:
                        self._stats["processed_packets"] += 1

                        # 调用回调函数
                        for callback in self._callbacks:
                            try:
                                callback(packet_data)
                            except Exception as e:
                                logger.debug("回调处理失败: {}".format(e))

                except Exception as e:
                    self._stats["dropped_packets"] += 1
                    logger.debug("数据包处理失败: {}".format(e))

            # 开始捕获
            sniff(
                iface=interface if interface else None,
                filter=bpf_filter if bpf_filter else None,
                prn=packet_handler,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,  # 不存储数据包以节省内存
                promisc=settings.network.promiscuous,
            )

        except ImportError:
            logger.error("scapy未安装，无法进行数据包捕获")
            self._running = False
        except PermissionError:
            logger.error("权限不足，请使用root权限运行")
            self._running = False
        except Exception as e:
            logger.error("数据包捕获异常: {}".format(e))
            self._running = False

    def _parse_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        解析scapy数据包为标准字典格式

        Args:
            packet: scapy数据包对象

        Returns:
            解析后的数据包字典
        """
        try:
            from scapy.all import IP, TCP, UDP, ICMP, ARP, IPv6
        except ImportError:
            logger.error("scapy未安装，无法解析数据包")
            return None

        # 检查是否是IPv4包
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            packet_data = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "src_port": None,
                "dst_port": None,
                "protocol": "OTHER",
                "length": len(packet),
                "flags": "",
                "ttl": ip_layer.ttl,
                "payload": b"",
                "ip_version": 4,
            }

            # 解析传输层协议
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_data["protocol"] = "TCP"
                packet_data["src_port"] = tcp_layer.sport
                packet_data["dst_port"] = tcp_layer.dport
                packet_data["flags"] = str(tcp_layer.flags)
                if tcp_layer.payload:
                    packet_data["payload"] = bytes(tcp_layer.payload)[:512]

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_data["protocol"] = "UDP"
                packet_data["src_port"] = udp_layer.sport
                packet_data["dst_port"] = udp_layer.dport
                if udp_layer.payload:
                    packet_data["payload"] = bytes(udp_layer.payload)[:512]

            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                packet_data["protocol"] = "ICMP"
                packet_data["icmp_type"] = icmp_layer.type
                packet_data["icmp_code"] = icmp_layer.code

            return packet_data

        # 检查是否是IPv6包
        if settings.network.ipv6_enabled and packet.haslayer(IPv6):
            ip6_layer = packet[IPv6]
            packet_data = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": ip6_layer.src,
                "dst_ip": ip6_layer.dst,
                "src_port": None,
                "dst_port": None,
                "protocol": "OTHER",
                "length": len(packet),
                "flags": "",
                "ttl": ip6_layer.hlim,
                "payload": b"",
                "ip_version": 6,
            }

            # 解析传输层协议（IPv6同样使用TCP/UDP）
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_data["protocol"] = "TCP"
                packet_data["src_port"] = tcp_layer.sport
                packet_data["dst_port"] = tcp_layer.dport
                packet_data["flags"] = str(tcp_layer.flags)
                if tcp_layer.payload:
                    packet_data["payload"] = bytes(tcp_layer.payload)[:512]

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_data["protocol"] = "UDP"
                packet_data["src_port"] = udp_layer.sport
                packet_data["dst_port"] = udp_layer.dport
                if udp_layer.payload:
                    packet_data["payload"] = bytes(udp_layer.payload)[:512]

            elif packet.haslayer(ICMPv6):
                icmp6_layer = packet[ICMPv6]
                packet_data["protocol"] = "ICMPv6"
                packet_data["icmp_type"] = icmp6_layer.type
                packet_data["icmp_code"] = icmp6_layer.code

            return packet_data

        return None

    def register_callback(self, callback: Callable):
        """注册数据包处理回调函数"""
        self._callbacks.append(callback)

    def unregister_callback(self, callback: Callable):
        """移除数据包处理回调函数"""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def get_stats(self) -> Dict[str, Any]:
        """获取捕获统计"""
        return {
            **self._stats,
            "is_running": self._running,
            "callbacks_count": len(self._callbacks),
        }

    @property
    def is_running(self) -> bool:
        """是否正在捕获"""
        return self._running
