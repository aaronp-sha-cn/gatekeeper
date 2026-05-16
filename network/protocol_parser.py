"""
GateKeeper - 协议解析模块
解析常见网络协议（HTTP, DNS, TLS, SSH等）的数据包内容
"""

import struct
import re
from typing import Dict, Any, Optional, Tuple
from collections import OrderedDict

from config.logging_config import get_logger

logger = get_logger("protocol_parser")


class ProtocolParser:
    """
    网络协议解析器
    支持解析多种常见网络协议的数据包内容
    """

    def __init__(self):
        # 已注册的解析器
        self._parsers = {
            "HTTP": self._parse_http,
            "DNS": self._parse_dns,
            "TLS": self._parse_tls,
            "SSH": self._parse_ssh,
            "DHCP": self._parse_dhcp,
            "ARP": self._parse_arp,
            "ICMP": self._parse_icmp,
        }

        logger.info("协议解析器初始化完成")

    def parse(self, protocol: str, payload: bytes, **kwargs) -> Dict[str, Any]:
        """
        解析协议数据

        Args:
            protocol: 协议名称
            payload: 原始数据载荷
            **kwargs: 额外参数（如端口号用于协议推断）

        Returns:
            解析结果字典
        """
        parser = self._parsers.get(protocol.upper())
        if parser:
            try:
                return parser(payload, **kwargs)
            except Exception as e:
                logger.debug("协议解析失败 ({}): {}".format(protocol, e))
                return {
                    "protocol": protocol,
                    "status": "error",
                    "message": str(e),
                    "raw_length": len(payload),
                }

        return {
            "protocol": protocol,
            "status": "unsupported",
            "raw_length": len(payload),
        }

    def detect_protocol(self, payload: bytes, port: Optional[int] = None) -> str:
        """
        根据数据内容检测协议类型

        Args:
            payload: 数据载荷
            port: 端口号（辅助判断）

        Returns:
            检测到的协议名称
        """
        if not payload:
            return "UNKNOWN"

        # 基于端口推断
        port_protocols = {
            80: "HTTP", 8080: "HTTP", 8000: "HTTP",
            443: "TLS", 8443: "TLS",
            53: "DNS",
            22: "SSH",
            67: "DHCP", 68: "DHCP",
        }
        if port and port in port_protocols:
            return port_protocols[port]

        # 基于内容特征检测
        # HTTP
        if payload.startswith(b"GET ") or payload.startswith(b"POST ") or \
           payload.startswith(b"PUT ") or payload.startswith(b"DELETE ") or \
           payload.startswith(b"HEAD ") or payload.startswith(b"HTTP/"):
            return "HTTP"

        # TLS/SSL
        if len(payload) >= 5 and payload[0] == 0x16 and payload[1] == 0x03:
            return "TLS"

        # SSH
        if payload.startswith(b"SSH-"):
            return "SSH"

        # DNS
        if len(payload) >= 12:
            qr = (payload[2] >> 7) & 1
            opcode = (payload[2] >> 3) & 0xF
            if opcode <= 2 and 1 <= payload[4] + payload[5] <= 50:
                return "DNS"

        # DHCP
        if len(payload) >= 240 and payload[0] == 2 and payload[1] == 1:
            return "DHCP"

        return "UNKNOWN"

    def _parse_http(self, payload: bytes, **kwargs) -> Dict[str, Any]:
        """解析HTTP协议"""
        result = {
            "protocol": "HTTP",
            "status": "ok",
        }

        try:
            text = payload.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            if not lines:
                return result

            # 解析请求行/状态行
            first_line = lines[0]
            if first_line.startswith("HTTP/"):
                # HTTP响应
                parts = first_line.split(" ", 2)
                result["type"] = "response"
                result["version"] = parts[0] if len(parts) > 0 else ""
                result["status_code"] = int(parts[1]) if len(parts) > 1 else 0
                result["status_text"] = parts[2] if len(parts) > 2 else ""
            else:
                # HTTP请求
                parts = first_line.split(" ", 2)
                result["type"] = "request"
                result["method"] = parts[0] if len(parts) > 0 else ""
                result["path"] = parts[1] if len(parts) > 1 else ""
                result["version"] = parts[2] if len(parts) > 2 else ""

            # 解析头部
            headers = OrderedDict()
            body_start = -1
            for i, line in enumerate(lines[1:], 1):
                if line == "":
                    body_start = i + 1
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()

            result["headers"] = dict(headers)
            result["header_count"] = len(headers)

            # 提取关键信息
            if "host" in headers:
                result["host"] = headers["host"]
            if "user-agent" in headers:
                result["user_agent"] = headers["user-agent"]
            if "content-type" in headers:
                result["content_type"] = headers["content-type"]

            # Body
            if body_start > 0 and body_start < len(lines):
                result["body"] = "\r\n".join(lines[body_start:])[:500]
                result["body_length"] = len(result["body"])

        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)

        return result

    def _parse_dns(self, payload: bytes, **kwargs) -> Dict[str, Any]:
        """解析DNS协议"""
        result = {
            "protocol": "DNS",
            "status": "ok",
        }

        if len(payload) < 12:
            result["status"] = "error"
            result["message"] = "数据包太短"
            return result

        try:
            # DNS头部 (12字节)
            transaction_id = struct.unpack("!H", payload[0:2])[0]
            flags = struct.unpack("!H", payload[2:4])[0]
            questions = struct.unpack("!H", payload[4:6])[0]
            answers = struct.unpack("!H", payload[6:8])[0]
            authority_rrs = struct.unpack("!H", payload[8:10])[0]
            additional_rrs = struct.unpack("!H", payload[10:12])[0]

            result["transaction_id"] = transaction_id
            result["is_response"] = bool(flags & 0x8000)
            result["opcode"] = (flags >> 11) & 0xF
            result["rcode"] = flags & 0xF
            result["questions"] = questions
            result["answers"] = answers

            # 解析查询/应答名称
            offset = 12
            query_names = []
            for _ in range(questions):
                name, offset = self._parse_dns_name(payload, offset)
                query_names.append(name)
                if offset + 4 <= len(payload):
                    offset += 4  # 跳过类型和类

            result["query_names"] = query_names

            # 解析应答
            answer_records = []
            for _ in range(min(answers, 10)):  # 最多解析10条
                if offset >= len(payload):
                    break
                name, offset = self._parse_dns_name(payload, offset)
                if offset + 10 > len(payload):
                    break
                rtype = struct.unpack("!H", payload[offset:offset+2])[0]
                rclass = struct.unpack("!H", payload[offset+2:offset+4])[0]
                ttl = struct.unpack("!I", payload[offset+4:offset+8])[0]
                rdlength = struct.unpack("!H", payload[offset+8:offset+10])[0]
                offset += 10

                rdata = payload[offset:offset+rdlength] if offset + rdlength <= len(payload) else b""
                offset += rdlength

                type_names = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}
                rdata_str = ""
                if rtype == 1 and len(rdata) == 4:
                    rdata_str = ".".join(str(b) for b in rdata)
                elif rtype == 28 and len(rdata) == 16:
                    rdata_str = self._format_ipv6(rdata)
                else:
                    rdata_str = rdata.decode("utf-8", errors="replace")

                answer_records.append({
                    "name": name,
                    "type": type_names.get(rtype, str(rtype)),
                    "ttl": ttl,
                    "data": rdata_str,
                })

            result["answers_data"] = answer_records

        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)

        return result

    def _parse_dns_name(self, payload: bytes, offset: int, max_jumps: int = 10) -> Tuple[str, int]:
        """解析DNS名称（支持指针压缩）

        Args:
            payload: 原始数据包
            offset: 当前偏移量
            max_jumps: 最大指针跳转次数，防止恶意数据包导致无限循环（默认10）

        Raises:
            ValueError: 超过最大指针跳转次数时抛出
        """
        labels = []
        original_offset = offset
        jumped = False
        jump_count = 0

        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                # 指针
                jump_count += 1
                if jump_count > max_jumps:
                    raise ValueError("DNS名称解析超过最大指针跳转次数 ({})，可能存在循环指针".format(max_jumps))
                if not jumped:
                    original_offset = offset + 2
                pointer = struct.unpack("!H", payload[offset:offset+2])[0] & 0x3FFF
                offset = pointer
                jumped = True
            else:
                offset += 1
                label = payload[offset:offset+length].decode("utf-8", errors="replace")
                labels.append(label)
                offset += length

        return ".".join(labels), original_offset if jumped else offset

    def _parse_tls(self, payload: bytes, **kwargs) -> Dict[str, Any]:
        """解析TLS协议"""
        result = {
            "protocol": "TLS",
            "status": "ok",
        }

        if len(payload) < 5:
            result["status"] = "error"
            return result

        try:
            content_type = payload[0]
            version = struct.unpack("!H", payload[1:3])[0]
            length = struct.unpack("!H", payload[3:5])[0]

            type_names = {
                20: "ChangeCipherSpec",
                21: "Alert",
                22: "Handshake",
                23: "Application",
            }
            version_names = {
                0x0301: "TLS 1.0",
                0x0302: "TLS 1.1",
                0x0303: "TLS 1.2",
                0x0304: "TLS 1.3",
            }

            result["content_type"] = type_names.get(content_type, str(content_type))
            result["version"] = version_names.get(version, "0x{:04x}".format(version))
            result["record_length"] = length

            # 解析握手协议
            if content_type == 22 and length > 1:
                handshake_type = payload[5]
                hs_types = {
                    1: "ClientHello",
                    2: "ServerHello",
                    11: "Certificate",
                    12: "ServerKeyExchange",
                    14: "ServerHelloDone",
                    16: "ClientKeyExchange",
                }
                result["handshake_type"] = hs_types.get(handshake_type, str(handshake_type))

                # 尝试提取SNI（Server Name Indication）
                if handshake_type == 1 and len(payload) > 43:
                    try:
                        # ClientHello解析
                        session_length = payload[43]
                        cipher_start = 44 + session_length
                        if cipher_start + 2 < len(payload):
                            cipher_length = struct.unpack("!H", payload[cipher_start:cipher_start+2])[0]
                            compression_start = cipher_start + 2 + cipher_length
                            if compression_start + 2 < len(payload):
                                extensions_length = struct.unpack("!H", payload[compression_start+1:compression_start+3])[0]
                                ext_start = compression_start + 3
                                # 搜索SNI扩展 (type=0)
                                while ext_start + 4 < len(payload):
                                    ext_type = struct.unpack("!H", payload[ext_start:ext_start+2])[0]
                                    ext_len = struct.unpack("!H", payload[ext_start+2:ext_start+4])[0]
                                    if ext_type == 0:  # SNI
                                        sni_start = ext_start + 4 + 3  # skip list info
                                        if sni_start < len(payload):
                                            sni_len = payload[sni_start + 1]
                                            sni_name = payload[sni_start+2:sni_start+2+sni_len].decode("utf-8", errors="replace")
                                            result["sni"] = sni_name
                                        break
                                    ext_start += 4 + ext_len
                    except Exception:
                        pass

        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)

        return result

    def _parse_ssh(self, payload: bytes, **kwargs) -> Dict[str, Any]:
        """解析SSH协议"""
        result = {
            "protocol": "SSH",
            "status": "ok",
        }

        try:
            text = payload.decode("utf-8", errors="replace").strip()
            if text.startswith("SSH-"):
                parts = text.split("-", 2)
                result["software"] = parts[2] if len(parts) > 2 else ""
                result["version"] = "{}-{}".format(parts[0], parts[1]) if len(parts) > 1 else ""
        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)

        return result

    def _parse_dhcp(self, payload: bytes, **kwargs) -> Dict[str, Any]:
        """解析DHCP协议"""
        result = {
            "protocol": "DHCP",
            "status": "ok",
        }

        if len(payload) < 240:
            result["status"] = "error"
            return result

        try:
            op = payload[0]
            result["message_type"] = "BOOTREPLY" if op == 2 else "BOOTREQUEST"

            # 客户端MAC地址
            chaddr = payload[28:44]
            mac = ":".join("{:02X}".format(b) for b in chaddr[:6] if b != 0)
            result["client_mac"] = mac

            # 解析DHCP选项（从偏移240开始）
            offset = 240
            while offset < len(payload) - 1:
                option_code = payload[offset]
                if option_code == 255:  # End
                    break
                if option_code == 0:  # Padding
                    offset += 1
                    continue

                option_len = payload[offset + 1]
                option_data = payload[offset + 2:offset + 2 + option_len]

                option_names = {
                    1: "subnet_mask", 3: "router", 6: "dns_server",
                    12: "hostname", 15: "domain_name", 51: "lease_time",
                    53: "dhcp_message_type", 54: "server_id",
                    61: "client_id",
                }

                name = option_names.get(option_code, "option_{}".format(option_code))
                if name == "dhcp_message_type" and option_data:
                    msg_types = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK"}
                    result["dhcp_type"] = msg_types.get(option_data[0], str(option_data[0]))
                elif name == "server_id" and len(option_data) == 4:
                    result["server_ip"] = ".".join(str(b) for b in option_data)
                elif name == "dns_server":
                    ips = []
                    for i in range(0, len(option_data), 4):
                        if i + 4 <= len(option_data):
                            ips.append(".".join(str(b) for b in option_data[i:i+4]))
                    result["dns_servers"] = ips

                offset += 2 + option_len

        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)

        return result

    def _parse_arp(self, payload: bytes, **kwargs) -> Dict[str, Any]:
        """解析ARP协议"""
        result = {
            "protocol": "ARP",
            "status": "ok",
        }

        if len(payload) < 28:
            result["status"] = "error"
            return result

        try:
            hw_type = struct.unpack("!H", payload[0:2])[0]
            proto_type = struct.unpack("!H", payload[2:4])[0]
            hw_size = payload[4]
            proto_size = payload[5]
            opcode = struct.unpack("!H", payload[6:8])[0]

            sender_mac = ":".join("{:02X}".format(b) for b in payload[8:14])
            sender_ip = ".".join(str(b) for b in payload[14:18])
            target_mac = ":".join("{:02X}".format(b) for b in payload[18:24])
            target_ip = ".".join(str(b) for b in payload[24:28])

            result["opcode"] = "request" if opcode == 1 else "reply"
            result["sender_mac"] = sender_mac
            result["sender_ip"] = sender_ip
            result["target_mac"] = target_mac
            result["target_ip"] = target_ip

        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)

        return result

    def _parse_icmp(self, payload: bytes, **kwargs) -> Dict[str, Any]:
        """解析ICMP协议"""
        result = {
            "protocol": "ICMP",
            "status": "ok",
        }

        if len(payload) < 8:
            result["status"] = "error"
            return result

        try:
            icmp_type = payload[0]
            icmp_code = payload[1]
            checksum = struct.unpack("!H", payload[2:4])[0]

            type_names = {
                0: "Echo Reply", 3: "Destination Unreachable",
                8: "Echo Request", 11: "Time Exceeded",
                5: "Redirect",
            }

            result["type"] = type_names.get(icmp_type, str(icmp_type))
            result["code"] = icmp_code
            result["checksum"] = checksum

            if icmp_type in (0, 8):  # Echo Request/Reply
                if len(payload) >= 8:
                    identifier = struct.unpack("!H", payload[4:6])[0]
                    sequence = struct.unpack("!H", payload[6:8])[0]
                    result["identifier"] = identifier
                    result["sequence"] = sequence

        except Exception as e:
            result["status"] = "error"
            result["message"] = str(e)

        return result

    def _format_ipv6(self, data: bytes) -> str:
        """格式化IPv6地址"""
        groups = []
        for i in range(0, 16, 2):
            groups.append("{:02x}{:02x}".format(data[i], data[i+1]))
        return ":".join(groups)
