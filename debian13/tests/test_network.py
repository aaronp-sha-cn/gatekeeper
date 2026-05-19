"""
GateKeeper - 网络模块测试
"""

import unittest
from unittest.mock import patch, MagicMock


class TestProtocolParser(unittest.TestCase):
    """协议解析器测试"""

    def setUp(self):
        from network.protocol_parser import ProtocolParser
        self.parser = ProtocolParser()

    def test_detect_protocol_http(self):
        """测试HTTP协议检测"""
        self.assertEqual(
            self.parser.detect_protocol(b"GET / HTTP/1.1\r\nHost: example.com"),
            "HTTP"
        )
        self.assertEqual(
            self.parser.detect_protocol(b"HTTP/1.1 200 OK"),
            "HTTP"
        )

    def test_detect_protocol_tls(self):
        """测试TLS协议检测"""
        tls_data = bytes([0x16, 0x03, 0x01, 0x00, 0x05])
        self.assertEqual(self.parser.detect_protocol(tls_data), "TLS")

    def test_detect_protocol_ssh(self):
        """测试SSH协议检测"""
        self.assertEqual(
            self.parser.detect_protocol(b"SSH-2.0-OpenSSH_8.9"),
            "SSH"
        )

    def test_detect_protocol_by_port(self):
        """测试基于端口推断协议"""
        self.assertEqual(self.parser.detect_protocol(b"", port=80), "HTTP")
        self.assertEqual(self.parser.detect_protocol(b"", port=443), "TLS")
        self.assertEqual(self.parser.detect_protocol(b"", port=22), "SSH")

    def test_parse_http_request(self):
        """测试HTTP请求解析"""
        payload = b"GET /api/test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\nbody"
        result = self.parser.parse("HTTP", payload)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["type"], "request")
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["path"], "/api/test")
        self.assertIn("host", result["headers"])
        self.assertEqual(result["headers"]["host"], "example.com")

    def test_parse_http_response(self):
        """测试HTTP响应解析"""
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
        result = self.parser.parse("HTTP", payload)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["type"], "response")
        self.assertEqual(result["status_code"], 200)

    def test_parse_ssh(self):
        """测试SSH解析"""
        payload = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
        result = self.parser.parse("SSH", payload)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["software"], "OpenSSH_8.9p1 Ubuntu-3")

    def test_parse_unsupported(self):
        """测试不支持的协议"""
        result = self.parser.parse("UNKNOWN", b"some data")
        self.assertEqual(result["status"], "unsupported")

    def test_parse_empty_payload(self):
        """测试空数据"""
        result = self.parser.parse("HTTP", b"")
        self.assertEqual(result["status"], "ok")


class TestNetworkConfig(unittest.TestCase):
    """网络配置管理器测试"""

    def setUp(self):
        from network.network_config import NetworkConfigManager
        self.config = NetworkConfigManager()

    def test_prefix_to_netmask(self):
        """测试CIDR前缀转子网掩码"""
        self.assertEqual(self.config._prefix_to_netmask(0), "0.0.0.0")
        self.assertEqual(self.config._prefix_to_netmask(8), "255.0.0.0")
        self.assertEqual(self.config._prefix_to_netmask(16), "255.255.0.0")
        self.assertEqual(self.config._prefix_to_netmask(24), "255.255.255.0")
        self.assertEqual(self.config._prefix_to_netmask(32), "255.255.255.255")


class TestPortScanner(unittest.TestCase):
    """端口扫描器测试"""

    def setUp(self):
        from network.port_scanner import PortScanner
        self.scanner = PortScanner()

    def test_quick_scan_invalid_host(self):
        """测试扫描无效主机"""
        result = self.scanner.quick_scan("invalid.host.that.does.not.exist.xyz")
        self.assertEqual(result["status"], "error")

    def test_get_probe(self):
        """测试获取探测数据"""
        probe = self.scanner._get_probe(80)
        self.assertIn(b"HTTP", probe)
        probe = self.scanner._get_probe(9999)
        self.assertEqual(probe, b"")


if __name__ == "__main__":
    unittest.main()
