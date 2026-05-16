"""
GateKeeper - SSL/TLS 检测模块
提供 SSL/TLS 证书验证、协议版本检查与加密套件评估功能
（与 ssl_inspector.py 互补，侧重于主动检测而非流量代理）
"""

import ssl
import re
import os
import json
import socket
import subprocess
import threading
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from config.logging_config import get_logger

logger = get_logger("ssl_checker")

# 不安全的协议版本
INSECURE_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

# 弱加密套件关键词
WEAK_CIPHER_KEYWORDS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED",
]

# 不安全的加密套件完整匹配
INSECURE_CIPHERS = {
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
}

# 推荐的最低 TLS 版本
MIN_TLS_VERSION = "TLSv1.2"

# 证书指纹算法安全等级
FINGERPRINT_SECURITY = {
    "sha256": "secure",
    "sha384": "secure",
    "sha512": "secure",
    "sha1": "weak",
    "md5": "insecure",
}

# 证书密钥长度最低要求
MIN_KEY_LENGTHS = {
    "RSA": 2048,
    "DSA": 2048,
    "EC": 256,
}


class SSLChecker:
    """SSL/TLS 检测器 - 证书验证、协议版本检查与加密套件评估"""

    def __init__(self):
        """初始化 SSL 检测器"""
        self._check_history: List[dict] = []
        self._lock = threading.Lock()
        self._stats = {
            "total_checks": 0,
            "total_hosts_checked": 0,
            "total_insecure": 0,
            "total_expired": 0,
            "total_weak_cipher": 0,
            "total_protocol_issues": 0,
            "last_check_time": None,
        }
        logger.info("SSL/TLS 检测器初始化完成")

    def check_host(self, host: str, port: int = 443) -> dict:
        """
        检查指定主机的 SSL/TLS 配置

        Args:
            host: 目标主机名或 IP 地址
            port: 目标端口，默认 443

        Returns:
            检查结果字典，包含证书、协议、加密套件等信息
        """
        result = {
            "host": host,
            "port": port,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "certificate": None,
            "protocol": None,
            "cipher_suites": [],
            "vulnerabilities": [],
            "overall_grade": "unknown",
        }

        # 1. 获取证书信息
        cert_info = self._get_certificate_info(host, port)
        result["certificate"] = cert_info

        # 2. 检查证书
        cert_check = self.check_certificate(cert_info)
        if cert_check.get("issues"):
            result["vulnerabilities"].extend(cert_check["issues"])

        # 3. 检查支持的协议版本
        protocol_info = self._check_supported_protocols(host, port)
        result["protocol"] = protocol_info
        if protocol_info.get("issues"):
            result["vulnerabilities"].extend(protocol_info["issues"])
            with self._lock:
                self._stats["total_protocol_issues"] += len(protocol_info["issues"])

        # 4. 检查加密套件
        cipher_info = self._check_cipher_suites(host, port)
        result["cipher_suites"] = cipher_info
        if cipher_info.get("weak_ciphers"):
            result["vulnerabilities"].append(
                "发现 {} 个弱加密套件".format(len(cipher_info["weak_ciphers"]))
            )
            with self._lock:
                self._stats["total_weak_cipher"] += len(cipher_info["weak_ciphers"])

        # 5. 使用 openssl 进行补充检查
        openssl_info = self._openssl_check(host, port)
        if openssl_info:
            result["openssl_details"] = openssl_info

        # 6. 计算总体评级
        result["overall_grade"] = self._calculate_grade(result)

        # 更新统计
        with self._lock:
            self._stats["total_checks"] += 1
            self._stats["total_hosts_checked"] += 1
            self._stats["last_check_time"] = datetime.now(timezone.utc).isoformat()

            if result["overall_grade"] in ("F", "D"):
                self._stats["total_insecure"] += 1
            if cert_check.get("expired"):
                self._stats["total_expired"] += 1

            self._check_history.append({
                "host": host,
                "port": port,
                "grade": result["overall_grade"],
                "timestamp": result["timestamp"],
                "vulnerability_count": len(result["vulnerabilities"]),
            })
            if len(self._check_history) > 1000:
                self._check_history = self._check_history[-1000:]

        logger.info("SSL/TLS 检测完成: {}:{} -> 评级 {}".format(
            host, port, result["overall_grade"]))
        return result

    def check_certificate(self, cert: dict) -> dict:
        """
        检查证书安全性

        Args:
            cert: 证书信息字典（需包含 subject, issuer, not_before, not_after 等字段）

        Returns:
            检查结果字典，包含 issues 列表和 expired 标志
        """
        issues = []
        expired = False

        if not cert or not cert.get("subject"):
            return {"issues": ["无法获取证书信息"], "expired": False, "valid": False}

        # 检查证书有效期
        not_after = cert.get("not_after")
        not_before = cert.get("not_before")
        now = datetime.now(timezone.utc)

        if not_after:
            try:
                if isinstance(not_after, str):
                    not_after_dt = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                else:
                    not_after_dt = not_after
                if now > not_after_dt:
                    issues.append("证书已过期: {}".format(not_after))
                    expired = True
            except (ValueError, TypeError):
                issues.append("无法解析证书过期时间")

        if not_before:
            try:
                if isinstance(not_before, str):
                    not_before_dt = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                else:
                    not_before_dt = not_before
                if now < not_before_dt:
                    issues.append("证书尚未生效: {}".format(not_before))
            except (ValueError, TypeError):
                pass

        # 检查自签名证书
        subject = cert.get("subject", {})
        issuer = cert.get("issuer", {})
        if subject == issuer and subject:
            issues.append("自签名证书")

        # 检查通配符域名
        cn = cert.get("common_name", "")
        if cn and cn.startswith("*."):
            issues.append("通配符证书: {}".format(cn))

        # 检查密钥长度
        key_info = cert.get("key_info", {})
        key_type = key_info.get("type", "")
        key_length = key_info.get("length", 0)
        if key_type and key_length:
            min_length = MIN_KEY_LENGTHS.get(key_type, 0)
            if min_length and key_length < min_length:
                issues.append(
                    "{} 密钥长度不足: {} 位 (最低要求: {} 位)".format(
                        key_type, key_length, min_length))

        # 检查签名算法
        sig_alg = cert.get("signature_algorithm", "")
        if sig_alg:
            if "md5" in sig_alg.lower():
                issues.append("不安全的签名算法: {}".format(sig_alg))
            elif "sha1" in sig_alg.lower():
                issues.append("弱签名算法: {}".format(sig_alg))

        return {
            "issues": issues,
            "expired": expired,
            "valid": len(issues) == 0,
        }

    def check_protocol_version(self, version: str) -> dict:
        """
        检查 TLS/SSL 协议版本安全性

        Args:
            version: 协议版本字符串，如 "TLSv1.2", "TLSv1.3"

        Returns:
            检查结果字典
        """
        version_upper = version.upper().strip()

        # 标准化版本名称
        version_map = {
            "SSLV2": "SSLv2",
            "SSLV3": "SSLv3",
            "TLSV1.0": "TLSv1",
            "TLSV1.1": "TLSv1.1",
            "TLSV1.2": "TLSv1.2",
            "TLSV1.3": "TLSv1.3",
            "TLS 1.0": "TLSv1",
            "TLS 1.1": "TLSv1.1",
            "TLS 1.2": "TLSv1.2",
            "TLS 1.3": "TLSv1.3",
        }
        normalized = version_map.get(version_upper, version_upper)

        result = {
            "version": normalized,
            "secure": True,
            "recommendation": "",
            "details": "",
        }

        if normalized in ("SSLv2", "SSLv3"):
            result["secure"] = False
            result["recommendation"] = "立即禁用"
            result["details"] = "{} 存在严重安全漏洞（POODLE, DROWN 等），应立即禁用".format(normalized)
        elif normalized in ("TLSv1", "TLSv1.1"):
            result["secure"] = False
            result["recommendation"] = "建议升级到 TLSv1.2+"
            result["details"] = "{} 已被 IETF 弃用（RFC 8996），存在已知漏洞".format(normalized)
        elif normalized == "TLSv1.2":
            result["secure"] = True
            result["recommendation"] = "安全，建议同时支持 TLSv1.3"
            result["details"] = "TLSv1.2 是当前广泛支持的安全版本"
        elif normalized == "TLSv1.3":
            result["secure"] = True
            result["recommendation"] = "推荐使用"
            result["details"] = "TLSv1.3 是最新版本，提供最佳安全性和性能"
        else:
            result["secure"] = None
            result["recommendation"] = "未知协议版本"
            result["details"] = "无法识别的协议版本: {}".format(version)

        return result

    def get_stats(self) -> dict:
        """
        获取检测器统计信息

        Returns:
            统计信息字典
        """
        with self._lock:
            stats = dict(self._stats)
            stats["history_count"] = len(self._check_history)
            return stats

    def get_check_history(self, limit: int = 50) -> list:
        """
        获取检测历史记录

        Args:
            limit: 最大返回数量

        Returns:
            检测历史列表
        """
        with self._lock:
            return list(self._check_history[-limit:])

    # ----------------------------------------------------------
    # 内部方法
    # ----------------------------------------------------------

    def _get_certificate_info(self, host: str, port: int) -> dict:
        """
        获取目标主机的 SSL 证书信息

        Args:
            host: 目标主机
            port: 目标端口

        Returns:
            证书信息字典
        """
        cert_info = {
            "subject": {},
            "issuer": {},
            "common_name": "",
            "not_before": None,
            "not_after": None,
            "serial_number": "",
            "signature_algorithm": "",
            "key_info": {},
            "fingerprint_sha256": "",
            "san": [],
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # 获取二进制证书
                    binary_cert = ssock.getpeercert(binary_form=True)
                    # 获取文本格式证书
                    text_cert = ssock.getpeercert()

                    if binary_cert:
                        # 计算 SHA256 指纹
                        sha256 = hashlib.sha256(binary_cert).hexdigest()
                        cert_info["fingerprint_sha256"] = ":".join(
                            sha256[i:i+2] for i in range(0, len(sha256), 2)
                        ).upper()

                    if text_cert:
                        # 解析主题
                        subject = {}
                        for rdn in text_cert.get("subject", ()):
                            for attr_type, attr_value in rdn:
                                subject[attr_type] = attr_value
                        cert_info["subject"] = subject
                        cert_info["common_name"] = subject.get("commonName", "")

                        # 解析颁发者
                        issuer = {}
                        for rdn in text_cert.get("issuer", ()):
                            for attr_type, attr_value in rdn:
                                issuer[attr_type] = attr_value
                        cert_info["issuer"] = issuer

                        # 有效期
                        not_before = text_cert.get("notBefore")
                        not_after = text_cert.get("notAfter")
                        if not_before:
                            cert_info["not_before"] = not_before
                        if not_after:
                            cert_info["not_after"] = not_after

                        # 序列号
                        cert_info["serial_number"] = str(
                            text_cert.get("serialNumber", ""))

                        # 主题备用名称
                        san = text_cert.get("subjectAltName", ())
                        cert_info["san"] = [name for _type, name in san]

                    # 获取协议版本
                    version = ssock.version()
                    if version:
                        cert_info["protocol_version"] = version

                    # 获取加密套件
                    cipher = ssock.cipher()
                    if cipher:
                        cert_info["cipher"] = {
                            "name": cipher[0],
                            "protocol": cipher[1],
                            "bits": cipher[2],
                        }

        except ssl.SSLError as e:
            cert_info["error"] = "SSL 错误: {}".format(str(e))
        except socket.timeout:
            cert_info["error"] = "连接超时"
        except socket.error as e:
            cert_info["error"] = "连接错误: {}".format(str(e))
        except Exception as e:
            cert_info["error"] = str(e)

        return cert_info

    def _check_supported_protocols(self, host: str, port: int) -> dict:
        """
        检查目标主机支持的 TLS/SSL 协议版本

        Args:
            host: 目标主机
            port: 目标端口

        Returns:
            协议检查结果
        """
        protocols = {
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1": ssl.TLSVersion.TLSv1,
        }

        supported = []
        issues = []

        for version_name, tls_version in protocols.items():
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = tls_version
                context.maximum_version = tls_version

                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        supported.append(version_name)

            except ssl.SSLError:
                pass
            except (socket.timeout, socket.error, OSError):
                pass
            except Exception:
                pass

        # 检查安全问题
        for proto in supported:
            if proto in INSECURE_PROTOCOLS:
                issues.append("支持不安全的协议版本: {}".format(proto))

        # 检查是否支持 TLSv1.2+
        has_secure = any(p in ("TLSv1.2", "TLSv1.3") for p in supported)
        if not has_secure and supported:
            issues.append("不支持 TLSv1.2 或更高版本")

        # 检查是否支持 TLSv1.3
        has_tls13 = "TLSv1.3" in supported
        if not has_tls13:
            issues.append("未检测到 TLSv1.3 支持（建议升级）")

        return {
            "supported": supported,
            "issues": issues,
            "supports_tls12": "TLSv1.2" in supported,
            "supports_tls13": has_tls13,
            "has_insecure": any(p in supported for p in INSECURE_PROTOCOLS),
        }

    def _check_cipher_suites(self, host: str, port: int) -> dict:
        """
        检查目标主机支持的加密套件

        Args:
            host: 目标主机
            port: 目标端口

        Returns:
            加密套件检查结果
        """
        all_ciphers = []
        weak_ciphers = []

        try:
            # 使用 openssl 获取完整加密套件列表
            cmd = [
                "openssl", "s_client",
                "-connect", "{}:{}".format(host, port),
                "-servername", host,
                "-cipher", "ALL:COMPLEMENTOFDEFAULT",
                "-connect_timeout", "5",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                input=""
            )
            output = result.stdout + result.stderr

            # 解析加密套件
            cipher_lines = output.splitlines()
            in_cipher_section = False
            for line in cipher_lines:
                line = line.strip()
                if "Cipher" in line and ":" in line:
                    in_cipher_section = True
                    continue
                if in_cipher_section and line.startswith("New"):
                    break
                if in_cipher_section and line and " " in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        cipher_name = parts[2].strip(",")
                        is_weak = self._is_weak_cipher(cipher_name)
                        cipher_entry = {
                            "name": cipher_name,
                            "ssl_version": parts[0] if parts else "",
                            "bits": parts[1] if len(parts) > 1 else "",
                            "weak": is_weak,
                        }
                        all_ciphers.append(cipher_entry)
                        if is_weak:
                            weak_ciphers.append(cipher_entry)

        except FileNotFoundError:
            logger.warning("openssl 命令不可用")
        except subprocess.TimeoutExpired:
            logger.warning("检查加密套件超时: {}:{}".format(host, port))
        except Exception as e:
            logger.debug("检查加密套件失败: {}".format(e))

        return {
            "total": len(all_ciphers),
            "ciphers": all_ciphers,
            "weak_ciphers": weak_ciphers,
            "weak_count": len(weak_ciphers),
            "has_weak": len(weak_ciphers) > 0,
        }

    def _openssl_check(self, host: str, port: int) -> Optional[dict]:
        """
        使用 openssl 进行补充安全检查

        Args:
            host: 目标主机
            port: 目标端口

        Returns:
            openssl 检查结果
        """
        try:
            cmd = [
                "openssl", "s_client",
                "-connect", "{}:{}".format(host, port),
                "-servername", host,
                "-connect_timeout", "5",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                input=""
            )
            output = result.stdout + result.stderr

            details = {}

            # 提取协议版本
            proto_match = re.search(r'Protocol\s*:\s*(\S+)', output)
            if proto_match:
                details["protocol"] = proto_match.group(1)

            # 提取加密套件
            cipher_match = re.search(r'Cipher\s*:\s*(.+)', output)
            if cipher_match:
                details["negotiated_cipher"] = cipher_match.group(1).strip()

            # 提取会话重用信息
            if "Session-ID" in output:
                session_match = re.search(r'Session-ID\s*:\s*(\S+)', output)
                details["session_reuse"] = bool(
                    session_match and session_match.group(1) != "none"
                )

            # 提取 OCSP stapling
            if "OCSP response" in output:
                details["ocsp_stapling"] = True
            else:
                details["ocsp_stapling"] = False

            return details

        except FileNotFoundError:
            return None
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            logger.debug("openssl 补充检查失败: {}".format(e))
            return None

    @staticmethod
    def _is_weak_cipher(cipher_name: str) -> bool:
        """
        判断加密套件是否为弱加密

        Args:
            cipher_name: 加密套件名称

        Returns:
            是否为弱加密
        """
        cipher_upper = cipher_name.upper()

        # 完整匹配不安全套件
        if cipher_upper in INSECURE_CIPHERS:
            return True

        # 关键词匹配
        for keyword in WEAK_CIPHER_KEYWORDS:
            if keyword.upper() in cipher_upper:
                return True

        return False

    @staticmethod
    def _calculate_grade(check_result: dict) -> str:
        """
        根据检测结果计算安全评级

        Args:
            check_result: 完整的检测结果

        Returns:
            评级字母 (A+/A/B/C/D/F)
        """
        vulnerabilities = check_result.get("vulnerabilities", [])
        protocol = check_result.get("protocol", {})
        cert = check_result.get("certificate", {})
        ciphers = check_result.get("cipher_suites", {})

        score = 100

        # 严重问题扣分
        for vuln in vulnerabilities:
            vuln_lower = vuln.lower()
            if "过期" in vuln_lower:
                score -= 30
            elif "自签名" in vuln_lower:
                score -= 15
            elif "ssl" in vuln_lower or "sslv" in vuln_lower:
                score -= 25
            elif "弱加密" in vuln_lower or "弱密码" in vuln_lower:
                score -= 20
            elif "密钥长度不足" in vuln_lower:
                score -= 15
            elif "弃用" in vuln_lower:
                score -= 10
            elif "签名算法" in vuln_lower:
                score -= 15
            else:
                score -= 5

        # 不安全协议扣分
        if protocol.get("has_insecure"):
            score -= 20

        # 弱加密套件扣分
        weak_count = ciphers.get("weak_count", 0)
        if weak_count > 0:
            score -= min(20, weak_count * 2)

        # TLSv1.3 加分
        if protocol.get("supports_tls13"):
            score += 5

        # 限制分数范围
        score = max(0, min(100, score))

        # 转换为评级
        if score >= 90:
            return "A+"
        elif score >= 80:
            return "A"
        elif score >= 65:
            return "B"
        elif score >= 50:
            return "C"
        elif score >= 30:
            return "D"
        else:
            return "F"


# ============================================================
# 单例
# ============================================================

_instance: Optional[SSLChecker] = None
_instance_lock = threading.Lock()


def get_ssl_checker() -> SSLChecker:
    """获取 SSL/TLS 检测器单例"""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = SSLChecker()
    return _instance
