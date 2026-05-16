#!/usr/bin/env python3
"""
GateKeeper - mitmproxy SSL 检查 addon 脚本
在 mitmproxy 运行时执行 SSL/TLS 安全检查

此脚本由 SSLInspector 自动生成并调用，也可独立使用:
    mitmdump -s mitm_inspect.py --mode transparent --listen-port 8080

检查项目:
    1. TLS 版本 >= TLSv1.2
    2. 密码套件强度（禁用 RC4, DES, 3DES, MD5, NULL, EXPORT, anon）
    3. 证书有效期
    4. 证书链完整性（自签名检测）
    5. 记录解密后的 HTTP 请求/响应
    6. 对不合规的连接记录日志或阻断
"""

import json
import os
import sys
from datetime import datetime

try:
    from mitmproxy import http, ctx
except ImportError:
    print("ERROR: mitmproxy 未安装。请执行: pip install mitmproxy", file=sys.stderr)
    sys.exit(1)

# 日志文件路径
LOG_FILE = os.environ.get(
    "GATEKEEPER_SSL_LOG",
    "/opt/gatekeeper/logs/ssl_inspector.log",
)

# 配置（可通过环境变量覆盖）
CONFIG = {
    "block_expired": os.environ.get("GATEKEEPER_SSL_BLOCK_EXPIRED", "true").lower() == "true",
    "block_self_signed": os.environ.get("GATEKEEPER_SSL_BLOCK_SELF_SIGNED", "true").lower() == "true",
    "block_weak_cipher": os.environ.get("GATEKEEPER_SSL_BLOCK_WEAK_CIPHER", "true").lower() == "true",
    "min_tls_version": os.environ.get("GATEKEEPER_SSL_MIN_TLS", "TLSv1.2"),
    "log_decrypted": os.environ.get("GATEKEEPER_SSL_LOG_DECRYPTED", "true").lower() == "true",
    "inspect_domains": [],
    "exclude_domains": [],
}

# 弱密码套件关键词
WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]

# TLS 版本排序（从低到高）
TLS_VERSIONS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


def _tls_version_ge(actual, minimum):
    """判断 actual TLS 版本是否 >= minimum"""
    try:
        return TLS_VERSIONS.index(actual) >= TLS_VERSIONS.index(minimum)
    except ValueError:
        # 未知版本，保守处理
        return False


def _log_event(event_data):
    """记录事件到日志文件"""
    try:
        event_data["timestamp"] = datetime.now().isoformat()
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event_data, ensure_ascii=False) + "\n")
    except Exception as e:
        print("写入日志失败: {}".format(e), file=sys.stderr)


def _should_inspect(domain):
    """判断是否应该检查该域名"""
    # 检查排除列表
    for d in CONFIG.get("exclude_domains", []):
        if d and d in domain:
            return False
    # 检查包含列表（空=全部检查）
    inspect = CONFIG.get("inspect_domains", [])
    if not inspect:
        return True
    for d in inspect:
        if d and d in domain:
            return True
    return False


class SSLInspectAddon:
    """SSL/TLS 安全检查 addon"""

    def tls_failed_client_hello(self, flow):
        """TLS 握手失败回调"""
        client_ip = "unknown"
        server = "unknown"
        try:
            if flow.client_conn and flow.client_conn.peername:
                client_ip = flow.client_conn.peername[0]
            if flow.server and flow.server.address:
                server = flow.server.address[0]
        except Exception:
            pass

        _log_event({
            "type": "tls_failed",
            "client_ip": client_ip,
            "server": server,
            "message": "TLS handshake failed",
        })

    def response(self, flow):
        """检查每个 HTTP 响应的 SSL/TLS 信息"""
        if not flow.server_conn or not flow.server_conn.tls_established:
            return

        server = flow.request.pretty_host
        if not _should_inspect(server):
            return

        client_ip = "unknown"
        try:
            if flow.client_conn and flow.client_conn.peername:
                client_ip = flow.client_conn.peername[0]
        except Exception:
            pass

        event = {
            "type": "ssl_inspect",
            "client_ip": client_ip,
            "server": server,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "tls_version": getattr(flow.server_conn, "tls_version", None) or "unknown",
            "cipher": getattr(flow.server_conn, "cipher", None) or "unknown",
            "cert_subject": "",
            "cert_issuer": "",
            "cert_expired": False,
            "cert_self_signed": False,
            "action": "allow",
            "reasons": [],
        }

        # 获取证书信息
        try:
            cert = flow.server_conn.cert
            if cert:
                event["cert_subject"] = str(cert.subject)
                event["cert_issuer"] = str(cert.issuer)
                # 检查证书是否过期
                not_after = getattr(cert, "not_after", None)
                if not_after and not_after < datetime.utcnow():
                    event["cert_expired"] = True
                # 检查是否自签名
                if cert.subject == cert.issuer:
                    event["cert_self_signed"] = True
        except Exception:
            pass

        blocked = False

        # 1. 检查 TLS 版本
        min_tls = CONFIG.get("min_tls_version", "TLSv1.2")
        tls_ver = event["tls_version"]
        if not _tls_version_ge(tls_ver, min_tls):
            event["reasons"].append(
                "TLS版本过低: {} (要求 >= {})".format(tls_ver, min_tls)
            )
            blocked = True

        # 2. 检查密码套件强度
        cipher = event["cipher"]
        if cipher and CONFIG.get("block_weak_cipher", True):
            for weak in WEAK_CIPHER_KEYWORDS:
                if weak.upper() in cipher.upper():
                    event["reasons"].append("弱密码套件: {}".format(cipher))
                    blocked = True
                    break

        # 3. 检查证书有效期
        if event["cert_expired"] and CONFIG.get("block_expired", True):
            event["reasons"].append("证书已过期")
            blocked = True

        # 4. 检查自签名证书
        if event["cert_self_signed"] and CONFIG.get("block_self_signed", True):
            event["reasons"].append("自签名证书")
            blocked = True

        if blocked:
            event["action"] = "block"
            # 中断连接，返回 503
            flow.response = http.Response.make(
                503,
                json.dumps({
                    "error": "SSL/TLS security check failed",
                    "reasons": event["reasons"],
                }),
                {"Content-Type": "application/json"},
            )

        # 5. 记录解密后的请求信息
        if CONFIG.get("log_decrypted", True):
            event["status_code"] = flow.response.status_code if flow.response else 0
            event["content_type"] = ""
            if flow.response:
                event["content_type"] = flow.response.headers.get("Content-Type", "")

        _log_event(event)


addons = [SSLInspectAddon()]
