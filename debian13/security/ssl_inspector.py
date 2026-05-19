"""
GateKeeper - SSL/TLS 流量解密检查引擎
基于 mitmproxy 的 SSL/TLS 流量解密与安全检查
"""

import os
import json
import subprocess
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

from config.logging_config import get_logger

logger = get_logger("ssl_inspector")

CONFIG_PATH = "/etc/gatekeeper/rules/ssl_inspector.json"
LOG_PATH = "/opt/gatekeeper/logs/ssl_inspector.log"
MITM_SCRIPT_PATH = "/opt/gatekeeper/scripts/mitm_inspect.py"
SSL_DIR = "/opt/gatekeeper/ssl"


class SSLInspector:
    """SSL/TLS 流量解密检查引擎"""

    def __init__(self):
        self._config = {
            "enabled": False,
            "listen_port": 8080,
            "upstream_proxy": None,
            "ca_cert_path": os.path.join(SSL_DIR, "ca-cert.pem"),
            "ca_key_path": os.path.join(SSL_DIR, "ca-key.pem"),
            "inspect_domains": [],       # 空=全部, 或指定域名列表
            "exclude_domains": [],       # 排除域名
            "block_expired": True,
            "block_self_signed": True,
            "block_weak_cipher": True,
            "min_tls_version": "TLSv1.2",
            "log_decrypted": True,
        }
        self._mitmproxy_process = None
        self._stats = {
            "inspected": 0,
            "blocked": 0,
            "errors": 0,
            "weak_cipher": 0,
            "expired": 0,
            "self_signed": 0,
        }
        self._logs: List[dict] = []
        self._lock = threading.RLock()
        self._load_config()

    # ---- 配置管理 ----

    def _load_config(self):
        """从配置文件加载配置"""
        try:
            if os.path.exists(CONFIG_PATH):
                with open(CONFIG_PATH, "r") as f:
                    saved = json.load(f)
                self._config.update(saved)
                logger.info("SSL检查配置已加载")
        except Exception as e:
            logger.warning("加载SSL检查配置失败: {}".format(e))

    def _save_config(self):
        """保存配置到文件"""
        try:
            os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
            with open(CONFIG_PATH, "w") as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error("保存SSL检查配置失败: {}".format(e))

    def configure(self, config: dict) -> dict:
        """更新配置"""
        try:
            with self._lock:
                for key, value in config.items():
                    if key in self._config:
                        self._config[key] = value
                self._save_config()
                logger.info("SSL检查配置已更新")
                return {"status": "ok", "message": "配置已更新"}
        except Exception as e:
            logger.error("更新SSL检查配置失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def get_config(self) -> dict:
        """获取配置"""
        with self._lock:
            return dict(self._config)

    # ---- CA 证书管理 ----

    def generate_ca(self) -> dict:
        """生成自签名 CA 证书（用于中间人解密）"""
        try:
            os.makedirs(SSL_DIR, exist_ok=True)
            ca_cert = self._config["ca_cert_path"]
            ca_key = self._config["ca_key_path"]

            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", ca_key,
                "-out", ca_cert,
                "-days", "3650",
                "-nodes",
                "-subj", "/CN=GateKeeper SSL CA/O=GateKeeper/C=CN",
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                logger.error("生成CA证书失败: {}".format(result.stderr))
                return {
                    "status": "error",
                    "message": "生成CA证书失败: {}".format(result.stderr),
                }

            logger.info("CA证书已生成: {}".format(ca_cert))
            return {
                "status": "ok",
                "message": "CA证书已生成",
                "ca_cert_path": ca_cert,
                "ca_key_path": ca_key,
            }
        except FileNotFoundError:
            return {
                "status": "error",
                "message": "openssl 未安装，请先安装: apt-get install openssl",
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "生成CA证书超时"}
        except Exception as e:
            logger.error("生成CA证书异常: {}".format(e))
            return {"status": "error", "message": str(e)}

    # ---- mitmproxy 脚本生成 ----

    def _generate_mitm_script(self) -> str:
        """生成 mitmproxy 检查脚本"""
        config = self._config
        script = '''#!/usr/bin/env python3
"""
GateKeeper - mitmproxy SSL 检查 addon 脚本
由 SSLInspector 自动生成，用于 mitmproxy 运行时执行 SSL 安全检查
"""
import json
import os
import sys
from datetime import datetime
from mitmproxy import http, ctx

LOG_FILE = "{log_path}"
CONFIG = {config_json}

# 弱密码套件关键词
WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
# TLS 版本排序
TLS_VERSIONS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


def _tls_version_ge(actual, minimum):
    """判断 actual TLS 版本是否 >= minimum"""
    try:
        return TLS_VERSIONS.index(actual) >= TLS_VERSIONS.index(minimum)
    except ValueError:
        return False


def _log_event(event_data):
    """记录事件到日志文件"""
    try:
        event_data["timestamp"] = datetime.now().isoformat()
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event_data, ensure_ascii=False) + "\\n")
    except Exception:
        pass


class SSLInspectAddon:
    """SSL/TLS 安全检查 addon"""

    def tls_failed_client_hello(self, flow):
        """TLS 握手失败"""
        _log_event({{
            "type": "tls_failed",
            "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "unknown",
            "server": flow.server.address[0] if flow.server.address else "unknown",
            "message": "TLS handshake failed",
        }})

    def response(self, flow: http.HTTPFlow):
        """检查每个 HTTP 响应的 SSL/TLS 信息"""
        if not flow.server_conn or not flow.server_conn.tls_established:
            return

        server = flow.request.pretty_host
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"

        # 检查是否在排除列表中
        exclude_domains = CONFIG.get("exclude_domains", [])
        for domain in exclude_domains:
            if domain and domain in server:
                return

        # 检查是否在检查列表中（空列表=全部检查）
        inspect_domains = CONFIG.get("inspect_domains", [])
        if inspect_domains:
            matched = False
            for domain in inspect_domains:
                if domain and domain in server:
                    matched = True
                    break
            if not matched:
                return

        event = {{
            "type": "ssl_inspect",
            "client_ip": client_ip,
            "server": server,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "tls_version": flow.server_conn.tls_version or "unknown",
            "cipher": flow.server_conn.cipher or "unknown",
            "cert_subject": "",
            "cert_issuer": "",
            "cert_expired": False,
            "cert_self_signed": False,
            "action": "allow",
            "reasons": [],
        }}

        # 获取证书信息
        try:
            cert = flow.server_conn.cert
            if cert:
                event["cert_subject"] = str(cert.subject)
                event["cert_issuer"] = str(cert.issuer)
                # 检查证书是否过期
                not_after = cert.not_after
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
            event["reasons"].append("TLS版本过低: {} (要求 >= {})".format(tls_ver, min_tls))
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
            # 中断连接
            flow.response = http.Response.make(
                503,
                json.dumps({{"error": "SSL/TLS security check failed", "reasons": event["reasons"]}}),
                {{"Content-Type": "application/json"}},
            )

        _log_event(event)


addons = [SSLInspectAddon()]
'''.format(
            log_path=LOG_PATH,
            config_json=json.dumps(config, indent=4, ensure_ascii=False),
        )
        return script

    # ---- 启动/停止 ----

    def start(self) -> dict:
        """启动 SSL 解密代理"""
        try:
            with self._lock:
                if self._mitmproxy_process is not None:
                    return {"status": "error", "message": "SSL解密代理已在运行"}

                # 检查 mitmproxy 是否可用（会自动安装）
                if not self._check_mitmproxy():
                    return {
                        "status": "error",
                        "message": "mitmproxy 安装失败，请手动执行: apt-get install mitmproxy",
                    }

                # 检查 CA 证书
                ca_cert = self._config["ca_cert_path"]
                ca_key = self._config["ca_key_path"]
                if not os.path.exists(ca_cert) or not os.path.exists(ca_key):
                    ca_result = self.generate_ca()
                    if ca_result.get("status") != "ok":
                        return {
                            "status": "error",
                            "message": "CA证书不存在且自动生成失败: {}".format(
                                ca_result.get("message", "")
                            ),
                        }

                # 生成 mitmproxy 检查脚本
                script_content = self._generate_mitm_script()
                os.makedirs(os.path.dirname(MITM_SCRIPT_PATH), exist_ok=True)
                with open(MITM_SCRIPT_PATH, "w") as f:
                    f.write(script_content)
                os.chmod(MITM_SCRIPT_PATH, 0o755)

                # 构建启动命令
                cmd = [
                    "mitmdump",
                    "--mode", "transparent",
                    "--listen-port", str(self._config["listen_port"]),
                    "--set", "ssl_insecure=true",
                    "--set", "certs={}".format(ca_cert),
                ]

                if self._config.get("upstream_proxy"):
                    cmd.extend([
                        "--set", "upstream_cert=false",
                        "--set", "mode=upstream:http://{}".format(
                            self._config["upstream_proxy"]
                        ),
                    ])

                cmd.extend(["-s", MITM_SCRIPT_PATH])

                # 启动进程
                log_file = open(LOG_PATH + ".mitm", "a")
                self._mitmproxy_process = subprocess.Popen(
                    cmd,
                    stdout=log_file,
                    stderr=log_file,
                    preexec_fn=os.setsid,
                )
                self._config["enabled"] = True
                self._save_config()

                logger.info(
                    "SSL解密代理已启动, 端口: {}".format(
                        self._config["listen_port"]
                    )
                )
                return {
                    "status": "ok",
                    "message": "SSL解密代理已启动",
                    "pid": self._mitmproxy_process.pid,
                    "port": self._config["listen_port"],
                }
        except Exception as e:
            logger.error("启动SSL解密代理失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    def stop(self) -> dict:
        """停止 SSL 解密代理"""
        try:
            with self._lock:
                if self._mitmproxy_process is None:
                    return {"status": "error", "message": "SSL解密代理未在运行"}

                try:
                    import signal
                    os.killpg(
                        os.getpgid(self._mitmproxy_process.pid),
                        signal.SIGTERM,
                    )
                    self._mitmproxy_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(
                            os.getpgid(self._mitmproxy_process.pid),
                            signal.SIGKILL,
                        )
                    except Exception:
                        pass
                except Exception:
                    pass

                pid = self._mitmproxy_process.pid
                self._mitmproxy_process = None
                self._config["enabled"] = False
                self._save_config()

                logger.info("SSL解密代理已停止 (PID: {})".format(pid))
                return {"status": "ok", "message": "SSL解密代理已停止"}
        except Exception as e:
            logger.error("停止SSL解密代理失败: {}".format(e))
            return {"status": "error", "message": str(e)}

    # ---- 状态与统计 ----

    def get_status(self) -> dict:
        """获取状态"""
        with self._lock:
            running = self._mitmproxy_process is not None
            if running:
                poll = self._mitmproxy_process.poll()
                running = poll is None
            return {
                "enabled": self._config["enabled"],
                "running": running,
                "pid": self._mitmproxy_process.pid if self._mitmproxy_process else None,
                "listen_port": self._config["listen_port"],
                "ca_cert_exists": os.path.exists(self._config["ca_cert_path"]),
                "mitmproxy_available": self._check_mitmproxy(),
            }

    def _check_mitmproxy(self) -> bool:
        """检查 mitmproxy 是否可用，未安装则自动安装"""
        try:
            result = subprocess.run(
                ["mitmdump", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except FileNotFoundError:
            logger.info("mitmproxy 未安装，正在自动安装...")
            try:
                subprocess.run(
                    ["apt-get", "install", "-y",
                     "-o", "DPkg::Options::=--force-confdef",
                     "-o", "DPkg::Options::=--force-confold",
                     "mitmproxy"],
                    capture_output=True, timeout=120,
                )
                # 验证安装
                result = subprocess.run(
                    ["mitmdump", "--version"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    logger.info("mitmproxy 安装成功")
                    return True
            except Exception as e:
                logger.warning("自动安装 mitmproxy 失败: %s", e)
            return False
        except Exception:
            return False

    def get_stats(self) -> dict:
        """获取统计"""
        with self._lock:
            return dict(self._stats)

    def _add_log(self, entry: dict):
        """添加日志条目"""
        with self._lock:
            entry["timestamp"] = datetime.now().isoformat()
            self._logs.append(entry)
            # 限制日志数量
            max_logs = 10000
            if len(self._logs) > max_logs:
                self._logs = self._logs[-max_logs:]
            # 更新统计
            action = entry.get("action", "")
            reasons = entry.get("reasons", [])
            self._stats["inspected"] += 1
            if action == "block":
                self._stats["blocked"] += 1
            for r in reasons:
                if "弱密码" in r or "弱密码套件" in r:
                    self._stats["weak_cipher"] += 1
                elif "过期" in r:
                    self._stats["expired"] += 1
                elif "自签名" in r:
                    self._stats["self_signed"] += 1

    def get_ssl_logs(self, limit=100) -> list:
        """获取 SSL 检查日志"""
        with self._lock:
            # 优先从日志文件读取
            logs = []
            if os.path.exists(LOG_PATH):
                try:
                    with open(LOG_PATH, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    logs.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue
                except Exception:
                    pass
            # 合并内存日志
            all_logs = logs + self._logs
            # 按时间倒序
            all_logs.sort(
                key=lambda x: x.get("timestamp", ""), reverse=True
            )
            return all_logs[:limit]


# 全局单例
_ssl_inspector = None
_ssl_inspector_lock = threading.Lock()


def get_ssl_inspector() -> SSLInspector:
    """获取 SSL 检查引擎单例"""
    global _ssl_inspector
    if _ssl_inspector is None:
        with _ssl_inspector_lock:
            if _ssl_inspector is None:
                _ssl_inspector = SSLInspector()
    return _ssl_inspector
