"""
GateKeeper - 蜜罐系统引擎
实现多种协议的蜜罐服务模拟，捕获攻击行为并记录
"""

import socket
import struct
import threading
import time
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import deque

from config.logging_config import get_logger
from core.database import db_manager
from core.models import ThreatLevel

logger = get_logger("honeypot")


# ============================================================
# 蜜罐服务配置
# ============================================================

class HoneypotService:
    """蜜罐服务配置"""

    def __init__(self, name: str, service_type: str, listen_port: int,
                 protocol: str = "tcp", max_connections: int = 100,
                 connection_timeout: int = 60, banner: str = ""):
        self.name = name
        self.service_type = service_type.lower()
        self.listen_port = listen_port
        self.protocol = protocol.lower()
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.banner = banner or self._default_banner()
        self.enabled = False
        self.created_at = datetime.now()
        self.stats = {
            "attacked_count": 0,
            "last_attack": None,
        }
        self._socket = None
        self._thread = None
        self._running = False
        self._lock = threading.Lock()

    def _default_banner(self) -> str:
        """根据服务类型返回默认banner"""
        banners = {
            "ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
            "http": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n",
            "ftp": "220 Welcome to FTP Server (Ubuntu)\r\n",
            "telnet": "\r\nLogin: ",
            "mysql": "J\u00005.7.42-0ubuntu0.18.04.1\u0000",
            "smtp": "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n",
            "dns": "",
            "smb": "",
            "mongodb": "",
            "redis": "",
        }
        return banners.get(self.service_type, "")

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "name": self.name,
            "service_type": self.service_type,
            "listen_port": self.listen_port,
            "protocol": self.protocol,
            "enabled": self.enabled,
            "max_connections": self.max_connections,
            "connection_timeout": self.connection_timeout,
            "banner": self.banner,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "stats": self.stats,
        }


# ============================================================
# 蜜罐捕获记录
# ============================================================

class HoneypotCapture:
    """蜜罐捕获记录"""

    def __init__(self, service_name: str, client_ip: str, client_port: int,
                 protocol: str, captured_data: str = "",
                 credentials: str = "", commands: str = "",
                 files_accessed: str = "",
                 threat_level: str = "low", tags: str = ""):
        self.id = None
        self.service_name = service_name
        self.client_ip = client_ip
        self.client_port = client_port
        self.timestamp = datetime.now()
        self.protocol = protocol
        self.captured_data = captured_data
        self.credentials = credentials
        self.commands = commands
        self.files_accessed = files_accessed
        self.threat_level = threat_level
        self.tags = tags

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "service_name": self.service_name,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "protocol": self.protocol,
            "captured_data": self.captured_data,
            "credentials": self.credentials,
            "commands": self.commands,
            "files_accessed": self.files_accessed,
            "threat_level": self.threat_level,
            "tags": self.tags,
        }


# ============================================================
# 蜜罐管理器
# ============================================================

class HoneypotManager:
    """蜜罐管理器"""

    def __init__(self):
        self._services: Dict[str, HoneypotService] = {}
        self._captures: deque = deque(maxlen=10000)
        self._lock = threading.Lock()
        self._capture_id_counter = 0
        logger.info("蜜罐管理器初始化完成")

    def create_service(self, config: dict) -> dict:
        """
        创建蜜罐服务

        Args:
            config: 服务配置字典
                - name: 服务名称
                - type: 服务类型 (ssh/http/ftp/smb/dns/smtp/telnet/mysql/mongodb/redis)
                - port: 监听端口
                - protocol: 协议 (tcp/udp)

        Returns:
            创建结果
        """
        with self._lock:
            name = config.get("name", "").strip()
            service_type = config.get("type", "").strip().lower()
            port = config.get("port", 0)
            protocol = config.get("protocol", "tcp").strip().lower()

            if not name:
                return {"status": "error", "message": "服务名称不能为空"}
            if name in self._services:
                return {"status": "error", "message": "服务名称已存在: {}".format(name)}
            if not service_type:
                return {"status": "error", "message": "服务类型不能为空"}
            valid_types = ["ssh", "http", "ftp", "smb", "dns", "smtp",
                           "telnet", "mysql", "mongodb", "redis"]
            if service_type not in valid_types:
                return {"status": "error", "message": "不支持的服务类型: {}".format(service_type)}
            if not (1 <= port <= 65535):
                return {"status": "error", "message": "端口必须在 1-65535 范围内"}
            if protocol not in ("tcp", "udp"):
                return {"status": "error", "message": "协议必须是 tcp 或 udp"}

            # 检查端口冲突
            for svc in self._services.values():
                if svc.listen_port == port and svc.protocol == protocol:
                    return {"status": "error", "message": "端口 {} ({}) 已被服务 {} 占用".format(
                        port, protocol, svc.name)}

            max_conn = config.get("max_connections", 100)
            timeout = config.get("connection_timeout", 60)
            banner = config.get("banner", "")

            service = HoneypotService(
                name=name,
                service_type=service_type,
                listen_port=port,
                protocol=protocol,
                max_connections=max_conn,
                connection_timeout=timeout,
                banner=banner,
            )
            self._services[name] = service

            logger.info("蜜罐服务已创建: {} ({}:{}/{})".format(name, service_type, port, protocol))
            return {"status": "ok", "message": "服务创建成功", "service": service.to_dict()}

    def remove_service(self, name: str) -> dict:
        """移除蜜罐服务"""
        with self._lock:
            service = self._services.get(name)
            if not service:
                return {"status": "error", "message": "服务不存在: {}".format(name)}

            if service._running:
                self._stop_service_internal(service)

            del self._services[name]
            logger.info("蜜罐服务已移除: {}".format(name))
            return {"status": "ok", "message": "服务已移除"}

    def start_service(self, name: str) -> dict:
        """启动蜜罐服务"""
        with self._lock:
            service = self._services.get(name)
            if not service:
                return {"status": "error", "message": "服务不存在: {}".format(name)}
            if service._running:
                return {"status": "error", "message": "服务已在运行中"}

            try:
                self._start_service_internal(service)
                logger.info("蜜罐服务已启动: {} ({}:{})".format(name, service.service_type, service.listen_port))
                return {"status": "ok", "message": "服务已启动"}
            except Exception as e:
                logger.error("启动蜜罐服务失败: {} - {}".format(name, e))
                return {"status": "error", "message": "启动失败: {}".format(str(e))}

    def stop_service(self, name: str) -> dict:
        """停止蜜罐服务"""
        with self._lock:
            service = self._services.get(name)
            if not service:
                return {"status": "error", "message": "服务不存在: {}".format(name)}
            if not service._running:
                return {"status": "error", "message": "服务未在运行"}

            self._stop_service_internal(service)
            logger.info("蜜罐服务已停止: {}".format(name))
            return {"status": "ok", "message": "服务已停止"}

    def _start_service_internal(self, service: HoneypotService):
        """内部启动服务"""
        if service.protocol == "udp" and service.service_type == "dns":
            # UDP服务使用不同的启动方式
            service._running = True
            service.enabled = True
            service._thread = threading.Thread(
                target=self._udp_listener, args=(service,),
                daemon=True, name="honeypot-udp-{}".format(service.name)
            )
            service._thread.start()
        else:
            # TCP服务
            service._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            service._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            service._socket.settimeout(1.0)
            service._socket.bind(("0.0.0.0", service.listen_port))
            service._socket.listen(service.max_connections)
            service._running = True
            service.enabled = True
            service._thread = threading.Thread(
                target=self._tcp_listener, args=(service,),
                daemon=True, name="honeypot-tcp-{}".format(service.name)
            )
            service._thread.start()

    def _stop_service_internal(self, service: HoneypotService):
        """内部停止服务"""
        service._running = False
        service.enabled = False
        if service._socket:
            try:
                service._socket.close()
            except Exception:
                pass
            service._socket = None
        if service._thread:
            service._thread.join(timeout=5.0)
            service._thread = None

    def _tcp_listener(self, service: HoneypotService):
        """TCP连接监听器"""
        logger.info("TCP蜜罐监听启动: {} -> 0.0.0.0:{}".format(
            service.name, service.listen_port))
        while service._running:
            try:
                conn, addr = service._socket.accept()
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr, service),
                    daemon=True,
                    name="honeypot-conn-{}".format(service.name)
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                logger.error("TCP监听异常 ({}): {}".format(service.name, e))
                break
        logger.info("TCP蜜罐监听已停止: {}".format(service.name))

    def _udp_listener(self, service: HoneypotService):
        """UDP连接监听器"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        try:
            sock.bind(("0.0.0.0", service.listen_port))
        except Exception as e:
            logger.error("UDP绑定失败 ({}): {}".format(service.name, e))
            return

        service._socket = sock
        logger.info("UDP蜜罐监听启动: {} -> 0.0.0.0:{}".format(
            service.name, service.listen_port))
        while service._running:
            try:
                data, addr = sock.recvfrom(4096)
                self._handle_dns_connection(data, addr, service)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                logger.error("UDP监听异常 ({}): {}".format(service.name, e))
                break
        logger.info("UDP蜜罐监听已停止: {}".format(service.name))

    def _handle_connection(self, conn: socket.socket, addr: tuple, service: HoneypotService):
        """根据服务类型分发连接处理"""
        client_ip, client_port = addr[0], addr[1]
        logger.info("蜜罐连接: {} <- {}:{}".format(service.name, client_ip, client_port))

        handler_map = {
            "ssh": self._handle_ssh_connection,
            "http": self._handle_http_connection,
            "ftp": self._handle_ftp_connection,
            "telnet": self._handle_telnet_connection,
            "mysql": self._handle_mysql_connection,
            "smtp": self._handle_smtp_connection,
            "smb": self._handle_smb_connection,
            "mongodb": self._handle_mongodb_connection,
            "redis": self._handle_redis_connection,
        }

        handler = handler_map.get(service.service_type)
        if handler:
            try:
                handler(conn, service, client_ip, client_port)
            except Exception as e:
                logger.error("处理连接异常 ({}): {}".format(service.name, e))
        else:
            # 通用处理
            self._handle_generic_connection(conn, service, client_ip, client_port)

        # 更新统计
        service.stats["attacked_count"] += 1
        service.stats["last_attack"] = datetime.now().isoformat()

    # ============================================================
    # 协议模拟处理
    # ============================================================

    def _handle_ssh_connection(self, conn: socket.socket, service: HoneypotService,
                                client_ip: str, client_port: int):
        """模拟SSH服务"""
        conn.settimeout(service.connection_timeout)
        try:
            # 发送SSH banner
            conn.sendall(service.banner.encode("utf-8", errors="replace"))

            captured_data = ""
            credentials = ""
            commands = ""
            username = ""
            password = ""

            # 等待客户端数据
            for _ in range(10):
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    raw = data.decode("utf-8", errors="replace")
                    captured_data += raw

                    # 检测用户名密码尝试
                    lower = raw.lower()
                    if "user" in lower:
                        parts = raw.replace("\r\n", "").split(" ", 1)
                        if len(parts) > 1:
                            username = parts[1].strip()
                    if "pass" in lower:
                        parts = raw.replace("\r\n", "").split(" ", 1)
                        if len(parts) > 1:
                            password = parts[1].strip()

                    # 尝试从SSH协议包中提取凭证
                    if not username and len(data) > 50:
                        # 尝试从SSH认证包中提取
                        try:
                            if b"password" in data.lower():
                                idx = data.find(b"password")
                                # 简单提取周围数据
                                surrounding = data[max(0, idx-20):idx+50]
                                credentials = surrounding.decode("utf-8", errors="replace")
                        except Exception:
                            pass

                    # 发送认证失败响应
                    if username and password:
                        credentials = "{}:{}".format(username, password)
                        conn.sendall(b"Permission denied, please try again.\r\n")
                        username = ""
                        password = ""
                    elif not credentials:
                        conn.sendall(b"\r\nPassword: ")

                except socket.timeout:
                    break
                except Exception:
                    break

            if credentials:
                credentials = credentials.replace("\r\n", "").replace("\n", "")

            # 创建捕获记录
            threat = self._assess_threat(client_ip, captured_data, credentials)
            capture = HoneypotCapture(
                service_name=service.name,
                client_ip=client_ip,
                client_port=client_port,
                protocol="tcp",
                captured_data=captured_data[:2000],
                credentials=credentials,
                commands=commands,
                threat_level=threat,
                tags="ssh,brute_force" if credentials else "ssh,scan",
            )
            self._log_capture(capture)
            self._create_alert(capture)

        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_http_connection(self, conn: socket.socket, service: HoneypotService,
                                 client_ip: str, client_port: int):
        """模拟HTTP服务"""
        conn.settimeout(service.connection_timeout)
        try:
            # 接收HTTP请求
            data = b""
            for _ in range(5):
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data:
                        break
                except socket.timeout:
                    break

            raw_request = data.decode("utf-8", errors="replace")
            captured_data = raw_request[:2000]

            # 解析请求
            request_lines = raw_request.split("\r\n")
            method = ""
            path = ""
            user_agent = ""
            if request_lines:
                first_line = request_lines[0]
                parts = first_line.split(" ")
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]

            for line in request_lines:
                if line.lower().startswith("user-agent:"):
                    user_agent = line.split(":", 1)[1].strip()

            # 返回模拟HTTP响应
            html_content = """<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>Welcome to the Server</h1><p>Please login to continue.</p>
<form method="post" action="/login">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<button type="submit">Login</button>
</form></body></html>"""
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Server: Apache/2.4.52 (Ubuntu)\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Content-Length: {}\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{}"
            ).format(len(html_content), html_content)
            conn.sendall(response.encode("utf-8"))

            # 评估威胁
            threat = self._assess_http_threat(method, path, raw_request)
            tags = "http"
            if method in ("POST", "PUT"):
                tags += ",post_request"
            if any(kw in path.lower() for kw in ["admin", "login", "wp-", "phpmyadmin", "shell"]):
                tags += ",sensitive_path"
            if any(kw in raw_request.lower() for kw in ["<script", "union", "select", "../"]):
                tags += ",attack_attempt"

            capture = HoneypotCapture(
                service_name=service.name,
                client_ip=client_ip,
                client_port=client_port,
                protocol="tcp",
                captured_data=captured_data,
                threat_level=threat,
                tags=tags,
            )
            self._log_capture(capture)
            if threat in ("high", "critical"):
                self._create_alert(capture)

        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_ftp_connection(self, conn: socket.socket, service: HoneypotService,
                                client_ip: str, client_port: int):
        """模拟FTP服务"""
        conn.settimeout(service.connection_timeout)
        try:
            # 发送FTP banner
            conn.sendall(service.banner.encode("utf-8", errors="replace"))

            captured_data = ""
            credentials = ""
            username = ""
            password = ""

            for _ in range(20):
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    raw = data.decode("utf-8", errors="replace")
                    captured_data += raw

                    cmd = raw.strip().upper()
                    if cmd.startswith("USER"):
                        username = raw.strip().split(" ", 1)[1] if " " in raw.strip() else ""
                        conn.sendall(b"331 Password required\r\n")
                    elif cmd.startswith("PASS"):
                        password = raw.strip().split(" ", 1)[1] if " " in raw.strip() else ""
                        credentials = "{}:{}".format(username, password)
                        conn.sendall(b"530 Login incorrect\r\n")
                        username = ""
                        password = ""
                    elif cmd.startswith("QUIT"):
                        conn.sendall(b"221 Goodbye\r\n")
                        break
                    elif cmd.startswith("SYST"):
                        conn.sendall(b"215 UNIX Type: L8\r\n")
                    elif cmd.startswith("TYPE"):
                        conn.sendall(b"200 Type set\r\n")
                    elif cmd.startswith("LIST") or cmd.startswith("PWD") or cmd.startswith("CWD"):
                        conn.sendall(b"530 Please login first\r\n")
                    else:
                        conn.sendall(b"530 Please login first\r\n")

                except socket.timeout:
                    break
                except Exception:
                    break

            threat = self._assess_threat(client_ip, captured_data, credentials)
            capture = HoneypotCapture(
                service_name=service.name,
                client_ip=client_ip,
                client_port=client_port,
                protocol="tcp",
                captured_data=captured_data[:2000],
                credentials=credentials,
                threat_level=threat,
                tags="ftp,brute_force" if credentials else "ftp,scan",
            )
            self._log_capture(capture)
            self._create_alert(capture)

        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_telnet_connection(self, conn: socket.socket, service: HoneypotService,
                                   client_ip: str, client_port: int):
        """模拟Telnet服务"""
        conn.settimeout(service.connection_timeout)
        try:
            # 发送登录提示
            conn.sendall(b"\r\nUbuntu 22.04 LTS\r\n")
            conn.sendall(b"login: ")

            captured_data = ""
            credentials = ""
            username = ""
            password = ""
            commands = ""

            for _ in range(20):
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    raw = data.decode("utf-8", errors="replace")
                    captured_data += raw

                    line = raw.strip()
                    if not username:
                        username = line
                        conn.sendall(b"Password: ")
                    elif not password:
                        password = line
                        credentials = "{}:{}".format(username, password)
                        conn.sendall(b"Login incorrect\r\nlogin: ")
                        username = ""
                        password = ""
                    else:
                        commands += line + "\n"
                        conn.sendall(b"$ \r\n")

                except socket.timeout:
                    break
                except Exception:
                    break

            threat = self._assess_threat(client_ip, captured_data, credentials)
            capture = HoneypotCapture(
                service_name=service.name,
                client_ip=client_ip,
                client_port=client_port,
                protocol="tcp",
                captured_data=captured_data[:2000],
                credentials=credentials,
                commands=commands[:1000],
                threat_level=threat,
                tags="telnet,brute_force" if credentials else "telnet,scan",
            )
            self._log_capture(capture)
            self._create_alert(capture)

        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_mysql_connection(self, conn: socket.socket, service: HoneypotService,
                                  client_ip: str, client_port: int):
        """模拟MySQL服务"""
        conn.settimeout(service.connection_timeout)
        try:
            # 发送MySQL握手包
            # MySQL greeting packet: protocol(1) + version(null-terminated) + ...
            version = b"5.7.42-0ubuntu0.18.04.1"
            greeting = struct.pack("<B", 10)  # protocol version 10
            greeting += version + b"\x00"
            greeting += b"\x00" * 8  # thread id (8 bytes)
            greeting += b"abcdefgh"  # salt part 1 (8 bytes)
            greeting += b"\x00"  # filler
            greeting += struct.pack("<H", 0xFFCF)  # capabilities (lower)
            greeting += b"\x08"  # charset
            greeting += struct.pack("<H", 0)  # status
            greeting += b"\x00\x00" * 6  # extended capabilities
            greeting += b"ijklmnop"  # salt part 2 (12 bytes)
            greeting += b"\x00"  # filler

            # MySQL packet header: length(3) + sequence(1)
            packet_len = len(greeting)
            header = struct.pack("<I", packet_len)[:3] + b"\x00"
            conn.sendall(header + greeting)

            captured_data = ""
            credentials = ""

            for _ in range(5):
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    captured_data += data.hex()

                    # 尝试从认证包中提取用户名
                    # MySQL auth packet structure: capabilities(4) + max_packet(4) + charset(1) + username(null-term) + ...
                    try:
                        if len(data) > 36:
                            # 跳过头部(4) + capabilities(4) + max_packet(4) + charset(1) = 13 bytes
                            offset = 36  # header(4) + caps(4) + max_pkt(4) + charset(1) + reserved(23)
                            if offset < len(data):
                                # 查找null终止的用户名
                                null_idx = data.find(b"\x00", offset)
                                if null_idx > offset:
                                    username = data[offset:null_idx].decode("utf-8", errors="replace")
                                    credentials = "user={}".format(username)
                    except Exception:
                        pass

                    # 返回认证失败
                    error_packet = b"\x00" * 4  # header placeholder
                    error_body = b"\xff" + b"\x00\x00" + b"#28000Access denied for user 'root'@'localhost'"
                    error_len = len(error_body)
                    error_header = struct.pack("<I", error_len)[:3] + b"\x01"
                    conn.sendall(error_header + error_body)
                    break

                except socket.timeout:
                    break
                except Exception:
                    break

            threat = self._assess_threat(client_ip, captured_data, credentials)
            capture = HoneypotCapture(
                service_name=service.name,
                client_ip=client_ip,
                client_port=client_port,
                protocol="tcp",
                captured_data=captured_data[:2000],
                credentials=credentials,
                threat_level=threat,
                tags="mysql,auth_attempt" if credentials else "mysql,scan",
            )
            self._log_capture(capture)
            self._create_alert(capture)

        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_smtp_connection(self, conn: socket.socket, service: HoneypotService,
                                 client_ip: str, client_port: int):
        """模拟SMTP服务"""
        conn.settimeout(service.connection_timeout)
        try:
            # 发送SMTP banner
            conn.sendall(service.banner.encode("utf-8", errors="replace"))

            captured_data = ""
            mail_from = ""
            rcpt_to = ""
            commands = ""

            for _ in range(20):
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    raw = data.decode("utf-8", errors="replace")
                    captured_data += raw

                    cmd = raw.strip().upper()
                    if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                        conn.sendall(b"250-mail.example.com Hello\r\n250 OK\r\n")
                    elif cmd.startswith("MAIL FROM"):
                        mail_from = raw.strip()
                        conn.sendall(b"250 OK\r\n")
                    elif cmd.startswith("RCPT TO"):
                        rcpt_to = raw.strip()
                        conn.sendall(b"250 OK\r\n")
                    elif cmd.startswith("DATA"):
                        conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    elif cmd.startswith("QUIT"):
                        conn.sendall(b"221 Bye\r\n")
                        break
                    elif cmd.startswith("RSET"):
                        conn.sendall(b"250 OK\r\n")
                    elif cmd.startswith("NOOP"):
                        conn.sendall(b"250 OK\r\n")
                    elif cmd.startswith("VRFY"):
                        conn.sendall(b"252 Cannot VRFY user\r\n")
                    elif cmd.startswith("AUTH"):
                        conn.sendall(b"502 Authentication not supported\r\n")
                    else:
                        conn.sendall(b"500 Command not recognized\r\n")

                except socket.timeout:
                    break
                except Exception:
                    break

            if mail_from or rcpt_to:
                commands = "MAIL_FROM:{}|RCPT_TO:{}".format(mail_from, rcpt_to)

            threat = "medium" if (mail_from and rcpt_to) else "low"
            capture = HoneypotCapture(
                service_name=service.name,
                client_ip=client_ip,
                client_port=client_port,
                protocol="tcp",
                captured_data=captured_data[:2000],
                commands=commands,
                threat_level=threat,
                tags="smtp,email_recon" if (mail_from and rcpt_to) else "smtp,scan",
            )
            self._log_capture(capture)

        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_dns_connection(self, data: bytes, addr: tuple, service: HoneypotService):
        """模拟DNS服务"""
        client_ip, client_port = addr[0], addr[1]
        captured_data = data.hex()
        queried_domains = []

        try:
            # 解析DNS查询包
            if len(data) >= 12:
                # DNS header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
                qdcount = struct.unpack("!H", data[4:6])[0]
                offset = 12

                for _ in range(min(qdcount, 10)):
                    domain = ""
                    while offset < len(data):
                        label_len = data[offset]
                        offset += 1
                        if label_len == 0:
                            break
                        if offset + label_len > len(data):
                            break
                        label = data[offset:offset + label_len].decode("utf-8", errors="replace")
                        domain += label + "."
                        offset += label_len
                    if domain.endswith("."):
                        domain = domain[:-1]
                    if domain:
                        queried_domains.append(domain)
                    offset += 4  # skip QTYPE(2) + QCLASS(2)

                # 发送简单的DNS响应
                try:
                    response = self._build_dns_response(data, queried_domains)
                    if service._socket:
                        service._socket.sendto(response, addr)
                except Exception:
                    pass

        except Exception as e:
            logger.error("解析DNS查询失败: {}".format(e))

        threat = "low"
        tags = "dns"
        if any(d for d in queried_domains if any(kw in d.lower() for kw in
                ["update", "bind", "version", "chaos", "txt"])):
            threat = "medium"
            tags += ",suspicious_query"

        capture = HoneypotCapture(
            service_name=service.name,
            client_ip=client_ip,
            client_port=client_port,
            protocol="udp",
            captured_data=captured_data[:2000],
            commands="queried:{}".format(",".join(queried_domains)) if queried_domains else "",
            threat_level=threat,
            tags=tags,
        )
        self._log_capture(capture)

        service.stats["attacked_count"] += 1
        service.stats["last_attack"] = datetime.now().isoformat()

    def _build_dns_response(self, query: bytes, domains: list) -> bytes:
        """构建简单的DNS响应"""
        try:
            # 复制查询头，设置响应标志
            response = bytearray(query[:12])
            # 设置QR=1 (response), AA=1 (authoritative), RCODE=0 (no error)
            flags = struct.unpack("!H", query[2:4])[0]
            flags = flags | 0x8400  # QR=1, AA=1
            response[2:4] = struct.pack("!H", flags)

            # 复制查询部分
            response.extend(query[12:])

            # 添加简单的answer section
            for domain in domains[:3]:
                # Name pointer (compression)
                response.extend(b"\xc0\x0c")  # pointer to first question name
                response.extend(struct.pack("!HHI", 1, 1, 300))  # TYPE=A, CLASS=IN, TTL=300
                response.extend(struct.pack("!H", 4))  # RDLENGTH=4
                response.extend(b"\x0a\x00\x00\x01")  # 10.0.0.1

            # 更新header counts
            qdcount = struct.unpack("!H", query[4:6])[0]
            response[6:8] = struct.pack("!H", len(domains[:3]))  # ANCOUNT

            return bytes(response)
        except Exception:
            return b""

    def _handle_smb_connection(self, conn: socket.socket, service: HoneypotService,
                                client_ip: str, client_port: int):
        """模拟SMB服务"""
        conn.settimeout(service.connection_timeout)
        try:
            # SMB negotiation
            smb_banner = b"\x00\x00\x00\x85\xffSMB"  # SMB1 header
            data = b""
            for _ in range(5):
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break

            captured_data = data.hex()

            # 返回SMB negotiation response
            response = (
                b"\x00\x00\x00\x43\xffSMB"
                b"\x72"  # negprot command
                b"\x00\x00\x00\x00"
                b"\x00\x00\x00\x00"
                b"\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x02"  # dialect index
                b"\x11\x03"  # security mode
                b"\x00\x00"
                b"\x5000"  # max buffer
                b"\x01\x00"  # max mux
                b"\x01\x00"  # num vcs
                b"\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            try:
                conn.sendall(response)
            except Exception:
                pass

            capture = HoneypotCapture(
                service_name=service.name,
                client_ip=client_ip,
                client_port=client_port,
                protocol="tcp",
                captured_data=captured_data[:2000],
                threat_level="medium",
                tags="smb,scan",
            )
            self._log_capture(capture)

        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_mongodb_connection(self, conn: socket.socket, service: HoneypotService,
                                    client_ip: str, client_port: int):
        """模拟MongoDB服务"""
        conn.settimeout(service.connection_timeout)
        try:
            data = b""
            for _ in range(5):
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) >= 16:
                        # MongoDB wire protocol: length(4) + requestID(4) + responseTo(4) + opCode(4)
                        msg_len = struct.unpack("<I", data[:4])[0]
                        if len(data) >= msg_len:
                            break
                except socket.timeout:
                    break

            captured_data = data.hex()

            # 构建MongoDB ismaster响应
            ismaster_doc = (
                b"\x00\x00\x00\x00"  # length placeholder
                b"\x01\x00\x00\x00"  # requestID
                b"\x00\x00\x00\x00"  # responseTo
                b"\xd4\x07\x00\x00"  # opCode = OP_REPLY (1)
                b"\x00\x00\x00\x00"  # flags
                b"\x01\x00\x00\x00"  # cursorID
                b"\x00\x00\x00\x00"  # cursorID
                b"\x01\x00\x00\x00"  # startingFrom
                b"\x01\x00\x00\x00"  # numberReturned
                # BSON document: {ismaster: true, maxBsonObjectSize: 16777216, ok: 1}
                b"\x26\x00\x00\x00"  # document length
                b"\x08" b"ismaster" b"\x00" b"\x01"  # ismaster: true
                b"\x01" b"maxBsonObjectSize" b"\x00" b"\x00\x00\x00\x01"  # int32: 16777216
                b"\x01" b"ok" b"\x00" b"\x00\x00\x00\x01"  # ok: 1
                b"\x00"  # document terminator
            )
            # Update length
            doc_len = len(ismaster_doc)
            ismaster_doc = struct.pack("<I", doc_len) + ismaster_doc[4:]

            try:
                conn.sendall(ismaster_doc)
            except Exception:
                pass

            capture = HoneypotCapture(
                service_name=service.name,
                client_ip=client_ip,
                client_port=client_port,
                protocol="tcp",
                captured_data=captured_data[:2000],
                threat_level="medium",
                tags="mongodb,scan",
            )
            self._log_capture(capture)

        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_redis_connection(self, conn: socket.socket, service: HoneypotService,
                                  client_ip: str, client_port: int):
        """模拟Redis服务"""
        conn.settimeout(service.connection_timeout)
        try:
            data = b""
            commands = ""

            for _ in range(10):
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    raw = chunk.decode("utf-8", errors="replace")
                    commands += raw + " "

                    # 简单解析Redis命令
                    cmd = raw.strip().upper()
                    if cmd.startswith("PING"):
                        conn.sendall(b"+PONG\r\n")
                    elif cmd.startswith("INFO"):
                        conn.sendall(
                            b"# Server\r\nredis_version:7.0.12\r\n"
                            b"os:Linux 5.15.0-91-generic x86_64\r\n"
                            b"# Clients\r\nconnected_clients:1\r\n"
                        )
                    elif cmd.startswith("COMMAND"):
                        conn.sendall(b"*0\r\n")
                    elif cmd.startswith("AUTH"):
                        # 记录认证尝试
                        conn.sendall(b"-ERR Client sent AUTH, but no password is set\r\n")
                    elif cmd.startswith("CONFIG"):
                        conn.sendall(b"-ERR unknown command\r\n")
                    elif cmd.startswith("SET") or cmd.startswith("GET") or cmd.startswith("DEL"):
                        conn.sendall(b"+OK\r\n")
                    elif cmd.startswith("KEYS"):
                        conn.sendall(b"*0\r\n")
                    elif cmd.startswith("QUIT"):
                        conn.sendall(b"+OK\r\n")
                        break
                    else:
                        conn.sendall(b"-ERR unknown command\r\n")

                except socket.timeout:
                    break
                except Exception:
                    break

            captured_data = data.hex()
            credentials = ""
            if "AUTH" in commands.upper():
                threat = "medium"
                tags = "redis,auth_attempt"
            else:
                threat = "low"
                tags = "redis,scan"

            capture = HoneypotCapture(
                service_name=service.name,
                client_ip=client_ip,
                client_port=client_port,
                protocol="tcp",
                captured_data=captured_data[:2000],
                commands=commands.strip()[:1000],
                credentials=credentials,
                threat_level=threat,
                tags=tags,
            )
            self._log_capture(capture)

        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_generic_connection(self, conn: socket.socket, service: HoneypotService,
                                    client_ip: str, client_port: int):
        """通用连接处理"""
        conn.settimeout(service.connection_timeout)
        try:
            data = b""
            for _ in range(5):
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break

            captured_data = data.hex()
            if data:
                conn.sendall(service.banner.encode("utf-8", errors="replace"))

            capture = HoneypotCapture(
                service_name=service.name,
                client_ip=client_ip,
                client_port=client_port,
                protocol=service.protocol,
                captured_data=captured_data[:2000],
                threat_level="low",
                tags="{},scan".format(service.service_type),
            )
            self._log_capture(capture)

        finally:
            try:
                conn.close()
            except Exception:
                pass

    # ============================================================
    # 威胁评估
    # ============================================================

    def _assess_threat(self, client_ip: str, captured_data: str,
                       credentials: str) -> str:
        """评估威胁级别"""
        if credentials:
            return "high"
        if captured_data and len(captured_data) > 200:
            return "medium"
        return "low"

    def _assess_http_threat(self, method: str, path: str, raw_request: str) -> str:
        """评估HTTP请求威胁级别"""
        attack_patterns = [
            (r"union\s+select", "critical"),
            (r"<script", "high"),
            (r"\.\./", "high"),
            (r"exec\s*\(", "critical"),
            (r"system\s*\(", "critical"),
            (r"passwd", "high"),
            (r"/etc/shadow", "critical"),
            (r"cmd=|command=", "high"),
            (r"base64_decode", "high"),
            (r"eval\s*\(", "high"),
        ]
        import re
        for pattern, level in attack_patterns:
            if re.search(pattern, raw_request, re.IGNORECASE):
                return level

        sensitive_paths = ["/admin", "/wp-admin", "/phpmyadmin", "/manager",
                          "/console", "/actuator", "/.env", "/config"]
        for sp in sensitive_paths:
            if sp in path.lower():
                return "high"

        if method in ("POST", "PUT", "DELETE"):
            return "medium"
        return "low"

    # ============================================================
    # 捕获记录管理
    # ============================================================

    def _log_capture(self, capture: HoneypotCapture):
        """记录捕获数据"""
        with self._lock:
            self._capture_id_counter += 1
            capture.id = self._capture_id_counter
            self._captures.append(capture)

        logger.info(
            "蜜罐捕获: service={}, ip={}, port={}, level={}, tags={}".format(
                capture.service_name, capture.client_ip, capture.client_port,
                capture.threat_level, capture.tags
            )
        )

    def _create_alert(self, capture: HoneypotCapture):
        """为高危捕获创建告警"""
        if capture.threat_level not in ("high", "critical"):
            return

        try:
            from alerting.alert_manager import AlertManager
            alert_mgr = AlertManager()

            level = "high"
            if capture.threat_level == "critical":
                level = "critical"

            title = "蜜罐检测到{}威胁".format(
                "严重" if level == "critical" else "高危"
            )
            description = "蜜罐服务 {} 检测到来自 {} 的{}活动".format(
                capture.service_name, capture.client_ip,
                "凭证暴力破解" if capture.credentials else "可疑探测"
            )
            if capture.credentials:
                description += ", 尝试凭证: {}".format(capture.credentials[:100])

            alert_mgr.create_alert(
                title=title,
                level=level,
                source="honeypot",
                description=description,
                source_ip=capture.client_ip,
                port=capture.client_port,
                protocol=capture.protocol,
                metadata={
                    "service_name": capture.service_name,
                    "captured_data": capture.captured_data[:500],
                    "credentials": capture.credentials,
                    "commands": capture.commands,
                    "tags": capture.tags,
                },
            )
        except Exception as e:
            logger.error("创建蜜罐告警失败: {}".format(e))

    def list_services(self) -> List[dict]:
        """列出所有服务"""
        with self._lock:
            return [svc.to_dict() for svc in self._services.values()]

    def get_captures(self, service: str = None, threat_level: str = None,
                     limit: int = 100) -> List[dict]:
        """获取捕获记录"""
        with self._lock:
            captures = list(self._captures)

        # 过滤
        if service:
            captures = [c for c in captures if c.service_name == service]
        if threat_level:
            captures = [c for c in captures if c.threat_level == threat_level]

        # 按时间倒序
        captures.sort(key=lambda c: c.timestamp, reverse=True)
        return [c.to_dict() for c in captures[:limit]]

    def get_stats(self) -> dict:
        """获取统计信息"""
        with self._lock:
            services = list(self._services.values())
            captures = list(self._captures)

        total_captures = len(captures)
        running_services = sum(1 for s in services if s._running)
        total_attacks = sum(s.stats["attacked_count"] for s in services)

        # 今日捕获
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_captures = sum(1 for c in captures if c.timestamp and c.timestamp >= today)

        # 威胁级别分布
        threat_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for c in captures:
            if c.threat_level in threat_dist:
                threat_dist[c.threat_level] += 1

        # Top攻击IP
        ip_counts = {}
        for c in captures:
            ip_counts[c.client_ip] = ip_counts.get(c.client_ip, 0) + 1
        top_attackers = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # 按服务类型统计
        service_counts = {}
        for c in captures:
            service_counts[c.service_name] = service_counts.get(c.service_name, 0) + 1

        return {
            "total_services": len(services),
            "running_services": running_services,
            "total_captures": total_captures,
            "total_attacks": total_attacks,
            "today_captures": today_captures,
            "threat_distribution": threat_dist,
            "top_attackers": [{"ip": ip, "count": count} for ip, count in top_attackers],
            "service_counts": service_counts,
            "services": [s.to_dict() for s in services],
        }


# ============================================================
# 单例管理
# ============================================================

_honeypot_manager: Optional[HoneypotManager] = None
_manager_lock = threading.Lock()


def get_honeypot_manager() -> HoneypotManager:
    """获取蜜罐管理器单例"""
    global _honeypot_manager
    with _manager_lock:
        if _honeypot_manager is None:
            _honeypot_manager = HoneypotManager()
    return _honeypot_manager
