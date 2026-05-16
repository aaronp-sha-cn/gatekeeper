# -*- coding: utf-8 -*-
"""
协议病毒扫描代理
实现 HTTP/FTP/SMTP/SMB 流量拦截和病毒扫描
"""

import os
import subprocess
import threading
import time
import tempfile
import socket
import select
import logging
import re
from typing import Dict, Optional, Tuple
from security.gateway_antivirus import get_gateway_antivirus

logger = logging.getLogger(__name__)


class ProtocolScannerBase:
    """协议扫描器基类"""

    def __init__(self, protocol: str, ports: list):
        self.protocol = protocol
        self.ports = ports
        self.enabled = False
        self.running = False
        self.thread = None
        self.engine = get_gateway_antivirus()

    def start(self):
        """启动扫描器"""
        if self.running:
            return
        self.enabled = True
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("%s 病毒扫描器已启动 (端口: %s)", self.protocol.upper(), self.ports)

    def stop(self):
        """停止扫描器"""
        self.enabled = False
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("%s 病毒扫描器已停止", self.protocol.upper())

    def _run(self):
        """运行循环（子类实现）"""
        pass

    def scan_file(self, file_path: str, metadata: dict) -> dict:
        """扫描文件"""
        metadata["protocol"] = self.protocol
        return self.engine.scan_file(file_path, metadata)


class HTTPScanner(ProtocolScannerBase):
    """HTTP 代理病毒扫描器

    使用 Squid + c-icap 架构实现 HTTP 流量病毒扫描
    """

    def __init__(self):
        super().__init__("http", [80, 443, 8080, 3128])
        self.squid_config = "/etc/squid/squid.conf"
        self.icap_config = "/etc/c-icap/c-icap.conf"

    def configure(self, listen_port: int = 3128, upstream_proxy: str = None) -> dict:
        """配置 Squid 代理"""
        config = f"""
# GateKeeper HTTP 代理配置
http_port {listen_port} intercept
icp_port 0

# ICAP 病毒扫描
icap_enable on
icap_service service_av reqmod_precache icap://127.0.0.1:1344/clamav
adaptation_access service_av allow all

# 缓存设置
cache_dir ufs /var/spool/squid 100 16 256
cache_mem 256 MB
maximum_object_size 50 MB

# 日志
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log

# ACL
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
http_access allow localnet
http_access deny all
"""
        try:
            os.makedirs(os.path.dirname(self.squid_config), exist_ok=True)
            with open(self.squid_config, "w") as f:
                f.write(config)
            logger.info("Squid 配置已生成: %s", self.squid_config)
            return {"status": "ok", "config_file": self.squid_config}
        except Exception as e:
            logger.error("配置 Squid 失败: %s", e)
            return {"status": "error", "message": str(e)}

    def configure_icap(self) -> dict:
        """配置 c-icap 服务"""
        config = """
# GateKeeper ICAP 服务配置
Port 1344
User proxy
Group proxy
PidFile /var/run/c-icap.pid

# ClamAV 模块
Service clamav /usr/lib/c-icap/clamav_mod.so
ServiceAlias avscan clamav?allow204=on&sizelimit=off&mode=simple

# 日志
ServerLog /var/log/c-icap/server.log
AccessLog /var/log/c-icap/access.log

# 超时设置
Timeout 300
MaxConnections 1024
"""
        try:
            os.makedirs(os.path.dirname(self.icap_config), exist_ok=True)
            with open(self.icap_config, "w") as f:
                f.write(config)
            logger.info("c-icap 配置已生成: %s", self.icap_config)
            return {"status": "ok", "config_file": self.icap_config}
        except Exception as e:
            logger.error("配置 c-icap 失败: %s", e)
            return {"status": "error", "message": str(e)}

    def start_services(self) -> dict:
        """启动 Squid 和 c-icap 服务"""
        results = {}

        # 启动 c-icap
        try:
            subprocess.run(["mkdir", "-p", "/var/log/c-icap"], check=True, capture_output=True, timeout=10)
            subprocess.run(["c-icap", "-f", self.icap_config], check=True, capture_output=True, timeout=10)
            results["icap"] = "started"
        except Exception as e:
            results["icap"] = f"error: {e}"

        # 启动 Squid
        try:
            subprocess.run(["squid", "-z"], capture_output=True, timeout=30)  # 初始化缓存
            subprocess.run(["squid", "-f", self.squid_config], check=True, capture_output=True, timeout=30)
            results["squid"] = "started"
        except Exception as e:
            results["squid"] = f"error: {e}"

        self.enabled = all("started" in v for v in results.values())
        return results

    def stop_services(self) -> dict:
        """停止服务"""
        results = {}
        try:
            subprocess.run(["squid", "-k", "shutdown"], capture_output=True, timeout=30)
            results["squid"] = "stopped"
        except Exception as e:
            results["squid"] = f"error: {e}"

        try:
            subprocess.run(["pkill", "c-icap"], capture_output=True, timeout=10)
            results["icap"] = "stopped"
        except Exception as e:
            results["icap"] = f"error: {e}"

        self.enabled = False
        return results

    def get_status(self) -> dict:
        """获取服务状态"""
        status = {"enabled": self.enabled}

        # 检查 Squid
        try:
            result = subprocess.run(["pgrep", "-x", "squid"], capture_output=True, timeout=10)
            status["squid_running"] = result.returncode == 0
        except Exception:
            status["squid_running"] = False

        # 检查 c-icap
        try:
            result = subprocess.run(["pgrep", "-x", "c-icap"], capture_output=True, timeout=10)
            status["icap_running"] = result.returncode == 0
        except Exception:
            status["icap_running"] = False

        return status


class FTPScanner(ProtocolScannerBase):
    """FTP 病毒扫描器

    使用 ProFTPD + ClamAV 模块实现 FTP 流量病毒扫描
    """

    def __init__(self):
        super().__init__("ftp", [20, 21])
        self.proftpd_config = "/etc/proftpd/proftpd.conf"

    def configure(self, listen_port: int = 21, passive_ports: tuple = (50000, 51000)) -> dict:
        """配置 ProFTPD"""
        config = f"""
# GateKeeper FTP 服务器配置
ServerName "GateKeeper FTP"
ServerType standalone
Port {listen_port}
MaxInstances 30
User nobody
Group nogroup

# 被动模式端口
PassivePorts {passive_ports[0]} {passive_ports[1]}

# ClamAV 病毒扫描模块
<IfModule mod_clamav.c>
    ClamAV on
    ClamServer 127.0.0.1
    ClamPort 3310
</IfModule>

# 上传扫描
<Directory /*>
    <Limit WRITE>
        AllowAll
    </Limit>
    ClamAV on
</Directory>

# 日志
TransferLog /var/log/proftpd/transfer.log
SystemLog /var/log/proftpd/system.log

# 禁止匿名
<Anonymous ~ftp>
    <Limit LOGIN>
        DenyAll
    </Limit>
</Anonymous>
"""
        try:
            os.makedirs(os.path.dirname(self.proftpd_config), exist_ok=True)
            with open(self.proftpd_config, "w") as f:
                f.write(config)
            logger.info("ProFTPD 配置已生成: %s", self.proftpd_config)
            return {"status": "ok", "config_file": self.proftpd_config}
        except Exception as e:
            logger.error("配置 ProFTPD 失败: %s", e)
            return {"status": "error", "message": str(e)}

    def start_services(self) -> dict:
        """启动 ProFTPD 和 ClamAV 服务"""
        results = {}

        # 启动 ClamAV daemon
        try:
            subprocess.run(["clamd"], capture_output=True, timeout=10)
            results["clamd"] = "started"
        except Exception as e:
            results["clamd"] = f"error: {e}"

        # 启动 ProFTPD
        try:
            subprocess.run(["proftpd", "-c", self.proftpd_config], check=True, capture_output=True, timeout=10)
            results["proftpd"] = "started"
        except Exception as e:
            results["proftpd"] = f"error: {e}"

        self.enabled = all("started" in v for v in results.values())
        return results

    def stop_services(self) -> dict:
        """停止服务"""
        results = {}
        try:
            subprocess.run(["pkill", "proftpd"], capture_output=True, timeout=10)
            results["proftpd"] = "stopped"
        except Exception as e:
            results["proftpd"] = f"error: {e}"

        self.enabled = False
        return results

    def get_status(self) -> dict:
        """获取服务状态"""
        status = {"enabled": self.enabled}

        try:
            result = subprocess.run(["pgrep", "-x", "proftpd"], capture_output=True, timeout=10)
            status["proftpd_running"] = result.returncode == 0
        except Exception:
            status["proftpd_running"] = False

        try:
            result = subprocess.run(["pgrep", "-x", "clamd"], capture_output=True, timeout=10)
            status["clamd_running"] = result.returncode == 0
        except Exception:
            status["clamd_running"] = False

        return status


class SMTPScanner(ProtocolScannerBase):
    """SMTP 邮件病毒扫描器

    使用 Postfix + amavisd-new + ClamAV 实现邮件病毒扫描
    """

    def __init__(self):
        super().__init__("smtp", [25, 587, 465])
        self.postfix_config = "/etc/postfix/main.cf"
        self.amavis_config = "/etc/amavis/conf.d/50-user"

    def configure_postfix(self, domain: str = "gatekeeper.local", hostname: str = "mail") -> dict:
        """配置 Postfix"""
        config = f"""
# GateKeeper Postfix 配置
myhostname = {hostname}.{domain}
mydomain = {domain}
myorigin = $mydomain
inet_interfaces = all

# amavisd-new 集成
content_filter = amavis:[127.0.0.1]:10024

# 接收域
mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain

# SMTP 设置
smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination

# 日志
maillog_file = /var/log/mail.log
"""
        try:
            os.makedirs(os.path.dirname(self.postfix_config), exist_ok=True)
            with open(self.postfix_config, "w") as f:
                f.write(config)
            logger.info("Postfix 配置已生成: %s", self.postfix_config)
            return {"status": "ok", "config_file": self.postfix_config}
        except Exception as e:
            logger.error("配置 Postfix 失败: %s", e)
            return {"status": "error", "message": str(e)}

    def configure_amavis(self) -> dict:
        """配置 amavisd-new"""
        config = """
# GateKeeper amavisd-new 配置
$mydomain = 'gatekeeper.local';
$myhostname = 'mail.gatekeeper.local';

# 监听地址
$inet_socket_port = [10024, 10026];
$inet_socket_bind = '127.0.0.1';

# ClamAV 配置
@av_scanners = (
    ['ClamAV-clamd',
     \&ask_daemon, ["CONTSCAN {}\n", "127.0.0.1:3310"],
     qr/\bOK$/, qr/\bFOUND$/,
     qr/^.*?: (?!Infected Archive)(.*) FOUND$/ ],
);

# 病毒处理
$final_virus_destiny = D_DISCARD;  # 丢弃带病毒邮件
$virus_admin = "admin\@$mydomain";
$virus_quarantine_to = 'virus-quarantine';

# 垃圾邮件处理
$final_spam_destiny = D_PASS;
$sa_tag_level_deflt = 2.0;
$sa_kill_level_deflt = 6.0;

# 日志
$log_level = 1;
$DO_SYSLOG = 0;
$LOGFILE = '/var/log/amavis/amavis.log';
"""
        try:
            os.makedirs(os.path.dirname(self.amavis_config), exist_ok=True)
            with open(self.amavis_config, "w") as f:
                f.write(config)
            logger.info("amavisd-new 配置已生成: %s", self.amavis_config)
            return {"status": "ok", "config_file": self.amavis_config}
        except Exception as e:
            logger.error("配置 amavisd-new 失败: %s", e)
            return {"status": "error", "message": str(e)}

    def start_services(self) -> dict:
        """启动服务"""
        results = {}

        # 启动 ClamAV daemon
        try:
            subprocess.run(["clamd"], capture_output=True, timeout=10)
            results["clamd"] = "started"
        except Exception as e:
            results["clamd"] = f"error: {e}"

        # 启动 amavisd-new
        try:
            subprocess.run(["amavisd-new", "start"], capture_output=True, timeout=10)
            results["amavis"] = "started"
        except Exception as e:
            results["amavis"] = f"error: {e}"

        # 启动 Postfix
        try:
            subprocess.run(["postfix", "start"], capture_output=True, timeout=10)
            results["postfix"] = "started"
        except Exception as e:
            results["postfix"] = f"error: {e}"

        self.enabled = all("started" in v for v in results.values())
        return results

    def stop_services(self) -> dict:
        """停止服务"""
        results = {}
        try:
            subprocess.run(["postfix", "stop"], capture_output=True, timeout=10)
            results["postfix"] = "stopped"
        except Exception as e:
            results["postfix"] = f"error: {e}"

        try:
            subprocess.run(["amavisd-new", "stop"], capture_output=True, timeout=10)
            results["amavis"] = "stopped"
        except Exception as e:
            results["amavis"] = f"error: {e}"

        self.enabled = False
        return results

    def get_status(self) -> dict:
        """获取服务状态"""
        status = {"enabled": self.enabled}

        try:
            result = subprocess.run(["pgrep", "-x", "master"], capture_output=True, timeout=10)
            status["postfix_running"] = result.returncode == 0
        except Exception:
            status["postfix_running"] = False

        try:
            result = subprocess.run(["pgrep", "-f", "amavisd"], capture_output=True, timeout=10)
            status["amavis_running"] = result.returncode == 0
        except Exception:
            status["amavis_running"] = False

        return status


class SMBScanner(ProtocolScannerBase):
    """SMB 文件共享病毒扫描器

    使用 Samba + ClamAV (VFS 模块) 实现 SMB 流量病毒扫描
    """

    def __init__(self):
        super().__init__("smb", [139, 445])
        self.smb_config = "/etc/samba/smb.conf"

    def configure(self, workgroup: str = "WORKGROUP", share_name: str = "shared",
                  share_path: str = "/srv/samba/shared") -> dict:
        """配置 Samba"""
        os.makedirs(share_path, exist_ok=True)

        config = f"""
[global]
   workgroup = {workgroup}
   server string = GateKeeper SMB Server
   security = user
   map to guest = Bad User

   # ClamAV VFS 模块
   vfs objects = clamav
   clamav:socket = /var/run/clamav/clamd.ctl
   clamav:scan on open = yes
   clamav:scan on close = yes
   clamav:max file size = 52428800
   clamav:infected file action = delete

   # 日志
   log file = /var/log/samba/log.%m
   log level = 1

[{share_name}]
   path = {share_path}
   browseable = yes
   writable = yes
   guest ok = yes
   read only = no
   create mask = 0644
   directory mask = 0755

   # 病毒扫描
   vfs objects = clamav
   clamav:scan on open = yes
   clamav:scan on close = yes
"""
        try:
            os.makedirs(os.path.dirname(self.smb_config), exist_ok=True)
            with open(self.smb_config, "w") as f:
                f.write(config)
            logger.info("Samba 配置已生成: %s", self.smb_config)
            return {"status": "ok", "config_file": self.smb_config, "share_path": share_path}
        except Exception as e:
            logger.error("配置 Samba 失败: %s", e)
            return {"status": "error", "message": str(e)}

    def start_services(self) -> dict:
        """启动服务"""
        results = {}

        # 启动 ClamAV daemon
        try:
            subprocess.run(["clamd"], capture_output=True, timeout=10)
            results["clamd"] = "started"
        except Exception as e:
            results["clamd"] = f"error: {e}"

        # 启动 smbd
        try:
            subprocess.run(["smbd"], capture_output=True, timeout=10)
            results["smbd"] = "started"
        except Exception as e:
            results["smbd"] = f"error: {e}"

        # 启动 nmbd
        try:
            subprocess.run(["nmbd"], capture_output=True, timeout=10)
            results["nmbd"] = "started"
        except Exception as e:
            results["nmbd"] = f"error: {e}"

        self.enabled = all("started" in v for v in results.values())
        return results

    def stop_services(self) -> dict:
        """停止服务"""
        results = {}
        try:
            subprocess.run(["pkill", "smbd"], capture_output=True, timeout=10)
            results["smbd"] = "stopped"
        except Exception as e:
            results["smbd"] = f"error: {e}"

        try:
            subprocess.run(["pkill", "nmbd"], capture_output=True, timeout=10)
            results["nmbd"] = "stopped"
        except Exception as e:
            results["nmbd"] = f"error: {e}"

        self.enabled = False
        return results

    def get_status(self) -> dict:
        """获取服务状态"""
        status = {"enabled": self.enabled}

        try:
            result = subprocess.run(["pgrep", "-x", "smbd"], capture_output=True, timeout=10)
            status["smbd_running"] = result.returncode == 0
        except Exception:
            status["smbd_running"] = False

        try:
            result = subprocess.run(["pgrep", "-x", "nmbd"], capture_output=True, timeout=10)
            status["nmbd_running"] = result.returncode == 0
        except Exception:
            status["nmbd_running"] = False

        return status


# 扫描器实例
_http_scanner = None
_ftp_scanner = None
_smtp_scanner = None
_smb_scanner = None


def get_http_scanner() -> HTTPScanner:
    global _http_scanner
    if _http_scanner is None:
        _http_scanner = HTTPScanner()
    return _http_scanner


def get_ftp_scanner() -> FTPScanner:
    global _ftp_scanner
    if _ftp_scanner is None:
        _ftp_scanner = FTPScanner()
    return _ftp_scanner


def get_smtp_scanner() -> SMTPScanner:
    global _smtp_scanner
    if _smtp_scanner is None:
        _smtp_scanner = SMTPScanner()
    return _smtp_scanner


def get_smb_scanner() -> SMBScanner:
    global _smb_scanner
    if _smb_scanner is None:
        _smb_scanner = SMBScanner()
    return _smb_scanner
