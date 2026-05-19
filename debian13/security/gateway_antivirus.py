# -*- coding: utf-8 -*-
"""
网关级病毒扫描模块
支持 HTTP/FTP/SMTP/SMB 流量病毒扫描
"""

import os
import subprocess
import threading
import time
import tempfile
import shutil
import logging
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
from core.database import db_manager
from core.models import AuditLog
from config.database import Base
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.sql import func

logger = logging.getLogger(__name__)


class GatewayVirusLog(Base):
    """网关病毒扫描日志表"""
    __tablename__ = 'gateway_virus_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, server_default=func.now())
    protocol = Column(String(20))  # http, ftp, smtp, smb
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    file_name = Column(String(255))
    file_size = Column(Integer)
    virus_name = Column(String(255))
    action = Column(String(20))  # blocked, passed, error
    scanner = Column(String(50))  # clamav, builtin
    details = Column(Text)


class GatewayAntivirusEngine:
    """网关级病毒扫描引擎"""

    def __init__(self):
        self._config = {
            "enabled": True,
            "block_infected": True,
            "max_file_size_mb": 50,
            "scan_protocols": {
                "http": {"enabled": True, "ports": [80, 443, 8080]},
                "ftp": {"enabled": True, "ports": [20, 21]},
                "smtp": {"enabled": True, "ports": [25, 587, 465]},
                "smb": {"enabled": True, "ports": [139, 445]},
            },
            "quarantine_dir": "/opt/gatekeeper/quarantine",
            "log_clean_files": False,
        }
        self._clamav_available = self._check_clamav()
        self._stats = {
            "total_scanned": 0,
            "infected_found": 0,
            "blocked": 0,
            "errors": 0,
            "by_protocol": {"http": 0, "ftp": 0, "smtp": 0, "smb": 0},
        }
        self._lock = threading.Lock()
        self._init_database()
        self._init_quarantine()
        logger.info("网关病毒扫描引擎初始化完成 (ClamAV: %s)", self._clamav_available)

    def _check_clamav(self) -> bool:
        """检查 ClamAV 是否可用"""
        try:
            result = subprocess.run(
                ["which", "clamscan"],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _init_database(self):
        """初始化数据库表"""
        try:
            Base.metadata.create_all(bind=db_manager._engine)
        except Exception as e:
            logger.error("初始化病毒日志表失败: %s", e)

    def _init_quarantine(self):
        """初始化隔离目录"""
        qdir = self._config["quarantine_dir"]
        if not os.path.exists(qdir):
            try:
                os.makedirs(qdir, mode=0o700)
                logger.info("创建隔离目录: %s", qdir)
            except Exception as e:
                logger.error("创建隔离目录失败: %s", e)

    def get_config(self) -> Dict:
        """获取当前配置"""
        return {
            "enabled": self._config["enabled"],
            "block_infected": self._config["block_infected"],
            "max_file_size_mb": self._config["max_file_size_mb"],
            "scan_protocols": self._config["scan_protocols"],
            "clamav_available": self._clamav_available,
            "quarantine_dir": self._config["quarantine_dir"],
        }

    def update_config(self, config: Dict) -> Dict:
        """更新配置"""
        if "enabled" in config:
            self._config["enabled"] = config["enabled"]
        if "block_infected" in config:
            self._config["block_infected"] = config["block_infected"]
        if "max_file_size_mb" in config:
            self._config["max_file_size_mb"] = config["max_file_size_mb"]
        if "scan_protocols" in config:
            for proto, settings in config["scan_protocols"].items():
                if proto in self._config["scan_protocols"]:
                    self._config["scan_protocols"][proto].update(settings)
        logger.info("网关病毒扫描配置已更新")
        return {"status": "ok", "config": self.get_config()}

    def get_stats(self) -> Dict:
        """获取统计数据"""
        with self._lock:
            return {
                "total_scanned": self._stats["total_scanned"],
                "infected_found": self._stats["infected_found"],
                "blocked": self._stats["blocked"],
                "errors": self._stats["errors"],
                "by_protocol": dict(self._stats["by_protocol"]),
                "clamav_available": self._clamav_available,
            }

    def scan_file(self, file_path: str, metadata: Dict) -> Dict:
        """
        扫描文件
        :param file_path: 文件路径
        :param metadata: 元数据 (protocol, src_ip, dst_ip, file_name 等)
        :return: 扫描结果
        """
        if not self._config["enabled"]:
            return {"status": "disabled", "action": "pass"}

        result = {
            "file_path": file_path,
            "file_name": metadata.get("file_name", os.path.basename(file_path)),
            "protocol": metadata.get("protocol", "unknown"),
            "src_ip": metadata.get("src_ip", ""),
            "dst_ip": metadata.get("dst_ip", ""),
            "clean": True,
            "threats": [],
            "action": "pass",
            "scanner": "none",
        }

        try:
            file_size = os.path.getsize(file_path)
            max_size = self._config["max_file_size_mb"] * 1024 * 1024

            if file_size > max_size:
                result["status"] = "skipped"
                result["reason"] = f"文件超过大小限制 ({self._config['max_file_size_mb']}MB)"
                return result

            # ClamAV 扫描
            if self._clamav_available:
                clam_result = self._scan_clamav(file_path)
                if clam_result["infected"]:
                    result["clean"] = False
                    result["threats"].extend(clam_result["threats"])
                    result["scanner"] = "clamav"

            # 内置特征扫描
            builtin_result = self._scan_builtin(file_path)
            if builtin_result["infected"]:
                result["clean"] = False
                result["threats"].extend(builtin_result["threats"])
                if result["scanner"] == "none":
                    result["scanner"] = "builtin"

            # 更新统计
            with self._lock:
                self._stats["total_scanned"] += 1
                proto = result["protocol"]
                if proto in self._stats["by_protocol"]:
                    self._stats["by_protocol"][proto] += 1

            # 处理感染文件
            if not result["clean"]:
                with self._lock:
                    self._stats["infected_found"] += 1

                if self._config["block_infected"]:
                    result["action"] = "block"
                    with self._lock:
                        self._stats["blocked"] += 1
                    # 隔离文件
                    self._quarantine_file(file_path, result)
                else:
                    result["action"] = "pass"

                # 记录日志
                self._log_virus(result)

            result["status"] = "completed"

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            with self._lock:
                self._stats["errors"] += 1
            logger.error("扫描文件出错: %s", e)

        return result

    def _scan_clamav(self, file_path: str) -> Dict:
        """使用 ClamAV 扫描"""
        result = {"infected": False, "threats": []}
        try:
            proc = subprocess.run(
                ["clamscan", "--no-summary", "--infected", file_path],
                capture_output=True, text=True, timeout=120
            )
            for line in (proc.stdout + proc.stderr).strip().splitlines():
                if "FOUND" in line:
                    match = re.search(r'(.+):\s*(\S+)\s+FOUND', line)
                    if match:
                        virus_name = match.group(2)
                        result["infected"] = True
                        result["threats"].append({
                            "name": virus_name,
                            "type": "virus",
                            "scanner": "clamav",
                        })
        except subprocess.TimeoutExpired:
            logger.warning("ClamAV 扫描超时: %s", file_path)
        except Exception as e:
            logger.error("ClamAV 扫描出错: %s", e)
        return result

    def _scan_builtin(self, file_path: str) -> Dict:
        """内置特征扫描"""
        result = {"infected": False, "threats": []}
        signatures = self._get_builtin_signatures()

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            for sig in signatures:
                if re.search(sig["pattern"], content):
                    result["infected"] = True
                    result["threats"].append({
                        "name": sig["name"],
                        "type": sig.get("type", "malware"),
                        "severity": sig.get("severity", "high"),
                        "scanner": "builtin",
                    })
        except Exception as e:
            logger.error("内置扫描出错: %s", e)

        return result

    def _get_builtin_signatures(self) -> List[Dict]:
        """获取内置病毒特征"""
        return [
            {"name": "EICAR-TEST", "pattern": rb"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR",
             "type": "test", "severity": "low"},
            {"name": "WannaCry", "pattern": rb"WANNA.*CRY|wncry@163\.com",
             "type": "ransomware", "severity": "critical"},
            {"name": "Locky", "pattern": rb"\.locky|locky_decrypt",
             "type": "ransomware", "severity": "critical"},
            {"name": "Emotet", "pattern": rb"Emotet|EmotetLoader",
             "type": "trojan", "severity": "critical"},
            {"name": "TrickBot", "pattern": rb"TrickBot|TrickLoader",
             "type": "trojan", "severity": "critical"},
            {"name": "QakBot", "pattern": rb"QakBot|Qbot",
             "type": "trojan", "severity": "high"},
            {"name": "Macro-VBA-AutoExec", "pattern": rb"AutoOpen|AutoExec|Document_Open",
             "type": "macro", "severity": "high"},
            {"name": "PowerShell-Obfuscated", "pattern": rb"powershell.*-enc|powershell.*-hidden",
             "type": "script", "severity": "high"},
        ]

    def _quarantine_file(self, file_path: str, scan_result: Dict):
        """隔离感染文件"""
        try:
            qdir = self._config["quarantine_dir"]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            orig_name = os.path.basename(file_path)
            qname = f"{timestamp}_{orig_name}"
            qpath = os.path.join(qdir, qname)

            shutil.move(file_path, qpath)
            scan_result["quarantine_path"] = qpath
            logger.warning("文件已隔离: %s -> %s", file_path, qpath)

        except Exception as e:
            logger.error("隔离文件失败: %s", e)

    def _log_virus(self, result: Dict):
        """记录病毒日志到数据库"""
        try:
            with db_manager.get_session() as session:
                log = GatewayVirusLog(
                    protocol=result.get("protocol", "unknown"),
                    src_ip=result.get("src_ip", ""),
                    dst_ip=result.get("dst_ip", ""),
                    file_name=result.get("file_name", ""),
                    file_size=0,
                    virus_name=", ".join([t["name"] for t in result.get("threats", [])]),
                    action=result.get("action", "unknown"),
                    scanner=result.get("scanner", "unknown"),
                    details=str(result),
                )
                session.add(log)
        except Exception as e:
            logger.error("记录病毒日志失败: %s", e)

    def get_virus_logs(self, limit: int = 100, protocol: str = None) -> List[Dict]:
        """获取病毒日志"""
        try:
            with db_manager.get_session() as session:
                query = session.query(GatewayVirusLog)
                if protocol:
                    query = query.filter(GatewayVirusLog.protocol == protocol)
                logs = query.order_by(GatewayVirusLog.timestamp.desc()).limit(limit).all()
                return [{
                    "id": log.id,
                    "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                    "protocol": log.protocol,
                    "src_ip": log.src_ip,
                    "dst_ip": log.dst_ip,
                    "file_name": log.file_name,
                    "virus_name": log.virus_name,
                    "action": log.action,
                    "scanner": log.scanner,
                } for log in logs]
        except Exception as e:
            logger.error("获取病毒日志失败: %s", e)
            return []

    def update_virus_database(self) -> Dict:
        """更新病毒库"""
        result = {"clamav_updated": False, "message": ""}

        if self._clamav_available:
            try:
                freshclam_conf = "/etc/clamav/freshclam.conf"
                if not os.path.exists(freshclam_conf):
                    os.makedirs(os.path.dirname(freshclam_conf), exist_ok=True)
                    with open(freshclam_conf, 'w') as f:
                        f.write("DatabaseMirror database.clamav.net\n")
                        f.write("DatabaseMirror db.local.clamav.net\n")
                        f.write("ScriptedUpdates yes\n")
                        f.write("NotifyClamd /etc/clamav/clamd.conf\n")
                        f.write("CompressLocalDatabase yes\n")
                proc = subprocess.run(
                    ["freshclam", "--config-file=" + freshclam_conf],
                    capture_output=True, text=True, timeout=120
                )
                result["clamav_updated"] = proc.returncode == 0
                result["message"] = proc.stdout.strip() or proc.stderr.strip()
                logger.info("病毒库更新: %s", result["message"])
            except Exception as e:
                result["message"] = str(e)
                logger.error("病毒库更新失败: %s", e)
        else:
            result["message"] = "ClamAV 未安装"

        return result

    def clear_stats(self) -> Dict:
        """清除统计"""
        with self._lock:
            self._stats = {
                "total_scanned": 0,
                "infected_found": 0,
                "blocked": 0,
                "errors": 0,
                "by_protocol": {"http": 0, "ftp": 0, "smtp": 0, "smb": 0},
            }
        return {"status": "ok"}


# 单例
_engine = None
_engine_lock = threading.Lock()


def get_gateway_antivirus() -> GatewayAntivirusEngine:
    """获取网关病毒扫描引擎单例"""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = GatewayAntivirusEngine()
    return _engine
