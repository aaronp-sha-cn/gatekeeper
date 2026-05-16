# -*- coding: utf-8 -*-
"""
GateKeeper - Sandbox 沙箱恶意软件分析引擎
集成 Cuckoo Sandbox 实现未知恶意软件的动态行为分析
"""

import os
import re
import json
import time
import uuid
import struct
import logging
import hashlib
import threading
import subprocess
import tempfile
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import deque

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from config.logging_config import get_logger

logger = get_logger("sandbox")


# ============================================================
# 数据类定义
# ============================================================

class TaskStatus(str, Enum):
    """沙箱任务状态枚举"""
    PENDING = "pending"          # 等待中
    RUNNING = "running"          # 分析中
    COMPLETED = "completed"      # 已完成
    REPORTED = "reported"        # 已生成报告
    FAILED = "failed"            # 失败
    DELETED = "deleted"          # 已删除


class RiskLevel(str, Enum):
    """风险等级枚举"""
    CLEAN = "clean"              # 安全
    LOW = "low"                  # 低风险
    MEDIUM = "medium"            # 中风险
    HIGH = "high"                # 高风险
    CRITICAL = "critical"        # 极高风险


@dataclass
class SandboxTask:
    """沙箱分析任务数据类"""
    task_id: str                          # 任务唯一ID
    target_type: str = "file"             # 目标类型: file / url
    target_name: str = ""                 # 文件名或URL
    target_path: str = ""                 # 文件本地路径
    target_url: str = ""                  # URL（当target_type=url时）
    file_size: int = 0                    # 文件大小（字节）
    file_md5: str = ""                    # 文件MD5哈希
    file_sha256: str = ""                 # 文件SHA256哈希
    status: str = TaskStatus.PENDING      # 任务状态
    cuckoo_task_id: Optional[int] = None  # Cuckoo沙箱返回的任务ID
    priority: int = 1                     # 优先级 (1-5, 1最高)
    options: Dict = field(default_factory=dict)  # 分析选项
    submitted_at: Optional[str] = None    # 提交时间
    started_at: Optional[str] = None      # 开始分析时间
    completed_at: Optional[str] = None    # 完成时间
    error_message: str = ""               # 错误信息
    backend: str = "cuckoo"              # 分析后端: cuckoo / local

    def to_dict(self) -> dict:
        """转换为字典"""
        return asdict(self)


@dataclass
class SandboxReport:
    """沙箱分析报告数据类"""
    task_id: str = ""                     # 关联任务ID
    target_name: str = ""                 # 文件名或URL
    target_type: str = "file"             # 目标类型
    backend: str = "cuckoo"              # 分析后端

    # 文件信息
    file_md5: str = ""                    # MD5哈希
    file_sha256: str = ""                 # SHA256哈希
    file_sha1: str = ""                   # SHA1哈希
    file_size: int = 0                    # 文件大小
    file_type: str = ""                   # 文件类型（MIME）
    pe_info: Dict = field(default_factory=dict)  # PE文件信息

    # 行为摘要
    behavior_summary: str = ""            # 行为摘要描述
    risk_score: float = 0.0               # 风险评分 (0-100)
    risk_level: str = RiskLevel.CLEAN     # 风险等级
    malware_family: str = ""              # 恶意软件家族
    malware_type: str = ""                # 恶意软件类型

    # 网络行为
    network_requests: List[Dict] = field(default_factory=list)  # 网络请求列表
    dns_queries: List[Dict] = field(default_factory=list)      # DNS查询列表
    domains_contacted: List[str] = field(default_factory=list)  # 联系的域名
    ips_contacted: List[str] = field(default_factory=list)     # 联系的IP地址
    http_requests: List[Dict] = field(default_factory=list)    # HTTP请求列表

    # 文件系统操作
    files_created: List[str] = field(default_factory=list)     # 创建的文件
    files_deleted: List[str] = field(default_factory=list)     # 删除的文件
    files_modified: List[str] = field(default_factory=list)    # 修改的文件
    files_read: List[str] = field(default_factory=list)        # 读取的文件
    dropped_files: List[Dict] = field(default_factory=list)    # 释放的文件

    # 注册表操作
    registry_keys_set: List[Dict] = field(default_factory=list)   # 设置的注册表键
    registry_keys_deleted: List[Dict] = field(default_factory=list)  # 删除的注册表键

    # 进程信息
    processes: List[Dict] = field(default_factory=list)        # 进程树信息
    process_tree: str = ""               # 进程树文本表示

    # IOC 指标（威胁情报指标）
    ioc_ips: List[str] = field(default_factory=list)           # 恶意IP
    ioc_domains: List[str] = field(default_factory=list)       # 恶意域名
    ioc_urls: List[str] = field(default_factory=list)          # 恶意URL
    ioc_mutexes: List[str] = field(default_factory=list)       # 互斥体名称
    ioc_signatures: List[Dict] = field(default_factory=list)   # YARA签名匹配

    # 签名检测结果
    signatures: List[Dict] = field(default_factory=list)       # 行为签名列表

    # 分析元数据
    analysis_duration: float = 0.0        # 分析时长（秒）
    cuckoo_version: str = ""              # Cuckoo版本
    machine_type: str = ""                # 分析机类型
    os_name: str = ""                     # 操作系统名称
    start_time: Optional[str] = None      # 分析开始时间
    end_time: Optional[str] = None        # 分析结束时间

    # ClamAV 扫描结果
    clamav_result: str = ""               # ClamAV扫描结果
    clamav_threat: str = ""               # ClamAV检测到的威胁名称

    def to_dict(self) -> dict:
        """转换为字典"""
        return asdict(self)


# ============================================================
# 单例实例管理
# ============================================================

_analyzer_instance = None
_analyzer_lock = threading.Lock()


def get_sandbox_analyzer():
    """获取沙箱分析器单例实例"""
    global _analyzer_instance
    if _analyzer_instance is None:
        with _analyzer_lock:
            if _analyzer_instance is None:
                _analyzer_instance = SandboxAnalyzer()
    return _analyzer_instance


# ============================================================
# 沙箱分析引擎
# ============================================================

class SandboxAnalyzer:
    """
    沙箱恶意软件分析引擎

    集成 Cuckoo Sandbox 实现未知恶意软件的动态行为分析，
    当 Cuckoo 不可用时自动切换到本地模拟模式。

    功能:
    - 文件/URL 提交到 Cuckoo 沙箱进行动态分析
    - ClamAV 快速预扫描
    - 本地模拟分析（PE文件头检查、字符串提取、API模式检测）
    - 异步任务管理
    - 分析报告生成
    """

    def __init__(self):
        """初始化沙箱分析引擎"""
        # ---- Cuckoo API 配置 ----
        self.cuckoo_api_url = "http://127.0.0.1:8090/api"
        self.cuckoo_timeout = 300           # Cuckoo API 请求超时（秒）
        self.analysis_timeout = 300         # 单次分析最大时长（秒）
        self.max_concurrent_tasks = 5       # 最大并发分析任务数
        self.auto_start_analysis = True     # 是否自动开始分析

        # ---- ClamAV 配置 ----
        self.clamav_enabled = True          # 是否启用 ClamAV 预扫描
        self.clamav_path = "clamscan"       # clamscan 可执行文件路径

        # ---- 本地模拟配置 ----
        self.local_mode = False             # 是否强制使用本地模拟模式
        self.max_file_size = 100 * 1024 * 1024  # 最大文件大小 100MB
        self.upload_dir = "/opt/gatekeeper/sandbox/uploads"  # 上传文件目录
        self.report_dir = "/opt/gatekeeper/sandbox/reports"  # 报告存储目录

        # ---- 内部状态 ----
        self._tasks: Dict[str, SandboxTask] = {}   # 任务字典 {task_id: SandboxTask}
        self._reports: Dict[str, SandboxReport] = {}  # 报告字典 {task_id: SandboxReport}
        self._task_queue: deque = deque()           # 待处理任务队列
        self._running_tasks: Dict[str, threading.Thread] = {}  # 运行中的任务线程
        self._lock = threading.Lock()               # 线程锁
        self._stats = {
            "total_tasks": 0,
            "malicious_tasks": 0,
            "suspicious_tasks": 0,
            "clean_tasks": 0,
            "failed_tasks": 0,
            "total_analysis_time": 0.0,
            "cuckoo_available": False,
            "clamav_available": False,
        }

        # 初始化目录
        self._init_dirs()

        # 检查后端可用性
        self._check_cuckoo_available()
        self._check_clamav_available()

        # 启动任务处理线程
        self._worker_running = True
        self._worker_thread = threading.Thread(
            target=self._task_worker,
            name="sandbox-worker",
            daemon=True
        )
        self._worker_thread.start()

        logger.info("沙箱分析引擎初始化完成 (Cuckoo: {}, ClamAV: {})".format(
            "可用" if self._stats["cuckoo_available"] else "不可用",
            "可用" if self._stats["clamav_available"] else "不可用"
        ))

    def _init_dirs(self):
        """初始化必要的目录"""
        for dir_path in [self.upload_dir, self.report_dir]:
            try:
                os.makedirs(dir_path, exist_ok=True)
            except Exception as e:
                logger.warning("创建目录失败 {}: {}".format(dir_path, e))

    def _check_cuckoo_available(self):
        """检查 Cuckoo Sandbox API 是否可用"""
        if self.local_mode:
            self._stats["cuckoo_available"] = False
            logger.info("强制本地模拟模式，跳过 Cuckoo 可用性检查")
            return
        try:
            if HAS_REQUESTS:
                resp = requests.get(
                    "{}/cuckoo/status".format(self.cuckoo_api_url),
                    timeout=5
                )
                self._stats["cuckoo_available"] = resp.status_code == 200
                if self._stats["cuckoo_available"]:
                    logger.info("Cuckoo Sandbox API 连接成功")
                else:
                    logger.warning("Cuckoo Sandbox API 返回异常状态码: {}".format(resp.status_code))
            else:
                self._stats["cuckoo_available"] = False
                logger.warning("requests 库未安装，无法连接 Cuckoo API")
        except Exception as e:
            self._stats["cuckoo_available"] = False
            logger.warning("Cuckoo Sandbox API 不可用: {}".format(e))

    def _check_clamav_available(self):
        """检查 ClamAV 是否可用"""
        try:
            result = subprocess.run(
                [self.clamav_path, "--version"],
                capture_output=True, text=True, timeout=10
            )
            self._stats["clamav_available"] = result.returncode == 0
            if self._stats["clamav_available"]:
                logger.info("ClamAV 可用: {}".format(result.stdout.strip()))
            else:
                logger.warning("ClamAV 不可用")
        except Exception as e:
            self._stats["clamav_available"] = False
            logger.warning("ClamAV 检查失败: {}".format(e))

    # ============================================================
    # 文件哈希计算
    # ============================================================

    def _calculate_hashes(self, file_path: str) -> Tuple[str, str, str]:
        """
        计算文件的 MD5、SHA1、SHA256 哈希值

        Args:
            file_path: 文件路径

        Returns:
            (md5, sha1, sha256) 元组
        """
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
        except Exception as e:
            logger.error("计算文件哈希失败: {}".format(e))

        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

    # ============================================================
    # ClamAV 快速扫描
    # ============================================================

    def scan_with_clamav(self, file_path: str) -> Dict[str, Any]:
        """
        使用 ClamAV 对文件进行快速扫描

        Args:
            file_path: 待扫描文件路径

        Returns:
            扫描结果字典:
            {
                "scanned": True/False,
                "infected": True/False,
                "threat_name": "威胁名称",
                "details": "详细信息"
            }
        """
        result = {
            "scanned": False,
            "infected": False,
            "threat_name": "",
            "details": ""
        }

        if not self.clamav_enabled or not self._stats["clamav_available"]:
            result["details"] = "ClamAV 未启用或不可用"
            return result

        try:
            logger.info("开始 ClamAV 扫描: {}".format(file_path))
            cmd = [
                self.clamav_path,
                "--no-summary",       # 不输出摘要
                "--infected",         # 只输出感染的文件
                "--detect-pua=yes",   # 检测潜在不需要的应用
                file_path
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            result["scanned"] = True

            if proc.returncode == 1:
                # 发现病毒
                result["infected"] = True
                output = proc.stdout.strip()
                # 解析 ClamAV 输出格式: /path/to/file: ThreatName
                if ":" in output:
                    result["threat_name"] = output.split(":", 1)[1].strip()
                else:
                    result["threat_name"] = output
                result["details"] = output
                logger.warning("ClamAV 检测到威胁: {} - {}".format(file_path, result["threat_name"]))
            elif proc.returncode == 0:
                result["details"] = "文件安全，未检测到威胁"
                logger.info("ClamAV 扫描完成，文件安全: {}".format(file_path))
            else:
                result["details"] = "扫描出错，返回码: {}".format(proc.returncode)
                logger.warning("ClamAV 扫描出错 {}: {}".format(file_path, proc.stderr))

        except subprocess.TimeoutExpired:
            result["details"] = "扫描超时"
            logger.error("ClamAV 扫描超时: {}".format(file_path))
        except Exception as e:
            result["details"] = "扫描异常: {}".format(str(e))
            logger.error("ClamAV 扫描异常: {}".format(e))

        return result

    # ============================================================
    # 文件提交
    # ============================================================

    def submit_file(self, file_path: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        """
        提交文件到沙箱进行分析

        Args:
            file_path: 文件路径
            options: 分析选项，可包含:
                - priority: 优先级 (1-5)
                - timeout: 分析超时时间
                - platform: 目标平台 (windows/linux/darwin)
                - route: 网络路由 (none/internet/vpn)
                - enforce_timeout: 是否强制超时
                - options: Cuckoo 额外选项 (如: {"procmemdump": "yes"})

        Returns:
            提交结果字典:
            {
                "status": "ok"/"error",
                "task_id": "任务ID",
                "message": "描述信息"
            }
        """
        options = options or {}

        # 验证文件
        if not os.path.isfile(file_path):
            return {"status": "error", "message": "文件不存在: {}".format(file_path)}

        file_size = os.path.getsize(file_path)
        if file_size > self.max_file_size:
            return {"status": "error", "message": "文件过大 ({}MB)，最大支持 {}MB".format(
                file_size // (1024 * 1024), self.max_file_size // (1024 * 1024)
            )}

        # 计算文件哈希
        md5, sha1, sha256 = self._calculate_hashes(file_path)

        # 创建任务
        task_id = str(uuid.uuid4())[:12]
        task = SandboxTask(
            task_id=task_id,
            target_type="file",
            target_name=os.path.basename(file_path),
            target_path=file_path,
            file_size=file_size,
            file_md5=md5,
            file_sha256=sha256,
            status=TaskStatus.PENDING,
            priority=options.get("priority", 1),
            options=options,
            submitted_at=datetime.now().isoformat(),
            backend="local" if (self.local_mode or not self._stats["cuckoo_available"]) else "cuckoo"
        )

        with self._lock:
            self._tasks[task_id] = task
            self._stats["total_tasks"] += 1

        # 加入任务队列
        self._task_queue.append(task_id)
        logger.info("文件已提交到沙箱队列: {} ({} bytes, MD5: {})".format(
            task.target_name, file_size, md5
        ))

        return {
            "status": "ok",
            "task_id": task_id,
            "message": "文件已提交到分析队列",
            "data": task.to_dict()
        }

    def submit_url(self, url: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        """
        提交URL到沙箱进行分析

        Args:
            url: 目标URL
            options: 分析选项

        Returns:
            提交结果字典
        """
        if not url:
            return {"status": "error", "message": "URL不能为空"}

        options = options or {}

        # 验证URL格式
        url_pattern = re.compile(r'^https?://[^\s/$.?#].[^\s]*$', re.IGNORECASE)
        if not url_pattern.match(url):
            return {"status": "error", "message": "URL格式无效"}

        # 创建任务
        task_id = str(uuid.uuid4())[:12]
        task = SandboxTask(
            task_id=task_id,
            target_type="url",
            target_name=url,
            target_url=url,
            status=TaskStatus.PENDING,
            priority=options.get("priority", 1),
            options=options,
            submitted_at=datetime.now().isoformat(),
            backend="local" if (self.local_mode or not self._stats["cuckoo_available"]) else "cuckoo"
        )

        with self._lock:
            self._tasks[task_id] = task
            self._stats["total_tasks"] += 1

        # 加入任务队列
        self._task_queue.append(task_id)
        logger.info("URL已提交到沙箱队列: {}".format(url))

        return {
            "status": "ok",
            "task_id": task_id,
            "message": "URL已提交到分析队列",
            "data": task.to_dict()
        }

    # ============================================================
    # 完整分析流程
    # ============================================================

    def analyze_file(self, file_path: str, options: Optional[Dict] = None) -> Dict[str, Any]:
        """
        完整分析流程：ClamAV 预扫描 + 沙箱动态分析

        Args:
            file_path: 文件路径
            options: 分析选项

        Returns:
            分析结果字典
        """
        # 第一步：ClamAV 快速扫描
        clamav_result = self.scan_with_clamav(file_path)

        # 第二步：提交到沙箱
        submit_result = self.submit_file(file_path, options)

        if submit_result["status"] != "ok":
            return submit_result

        task_id = submit_result["task_id"]

        # 将 ClamAV 结果保存到任务选项中
        with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].options["clamav_result"] = clamav_result

        return {
            "status": "ok",
            "task_id": task_id,
            "message": "文件已提交进行完整分析（ClamAV + 沙箱）",
            "clamav": clamav_result,
            "data": submit_result.get("data", {})
        }

    # ============================================================
    # 任务状态查询
    # ============================================================

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        获取任务状态

        Args:
            task_id: 任务ID

        Returns:
            任务状态字典，如果任务不存在返回 None
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return None
            return task.to_dict()

    def get_task_report(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        获取任务分析报告

        Args:
            task_id: 任务ID

        Returns:
            分析报告字典，如果报告不存在返回 None
        """
        with self._lock:
            report = self._reports.get(task_id)
            if not report:
                return None
            return report.to_dict()

    def list_tasks(self, limit: int = 50, offset: int = 0,
                   status: Optional[str] = None) -> Dict[str, Any]:
        """
        列出分析任务

        Args:
            limit: 返回数量上限
            offset: 偏移量
            status: 按状态过滤

        Returns:
            任务列表字典:
            {
                "tasks": [...],
                "total": 总数,
                "limit": limit,
                "offset": offset
            }
        """
        with self._lock:
            all_tasks = list(self._tasks.values())

        # 按状态过滤
        if status:
            all_tasks = [t for t in all_tasks if t.status == status]

        # 按提交时间倒序排列
        all_tasks.sort(key=lambda t: t.submitted_at or "", reverse=True)

        total = len(all_tasks)
        paginated = all_tasks[offset:offset + limit]

        return {
            "tasks": [t.to_dict() for t in paginated],
            "total": total,
            "limit": limit,
            "offset": offset
        }

    def delete_task(self, task_id: str) -> Dict[str, Any]:
        """
        删除任务及其报告

        Args:
            task_id: 任务ID

        Returns:
            操作结果字典
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return {"status": "error", "message": "任务不存在: {}".format(task_id)}

            # 标记为已删除
            task.status = TaskStatus.DELETED

            # 移除报告
            if task_id in self._reports:
                del self._reports[task_id]

            # 从队列中移除
            try:
                self._task_queue.remove(task_id)
            except ValueError:
                pass

        logger.info("任务已删除: {}".format(task_id))
        return {"status": "ok", "message": "任务已删除"}

    def get_stats(self) -> Dict[str, Any]:
        """
        获取沙箱统计信息

        Returns:
            统计信息字典
        """
        with self._lock:
            stats = dict(self._stats)
            stats["pending_tasks"] = len([t for t in self._tasks.values()
                                          if t.status == TaskStatus.PENDING])
            stats["running_tasks"] = len([t for t in self._tasks.values()
                                          if t.status == TaskStatus.RUNNING])
            stats["completed_tasks"] = len([t for t in self._tasks.values()
                                            if t.status in (TaskStatus.COMPLETED, TaskStatus.REPORTED)])
            stats["queued_tasks"] = len(self._task_queue)

            # 计算平均分析时长
            completed_count = stats["malicious_tasks"] + stats["suspicious_tasks"] + stats["clean_tasks"]
            if completed_count > 0:
                stats["avg_analysis_time"] = round(stats["total_analysis_time"] / completed_count, 1)
            else:
                stats["avg_analysis_time"] = 0.0

            stats["cuckoo_api_url"] = self.cuckoo_api_url
            stats["backend_mode"] = "local" if (self.local_mode or not self._stats["cuckoo_available"]) else "cuckoo"

        return stats

    # ============================================================
    # 配置管理
    # ============================================================

    def get_config(self) -> Dict[str, Any]:
        """获取当前配置"""
        return {
            "cuckoo_api_url": self.cuckoo_api_url,
            "cuckoo_timeout": self.cuckoo_timeout,
            "analysis_timeout": self.analysis_timeout,
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "auto_start_analysis": self.auto_start_analysis,
            "clamav_enabled": self.clamav_enabled,
            "local_mode": self.local_mode,
            "max_file_size": self.max_file_size,
            "upload_dir": self.upload_dir,
            "report_dir": self.report_dir,
        }

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        更新配置

        Args:
            config: 配置字典

        Returns:
            更新结果
        """
        try:
            if "cuckoo_api_url" in config:
                self.cuckoo_api_url = config["cuckoo_api_url"]
            if "cuckoo_timeout" in config:
                self.cuckoo_timeout = int(config["cuckoo_timeout"])
            if "analysis_timeout" in config:
                self.analysis_timeout = int(config["analysis_timeout"])
            if "max_concurrent_tasks" in config:
                self.max_concurrent_tasks = int(config["max_concurrent_tasks"])
            if "auto_start_analysis" in config:
                self.auto_start_analysis = bool(config["auto_start_analysis"])
            if "clamav_enabled" in config:
                self.clamav_enabled = bool(config["clamav_enabled"])
            if "local_mode" in config:
                self.local_mode = bool(config["local_mode"])

            # 重新检查后端可用性
            self._check_cuckoo_available()
            self._check_clamav_available()

            logger.info("沙箱配置已更新")
            return {"status": "ok", "message": "配置已更新"}
        except Exception as e:
            logger.error("更新沙箱配置失败: {}".format(e))
            return {"status": "error", "message": "配置更新失败: {}".format(str(e))}

    # ============================================================
    # Cuckoo Sandbox API 交互
    # ============================================================

    def _cuckoo_submit_file(self, file_path: str, options: Dict) -> Optional[int]:
        """
        提交文件到 Cuckoo Sandbox

        Args:
            file_path: 文件路径
            options: 分析选项

        Returns:
            Cuckoo 任务ID，失败返回 None
        """
        if not HAS_REQUESTS:
            logger.error("requests 库未安装，无法提交到 Cuckoo")
            return None

        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                data = {}

                # 构建提交参数
                if "timeout" in options:
                    data["timeout"] = options["timeout"]
                if "priority" in options:
                    data["priority"] = options["priority"]
                if "platform" in options:
                    data["platform"] = options["platform"]
                if "route" in options:
                    data["route"] = options["route"]
                if "enforce_timeout" in options:
                    data["enforce_timeout"] = options["enforce_timeout"]
                if "options" in options and isinstance(options["options"], dict):
                    data["options"] = json.dumps(options["options"])

                resp = requests.post(
                    "{}/tasks/create/file".format(self.cuckoo_api_url),
                    files=files,
                    data=data,
                    timeout=self.cuckoo_timeout
                )

                if resp.status_code == 200:
                    result = resp.json()
                    task_id = result.get("task_id")
                    logger.info("文件已提交到 Cuckoo，任务ID: {}".format(task_id))
                    return task_id
                else:
                    logger.error("Cuckoo 提交失败: HTTP {} - {}".format(
                        resp.status_code, resp.text
                    ))
                    return None

        except requests.exceptions.Timeout:
            logger.error("Cuckoo API 请求超时")
            return None
        except Exception as e:
            logger.error("提交文件到 Cuckoo 失败: {}".format(e))
            return None

    def _cuckoo_submit_url(self, url: str, options: Dict) -> Optional[int]:
        """
        提交URL到 Cuckoo Sandbox

        Args:
            url: 目标URL
            options: 分析选项

        Returns:
            Cuckoo 任务ID，失败返回 None
        """
        if not HAS_REQUESTS:
            logger.error("requests 库未安装，无法提交到 Cuckoo")
            return None

        try:
            data = {"url": url}

            if "timeout" in options:
                data["timeout"] = options["timeout"]
            if "priority" in options:
                data["priority"] = options["priority"]
            if "platform" in options:
                data["platform"] = options["platform"]
            if "route" in options:
                data["route"] = options["route"]

            resp = requests.post(
                "{}/tasks/create/url".format(self.cuckoo_api_url),
                data=data,
                timeout=self.cuckoo_timeout
            )

            if resp.status_code == 200:
                result = resp.json()
                task_id = result.get("task_id")
                logger.info("URL已提交到 Cuckoo，任务ID: {}".format(task_id))
                return task_id
            else:
                logger.error("Cuckoo URL 提交失败: HTTP {} - {}".format(
                    resp.status_code, resp.text
                ))
                return None

        except Exception as e:
            logger.error("提交URL到 Cuckoo 失败: {}".format(e))
            return None

    def _cuckoo_get_status(self, cuckoo_task_id: int) -> Optional[str]:
        """
        获取 Cuckoo 任务状态

        Args:
            cuckoo_task_id: Cuckoo 任务ID

        Returns:
            状态字符串: pending/running/completed/failed
        """
        if not HAS_REQUESTS:
            return None

        try:
            resp = requests.get(
                "{}/tasks/view/{}".format(self.cuckoo_api_url, cuckoo_task_id),
                timeout=self.cuckoo_timeout
            )
            if resp.status_code == 200:
                result = resp.json()
                status = result.get("task", {}).get("status", "failed")
                return status
        except Exception as e:
            logger.error("获取 Cuckoo 任务状态失败: {}".format(e))

        return None

    def _cuckoo_get_report(self, cuckoo_task_id: int) -> Optional[Dict]:
        """
        获取 Cuckoo 分析报告

        Args:
            cuckoo_task_id: Cuckoo 任务ID

        Returns:
            报告字典
        """
        if not HAS_REQUESTS:
            return None

        try:
            resp = requests.get(
                "{}/tasks/report/{}".format(self.cuckoo_api_url, cuckoo_task_id),
                timeout=self.cuckoo_timeout
            )
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.error("获取 Cuckoo 报告失败: HTTP {}".format(resp.status_code))
        except Exception as e:
            logger.error("获取 Cuckoo 报告失败: {}".format(e))

        return None

    def _parse_cuckoo_report(self, cuckoo_report: Dict, task: SandboxTask) -> SandboxReport:
        """
        解析 Cuckoo 报告为标准 SandboxReport 格式

        Args:
            cuckoo_report: Cuckoo 原始报告
            task: 关联的沙箱任务

        Returns:
            SandboxReport 实例
        """
        report = SandboxReport(
            task_id=task.task_id,
            target_name=task.target_name,
            target_type=task.target_type,
            backend="cuckoo"
        )

        try:
            # 基本信息
            info = cuckoo_report.get("info", {})
            report.start_time = info.get("started")
            report.end_time = info.get("ended")
            if report.start_time and report.end_time:
                try:
                    start = datetime.fromisoformat(report.start_time.replace("Z", "+00:00"))
                    end = datetime.fromisoformat(report.end_time.replace("Z", "+00:00"))
                    report.analysis_duration = (end - start).total_seconds()
                except Exception:
                    pass
            report.machine_type = info.get("machine", {}).get("type", "")
            report.os_name = info.get("machine", {}).get("manager", "")
            report.cuckoo_version = info.get("version", "")

            # 文件信息
            target = cuckoo_report.get("target", {})
            report.file_md5 = target.get("file", {}).get("md5", task.file_md5)
            report.file_sha256 = target.get("file", {}).get("sha256", task.file_sha256)
            report.file_sha1 = target.get("file", {}).get("sha1", "")
            report.file_size = target.get("file", {}).get("size", task.file_size)
            report.file_type = target.get("file", {}).get("type", "")

            # PE 信息
            pe_info = cuckoo_report.get("static", {}).get("peid_signatures", [])
            if pe_info:
                report.pe_info = {"signatures": pe_info}

            # 网络行为
            network = cuckoo_report.get("network", {})
            report.network_requests = network.get("tcp", []) + network.get("udp", [])
            report.dns_queries = network.get("dns", [])
            report.http_requests = network.get("http", [])

            # 提取域名和IP
            for dns in report.dns_queries:
                if isinstance(dns, dict):
                    request = dns.get("request", "")
                    if request:
                        report.domains_contacted.append(request)
            for req in report.network_requests:
                if isinstance(req, dict):
                    dst = req.get("dst", "")
                    if dst:
                        report.ips_contacted.append(dst)

            # 去重
            report.domains_contacted = list(set(report.domains_contacted))
            report.ips_contacted = list(set(report.ips_contacted))

            # 文件系统操作
            behavior = cuckoo_report.get("behavior", {})
            summary = behavior.get("summary", {})

            report.files_created = summary.get("files", []) or []
            report.files_deleted = summary.get("file_deleted", []) or []
            report.files_read = summary.get("file_read", []) or []
            report.files_modified = summary.get("file_written", []) or []
            report.dropped_files = cuckoo_report.get("dropped", []) or []

            # 注册表操作
            report.registry_keys_set = summary.get("regkey_written", []) or []
            report.registry_keys_deleted = summary.get("regkey_deleted", []) or []

            # 进程信息
            report.processes = behavior.get("processes", []) or []
            # 构建进程树文本
            proc_lines = []
            for proc in report.processes[:20]:
                if isinstance(proc, dict):
                    proc_name = proc.get("process_name", "")
                    pid = proc.get("pid", "")
                    ppid = proc.get("ppid", "")
                    calls = len(proc.get("calls", []))
                    proc_lines.append("{} (PID: {}, PPID: {}, 调用数: {})".format(
                        proc_name, pid, ppid, calls
                    ))
            report.process_tree = "\n".join(proc_lines)

            # 签名检测结果
            report.signatures = cuckoo_report.get("signatures", []) or []

            # IOC 指标
            ioc_data = cuckoo_report.get("iocs", {}) or {}
            report.ioc_ips = ioc_data.get("ips", {}).get("malicious", []) or []
            report.ioc_domains = ioc_data.get("domains", {}).get("malicious", []) or []
            report.ioc_urls = ioc_data.get("urls", {}).get("malicious", []) or []

            # YARA 签名匹配
            report.ioc_signatures = cuckoo_report.get("static", {}).get("YARA", []) or []

            # 互斥体
            for sig in report.signatures:
                if isinstance(sig, dict) and "mutex" in sig.get("name", "").lower():
                    mark = sig.get("markinfo", {})
                    if mark:
                        report.ioc_mutexes.extend(mark.values() if isinstance(mark, dict) else [mark])

            # ClamAV 结果（从任务选项中获取）
            clamav_res = task.options.get("clamav_result", {})
            if isinstance(clamav_res, dict):
                report.clamav_result = "infected" if clamav_res.get("infected") else "clean"
                report.clamav_threat = clamav_res.get("threat_name", "")

            # 计算风险评分
            report.risk_score = self._calculate_risk_score(report)
            report.risk_level = self._get_risk_level(report.risk_score)

            # 生成行为摘要
            report.behavior_summary = self._generate_behavior_summary(report)

            # 恶意软件分类
            for sig in report.signatures:
                if isinstance(sig, dict):
                    desc = sig.get("description", "")
                    if "trojan" in desc.lower():
                        report.malware_type = "木马"
                        break
                    elif "ransomware" in desc.lower():
                        report.malware_type = "勒索软件"
                        break
                    elif "worm" in desc.lower():
                        report.malware_type = "蠕虫"
                        break
                    elif "backdoor" in desc.lower():
                        report.malware_type = "后门"
                        break
                    elif "spyware" in desc.lower() or "keylog" in desc.lower():
                        report.malware_type = "间谍软件"
                        break
                    elif "adware" in desc.lower():
                        report.malware_type = "广告软件"
                        break
                    elif "rootkit" in desc.lower():
                        report.malware_type = "Rootkit"
                        break
            if not report.malware_type and report.risk_score >= 50:
                report.malware_type = "可疑程序"

        except Exception as e:
            logger.error("解析 Cuckoo 报告异常: {}".format(e))

        return report

    # ============================================================
    # 本地模拟分析
    # ============================================================

    def _local_analyze_file(self, task: SandboxTask) -> SandboxReport:
        """
        本地模拟分析文件行为

        当 Cuckoo 不可用时，使用本地静态分析模拟沙箱行为：
        - PE 文件头检查
        - 字符串提取
        - 可疑 API 调用模式检测
        - 导入表分析

        Args:
            task: 沙箱任务

        Returns:
            SandboxReport 实例
        """
        report = SandboxReport(
            task_id=task.task_id,
            target_name=task.target_name,
            target_type=task.target_type,
            backend="local"
        )

        file_path = task.target_path
        if not file_path or not os.path.isfile(file_path):
            report.behavior_summary = "文件不存在或无法访问"
            return report

        start_time = time.time()

        try:
            # 计算哈希
            md5, sha1, sha256 = self._calculate_hashes(file_path)
            report.file_md5 = md5
            report.file_sha1 = sha1
            report.file_sha256 = sha256
            report.file_size = os.path.getsize(file_path)

            # 检测文件类型
            report.file_type = self._detect_file_type(file_path)

            # PE 文件分析
            if report.file_type and "PE" in report.file_type.upper():
                self._analyze_pe_file(file_path, report)

            # 提取字符串
            strings = self._extract_strings(file_path)
            self._analyze_strings(strings, report)

            # 检测可疑 API 调用模式
            self._detect_suspicious_patterns(file_path, report)

            # ClamAV 结果
            clamav_res = task.options.get("clamav_result", {})
            if isinstance(clamav_res, dict):
                report.clamav_result = "infected" if clamav_res.get("infected") else "clean"
                report.clamav_threat = clamav_res.get("threat_name", "")

            # 计算风险评分
            report.risk_score = self._calculate_risk_score(report)
            report.risk_level = self._get_risk_level(report.risk_score)

            # 生成行为摘要
            report.behavior_summary = self._generate_behavior_summary(report)

        except Exception as e:
            logger.error("本地分析异常: {}".format(e))
            report.behavior_summary = "分析过程出错: {}".format(str(e))

        report.analysis_duration = round(time.time() - start_time, 2)
        return report

    def _detect_file_type(self, file_path: str) -> str:
        """
        检测文件类型（通过 magic bytes）

        Args:
            file_path: 文件路径

        Returns:
            文件类型描述字符串
        """
        magic_map = {
            b"\x4d\x5a": "PE32 executable (Windows)",
            b"\x50\x4b\x03\x04": "ZIP archive",
            b"\x37\x7a\xbc\xaf": "7-Zip archive",
            b"\x1f\x8b": "GZIP compressed",
            b"\x89\x50\x4e\x47": "PNG image",
            b"\xff\xd8\xff": "JPEG image",
            b"\x25\x50\x44\x46": "PDF document",
            b"\x7f\x45\x4c\x46": "ELF executable (Linux)",
            b"\xca\xfe\xba\xbe": "Java class file",
            b"\xed\xab\xee\xdb": "RPM package",
        }

        try:
            with open(file_path, "rb") as f:
                header = f.read(256)

            for magic, desc in magic_map.items():
                if header.startswith(magic):
                    return desc

            # 尝试使用 file 命令
            try:
                result = subprocess.run(
                    ["file", "-b", file_path],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    return result.stdout.strip()
            except Exception:
                pass

        except Exception as e:
            logger.error("检测文件类型失败: {}".format(e))

        return "未知类型"

    def _analyze_pe_file(self, file_path: str, report: SandboxReport):
        """
        分析 PE 文件头信息

        Args:
            file_path: PE文件路径
            report: 报告对象
        """
        try:
            with open(file_path, "rb") as f:
                # 读取 DOS 头
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b"\x4d\x5a":
                    return

                # 获取 PE 偏移
                pe_offset = struct.unpack("<I", dos_header[60:64])[0]
                f.seek(pe_offset)

                # 读取 PE 签名
                pe_sig = f.read(4)
                if pe_sig != b"\x50\x45\x00\x00":
                    return

                # 读取 COFF 文件头
                coff_header = f.read(20)
                machine = struct.unpack("<H", coff_header[0:2])[0]
                num_sections = struct.unpack("<H", coff_header[2:4])[0]
                timestamp = struct.unpack("<I", coff_header[4:8])[0]

                # 机器类型映射
                machine_types = {
                    0x014c: "i386 (32-bit)",
                    0x8664: "AMD64 (64-bit)",
                    0x01c0: "ARM",
                    0x01c4: "ARM Thumb-2",
                    0xaa64: "ARM64",
                }

                pe_info = {
                    "machine": machine_types.get(machine, "0x{:04x}".format(machine)),
                    "sections": num_sections,
                    "timestamp": datetime.fromtimestamp(timestamp).isoformat() if timestamp else "",
                    "is_64bit": machine == 0x8664,
                    "is_dll": False,
                    "is_exe": False,
                }

                # 读取可选头
                opt_magic = struct.unpack("<H", f.read(2))[0]
                if opt_magic == 0x10b:  # PE32
                    characteristics_offset = 70
                elif opt_magic == 0x20b:  # PE32+
                    characteristics_offset = 70
                else:
                    characteristics_offset = 70

                f.seek(pe_offset + 24 + characteristics_offset)
                characteristics = struct.unpack("<H", f.read(2))[0]
                pe_info["is_dll"] = bool(characteristics & 0x2000)
                pe_info["is_exe"] = bool(characteristics & 0x0002)

                report.pe_info = pe_info

                # 提取节区名称
                f.seek(pe_offset + 24 + (96 if opt_magic == 0x10b else 112))
                section_names = []
                for _ in range(min(num_sections, 20)):
                    section_data = f.read(40)
                    if len(section_data) < 40:
                        break
                    name = section_data[:8].rstrip(b"\x00").decode("ascii", errors="ignore")
                    if name:
                        section_names.append(name)
                if section_names:
                    report.pe_info["section_names"] = section_names

                # 检测可疑节区
                suspicious_sections = [s for s in section_names
                                       if s.lower() in (".textbss", ".rsrc", ".reloc")]
                if suspicious_sections:
                    report.signatures.append({
                        "name": "Suspicious Sections",
                        "description": "包含可疑节区: {}".format(", ".join(suspicious_sections)),
                        "severity": 2,
                    })

                # 检测是否为 DLL（通常 DLL 不太常见作为恶意软件入口）
                if pe_info["is_dll"]:
                    report.signatures.append({
                        "name": "DLL File",
                        "description": "目标文件为动态链接库 (DLL)",
                        "severity": 1,
                    })

        except Exception as e:
            logger.error("PE 文件分析失败: {}".format(e))

    def _extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """
        从文件中提取可打印字符串

        Args:
            file_path: 文件路径
            min_length: 最小字符串长度

        Returns:
            字符串列表
        """
        strings = []
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                # ASCII 字符串
                current = b""
                for byte in data:
                    if 32 <= byte <= 126:
                        current += bytes([byte])
                    else:
                        if len(current) >= min_length:
                            strings.append(current.decode("ascii", errors="ignore"))
                        current = b""
                if len(current) >= min_length:
                    strings.append(current.decode("ascii", errors="ignore"))

                # 宽字符 (UTF-16LE) 字符串
                current = b""
                i = 0
                while i < len(data) - 1:
                    char = data[i:i+2]
                    if len(char) == 2 and char[1] == 0 and 32 <= char[0] <= 126:
                        current += bytes([char[0]])
                    else:
                        if len(current) >= min_length:
                            strings.append(current.decode("ascii", errors="ignore"))
                        current = b""
                    i += 2
                if len(current) >= min_length:
                    strings.append(current.decode("ascii", errors="ignore"))

        except Exception as e:
            logger.error("提取字符串失败: {}".format(e))

        return strings

    def _analyze_strings(self, strings: List[str], report: SandboxReport):
        """
        分析提取的字符串，检测可疑模式

        Args:
            strings: 字符串列表
            report: 报告对象
        """
        if not strings:
            return

        # 可疑 URL 模式
        url_pattern = re.compile(r'https?://[^\s"\',;}>]+')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        email_pattern = re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+')
        # 注册表键路径
        reg_pattern = re.compile(r'[HhKk][EeLlMm][_-]..\\[\\\w]+', re.IGNORECASE)
        # 可执行文件路径
        exe_pattern = re.compile(r'[A-Za-z]:\\[\\\w\s\-\.]+\.(exe|dll|bat|cmd|ps1|vbs|js|wsf)', re.IGNORECASE)

        urls_found = set()
        ips_found = set()
        emails_found = set()
        reg_keys_found = set()
        exe_paths_found = set()

        for s in strings:
            # URL 检测
            for url in url_pattern.findall(s):
                urls_found.add(url)
            # IP 检测
            for ip in ip_pattern.findall(s):
                # 过滤掉明显不是IP的
                parts = ip.split(".")
                if all(0 <= int(p) <= 255 for p in parts):
                    ips_found.add(ip)
            # 邮箱检测
            for email in email_pattern.findall(s):
                emails_found.add(email)
            # 注册表键
            for reg in reg_pattern.findall(s):
                reg_keys_found.add(reg)
            # 可执行路径
            for exe in exe_pattern.findall(s):
                exe_paths_found.add(exe)

        # 添加到报告
        report.ioc_urls = list(urls_found)[:50]
        report.ips_contacted = list(ips_found)[:50]
        report.domains_contacted = [self._extract_domain(u) for u in urls_found
                                     if self._extract_domain(u)][:50]

        # 注册表操作模拟
        for reg in reg_keys_found:
            report.registry_keys_set.append({"key": reg, "action": "simulated_write"})

        # 文件操作模拟
        for exe in exe_paths_found:
            report.files_read.append(exe)

        # 检测可疑字符串模式
        suspicious_keywords = {
            "keylog": "键盘记录",
            "password": "密码窃取",
            "credential": "凭证窃取",
            "crypto": "加密货币/加密操作",
            "bitcoin": "比特币相关",
            "wallet": "钱包相关",
            "inject": "代码注入",
            "hook": "API Hook",
            "rootkit": "Rootkit",
            "backdoor": "后门",
            "shell": "Shell 操作",
            "cmd.exe": "命令执行",
            "powershell": "PowerShell 执行",
            "regsvr32": "COM 注册",
            "rundll32": "DLL 加载",
            "schtasks": "计划任务",
            "net user": "用户管理",
            "net localgroup": "用户组管理",
            "taskkill": "进程终止",
            "download": "下载行为",
            "upload": "上传行为",
            "reverse": "反向连接",
            "bind": "绑定端口",
            "listen": "监听端口",
            "connect": "网络连接",
            "socket": "Socket 操作",
            "mutex": "互斥体操作",
            "anti-debug": "反调试",
            "anti-vm": "反虚拟机",
            "sandbox": "沙箱检测",
            "virus": "病毒相关",
            "worm": "蠕虫相关",
            "trojan": "木马相关",
            "rat": "远程控制",
        }

        for keyword, desc in suspicious_keywords.items():
            for s in strings:
                if keyword.lower() in s.lower():
                    report.signatures.append({
                        "name": "Suspicious String: {}".format(keyword),
                        "description": "发现可疑字符串 '{}' - 可能与{}相关".format(s[:100], desc),
                        "severity": 3,
                    })
                    break  # 每个关键词只报告一次

    def _detect_suspicious_patterns(self, file_path: str, report: SandboxReport):
        """
        检测文件中的可疑二进制模式

        Args:
            file_path: 文件路径
            report: 报告对象
        """
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            # 检测常见恶意软件特征
            patterns = {
                # 反虚拟机检测
                b"\x56\x69\x72\x74\x75\x61\x6c\x42\x6f\x78": "VirtualBox 检测",
                b"\x56\x4d\x77\x61\x72\x65": "VMware 检测",
                b"\x71\x65\x6d\x75": "QEMU 检测",
                b"\x58\x65\x6e": "Xen 检测",
                # 反调试
                b"\x49\x73\x44\x65\x62\x75\x67\x67\x65\x72\x50\x72\x65\x73\x65\x6e\x74": "IsDebuggerPresent API",
                b"\x43\x68\x65\x63\x6b\x52\x65\x6d\x6f\x74\x65\x44\x65\x62\x75\x67\x67\x65\x72": "CheckRemoteDebuggerPresent API",
                # 常见恶意 API 导入
                b"\x43\x72\x65\x61\x74\x65\x52\x65\x6d\x6f\x74\x65\x54\x68\x72\x65\x61\x64": "CreateRemoteThread (代码注入)",
                b"\x57\x72\x69\x74\x65\x50\x72\x6f\x63\x65\x73\x73\x4d\x65\x6d\x6f\x72\x79": "WriteProcessMemory (内存写入)",
                b"\x56\x69\x72\x74\x75\x61\x6c\x41\x6c\x6c\x6f\x63": "VirtualAlloc (内存分配)",
                b"\x53\x65\x74\x57\x69\x6e\x64\x6f\x77\x73\x48\x6f\x6f\x6b\x45\x78": "SetWindowsHookEx (键盘钩子)",
                b"\x47\x65\x74\x41\x73\x79\x6e\x63\x4b\x65\x79\x53\x74\x61\x74\x65": "GetAsyncKeyState (键盘记录)",
            }

            for pattern, desc in patterns.items():
                if pattern in data:
                    report.signatures.append({
                        "name": "Binary Pattern Detected",
                        "description": "检测到可疑二进制模式: {}".format(desc),
                        "severity": 4,
                    })

            # 检测是否包含多个可执行文件（可能为捆绑器/加壳器）
            pe_count = data.count(b"\x4d\x5a")
            if pe_count > 2:
                report.signatures.append({
                    "name": "Multiple PE Headers",
                    "description": "文件包含 {} 个 PE 头标记，可能为捆绑器或加壳器".format(pe_count),
                    "severity": 5,
                })

            # 检测高熵值（可能加壳/加密）
            entropy = self._calculate_entropy(data[:8192])
            if entropy > 7.5:
                report.signatures.append({
                    "name": "High Entropy",
                    "description": "文件头部熵值为 {:.2f}，可能经过加壳或加密".format(entropy),
                    "severity": 3,
                })

        except Exception as e:
            logger.error("检测可疑模式失败: {}".format(e))

    def _calculate_entropy(self, data: bytes) -> float:
        """
        计算数据的 Shannon 熵值

        Args:
            data: 字节数据

        Returns:
            熵值 (0-8)
        """
        if not data:
            return 0.0

        from collections import Counter
        import math

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy

    def _extract_domain(self, url: str) -> str:
        """从 URL 中提取域名"""
        try:
            match = re.match(r'https?://([^/:]+)', url)
            if match:
                return match.group(1)
        except Exception:
            pass
        return ""

    # ============================================================
    # 风险评分与报告生成
    # ============================================================

    def _calculate_risk_score(self, report: SandboxReport) -> float:
        """
        计算综合风险评分

        评分维度:
        - ClamAV 检测结果 (0-30分)
        - 行为签名严重度 (0-30分)
        - 网络行为 (0-15分)
        - 文件系统操作 (0-10分)
        - 注册表操作 (0-10分)
        - IOC 指标 (0-5分)

        Args:
            report: 分析报告

        Returns:
            风险评分 (0-100)
        """
        score = 0.0

        # ClamAV 检测
        if report.clamav_result == "infected":
            score += 30.0

        # 行为签名评分
        for sig in report.signatures:
            if isinstance(sig, dict):
                severity = sig.get("severity", 1)
                score += min(severity * 3, 30)

        # 网络行为评分
        network_score = 0
        network_score += min(len(report.domains_contacted) * 1, 5)
        network_score += min(len(report.ips_contacted) * 1, 5)
        network_score += min(len(report.http_requests) * 0.5, 5)
        score += min(network_score, 15)

        # 文件系统操作评分
        fs_score = 0
        fs_score += min(len(report.files_created) * 0.5, 3)
        fs_score += min(len(report.files_deleted) * 1, 3)
        fs_score += min(len(report.dropped_files) * 2, 4)
        score += min(fs_score, 10)

        # 注册表操作评分
        reg_score = min(len(report.registry_keys_set) * 0.5, 5) + \
                    min(len(report.registry_keys_deleted) * 1, 5)
        score += min(reg_score, 10)

        # IOC 指标评分
        ioc_score = 0
        ioc_score += min(len(report.ioc_ips) * 1, 2)
        ioc_score += min(len(report.ioc_domains) * 1, 2)
        ioc_score += min(len(report.ioc_urls) * 0.5, 1)
        score += min(ioc_score, 5)

        return min(round(score, 1), 100.0)

    def _get_risk_level(self, score: float) -> str:
        """
        根据风险评分返回风险等级

        Args:
            score: 风险评分

        Returns:
            风险等级字符串
        """
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 30:
            return RiskLevel.MEDIUM
        elif score >= 10:
            return RiskLevel.LOW
        return RiskLevel.CLEAN

    def _generate_behavior_summary(self, report: SandboxReport) -> str:
        """
        生成行为摘要文本

        Args:
            report: 分析报告

        Returns:
            行为摘要字符串
        """
        parts = []

        if report.clamav_result == "infected":
            parts.append("ClamAV 检测到威胁: {}".format(report.clamav_threat))

        if report.malware_type:
            parts.append("疑似类型: {}".format(report.malware_type))

        # 网络行为
        if report.domains_contacted:
            parts.append("联系了 {} 个域名".format(len(report.domains_contacted)))
        if report.ips_contacted:
            parts.append("联系了 {} 个IP地址".format(len(report.ips_contacted)))
        if report.http_requests:
            parts.append("发起 {} 个HTTP请求".format(len(report.http_requests)))

        # 文件操作
        if report.files_created:
            parts.append("创建了 {} 个文件".format(len(report.files_created)))
        if report.files_deleted:
            parts.append("删除了 {} 个文件".format(len(report.files_deleted)))
        if report.dropped_files:
            parts.append("释放了 {} 个文件".format(len(report.dropped_files)))

        # 注册表操作
        reg_count = len(report.registry_keys_set) + len(report.registry_keys_deleted)
        if reg_count > 0:
            parts.append("操作了 {} 个注册表键".format(reg_count))

        # 签名
        if report.signatures:
            parts.append("触发 {} 个行为签名".format(len(report.signatures)))

        if not parts:
            parts.append("未发现明显恶意行为")

        return "; ".join(parts)

    # ============================================================
    # 任务处理工作线程
    # ============================================================

    def _task_worker(self):
        """任务处理工作线程 - 从队列中取出任务并执行分析"""
        logger.info("沙箱任务处理线程已启动")

        while self._worker_running:
            try:
                # 检查并发限制
                with self._lock:
                    running_count = len([t for t in self._tasks.values()
                                         if t.status == TaskStatus.RUNNING])
                    if running_count >= self.max_concurrent_tasks:
                        time.sleep(2)
                        continue

                # 从队列获取任务
                try:
                    task_id = self._task_queue.popleft()
                except IndexError:
                    time.sleep(1)
                    continue

                with self._lock:
                    task = self._tasks.get(task_id)
                    if not task or task.status != TaskStatus.PENDING:
                        continue
                    task.status = TaskStatus.RUNNING
                    task.started_at = datetime.now().isoformat()

                # 在新线程中执行分析
                thread = threading.Thread(
                    target=self._execute_task,
                    args=(task_id,),
                    name="sandbox-task-{}".format(task_id),
                    daemon=True
                )
                with self._lock:
                    self._running_tasks[task_id] = thread
                thread.start()

            except Exception as e:
                logger.error("任务处理线程异常: {}".format(e))
                time.sleep(2)

    def _execute_task(self, task_id: str):
        """
        执行单个分析任务

        Args:
            task_id: 任务ID
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return

        logger.info("开始分析任务: {} ({})".format(task_id, task.target_name))
        report = None

        try:
            # 判断使用 Cuckoo 还是本地模拟
            use_cuckoo = (not self.local_mode and
                          self._stats["cuckoo_available"] and
                          HAS_REQUESTS)

            if use_cuckoo:
                report = self._execute_cuckoo_task(task)
            else:
                report = self._local_analyze_file(task)

            # 保存报告
            with self._lock:
                self._reports[task_id] = report
                task.status = TaskStatus.REPORTED
                task.completed_at = datetime.now().isoformat()

                # 更新统计
                self._stats["total_analysis_time"] += report.analysis_duration
                if report.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                    self._stats["malicious_tasks"] += 1
                elif report.risk_level in (RiskLevel.MEDIUM, RiskLevel.LOW):
                    self._stats["suspicious_tasks"] += 1
                else:
                    self._stats["clean_tasks"] += 1

            logger.info("任务分析完成: {} (风险评分: {}, 等级: {})".format(
                task_id, report.risk_score, report.risk_level
            ))

        except Exception as e:
            logger.error("任务分析失败: {}".format(e))
            with self._lock:
                task.status = TaskStatus.FAILED
                task.error_message = str(e)
                task.completed_at = datetime.now().isoformat()
                self._stats["failed_tasks"] += 1

        finally:
            with self._lock:
                if task_id in self._running_tasks:
                    del self._running_tasks[task_id]

    def _execute_cuckoo_task(self, task: SandboxTask) -> SandboxReport:
        """
        使用 Cuckoo 执行分析任务

        Args:
            task: 沙箱任务

        Returns:
            SandboxReport 实例
        """
        start_time = time.time()

        # 提交到 Cuckoo
        cuckoo_task_id = None
        if task.target_type == "file":
            cuckoo_task_id = self._cuckoo_submit_file(task.target_path, task.options)
        elif task.target_type == "url":
            cuckoo_task_id = self._cuckoo_submit_url(task.target_url, task.options)

        if not cuckoo_task_id:
            logger.warning("Cuckoo 提交失败，回退到本地模拟: {}".format(task.task_id))
            task.backend = "local"
            return self._local_analyze_file(task)

        # 保存 Cuckoo 任务ID
        with self._lock:
            task.cuckoo_task_id = cuckoo_task_id

        # 轮询等待分析完成
        timeout = task.options.get("timeout", self.analysis_timeout)
        poll_interval = 10
        elapsed = 0

        while elapsed < timeout:
            status = self._cuckoo_get_status(cuckoo_task_id)
            if status == "completed":
                break
            elif status == "failed":
                raise RuntimeError("Cuckoo 分析任务失败")
            elif status == "reported":
                break

            time.sleep(poll_interval)
            elapsed += poll_interval

        if elapsed >= timeout:
            raise RuntimeError("Cuckoo 分析超时 ({}秒)".format(timeout))

        # 获取报告
        cuckoo_report = self._cuckoo_get_report(cuckoo_task_id)
        if not cuckoo_report:
            logger.warning("获取 Cuckoo 报告失败，回退到本地模拟")
            task.backend = "local"
            return self._local_analyze_file(task)

        # 解析报告
        report = self._parse_cuckoo_report(cuckoo_report, task)
        report.analysis_duration = round(time.time() - start_time, 2)

        return report

    # ============================================================
    # 服务状态
    # ============================================================

    def get_service_status(self) -> Dict[str, Any]:
        """
        获取沙箱服务状态

        Returns:
            服务状态字典
        """
        # 重新检查可用性
        self._check_cuckoo_available()
        self._check_clamav_available()

        return {
            "cuckoo_available": self._stats["cuckoo_available"],
            "clamav_available": self._stats["clamav_available"],
            "backend_mode": "local" if (self.local_mode or not self._stats["cuckoo_available"]) else "cuckoo",
            "worker_running": self._worker_running,
            "running_tasks": len(self._running_tasks),
            "queued_tasks": len(self._task_queue),
            "cuckoo_api_url": self.cuckoo_api_url,
        }

    def shutdown(self):
        """关闭沙箱分析引擎"""
        self._worker_running = False
        logger.info("沙箱分析引擎已关闭")
