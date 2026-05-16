"""
GateKeeper - 健康检查路由
提供存活检查、就绪检查和 Prometheus 格式指标端点
"""

import time
import os
import psutil
from datetime import datetime, timezone
from flask import Blueprint, jsonify, Response

from config.settings import settings
from config.logging_config import get_logger

logger = get_logger("health")

health_bp = Blueprint("health", __name__)

# 应用启动时间戳，用于计算运行时长
_start_time = time.time()

# 初始化 CPU 使用率计数器（首次调用返回0，需要先调用一次）
_cpu_process = psutil.Process(os.getpid())
_cpu_process.cpu_percent(interval=0)


@health_bp.route("/health")
def liveness():
    """
    存活检查 (Liveness Probe)
    ---
    tags: [健康检查]
    description: 仅检查进程是否在运行，适用于 Kubernetes livenessProbe
    responses:
      200:
        description: 服务存活
        schema:
          type: object
          properties:
            status:
              type: string
              example: ok
            timestamp:
              type: string
              format: date-time
    """
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@health_bp.route("/ready")
def readiness():
    """
    就绪检查 (Readiness Probe)
    ---
    tags: [健康检查]
    description: 检查数据库连接、内存使用、磁盘使用等关键依赖，适用于 Kubernetes readinessProbe
    responses:
      200:
        description: 服务就绪
        schema:
          type: object
          properties:
            status:
              type: string
              example: ok
            timestamp:
              type: string
              format: date-time
            checks:
              type: object
              properties:
                database:
                  type: object
                memory:
                  type: object
                disk:
                  type: object
      503:
        description: 服务降级（部分依赖不可用）
    """
    checks = {}
    all_ok = True

    # 1. 数据库连接检查
    try:
        from config.database import check_connection
        ok, msg = check_connection()
        checks["database"] = {"status": "ok" if ok else "error", "detail": msg}
        if not ok:
            all_ok = False
    except Exception as e:
        checks["database"] = {"status": "error", "detail": str(e)}
        all_ok = False

    # 2. 内存使用检查
    try:
        mem = psutil.virtual_memory()
        mem_percent = mem.percent
        mem_ok = mem_percent < 90
        checks["memory"] = {
            "status": "ok" if mem_ok else "warning",
            "usage_percent": round(mem_percent, 1),
            "total_mb": round(mem.total / (1024 * 1024), 1),
            "available_mb": round(mem.available / (1024 * 1024), 1),
        }
        if not mem_ok:
            all_ok = False
    except Exception as e:
        checks["memory"] = {"status": "error", "detail": str(e)}
        all_ok = False

    # 3. 磁盘使用检查
    try:
        disk = psutil.disk_usage("/")
        disk_percent = disk.percent
        disk_ok = disk_percent < 90
        checks["disk"] = {
            "status": "ok" if disk_ok else "warning",
            "usage_percent": round(disk_percent, 1),
            "total_gb": round(disk.total / (1024 ** 3), 1),
            "free_gb": round(disk.free / (1024 ** 3), 1),
        }
        if not disk_ok:
            all_ok = False
    except Exception as e:
        checks["disk"] = {"status": "error", "detail": str(e)}
        all_ok = False

    status_code = 200 if all_ok else 503
    return jsonify({
        "status": "ok" if all_ok else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
    }), status_code


@health_bp.route("/metrics")
def metrics():
    """
    Prometheus 格式指标端点
    ---
    tags: [健康检查]
    description: 返回 text/plain 格式的 Prometheus 指标数据，包括运行时间、内存、CPU等
    produces:
      - text/plain
    responses:
      200:
        description: Prometheus 格式指标数据
    """
    now = datetime.now(timezone.utc)
    uptime_seconds = time.time() - _start_time

    # 进程内存信息
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    mem_rss_bytes = mem_info.rss
    mem_vms_bytes = mem_info.vms

    # 系统内存信息
    sys_mem = psutil.virtual_memory()

    # CPU 使用率
    cpu_percent = process.cpu_percent(interval=0)

    lines = [
        "# HELP gatekeeper_up GateKeeper service liveness (1 = up)",
        "# TYPE gatekeeper_up gauge",
        "gatekeeper_up 1",
        "",
        "# HELP gatekeeper_uptime_seconds GateKeeper uptime in seconds",
        "# TYPE gatekeeper_uptime_seconds gauge",
        "gatekeeper_uptime_seconds {:.1f}".format(uptime_seconds),
        "",
        "# HELP process_memory_bytes Process resident memory in bytes",
        "# TYPE process_memory_bytes gauge",
        "process_memory_bytes {}".format(mem_rss_bytes),
        "",
        "# HELP process_memory_vms_bytes Process virtual memory in bytes",
        "# TYPE process_memory_vms_bytes gauge",
        "process_memory_vms_bytes {}".format(mem_vms_bytes),
        "",
        "# HELP system_memory_usage_percent System memory usage percentage",
        "# TYPE system_memory_usage_percent gauge",
        "system_memory_usage_percent {:.1f}".format(sys_mem.percent),
        "",
        "# HELP system_memory_available_bytes System available memory in bytes",
        "# TYPE system_memory_available_bytes gauge",
        "system_memory_available_bytes {}".format(sys_mem.available),
        "",
        "# HELP process_cpu_percent Process CPU usage percentage",
        "# TYPE process_cpu_percent gauge",
        "process_cpu_percent {:.1f}".format(cpu_percent),
        "",
        "# HELP gatekeeper_info GateKeeper version and build information",
        "# TYPE gatekeeper_info gauge",
        'gatekeeper_info{{version="{}"}} 1'.format(settings.version),
    ]

    return Response("\n".join(lines) + "\n", mimetype="text/plain")
