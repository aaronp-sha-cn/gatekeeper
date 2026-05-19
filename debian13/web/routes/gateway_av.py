# -*- coding: utf-8 -*-
"""
网关病毒扫描 Web 路由
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required
from web.routes.auth import admin_required
from flask_login import current_user
from security.gateway_antivirus import get_gateway_antivirus
from security.protocol_scanners import (
    get_http_scanner, get_ftp_scanner, get_smtp_scanner, get_smb_scanner
)
import logging
import uuid

logger = logging.getLogger(__name__)
gateway_av_bp = Blueprint('gateway_av', __name__)


def _log_error(message, error):
    """安全地记录错误，避免泄露敏感信息"""
    error_id = str(uuid.uuid4())[:8]
    logger.error("%s [错误ID: %s]", message, error_id)
    # 详细堆栈记录到安全日志（如果有配置的话）
    return error_id


@gateway_av_bp.route("/")
@login_required
def index():
    """网关病毒扫描管理页面"""
    return render_template("gateway_antivirus.html")


# ============================================================
# 全局配置 API
# ============================================================

@gateway_av_bp.route("/api/config")
@login_required
def api_get_config():
    """获取配置"""
    try:
        engine = get_gateway_antivirus()
        return jsonify({"status": "ok", "data": engine.get_config()})
    except Exception as e:
        error_id = _log_error("获取网关防病毒配置失败", e)
        return jsonify({"status": "error", "message": f"获取配置失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/config", methods=["POST"])
@admin_required
def api_update_config():
    """更新配置"""
    try:
        engine = get_gateway_antivirus()
        data = request.json or {}
        result = engine.update_config(data)
        return jsonify(result)
    except Exception as e:
        error_id = _log_error("更新网关防病毒配置失败", e)
        return jsonify({"status": "error", "message": f"更新配置失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/stats")
@login_required
def api_get_stats():
    """获取统计"""
    try:
        engine = get_gateway_antivirus()
        return jsonify({"status": "ok", "data": engine.get_stats()})
    except Exception as e:
        error_id = _log_error("获取网关防病毒统计失败", e)
        return jsonify({"status": "error", "message": f"获取统计失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/stats/clear", methods=["POST"])
@admin_required
def api_clear_stats():
    """清除统计"""
    try:
        engine = get_gateway_antivirus()
        return jsonify(engine.clear_stats())
    except Exception as e:
        error_id = _log_error("清除网关防病毒统计失败", e)
        return jsonify({"status": "error", "message": f"清除统计失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/logs")
@login_required
def api_get_logs():
    """获取病毒日志"""
    try:
        engine = get_gateway_antivirus()
        limit = request.args.get("limit", 100, type=int)
        protocol = request.args.get("protocol", None)
        logs = engine.get_virus_logs(limit=limit, protocol=protocol)
        return jsonify({"status": "ok", "data": logs})
    except Exception as e:
        error_id = _log_error("获取网关防病毒日志失败", e)
        return jsonify({"status": "error", "message": f"获取日志失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/update", methods=["POST"])
@admin_required
def api_update_virus_db():
    """更新病毒库"""
    try:
        engine = get_gateway_antivirus()
        result = engine.update_virus_database()
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        error_id = _log_error("更新病毒库失败", e)
        return jsonify({"status": "error", "message": f"更新病毒库失败，错误ID: {error_id}"}), 500


# ============================================================
# HTTP 代理扫描 API
# ============================================================

@gateway_av_bp.route("/api/http/status")
@login_required
def api_http_status():
    """获取 HTTP 扫描器状态"""
    try:
        scanner = get_http_scanner()
        return jsonify({"status": "ok", "data": scanner.get_status()})
    except Exception as e:
        error_id = _log_error("获取 HTTP 扫描器状态失败", e)
        return jsonify({"status": "error", "message": f"获取状态失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/http/configure", methods=["POST"])
@admin_required
def api_http_configure():
    """配置 HTTP 扫描器"""
    try:
        scanner = get_http_scanner()
        data = request.json or {}
        listen_port = data.get("listen_port", 3128)
        result = scanner.configure(listen_port=listen_port)
        return jsonify(result)
    except Exception as e:
        error_id = _log_error("配置 HTTP 扫描器失败", e)
        return jsonify({"status": "error", "message": f"配置失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/http/start", methods=["POST"])
@admin_required
def api_http_start():
    """启动 HTTP 扫描器"""
    try:
        scanner = get_http_scanner()
        scanner.configure()
        scanner.configure_icap()
        result = scanner.start_services()
        # 检查是否所有服务都启动成功
        failed = [k for k, v in result.items() if "error" in str(v)]
        if failed:
            return jsonify({
                "status": "error",
                "message": "部分服务启动失败: {}".format(", ".join(failed)),
                "data": result
            })
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        error_id = _log_error("启动 HTTP 扫描器失败", e)
        return jsonify({"status": "error", "message": f"启动失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/http/stop", methods=["POST"])
@admin_required
def api_http_stop():
    """停止 HTTP 扫描器"""
    try:
        scanner = get_http_scanner()
        result = scanner.stop_services()
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        error_id = _log_error("停止 HTTP 扫描器失败", e)
        return jsonify({"status": "error", "message": f"停止失败，错误ID: {error_id}"}), 500


# ============================================================
# FTP 扫描 API
# ============================================================

@gateway_av_bp.route("/api/ftp/status")
@login_required
def api_ftp_status():
    """获取 FTP 扫描器状态"""
    try:
        scanner = get_ftp_scanner()
        return jsonify({"status": "ok", "data": scanner.get_status()})
    except Exception as e:
        error_id = _log_error("获取 FTP 扫描器状态失败", e)
        return jsonify({"status": "error", "message": f"获取状态失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/ftp/configure", methods=["POST"])
@admin_required
def api_ftp_configure():
    """配置 FTP 扫描器"""
    try:
        scanner = get_ftp_scanner()
        data = request.json or {}
        listen_port = data.get("listen_port", 21)
        result = scanner.configure(listen_port=listen_port)
        return jsonify(result)
    except Exception as e:
        error_id = _log_error("配置 FTP 扫描器失败", e)
        return jsonify({"status": "error", "message": f"配置失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/ftp/start", methods=["POST"])
@admin_required
def api_ftp_start():
    """启动 FTP 扫描器"""
    try:
        scanner = get_ftp_scanner()
        scanner.configure()
        result = scanner.start_services()
        failed = [k for k, v in result.items() if "error" in str(v)]
        if failed:
            return jsonify({"status": "error", "message": "部分服务启动失败: {}".format(", ".join(failed)), "data": result})
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        error_id = _log_error("启动 FTP 扫描器失败", e)
        return jsonify({"status": "error", "message": f"启动失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/ftp/stop", methods=["POST"])
@admin_required
def api_ftp_stop():
    """停止 FTP 扫描器"""
    try:
        scanner = get_ftp_scanner()
        result = scanner.stop_services()
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        error_id = _log_error("停止 FTP 扫描器失败", e)
        return jsonify({"status": "error", "message": f"停止失败，错误ID: {error_id}"}), 500


# ============================================================
# SMTP 扫描 API
# ============================================================

@gateway_av_bp.route("/api/smtp/status")
@login_required
def api_smtp_status():
    """获取 SMTP 扫描器状态"""
    try:
        scanner = get_smtp_scanner()
        return jsonify({"status": "ok", "data": scanner.get_status()})
    except Exception as e:
        error_id = _log_error("获取 SMTP 扫描器状态失败", e)
        return jsonify({"status": "error", "message": f"获取状态失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/smtp/configure", methods=["POST"])
@admin_required
def api_smtp_configure():
    """配置 SMTP 扫描器"""
    try:
        scanner = get_smtp_scanner()
        data = request.json or {}
        domain = data.get("domain", "gatekeeper.local")
        hostname = data.get("hostname", "mail")
        result1 = scanner.configure_postfix(domain=domain, hostname=hostname)
        result2 = scanner.configure_amavis()
        return jsonify({"status": "ok", "postfix": result1, "amavis": result2})
    except Exception as e:
        error_id = _log_error("配置 SMTP 扫描器失败", e)
        return jsonify({"status": "error", "message": f"配置失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/smtp/start", methods=["POST"])
@admin_required
def api_smtp_start():
    """启动 SMTP 扫描器"""
    try:
        scanner = get_smtp_scanner()
        scanner.configure_postfix()
        scanner.configure_amavis()
        result = scanner.start_services()
        failed = [k for k, v in result.items() if "error" in str(v)]
        if failed:
            return jsonify({"status": "error", "message": "部分服务启动失败: {}".format(", ".join(failed)), "data": result})
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        error_id = _log_error("启动 SMTP 扫描器失败", e)
        return jsonify({"status": "error", "message": f"启动失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/smtp/stop", methods=["POST"])
@admin_required
def api_smtp_stop():
    """停止 SMTP 扫描器"""
    try:
        scanner = get_smtp_scanner()
        result = scanner.stop_services()
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        error_id = _log_error("停止 SMTP 扫描器失败", e)
        return jsonify({"status": "error", "message": f"停止失败，错误ID: {error_id}"}), 500


# ============================================================
# SMB 扫描 API
# ============================================================

@gateway_av_bp.route("/api/smb/status")
@login_required
def api_smb_status():
    """获取 SMB 扫描器状态"""
    try:
        scanner = get_smb_scanner()
        return jsonify({"status": "ok", "data": scanner.get_status()})
    except Exception as e:
        error_id = _log_error("获取 SMB 扫描器状态失败", e)
        return jsonify({"status": "error", "message": f"获取状态失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/smb/configure", methods=["POST"])
@admin_required
def api_smb_configure():
    """配置 SMB 扫描器"""
    try:
        scanner = get_smb_scanner()
        data = request.json or {}
        workgroup = data.get("workgroup", "WORKGROUP")
        share_name = data.get("share_name", "shared")
        share_path = data.get("share_path", "/srv/samba/shared")
        result = scanner.configure(workgroup=workgroup, share_name=share_name, share_path=share_path)
        return jsonify(result)
    except Exception as e:
        error_id = _log_error("配置 SMB 扫描器失败", e)
        return jsonify({"status": "error", "message": f"配置失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/smb/start", methods=["POST"])
@admin_required
def api_smb_start():
    """启动 SMB 扫描器"""
    try:
        scanner = get_smb_scanner()
        scanner.configure()
        result = scanner.start_services()
        failed = [k for k, v in result.items() if "error" in str(v)]
        if failed:
            return jsonify({"status": "error", "message": "部分服务启动失败: {}".format(", ".join(failed)), "data": result})
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        error_id = _log_error("启动 SMB 扫描器失败", e)
        return jsonify({"status": "error", "message": f"启动失败，错误ID: {error_id}"}), 500


@gateway_av_bp.route("/api/smb/stop", methods=["POST"])
@admin_required
def api_smb_stop():
    """停止 SMB 扫描器"""
    try:
        scanner = get_smb_scanner()
        result = scanner.stop_services()
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        error_id = _log_error("停止 SMB 扫描器失败", e)
        return jsonify({"status": "error", "message": f"停止失败，错误ID: {error_id}"}), 500
