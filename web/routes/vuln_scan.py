"""
GateKeeper - 漏洞扫描路由
提供漏洞扫描管理的API接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user

from web.routes.auth import admin_required

from core.database import db_manager
from config.logging_config import get_logger
from core.audit import log_web_action
from security.vuln_scanner import get_vuln_scanner
from web.app import _safe_error_message

logger = get_logger("vuln_scan_routes")

vuln_scan_bp = Blueprint("vuln_scan", __name__, url_prefix="/vuln-scan")


@vuln_scan_bp.route("/")
@login_required
def index():
    """漏洞扫描页面"""
    return render_template("vuln_scan.html")


@vuln_scan_bp.route("/api/scan", methods=["POST"])
@admin_required
def start_scan():
    """启动漏洞扫描"""
    try:
        data = request.get_json()
        target = data.get("target", "").strip()
        scan_type = data.get("scan_type", "quick")
        ports = data.get("ports")

        if not target:
            return jsonify({"status": "error", "message": "扫描目标不能为空"}), 400

        # 验证扫描类型
        if scan_type not in ("quick", "full", "custom"):
            return jsonify({"status": "error", "message": "无效的扫描类型"}), 400

        # 解析自定义端口
        port_list = None
        if scan_type == "custom" and ports:
            try:
                port_list = []
                for p in str(ports).split(","):
                    p = p.strip()
                    if "-" in p:
                        start, end = p.split("-", 1)
                        port_list.extend(range(int(start), int(end) + 1))
                    else:
                        port_list.append(int(p))
            except (ValueError, AttributeError):
                return jsonify({"status": "error", "message": "无效的端口格式"}), 400

        scanner = get_vuln_scanner()
        result = scanner.start_scan(
            target=target,
            scan_type=scan_type,
            ports=port_list,
            username=current_user.username if current_user.is_authenticated else "system",
        )

        log_web_action(
            action="start_scan",
            module="vuln_scan",
            detail="启动漏洞扫描: target={}, type={}".format(target, scan_type),
        )

        return jsonify(result)

    except Exception as e:
        logger.error("启动扫描失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vuln_scan_bp.route("/api/scan/status")
@login_required
def get_scan_status():
    """获取当前扫描状态"""
    try:
        scanner = get_vuln_scanner()
        status = scanner.get_scan_status()
        return jsonify({"status": "ok", "data": status})
    except Exception as e:
        logger.error("获取扫描状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vuln_scan_bp.route("/api/scan/stop", methods=["POST"])
@admin_required
def stop_scan():
    """停止当前扫描"""
    try:
        scanner = get_vuln_scanner()
        result = scanner.stop_scan()

        log_web_action(
            action="stop_scan",
            module="vuln_scan",
            detail="停止漏洞扫描",
        )

        return jsonify(result)
    except Exception as e:
        logger.error("停止扫描失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vuln_scan_bp.route("/api/results")
@login_required
def get_results():
    """获取扫描结果（分页，支持按严重度过滤）"""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        severity = request.args.get("severity")
        target = request.args.get("target")

        scanner = get_vuln_scanner()

        if target:
            data = scanner.get_latest_results(
                target=target,
                severity=severity,
                page=page,
                per_page=per_page,
            )
        else:
            data = scanner.get_all_results(
                severity=severity,
                page=page,
                per_page=per_page,
            )

        return jsonify({"status": "ok", "data": data})
    except Exception as e:
        logger.error("获取扫描结果失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vuln_scan_bp.route("/api/history")
@login_required
def get_history():
    """获取扫描历史列表"""
    try:
        limit = request.args.get("limit", 20, type=int)
        scanner = get_vuln_scanner()
        history = scanner.get_scan_history(limit=limit)
        return jsonify({"status": "ok", "data": history})
    except Exception as e:
        logger.error("获取扫描历史失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vuln_scan_bp.route("/api/stats")
@login_required
def get_stats():
    """获取漏洞扫描统计信息"""
    try:
        scanner = get_vuln_scanner()
        stats = scanner.get_stats()
        return jsonify({"status": "ok", "data": stats})
    except Exception as e:
        logger.error("获取统计信息失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
