"""
GateKeeper - SSL 解密检查 Web 路由
提供 SSL/TLS 解密检查的 API 接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required

from web.routes.auth import admin_required
from config.logging_config import get_logger
from core.audit import log_web_action
from security.ssl_inspector import get_ssl_inspector
from web.app import _safe_error_message

logger = get_logger("ssl_inspector_routes")

ssl_bp = Blueprint("ssl_inspector", __name__, url_prefix="/ssl")


def _get_engine():
    return get_ssl_inspector()


@ssl_bp.route("/")
@login_required
def index():
    """SSL解密检查管理页面"""
    return render_template("ssl_inspector.html")


# ============================================================
# 配置管理
# ============================================================

@ssl_bp.route("/api/config", methods=["GET"])
@login_required
def api_get_config():
    """获取配置"""
    try:
        engine = _get_engine()
        config = engine.get_config()
        return jsonify({"status": "ok", "data": config})
    except Exception as e:
        logger.error("获取SSL检查配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ssl_bp.route("/api/config", methods=["POST"])
@admin_required
def api_update_config():
    """更新配置"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        engine = _get_engine()
        result = engine.configure(data)

        log_web_action(
            action="update_ssl_config",
            module="ssl_inspector",
            detail="更新SSL解密检查配置",
        )
        return jsonify(result)
    except Exception as e:
        logger.error("更新SSL检查配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 启动/停止
# ============================================================

@ssl_bp.route("/api/start", methods=["POST"])
@admin_required
def api_start():
    """启动 SSL 解密代理"""
    try:
        engine = _get_engine()
        result = engine.start()

        log_web_action(
            action="start_ssl_inspector",
            module="ssl_inspector",
            detail="启动SSL解密代理",
        )
        return jsonify(result)
    except Exception as e:
        logger.error("启动SSL解密代理失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ssl_bp.route("/api/stop", methods=["POST"])
@admin_required
def api_stop():
    """停止 SSL 解密代理"""
    try:
        engine = _get_engine()
        result = engine.stop()

        log_web_action(
            action="stop_ssl_inspector",
            module="ssl_inspector",
            detail="停止SSL解密代理",
        )
        return jsonify(result)
    except Exception as e:
        logger.error("停止SSL解密代理失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 状态与统计
# ============================================================

@ssl_bp.route("/api/status")
@login_required
def api_get_status():
    """获取状态"""
    try:
        engine = _get_engine()
        status = engine.get_status()
        return jsonify({"status": "ok", "data": status})
    except Exception as e:
        logger.error("获取SSL检查状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ssl_bp.route("/api/stats")
@login_required
def api_get_stats():
    """获取统计"""
    try:
        engine = _get_engine()
        stats = engine.get_stats()
        return jsonify({"status": "ok", "data": stats})
    except Exception as e:
        logger.error("获取SSL检查统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ssl_bp.route("/api/logs")
@login_required
def api_get_logs():
    """获取日志"""
    try:
        engine = _get_engine()
        limit = request.args.get("limit", 100, type=int)
        logs = engine.get_ssl_logs(limit=limit)
        return jsonify({"status": "ok", "data": logs})
    except Exception as e:
        logger.error("获取SSL检查日志失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# CA 证书管理
# ============================================================

@ssl_bp.route("/api/generate-ca", methods=["POST"])
@admin_required
def api_generate_ca():
    """生成 CA 证书"""
    try:
        engine = _get_engine()
        result = engine.generate_ca()

        log_web_action(
            action="generate_ca",
            module="ssl_inspector",
            detail="生成SSL解密CA证书",
        )
        return jsonify(result)
    except Exception as e:
        logger.error("生成CA证书失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
