"""
GateKeeper - LDAP/AD 身份集成 Web 路由
提供 LDAP/AD 身份认证管理的 API 接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required

from web.routes.auth import admin_required
from config.logging_config import get_logger
from core.audit import log_web_action
from security.auth_ldap import get_ldap_auth_provider
from web.app import _safe_error_message

logger = get_logger("auth_ldap_routes")

ldap_bp = Blueprint("auth_ldap", __name__, url_prefix="/ldap")


def _get_engine():
    return get_ldap_auth_provider()


@ldap_bp.route("/")
@login_required
def index():
    """LDAP身份集成管理页面"""
    return render_template("auth_ldap.html")


# ============================================================
# 配置管理
# ============================================================

@ldap_bp.route("/api/config", methods=["GET"])
@login_required
def api_get_config():
    """获取配置"""
    try:
        engine = _get_engine()
        config = engine.get_config()
        return jsonify({"status": "ok", "data": config})
    except Exception as e:
        logger.error("获取LDAP配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ldap_bp.route("/api/config", methods=["POST"])
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
            action="update_ldap_config",
            module="auth_ldap",
            detail="更新LDAP/AD身份集成配置",
        )
        return jsonify(result)
    except Exception as e:
        logger.error("更新LDAP配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 连接测试
# ============================================================

@ldap_bp.route("/api/test", methods=["POST"])
@admin_required
def api_test_connection():
    """测试 LDAP 连接"""
    try:
        engine = _get_engine()
        result = engine.test_connection()

        log_web_action(
            action="test_ldap_connection",
            module="auth_ldap",
            detail="测试LDAP连接: {}".format(
                result.get("status", "unknown")
            ),
        )
        return jsonify(result)
    except Exception as e:
        logger.error("测试LDAP连接失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 用户同步
# ============================================================

@ldap_bp.route("/api/sync", methods=["POST"])
@admin_required
def api_sync_users():
    """同步用户"""
    try:
        engine = _get_engine()
        result = engine.sync_users()

        log_web_action(
            action="sync_ldap_users",
            module="auth_ldap",
            detail="LDAP用户同步: {}".format(
                result.get("message", result.get("synced", 0))
            ),
        )
        return jsonify(result)
    except Exception as e:
        logger.error("同步LDAP用户失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 统计
# ============================================================

@ldap_bp.route("/api/stats")
@login_required
def api_get_stats():
    """获取统计"""
    try:
        engine = _get_engine()
        stats = engine.get_stats()
        return jsonify({"status": "ok", "data": stats})
    except Exception as e:
        logger.error("获取LDAP统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
