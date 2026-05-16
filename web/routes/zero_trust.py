"""
GateKeeper - 零信任架构 Web 路由
提供零信任策略管理的 API 接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required

from web.routes.auth import admin_required
from config.logging_config import get_logger
from core.audit import log_web_action
from security.zero_trust import get_zero_trust_engine
from web.app import _safe_error_message

logger = get_logger("zero_trust_routes")

zta_bp = Blueprint("zero_trust", __name__, url_prefix="/zta")


def _get_engine():
    return get_zero_trust_engine()


@zta_bp.route("/")
@login_required
def index():
    """零信任架构管理页面"""
    return render_template("zero_trust.html")


# ============================================================
# 配置管理
# ============================================================

@zta_bp.route("/api/config", methods=["GET"])
@login_required
def api_get_config():
    """获取配置"""
    try:
        engine = _get_engine()
        config = engine.get_config()
        return jsonify({"status": "ok", "data": config})
    except Exception as e:
        logger.error("获取零信任配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@zta_bp.route("/api/config", methods=["POST"])
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
            action="update_zta_config",
            module="zero_trust",
            detail="更新零信任策略配置",
        )
        return jsonify(result)
    except Exception as e:
        logger.error("更新零信任配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 策略管理
# ============================================================

@zta_bp.route("/api/policies", methods=["GET"])
@login_required
def api_get_policies():
    """获取策略列表"""
    try:
        engine = _get_engine()
        policies = engine.get_policies()
        return jsonify({"status": "ok", "data": policies})
    except Exception as e:
        logger.error("获取零信任策略列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@zta_bp.route("/api/policies", methods=["POST"])
@admin_required
def api_add_policy():
    """添加策略"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        engine = _get_engine()
        result = engine.add_policy(data)

        if result.get("status") == "ok":
            log_web_action(
                action="add_zta_policy",
                module="zero_trust",
                detail="添加零信任策略: {}".format(data.get("name", "")),
            )
        return jsonify(result)
    except Exception as e:
        logger.error("添加零信任策略失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@zta_bp.route("/api/policies/<int:policy_id>", methods=["PUT"])
@admin_required
def api_update_policy(policy_id):
    """更新策略"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        engine = _get_engine()
        result = engine.update_policy(policy_id, data)

        if result.get("status") == "ok":
            log_web_action(
                action="update_zta_policy",
                module="zero_trust",
                detail="更新零信任策略: ID={}".format(policy_id),
            )
        return jsonify(result)
    except Exception as e:
        logger.error("更新零信任策略失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@zta_bp.route("/api/policies/<int:policy_id>", methods=["DELETE"])
@admin_required
def api_delete_policy(policy_id):
    """删除策略"""
    try:
        engine = _get_engine()
        result = engine.delete_policy(policy_id)

        if result.get("status") == "ok":
            log_web_action(
                action="delete_zta_policy",
                module="zero_trust",
                detail="删除零信任策略: ID={}".format(policy_id),
            )
        return jsonify(result)
    except Exception as e:
        logger.error("删除零信任策略失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 信任评估
# ============================================================

@zta_bp.route("/api/evaluate", methods=["POST"])
@login_required
def api_evaluate():
    """评估信任等级"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        engine = _get_engine()
        result = engine.evaluate(data)
        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        logger.error("评估信任等级失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 日志与统计
# ============================================================

@zta_bp.route("/api/logs")
@login_required
def api_get_logs():
    """获取访问日志"""
    try:
        engine = _get_engine()
        limit = request.args.get("limit", 100, type=int)
        logs = engine.get_access_logs(limit=limit)
        return jsonify({"status": "ok", "data": logs})
    except Exception as e:
        logger.error("获取零信任访问日志失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@zta_bp.route("/api/stats")
@login_required
def api_get_stats():
    """获取统计"""
    try:
        engine = _get_engine()
        stats = engine.get_stats()
        return jsonify({"status": "ok", "data": stats})
    except Exception as e:
        logger.error("获取零信任统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
