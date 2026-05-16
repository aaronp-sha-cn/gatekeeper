"""
GateKeeper - 网络隔离路由
提供网络隔离管理的Web API接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.network_isolation import get_isolation_manager
from web.app import _safe_error_message

logger = get_logger("isolation_routes")

isolation_bp = Blueprint("isolation", __name__, url_prefix="/isolation")


@isolation_bp.route("/")
@login_required
def index():
    """网络隔离管理页面"""
    return render_template("isolation.html")


# ============================================================
# 统计与状态
# ============================================================

@isolation_bp.route("/api/status", methods=["GET"])
@login_required
def get_status():
    """获取隔离状态概览"""
    try:
        manager = get_isolation_manager()
        status = manager.get_status()
        return jsonify({"status": "ok", "data": status})
    except Exception as e:
        logger.error("获取隔离状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@isolation_bp.route("/api/topology", methods=["GET"])
@login_required
def get_topology():
    """获取区域拓扑"""
    try:
        manager = get_isolation_manager()
        topology = manager.get_topology()
        return jsonify({"status": "ok", "data": topology})
    except Exception as e:
        logger.error("获取拓扑数据失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 区域管理
# ============================================================

@isolation_bp.route("/api/zones", methods=["GET"])
@login_required
def get_zones():
    """获取所有隔离区域"""
    try:
        manager = get_isolation_manager()
        zones = manager.get_zones()
        return jsonify({
            "status": "ok",
            "data": {"zones": zones, "total": len(zones)},
        })
    except Exception as e:
        logger.error("获取隔离区域列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@isolation_bp.route("/api/zones", methods=["POST"])
@admin_required
def create_zone():
    """创建隔离区域"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        manager = get_isolation_manager()
        result = manager.create_zone(data)

        if result["status"] == "ok":
            log_web_action(
                action="create_zone",
                module="isolation",
                detail="创建隔离区域: {}".format(data.get("name", "")),
                request_data=data,
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("创建隔离区域失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@isolation_bp.route("/api/zones/<zone_id>", methods=["PUT"])
@admin_required
def update_zone(zone_id):
    """更新隔离区域"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        manager = get_isolation_manager()
        result = manager.update_zone(zone_id, data)

        if result["status"] == "ok":
            log_web_action(
                action="update_zone",
                module="isolation",
                detail="更新隔离区域: {}".format(zone_id),
                request_data=data,
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("更新隔离区域失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@isolation_bp.route("/api/zones/<zone_id>", methods=["DELETE"])
@admin_required
def delete_zone(zone_id):
    """删除隔离区域"""
    try:
        manager = get_isolation_manager()
        result = manager.delete_zone(zone_id)

        if result["status"] == "ok":
            log_web_action(
                action="delete_zone",
                module="isolation",
                detail="删除隔离区域: {}".format(zone_id),
            )

        status_code = 200 if result["status"] == "ok" else 404
        return jsonify(result), status_code
    except Exception as e:
        logger.error("删除隔离区域失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 规则管理
# ============================================================

@isolation_bp.route("/api/rules", methods=["GET"])
@login_required
def get_rules():
    """获取所有隔离规则"""
    try:
        manager = get_isolation_manager()
        rules = manager.get_rules()
        return jsonify({
            "status": "ok",
            "data": {"rules": rules, "total": len(rules)},
        })
    except Exception as e:
        logger.error("获取隔离规则列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@isolation_bp.route("/api/rules", methods=["POST"])
@admin_required
def add_rule():
    """添加隔离规则"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        manager = get_isolation_manager()
        result = manager.add_rule(data)

        if result["status"] == "ok":
            log_web_action(
                action="add_rule",
                module="isolation",
                detail="添加隔离规则: {}".format(data.get("name", "")),
                request_data=data,
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("添加隔离规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@isolation_bp.route("/api/rules/<rule_id>", methods=["DELETE"])
@admin_required
def remove_rule(rule_id):
    """删除隔离规则"""
    try:
        manager = get_isolation_manager()
        result = manager.remove_rule(rule_id)

        if result["status"] == "ok":
            log_web_action(
                action="remove_rule",
                module="isolation",
                detail="删除隔离规则: {}".format(rule_id),
            )

        status_code = 200 if result["status"] == "ok" else 404
        return jsonify(result), status_code
    except Exception as e:
        logger.error("删除隔离规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@isolation_bp.route("/api/rules/<rule_id>/toggle", methods=["POST"])
@admin_required
def toggle_rule(rule_id):
    """启用/禁用隔离规则"""
    try:
        data = request.get_json()
        enabled = data.get("enabled", True) if data else True

        manager = get_isolation_manager()
        result = manager.toggle_rule(rule_id, enabled)

        if result["status"] == "ok":
            action_text = "启用" if enabled else "禁用"
            log_web_action(
                action="toggle_rule",
                module="isolation",
                detail="{}隔离规则: {}".format(action_text, rule_id),
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("切换隔离规则状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 流量检查
# ============================================================

@isolation_bp.route("/api/check-traffic", methods=["POST"])
@admin_required
def check_traffic():
    """检查流量是否允许"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        src_zone = data.get("src_zone", "")
        dst_zone = data.get("dst_zone", "")
        protocol = data.get("protocol", "tcp")
        port = data.get("port", 0)

        if not src_zone or not dst_zone:
            return jsonify({"status": "error", "message": "源区域和目标区域不能为空"}), 400

        manager = get_isolation_manager()
        result = manager.check_traffic(src_zone, dst_zone, protocol, port)

        log_web_action(
            action="check_traffic",
            module="isolation",
            detail="流量检查: {} -> {} ({}:{}) - {}".format(
                src_zone, dst_zone, protocol, port,
                "允许" if result["allowed"] else "拒绝"),
        )

        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        logger.error("流量检查失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 应用规则
# ============================================================

@isolation_bp.route("/api/apply", methods=["POST"])
@admin_required
def apply_isolation():
    """应用隔离规则到iptables"""
    try:
        manager = get_isolation_manager()
        result = manager.apply_isolation()

        log_web_action(
            action="apply_isolation",
            module="isolation",
            detail="应用网络隔离规则",
            result="success" if result["status"] == "ok" else "failure",
        )

        status_code = 200 if result["status"] == "ok" else 500
        return jsonify(result), status_code
    except Exception as e:
        logger.error("应用隔离规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 预设模板
# ============================================================

@isolation_bp.route("/api/presets", methods=["GET"])
@login_required
def get_presets():
    """获取可用预设列表"""
    try:
        manager = get_isolation_manager()
        presets = manager.get_presets()
        return jsonify({"status": "ok", "data": presets})
    except Exception as e:
        logger.error("获取预设列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@isolation_bp.route("/api/presets/<preset_name>", methods=["POST"])
@admin_required
def apply_preset(preset_name):
    """应用预设模板"""
    try:
        manager = get_isolation_manager()
        result = manager.apply_preset(preset_name)

        if result["status"] == "ok":
            log_web_action(
                action="apply_preset",
                module="isolation",
                detail="应用预设模板: {}".format(preset_name),
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("应用预设模板失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
