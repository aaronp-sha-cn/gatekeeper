"""
GateKeeper - QoS流量整形路由
提供QoS管理、规则CRUD、统计和预设策略的API接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.qos_manager import get_qos_manager, QoSRule
from web.app import _safe_error_message

logger = get_logger("qos_routes")

qos_bp = Blueprint("qos", __name__)


@qos_bp.route("/")
@login_required
def index():
    """QoS管理页面"""
    return render_template("qos.html")


# ============================================================
# 规则管理 API
# ============================================================

@qos_bp.route("/api/rules")
@login_required
def get_rules():
    """获取规则列表"""
    try:
        manager = get_qos_manager()
        rules = manager.get_rules()
        return jsonify({"status": "ok", "data": rules})
    except Exception as e:
        logger.error("获取QoS规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@qos_bp.route("/api/rules", methods=["POST"])
@admin_required
def add_rule():
    """添加规则"""
    try:
        data = request.get_json()
        name = data.get("name", "")
        interface = data.get("interface", "eth0")
        direction = data.get("direction", "egress")
        match_type = data.get("match_type", "ip")
        match_value = data.get("match_value", "")
        priority = data.get("priority", 50)
        bandwidth_limit = data.get("bandwidth_limit", 0)
        burst_limit = data.get("burst_limit", 0)
        latency_ms = data.get("latency_ms", 0)
        action = data.get("action", "shape")
        enabled = data.get("enabled", True)

        if not name:
            return jsonify({"status": "error", "message": "规则名称不能为空"}), 400

        valid_directions = ["ingress", "egress"]
        if direction not in valid_directions:
            return jsonify({"status": "error", "message": "方向必须是 ingress 或 egress"}), 400

        valid_match_types = ["ip", "port", "protocol", "mac", "app"]
        if match_type not in valid_match_types:
            return jsonify({"status": "error", "message": "无效的匹配类型"}), 400

        valid_actions = ["shape", "prioritize", "block"]
        if action not in valid_actions:
            return jsonify({"status": "error", "message": "无效的动作类型"}), 400

        if not (0 <= priority <= 100):
            return jsonify({"status": "error", "message": "优先级必须在 0-100 之间"}), 400

        rule = QoSRule(
            name=name,
            interface=interface,
            direction=direction,
            match_type=match_type,
            match_value=match_value,
            priority=int(priority),
            bandwidth_limit=float(bandwidth_limit),
            burst_limit=float(burst_limit),
            latency_ms=float(latency_ms),
            action=action,
            enabled=enabled,
        )

        manager = get_qos_manager()
        created = manager.add_rule(rule)

        log_web_action(
            action="add_rule",
            module="qos",
            detail="添加QoS规则: {}".format(name),
            request_data={
                "name": name, "interface": interface, "direction": direction,
                "match_type": match_type, "match_value": match_value,
                "priority": priority, "action": action,
            },
        )

        return jsonify({"status": "ok", "data": created.to_dict()})
    except Exception as e:
        logger.error("添加QoS规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@qos_bp.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@admin_required
def delete_rule(rule_id):
    """删除规则"""
    try:
        manager = get_qos_manager()
        success = manager.remove_rule(rule_id)

        if success:
            log_web_action(
                action="delete_rule",
                module="qos",
                detail="删除QoS规则 ID: {}".format(rule_id),
            )
            return jsonify({"status": "ok", "message": "规则已删除"})
        else:
            return jsonify({"status": "error", "message": "规则不存在"}), 404
    except Exception as e:
        logger.error("删除QoS规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@qos_bp.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@admin_required
def toggle_rule(rule_id):
    """启用/禁用规则"""
    try:
        data = request.get_json()
        enabled = data.get("enabled", True)

        manager = get_qos_manager()
        success = manager.toggle_rule(rule_id, enabled)

        if success:
            state = "启用" if enabled else "禁用"
            log_web_action(
                action="toggle_rule",
                module="qos",
                detail="{}QoS规则 ID: {}".format(state, rule_id),
            )
            return jsonify({"status": "ok", "message": "规则已{}".format(state)})
        else:
            return jsonify({"status": "error", "message": "规则不存在"}), 404
    except Exception as e:
        logger.error("切换QoS规则状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 规则应用 API
# ============================================================

@qos_bp.route("/api/apply", methods=["POST"])
@admin_required
def apply_rules():
    """应用所有规则到系统"""
    try:
        manager = get_qos_manager()
        result = manager.apply_rules()

        log_web_action(
            action="apply_rules",
            module="qos",
            detail="应用QoS规则: {}".format(result["message"]),
        )

        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        logger.error("应用QoS规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@qos_bp.route("/api/clear", methods=["POST"])
@admin_required
def clear_rules():
    """清除tc规则"""
    try:
        manager = get_qos_manager()
        result = manager.remove_tc_rules()

        log_web_action(
            action="clear_rules",
            module="qos",
            detail="清除tc规则: {}".format(result["message"]),
        )

        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        logger.error("清除tc规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 统计 API
# ============================================================

@qos_bp.route("/api/stats")
@login_required
def get_stats():
    """获取流量统计"""
    try:
        interface = request.args.get("interface")
        manager = get_qos_manager()
        stats = manager.get_stats(interface=interface)
        return jsonify({"status": "ok", "data": stats})
    except Exception as e:
        logger.error("获取QoS统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@qos_bp.route("/api/bandwidth")
@login_required
def get_bandwidth():
    """获取接口带宽使用"""
    try:
        interface = request.args.get("interface", "eth0")
        manager = get_qos_manager()
        bw = manager.get_bandwidth_usage(interface)
        return jsonify({"status": "ok", "data": bw})
    except Exception as e:
        logger.error("获取带宽使用失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@qos_bp.route("/api/bandwidth/all")
@login_required
def get_all_bandwidth():
    """获取所有接口带宽使用"""
    try:
        manager = get_qos_manager()
        interfaces = manager.get_available_interfaces()
        results = []
        for iface in interfaces:
            bw = manager.get_bandwidth_usage(iface)
            results.append(bw)
        return jsonify({"status": "ok", "data": results})
    except Exception as e:
        logger.error("获取所有接口带宽失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# tc状态 API
# ============================================================

@qos_bp.route("/api/tc-status")
@login_required
def get_tc_status():
    """获取tc规则状态"""
    try:
        interface = request.args.get("interface")
        manager = get_qos_manager()
        status = manager.get_tc_status(interface=interface)
        return jsonify({"status": "ok", "data": status})
    except Exception as e:
        logger.error("获取tc状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@qos_bp.route("/api/tc-history")
@login_required
def get_tc_history():
    """获取tc命令执行历史"""
    try:
        manager = get_qos_manager()
        history = manager.get_tc_history()
        return jsonify({"status": "ok", "data": history})
    except Exception as e:
        logger.error("获取tc历史失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 预设策略 API
# ============================================================

@qos_bp.route("/api/presets")
@login_required
def get_presets():
    """获取预设策略列表"""
    try:
        manager = get_qos_manager()
        presets = manager.get_presets()
        return jsonify({"status": "ok", "data": presets})
    except Exception as e:
        logger.error("获取预设策略失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@qos_bp.route("/api/presets/<preset_name>", methods=["POST"])
@admin_required
def apply_preset(preset_name):
    """应用预设策略"""
    try:
        data = request.get_json() or {}
        interface = data.get("interface", "eth0")

        manager = get_qos_manager()
        result = manager.apply_preset(preset_name, interface=interface)

        if result["success"]:
            log_web_action(
                action="apply_preset",
                module="qos",
                detail="应用预设策略: {}".format(preset_name),
                request_data={"preset": preset_name, "interface": interface},
            )

        return jsonify({"status": "ok" if result["success"] else "error",
                        "data": result})
    except Exception as e:
        logger.error("应用预设策略失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 接口 API
# ============================================================

@qos_bp.route("/api/interfaces")
@login_required
def get_interfaces():
    """获取可用网络接口列表"""
    try:
        manager = get_qos_manager()
        interfaces = manager.get_available_interfaces()
        return jsonify({"status": "ok", "data": interfaces})
    except Exception as e:
        logger.error("获取网络接口列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
