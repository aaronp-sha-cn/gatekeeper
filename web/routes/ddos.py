"""
GateKeeper - DDoS防护路由
提供DDoS防护管理的API接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.ddos_protector import get_ddos_protector
from web.app import _safe_error_message

logger = get_logger("ddos_routes")

ddos_bp = Blueprint("ddos", __name__)


@ddos_bp.route("/")
@login_required
def index():
    """DDoS防护页面"""
    return render_template("ddos.html")


@ddos_bp.route("/api/rules")
@login_required
def get_rules():
    """获取规则列表"""
    try:
        protector = get_ddos_protector()
        rules = protector.get_rules()
        return jsonify({"status": "ok", "data": rules})
    except Exception as e:
        logger.error("获取DDoS规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ddos_bp.route("/api/rules", methods=["POST"])
@admin_required
def add_rule():
    """添加规则"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求体不能为空"}), 400
        name = data.get("name")
        rule_type = data.get("rule_type")
        params = data.get("params", {})
        enabled = data.get("enabled", True)

        if not name or not rule_type:
            return jsonify({"status": "error", "message": "规则名称和类型不能为空"}), 400

        valid_types = [
            "syn_flood", "udp_flood", "icmp_flood",
            "connection_limit", "rate_limit", "bandwidth_limit", "fragment_flood",
        ]
        if rule_type not in valid_types:
            return jsonify({"status": "error", "message": "无效的规则类型"}), 400

        # 设置默认参数
        default_params = {
            "threshold": 100,
            "action": "block",
            "duration": 3600,
            "burst_size": 10,
        }
        default_params.update(params)

        protector = get_ddos_protector()
        rule = protector.add_rule(name=name, rule_type=rule_type,
                                  params=default_params, enabled=enabled)

        log_web_action(
            action="add_rule",
            module="ddos",
            detail="添加DDoS防护规则: {}".format(name),
            request_data={"name": name, "rule_type": rule_type},
        )

        return jsonify({"status": "ok", "data": rule.to_dict()})
    except Exception as e:
        logger.error("添加DDoS规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ddos_bp.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@admin_required
def delete_rule(rule_id):
    """删除规则"""
    try:
        protector = get_ddos_protector()
        success = protector.remove_rule(rule_id)

        if success:
            log_web_action(
                action="delete_rule",
                module="ddos",
                detail="删除DDoS防护规则 ID: {}".format(rule_id),
            )
            return jsonify({"status": "ok", "message": "规则已删除"})
        else:
            return jsonify({"status": "error", "message": "规则不存在"}), 404
    except Exception as e:
        logger.error("删除DDoS规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ddos_bp.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@admin_required
def toggle_rule(rule_id):
    """启用/禁用规则"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求体不能为空"}), 400
        enabled = data.get("enabled", True)

        protector = get_ddos_protector()
        success = protector.toggle_rule(rule_id, enabled)

        if success:
            state = "启用" if enabled else "禁用"
            log_web_action(
                action="toggle_rule",
                module="ddos",
                detail="{}DDoS防护规则 ID: {}".format(state, rule_id),
            )
            return jsonify({"status": "ok", "message": "规则已{}".format(state)})
        else:
            return jsonify({"status": "error", "message": "规则不存在"}), 404
    except Exception as e:
        logger.error("切换DDoS规则状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ddos_bp.route("/api/stats")
@login_required
def get_stats():
    """获取实时统计"""
    try:
        protector = get_ddos_protector()
        stats = protector.get_stats()
        return jsonify({"status": "ok", "data": stats})
    except Exception as e:
        logger.error("获取DDoS统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ddos_bp.route("/api/blacklist")
@login_required
def get_blacklist():
    """获取黑名单列表"""
    try:
        protector = get_ddos_protector()
        blacklist = protector.get_blacklist()
        return jsonify({
            "status": "ok",
            "data": {"count": len(blacklist), "items": blacklist},
        })
    except Exception as e:
        logger.error("获取黑名单失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ddos_bp.route("/api/blacklist", methods=["POST"])
@admin_required
def add_blacklist():
    """手动拉黑IP"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求体不能为空"}), 400
        ip = data.get("ip")
        reason = data.get("reason", "手动拉黑")
        duration = data.get("duration", 3600)

        if not ip:
            return jsonify({"status": "error", "message": "IP地址不能为空"}), 400

        protector = get_ddos_protector()
        success = protector.add_to_blacklist(ip, reason=reason, duration=duration)

        if success:
            log_web_action(
                action="add_blacklist",
                module="ddos",
                detail="手动拉黑IP: {}".format(ip),
                request_data={"ip": ip, "reason": reason, "duration": duration},
            )
            return jsonify({"status": "ok", "message": "IP {} 已加入黑名单".format(ip)})
        else:
            return jsonify({"status": "error", "message": "该IP在白名单中，无法拉黑"}), 400
    except Exception as e:
        logger.error("添加黑名单失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ddos_bp.route("/api/blacklist/<ip>", methods=["DELETE"])
@admin_required
def remove_blacklist(ip):
    """从黑名单移除"""
    try:
        protector = get_ddos_protector()
        success = protector.remove_blacklist(ip)

        if success:
            log_web_action(
                action="remove_blacklist",
                module="ddos",
                detail="从黑名单移除IP: {}".format(ip),
            )
            return jsonify({"status": "ok", "message": "IP {} 已从黑名单移除".format(ip)})
        else:
            return jsonify({"status": "error", "message": "IP不在黑名单中"}), 404
    except Exception as e:
        logger.error("移除黑名单失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ddos_bp.route("/api/whitelist", methods=["POST"])
@admin_required
def add_whitelist():
    """加入白名单"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求体不能为空"}), 400
        ip = data.get("ip")

        if not ip:
            return jsonify({"status": "error", "message": "IP地址不能为空"}), 400

        protector = get_ddos_protector()
        success = protector.whitelist_ip(ip)

        if success:
            log_web_action(
                action="add_whitelist",
                module="ddos",
                detail="加入白名单IP: {}".format(ip),
                request_data={"ip": ip},
            )
            return jsonify({"status": "ok", "message": "IP {} 已加入白名单".format(ip)})
        else:
            return jsonify({"status": "error", "message": "操作失败"}), 400
    except Exception as e:
        logger.error("添加白名单失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ddos_bp.route("/api/whitelist/<ip>", methods=["DELETE"])
@admin_required
def remove_whitelist(ip):
    """从白名单移除"""
    try:
        protector = get_ddos_protector()
        success = protector.remove_whitelist(ip)

        if success:
            log_web_action(
                action="remove_whitelist",
                module="ddos",
                detail="从白名单移除IP: {}".format(ip),
            )
            return jsonify({"status": "ok", "message": "IP {} 已从白名单移除".format(ip)})
        else:
            return jsonify({"status": "error", "message": "IP不在白名单中"}), 404
    except Exception as e:
        logger.error("移除白名单失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ddos_bp.route("/api/top_attackers")
@login_required
def get_top_attackers():
    """获取攻击者TOP榜"""
    try:
        limit = request.args.get("limit", 20, type=int)
        protector = get_ddos_protector()
        attackers = protector.get_top_attackers(limit=limit)
        return jsonify({
            "status": "ok",
            "data": {"count": len(attackers), "items": attackers},
        })
    except Exception as e:
        logger.error("获取攻击者TOP榜失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
