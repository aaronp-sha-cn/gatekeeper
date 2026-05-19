"""
双出口Web路由 - 提供双出口接入管理的API接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from network.dual_wan import get_dual_wan, LoadBalanceMode
from web.app import _safe_error_message

logger = get_logger("dual_wan_routes")

dual_wan_bp = Blueprint("dual_wan", __name__)


@dual_wan_bp.route("/")
@login_required
def index():
    """双出口管理页面"""
    return render_template("dual_wan.html")


# ==================== WAN接口API ====================

@dual_wan_bp.route("/api/wan")
@login_required
def list_wan():
    """获取所有WAN接口"""
    try:
        manager = get_dual_wan()
        wans = manager.get_wan_interfaces()
        return jsonify({"status": "ok", "data": wans})
    except Exception as e:
        logger.error(f"获取WAN接口列表失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/wan", methods=["POST"])
@admin_required
def add_wan():
    """添加WAN接口"""
    try:
        data = request.get_json()
        manager = get_dual_wan()
        
        result = manager.add_wan_interface(
            name=data.get("name"),
            gateway=data.get("gateway"),
            ip_address=data.get("ip_address"),
            description=data.get("description", ""),
            weight=data.get("weight", 1),
            priority=data.get("priority", 1),
            check_targets=data.get("check_targets"),
        )
        
        if result["success"]:
            log_web_action(
                action="wan_add",
                module="dual_wan",
                detail=f"添加WAN接口: {data.get('name')}",
                result="success"
            )
            return jsonify({"status": "ok", "message": result["message"], "wan_id": result.get("wan_id")})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"添加WAN接口失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/wan/<wan_id>")
@login_required
def get_wan(wan_id):
    """获取单个WAN接口"""
    try:
        manager = get_dual_wan()
        wan = manager.get_wan_interface(wan_id)
        if wan:
            return jsonify({"status": "ok", "data": wan})
        else:
            return jsonify({"status": "error", "message": "WAN接口不存在"}), 404
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/wan/<wan_id>", methods=["PUT"])
@admin_required
def update_wan(wan_id):
    """更新WAN接口配置"""
    try:
        data = request.get_json()
        manager = get_dual_wan()
        
        result = manager.update_wan_interface(wan_id, **data)
        
        if result["success"]:
            log_web_action(
                action="wan_update",
                module="dual_wan",
                detail=f"更新WAN接口: {wan_id}",
                result="success"
            )
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"更新WAN接口失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/wan/<wan_id>", methods=["DELETE"])
@admin_required
def remove_wan(wan_id):
    """移除WAN接口"""
    try:
        manager = get_dual_wan()
        result = manager.remove_wan_interface(wan_id)
        
        if result["success"]:
            log_web_action(
                action="wan_remove",
                module="dual_wan",
                detail=f"移除WAN接口: {wan_id}",
                result="success"
            )
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"移除WAN接口失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/wan/<wan_id>/toggle", methods=["POST"])
@admin_required
def toggle_wan(wan_id):
    """启用/禁用WAN接口"""
    try:
        data = request.get_json(silent=True) or {}
        enabled = data.get("enabled", True)
        manager = get_dual_wan()
        result = manager.update_wan_interface(wan_id, enabled=enabled)
        
        if result["success"]:
            log_web_action(
                action="wan_toggle",
                module="dual_wan",
                detail=f"{'启用' if enabled else '禁用'}WAN接口: {wan_id}",
                result="success"
            )
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


# ==================== 策略路由API ====================

@dual_wan_bp.route("/api/policy")
@login_required
def list_policy():
    """获取所有策略路由规则"""
    try:
        manager = get_dual_wan()
        rules = manager.get_policy_rules()
        return jsonify({"status": "ok", "data": rules})
    except Exception as e:
        logger.error(f"获取策略路由列表失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/policy", methods=["POST"])
@admin_required
def add_policy():
    """添加策略路由规则"""
    try:
        data = request.get_json()
        manager = get_dual_wan()
        
        result = manager.add_policy_rule(
            name=data.get("name"),
            source_ip=data.get("source_ip"),
            wan_interface=data.get("wan_interface"),
            dest_ip=data.get("dest_ip", ""),
            protocol=data.get("protocol", ""),
            dest_port=data.get("dest_port", 0),
            description=data.get("description", ""),
        )
        
        if result["success"]:
            log_web_action(
                action="policy_add",
                module="dual_wan",
                detail=f"添加策略路由: {data.get('name')}",
                result="success"
            )
            return jsonify({"status": "ok", "message": result["message"], "rule_id": result.get("rule_id")})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"添加策略路由失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/policy/<rule_id>", methods=["DELETE"])
@admin_required
def remove_policy(rule_id):
    """移除策略路由规则"""
    try:
        manager = get_dual_wan()
        result = manager.remove_policy_rule(rule_id)
        
        if result["success"]:
            log_web_action(
                action="policy_remove",
                module="dual_wan",
                detail=f"移除策略路由: {rule_id}",
                result="success"
            )
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"移除策略路由失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/policy/<rule_id>/toggle", methods=["POST"])
@admin_required
def toggle_policy(rule_id):
    """启用/禁用策略路由规则"""
    try:
        data = request.get_json(silent=True) or {}
        enabled = data.get("enabled", True)
        manager = get_dual_wan()
        result = manager.toggle_policy_rule(rule_id, enabled)
        
        if result["success"]:
            log_web_action(
                action="policy_toggle",
                module="dual_wan",
                detail=f"{'启用' if enabled else '禁用'}策略路由: {rule_id}",
                result="success"
            )
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


# ==================== 负载均衡API ====================

@dual_wan_bp.route("/api/load-balance", methods=["GET"])
@login_required
def get_load_balance():
    """获取负载均衡配置"""
    try:
        manager = get_dual_wan()
        config = manager.get_config()
        return jsonify({"status": "ok", "data": config})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/load-balance", methods=["POST"])
@admin_required
def set_load_balance():
    """设置负载均衡模式"""
    try:
        data = request.get_json()
        mode = data.get("mode")
        manager = get_dual_wan()
        
        result = manager.set_load_balance_mode(mode)
        
        if result["success"]:
            log_web_action(
                action="load_balance_set",
                module="dual_wan",
                detail=f"设置负载均衡模式: {mode}",
                result="success"
            )
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"设置负载均衡模式失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/load-balance/modes")
@login_required
def get_load_balance_modes():
    """获取可用的负载均衡模式"""
    modes = [
        {"value": "failover", "label": "主备模式", "description": "主接口故障时自动切换到备用接口"},
        {"value": "round_robin", "label": "轮询模式", "description": "流量依次分配到各个接口"},
        {"value": "weighted", "label": "加权模式", "description": "根据权重比例分配流量"},
        {"value": "source_ip", "label": "源IP哈希", "description": "相同源IP的流量始终走同一接口"},
    ]
    return jsonify({"status": "ok", "data": modes})


# ==================== 健康检查API ====================

@dual_wan_bp.route("/api/health/start", methods=["POST"])
@admin_required
def start_health():
    """启动健康检查"""
    try:
        manager = get_dual_wan()
        result = manager.start_health_monitor()
        
        if result["success"]:
            log_web_action(
                action="health_start",
                module="dual_wan",
                detail="启动健康检查",
                result="success"
            )
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"启动健康检查失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/health/stop", methods=["POST"])
@admin_required
def stop_health():
    """停止健康检查"""
    try:
        manager = get_dual_wan()
        result = manager.stop_health_monitor()
        
        log_web_action(
            action="health_stop",
            module="dual_wan",
            detail="停止健康检查",
            result="success"
        )
        return jsonify({"status": "ok", "message": result["message"]})
        
    except Exception as e:
        logger.error(f"停止健康检查失败: {e}")
        return jsonify(_safe_error_message(e)), 500


# ==================== 故障切换API ====================

@dual_wan_bp.route("/api/failover/manual", methods=["POST"])
@admin_required
def manual_failover():
    """手动故障切换"""
    try:
        data = request.get_json()
        target_wan_id = data.get("wan_id")
        
        if not target_wan_id:
            return jsonify({"status": "error", "message": "请指定目标WAN接口"}), 400
        
        manager = get_dual_wan()
        result = manager.manual_failover(target_wan_id)
        
        if result["success"]:
            log_web_action(
                action="manual_failover",
                module="dual_wan",
                detail=f"手动切换到: {target_wan_id}",
                result="success"
            )
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"手动故障切换失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/failover/log")
@login_required
def get_failover_log():
    """获取故障切换日志"""
    try:
        limit = request.args.get("limit", 50, type=int)
        manager = get_dual_wan()
        logs = manager.get_failover_log(limit)
        return jsonify({"status": "ok", "data": logs})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


# ==================== 配置API ====================

@dual_wan_bp.route("/api/config", methods=["GET"])
@login_required
def get_config():
    """获取双出口配置"""
    try:
        manager = get_dual_wan()
        config = manager.get_config()
        return jsonify({"status": "ok", "data": config})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/config", methods=["POST"])
@admin_required
def update_config():
    """更新双出口配置"""
    try:
        data = request.get_json()
        manager = get_dual_wan()
        result = manager.update_config(**data)
        
        if result["success"]:
            log_web_action(
                action="config_update",
                module="dual_wan",
                detail="更新双出口配置",
                result="success"
            )
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"更新配置失败: {e}")
        return jsonify(_safe_error_message(e)), 500


# ==================== 统计信息API ====================

@dual_wan_bp.route("/api/stats")
@login_required
def stats():
    """获取统计信息"""
    try:
        manager = get_dual_wan()
        stats = manager.get_stats()
        return jsonify({"status": "ok", "data": stats})
    except Exception as e:
        logger.error(f"获取统计信息失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@dual_wan_bp.route("/api/status")
@login_required
def status():
    """获取整体状态"""
    try:
        manager = get_dual_wan()
        status = manager.get_status()
        return jsonify({"status": "ok", "data": status})
    except Exception as e:
        logger.error(f"获取状态失败: {e}")
        return jsonify(_safe_error_message(e)), 500
