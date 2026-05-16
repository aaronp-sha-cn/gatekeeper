"""
GateKeeper - 高可用管理路由
提供HA集群配置、状态监控、故障切换和配置同步的API接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required

from web.routes.auth import admin_required, super_admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.ha_manager import get_ha_manager
from web.app import _safe_error_message

logger = get_logger("ha_routes")

ha_bp = Blueprint("ha", __name__, url_prefix="/ha")


def _get_manager():
    return get_ha_manager()


@ha_bp.route("/")
@login_required
def index():
    """高可用管理页面"""
    return render_template("ha.html")


@ha_bp.route("/api/status")
@login_required
def get_status():
    """获取HA状态"""
    try:
        manager = _get_manager()
        status = manager.get_status()
        return jsonify({
            "status": "ok",
            "data": status,
        })
    except Exception as e:
        logger.error("获取HA状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ha_bp.route("/api/configure", methods=["POST"])
@admin_required
def configure():
    """配置HA参数"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        mode = data.get("mode", "").strip()
        peer_ip = data.get("peer_ip", "").strip()
        vip = data.get("vip", "").strip()
        interface = data.get("interface", "").strip()

        if not mode:
            return jsonify({"status": "error", "message": "缺少mode参数"}), 400
        if not peer_ip:
            return jsonify({"status": "error", "message": "缺少peer_ip参数"}), 400

        valid_modes = ["active-passive", "active-active"]
        if mode not in valid_modes:
            return jsonify({
                "status": "error",
                "message": "无效的模式，可选: {}".format(", ".join(valid_modes)),
            }), 400

        manager = _get_manager()
        result = manager.configure(
            mode=mode, peer_ip=peer_ip, vip=vip, interface=interface,
        )

        log_web_action(
            action="configure_ha",
            module="ha",
            detail="配置HA: mode={}, peer_ip={}, vip={}, interface={}".format(
                mode, peer_ip, vip, interface),
        )
        return jsonify({
            "status": "ok",
            "message": "HA配置已更新",
            "data": result,
        })
    except Exception as e:
        logger.error("配置HA失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ha_bp.route("/api/start", methods=["POST"])
@admin_required
def start_ha():
    """启动HA服务"""
    try:
        manager = _get_manager()
        result = manager.start()

        log_web_action(
            action="start_ha",
            module="ha",
            detail="启动HA服务",
        )
        return jsonify({
            "status": "ok",
            "message": "HA服务已启动",
            "data": result,
        })
    except Exception as e:
        logger.error("启动HA失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ha_bp.route("/api/stop", methods=["POST"])
@admin_required
def stop_ha():
    """停止HA服务"""
    try:
        manager = _get_manager()
        result = manager.stop()

        log_web_action(
            action="stop_ha",
            module="ha",
            detail="停止HA服务",
        )
        return jsonify({
            "status": "ok",
            "message": "HA服务已停止",
            "data": result,
        })
    except Exception as e:
        logger.error("停止HA失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ha_bp.route("/api/failover", methods=["POST"])
@super_admin_required
def force_failover():
    """强制故障切换"""
    try:
        manager = _get_manager()
        result = manager.force_failover()

        log_web_action(
            action="force_failover",
            module="ha",
            detail="执行强制故障切换",
        )
        return jsonify({
            "status": "ok",
            "message": "故障切换已执行",
            "data": result,
        })
    except Exception as e:
        logger.error("故障切换失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ha_bp.route("/api/sync", methods=["POST"])
@admin_required
def sync_config():
    """同步配置到对端节点"""
    try:
        manager = _get_manager()
        result = manager.sync_config()

        log_web_action(
            action="sync_config",
            module="ha",
            detail="同步配置到对端节点",
        )
        return jsonify({
            "status": "ok",
            "message": "配置同步已执行",
            "data": result,
        })
    except Exception as e:
        logger.error("配置同步失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ha_bp.route("/api/peer")
@login_required
def peer_status():
    """获取对端节点状态"""
    try:
        manager = _get_manager()
        status = manager.get_peer_status()
        return jsonify({
            "status": "ok",
            "data": status,
        })
    except Exception as e:
        logger.error("获取对端状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ha_bp.route("/api/health")
@login_required
def health_check():
    """健康检查"""
    try:
        manager = _get_manager()
        health = manager.get_health()
        return jsonify({
            "status": "ok",
            "data": health,
        })
    except Exception as e:
        logger.error("健康检查失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ha_bp.route("/api/history")
@login_required
def failover_history():
    """获取故障切换历史"""
    try:
        manager = _get_manager()
        history = manager.get_failover_history()
        return jsonify({
            "status": "ok",
            "data": {
                "history": history,
                "total": len(history),
            }
        })
    except Exception as e:
        logger.error("获取故障切换历史失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ha_bp.route("/api/maintenance", methods=["POST"])
@admin_required
def toggle_maintenance():
    """切换维护模式"""
    try:
        data = request.get_json()
        if not data or "enabled" not in data:
            return jsonify({"status": "error", "message": "缺少enabled参数"}), 400

        enabled = bool(data["enabled"])
        manager = _get_manager()

        if enabled:
            result = manager.enable_maintenance_mode()
        else:
            result = manager.disable_maintenance_mode()

        log_web_action(
            action="toggle_maintenance",
            module="ha",
            detail="{}维护模式".format("启用" if enabled else "禁用"),
        )
        return jsonify({
            "status": "ok",
            "message": "维护模式已{}".format("启用" if enabled else "禁用"),
            "data": result,
        })
    except Exception as e:
        logger.error("切换维护模式失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
