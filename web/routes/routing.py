"""
动态路由Web路由
提供OSPF/BGP配置和管理的API接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from web.app import _safe_error_message
from network.dynamic_routing import (
    get_dynamic_routing,
    OSPFConfig,
    BGPConfig,
    BGPNeighbor,
)

logger = get_logger("routing_routes")

routing_bp = Blueprint("routing", __name__, url_prefix="/routing")


@routing_bp.route("/")
@login_required
def index():
    """动态路由管理页面"""
    return render_template("routing.html")


# ============================================================
# OSPF API
# ============================================================

@routing_bp.route("/api/ospf/status")
@login_required
def ospf_status():
    """获取OSPF状态"""
    try:
        manager = get_dynamic_routing()
        return jsonify({"status": "ok", "data": manager.get_ospf_status()})
    except Exception as e:
        logger.error("获取OSPF状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/ospf/neighbors")
@login_required
def ospf_neighbors():
    """获取OSPF邻居列表"""
    try:
        manager = get_dynamic_routing()
        return jsonify({"status": "ok", "data": manager.get_ospf_neighbors()})
    except Exception as e:
        logger.error("获取OSPF邻居失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/ospf/database")
@login_required
def ospf_database():
    """获取OSPF数据库"""
    try:
        manager = get_dynamic_routing()
        return jsonify({"status": "ok", "data": manager.get_ospf_database()})
    except Exception as e:
        logger.error("获取OSPF数据库失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/ospf/interfaces")
@login_required
def ospf_interfaces():
    """获取OSPF接口信息"""
    try:
        manager = get_dynamic_routing()
        return jsonify({"status": "ok", "data": manager.get_ospf_interfaces()})
    except Exception as e:
        logger.error("获取OSPF接口失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/ospf/configure", methods=["POST"])
@admin_required
def ospf_configure():
    """配置OSPF"""
    try:
        data = request.get_json()
        config = OSPFConfig(
            router_id=data.get("router_id"),
            areas=data.get("areas", []),
            redistribute=data.get("redistribute", []),
            passive_interfaces=data.get("passive_interfaces", []),
            enabled=True
        )
        manager = get_dynamic_routing()
        success = manager.configure_ospf(config)
        log_web_action(
            "configure_ospf",
            "动态路由",
            "router-id={}".format(config.router_id),
            "success" if success else "failed"
        )
        return jsonify({
            "status": "ok" if success else "error",
            "message": "" if success else "配置失败"
        })
    except Exception as e:
        logger.error("配置OSPF失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/ospf/disable", methods=["POST"])
@admin_required
def ospf_disable():
    """禁用OSPF"""
    try:
        manager = get_dynamic_routing()
        success = manager.disable_ospf()
        log_web_action("disable_ospf", "动态路由", "禁用OSPF", "success" if success else "failed")
        return jsonify({"status": "ok" if success else "error"})
    except Exception as e:
        logger.error("禁用OSPF失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# BGP API
# ============================================================

@routing_bp.route("/api/bgp/status")
@login_required
def bgp_status():
    """获取BGP状态"""
    try:
        manager = get_dynamic_routing()
        return jsonify({"status": "ok", "data": manager.get_bgp_status()})
    except Exception as e:
        logger.error("获取BGP状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/bgp/neighbors")
@login_required
def bgp_neighbors():
    """获取BGP邻居状态"""
    try:
        manager = get_dynamic_routing()
        return jsonify({"status": "ok", "data": manager.get_bgp_neighbors()})
    except Exception as e:
        logger.error("获取BGP邻居失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/bgp/routes")
@login_required
def bgp_routes():
    """获取BGP路由表"""
    try:
        manager = get_dynamic_routing()
        return jsonify({"status": "ok", "data": manager.get_bgp_routes()})
    except Exception as e:
        logger.error("获取BGP路由失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/bgp/configure", methods=["POST"])
@admin_required
def bgp_configure():
    """配置BGP"""
    try:
        data = request.get_json()
        neighbors = [BGPNeighbor(**n) for n in data.get("neighbors", [])]
        config = BGPConfig(
            local_as=data.get("local_as"),
            router_id=data.get("router_id"),
            neighbors=neighbors,
            networks=data.get("networks", []),
            redistribute=data.get("redistribute", []),
            enabled=True
        )
        manager = get_dynamic_routing()
        success = manager.configure_bgp(config)
        log_web_action(
            "configure_bgp",
            "动态路由",
            "AS={}".format(config.local_as),
            "success" if success else "failed"
        )
        return jsonify({
            "status": "ok" if success else "error",
            "message": "" if success else "配置失败"
        })
    except Exception as e:
        logger.error("配置BGP失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/bgp/disable", methods=["POST"])
@admin_required
def bgp_disable():
    """禁用BGP"""
    try:
        manager = get_dynamic_routing()
        success = manager.disable_bgp()
        log_web_action("disable_bgp", "动态路由", "禁用BGP", "success" if success else "failed")
        return jsonify({"status": "ok" if success else "error"})
    except Exception as e:
        logger.error("禁用BGP失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 路由表 API
# ============================================================

@routing_bp.route("/api/routes")
@login_required
def get_routes():
    """获取路由表"""
    try:
        manager = get_dynamic_routing()
        protocol = request.args.get("protocol")
        return jsonify({"status": "ok", "data": manager.get_routing_table(protocol)})
    except Exception as e:
        logger.error("获取路由表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/routes/summary")
@login_required
def route_summary():
    """获取路由摘要"""
    try:
        manager = get_dynamic_routing()
        return jsonify({"status": "ok", "data": manager.get_route_summary()})
    except Exception as e:
        logger.error("获取路由摘要失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# FRR服务管理
# ============================================================

@routing_bp.route("/api/status")
@login_required
def status():
    """获取整体状态"""
    try:
        manager = get_dynamic_routing()
        return jsonify({"status": "ok", "data": manager.get_status()})
    except Exception as e:
        logger.error("获取状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/frr/status")
@login_required
def frr_status():
    """获取FRR服务状态"""
    try:
        manager = get_dynamic_routing()
        return jsonify({"status": "ok", "data": manager.get_frr_status()})
    except Exception as e:
        logger.error("获取FRR状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/frr/version")
@login_required
def frr_version():
    """获取FRR版本"""
    try:
        manager = get_dynamic_routing()
        return jsonify({"status": "ok", "data": {"version": manager.get_version()}})
    except Exception as e:
        logger.error("获取FRR版本失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/frr/start", methods=["POST"])
@admin_required
def frr_start():
    """启动FRR服务"""
    try:
        manager = get_dynamic_routing()
        success = manager.start_frr_services()
        log_web_action("start_frr", "动态路由", "启动FRR服务", "success" if success else "failed")
        return jsonify({"status": "ok" if success else "error"})
    except Exception as e:
        logger.error("启动FRR失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/frr/stop", methods=["POST"])
@admin_required
def frr_stop():
    """停止FRR服务"""
    try:
        manager = get_dynamic_routing()
        success = manager.stop_frr_services()
        log_web_action("stop_frr", "动态路由", "停止FRR服务", "success" if success else "failed")
        return jsonify({"status": "ok" if success else "error"})
    except Exception as e:
        logger.error("停止FRR失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@routing_bp.route("/api/frr/restart", methods=["POST"])
@admin_required
def frr_restart():
    """重启FRR服务"""
    try:
        manager = get_dynamic_routing()
        success = manager.restart_frr_services()
        log_web_action("restart_frr", "动态路由", "重启FRR服务", "success" if success else "failed")
        return jsonify({"status": "ok" if success else "error"})
    except Exception as e:
        logger.error("重启FRR失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
