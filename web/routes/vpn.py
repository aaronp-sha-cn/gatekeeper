"""
GateKeeper - VPN管理路由
提供VPN服务的Web管理API接口
"""

from flask import Blueprint, jsonify, request, render_template, Response

from flask_login import login_required

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.vpn_service import get_vpn_service
from web.app import _safe_error_message

logger = get_logger("vpn_routes")

vpn_bp = Blueprint("vpn", __name__, url_prefix="/vpn")


# ============================================================
# 页面路由
# ============================================================

@vpn_bp.route("/")
@login_required
def index():
    """VPN管理页面"""
    return render_template("vpn.html")


# ============================================================
# 配置管理 API
# ============================================================

@vpn_bp.route("/api/configs", methods=["GET"])
@login_required
def get_configs():
    """获取所有VPN配置"""
    try:
        service = get_vpn_service()
        configs = service.get_configs()
        return jsonify({
            "status": "ok",
            "data": {"configs": configs, "total": len(configs)},
        })
    except Exception as e:
        logger.error("获取VPN配置列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vpn_bp.route("/api/configs", methods=["POST"])
@admin_required
def create_config():
    """创建VPN配置"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        name = data.get("name", "").strip()
        vpn_type = data.get("vpn_type", "").strip()
        server_ip = data.get("server_ip", "").strip()
        port = data.get("port", 0)
        ip_range = data.get("ip_range", "").strip()
        dns = data.get("dns", "").strip()
        mtu = data.get("mtu", 1420)
        keepalive = data.get("keepalive", 25)

        if not name:
            return jsonify({"status": "error", "message": "配置名称不能为空"}), 400
        if not vpn_type:
            return jsonify({"status": "error", "message": "VPN类型不能为空"}), 400
        if not server_ip:
            return jsonify({"status": "error", "message": "服务器IP不能为空"}), 400
        if not port:
            return jsonify({"status": "error", "message": "端口不能为空"}), 400
        if not ip_range:
            return jsonify({"status": "error", "message": "IP范围不能为空"}), 400

        service = get_vpn_service()
        result = service.create_config(
            name=name, vpn_type=vpn_type, server_ip=server_ip,
            port=port, ip_range=ip_range, dns=dns,
            mtu=mtu, keepalive=keepalive,
        )

        if result["status"] == "ok":
            log_web_action(
                action="create_vpn_config",
                module="vpn",
                detail="创建VPN配置: {} (类型: {})".format(name, vpn_type),
                request_data=data,
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("创建VPN配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vpn_bp.route("/api/configs/<int:config_id>", methods=["DELETE"])
@admin_required
def delete_config(config_id):
    """删除VPN配置"""
    try:
        service = get_vpn_service()
        result = service.delete_config(config_id)

        if result["status"] == "ok":
            log_web_action(
                action="delete_vpn_config",
                module="vpn",
                detail="删除VPN配置: ID={}".format(config_id),
            )

        status_code = 200 if result["status"] == "ok" else 404
        return jsonify(result), status_code

    except Exception as e:
        logger.error("删除VPN配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vpn_bp.route("/api/configs/<int:config_id>/toggle", methods=["POST"])
@admin_required
def toggle_config(config_id):
    """启用/禁用VPN配置"""
    try:
        data = request.get_json() or {}
        enabled = data.get("enabled", True)

        service = get_vpn_service()
        result = service.toggle_config(config_id, enabled)

        if result["status"] == "ok":
            action_text = "启用" if enabled else "禁用"
            log_web_action(
                action="toggle_vpn_config",
                module="vpn",
                detail="{}VPN配置: ID={}".format(action_text, config_id),
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("切换VPN配置状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 客户端管理 API
# ============================================================

@vpn_bp.route("/api/configs/<int:config_id>/clients", methods=["GET"])
@login_required
def get_clients(config_id):
    """获取配置的客户端列表"""
    try:
        service = get_vpn_service()
        clients = service.get_clients(config_id)
        return jsonify({
            "status": "ok",
            "data": {"clients": clients, "total": len(clients)},
        })
    except Exception as e:
        logger.error("获取VPN客户端列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vpn_bp.route("/api/configs/<int:config_id>/clients", methods=["POST"])
@admin_required
def add_client(config_id):
    """添加VPN客户端"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        username = data.get("username", "").strip()
        public_key = data.get("public_key", "").strip()

        if not username:
            return jsonify({"status": "error", "message": "客户端用户名不能为空"}), 400

        service = get_vpn_service()
        result = service.add_client(config_id, username, public_key)

        if result["status"] == "ok":
            log_web_action(
                action="add_vpn_client",
                module="vpn",
                detail="添加VPN客户端: {} (配置ID={})".format(username, config_id),
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("添加VPN客户端失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vpn_bp.route("/api/clients/<int:client_id>", methods=["DELETE"])
@admin_required
def remove_client(client_id):
    """移除VPN客户端"""
    try:
        service = get_vpn_service()
        result = service.remove_client(client_id)

        if result["status"] == "ok":
            log_web_action(
                action="remove_vpn_client",
                module="vpn",
                detail="移除VPN客户端: ID={}".format(client_id),
            )

        status_code = 200 if result["status"] == "ok" else 404
        return jsonify(result), status_code

    except Exception as e:
        logger.error("移除VPN客户端失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vpn_bp.route("/api/configs/<int:config_id>/clients/<int:client_id>/config", methods=["GET"])
@login_required
def generate_client_config(config_id, client_id):
    """生成客户端配置文件"""
    try:
        service = get_vpn_service()
        result = service.generate_client_config(config_id, client_id)

        if result["status"] == "ok":
            log_web_action(
                action="generate_client_config",
                module="vpn",
                detail="生成客户端配置 (配置ID={}, 客户端ID={})".format(config_id, client_id),
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("生成客户端配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 服务控制 API
# ============================================================

@vpn_bp.route("/api/configs/<int:config_id>/start", methods=["POST"])
@admin_required
def start_service(config_id):
    """启动VPN服务"""
    try:
        service = get_vpn_service()
        result = service.start_service(config_id)

        if result["status"] == "ok":
            log_web_action(
                action="start_vpn_service",
                module="vpn",
                detail="启动VPN服务: ID={}".format(config_id),
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("启动VPN服务失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vpn_bp.route("/api/configs/<int:config_id>/stop", methods=["POST"])
@admin_required
def stop_service(config_id):
    """停止VPN服务"""
    try:
        service = get_vpn_service()
        result = service.stop_service(config_id)

        if result["status"] == "ok":
            log_web_action(
                action="stop_vpn_service",
                module="vpn",
                detail="停止VPN服务: ID={}".format(config_id),
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("停止VPN服务失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 状态与统计 API
# ============================================================

@vpn_bp.route("/api/status", methods=["GET"])
@login_required
def get_status():
    """获取VPN服务状态"""
    try:
        service = get_vpn_service()
        status = service.get_status()
        return jsonify({
            "status": "ok",
            "data": status,
        })
    except Exception as e:
        logger.error("获取VPN状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@vpn_bp.route("/api/stats", methods=["GET"])
@login_required
def get_stats():
    """获取VPN统计信息"""
    try:
        service = get_vpn_service()
        stats = service.get_stats()
        return jsonify({
            "status": "ok",
            "data": stats,
        })
    except Exception as e:
        logger.error("获取VPN统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
