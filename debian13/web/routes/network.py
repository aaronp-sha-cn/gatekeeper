"""
GateKeeper - 网络管理路由
"""

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user

from web.routes.auth import admin_required

from config.logging_config import get_logger, log_security_event
from config.settings import settings
from core.database import db_manager
from core.models import FirewallRule, NetworkInterface
from network.firewall import FirewallManager
from network.network_config import NetworkConfigManager
from network.port_scanner import PortScanner
from web.app import _safe_error_message

logger = get_logger("web.network")

network_bp = Blueprint("network", __name__)


@network_bp.route("/")
@login_required
def index():
    """网络管理页面"""
    return render_template("network.html", title="网络管理")


@network_bp.route("/api/interfaces")
@login_required
def api_interfaces():
    """获取网络接口列表"""
    try:
        net_config = NetworkConfigManager()
        interfaces = net_config.get_interfaces()
        return jsonify({"status": "ok", "data": interfaces})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@network_bp.route("/api/routes")
@login_required
def api_routes():
    """获取路由表"""
    try:
        net_config = NetworkConfigManager()
        routes = net_config.get_routing_table()
        return jsonify({"status": "ok", "data": routes})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@network_bp.route("/api/dns")
@login_required
def api_dns():
    """获取DNS配置"""
    try:
        net_config = NetworkConfigManager()
        dns = net_config.get_dns_config()
        return jsonify({"status": "ok", "data": dns})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@network_bp.route("/api/firewall/rules")
@login_required
def api_firewall_rules():
    """获取防火墙规则列表"""
    try:
        firewall = FirewallManager()
        rules = firewall.list_rules()
        return jsonify({"status": "ok", "data": rules})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@network_bp.route("/api/firewall/add", methods=["POST"])
@admin_required
def api_firewall_add():
    """添加防火墙规则"""
    data = request.json if request.is_json else {}

    try:
        firewall = FirewallManager()
        result = firewall.add_rule(
            name=data.get("name", ""),
            action=data.get("action", "DROP"),
            chain=data.get("chain", "INPUT"),
            protocol=data.get("protocol", "any"),
            source_ip=data.get("source_ip"),
            dest_port=data.get("dest_port"),
            description=data.get("description", ""),
            user_id=current_user.id if hasattr(current_user, 'id') else None,
        )

        log_security_event(
            user=getattr(current_user, 'username', 'unknown'),
            action="firewall_add",
            resource=data.get("name", ""),
            result="success" if result.get("status") == "ok" else "failure",
        )

        return jsonify(result)
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@network_bp.route("/api/firewall/<int:rule_id>", methods=["DELETE"])
@admin_required
def api_firewall_remove(rule_id: int):
    """删除防火墙规则"""
    try:
        firewall = FirewallManager()
        result = firewall.remove_rule(rule_id)
        return jsonify(result)
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@network_bp.route("/api/firewall/status")
@login_required
def api_firewall_status():
    """获取防火墙状态"""
    try:
        firewall = FirewallManager()
        status = firewall.get_status()
        return jsonify({"status": "ok", "data": status})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@network_bp.route("/api/scan", methods=["POST"])
@admin_required
def api_scan():
    """启动网络扫描"""
    data = request.json if request.is_json else {}
    target = data.get("target", "")
    scan_type = data.get("type", "port_scan")

    if not target:
        return jsonify({"status": "error", "message": "请指定扫描目标"}), 400

    try:
        scanner = PortScanner()
        if scan_type == "port_scan":
            result = scanner.scan_host(target)
        else:
            result = scanner.scan_network(target)

        return jsonify({"status": "ok", "data": result})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@network_bp.route("/api/interfaces/config", methods=["POST"])
@admin_required
def api_interface_config():
    """配置网络接口"""
    data = request.json if request.is_json else {}

    iface_name = data.get("name", "")
    if not iface_name:
        return jsonify({"status": "error", "message": "缺少接口名称"}), 400

    try:
        net_config = NetworkConfigManager()
        result = net_config.configure_interface(
            name=iface_name,
            ip_address=data.get("ip_address", ""),
            netmask=data.get("netmask", ""),
            gateway=data.get("gateway", ""),
            dns=data.get("dns", []),
            mtu=data.get("mtu", 1500),
            description=data.get("description", ""),
            enabled=data.get("enabled", True),
        )

        log_security_event(
            user=getattr(current_user, "username", "unknown"),
            action="interface_config",
            resource=iface_name,
            result="success" if result.get("status") == "ok" else "failure",
        )

        return jsonify(result)
    except Exception as e:
        logger.error("配置网络接口失败: {}".format(str(e)))
        return jsonify(_safe_error_message(e)), 500


@network_bp.route("/api/routes", methods=["POST"])
@admin_required
def api_add_route():
    """添加静态路由"""
    data = request.json if request.is_json else {}

    target = data.get("target", "")
    netmask = data.get("netmask", "")
    gateway = data.get("gateway", "")

    if not target or not netmask or not gateway:
        return jsonify({"status": "error", "message": "缺少必要参数"}), 400

    try:
        net_config = NetworkConfigManager()
        result = net_config.add_route(
            target=target,
            netmask=netmask,
            gateway=gateway,
        )

        log_security_event(
            user=getattr(current_user, "username", "unknown"),
            action="route_add",
            resource="{} via {}".format(target, gateway),
            result="success" if result.get("status") == "ok" else "failure",
        )

        return jsonify(result)
    except Exception as e:
        logger.error("添加静态路由失败: {}".format(str(e)))
        return jsonify(_safe_error_message(e)), 500


@network_bp.route("/api/dns", methods=["POST"])
@admin_required
def api_update_dns():
    """更新DNS配置"""
    data = request.json if request.is_json else {}

    dns_servers = data.get("dns_servers", [])
    if not isinstance(dns_servers, list) or len(dns_servers) == 0:
        return jsonify({"status": "error", "message": "请提供有效的DNS服务器列表"}), 400

    try:
        net_config = NetworkConfigManager()
        result = net_config.update_dns(dns_servers)

        log_security_event(
            user=getattr(current_user, "username", "unknown"),
            action="dns_update",
            resource=", ".join(dns_servers),
            result="success" if result.get("status") == "ok" else "failure",
        )

        return jsonify(result)
    except Exception as e:
        logger.error("更新DNS配置失败: {}".format(str(e)))
        return jsonify(_safe_error_message(e)), 500
