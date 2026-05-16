"""
GateKeeper - 网关管理路由
提供网关配置和管理的API接口
"""

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required, current_user

from web.routes.auth import admin_required

from config.logging_config import get_logger
from network.gateway import get_gateway_manager, NATType
from web.app import _safe_error_message

logger = get_logger("gateway_routes")

gateway_bp = Blueprint("gateway", __name__, url_prefix="/gateway")


@gateway_bp.route("/")
@login_required
def index():
    """网关管理页面"""
    return render_template("gateway.html")


@gateway_bp.route("/api/status")
@login_required
def get_status():
    """获取网关状态"""
    try:
        manager = get_gateway_manager()
        status = manager.get_status()
        return jsonify({"status": "ok", "data": status})
    except Exception as e:
        logger.error(f"获取网关状态失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/interfaces")
@login_required
def get_interfaces():
    """获取网络接口列表"""
    try:
        manager = get_gateway_manager()
        interfaces = manager.get_interfaces()
        return jsonify({"status": "ok", "data": interfaces})
    except Exception as e:
        logger.error(f"获取接口列表失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/enable", methods=["POST"])
@admin_required
def enable_gateway():
    """启用网关模式"""
    try:
        data = request.get_json()
        wan_interface = data.get("wan_interface")
        lan_interface = data.get("lan_interface")
        lan_network = data.get("lan_network", "192.168.1.0/24")

        if not wan_interface or not lan_interface:
            return jsonify({"status": "error", "message": "请指定WAN和LAN接口"}), 400

        manager = get_gateway_manager()
        success = manager.enable_gateway(wan_interface, lan_interface, lan_network)

        if success:
            logger.info(f"用户 {current_user.username} 启用网关模式")
            return jsonify({"status": "ok", "message": "网关模式已启用"})
        else:
            return jsonify({"status": "error", "message": "启用网关失败"}), 500

    except Exception as e:
        logger.error(f"启用网关失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/disable", methods=["POST"])
@admin_required
def disable_gateway():
    """禁用网关模式"""
    try:
        manager = get_gateway_manager()
        success = manager.disable_gateway()

        if success:
            logger.info(f"用户 {current_user.username} 禁用网关模式")
            return jsonify({"status": "ok", "message": "网关模式已禁用"})
        else:
            return jsonify({"status": "error", "message": "禁用网关失败"}), 500

    except Exception as e:
        logger.error(f"禁用网关失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/dhcp/config", methods=["GET", "POST"])
@admin_required
def dhcp_config():
    """获取/配置DHCP服务器"""
    manager = get_gateway_manager()

    if request.method == "GET":
        try:
            return jsonify({
                "status": "ok",
                "data": {
                    "enabled": manager.config.dhcp_enabled,
                    "start_ip": manager.config.dhcp_start,
                    "end_ip": manager.config.dhcp_end,
                    "lease_time": manager.config.dhcp_lease_time,
                    "dns_servers": manager.config.dns_upstream
                }
            })
        except Exception as e:
            logger.error(f"获取DHCP配置失败: {e}")
            return jsonify(_safe_error_message(e)), 500

    # POST - 更新配置
    try:
        data = request.get_json()
        manager.configure_dhcp(
            enabled=data.get("enabled", True),
            start_ip=data.get("start_ip"),
            end_ip=data.get("end_ip"),
            lease_time=data.get("lease_time"),
            dns_servers=data.get("dns_servers")
        )
        return jsonify({"status": "ok", "message": "DHCP配置已更新"})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/dhcp/leases")
@login_required
def dhcp_leases():
    """获取DHCP租约列表"""
    try:
        manager = get_gateway_manager()
        leases = manager.get_dhcp_leases()
        return jsonify({"status": "ok", "data": leases})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/dns/config", methods=["GET", "POST"])
@admin_required
def dns_config():
    """获取/配置DNS转发"""
    manager = get_gateway_manager()

    if request.method == "GET":
        try:
            return jsonify({
                "status": "ok",
                "data": {
                    "enabled": manager.config.dns_enabled,
                    "upstream": manager.config.dns_upstream
                }
            })
        except Exception as e:
            logger.error(f"获取DNS配置失败: {e}")
            return jsonify(_safe_error_message(e)), 500

    # POST - 更新配置
    try:
        data = request.get_json()
        manager.configure_dns(
            enabled=data.get("enabled", True),
            upstream=data.get("upstream")
        )
        return jsonify({"status": "ok", "message": "DNS配置已更新"})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/port-forward", methods=["GET", "POST"])
@admin_required
def port_forward():
    """获取/添加端口转发"""
    manager = get_gateway_manager()

    if request.method == "GET":
        try:
            status = manager.get_status()
            return jsonify({"status": "ok", "data": status.get("port_forwards", [])})
        except Exception as e:
            logger.error(f"获取端口转发列表失败: {e}")
            return jsonify(_safe_error_message(e)), 500

    # POST - 添加端口转发
    try:
        data = request.get_json()
        success = manager.add_port_forward(
            name=data.get("name"),
            protocol=data.get("protocol", "tcp"),
            external_port=data.get("external_port"),
            internal_ip=data.get("internal_ip"),
            internal_port=data.get("internal_port")
        )

        if success:
            logger.info(f"用户 {current_user.username} 添加端口转发: {data.get('name')}")
            return jsonify({"status": "ok", "message": "端口转发已添加"})
        else:
            return jsonify({"status": "error", "message": "添加端口转发失败"}), 500

    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/port-forward/<name>", methods=["DELETE"])
@admin_required
def remove_port_forward(name):
    """删除端口转发"""
    try:
        manager = get_gateway_manager()
        success = manager.remove_port_forward(name)

        if success:
            logger.info(f"用户 {current_user.username} 删除端口转发: {name}")
            return jsonify({"status": "ok", "message": "端口转发已删除"})
        else:
            return jsonify({"status": "error", "message": "端口转发不存在"}), 404

    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# DHCP子网管理API（支持多IP地址段和VLAN）
# ============================================================

@gateway_bp.route("/api/dhcp/subnets")
@login_required
def get_dhcp_subnets():
    """获取所有DHCP子网配置"""
    try:
        manager = get_gateway_manager()
        subnets = manager.get_dhcp_subnets()
        return jsonify({"status": "ok", "data": subnets})
    except Exception as e:
        logger.error(f"获取DHCP子网列表失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/dhcp/subnets", methods=["POST"])
@admin_required
def add_dhcp_subnet():
    """添加DHCP子网"""
    try:
        data = request.get_json()
        manager = get_gateway_manager()
        
        result = manager.add_dhcp_subnet(
            name=data.get("name"),
            network=data.get("network"),
            gateway=data.get("gateway"),
            start_ip=data.get("start_ip"),
            end_ip=data.get("end_ip"),
            interface=data.get("interface"),
            vlan_id=data.get("vlan_id"),
            lease_time=data.get("lease_time", 86400),
            dns_servers=data.get("dns_servers"),
            description=data.get("description", "")
        )
        
        if result["success"]:
            logger.info(f"用户 {current_user.username} 添加DHCP子网: {data.get('name')}")
            return jsonify({"status": "ok", "message": result["message"], "subnet_id": result.get("subnet_id")})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"添加DHCP子网失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/dhcp/subnets/<int:subnet_id>")
@login_required
def get_dhcp_subnet(subnet_id):
    """获取单个DHCP子网配置"""
    try:
        manager = get_gateway_manager()
        subnet = manager.get_dhcp_subnet(subnet_id)
        
        if subnet:
            return jsonify({"status": "ok", "data": subnet})
        else:
            return jsonify({"status": "error", "message": "子网不存在"}), 404
            
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/dhcp/subnets/<int:subnet_id>", methods=["PUT"])
@admin_required
def update_dhcp_subnet(subnet_id):
    """更新DHCP子网配置"""
    try:
        data = request.get_json()
        manager = get_gateway_manager()
        
        result = manager.update_dhcp_subnet(subnet_id, **data)
        
        if result["success"]:
            logger.info(f"用户 {current_user.username} 更新DHCP子网: {subnet_id}")
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"更新DHCP子网失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/dhcp/subnets/<int:subnet_id>", methods=["DELETE"])
@admin_required
def delete_dhcp_subnet(subnet_id):
    """删除DHCP子网"""
    try:
        manager = get_gateway_manager()
        result = manager.delete_dhcp_subnet(subnet_id)
        
        if result["success"]:
            logger.info(f"用户 {current_user.username} 删除DHCP子网: {subnet_id}")
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
            
    except Exception as e:
        logger.error(f"删除DHCP子网失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/dhcp/statistics")
@login_required
def get_dhcp_statistics():
    """获取DHCP统计信息"""
    try:
        manager = get_gateway_manager()
        stats = manager.get_dhcp_statistics()
        return jsonify({"status": "ok", "data": stats})
    except Exception as e:
        logger.error(f"获取DHCP统计失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/vlan/interfaces")
@login_required
def get_vlan_interfaces():
    """获取VLAN接口列表"""
    try:
        manager = get_gateway_manager()
        vlans = manager.get_vlan_interfaces()
        return jsonify({"status": "ok", "data": vlans})
    except Exception as e:
        logger.error(f"获取VLAN接口失败: {e}")
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# WAN上联接口管理API（DHCP / PPPoE / 静态IP）
# ============================================================

@gateway_bp.route("/api/wan/status")
@login_required
def get_wan_status():
    """获取WAN连接状态"""
    try:
        manager = get_gateway_manager()
        status = manager.get_wan_status()
        return jsonify({"status": "ok", "data": status})
    except Exception as e:
        logger.error(f"获取WAN状态失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/wan/config", methods=["POST"])
@admin_required
def configure_wan():
    """配置WAN连接方式"""
    try:
        data = request.get_json()
        manager = get_gateway_manager()

        result = manager.configure_wan(
            mode=data.get("mode", "dhcp"),
            interface=data.get("interface", "eth0"),
            static_ip=data.get("static_ip", ""),
            static_netmask=data.get("static_netmask", "255.255.255.0"),
            static_gateway=data.get("static_gateway", ""),
            static_dns=data.get("static_dns"),
            pppoe_username=data.get("pppoe_username", ""),
            pppoe_password=data.get("pppoe_password", ""),
            pppoe_mtu=data.get("pppoe_mtu", 1492),
        )

        if result["success"]:
            logger.info(f"用户 {current_user.username} 配置WAN: mode={data.get('mode')}")
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400

    except Exception as e:
        logger.error(f"配置WAN失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/wan/connect", methods=["POST"])
@admin_required
def connect_wan():
    """连接WAN"""
    try:
        manager = get_gateway_manager()
        result = manager.connect_wan()

        if result["success"]:
            logger.info(f"用户 {current_user.username} 连接WAN: IP={result.get('ip')}")
            return jsonify({"status": "ok", "message": result["message"], "ip": result.get("ip")})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 500

    except Exception as e:
        logger.error(f"连接WAN失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/wan/disconnect", methods=["POST"])
@admin_required
def disconnect_wan():
    """断开WAN"""
    try:
        manager = get_gateway_manager()
        result = manager.disconnect_wan()

        if result["success"]:
            logger.info(f"用户 {current_user.username} 断开WAN")
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 500

    except Exception as e:
        logger.error(f"断开WAN失败: {e}")
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 网络测速API
# ============================================================

@gateway_bp.route("/api/speedtest/start", methods=["POST"])
@admin_required
def start_speedtest():
    """启动网络测速"""
    try:
        from network.speedtest import get_speedtest
        tester = get_speedtest()

        if tester.is_running:
            return jsonify({"status": "error", "message": "测速正在进行中"})

        data = request.get_json() or {}
        target = data.get("target", "")

        tester.run_speed_test_async(
            target_host=target,
            callback=None  # 前端通过轮询获取结果
        )

        return jsonify({"status": "ok", "message": "测速已启动"})

    except Exception as e:
        logger.error(f"启动测速失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/speedtest/result")
@login_required
def get_speedtest_result():
    """获取测速结果"""
    try:
        from network.speedtest import get_speedtest
        tester = get_speedtest()
        r = tester.result

        return jsonify({
            "status": "ok",
            "data": {
                "is_running": r.is_running,
                "download_mbps": r.download_speed_mbps,
                "upload_mbps": r.upload_speed_mbps,
                "latency_ms": r.latency_ms,
                "jitter_ms": r.jitter_ms,
                "packet_loss": r.packet_loss,
                "target": r.target_host,
                "duration": r.test_duration,
                "timestamp": r.timestamp,
                "error": r.error,
            }
        })
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/speedtest/cancel", methods=["POST"])
@admin_required
def cancel_speedtest():
    """取消测速"""
    try:
        from network.speedtest import get_speedtest
        tester = get_speedtest()
        tester.cancel()
        return jsonify({"status": "ok", "message": "测速已取消"})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/speedtest/servers")
@login_required
def get_speedtest_servers():
    """获取可用测速服务器"""
    try:
        from network.speedtest import get_speedtest
        tester = get_speedtest()
        servers = tester.get_speedtest_servers()
        return jsonify({"status": "ok", "data": servers})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# NAT高级配置API
# ============================================================

@gateway_bp.route("/api/nat/config")
@login_required
def get_nat_config():
    """获取NAT高级配置"""
    try:
        manager = get_gateway_manager()
        config = manager.get_nat_config()
        return jsonify({"status": "ok", "data": config})
    except Exception as e:
        logger.error(f"获取NAT配置失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/nat/advanced", methods=["POST"])
@admin_required
def set_nat_advanced():
    """设置NAT高级参数"""
    try:
        data = request.get_json() or {}
        manager = get_gateway_manager()

        result = manager.set_nat_advanced(
            conntrack_max=data.get("conntrack_max"),
            tcp_established_timeout=data.get("tcp_established_timeout"),
            tcp_time_wait_timeout=data.get("tcp_time_wait_timeout"),
            udp_timeout=data.get("udp_timeout"),
            enable_syn_proxy=data.get("enable_syn_proxy"),
            enable_log_dropped=data.get("enable_log_dropped"),
        )

        if result["success"]:
            logger.info(f"用户 {current_user.username} 更新NAT高级配置")
            return jsonify({"status": "ok", "message": result["message"], "changes": result.get("changes", [])})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400

    except Exception as e:
        logger.error(f"NAT高级配置失败: {e}")
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/nat/rules")
@login_required
def get_nat_rules():
    """获取NAT规则列表"""
    try:
        manager = get_gateway_manager()
        rules = manager.get_nat_rules()
        return jsonify({"status": "ok", "data": rules})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@gateway_bp.route("/api/nat/flush-conntrack", methods=["POST"])
@admin_required
def flush_conntrack():
    """刷新连接跟踪表"""
    try:
        manager = get_gateway_manager()
        result = manager.flush_conntrack()
        if result["success"]:
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500
