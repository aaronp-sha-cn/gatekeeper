"""
GateKeeper - 资产管理路由
资产管理页面的Web路由和API
"""

from flask import Blueprint, render_template, jsonify, request, Response
from flask_login import login_required

from web.routes.auth import admin_required

from config.logging_config import get_logger
from security.asset_discovery import get_asset_discovery
from web.app import _safe_error_message

logger = get_logger("web.assets")

assets_bp = Blueprint("assets", __name__, url_prefix="/assets")


@assets_bp.route("/")
@login_required
def index():
    """资产管理页面"""
    return render_template("assets.html", title="资产管理")


# ============================================================
# 扫描控制API
# ============================================================

@assets_bp.route("/api/scan/start", methods=["POST"])
@admin_required
def api_scan_start():
    """启动扫描"""
    try:
        data = request.get_json() or {}
        target = data.get("target", "").strip()
        scan_type = data.get("scan_type", "quick")
        ports = data.get("ports")

        if not target:
            return jsonify({"status": "error", "message": "请输入扫描目标"})

        if scan_type not in ("quick", "full", "custom"):
            return jsonify({"status": "error", "message": "无效的扫描类型"})

        port_list = None
        if ports:
            try:
                port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
            except ValueError:
                return jsonify({"status": "error", "message": "端口格式错误"})

        manager = get_asset_discovery()
        result = manager.start_scan(target, scan_type=scan_type, ports=port_list)
        return jsonify(result)

    except Exception as e:
        logger.error("启动扫描失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@assets_bp.route("/api/scan/stop", methods=["POST"])
@admin_required
def api_scan_stop():
    """停止扫描"""
    try:
        manager = get_asset_discovery()
        result = manager.stop_scan()
        return jsonify(result)
    except Exception as e:
        logger.error("停止扫描失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@assets_bp.route("/api/scan/status")
@login_required
def api_scan_status():
    """获取扫描状态"""
    try:
        manager = get_asset_discovery()
        result = manager.get_scan_status()
        return jsonify(result)
    except Exception as e:
        logger.error("获取扫描状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 资产管理API
# ============================================================

@assets_bp.route("/api/assets")
@login_required
def api_get_assets():
    """获取资产列表"""
    try:
        manager = get_asset_discovery()
        result = manager.get_assets(
            device_type=request.args.get("device_type"),
            vendor=request.args.get("vendor"),
            risk_level=request.args.get("risk_level"),
            online_only=request.args.get("online_only", "false").lower() == "true",
            page=request.args.get("page", 1, type=int),
            page_size=request.args.get("page_size", 50, type=int),
        )
        return jsonify(result)
    except Exception as e:
        logger.error("获取资产列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@assets_bp.route("/api/assets/<asset_id>")
@login_required
def api_get_asset(asset_id):
    """获取资产详情"""
    try:
        manager = get_asset_discovery()
        result = manager.get_asset(asset_id)
        return jsonify(result)
    except Exception as e:
        logger.error("获取资产详情失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@assets_bp.route("/api/assets/<asset_id>", methods=["DELETE"])
@admin_required
def api_delete_asset(asset_id):
    """删除资产"""
    try:
        manager = get_asset_discovery()
        result = manager.delete_asset(asset_id)
        return jsonify(result)
    except Exception as e:
        logger.error("删除资产失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@assets_bp.route("/api/assets/<asset_id>", methods=["PUT"])
@admin_required
def api_update_asset(asset_id):
    """更新资产"""
    try:
        data = request.get_json() or {}
        manager = get_asset_discovery()
        result = manager.update_asset(asset_id, data)
        return jsonify(result)
    except Exception as e:
        logger.error("更新资产失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 统计与导出API
# ============================================================

@assets_bp.route("/api/stats")
@login_required
def api_stats():
    """获取资产统计"""
    try:
        manager = get_asset_discovery()
        result = manager.get_stats()
        return jsonify(result)
    except Exception as e:
        logger.error("获取统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@assets_bp.route("/api/scan/history")
@login_required
def api_scan_history():
    """获取扫描历史"""
    try:
        manager = get_asset_discovery()
        result = manager.get_scan_history()
        return jsonify(result)
    except Exception as e:
        logger.error("获取扫描历史失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@assets_bp.route("/api/export")
@login_required
def api_export():
    """导出资产数据"""
    try:
        fmt = request.args.get("format", "csv")
        manager = get_asset_discovery()
        result = manager.export_assets(format=fmt)

        if result["status"] != "ok":
            return jsonify(result)

        if fmt == "csv":
            return Response(
                result["data"],
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=assets_export.csv"},
            )
        elif fmt == "json":
            return Response(
                result["data"],
                mimetype="application/json",
                headers={"Content-Disposition": "attachment; filename=assets_export.json"},
            )

        return jsonify({"status": "error", "message": "不支持的导出格式"})

    except Exception as e:
        logger.error("导出资产失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
