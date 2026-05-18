"""
GateKeeper - 蜜罐管理路由
提供蜜罐系统的Web管理API接口
"""

import csv
import io
from flask import Blueprint, jsonify, request, render_template, Response
from flask_login import login_required, current_user

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.honeypot import get_honeypot_manager
from web.app import _safe_error_message

logger = get_logger("honeypot_routes")

honeypot_bp = Blueprint("honeypot", __name__)


@honeypot_bp.route("/")
@login_required
def index():
    """蜜罐管理页面"""
    return render_template("honeypot.html")


@honeypot_bp.route("/api/services", methods=["GET"])
@login_required
def get_services():
    """获取蜜罐服务列表"""
    try:
        manager = get_honeypot_manager()
        services = manager.list_services()
        return jsonify({
            "status": "ok",
            "data": {
                "services": services,
                "total": len(services),
            }
        })
    except Exception as e:
        logger.error("获取蜜罐服务列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@honeypot_bp.route("/api/services", methods=["POST"])
@admin_required
def create_service():
    """创建蜜罐服务"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        manager = get_honeypot_manager()
        result = manager.create_service(data)

        if result["status"] == "ok":
            log_web_action(
                action="create_service",
                module="honeypot",
                detail="创建蜜罐服务: {}".format(data.get("name", "")),
                request_data=data,
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("创建蜜罐服务失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@honeypot_bp.route("/api/services/<name>", methods=["DELETE"])
@admin_required
def delete_service(name):
    """删除蜜罐服务"""
    try:
        manager = get_honeypot_manager()
        result = manager.remove_service(name)

        if result["status"] == "ok":
            log_web_action(
                action="delete_service",
                module="honeypot",
                detail="删除蜜罐服务: {}".format(name),
            )

        status_code = 200 if result["status"] == "ok" else 404
        return jsonify(result), status_code
    except Exception as e:
        logger.error("删除蜜罐服务失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@honeypot_bp.route("/api/services/<name>/toggle", methods=["POST"])
@admin_required
def toggle_service(name):
    """启用/禁用蜜罐服务"""
    try:
        manager = get_honeypot_manager()
        services = manager.list_services()

        # 查找服务当前状态
        target = None
        for svc in services:
            if svc["name"] == name:
                target = svc
                break

        if not target:
            return jsonify({"status": "error", "message": "服务不存在: {}".format(name)}), 404

        if target["enabled"]:
            result = manager.stop_service(name)
            action_text = "停止"
        else:
            result = manager.start_service(name)
            action_text = "启动"

        if result["status"] == "ok":
            log_web_action(
                action="toggle_service",
                module="honeypot",
                detail="{}蜜罐服务: {}".format(action_text, name),
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("切换蜜罐服务状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@honeypot_bp.route("/api/captures", methods=["GET"])
@login_required
def get_captures():
    """获取捕获记录"""
    try:
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 50, type=int)
        service = request.args.get("service")
        threat_level = request.args.get("threat_level")

        manager = get_honeypot_manager()
        # 获取所有匹配的记录（在内存中分页）
        all_captures = manager.get_captures(
            service=service,
            threat_level=threat_level,
            limit=10000,
        )

        total = len(all_captures)
        start = (page - 1) * per_page
        end = start + per_page
        paginated = all_captures[start:end]

        return jsonify({
            "status": "ok",
            "data": {
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": (total + per_page - 1) // per_page if total > 0 else 0,
                "captures": paginated,
            }
        })
    except Exception as e:
        logger.error("获取蜜罐捕获记录失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@honeypot_bp.route("/api/stats", methods=["GET"])
@login_required
def get_stats():
    """获取统计信息"""
    try:
        manager = get_honeypot_manager()
        stats = manager.get_stats()
        return jsonify({
            "status": "ok",
            "data": stats,
        })
    except Exception as e:
        logger.error("获取蜜罐统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@honeypot_bp.route("/api/export/captures", methods=["GET"])
@login_required
def export_captures():
    """导出捕获记录为CSV"""
    try:
        service = request.args.get("service")
        threat_level = request.args.get("threat_level")

        manager = get_honeypot_manager()
        captures = manager.get_captures(
            service=service,
            threat_level=threat_level,
            limit=10000,
        )

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "时间", "服务名称", "客户端IP", "客户端端口",
            "协议", "捕获数据", "凭证", "命令", "威胁级别", "标签"
        ])

        for c in captures:
            writer.writerow([
                c.get("id", ""),
                c.get("timestamp", ""),
                c.get("service_name", ""),
                c.get("client_ip", ""),
                c.get("client_port", ""),
                c.get("protocol", ""),
                c.get("captured_data", "")[:200],
                c.get("credentials", ""),
                c.get("commands", "")[:200],
                c.get("threat_level", ""),
                c.get("tags", ""),
            ])

        csv_content = output.getvalue()
        log_web_action(
            action="export_captures",
            module="honeypot",
            detail="导出蜜罐捕获记录, 共{}条".format(len(captures)),
        )

        return Response(
            csv_content,
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=honeypot_captures_{}.csv".format(
                    __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
                )
            },
        )
    except Exception as e:
        logger.error("导出蜜罐捕获记录失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
