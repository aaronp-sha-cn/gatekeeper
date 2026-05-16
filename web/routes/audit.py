"""
GateKeeper - 日志管理路由
提供操作审计日志的查看、搜索和下载功能
"""

import io
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request, render_template, send_file
from flask_login import login_required

from core.audit import get_audit_logger
from config.logging_config import get_logger
from web.routes.auth import admin_required
from web.app import _safe_error_message

logger = get_logger("audit_routes")

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


@audit_bp.route("/")
@login_required
def index():
    """日志管理页面"""
    return render_template("audit.html")


@audit_bp.route("/api/logs")
@admin_required
def get_logs():
    """查询操作日志"""
    try:
        al = get_audit_logger()

        # 解析查询参数
        source = request.args.get("source")
        username = request.args.get("username")
        action = request.args.get("action")
        module = request.args.get("module")
        result = request.args.get("result")
        keyword = request.args.get("keyword")
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("page_size", 50, type=int)

        # 时间范围
        start_time = None
        end_time = None
        start_str = request.args.get("start_time")
        end_str = request.args.get("end_time")
        if start_str:
            try:
                start_time = datetime.fromisoformat(start_str)
            except ValueError:
                pass
        if end_str:
            try:
                end_time = datetime.fromisoformat(end_str)
            except ValueError:
                pass

        data = al.query(
            source=source, username=username, action=action,
            module=module, result=result, keyword=keyword,
            start_time=start_time, end_time=end_time,
            page=page, page_size=page_size
        )

        return jsonify({"status": "ok", "data": data})

    except Exception as e:
        logger.error("查询日志失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@audit_bp.route("/api/statistics")
@admin_required
def get_statistics():
    """获取日志统计信息"""
    try:
        days = request.args.get("days", 7, type=int)
        al = get_audit_logger()
        stats = al.get_statistics(days=days)
        return jsonify({"status": "ok", "data": stats})
    except Exception as e:
        return jsonify(_safe_error_message(e)), 500


@audit_bp.route("/api/users")
@admin_required
def get_audit_users():
    """获取审计日志中的所有用户列表"""
    try:
        al = get_audit_logger()
        users = al.get_distinct_users()
        return jsonify({"status": "ok", "data": users})
    except Exception as e:
        logger.error("获取用户列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@audit_bp.route("/api/record", methods=["POST"])
@login_required
def record_action():
    """记录前端操作日志（菜单点击、页面导航等）"""
    try:
        data = request.get_json(silent=True, force=True) or {}
        al = get_audit_logger()
        al.log(
            source="web",
            action=data.get("action", "page_view"),
            module=data.get("module", ""),
            detail=data.get("detail", ""),
            client_ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
            result="success",
        )
        return jsonify({"status": "ok"})
    except Exception as e:
        logger.debug("记录操作日志失败: {}".format(e))
        return jsonify({"status": "ok"})  # 不影响前端操作


@audit_bp.route("/api/export/csv")
@admin_required
def export_csv():
    """导出日志为CSV"""
    try:
        al = get_audit_logger()

        source = request.args.get("source")
        username = request.args.get("username")
        action = request.args.get("action")
        module = request.args.get("module")

        start_time = None
        end_time = None
        start_str = request.args.get("start_time")
        end_str = request.args.get("end_time")
        if start_str:
            try:
                start_time = datetime.fromisoformat(start_str)
            except ValueError:
                pass
        if end_str:
            try:
                end_time = datetime.fromisoformat(end_str)
            except ValueError:
                pass

        csv_content = al.export_csv(
            source=source, username=username, action=action,
            module=module, start_time=start_time, end_time=end_time
        )

        if not csv_content:
            return jsonify({"status": "error", "message": "无数据可导出"}), 404

        buf = io.BytesIO(csv_content.encode("utf-8-sig"))
        return send_file(
            buf,
            mimetype="text/csv",
            as_attachment=True,
            download_name="audit_log_{}.csv".format(
                datetime.now().strftime("%Y%m%d_%H%M%S")
            ),
        )

    except Exception as e:
        logger.error("导出日志失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@audit_bp.route("/api/cleanup", methods=["POST"])
@admin_required
def cleanup_logs():
    """清理过期日志"""
    try:
        days = request.get_json().get("days", 90)
        al = get_audit_logger()
        result = al.cleanup(days=days)

        if result["success"]:
            return jsonify({"status": "ok", "message": result["message"]})
        else:
            return jsonify({"status": "error", "message": result["message"]}), 400

    except Exception as e:
        return jsonify(_safe_error_message(e)), 500
