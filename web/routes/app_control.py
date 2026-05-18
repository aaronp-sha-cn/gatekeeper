"""
GateKeeper - 应用识别与管控路由
提供应用识别、流量检测、阻断策略和统计分析的API接口
"""

from flask import Blueprint, jsonify, request, render_template, Response
from flask_login import login_required

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.app_detector import AppDetector
from web.app import _safe_error_message
import json

logger = get_logger("app_control_routes")

app_control_bp = Blueprint("app_control", __name__)

_detector = None


def _get_detector():
    """延迟加载AppDetector，避免模块级实例化失败导致整个路由不可用"""
    global _detector
    if _detector is None:
        try:
            _detector = AppDetector()
        except Exception as e:
            logger.warning("AppDetector初始化失败: {}".format(e))
    return _detector


@app_control_bp.route("/")
@login_required
def index():
    """应用识别与管控页面"""
    return render_template("app_control.html")


@app_control_bp.route("/api/apps")
@login_required
def list_apps():
    """列出所有应用，支持按分类过滤"""
    try:
        detector = _get_detector()
        if detector is None:
            return jsonify({"status": "error", "message": "应用识别引擎初始化失败，请检查日志"}), 500
        category = request.args.get("category", "").strip()
        if category:
            apps = detector.get_apps_by_category(category)
        else:
            apps = detector.get_all_apps()
        return jsonify({
            "status": "ok",
            "data": {
                "apps": apps,
                "total": len(apps),
            }
        })
    except Exception as e:
        logger.error("获取应用列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@app_control_bp.route("/api/categories")
@login_required
def list_categories():
    """列出所有应用分类"""
    try:
        categories = _get_detector().get_categories()
        return jsonify({
            "status": "ok",
            "data": {
                "categories": categories,
            }
        })
    except Exception as e:
        logger.error("获取分类列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@app_control_bp.route("/api/stats")
@login_required
def get_stats():
    """获取检测统计数据"""
    try:
        stats = _get_detector().get_app_stats()
        return jsonify({
            "status": "ok",
            "data": stats,
        })
    except Exception as e:
        logger.error("获取统计数据失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@app_control_bp.route("/api/block", methods=["POST"])
@admin_required
def block_app():
    """阻断指定应用"""
    try:
        data = request.get_json()
        if not data or not data.get("app_id"):
            return jsonify({"status": "error", "message": "缺少app_id参数"}), 400

        app_id = data["app_id"]
        success = _get_detector().block_app(app_id)
        if not success:
            return jsonify({"status": "error", "message": "阻断应用失败，应用可能不存在"}), 404

        log_web_action(
            action="block_app",
            module="app_control",
            detail="阻断应用: {}".format(app_id),
        )

        return jsonify({
            "status": "ok",
            "message": "应用已阻断",
            "data": {"app_id": app_id},
        })
    except Exception as e:
        logger.error("阻断应用失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@app_control_bp.route("/api/unblock", methods=["POST"])
@admin_required
def unblock_app():
    """解除应用阻断"""
    try:
        data = request.get_json()
        if not data or not data.get("app_id"):
            return jsonify({"status": "error", "message": "缺少app_id参数"}), 400

        app_id = data["app_id"]
        success = _get_detector().unblock_app(app_id)
        if not success:
            return jsonify({"status": "error", "message": "解除阻断失败，应用可能未被阻断"}), 404

        log_web_action(
            action="unblock_app",
            module="app_control",
            detail="解除阻断应用: {}".format(app_id),
        )

        return jsonify({
            "status": "ok",
            "message": "已解除阻断",
            "data": {"app_id": app_id},
        })
    except Exception as e:
        logger.error("解除阻断失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@app_control_bp.route("/api/blocked")
@login_required
def list_blocked():
    """列出已阻断的应用"""
    try:
        blocked = _get_detector().get_blocked_apps()
        return jsonify({
            "status": "ok",
            "data": {
                "blocked_apps": blocked,
                "total": len(blocked),
            }
        })
    except Exception as e:
        logger.error("获取阻断列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@app_control_bp.route("/api/active-connections")
@login_required
def active_connections():
    """扫描当前活跃连接并识别应用"""
    try:
        connections = _get_detector().scan_active_connections()
        return jsonify({
            "status": "ok",
            "data": {
                "connections": connections,
                "total": len(connections),
            }
        })
    except Exception as e:
        logger.error("扫描活跃连接失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@app_control_bp.route("/api/search", methods=["POST"])
@login_required
def search_apps():
    """搜索应用"""
    try:
        data = request.get_json()
        if not data or not data.get("keyword"):
            return jsonify({"status": "error", "message": "缺少keyword参数"}), 400

        keyword = data["keyword"].strip()
        if not keyword:
            return jsonify({"status": "error", "message": "搜索关键词不能为空"}), 400

        results = _get_detector().search_apps(keyword)
        return jsonify({
            "status": "ok",
            "data": {
                "results": results,
                "total": len(results),
            }
        })
    except Exception as e:
        logger.error("搜索应用失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@app_control_bp.route("/api/export", methods=["GET"])
@login_required
def export_apps():
    """导出应用列表（含阻断状态）为JSON"""
    try:
        detector = _get_detector()
        if detector is None:
            return jsonify({"status": "error", "message": "引擎未初始化"}), 500

        apps = detector.get_all_apps()
        blocked_ids = set(detector.get_blocked_apps())

        export_data = {
            "version": "1.2.0",
            "exported_at": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total": len(apps),
            "apps": []
        }
        for app in apps:
            item = dict(app) if isinstance(app, dict) else {
                "id": getattr(app, "id", ""),
                "name": getattr(app, "name", ""),
                "category": getattr(app, "category", ""),
                "risk": getattr(app, "risk", ""),
                "protocols": getattr(app, "protocols", []),
                "description": getattr(app, "description", ""),
            }
            item["blocked"] = item.get("id", "") in blocked_ids
            export_data["apps"].append(item)

        content = json.dumps(export_data, ensure_ascii=False, indent=2)
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=gatekeeper_apps_export.json"}
        )
    except Exception as e:
        logger.error("导出应用列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@app_control_bp.route("/api/import", methods=["POST"])
@admin_required
def import_apps():
    """导入应用列表（仅导入阻断状态）"""
    try:
        if "file" not in request.files:
            return jsonify({"status": "error", "message": "未找到上传文件"}), 400

        uploaded = request.files["file"]
        if not uploaded.filename.endswith(".json"):
            return jsonify({"status": "error", "message": "仅支持JSON文件"}), 400

        data = json.loads(uploaded.read().decode("utf-8"))
        apps = data.get("apps", [])
        if not apps:
            return jsonify({"status": "error", "message": "文件中没有应用数据"}), 400

        detector = _get_detector()
        if detector is None:
            return jsonify({"status": "error", "message": "引擎未初始化"}), 500

        blocked_count = 0
        unblocked_count = 0
        for item in apps:
            app_id = item.get("id", "")
            if not app_id:
                continue
            if item.get("blocked"):
                detector.block_app(app_id)
                blocked_count += 1
            else:
                detector.unblock_app(app_id)
                unblocked_count += 1

        log_web_action(
            action="import_apps",
            module="app_control",
            detail="导入应用策略: {} 条阻断, {} 条解除".format(blocked_count, unblocked_count),
        )

        return jsonify({
            "status": "ok",
            "message": "导入完成",
            "data": {
                "total": len(apps),
                "blocked": blocked_count,
                "unblocked": unblocked_count,
            }
        })
    except json.JSONDecodeError:
        return jsonify({"status": "error", "message": "JSON格式错误"}), 400
    except Exception as e:
        logger.error("导入应用列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
