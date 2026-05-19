"""
GateKeeper - 内容安全路由
提供防病毒、反垃圾邮件、URL过滤和数据防泄漏(DLP)的API接口
"""

import os
import tempfile

from flask import Blueprint, jsonify, request, render_template
from flask_login import login_required

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.content_security import get_content_security_engine
from web.app import _safe_error_message

logger = get_logger("content_security_routes")

content_security_bp = Blueprint("content_security", __name__)


def _get_engine():
    return get_content_security_engine()


@content_security_bp.route("/")
@login_required
def index():
    """内容安全管理页面"""
    return render_template("content_security.html")


# ============================================================
# 总览
# ============================================================

@content_security_bp.route("/api/status")
@login_required
def get_status():
    """获取内容安全所有模块的整体状态"""
    try:
        engine = _get_engine()
        status = engine.get_status()
        return jsonify({
            "status": "ok",
            "data": status,
        })
    except Exception as e:
        logger.error("获取内容安全状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 防病毒
# ============================================================

@content_security_bp.route("/api/scan/file", methods=["POST"])
@login_required
def scan_file():
    """扫描上传的文件"""
    try:
        if "file" not in request.files:
            return jsonify({"status": "error", "message": "未找到上传文件"}), 400

        uploaded = request.files["file"]
        if uploaded.filename == "":
            return jsonify({"status": "error", "message": "文件名为空"}), 400

        # 保存到临时文件进行扫描（强制使用 .tmp 后缀防止自动执行）
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as tmp:
            uploaded.save(tmp)
            tmp_path = tmp.name

        try:
            engine = _get_engine()
            result = engine.scan_file(tmp_path)
            log_web_action(
                action="scan_file",
                module="content_security",
                detail="扫描文件: {} (结果: {})".format(
                    uploaded.filename, result.get("threat", "clean")),
            )
            return jsonify({
                "status": "ok",
                "data": result,
            })
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        logger.error("文件扫描失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@content_security_bp.route("/api/quarantine")
@login_required
def list_quarantine():
    """列出隔离区文件"""
    try:
        engine = _get_engine()
        items = engine.get_quarantine_list()
        return jsonify({
            "status": "ok",
            "data": {
                "items": items,
                "total": len(items),
            }
        })
    except Exception as e:
        logger.error("获取隔离区列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@content_security_bp.route("/api/quarantine/<item_id>/restore", methods=["POST"])
@admin_required
def restore_quarantine(item_id):
    """从隔离区恢复文件"""
    try:
        engine = _get_engine()
        success = engine.restore_quarantine(item_id)
        if not success:
            return jsonify({"status": "error", "message": "恢复失败，隔离项可能不存在"}), 404

        log_web_action(
            action="restore_quarantine",
            module="content_security",
            detail="恢复隔离文件: {}".format(item_id),
        )
        return jsonify({
            "status": "ok",
            "message": "文件已恢复",
        })
    except Exception as e:
        logger.error("恢复隔离文件失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@content_security_bp.route("/api/antivirus/update", methods=["POST"])
@admin_required
def update_antivirus():
    """更新防病毒签名库"""
    try:
        engine = _get_engine()
        result = engine.update_antivirus_signatures()

        log_web_action(
            action="update_antivirus",
            module="content_security",
            detail="更新防病毒签名: {}".format(result.get("status", "unknown")),
        )
        return jsonify({
            "status": "ok",
            "data": result,
        })
    except Exception as e:
        logger.error("更新防病毒签名失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 反垃圾邮件
# ============================================================

@content_security_bp.route("/api/email/check", methods=["POST"])
@login_required
def check_email():
    """检查邮件是否为垃圾邮件"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        headers = data.get("headers", {})
        body = data.get("body", "")

        if not headers and not body:
            return jsonify({"status": "error", "message": "headers和body不能同时为空"}), 400

        engine = _get_engine()
        result = engine.check_email(headers=headers, body=body)
        return jsonify({
            "status": "ok",
            "data": result,
        })
    except Exception as e:
        logger.error("邮件检查失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@content_security_bp.route("/api/spam/stats")
@login_required
def spam_stats():
    """获取垃圾邮件统计"""
    try:
        engine = _get_engine()
        stats = engine.get_spam_stats()
        return jsonify({
            "status": "ok",
            "data": stats,
        })
    except Exception as e:
        logger.error("获取垃圾邮件统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# URL过滤
# ============================================================

@content_security_bp.route("/api/url/check", methods=["POST"])
@login_required
def check_url():
    """检查URL分类"""
    try:
        data = request.get_json()
        if not data or not data.get("url"):
            return jsonify({"status": "error", "message": "缺少url参数"}), 400

        url = data["url"].strip()
        engine = _get_engine()
        result = engine.check_url(url)
        return jsonify({
            "status": "ok",
            "data": result,
        })
    except Exception as e:
        logger.error("URL检查失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@content_security_bp.route("/api/url/blacklist", methods=["POST"])
@admin_required
def add_url_blacklist():
    """添加URL到黑名单"""
    try:
        data = request.get_json()
        if not data or not data.get("url"):
            return jsonify({"status": "error", "message": "缺少url参数"}), 400

        url = data["url"].strip()
        category = data.get("category", "").strip()
        engine = _get_engine()
        success = engine.add_url_blacklist(url, category)
        if not success:
            return jsonify({"status": "error", "message": "添加黑名单失败"}), 500

        log_web_action(
            action="add_url_blacklist",
            module="content_security",
            detail="添加URL黑名单: {} (分类: {})".format(url, category),
        )
        return jsonify({
            "status": "ok",
            "message": "已添加到黑名单",
        })
    except Exception as e:
        logger.error("添加URL黑名单失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@content_security_bp.route("/api/url/whitelist", methods=["POST"])
@admin_required
def add_url_whitelist():
    """添加URL到白名单"""
    try:
        data = request.get_json()
        if not data or not data.get("url"):
            return jsonify({"status": "error", "message": "缺少url参数"}), 400

        url = data["url"].strip()
        engine = _get_engine()
        success = engine.add_url_whitelist(url)
        if not success:
            return jsonify({"status": "error", "message": "添加白名单失败"}), 500

        log_web_action(
            action="add_url_whitelist",
            module="content_security",
            detail="添加URL白名单: {}".format(url),
        )
        return jsonify({
            "status": "ok",
            "message": "已添加到白名单",
        })
    except Exception as e:
        logger.error("添加URL白名单失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@content_security_bp.route("/api/url/categories")
@login_required
def url_categories():
    """列出URL分类"""
    try:
        engine = _get_engine()
        categories = engine.get_url_categories()
        return jsonify({
            "status": "ok",
            "data": {
                "categories": categories,
            }
        })
    except Exception as e:
        logger.error("获取URL分类失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@content_security_bp.route("/api/url/stats")
@login_required
def url_stats():
    """获取URL过滤统计"""
    try:
        engine = _get_engine()
        stats = engine.get_url_filter_stats()
        return jsonify({
            "status": "ok",
            "data": stats,
        })
    except Exception as e:
        logger.error("获取URL过滤统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 数据防泄漏 (DLP)
# ============================================================

@content_security_bp.route("/api/dlp/scan", methods=["POST"])
@login_required
def dlp_scan():
    """扫描内容是否包含敏感数据"""
    try:
        data = request.get_json()
        if not data or not data.get("content"):
            return jsonify({"status": "error", "message": "缺少content参数"}), 400

        content = data["content"]
        engine = _get_engine()
        result = engine.scan_content(content)
        return jsonify({
            "status": "ok",
            "data": result,
        })
    except Exception as e:
        logger.error("DLP扫描失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@content_security_bp.route("/api/dlp/pattern", methods=["POST"])
@admin_required
def add_dlp_pattern():
    """添加自定义DLP检测模式"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        name = data.get("name", "").strip()
        pattern = data.get("pattern", "").strip()
        severity = data.get("severity", "medium").strip()

        if not name:
            return jsonify({"status": "error", "message": "模式名称不能为空"}), 400
        if not pattern:
            return jsonify({"status": "error", "message": "匹配模式不能为空"}), 400

        engine = _get_engine()
        success = engine.add_dlp_pattern(name=name, pattern=pattern, severity=severity)
        if not success:
            return jsonify({"status": "error", "message": "添加DLP模式失败"}), 500

        log_web_action(
            action="add_dlp_pattern",
            module="content_security",
            detail="添加DLP模式: {} (严重程度: {})".format(name, severity),
        )
        return jsonify({
            "status": "ok",
            "message": "DLP模式已添加",
        })
    except Exception as e:
        logger.error("添加DLP模式失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@content_security_bp.route("/api/dlp/events")
@login_required
def dlp_events():
    """列出DLP事件"""
    try:
        engine = _get_engine()
        events = engine.get_dlp_events()
        return jsonify({
            "status": "ok",
            "data": {
                "events": events,
                "total": len(events),
            }
        })
    except Exception as e:
        logger.error("获取DLP事件失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 配置管理
# ============================================================

@content_security_bp.route("/api/config", methods=["GET"])
@login_required
def get_config():
    """获取内容安全配置"""
    try:
        engine = _get_engine()
        config = engine.get_config()
        return jsonify({
            "status": "ok",
            "data": config,
        })
    except Exception as e:
        logger.error("获取内容安全配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@content_security_bp.route("/api/config", methods=["POST"])
@admin_required
def update_config():
    """更新内容安全配置"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        engine = _get_engine()
        result = engine.update_config(data)

        log_web_action(
            action="update_content_security_config",
            module="content_security",
            detail="更新内容安全配置",
        )
        return jsonify({
            "status": "ok",
            "message": "配置已更新",
            "data": result,
        })
    except Exception as e:
        logger.error("更新内容安全配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
