"""
GateKeeper - 系统备份管理路由
提供备份创建、恢复、列表、下载、上传、定时计划和远程同步 API
"""

import os

from flask import Blueprint, jsonify, render_template, request, send_file
from flask_login import login_required

from config.logging_config import get_logger
from core.audit import log_web_action
from web.routes.auth import admin_required
from web.app import _safe_error_message

logger = get_logger("web.backup")

backup_bp = Blueprint("backup", __name__)


@backup_bp.route("/")
@login_required
@admin_required
def index():
    """备份管理页面"""
    return render_template("backup.html", title="系统备份")


@backup_bp.route("/api/list", methods=["GET"])
@login_required
@admin_required
def api_list():
    """获取备份列表"""
    try:
        from core.backup_manager import backup_manager
        backups = backup_manager.list_backups()
        return jsonify({"status": "ok", "data": backups})
    except Exception as e:
        logger.error("获取备份列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@backup_bp.route("/api/create", methods=["POST"])
@login_required
@admin_required
def api_create():
    """创建备份"""
    try:
        data = request.get_json(silent=True) or {}
        encrypt = data.get("encrypt", False)
        description = data.get("description", "")

        from core.backup_manager import backup_manager
        result = backup_manager.create_backup(
            encrypt=bool(encrypt),
            description=description,
        )

        if result.get("status") == "ok":
            log_web_action(
                action="backup_create",
                module="backup",
                detail="创建备份: {}".format(result["data"].get("filename", "")),
            )

        status_code = 200 if result.get("status") == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("创建备份失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@backup_bp.route("/api/restore/<filename>", methods=["POST"])
@login_required
@admin_required
def api_restore(filename):
    """恢复备份"""
    try:
        data = request.get_json(silent=True) or {}
        password = data.get("password", "")

        # 安全检查：防止路径遍历
        safe_name = os.path.basename(filename)
        if safe_name != filename or ".." in filename:
            return jsonify({"status": "error", "message": "无效的文件名"}), 400

        from core.backup_manager import backup_manager
        result = backup_manager.restore_backup(safe_name, password=password)

        if result.get("status") == "ok":
            log_web_action(
                action="backup_restore",
                module="backup",
                detail="恢复备份: {}".format(safe_name),
            )

        status_code = 200 if result.get("status") == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("恢复备份失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@backup_bp.route("/api/delete/<filename>", methods=["DELETE"])
@login_required
@admin_required
def api_delete(filename):
    """删除备份"""
    try:
        safe_name = os.path.basename(filename)
        if safe_name != filename or ".." in filename:
            return jsonify({"status": "error", "message": "无效的文件名"}), 400

        from core.backup_manager import backup_manager
        result = backup_manager.delete_backup(safe_name)

        if result.get("status") == "ok":
            log_web_action(
                action="backup_delete",
                module="backup",
                detail="删除备份: {}".format(safe_name),
            )

        status_code = 200 if result.get("status") == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("删除备份失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@backup_bp.route("/api/download/<filename>", methods=["GET"])
@login_required
@admin_required
def api_download(filename):
    """下载备份文件"""
    try:
        safe_name = os.path.basename(filename)
        if safe_name != filename or ".." in filename:
            return jsonify({"status": "error", "message": "无效的文件名"}), 400

        from core.backup_manager import backup_manager
        backup_path = backup_manager.get_backup_path(safe_name)
        if backup_path is None:
            return jsonify({"status": "error", "message": "备份文件不存在"}), 404

        log_web_action(
            action="backup_download",
            module="backup",
            detail="下载备份: {}".format(safe_name),
        )

        return send_file(
            str(backup_path),
            as_attachment=True,
            download_name=safe_name,
            mimetype="application/gzip",
        )
    except Exception as e:
        logger.error("下载备份失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@backup_bp.route("/api/upload", methods=["POST"])
@login_required
@admin_required
def api_upload():
    """上传备份文件"""
    try:
        if "file" not in request.files:
            return jsonify({"status": "error", "message": "未选择文件"}), 400

        file_obj = request.files["file"]
        description = request.form.get("description", "")

        from core.backup_manager import backup_manager
        result = backup_manager.upload_backup(file_obj, description=description)

        if result.get("status") == "ok":
            log_web_action(
                action="backup_upload",
                module="backup",
                detail="上传备份: {}".format(result["data"].get("filename", "")),
            )

        status_code = 200 if result.get("status") == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("上传备份失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@backup_bp.route("/api/schedule", methods=["GET"])
@login_required
@admin_required
def api_get_schedule():
    """获取自动备份计划"""
    try:
        from core.backup_manager import backup_manager
        schedule = backup_manager.get_schedule()
        return jsonify({"status": "ok", "data": schedule})
    except Exception as e:
        logger.error("获取备份计划失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@backup_bp.route("/api/schedule", methods=["POST"])
@login_required
@admin_required
def api_set_schedule():
    """设置自动备份计划"""
    try:
        data = request.get_json(silent=True) or {}
        enabled = data.get("enabled", False)
        cron_expression = data.get("cron_expression", "0 2 * * *")
        retain_count = data.get("retain_count", 10)
        encrypt = data.get("encrypt", False)

        # 验证 cron 表达式格式（5 个字段）
        parts = cron_expression.strip().split()
        if len(parts) != 5:
            return jsonify({"status": "error", "message": "cron 表达式格式无效，需要 5 个字段"}), 400

        # 验证保留份数
        try:
            retain_count = int(retain_count)
            if retain_count < 1 or retain_count > 100:
                return jsonify({"status": "error", "message": "保留份数应在 1-100 之间"}), 400
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "保留份数必须是整数"}), 400

        config = {
            "enabled": bool(enabled),
            "cron_expression": cron_expression,
            "retain_count": retain_count,
            "encrypt": bool(encrypt),
        }

        from core.backup_manager import backup_manager
        result = backup_manager.set_schedule(config)

        log_web_action(
            action="backup_schedule_update",
            module="backup",
            detail="更新自动备份计划: enabled={}, cron={}, retain={}".format(
                enabled, cron_expression, retain_count
            ),
        )

        status_code = 200 if result.get("status") == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("设置备份计划失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@backup_bp.route("/api/remote-test", methods=["POST"])
@login_required
@admin_required
def api_remote_test():
    """测试远程连接"""
    try:
        data = request.get_json(silent=True) or {}
        config = {
            "host": data.get("host", ""),
            "port": data.get("port", 22),
            "username": data.get("username", ""),
            "password": data.get("password", ""),
            "key_path": data.get("key_path", ""),
            "auth_type": data.get("auth_type", "password"),
            "use_paramiko": data.get("use_paramiko", True),
        }

        from core.backup_manager import backup_manager
        result = backup_manager.test_remote_connection(config)

        status_code = 200 if result.get("status") == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("测试远程连接失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@backup_bp.route("/api/remote-sync", methods=["POST"])
@login_required
@admin_required
def api_remote_sync():
    """手动同步到远程服务器"""
    try:
        data = request.get_json(silent=True) or {}
        filename = data.get("filename")

        from core.backup_manager import backup_manager
        result = backup_manager.sync_to_remote(filename=filename)

        if result.get("status") == "ok":
            log_web_action(
                action="backup_remote_sync",
                module="backup",
                detail="远程同步备份: {}".format(filename or "全部"),
            )

        status_code = 200 if result.get("status") == "ok" else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error("远程同步失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
