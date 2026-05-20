# -*- coding: utf-8 -*-
"""
GateKeeper - 沙箱分析路由
提供沙箱恶意软件分析的 Web 管理 API 接口
"""

import os
import uuid
from flask import Blueprint, jsonify, request, render_template
from flask_login import current_user

from flask_login import login_required
from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.sandbox_analyzer import get_sandbox_analyzer
from web.app import _safe_error_message

logger = get_logger("sandbox_routes")

sandbox_bp = Blueprint("sandbox", __name__)


# ============================================================
# 页面路由
# ============================================================

@sandbox_bp.route("/")
@login_required
def index():
    """沙箱分析管理页面"""
    return render_template("sandbox.html")


# ============================================================
# API 路由 - 服务状态
# ============================================================

@sandbox_bp.route("/api/status", methods=["GET"])
@login_required
def get_status():
    """获取沙箱服务状态"""
    try:
        analyzer = get_sandbox_analyzer()
        status = analyzer.get_service_status()
        return jsonify({
            "status": "ok",
            "data": status,
        })
    except Exception as e:
        logger.error("获取沙箱服务状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# API 路由 - 统计信息
# ============================================================

@sandbox_bp.route("/api/stats", methods=["GET"])
@login_required
def get_stats():
    """获取沙箱统计信息"""
    try:
        analyzer = get_sandbox_analyzer()
        stats = analyzer.get_stats()
        return jsonify({
            "status": "ok",
            "data": stats,
        })
    except Exception as e:
        logger.error("获取沙箱统计信息失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# API 路由 - 文件提交
# ============================================================

@sandbox_bp.route("/api/submit/file", methods=["POST"])
@login_required
def submit_file():
    """
    提交文件进行沙箱分析

    请求方式: multipart/form-data
    参数:
    - file: 文件对象
    - priority: 优先级 (1-5, 可选)
    - timeout: 分析超时时间 (可选)
    - platform: 目标平台 (可选)
    - auto_analyze: 是否自动分析 (可选, 默认true)
    """
    try:
        # 检查是否有文件上传
        if "file" not in request.files:
            return jsonify({"status": "error", "message": "请选择要分析的文件"}), 400

        uploaded_file = request.files["file"]
        if not uploaded_file.filename:
            return jsonify({"status": "error", "message": "文件名为空"}), 400

        # 文件大小限制（100MB）
        MAX_FILE_SIZE = 100 * 1024 * 1024
        # 检查 Content-Length（如果客户端提供）
        content_length = request.content_length
        if content_length and content_length > MAX_FILE_SIZE:
            return jsonify({"status": "error", "message": "文件大小超过限制（最大100MB）"}), 413

        # 文件扩展名白名单
        ALLOWED_EXTENSIONS = {
            '.exe', '.dll', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.msi',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.rtf',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.py', '.sh', '.pl', '.rb', '.jar', '.war',
            '.apk', '.dmg', '.iso', '.img',
            '.html', '.htm', '.php', '.asp', '.jsp',
            '.cfg', '.ini', '.conf', '.yaml', '.yml', '.json', '.xml',
            '.txt', '.csv', '.log',
            '.scr', '.hta', '.wsf', '.vbe', '.jse', '.wsh',
            '.lnk', '.reg', '.inf', '.cpl',
        }
        file_ext = os.path.splitext(uploaded_file.filename)[1].lower()
        if file_ext not in ALLOWED_EXTENSIONS:
            return jsonify({"status": "error", "message": "不支持的文件类型: {}".format(file_ext)}), 400

        # 构建分析选项
        options = {}
        priority = request.form.get("priority")
        if priority:
            options["priority"] = int(priority)
        timeout = request.form.get("timeout")
        if timeout:
            options["timeout"] = int(timeout)
        platform = request.form.get("platform")
        if platform:
            options["platform"] = platform
        route = request.form.get("route")
        if route:
            options["route"] = route

        # 保存上传文件到临时目录
        analyzer = get_sandbox_analyzer()
        upload_dir = analyzer.upload_dir
        os.makedirs(upload_dir, exist_ok=True)

        # 生成唯一文件名防止冲突
        file_ext = os.path.splitext(uploaded_file.filename)[1]
        safe_filename = "{}{}".format(str(uuid.uuid4())[:12], file_ext)
        save_path = os.path.join(upload_dir, safe_filename)

        uploaded_file.save(save_path)

        logger.info("文件已保存: {} (原始名: {})".format(save_path, uploaded_file.filename))

        # 判断是否使用完整分析流程（ClamAV + 沙箱）
        auto_analyze = request.form.get("auto_analyze", "true").lower() == "true"

        if auto_analyze:
            result = analyzer.analyze_file(save_path, options)
        else:
            result = analyzer.submit_file(save_path, options)

        # 记录审计日志
        log_web_action(
            action="submit_file",
            module="sandbox",
            detail="提交文件到沙箱分析: {} (任务ID: {})".format(
                uploaded_file.filename, result.get("task_id", "")
            ),
        )

        return jsonify(result)

    except Exception as e:
        logger.error("提交文件到沙箱失败: {}".format(e))
        return jsonify({"status": "error", "message": "提交失败，请联系管理员"}), 500


# ============================================================
# API 路由 - URL 提交
# ============================================================

@sandbox_bp.route("/api/submit/url", methods=["POST"])
@login_required
def submit_url():
    """
    提交 URL 进行沙箱分析

    请求体 (JSON):
    {
        "url": "https://example.com",
        "priority": 1,
        "timeout": 300,
        "platform": "windows"
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        url = data.get("url", "").strip()
        if not url:
            return jsonify({"status": "error", "message": "URL不能为空"}), 400

        # 构建分析选项
        options = {}
        for key in ["priority", "timeout", "platform", "route"]:
            if key in data:
                options[key] = data[key]

        analyzer = get_sandbox_analyzer()
        result = analyzer.submit_url(url, options)

        # 记录审计日志
        log_web_action(
            action="submit_url",
            module="sandbox",
            detail="提交URL到沙箱分析: {} (任务ID: {})".format(
                url, result.get("task_id", "")
            ),
        )

        return jsonify(result)

    except Exception as e:
        logger.error("提交URL到沙箱失败: {}".format(e))
        return jsonify({"status": "error", "message": "提交失败，请联系管理员"}), 500


# ============================================================
# API 路由 - 任务列表
# ============================================================

@sandbox_bp.route("/api/tasks", methods=["GET"])
@login_required
def list_tasks():
    """
    获取分析任务列表

    查询参数:
    - limit: 返回数量上限 (默认50)
    - offset: 偏移量 (默认0)
    - status: 按状态过滤 (pending/running/completed/reported/failed)
    """
    try:
        limit = request.args.get("limit", 50, type=int)
        offset = request.args.get("offset", 0, type=int)
        status = request.args.get("status")

        # 限制最大返回数量
        limit = min(limit, 200)

        analyzer = get_sandbox_analyzer()
        result = analyzer.list_tasks(limit=limit, offset=offset, status=status)

        return jsonify({
            "status": "ok",
            "data": result,
        })

    except Exception as e:
        logger.error("获取沙箱任务列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# API 路由 - 任务详情/报告
# ============================================================

@sandbox_bp.route("/api/task/<task_id>", methods=["GET"])
@login_required
def get_task(task_id):
    """
    获取任务详情和报告

    路径参数:
    - task_id: 任务ID
    """
    try:
        analyzer = get_sandbox_analyzer()

        # 获取任务状态
        task = analyzer.get_task_status(task_id)
        if not task:
            return jsonify({"status": "error", "message": "任务不存在"}), 404

        result = {
            "task": task,
        }

        # 如果任务已完成，尝试获取报告
        if task.get("status") in ("completed", "reported"):
            report = analyzer.get_task_report(task_id)
            if report:
                result["report"] = report

        return jsonify({
            "status": "ok",
            "data": result,
        })

    except Exception as e:
        logger.error("获取沙箱任务详情失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# API 路由 - 删除任务
# ============================================================

@sandbox_bp.route("/api/task/<task_id>", methods=["DELETE"])
@admin_required
def delete_task(task_id):
    """
    删除分析任务

    路径参数:
    - task_id: 任务ID
    """
    try:
        analyzer = get_sandbox_analyzer()
        result = analyzer.delete_task(task_id)

        if result["status"] == "ok":
            log_web_action(
                action="delete_task",
                module="sandbox",
                detail="删除沙箱分析任务: {}".format(task_id),
            )

        status_code = 200 if result["status"] == "ok" else 404
        return jsonify(result), status_code

    except Exception as e:
        logger.error("删除沙箱任务失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# API 路由 - 配置管理
# ============================================================

@sandbox_bp.route("/api/config", methods=["GET"])
@login_required
def get_config():
    """获取沙箱配置"""
    try:
        analyzer = get_sandbox_analyzer()
        config = analyzer.get_config()
        return jsonify({
            "status": "ok",
            "data": config,
        })
    except Exception as e:
        logger.error("获取沙箱配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@sandbox_bp.route("/api/config", methods=["POST"])
@admin_required
def update_config():
    """
    更新沙箱配置

    请求体 (JSON):
    {
        "cuckoo_api_url": "http://127.0.0.1:8090/api",
        "cuckoo_timeout": 300,
        "analysis_timeout": 300,
        "max_concurrent_tasks": 5,
        "auto_start_analysis": true,
        "clamav_enabled": true,
        "local_mode": false
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        analyzer = get_sandbox_analyzer()
        result = analyzer.update_config(data)

        if result["status"] == "ok":
            log_web_action(
                action="update_config",
                module="sandbox",
                detail="更新沙箱配置",
                request_data=data,
            )

        status_code = 200 if result["status"] == "ok" else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("更新沙箱配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
