"""
GateKeeper - 网络设备安全基线检查路由
提供NTConfigChecker模块的API接口和页面
"""

from flask import Blueprint, jsonify, request, render_template, Response
from flask_login import login_required

from web.routes.auth import admin_required

from werkzeug.utils import secure_filename

from config.logging_config import get_logger
from core.audit import log_web_action
from security.ntconfig_checker import get_ntconfig_checker, BaselineRule
from web.app import _safe_error_message

logger = get_logger("ntconfig_routes")

ntconfig_bp = Blueprint("ntconfig", __name__, url_prefix="/ntconfig")


@ntconfig_bp.route("/")
@login_required
def index():
    """基线检查管理页面"""
    return render_template("ntconfig.html")


# ==================== 统计信息 ====================

@ntconfig_bp.route("/api/stats")
@login_required
def get_stats():
    """获取统计信息"""
    try:
        checker = get_ntconfig_checker()
        stats = checker.get_stats()
        
        # 计算已完成任务数
        completed_tasks = stats["tasks"]["by_status"].get("completed", 0)
        
        return jsonify({
            "status": "ok",
            "data": {
                "rules_count": stats["rules"]["total"],
                "rules_enabled": stats["rules"]["enabled"],
                "devices_count": stats["devices"]["total"],
                "tasks_count": stats["tasks"]["total"],
                "completed_tasks": completed_tasks,
                "rules_by_category": stats["rules"]["by_category"],
                "devices_by_vendor": stats["devices"]["by_vendor"],
                "tasks_by_status": stats["tasks"]["by_status"],
            },
        })
    except Exception as e:
        logger.error("获取统计信息失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ==================== 规则管理 ====================

@ntconfig_bp.route("/api/rules")
@login_required
def get_rules():
    """获取规则列表"""
    try:
        checker = get_ntconfig_checker()
        category = request.args.get("category")
        vendor = request.args.get("vendor")
        
        rules = checker.get_rules(category=category, vendor=vendor)
        
        return jsonify({
            "status": "ok",
            "data": [r.to_dict() for r in rules],
        })
    except Exception as e:
        logger.error("获取规则列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/rules", methods=["POST"])
@admin_required
def add_rule():
    """添加规则"""
    try:
        data = request.get_json(silent=True) or {}
        
        # 验证必填字段
        required_fields = ["id", "name", "category", "description", "check_prompt"]
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    "status": "error",
                    "message": "缺少必填字段: {}".format(field),
                }), 400
        
        rule = BaselineRule(
            id=data["id"],
            name=data["name"],
            category=data["category"],
            description=data["description"],
            check_prompt=data["check_prompt"],
            vendor=data.get("vendor", "all"),
            severity=data.get("severity", "medium"),
            reference=data.get("reference", ""),
            enabled=data.get("enabled", True),
        )
        
        checker = get_ntconfig_checker()
        if not checker.add_rule(rule):
            return jsonify({
                "status": "error",
                "message": "规则ID已存在",
            }), 400
        
        log_web_action(
            action="add_rule",
            module="ntconfig",
            detail="添加基线规则: id={}, name={}".format(rule.id, rule.name),
        )
        
        return jsonify({
            "status": "ok",
            "data": rule.to_dict(),
            "message": "规则添加成功",
        })
    except Exception as e:
        logger.error("添加规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/rules/<rule_id>", methods=["PUT"])
@admin_required
def update_rule(rule_id):
    """更新规则"""
    try:
        data = request.get_json(silent=True) or {}
        
        checker = get_ntconfig_checker()
        if not checker.update_rule(rule_id, data):
            return jsonify({
                "status": "error",
                "message": "规则不存在",
            }), 404
        
        log_web_action(
            action="update_rule",
            module="ntconfig",
            detail="更新基线规则: id={}".format(rule_id),
        )
        
        return jsonify({
            "status": "ok",
            "message": "规则更新成功",
        })
    except Exception as e:
        logger.error("更新规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/rules/<rule_id>", methods=["DELETE"])
@admin_required
def delete_rule(rule_id):
    """删除规则"""
    try:
        checker = get_ntconfig_checker()
        if not checker.delete_rule(rule_id):
            return jsonify({
                "status": "error",
                "message": "规则不存在或为内置规则，无法删除",
            }), 400
        
        log_web_action(
            action="delete_rule",
            module="ntconfig",
            detail="删除基线规则: id={}".format(rule_id),
        )
        
        return jsonify({
            "status": "ok",
            "message": "规则删除成功",
        })
    except Exception as e:
        logger.error("删除规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/rules/<rule_id>/toggle", methods=["POST"])
@admin_required
def toggle_rule(rule_id):
    """启用/禁用规则"""
    try:
        data = request.get_json(silent=True) or {}
        enabled = data.get("enabled", True)
        
        checker = get_ntconfig_checker()
        if not checker.toggle_rule(rule_id, enabled):
            return jsonify({
                "status": "error",
                "message": "规则不存在",
            }), 404
        
        log_web_action(
            action="toggle_rule",
            module="ntconfig",
            detail="{}基线规则: id={}".format("启用" if enabled else "禁用", rule_id),
        )
        
        return jsonify({
            "status": "ok",
            "message": "规则{}成功".format("启用" if enabled else "禁用"),
        })
    except Exception as e:
        logger.error("切换规则状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ==================== 设备配置管理 ====================

@ntconfig_bp.route("/api/devices")
@login_required
def get_devices():
    """获取设备列表"""
    try:
        checker = get_ntconfig_checker()
        devices = checker.get_devices()
        
        return jsonify({
            "status": "ok",
            "data": [d.to_dict() for d in devices],
        })
    except Exception as e:
        logger.error("获取设备列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/devices/upload", methods=["POST"])
@admin_required
def upload_device():
    """上传设备配置，支持指定设备连接信息"""
    try:
        if "file" not in request.files:
            return jsonify({
                "status": "error",
                "message": "未找到上传文件",
            }), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({
                "status": "error",
                "message": "未选择文件",
            }), 400

        filename = secure_filename(file.filename)
        config_text = file.read().decode("utf-8", errors="ignore")

        # 获取设备连接信息（可选）
        ip_address = request.form.get("ip_address", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        checker = get_ntconfig_checker()
        device = checker.upload_config(
            filename, config_text,
            ip_address=ip_address,
            username=username,
            password=password,
        )

        log_web_action(
            action="upload_device_config",
            module="ntconfig",
            detail="上传设备配置: filename={}, vendor={}, hostname={}, ip={}".format(
                filename, device.vendor, device.hostname, ip_address or "未指定"
            ),
        )

        return jsonify({
            "status": "ok",
            "data": device.to_dict(),
            "message": "设备配置上传成功",
        })
    except Exception as e:
        logger.error("上传设备配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/devices/<device_id>")
@login_required
def get_device(device_id):
    """获取设备详情"""
    try:
        checker = get_ntconfig_checker()
        device = checker.get_device(device_id)
        
        if not device:
            return jsonify({
                "status": "error",
                "message": "设备不存在",
            }), 404
        
        result = device.to_dict()
        result["config_lines_count"] = len(device.config_lines)
        result["config_text_length"] = len(device.config_text)
        
        return jsonify({
            "status": "ok",
            "data": result,
        })
    except Exception as e:
        logger.error("获取设备详情失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/devices/<device_id>", methods=["DELETE"])
@admin_required
def delete_device(device_id):
    """删除设备配置"""
    try:
        checker = get_ntconfig_checker()
        if not checker.delete_device(device_id):
            return jsonify({
                "status": "error",
                "message": "设备不存在",
            }), 404
        
        log_web_action(
            action="delete_device_config",
            module="ntconfig",
            detail="删除设备配置: id={}".format(device_id),
        )
        
        return jsonify({
            "status": "ok",
            "message": "设备配置删除成功",
        })
    except Exception as e:
        logger.error("删除设备配置失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ==================== 检查任务管理 ====================

@ntconfig_bp.route("/api/tasks", methods=["GET"])
@login_required
def get_tasks():
    """获取任务列表"""
    try:
        checker = get_ntconfig_checker()
        tasks = checker.get_tasks()
        
        return jsonify({
            "status": "ok",
            "data": [t.to_dict() for t in tasks],
        })
    except Exception as e:
        logger.error("获取任务列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/tasks", methods=["POST"])
@admin_required
def create_task():
    """创建检查任务"""
    try:
        data = request.get_json(silent=True) or {}
        
        name = data.get("name")
        device_ids = data.get("device_ids", [])
        rule_ids = data.get("rule_ids", [])
        
        if not name:
            return jsonify({
                "status": "error",
                "message": "任务名称不能为空",
            }), 400
        
        if not device_ids:
            return jsonify({
                "status": "error",
                "message": "请选择至少一个设备",
            }), 400
        
        if not rule_ids:
            return jsonify({
                "status": "error",
                "message": "请选择至少一条规则",
            }), 400
        
        checker = get_ntconfig_checker()
        task = checker.create_task(name, device_ids, rule_ids)
        
        log_web_action(
            action="create_check_task",
            module="ntconfig",
            detail="创建检查任务: name={}, devices={}, rules={}".format(
                name, len(device_ids), len(rule_ids)
            ),
        )
        
        return jsonify({
            "status": "ok",
            "data": task.to_dict(),
            "message": "任务创建成功",
        })
    except Exception as e:
        logger.error("创建任务失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/tasks/<task_id>")
@login_required
def get_task(task_id):
    """获取任务详情"""
    try:
        checker = get_ntconfig_checker()
        task = checker.get_task(task_id)
        
        if not task:
            return jsonify({
                "status": "error",
                "message": "任务不存在",
            }), 404
        
        result = task.to_dict()
        
        # 计算进度信息
        result["progress_percent"] = task.progress
        result["is_running"] = task.status == "running"
        
        return jsonify({
            "status": "ok",
            "data": result,
        })
    except Exception as e:
        logger.error("获取任务详情失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/tasks/<task_id>/start", methods=["POST"])
@admin_required
def start_task(task_id):
    """启动检查任务"""
    try:
        checker = get_ntconfig_checker()
        if not checker.start_task(task_id):
            return jsonify({
                "status": "error",
                "message": "任务不存在或已有任务在运行",
            }), 400
        
        log_web_action(
            action="start_check_task",
            module="ntconfig",
            detail="启动检查任务: id={}".format(task_id),
        )
        
        return jsonify({
            "status": "ok",
            "message": "任务已启动",
        })
    except Exception as e:
        logger.error("启动任务失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/tasks/<task_id>/stop", methods=["POST"])
@admin_required
def stop_task(task_id):
    """停止检查任务"""
    try:
        checker = get_ntconfig_checker()
        if not checker.stop_task(task_id):
            return jsonify({
                "status": "error",
                "message": "任务未在运行",
            }), 400
        
        log_web_action(
            action="stop_check_task",
            module="ntconfig",
            detail="停止检查任务: id={}".format(task_id),
        )
        
        return jsonify({
            "status": "ok",
            "message": "任务已停止",
        })
    except Exception as e:
        logger.error("停止任务失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@ntconfig_bp.route("/api/tasks/<task_id>", methods=["DELETE"])
@admin_required
def delete_task(task_id):
    """删除检查任务"""
    try:
        checker = get_ntconfig_checker()
        if not checker.delete_task(task_id):
            return jsonify({
                "status": "error",
                "message": "任务不存在",
            }), 404
        
        log_web_action(
            action="delete_check_task",
            module="ntconfig",
            detail="删除检查任务: id={}".format(task_id),
        )
        
        return jsonify({
            "status": "ok",
            "message": "任务删除成功",
        })
    except Exception as e:
        logger.error("删除任务失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ==================== 报告生成 ====================

@ntconfig_bp.route("/api/tasks/<task_id>/report")
@login_required
def generate_report(task_id):
    """生成检查报告"""
    try:
        format_type = request.args.get("format", "html")
        
        if format_type not in ("html", "json"):
            return jsonify({
                "status": "error",
                "message": "不支持的报告格式，支持: html, json",
            }), 400
        
        checker = get_ntconfig_checker()
        content = checker.generate_report(task_id, format=format_type)
        
        if content is None:
            return jsonify({
                "status": "error",
                "message": "任务不存在或未完成",
            }), 404
        
        log_web_action(
            action="generate_report",
            module="ntconfig",
            detail="生成检查报告: task_id={}, format={}".format(task_id, format_type),
        )
        
        if format_type == "json":
            return Response(
                content,
                mimetype="application/json",
                headers={
                    "Content-Disposition": "attachment; filename=ntconfig_report_{}.json".format(task_id)
                },
            )
        else:
            return Response(
                content,
                mimetype="text/html; charset=utf-8",
                headers={
                    "Content-Disposition": "attachment; filename=ntconfig_report_{}.html".format(task_id)
                },
            )
    except Exception as e:
        logger.error("生成报告失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
