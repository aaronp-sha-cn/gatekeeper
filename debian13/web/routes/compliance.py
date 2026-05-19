"""
GateKeeper - 合规检查路由
提供合规检查管理的API接口和页面
"""

import uuid

from flask import Blueprint, jsonify, request, render_template, Response
from flask_login import login_required

from web.routes.auth import admin_required

from config.logging_config import get_logger
from core.audit import log_web_action
from security.compliance_checker import get_compliance_checker
from web.app import _safe_error_message

logger = get_logger("compliance_routes")

compliance_bp = Blueprint("compliance", __name__)

# 内存存储网络设备列表（简易实现，生产环境应持久化到数据库）
_network_devices = []


@compliance_bp.route("/")
@login_required
def index():
    """合规检查页面"""
    return render_template("compliance.html")


@compliance_bp.route("/api/run", methods=["POST"])
@admin_required
def run_check():
    """执行合规检查"""
    try:
        data = request.get_json(silent=True) or {}
        standard = data.get("standard", "cis")
        category = data.get("category")

        if standard not in ("cis", "djcp"):
            return jsonify({
                "status": "error",
                "message": "无效的检查标准，支持: cis, djcp",
            }), 400

        checker = get_compliance_checker()

        if checker.is_checking():
            return jsonify({
                "status": "error",
                "message": "合规检查正在进行中，请稍后再试",
            }), 409

        if category:
            checks = checker.run_category_check(category, standard)
            log_web_action(
                action="run_category_check",
                module="compliance",
                detail="执行分类合规检查: category={}, standard={}".format(
                    category, standard
                ),
            )
            return jsonify({
                "status": "ok",
                "data": {
                    "checks": [c.to_dict() for c in checks],
                    "total": len(checks),
                    "passed": sum(1 for c in checks if c.status == "pass"),
                    "failed": sum(1 for c in checks if c.status == "fail"),
                    "warnings": sum(1 for c in checks if c.status == "warning"),
                },
            })

        report = checker.run_full_check(standard)

        log_web_action(
            action="run_full_check",
            module="compliance",
            detail="执行完整合规检查: standard={}, score={}".format(
                standard, report.score
            ),
        )

        return jsonify({
            "status": "ok",
            "data": report.to_dict(),
        })

    except RuntimeError as e:
        return jsonify(_safe_error_message(e)), 409
    except Exception as e:
        logger.error("执行合规检查失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@compliance_bp.route("/api/checks")
@login_required
def get_checks():
    """获取检查结果"""
    try:
        category = request.args.get("category")
        status = request.args.get("status")

        checker = get_compliance_checker()
        checks = checker.get_checks(category=category, status=status)

        return jsonify({
            "status": "ok",
            "data": {
                "checks": checks,
                "total": len(checks),
                "passed": sum(1 for c in checks if c.get("status") == "pass"),
                "failed": sum(1 for c in checks if c.get("status") == "fail"),
                "warnings": sum(1 for c in checks if c.get("status") == "warning"),
            },
        })

    except Exception as e:
        logger.error("获取检查结果失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@compliance_bp.route("/api/score")
@login_required
def get_score():
    """获取当前合规分数"""
    try:
        checker = get_compliance_checker()
        score = checker.get_score()
        latest = checker.get_latest_report()

        return jsonify({
            "status": "ok",
            "data": {
                "score": score,
                "latest_report": latest,
            },
        })

    except Exception as e:
        logger.error("获取合规分数失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@compliance_bp.route("/api/reports")
@login_required
def get_reports():
    """获取历史报告列表"""
    try:
        checker = get_compliance_checker()
        reports = checker.get_reports()

        return jsonify({
            "status": "ok",
            "data": reports,
        })

    except Exception as e:
        logger.error("获取报告列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@compliance_bp.route("/api/reports/<report_id>")
@login_required
def get_report(report_id):
    """获取指定报告详情"""
    try:
        checker = get_compliance_checker()
        reports = checker.get_reports()

        for report in reports:
            if report["id"] == report_id:
                return jsonify({"status": "ok", "data": report})

        return jsonify({"status": "error", "message": "报告不存在"}), 404

    except Exception as e:
        logger.error("获取报告详情失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@compliance_bp.route("/api/export/<report_id>")
@login_required
def export_report(report_id):
    """导出报告"""
    try:
        format_type = request.args.get("format", "json")

        if format_type not in ("json", "csv", "html"):
            return jsonify({
                "status": "error",
                "message": "不支持的导出格式，支持: json, csv, html",
            }), 400

        checker = get_compliance_checker()
        content = checker.export_report(report_id, format=format_type)

        if content is None:
            return jsonify({"status": "error", "message": "报告不存在或导出失败"}), 404

        # 设置响应头
        mime_types = {
            "json": "application/json",
            "csv": "text/csv; charset=utf-8",
            "html": "text/html; charset=utf-8",
        }
        file_extensions = {
            "json": "json",
            "csv": "csv",
            "html": "html",
        }

        log_web_action(
            action="export_report",
            module="compliance",
            detail="导出合规报告: report_id={}, format={}".format(
                report_id, format_type
            ),
        )

        return Response(
            content,
            mimetype=mime_types.get(format_type, "text/plain"),
            headers={
                "Content-Disposition": "attachment; filename=compliance_report_{}.{}".format(
                    report_id, file_extensions.get(format_type, "txt")
                )
            },
        )

    except Exception as e:
        logger.error("导出报告失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@compliance_bp.route("/api/status")
@login_required
def get_status():
    """获取合规检查器状态"""
    try:
        checker = get_compliance_checker()
        return jsonify({
            "status": "ok",
            "data": {
                "is_checking": checker.is_checking(),
                "score": checker.get_score(),
                "has_reports": len(checker.get_reports()) > 0,
            },
        })

    except Exception as e:
        logger.error("获取检查器状态失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


# ============================================================
# 网络设备管理 API
# ============================================================

@compliance_bp.route("/api/devices", methods=["GET"])
@login_required
def get_devices():
    """获取已添加的网络设备列表"""
    try:
        return jsonify({
            "status": "ok",
            "data": [
                {**d, "password": "******"}
                for d in _network_devices
            ],
        })
    except Exception as e:
        logger.error("获取设备列表失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@compliance_bp.route("/api/devices", methods=["POST"])
@admin_required
def add_device():
    """添加网络设备"""
    try:
        data = request.get_json(silent=True) or {}
        host = data.get("host", "").strip()
        username = data.get("username", "").strip()
        password = data.get("password", "")
        vendor = data.get("vendor", "cisco")
        port = int(data.get("port", 22))
        alias = data.get("alias", "").strip()

        if not host or not username or not password:
            return jsonify({
                "status": "error",
                "message": "请填写设备地址、用户名和密码",
            }), 400

        if vendor not in ("cisco", "huawei", "h3c", "juniper"):
            return jsonify({
                "status": "error",
                "message": "不支持的设备厂商，支持: cisco, huawei, h3c, juniper",
            }), 400

        device = {
            "id": str(uuid.uuid4())[:8],
            "host": host,
            "username": username,
            "password": password,
            "vendor": vendor,
            "port": port,
            "alias": alias or host,
        }
        _network_devices.append(device)

        log_web_action(
            action="add_network_device",
            module="compliance",
            detail="添加网络设备: {} ({})".format(alias or host, host),
        )

        return jsonify({
            "status": "ok",
            "data": {**device, "password": "******"},
        })

    except Exception as e:
        logger.error("添加设备失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@compliance_bp.route("/api/devices/<device_id>", methods=["DELETE"])
@admin_required
def remove_device(device_id):
    """删除网络设备"""
    try:
        global _network_devices
        original_len = len(_network_devices)
        _network_devices = [d for d in _network_devices if d["id"] != device_id]

        if len(_network_devices) == original_len:
            return jsonify({"status": "error", "message": "设备不存在"}), 404

        log_web_action(
            action="remove_network_device",
            module="compliance",
            detail="删除网络设备: device_id={}".format(device_id),
        )

        return jsonify({"status": "ok", "message": "设备已删除"})

    except Exception as e:
        logger.error("删除设备失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@compliance_bp.route("/api/devices/test", methods=["POST"])
@admin_required
def test_device():
    """测试设备SSH连接"""
    try:
        data = request.get_json(silent=True) or {}
        device = {
            "host": data.get("host", "").strip(),
            "username": data.get("username", "").strip(),
            "password": data.get("password", ""),
            "vendor": data.get("vendor", "cisco"),
            "port": int(data.get("port", 22)),
        }

        if not device["host"] or not device["username"] or not device["password"]:
            return jsonify({
                "status": "error",
                "message": "请填写设备地址、用户名和密码",
            }), 400

        checker = get_compliance_checker()
        result = checker.test_device_connection(device)

        return jsonify({"status": "ok", "data": result})

    except Exception as e:
        logger.error("测试设备连接失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@compliance_bp.route("/api/run-network", methods=["POST"])
@admin_required
def run_network_check():
    """执行网络设备合规检查"""
    try:
        checker = get_compliance_checker()

        if checker.is_checking():
            return jsonify({
                "status": "error",
                "message": "合规检查正在进行中，请稍后再试",
            }), 409

        if not _network_devices:
            return jsonify({
                "status": "error",
                "message": "请先添加网络设备",
            }), 400

        # 使用存储的设备信息（含密码）进行检查
        devices = [dict(d) for d in _network_devices]
        checks = checker.check_network_devices(devices)

        log_web_action(
            action="run_network_check",
            module="compliance",
            detail="执行网络设备合规检查: {}台设备, {}项检查".format(
                len(devices), len(checks)
            ),
        )

        return jsonify({
            "status": "ok",
            "data": {
                "checks": [c.to_dict() for c in checks],
                "total": len(checks),
                "passed": sum(1 for c in checks if c.status == "pass"),
                "failed": sum(1 for c in checks if c.status == "fail"),
                "warnings": sum(1 for c in checks if c.status == "warning"),
                "devices_checked": len(devices),
            },
        })

    except Exception as e:
        logger.error("执行网络设备检查失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
