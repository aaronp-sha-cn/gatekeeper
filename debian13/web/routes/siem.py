"""
GateKeeper - SIEM路由
提供安全信息和事件管理的Web API接口
"""

from flask import Blueprint, jsonify, request, render_template, Response
from flask_login import login_required, current_user

from web.routes.auth import admin_required

from datetime import datetime

from config.logging_config import get_logger
from core.audit import log_web_action
from security.siem_engine import (
    get_siem_engine, SIEMCorrelationRule,
)
from web.app import _safe_error_message

logger = get_logger("siem_routes")

siem_bp = Blueprint("siem", __name__)


@siem_bp.route("/")
@login_required
def index():
    """SIEM管理页面"""
    return render_template("siem.html")


@siem_bp.route("/api/events")
@login_required
def get_events():
    """查询SIEM事件"""
    try:
        source = request.args.get("source")
        severity = request.args.get("severity")
        keyword = request.args.get("keyword")
        start_time = request.args.get("start_time")
        end_time = request.args.get("end_time")
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("page_size", 50, type=int)

        # 限制分页大小
        page_size = min(page_size, 200)

        # 解析时间参数
        st = None
        et = None
        if start_time:
            try:
                st = datetime.fromisoformat(start_time)
            except (ValueError, TypeError):
                pass
        if end_time:
            try:
                et = datetime.fromisoformat(end_time)
            except (ValueError, TypeError):
                pass

        engine = get_siem_engine()
        result = engine.get_events(
            source=source,
            severity=severity,
            keyword=keyword,
            start_time=st,
            end_time=et,
            page=page,
            page_size=page_size,
        )

        return jsonify({"status": "ok", "data": result})

    except Exception as e:
        logger.error("查询SIEM事件失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@siem_bp.route("/api/collect")
@admin_required
def collect_events():
    """手动触发事件收集"""
    try:
        engine = get_siem_engine()
        events = engine.collect_events()
        log_web_action(
            action="siem_collect",
            module="siem",
            detail="手动触发SIEM事件收集，共 {} 条".format(len(events)),
        )
        return jsonify({
            "status": "ok",
            "data": {"event_count": len(events)},
        })
    except Exception as e:
        logger.error("SIEM事件收集失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@siem_bp.route("/api/correlate")
@admin_required
def correlate_events():
    """手动触发关联分析"""
    try:
        engine = get_siem_engine()
        # 先收集最新事件
        engine.collect_events()
        alerts = engine.correlate_events()
        log_web_action(
            action="siem_correlate",
            module="siem",
            detail="手动触发关联分析，触发 {} 条告警".format(len(alerts)),
        )
        return jsonify({
            "status": "ok",
            "data": {"alert_count": len(alerts), "alerts": alerts},
        })
    except Exception as e:
        logger.error("SIEM关联分析失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@siem_bp.route("/api/stats")
@login_required
def get_stats():
    """获取SIEM统计信息"""
    try:
        engine = get_siem_engine()
        stats = engine.get_stats()
        return jsonify({"status": "ok", "data": stats})
    except Exception as e:
        logger.error("获取SIEM统计失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@siem_bp.route("/api/timeline")
@login_required
def get_timeline():
    """获取事件时间线"""
    try:
        hours = request.args.get("hours", 24, type=int)
        hours = min(max(hours, 1), 168)  # 限制在1小时到7天

        engine = get_siem_engine()
        timeline = engine.get_timeline(hours=hours)
        return jsonify({"status": "ok", "data": timeline})
    except Exception as e:
        logger.error("获取SIEM时间线失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@siem_bp.route("/api/attack-chain")
@login_required
def get_attack_chain():
    """获取IP攻击链分析"""
    try:
        ip = request.args.get("ip", "").strip()
        if not ip:
            return jsonify({"status": "error", "message": "IP地址不能为空"}), 400

        engine = get_siem_engine()
        chain = engine.get_attack_chain(ip)
        return jsonify({"status": "ok", "data": chain})
    except Exception as e:
        logger.error("获取攻击链失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@siem_bp.route("/api/correlation-rules", methods=["GET"])
@login_required
def get_correlation_rules():
    """获取关联规则列表"""
    try:
        engine = get_siem_engine()
        rules = engine.get_correlation_rules()
        return jsonify({"status": "ok", "data": rules})
    except Exception as e:
        logger.error("获取关联规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@siem_bp.route("/api/correlation-rules", methods=["POST"])
@admin_required
def add_correlation_rule():
    """添加关联规则"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "请求数据不能为空"}), 400

        name = data.get("name", "").strip()
        if not name:
            return jsonify({"status": "error", "message": "规则名称不能为空"}), 400

        rule = SIEMCorrelationRule(
            name=name,
            description=data.get("description", ""),
            conditions=data.get("conditions", []),
            action=data.get("action", "alert"),
            severity=data.get("severity", "high"),
            threshold=data.get("threshold", 1),
            enabled=data.get("enabled", True),
        )

        engine = get_siem_engine()
        engine.add_correlation_rule(rule)

        log_web_action(
            action="siem_add_rule",
            module="siem",
            detail="添加SIEM关联规则: {}".format(name),
        )
        return jsonify({"status": "ok", "message": "规则已添加", "data": rule.to_dict()})
    except Exception as e:
        logger.error("添加关联规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@siem_bp.route("/api/correlation-rules/<rule_id>", methods=["DELETE"])
@admin_required
def remove_correlation_rule(rule_id):
    """删除关联规则"""
    try:
        engine = get_siem_engine()
        removed = engine.remove_correlation_rule(rule_id)
        if removed:
            log_web_action(
                action="siem_remove_rule",
                module="siem",
                detail="删除SIEM关联规则: {}".format(rule_id),
            )
            return jsonify({"status": "ok", "message": "规则已删除"})
        else:
            return jsonify({"status": "error", "message": "规则不存在"}), 404
    except Exception as e:
        logger.error("删除关联规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@siem_bp.route("/api/correlation-rules/<rule_id>", methods=["PUT"])
@admin_required
def update_correlation_rule(rule_id):
    """更新关联规则（启用/禁用）"""
    try:
        data = request.get_json()
        engine = get_siem_engine()

        rules = engine._correlation_rules
        for rule in rules:
            if rule.id == rule_id:
                if "enabled" in data:
                    rule.enabled = bool(data["enabled"])
                if "name" in data:
                    rule.name = data["name"]
                if "description" in data:
                    rule.description = data["description"]
                if "severity" in data:
                    rule.severity = data["severity"]
                if "threshold" in data:
                    rule.threshold = int(data["threshold"])
                if "conditions" in data:
                    rule.conditions = data["conditions"]

                log_web_action(
                    action="siem_update_rule",
                    module="siem",
                    detail="更新SIEM关联规则: {}".format(rule.name),
                )
                return jsonify({"status": "ok", "message": "规则已更新", "data": rule.to_dict()})

        return jsonify({"status": "error", "message": "规则不存在"}), 404
    except Exception as e:
        logger.error("更新关联规则失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@siem_bp.route("/api/correlation-alerts")
@login_required
def get_correlation_alerts():
    """获取最近的关联告警"""
    try:
        engine = get_siem_engine()
        alerts = engine.get_correlation_alerts()
        return jsonify({"status": "ok", "data": alerts})
    except Exception as e:
        logger.error("获取关联告警失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500


@siem_bp.route("/api/export")
@login_required
def export_events():
    """导出SIEM事件"""
    try:
        fmt = request.args.get("format", "json")
        if fmt not in ("json", "csv"):
            return jsonify({"status": "error", "message": "不支持的导出格式，仅支持 json 和 csv"}), 400

        engine = get_siem_engine()
        content = engine.export_events(format=fmt)

        log_web_action(
            action="siem_export",
            module="siem",
            detail="导出SIEM事件，格式: {}".format(fmt),
        )

        if fmt == "json":
            return Response(
                content,
                mimetype="application/json",
                headers={"Content-Disposition": "attachment; filename=siem_events_{}.json".format(
                    datetime.now().strftime("%Y%m%d_%H%M%S")
                )},
            )
        else:
            return Response(
                content,
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=siem_events_{}.csv".format(
                    datetime.now().strftime("%Y%m%d_%H%M%S")
                )},
            )
    except Exception as e:
        logger.error("导出SIEM事件失败: {}".format(e))
        return jsonify(_safe_error_message(e)), 500
